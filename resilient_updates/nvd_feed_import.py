#!/usr/bin/env python3
"""Import NVD CVE data into cve-bin-tool's ``cve.db`` directly from the NVD 2.0
JSON *data feeds*, bypassing the rate-limited REST API.

Why this exists
---------------
cve-bin-tool's ``--nvd api2`` route calls the NVD REST API
(``https://nvd.nist.gov/rest/...``).  In some egress contours (corporate
proxy / VPN) that endpoint returns ``403 Forbidden`` even with a valid API
key, so the whole cve-bin-tool DB build fails on its required NVD source.

The static **2.0 JSON feeds** at ``https://nvd.nist.gov/feeds/json/cve/2.0/``
are plain ``.json.gz`` files served from the feed host (not the rate-limited
API).  They carry the *same* schema as the API 2.0 response
(``{"vulnerabilities": [{"cve": {...}}, ...]}``), so we can feed them straight
into cve-bin-tool's own ``NVD_Source.format_data_api2`` parser and write the
result with ``CVEDB.populate_db`` — producing rows byte-identical to an api2
update, with no schema guessing and no fork of cve-bin-tool.

cve-bin-tool 3.4's built-in ``json-nvd`` / ``json-mirror`` routes look for the
*legacy 1.1* feeds (``nvdcve-1.1-*.meta``) which NVD retired at the end of
2023, which is why those routes now return "NVD count 0".  This importer
targets the current 2.0 feeds instead.

Network
-------
Downloads honour ``HTTPS_PROXY`` / ``HTTP_PROXY`` from the environment (urllib
reads them automatically), matching how the rest of the stack reaches the
internet through the contour proxy.

Usage
-----
    python nvd_feed_import.py --db-root /path/to/.cache/cve-bin-tool \
        [--start-year 2002] [--end-year 2026] [--no-modified] \
        [--feed-base URL] [--timeout 300]

``--db-root`` is the candidate ``.cache/cve-bin-tool`` directory that the
cve-bin-tool wrapper later audits/activates; the script writes ``cve.db``
there.
"""

import argparse
import contextlib
import gzip
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
try:
    from datetime import UTC  # py3.11+
except ImportError:
    from datetime import timezone as _tz

    UTC = _tz.utc  # noqa: UP017
from datetime import datetime

DEFAULT_FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"

# nvd.nist.gov's WAF tarpits/blocks unknown User-Agents (a non-browser UA can
# hang indefinitely), so present a browser-like UA — the same host the user's
# browser reaches fine.
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


def feed_names(start_year: int, end_year: int, include_modified: bool) -> list[str]:
    names = [f"nvdcve-2.0-{y}" for y in range(start_year, end_year + 1)]
    if include_modified:
        # "modified" carries the last 8 days of adds/changes (every ~2h); it
        # makes a year-feed import current without re-pulling everything.
        names.append("nvdcve-2.0-modified")
    return names


def _local_source(url: str) -> str | None:
    """Return a local filesystem path if ``url`` points at a local file, else
    None.  Lets a manually-downloaded feed dir be imported with no network and
    no curl in the image (``--feed-base file:///workspace/artifacts/nvd-feeds``
    or a plain directory path)."""
    if url.startswith("file://"):
        return url[len("file://") :]
    if url.startswith("/") or (len(url) > 1 and url[1] == ":"):  # POSIX or Windows path
        return url
    return None


def download(url: str, timeout: int, dest: str) -> None:
    """Fetch ``url`` to ``dest``.

    Local files (``file://`` or a plain path) are copied directly — no network,
    no curl needed.  Remote URLs use curl, which honours
    ``ALL_PROXY=socks5h://...`` — the SOCKS5 proxy the browser uses — that
    urllib cannot speak (urllib only does HTTP proxies, and the HTTP side of the
    mixed inbound hangs).  If curl is missing, fall back to urllib (works for a
    direct/HTTP-proxy egress, but not SOCKS).
    """
    src = _local_source(url)
    if src is not None:
        shutil.copyfile(src, dest)
        return

    if shutil.which("curl"):
        proxy = os.environ.get("ALL_PROXY") or os.environ.get("all_proxy") or ""  # noqa: SIM112
        cmd = [
            "curl",
            "-fsS",
            "--connect-timeout",
            "30",
            "--max-time",
            str(timeout),
            "--retry",
            "2",
            "--retry-delay",
            "3",
            "-A",
            BROWSER_UA,
            "-o",
            dest,
        ]
        if proxy:
            cmd += ["--proxy", proxy]
        cmd.append(url)
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return

    # Last resort: urllib (no SOCKS support — only works on direct/HTTP-proxy).
    import urllib.request

    req = urllib.request.Request(url, headers={"User-Agent": BROWSER_UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp, open(dest, "wb") as fh:  # nosec B310
        shutil.copyfileobj(resp, fh)


def log(msg: str) -> None:
    print(msg, flush=True)


def _shim_nvd_source_logger(src: object) -> None:
    """Work around cve-bin-tool 3.4's mixed LOGGER/logger usage.

    NVD_Source.format_data_api2() uses ``self.LOGGER`` on the happy path but
    calls ``self.logger.debug(...)`` when it encounters an invalid severity or
    score.  Some current NVD 2.0 feed entries carry ``score="unknown"``, which
    takes that branch and crashes with AttributeError before the parser can
    downgrade the score to ``"invalid"``.  Keep the workaround local to this
    importer rather than forking cve-bin-tool.
    """
    if hasattr(src, "LOGGER") and not hasattr(src, "logger"):
        src.logger = src.LOGGER


def _format_data_api2_safe(src: object, all_cve_entries: list[dict]) -> tuple[list[dict], list[dict]]:
    """Local copy of cve-bin-tool 3.4's NVD api2 formatter with two fixes:

    1. mixed ``LOGGER``/``logger`` usage for invalid score/severity branches;
    2. invalid-score debug path referencing ``cve['id']`` instead of ``cve['ID']``.

    Keep the logic otherwise aligned with upstream so we only isolate the
    broken NVD feed-import path.
    """
    cve_data: list[dict] = []
    affects_data: list[dict] = []

    logger = getattr(src, "LOGGER", None) or getattr(src, "logger", None)
    if logger is not None:
        logger.debug(f"Process vuln data - {len(all_cve_entries)} entries")

    for cve_element in all_cve_entries:
        cve_item = cve_element["cve"]

        cve = {
            "ID": cve_item["id"],
            "description": cve_item["descriptions"][0]["value"],
            "severity": "unknown",
            "score": "unknown",
            "CVSS_version": "unknown",
            "CVSS_vector": "unknown",
            "last_modified": (
                cve_item["lastModified"] if cve_item.get("lastModified", None) else cve_item["published"]
            ),
        }
        if cve["description"].startswith("** REJECT **"):
            continue

        if "impact" in cve_item:
            if "baseMetricV3" in cve_item["impact"]:
                cve["CVSS_version"] = 3
                if "cvssV3" in cve_item["impact"]["baseMetricV3"]:
                    cve["severity"] = cve_item["impact"]["baseMetricV3"]["cvssV3"].get(
                        "baseSeverity", "UNKNOWN"
                    )
                    cve["score"] = cve_item["impact"]["baseMetricV3"]["cvssV3"].get("baseScore", 0)
                    cve["CVSS_vector"] = cve_item["impact"]["baseMetricV3"]["cvssV3"].get("vectorString", "")
            elif "baseMetricV2" in cve_item["impact"]:
                cve["CVSS_version"] = 2
                cve["severity"] = cve_item["impact"]["baseMetricV2"].get("severity", "UNKNOWN")
                if "cvssV2" in cve_item["impact"]["baseMetricV2"]:
                    cve["score"] = cve_item["impact"]["baseMetricV2"]["cvssV2"].get("baseScore", 0)
                    cve["CVSS_vector"] = cve_item["impact"]["baseMetricV2"]["cvssV2"].get("vectorString", "")
        elif "metrics" in cve_item:
            cve_cvss = cve_item["metrics"]
            cvss_available = True
            if "cvssMetricV31" in cve_cvss:
                cvss_data = cve_cvss["cvssMetricV31"][0]["cvssData"]
                cve["CVSS_version"] = 3
            elif "cvssMetricV30" in cve_cvss:
                cvss_data = cve_cvss["cvssMetricV30"][0]["cvssData"]
                cve["CVSS_version"] = 3
            elif "cvssMetricV2" in cve_cvss:
                cvss_data = cve_cvss["cvssMetricV2"][0]["cvssData"]
                cve["CVSS_version"] = 2
            else:
                cvss_available = False
            if cvss_available:
                cve["severity"] = cvss_data.get("baseSeverity", "UNKNOWN")
                cve["score"] = cvss_data.get("baseScore", 0)
                cve["CVSS_vector"] = cvss_data.get("vectorString", "")

        if not cve["severity"].isalnum():
            if logger is not None:
                logger.debug(f"Severity for {cve['ID']} is invalid: {cve['severity']}")
            cve["severity"] = re.sub(r"[\W]", "", cve["severity"])

        try:
            cve["score"] = float(cve["score"])
        except (TypeError, ValueError):
            if logger is not None:
                logger.debug(f"Score for {cve['ID']} is invalid: {cve['score']}")
            cve["score"] = "invalid"

        cve["CVSS_vector"] = re.sub("[^A-Za-z0-9:/]", "", cve["CVSS_vector"])
        cve_data.append(cve)

        affects_list: list[dict] = []
        if "configurations" in cve_item:
            for configuration in cve_item["configurations"]:
                for node in configuration["nodes"]:
                    if logger is not None:
                        logger.debug(f"Processing {node} for {cve_item['id']}")
                    affects_list.extend(src.parse_node_api2(node))
                    if "children" in node:
                        for child in node["children"]:
                            affects_list.extend(src.parse_node_api2(child))
        else:
            if logger is not None:
                logger.debug(f"No configuration information for {cve_item['id']}")
        for affects in affects_list:
            affects["cve_id"] = cve["ID"]
        affects_data.extend(affects_list)

    return cve_data, affects_data


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--db-root",
        required=True,
        help="candidate .cache/cve-bin-tool dir to write cve.db into",
    )
    ap.add_argument("--start-year", type=int, default=2002)
    ap.add_argument("--end-year", type=int, default=datetime.now(UTC).year)
    ap.add_argument(
        "--no-modified",
        action="store_true",
        help="skip the nvdcve-2.0-modified incremental feed",
    )
    ap.add_argument("--feed-base", default=os.environ.get("NVD_FEED_BASE", DEFAULT_FEED_BASE))
    ap.add_argument("--timeout", type=int, default=int(os.environ.get("NVD_FEED_TIMEOUT", "300")))
    ap.add_argument(
        "--min-cves",
        type=int,
        default=1000,
        help="fail if fewer than this many CVEs were downloaded (sanity gate)",
    )
    args = ap.parse_args()

    # Point cve-bin-tool's CVEDB at the candidate cache root.  CVEDB derives
    # its cachedir from XDG_CACHE_HOME/cve-bin-tool, so set it BEFORE importing.
    db_root = os.path.abspath(args.db_root)  # .../.cache/cve-bin-tool
    xdg = os.path.dirname(db_root)  # .../.cache
    os.environ["XDG_CACHE_HOME"] = xdg
    os.makedirs(db_root, exist_ok=True)

    try:
        from cve_bin_tool.cvedb import CVEDB
        from cve_bin_tool.data_sources.nvd_source import NVD_Source
    except Exception as exc:  # pragma: no cover - import guard
        log(f"[feed] ERROR: cannot import cve_bin_tool ({exc!r})")
        return 3

    names = feed_names(args.start_year, args.end_year, not args.no_modified)
    log(
        f"[feed] importing NVD 2.0 feeds {args.start_year}-{args.end_year}"
        f"{' + modified' if not args.no_modified else ''} from {args.feed_base}"
    )
    base_is_local = _local_source(f"{args.feed_base}/x") is not None
    if base_is_local:
        log(f"[feed] downloader: local files from {args.feed_base} (no network)")
    elif shutil.which("curl"):
        proxy = os.environ.get("ALL_PROXY") or os.environ.get("all_proxy") or "(direct)"  # noqa: SIM112
        log(f"[feed] downloader: curl  proxy(ALL_PROXY): {proxy}")
    else:
        log(
            "[feed] WARN: curl not in image and feed-base is remote — falling back "
            "to urllib, which cannot use a SOCKS proxy.  If this hangs/fails, either "
            "rebuild the image (adds curl) or download feeds on the host and pass "
            "--feed-base file:///workspace/artifacts/nvd-feeds."
        )

    entries: list = []
    failures: list[str] = []
    t0 = time.time()
    n_feeds = len(names)
    tmpd = tempfile.mkdtemp(prefix="nvdfeed-")

    def emit_progress(done_feeds: float) -> None:
        # "X MiB / Y MiB" form is what the dashboard's barrel-progress parser
        # reads (orchestrator.parse_progress); the unit is feeds-as-MiB so the
        # barrel climbs 0->100% across the whole feed set.
        print(
            f"[feed] progress {done_feeds:.3f} MiB / {n_feeds:.3f} MiB "
            f"({done_feeds / n_feeds * 100:.1f}% overall)",
            flush=True,
        )

    try:
        for idx, name in enumerate(names):
            url = f"{args.feed_base}/{name}.json.gz"
            dest = os.path.join(tmpd, f"{name}.json.gz")
            emit_progress(idx)  # step at the start of each feed
            try:
                download(url, args.timeout, dest)
                with gzip.open(dest, "rb") as fh:
                    data = json.load(fh)
            except subprocess.CalledProcessError as exc:
                err = (exc.stderr or "").strip()[:200]
                log(f"[feed] WARN failed {name}: curl rc={exc.returncode} {err}")
                failures.append(name)
                continue
            except Exception as exc:
                log(f"[feed] WARN failed {name}: {exc}")
                failures.append(name)
                continue
            finally:
                with contextlib.suppress(OSError):
                    os.remove(dest)
            vulns = data.get("vulnerabilities") or []
            entries.extend(vulns)
            log(f"[feed]   {name}: {len(vulns):>6} CVEs  (total {len(entries)})")
            emit_progress(idx + 1)  # step at the end of each feed
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)

    if len(entries) < args.min_cves:
        log(
            f"[feed] ERROR: only {len(entries)} CVEs downloaded "
            f"(< --min-cves {args.min_cves}); aborting — likely proxy/network."
        )
        return 2

    src = NVD_Source(nvd_type="api2")
    _shim_nvd_source_logger(src)
    severity_data, affected_data = _format_data_api2_safe(src, entries)
    log(
        f"[feed] parsed {len(entries)} entries -> "
        f"{len(severity_data)} severity rows, {len(affected_data)} affected rows"
    )

    db = CVEDB(cachedir=db_root)
    os.makedirs(os.path.dirname(db.dbpath), exist_ok=True)
    db.data = [((severity_data, affected_data), "NVD")]
    db.init_database()
    db.populate_db()
    dt = time.time() - t0

    log(
        f"[feed] wrote NVD data into {db.dbpath} in {dt:.1f}s"
        + (f"  (failed feeds: {', '.join(failures)})" if failures else "")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
