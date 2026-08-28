#!/usr/bin/env python3
"""Apply targeted fixes to cve-bin-tool 3.4's broken EPSS enrichment source.

Run at image-build time (Dockerfile.cve-bin-tool) right after
`pip install cve-bin-tool==3.4`.  3.4 is the latest PyPI release, so there is
no version to bump to; these are upstream bugs that fire on *every* machine
and every code path (proven on 10.2.108.47), which is why OSV/EPSS/PURL2CPE
were disabled via CVE_BIN_TOOL_ENRICH_DISABLE.

Wrapper-first project rule: we do NOT fork cve-bin-tool.  This patcher only
repairs the specific breakages in-place and reuses cve-bin-tool's own
download/parse/store -- so the data stays upstream's, not ours.

Each fix is idempotent and *verified*: if the exact target text is missing
(e.g. a future version moved the code), the build FAILS loudly instead of
silently shipping an unpatched image.  After patching, the offline
end-to-end check scripts/patches/verify_cve_bin_tool_epss_fix.py gates the
image build.

The bug (two layers, both proven offline: tests/test_cve_bin_tool_epss_fixups.py)
----------------------------------------------------------------------------------
1. TypeError -- ``get_cve_data()`` calls ``await self.update_epss()`` but the
   3.4 signature is ``update_epss(self, cursor)``; the broad ``except`` hides
   the crash ("Unable to fetch EPSS, skipping EPSS."), so EPSS silently never
   loads.
2. Ordering (root cause) -- even with a cursor, ``EPSS_id_finder()`` SELECTs
   from the ``metrics`` table during the source gather
   (``refresh_cache_and_update_db()`` -> ``refresh()`` -> ``get_data()``,
   cvedb.py:401), which runs BEFORE ``populate_db()`` ->
   ``populate_metrics()`` (cvedb.py:470) inserts the (1,'EPSS') row.  Fresh
   cache -> ``sqlite3.OperationalError: no such table: metrics``; created but
   still-empty table -> ``IndexError`` from ``fetchall()[0][0]``.

The fix (backport of upstream's own solution, not a local invention)
---------------------------------------------------------------------
Upstream (repo moved intel/ -> ossf/cve-bin-tool) already fixed this on
``main`` -- the "metric ids as constants" change (~PR #4473), merged in 2025
-- but never shipped a release with it: the latest tag is still v3.4 and the
latest PyPI stable is 3.4 (3.4.1rc0 of 2025-06-13 contains the fix but is an
RC).  Earlier revisions of this patcher fixed the same two layers with a
local reorder (hoisting populate_metrics() before the gather) plus a
cursor-shim; that worked, but diverged from upstream.  This revision
backports upstream's actual fix so our 3.4 behaves exactly like main /
3.4.1rc0:

* cvedb.py gains module-level constants (EPSS_METRIC_ID = 1, CVSS_2/3_...)
  and populate_metrics() uses them;
* epss_source.py: update_epss() loses the ``cursor`` parameter,
  ``EPSS_id_finder()`` is deleted, and parse_epss_data() tags rows with
  EPSS_METRIC_ID directly (lazy import to avoid a circular dependency).

After this the download phase never touches the database, so the ordering
bug disappears as a class.  On a version bump to >= 3.4.1 the targets below
will be missing and every fix reports "already-patched"/fails loudly --
at that point simply drop this file from the build.

See docs/upstream/STATUS.md for the upstream situation and the
release-request issue template.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _cvebt_dir() -> Path:
    import cve_bin_tool

    return Path(cve_bin_tool.__file__).parent


def _replace_once(path: Path, old: str, new: str, *, marker: str) -> str:
    text = path.read_text(encoding="utf-8")
    if marker in text:
        return "already-patched"
    if old not in text:
        raise SystemExit(
            f"PATCH FAILED: expected text not found in {path.name}; "
            f"cve-bin-tool internals changed -- review scripts/patches/ before building.\n"
            f"--- expected ---\n{old}"
        )
    if text.count(old) != 1:
        raise SystemExit(f"PATCH FAILED: {path.name}: expected exactly 1 match, found {text.count(old)}")
    path.write_text(text.replace(old, new), encoding="utf-8")
    return "patched"


def fix_cvedb_metric_constants() -> str:
    """cvedb.py: module-level metric id constants (upstream main backport)."""
    path = _cvebt_dir() / "cvedb.py"

    old_anchor = 'OLD_CACHE_DIR = Path("~") / ".cache" / "cvedb"\n'
    new_anchor = (
        'OLD_CACHE_DIR = Path("~") / ".cache" / "cvedb"\n'
        "\n"
        "# PATCH(el-sca): metric ids as module-level constants -- backport of the\n"
        "# upstream fix (ossf/cve-bin-tool main, merged 2025, unreleased).  Must\n"
        "# match the rows populate_metrics() inserts into the metrics table.\n"
        "EPSS_METRIC_ID = 1\n"
        "CVSS_2_METRIC_ID = 2\n"
        "CVSS_3_METRIC_ID = 3\n"
    )
    part1 = _replace_once(
        path,
        old_anchor,
        new_anchor,
        marker="PATCH(el-sca): metric ids as module-level constants",
    )

    old_data = (
        "        data = [\n"
        '            (1, "EPSS"),\n'
        '            (2, "CVSS-2"),\n'
        '            (3, "CVSS-3"),\n'
        "        ]\n"
    )
    new_data = (
        "        data = [\n"
        '            (EPSS_METRIC_ID, "EPSS"),\n'
        '            (CVSS_2_METRIC_ID, "CVSS-2"),\n'
        '            (CVSS_3_METRIC_ID, "CVSS-3"),\n'
        "        ]\n"
    )
    part2 = _replace_once(path, old_data, new_data, marker='(EPSS_METRIC_ID, "EPSS"),')

    if part1 == part2 == "already-patched":
        return "already-patched"
    return "patched"


def fix_epss_source() -> str:
    """epss_source.py: no cursor, no DB reads mid-fetch (upstream main backport)."""
    path = _cvebt_dir() / "data_sources" / "epss_source.py"

    # (a) __init__: drop the now-unused epss_metric_id attribute.
    old_init = (
        '        self.file_name = os.path.join(self.epss_path, "epss_scores-current.csv")\n'
        "        self.epss_metric_id = None\n"
    )
    new_init = (
        '        self.file_name = os.path.join(self.epss_path, "epss_scores-current.csv")\n'
        "        # PATCH(el-sca): epss_metric_id attribute removed -- rows are tagged\n"
        "        # with cvedb.EPSS_METRIC_ID (upstream main backport).\n"
    )
    a = _replace_once(path, old_init, new_init, marker="PATCH(el-sca): epss_metric_id attribute removed")

    # (b) update_epss: drop the cursor parameter -- the 3.4 call site invokes
    # update_epss() with no arguments, so every EPSS update died with a
    # swallowed TypeError.
    old_sig = "    async def update_epss(self, cursor):\n"
    new_sig = (
        "    # PATCH(el-sca): cursor parameter removed (upstream main backport).\n"
        "    async def update_epss(self):\n"
    )
    b = _replace_once(path, old_sig, new_sig, marker="PATCH(el-sca): cursor parameter removed")

    # (c) no DB lookup during the fetch phase.
    old_fetch = (
        '        self.LOGGER.debug("Fetching EPSS data...")\n'
        "\n"
        "        self.EPSS_id_finder(cursor)\n"
        "        await self.download_epss_data()\n"
    )
    new_fetch = (
        '        self.LOGGER.debug("Fetching EPSS data...")\n'
        "\n"
        "        # PATCH(el-sca): EPSS_id_finder(cursor) call removed -- the fetch\n"
        "        # phase must not touch the database (upstream main backport).\n"
        "        await self.download_epss_data()\n"
    )
    c = _replace_once(path, old_fetch, new_fetch, marker="PATCH(el-sca): EPSS_id_finder(cursor) call removed")

    # (d) delete the EPSS_id_finder method entirely.
    old_finder = (
        "    def EPSS_id_finder(self, cursor):\n"
        '        """Search for metric id in EPSS table"""\n'
        '        query = """\n'
        "        SELECT metrics_id FROM metrics\n"
        '        WHERE metrics_name = "EPSS"\n'
        '        """\n'
        "        cursor.execute(query)\n"
        "        self.epss_metric_id = cursor.fetchall()[0][0]\n"
        "\n"
    )
    new_finder = "    # PATCH(el-sca): EPSS_id_finder() deleted (upstream main backport).\n\n"
    d = _replace_once(path, old_finder, new_finder, marker="PATCH(el-sca): EPSS_id_finder() deleted")

    # (e) parse_epss_data(): tag rows with the constant, not a DB-resolved id.
    old_parse = (
        "            cve_id, epss_score, epss_percentile = row[:3]\n"
        "            parsed_data.append(\n"
        "                (cve_id, self.epss_metric_id, epss_score, epss_percentile)\n"
        "            )\n"
    )
    new_parse = (
        "            cve_id, epss_score, epss_percentile = row[:3]\n"
        "\n"
        "            # PATCH(el-sca): rows tagged with the module-level constant\n"
        "            # (upstream main backport); local import avoids a circular\n"
        "            # dependency between cvedb and the data sources.\n"
        "            from cve_bin_tool.cvedb import EPSS_METRIC_ID\n"
        "\n"
        "            parsed_data.append((cve_id, EPSS_METRIC_ID, epss_score, epss_percentile))\n"
    )
    e = _replace_once(
        path, old_parse, new_parse, marker="PATCH(el-sca): rows tagged with the module-level constant"
    )

    results = (a, b, c, d, e)
    if all(r == "already-patched" for r in results):
        return "already-patched"
    return "patched"


def fix_epss_hardening() -> str:
    """Hardening on top of the backport: current CDN + mirror fallback,
    visible failure reasons, tolerant parser, and a store that can never
    abort the whole cve.db update.  Targets the post-backport text, so this
    must run after fix_epss_source()."""
    path = _cvebt_dir() / "data_sources" / "epss_source.py"

    # (a) current EPSS home + fallback mirror.  Upstream main moved to
    # empiricalsecurity.com after 3.4.1rc0; cyentia.com is kept as backup.
    old_url = '    DATA_SOURCE_LINK = "https://epss.cyentia.com/epss_scores-current.csv.gz"\n'
    new_url = (
        "    # PATCH(el-sca): empiricalsecurity.com is the current home of EPSS\n"
        "    # data (upstream main moved off cyentia after 3.4.1rc0); cyentia is\n"
        "    # kept as a fallback mirror.\n"
        '    DATA_SOURCE_LINK = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"\n'
        '    BACKUP_DATA_SOURCE_LINK = "https://epss.cyentia.com/epss_scores-current.csv.gz"\n'
    )
    a = _replace_once(
        path, old_url, new_url, marker="PATCH(el-sca): empiricalsecurity.com is the current home"
    )

    # (b) deduplicate the two copy-pasted download blocks into helpers with
    # mirror fallback.
    old_dl = (
        "    async def download_epss_data(self):\n"
        '        """Downloads the EPSS CSV file and saves it to the local filesystem.\n'
        "        The download is only performed if the file is older than 24 hours.\n"
        '        """\n'
        "        os.makedirs(self.epss_path, exist_ok=True)\n"
        "        # Check if the file exists\n"
        "        if os.path.exists(self.file_name):\n"
        "            # Get the modification time of the file\n"
        "            modified_time = os.path.getmtime(self.file_name)\n"
        "            last_modified = datetime.fromtimestamp(modified_time)\n"
        "\n"
        "            # Calculate the time difference between now and the last modified time\n"
        "            time_difference = datetime.now() - last_modified\n"
        "\n"
        "            # Check if the file is older than 24 hours\n"
        "            if time_difference > timedelta(hours=24):\n"
        "                try:\n"
        "                    async with aiohttp.ClientSession(\n"
        "                        headers=HTTP_HEADERS, trust_env=True\n"
        "                    ) as session:\n"
        "                        async with session.get(self.DATA_SOURCE_LINK) as response:\n"
        "                            response.raise_for_status()\n"
        '                            self.LOGGER.info("Getting EPSS data...")\n'
        "                            decompressed_data = gzip.decompress(await response.read())\n"
        "\n"
        "                    # Save the downloaded data to the file\n"
        '                    with open(self.file_name, "wb") as file:\n'
        "                        file.write(decompressed_data)\n"
        "\n"
        "                except aiohttp.ClientError as e:\n"
        '                    self.LOGGER.error(f"An error occurred during updating epss {e}")\n'
        "\n"
        "            else:\n"
        "                self.LOGGER.info(\n"
        '                    "Utilizing the latest cache of EPSS data, which is less than 24 hours old."\n'
        "                )\n"
        "\n"
        "        else:\n"
        "            try:\n"
        "                async with aiohttp.ClientSession(\n"
        "                    headers=HTTP_HEADERS, trust_env=True\n"
        "                ) as session:\n"
        "                    async with session.get(self.DATA_SOURCE_LINK) as response:\n"
        "                        response.raise_for_status()\n"
        '                        self.LOGGER.info("Getting EPSS data...")\n'
        "                        decompressed_data = gzip.decompress(await response.read())\n"
        "\n"
        "                # Save the downloaded data to the file\n"
        '                with open(self.file_name, "wb") as file:\n'
        "                    file.write(decompressed_data)\n"
        "\n"
        "            except aiohttp.ClientError as e:\n"
        '                self.LOGGER.error(f"An error occurred during downloading epss {e}")\n'
    )
    new_dl = (
        "    # PATCH(el-sca): download deduplicated into helpers with mirror fallback.\n"
        "    async def _fetch_epss_csv(self, url):\n"
        '        """Download and decompress the EPSS CSV file from one URL."""\n'
        "        async with aiohttp.ClientSession(\n"
        "            headers=HTTP_HEADERS, trust_env=True\n"
        "        ) as session:\n"
        "            async with session.get(url) as response:\n"
        "                response.raise_for_status()\n"
        '                self.LOGGER.info(f"Getting EPSS data from {url}")\n'
        "                return gzip.decompress(await response.read())\n"
        "\n"
        "    async def _download_and_save(self):\n"
        '        """Try each EPSS mirror in order and store the first successful result."""\n'
        "        last_error = None\n"
        "        for url in (self.DATA_SOURCE_LINK, self.BACKUP_DATA_SOURCE_LINK):\n"
        "            try:\n"
        "                decompressed_data = await self._fetch_epss_csv(url)\n"
        '                with open(self.file_name, "wb") as file:\n'
        "                    file.write(decompressed_data)\n"
        "                return\n"
        "            except (aiohttp.ClientError, gzip.BadGzipFile, OSError) as e:\n"
        "                last_error = e\n"
        '                self.LOGGER.warning(f"EPSS download failed from {url}: {e!r}")\n'
        '        self.LOGGER.error(f"An error occurred during updating epss {last_error}")\n'
        "\n"
        "    async def download_epss_data(self):\n"
        '        """Downloads the EPSS CSV file and saves it to the local filesystem.\n'
        "        The download is only performed if the file is older than 24 hours.\n"
        '        """\n'
        "        os.makedirs(self.epss_path, exist_ok=True)\n"
        "        # Check if the file exists\n"
        "        if os.path.exists(self.file_name):\n"
        "            # Get the modification time of the file\n"
        "            modified_time = os.path.getmtime(self.file_name)\n"
        "            last_modified = datetime.fromtimestamp(modified_time)\n"
        "\n"
        "            # Calculate the time difference between now and the last modified time\n"
        "            time_difference = datetime.now() - last_modified\n"
        "\n"
        "            # Check if the file is older than 24 hours\n"
        "            if time_difference > timedelta(hours=24):\n"
        "                await self._download_and_save()\n"
        "            else:\n"
        "                self.LOGGER.info(\n"
        '                    "Utilizing the latest cache of EPSS data, which is less than 24 hours old."\n'
        "                )\n"
        "        else:\n"
        "            await self._download_and_save()\n"
    )
    b = _replace_once(
        path, old_dl, new_dl, marker="PATCH(el-sca): download deduplicated into helpers"
    )

    # (c) tolerate malformed CSV rows instead of crashing on unpack.
    old_rows = (
        "        for row in reader:\n"
        "            cve_id, epss_score, epss_percentile = row[:3]\n"
    )
    new_rows = (
        "        for row in reader:\n"
        "            # PATCH(el-sca): skip malformed rows instead of crashing on unpack.\n"
        "            if len(row) < 3:\n"
        '                self.LOGGER.debug(f"Skipping malformed EPSS row: {row!r}")\n'
        "                continue\n"
        "            cve_id, epss_score, epss_percentile = row[:3]\n"
    )
    c = _replace_once(
        path, old_rows, new_rows, marker="PATCH(el-sca): skip malformed rows"
    )

    # (d) make the real failure reason visible -- the 3.4 TypeError went
    # unnoticed precisely because this line hid it.
    old_log = '            self.LOGGER.error("Unable to fetch EPSS, skipping EPSS.")\n'
    new_log = (
        "            # PATCH(el-sca): log the actual exception, not just the fact.\n"
        '            self.LOGGER.error(f"Unable to fetch EPSS ({e!r}), skipping EPSS.")\n'
    )
    d = _replace_once(
        path, old_log, new_log, marker="PATCH(el-sca): log the actual exception"
    )

    # (e) cvedb.store_epss_data(): EPSS is auxiliary data -- a failure here
    # must never abort the whole cve.db update.
    cvedb_path = _cvebt_dir() / "cvedb.py"
    old_store = (
        '        insert_cve_metrics = self.INSERT_QUERIES["insert_cve_metrics"]\n'
        "        cursor = self.db_open_and_get_cursor()\n"
        "        cursor.executemany(insert_cve_metrics, epss_data)\n"
        "        self.connection.commit()\n"
        "        self.db_close()\n"
    )
    new_store = (
        '        insert_cve_metrics = self.INSERT_QUERIES["insert_cve_metrics"]\n'
        "        cursor = self.db_open_and_get_cursor()\n"
        "        # PATCH(el-sca): EPSS is auxiliary data -- a failure here must never\n"
        "        # abort the whole cve.db update.\n"
        "        try:\n"
        "            cursor.executemany(insert_cve_metrics, epss_data)\n"
        "            self.connection.commit()\n"
        "        except Exception as e:\n"
        '            LOGGER.error(f"Unable to insert EPSS data: {e!r}")\n'
        "        finally:\n"
        "            self.db_close()\n"
    )
    e = _replace_once(
        cvedb_path, old_store, new_store, marker="PATCH(el-sca): EPSS is auxiliary data"
    )

    results = (a, b, c, d, e)
    if all(r == "already-patched" for r in results):
        return "already-patched"
    return "patched"


def main() -> int:
    results = {
        "cvedb_metric_constants": fix_cvedb_metric_constants(),
        "epss_source": fix_epss_source(),
        "epss_hardening": fix_epss_hardening(),
    }
    print("[cve-bin-tool 3.4 fixups]", results)
    if all(v == "already-patched" for v in results.values()) and os.environ.get("CVEBT_PATCH_STRICT"):
        print(
            "WARNING: every fix already applied -- unexpected on a clean install",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
