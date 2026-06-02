from __future__ import annotations

import json
import os
import tarfile
from argparse import ArgumentParser

try:
    from datetime import UTC  # py3.11+
except ImportError:
    from datetime import timezone as _tz
    UTC = _tz.utc  # noqa: UP017
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from ._retry import RetryPolicy
from .artifact_store import build_last_known_good, ensure_directory, file_sha256
from .atomic_publish import publish_directory
from .config import (
    DEFAULT_CONFIG_PATH,
    load_config,
    parse_duration_hours,
    parse_proxy_config,
    validate_config_data,
)
from .cve_db_audit import activate_best_cve_bin_tool_db, audit_cve_bin_tool_db, seed_cve_bin_tool_aux_sources
from .extractor import extract_artifacts
from .fallback import AttemptResult, FailureReason, attempt_sources, build_session, fetch_bytes
from .healthcheck import run_healthcheck
from .provenance import write_provenance
from .reporting import build_report
from .source_policy import build_sources

EXIT_SUCCESS = 0
EXIT_CONFIG_ERROR = 1
EXIT_ALL_SOURCES_FAILED = 2
EXIT_VALIDATION_FAILED = 3
EXIT_STALE_REJECTED = 4
EXIT_LKG_USED = 5


def _dedup_attempted_sources(attempts: list[AttemptResult]) -> list[dict[str, Any]]:
    """Collapse retries into one record per source, accumulating attempt metadata.

    Each returned dict is the source's ``to_dict()`` output extended with:
    - ``retry_count``  — total number of attempts made against this source.
    - ``succeeded``    — True if any attempt for this source succeeded.
    - ``outcomes``     — ordered list of per-attempt outcome dicts
                         ``{success, reason, message, status_code}``.
    """
    # Preserve insertion order (first time a source is seen).
    seen: dict[str, dict[str, Any]] = {}
    for item in attempts:
        name = item.source.name
        if name not in seen:
            seen[name] = {**item.source.to_dict(), "retry_count": 0, "succeeded": False, "outcomes": []}
        rec = seen[name]
        rec["retry_count"] += 1
        if item.success:
            rec["succeeded"] = True
        rec["outcomes"].append(
            {
                "success": item.success,
                "reason": item.reason.value if item.reason is not None else None,
                "message": item.message,
                "status_code": item.status_code,
            }
        )
    return list(seen.values())


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _safe_exists(path: Path) -> bool:
    """``Path.exists`` that treats an unreadable parent as "absent".

    Under a non-root container user (``USER appuser`` in our Dockerfiles),
    probing a root-owned default path such as ``/root/.cache/cve-bin-tool``
    raises ``PermissionError`` instead of returning ``False``.  Swallow that so
    ``db-status`` / ``render-flags`` degrade gracefully instead of crashing.
    """
    try:
        return path.exists()
    except OSError:
        return False


def _safe_is_dir(path: Path) -> bool:
    """``Path.is_dir`` variant that survives an unreadable parent (see
    :func:`_safe_exists`)."""
    try:
        return path.is_dir()
    except OSError:
        return False


def _latest_mtime(path: Path) -> float | None:
    if not _safe_exists(path):
        return None
    if path.is_file():
        return path.stat().st_mtime
    latest: float | None = None
    for item in path.rglob("*"):
        if not item.is_file():
            continue
        mtime = item.stat().st_mtime
        latest = mtime if latest is None else max(latest, mtime)
    return latest


def _db_status_payload(tool: str, path: Path, warning_age: str) -> dict[str, Any]:
    warning_hours = parse_duration_hours(warning_age)
    status_path = path
    if tool == "cve-bin-tool" and _safe_exists(path):
        cve_db = next(path.rglob("cve.db"), None) if _safe_is_dir(path) else None
        if cve_db is None:
            return {
                "tool": tool,
                "path": str(path),
                "exists": _safe_exists(path),
                "age_hours": None,
                "warning_age_hours": warning_hours,
                "warning": True,
                "message": "cve-bin-tool database is missing: cve.db was not found",
                "timestamp_utc": _now_iso(),
            }
        status_path = cve_db
    latest = _latest_mtime(status_path)
    if latest is None:
        return {
            "tool": tool,
            "path": str(path),
            "exists": _safe_exists(path),
            "age_hours": None,
            "warning_age_hours": warning_hours,
            "warning": False,
            "message": "database path is empty or missing",
            "timestamp_utc": _now_iso(),
        }
    age_hours = round((datetime.now(UTC).timestamp() - latest) / 3600, 2)
    warning = age_hours > warning_hours
    return {
        "tool": tool,
        "path": str(path),
        "exists": _safe_exists(path),
        "age_hours": age_hours,
        "warning_age_hours": warning_hours,
        "warning": warning,
        "message": (
            f"database age warning: {age_hours}h exceeds {warning_hours}h"
            if warning
            else f"database age is {age_hours}h"
        ),
        "timestamp_utc": _now_iso(),
    }


def _render_trivy_flags(config: dict[str, Any]) -> str:
    parts: list[str] = []
    for item in build_sources(config, "trivy", "trivy-db"):
        parts.append(f"--db-repository {item.url.removeprefix('oci://')}")
    for item in build_sources(config, "trivy", "trivy-java-db"):
        parts.append(f"--java-db-repository {item.url.removeprefix('oci://')}")
    for item in build_sources(config, "trivy", "trivy-checks"):
        parts.append(f"--checks-bundle-repository {item.url.removeprefix('oci://')}")
    # VEX layer (ADR-0003): apply published VEX docs only when the policy is
    # enabled and at least one doc has been fetched to <cache_dir>/vex/.  When
    # unconfigured this is a no-op, so existing scans are unaffected.
    trivy_cfg = config.get("trivy", {})
    if trivy_cfg.get("vex_policy", {}).get("enabled"):
        vex_dir = Path(trivy_cfg.get("cache_dir", "/var/lib/resilient-db/trivy")) / "vex"
        if _safe_is_dir(vex_dir):
            for doc in sorted(vex_dir.glob("*")):
                if doc.is_file():
                    parts.append(f"--vex {doc}")
    return " ".join(parts)


def _provenance_path(config: dict[str, Any], tool: str) -> Path:
    if tool == "grype":
        return Path(config["grype"]["atomic_activation_policy"]["provenance_path"])
    return Path("artifacts/provenance") / f"{tool}.json"


def _health_probe_sources(sources):
    """Healthcheck-only: rewrite ``oci://`` sources to the registry https ``/v2/``
    ping.  ``requests`` cannot fetch ``oci://`` (it raises ``invalid_schema``);
    the real DB pull is delegated to the scanner binary's OCI client.  A 401 from
    the rewritten probe means "registry reachable, auth handled by the tool" — far
    clearer than "No connection adapters for oci://".  See ADR-0007 §D1."""
    from dataclasses import replace

    from .update_doctor import _probe_url_for

    out = []
    for src in sources:
        probe = _probe_url_for(src.url)
        out.append(replace(src, url=probe) if probe and probe != src.url else src)
    return out


def _health_summary(
    config: dict[str, Any],
    tool: str,
    layer: str,
    timeout: int,
    retry_count: int,
    backoff_seconds: int,
    retry_codes: list[int],
    session: requests.Session | None = None,
) -> tuple[int, dict[str, Any]]:
    source, _payload, attempts = attempt_sources(
        _health_probe_sources(build_sources(config, tool, layer)),
        timeout=timeout,
        retry_count=retry_count,
        backoff_seconds=backoff_seconds,
        retry_status_codes=retry_codes,
        session=session,
    )
    payload = {
        "tool": tool,
        "artifact_type": layer,
        "selected_source": source.to_dict() if source else None,
        "attempted_sources": _dedup_attempted_sources(attempts),
        "failures": [
            {
                "source": item.source.name,
                "reason": item.reason.value if item.reason else None,
                "message": item.message,
                "status_code": item.status_code,
            }
            for item in attempts
            if not item.success
        ],
        "activation_status": "healthcheck-only",
        "used_last_known_good": False,
        "timestamp_utc": _now_iso(),
    }
    write_provenance(_provenance_path(config, tool), payload)
    return EXIT_SUCCESS if source else EXIT_ALL_SOURCES_FAILED, payload


def _download_text(url: str, timeout: int, session: requests.Session | None = None) -> str:
    status_code, payload = fetch_bytes(url, timeout, session=session)
    if status_code >= 400:
        raise ValueError(f"status {status_code}")
    return payload.decode("utf-8")


def _extract_checksum_from_text(text: str) -> str:
    return text.strip().split()[0]


def _resolve_listing(listing_bytes: bytes, base_url: str) -> tuple[str, str | None, str | None]:
    listing = json.loads(listing_bytes.decode("utf-8"))
    if "path" in listing:
        return listing["path"], listing.get("checksum"), listing.get("built")
    if "archive_url" in listing:
        return listing["archive_url"], listing.get("checksum"), listing.get("built")
    available = listing.get("available")
    if isinstance(available, dict):
        candidates = []
        for values in available.values():
            if isinstance(values, list):
                candidates.extend(values)
        if not candidates:
            raise ValueError("listing available block is empty")
        candidates.sort(key=lambda item: item.get("built", ""))
        latest = candidates[-1]
        archive_url = latest["url"]
        checksum = latest.get("checksum")
        built = latest.get("built")
        if checksum is None:
            checksum = latest.get("hash")
        return archive_url, checksum, built
    if isinstance(available, list) and available:
        latest = sorted(available, key=lambda item: item.get("built", ""))[-1]
        return latest["url"], latest.get("checksum"), latest.get("built")
    if "url" in listing:
        return listing["url"], listing.get("checksum"), listing.get("built")
    raise ValueError("unsupported grype listing schema")


def _validate_grype_archive(archive_path: Path, checksum: str | None) -> None:
    if checksum and file_sha256(archive_path) != checksum:
        raise ValueError(FailureReason.CHECKSUM_MISMATCH.value)
    if tarfile.is_tarfile(archive_path):
        return
    with archive_path.open("rb") as handle:
        magic = handle.read(4)
    if magic == b"\x28\xb5\x2f\xfd":
        return
    raise ValueError(FailureReason.CORRUPT_ARTIFACT.value)


def _download_grype_candidate(
    source,
    listing_payload: bytes,
    timeout_cfg: dict[str, Any],
    validation_cfg: dict[str, Any],
    temp_dir: Path,
    session: requests.Session | None = None,
) -> tuple[Path, str | None, str | None]:
    listing_target = temp_dir / f"{source.name}-listing.json"
    archive_target = temp_dir / f"{source.name}-db.archive"
    listing_target.write_bytes(listing_payload)
    archive_url, checksum, built = _resolve_listing(listing_payload, source.url)
    if archive_url.startswith("/") or not archive_url.startswith(("http://", "https://", "file://")):
        archive_url = urljoin(source.url, archive_url)
    if checksum is None and archive_url.startswith(("http://", "https://")):
        try:
            checksum = _extract_checksum_from_text(
                _download_text(
                    f"{archive_url}.sha256", int(timeout_cfg["update_download_timeout"]), session=session
                )
            )
        except Exception:
            checksum = None
    if validation_cfg.get("validate_hash") and not checksum:
        raise ValueError(FailureReason.CHECKSUM_MISMATCH.value)
    archive_name = Path(urlparse(archive_url).path).name or "db.archive"
    archive_target = temp_dir / f"{source.name}-{archive_name}"
    archive_status, archive_payload = fetch_bytes(
        archive_url, int(timeout_cfg["update_download_timeout"]), session=session
    )
    if archive_status >= 400:
        raise ValueError(f"http_{archive_status}")
    archive_target.write_bytes(archive_payload)
    _validate_grype_archive(archive_target, checksum if validation_cfg.get("validate_hash") else None)
    if validation_cfg.get("validate_age") and built:
        built_at = datetime.fromisoformat(built.replace("Z", "+00:00"))
        max_age_hours = parse_duration_hours(validation_cfg["max_allowed_built_age"])
        age_hours = (datetime.now(UTC) - built_at).total_seconds() / 3600
        if age_hours > max_age_hours:
            raise ValueError(FailureReason.STALE_DATA.value)
    return archive_target, checksum, built


def update_grype(config: dict[str, Any], session: requests.Session | None = None) -> int:
    timeout_cfg = config["grype"]["timeout_policy"]
    validation_cfg = config["grype"]["validation"]
    atomic_cfg = config["grype"]["atomic_activation_policy"]
    lkg_cfg = config["grype"]["last_known_good"]
    # Listing-fetch retry policy.  Lives in feed_sources.yaml under
    # grype.retry_backoff_policy; defaults match the original hardcoded
    # 1/1/[429,5xx] for forward compatibility with YAML files that
    # predate the section.  See docs/audit/20-architecture.md §2.
    grype_retry = RetryPolicy.from_tool_config(config, "grype")
    retry_codes = list(grype_retry.retry_status_codes)

    active_dir = Path(atomic_cfg["active_dir"])
    previous_dir = Path(atomic_cfg["previous_dir"])
    temp_root = ensure_directory(atomic_cfg["temp_dir"])
    temp_dir = ensure_directory(temp_root / f"run-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}")
    attempts = []
    validation_failures: list[dict[str, Any]] = []
    selected_source = None
    selected_archive = None
    built = None
    for source in build_sources(config, "grype", "grype-db"):
        candidate_source, listing_payload, source_attempts = attempt_sources(
            [source],
            # timeout for the listing probe lives in `timeout_policy` (not
            # retry_backoff_policy), because grype splits "how long do I
            # wait for the listing endpoint" from "how long do I wait for
            # the actual archive download".  retry_count / backoff /
            # status codes come from the shared RetryPolicy above.
            timeout=int(timeout_cfg["update_available_timeout"]),
            retry_count=grype_retry.retry_count,
            backoff_seconds=int(grype_retry.backoff_seconds),
            retry_status_codes=retry_codes,
            session=session,
        )
        attempts.extend(source_attempts)
        if not candidate_source or not listing_payload:
            continue
        try:
            selected_archive, _checksum, built = _download_grype_candidate(
                candidate_source,
                listing_payload,
                timeout_cfg,
                validation_cfg,
                temp_dir,
                session=session,
            )
            selected_source = candidate_source
            break
        except ValueError as exc:
            validation_failures.append(
                {
                    "source": candidate_source.name,
                    "reason": str(exc),
                    "message": str(exc),
                    "status_code": None,
                }
            )
            continue

    if not selected_source or not selected_archive:
        lkg = build_last_known_good(active_dir, lkg_cfg["max_age"])
        payload = {
            "tool": "grype",
            "artifact_type": "grype-db",
            "selected_source": None,
            "attempted_sources": _dedup_attempted_sources(attempts),
            "failures": [
                {
                    "source": item.source.name,
                    "reason": item.reason.value if item.reason else None,
                    "message": item.message,
                    "status_code": item.status_code,
                }
                for item in attempts
                if not item.success
            ]
            + validation_failures,
            "activation_status": "last-known-good" if lkg.is_usable() else "failed",
            "used_last_known_good": lkg.is_usable(),
            "timestamp_utc": _now_iso(),
        }
        write_provenance(_provenance_path(config, "grype"), payload)
        if (
            any(item["reason"] == FailureReason.STALE_DATA.value for item in validation_failures)
            and not lkg.is_usable()
        ):
            return EXIT_STALE_REJECTED
        return EXIT_LKG_USED if lkg.is_usable() else EXIT_ALL_SOURCES_FAILED

    listing_bytes = (temp_dir / f"{selected_source.name}-listing.json").read_bytes()
    archive_bytes = selected_archive.read_bytes()
    (temp_dir / "listing.json").write_bytes(listing_bytes)
    (temp_dir / "latest.json").write_bytes(listing_bytes)
    (temp_dir / "db.tar.gz").write_bytes(archive_bytes)
    (temp_dir / "db.tar.zst").write_bytes(archive_bytes)
    v6_dir = ensure_directory(temp_dir / "v6")
    (v6_dir / "latest.json").write_bytes(listing_bytes)
    (v6_dir / selected_archive.name.removeprefix(f"{selected_source.name}-")).write_bytes(archive_bytes)
    publish_directory(temp_dir, active_dir, previous_dir)
    payload = {
        "tool": "grype",
        "artifact_type": "grype-db",
        "selected_source": selected_source.to_dict(),
        "attempted_sources": _dedup_attempted_sources(attempts),
        "failures": [
            {
                "source": item.source.name,
                "reason": item.reason.value if item.reason else None,
                "message": item.message,
                "status_code": item.status_code,
            }
            for item in attempts
            if not item.success
        ],
        "checksum": file_sha256(active_dir / "db.tar.gz"),
        "size": (active_dir / "db.tar.gz").stat().st_size,
        "freshness_metadata": {"built": built},
        "activation_status": "active",
        "used_last_known_good": False,
        "timestamp_utc": _now_iso(),
    }
    write_provenance(_provenance_path(config, "grype"), payload)
    return EXIT_SUCCESS


def _cve_db_policy(config: dict[str, Any]) -> tuple[list[str], dict[str, int], str, list[str], str]:
    cve_cfg = config["cve_bin_tool"]
    db_audit = cve_cfg["db_audit"]
    required_sources = [str(item).upper() for item in db_audit.get("required_sources", [])]
    min_entries = {str(key).upper(): int(value) for key, value in db_audit.get("min_entries", {}).items()}
    max_cache_age = str(db_audit.get("max_cache_age", "168h"))
    declared_sources = [str(item).upper() for item in cve_cfg.get("data_sources", [])]
    db_policy = (
        str(os.environ.get("CVE_BIN_TOOL_DB_POLICY") or db_audit.get("db_policy", "strict")).strip().lower()
    )
    return required_sources, min_entries, max_cache_age, declared_sources, db_policy


def _run_cve_db_audit(config: dict[str, Any], db_root: str) -> tuple[int, dict[str, Any]]:
    required_sources, min_entries, max_cache_age, declared_sources, _db_policy = _cve_db_policy(config)
    payload = audit_cve_bin_tool_db(db_root, required_sources, min_entries, max_cache_age, declared_sources)
    if payload["overall_status"] == "pass":
        return EXIT_SUCCESS, payload
    stale_reasons = [item for item in payload["failures"] if "stale" in item]
    return (EXIT_STALE_REJECTED if stale_reasons else EXIT_VALIDATION_FAILED), payload


def _activate_cve_db(
    config: dict[str, Any],
    candidate_roots: list[str],
    active_root: str,
    previous_root: str,
    temp_root: str,
    provenance_path: str,
) -> tuple[int, dict[str, Any]]:
    required_sources, min_entries, max_cache_age, declared_sources, db_policy = _cve_db_policy(config)
    activated, payload = activate_best_cve_bin_tool_db(
        candidate_roots=candidate_roots,
        active_root=active_root,
        previous_root=previous_root,
        temp_root=temp_root,
        provenance_path=provenance_path,
        required_sources=required_sources,
        min_entries=min_entries,
        max_cache_age=max_cache_age,
        declared_sources=declared_sources,
        db_policy=db_policy,
    )
    if activated:
        return EXIT_SUCCESS, payload
    if payload.get("used_last_known_good"):
        return EXIT_LKG_USED, payload
    return EXIT_VALIDATION_FAILED, payload


def main() -> int:
    parser = ArgumentParser(prog="python -m resilient_updates.cli")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate-config")
    subparsers.add_parser("healthcheck")
    subparsers.add_parser("provenance")
    db_status = subparsers.add_parser("db-status")
    db_status.add_argument("tool", choices=["trivy", "grype", "cve-bin-tool"])
    db_status.add_argument("--path")
    db_status.add_argument("--warning-age", default="24h")
    audit = subparsers.add_parser("audit")
    audit.add_argument("subject", choices=["cve-bin-tool-db"])
    audit.add_argument("--db-root", required=True)
    activate = subparsers.add_parser("activate")
    activate.add_argument("subject", choices=["cve-bin-tool-db"])
    activate.add_argument("--candidate-root", action="append", required=True)
    activate.add_argument("--active-root", required=True)
    activate.add_argument("--previous-root")
    activate.add_argument("--temp-root")
    activate.add_argument("--provenance-path")
    seed = subparsers.add_parser("seed")
    seed.add_argument("subject", choices=["cve-bin-tool-aux"])
    seed.add_argument("--db-root", required=True)
    seed.add_argument("--seed-epss", action="store_true")
    seed.add_argument("--seed-rsd", action="store_true")
    seed.add_argument("--osv-ecosystem", action="append", default=[])
    seed.add_argument("--timeout", type=int, default=120)
    collect_report = subparsers.add_parser("collect-report")
    collect_report.add_argument("--reports-dir", default="artifacts")
    collect_report.add_argument(
        "--output", default="artifacts/reports/final/cve_analysis_report_generated_ru.md"
    )
    collect_report.add_argument("--target", default="")
    collect_report.add_argument("--display-target", default="")
    collect_report.add_argument("--case-id", default="CYBERSEC-UNKNOWN")
    extract = subparsers.add_parser("extract")
    extract.add_argument("--input", required=True)
    extract.add_argument("--output", required=True)
    extract.add_argument("--max-depth", type=int, default=4)
    extract.add_argument("--max-files", type=int, default=20000)
    extract.add_argument("--max-bytes", type=int, default=10 * 1024 * 1024 * 1024)
    # Phase 3.5 pre-filter — both default to disabled to keep legacy parity.
    extract.add_argument(
        "--max-member-size-mb",
        type=int,
        default=0,
        help="Skip archive members larger than this many MB (0 = no limit).",
    )
    extract.add_argument(
        "--skip-ext",
        action="append",
        default=[],
        help="Skip archive members with this extension (e.g. --skip-ext .png --skip-ext .ttf). "
        "Pass multiple times.",
    )
    render_flags = subparsers.add_parser("render-flags")
    render_flags.add_argument("tool", choices=["trivy"])
    subparsers.add_parser(
        "freshness",
        help="report EPSS/KEV cache age vs enrichment_policy TTL; non-zero exit when on_stale=fail",
    )
    scan_parser = subparsers.add_parser(
        "scan",
        help="unified pipeline orchestrator (ADR-0005); use --dry-run to preview the steps",
    )
    scan_parser.add_argument("--target", required=True)
    scan_parser.add_argument(
        "--tool", choices=["all", "syft", "grype", "trivy", "cve-bin-tool"], default="all"
    )
    scan_parser.add_argument("--extract", action="store_true")
    scan_parser.add_argument("--extract-max-depth", type=int, default=4)
    scan_parser.add_argument("--sbom-scan", action="store_true")
    scan_parser.add_argument("--timeout", type=int, default=1800)
    scan_parser.add_argument("--update-db", action="store_true")
    scan_parser.add_argument("--profile", default="default")
    scan_parser.add_argument("--dry-run", action="store_true")
    scan_parser.add_argument("--json", action="store_true")
    dashboard_parser = subparsers.add_parser(
        "dashboard",
        help="launch the read-only run dashboard (ADR-0006); requires fastapi + uvicorn",
    )
    dashboard_parser.add_argument("--host", default="127.0.0.1")
    dashboard_parser.add_argument("--port", type=int, default=8080)
    dashboard_parser.add_argument("--artifacts-dir", default="artifacts")
    doctor_parser = subparsers.add_parser(
        "update-doctor",
        help="probe every DB source over every proxy chain; print a reachability matrix (ADR-0007)",
    )
    doctor_parser.add_argument("--timeout", type=float, default=8.0)
    doctor_parser.add_argument("--json", action="store_true")
    write_summary = subparsers.add_parser(
        "write-run-summary",
        help="Derive summary.json / status.json / run_manifest.json / db_snapshot.json from existing artefacts",
    )
    write_summary.add_argument("--reports-dir", default="artifacts")
    write_summary.add_argument(
        "--no-overwrite",
        action="store_true",
        help="Leave existing sidecar JSONs untouched (default: regenerate every run)",
    )
    update = subparsers.add_parser("update")
    update.add_argument("tool", choices=["trivy", "grype", "cve-bin-tool", "vex"])
    proxy_status = subparsers.add_parser(
        "proxy-status",
        help="Healthcheck every declared proxy chain and write artifacts/provenance/proxy.json",
    )
    proxy_status.add_argument("--force", action="store_true", help="Bypass the TTL cache")
    proxy_status.add_argument(
        "--provenance-path",
        default="artifacts/provenance/proxy.json",
    )
    manifest_parser = subparsers.add_parser(
        "manifest",
        help="Build artifacts/MANIFEST.json tying together all per-run artefacts",
    )
    manifest_parser.add_argument("--artifacts-dir", default="artifacts")
    manifest_parser.add_argument("--output", default="artifacts/MANIFEST.json")
    manifest_parser.add_argument("--case-id", default=None)
    manifest_parser.add_argument("--target-host", default=None)
    manifest_parser.add_argument("--target-container", default=None)
    manifest_parser.add_argument(
        "--run-id",
        default=None,
        help="Override run_id; default derives one deterministically from target+case+timestamp",
    )

    scanner_diff = subparsers.add_parser(
        "scanner-diff",
        help="Compare two artifacts/ directories and show added/removed components and findings",
    )
    scanner_diff.add_argument("--before", required=True, help="Path to the older artifacts/ root")
    scanner_diff.add_argument("--after", required=True, help="Path to the newer artifacts/ root")
    scanner_diff.add_argument(
        "--output",
        default="-",
        help="Output path (default: stdout); '.json' or '.md' picks the writer",
    )
    scanner_diff.add_argument(
        "--format",
        choices=["json", "md"],
        default="json",
        help="Force output format regardless of --output extension",
    )
    args = parser.parse_args()

    # Configure the root logger before any module does work.  LOG_LEVEL and
    # LOG_FORMAT (text|json) are read from environment.  See
    # docs/audit/20-architecture.md section 3.
    from ._logging import setup_logging  # local import keeps top-level fast

    setup_logging()

    config = load_config(args.config)
    # Build a shared HTTP session honoring proxy settings from config and env vars.
    _session = build_session(parse_proxy_config(config))
    if args.command == "validate-config":
        errors = validate_config_data(config)
        if errors:
            print(json.dumps({"status": "error", "errors": errors}, indent=2))
            return EXIT_CONFIG_ERROR
        print(json.dumps({"status": "ok"}, indent=2))
        return EXIT_SUCCESS
    if args.command == "healthcheck":
        print(json.dumps(run_healthcheck(args.config), indent=2))
        return EXIT_SUCCESS
    if args.command == "provenance":
        for item in sorted(Path("artifacts/provenance").glob("*.json")):
            print(item.read_text(encoding="utf-8"))
        return EXIT_SUCCESS
    if args.command == "db-status":
        defaults = {
            "trivy": Path(config.get("trivy", {}).get("cache_dir", "/var/lib/resilient-db/trivy")),
            "grype": Path(
                config.get("grype", {})
                .get("atomic_activation_policy", {})
                .get("active_dir", "/var/lib/resilient-db/grype/active")
            ),
            "cve-bin-tool": Path("/root/.cache/cve-bin-tool"),
        }
        path = Path(args.path) if args.path else defaults[args.tool]
        payload = _db_status_payload(args.tool, path, args.warning_age)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return (
            EXIT_SUCCESS if payload["exists"] and payload["age_hours"] is not None else EXIT_VALIDATION_FAILED
        )
    if args.command == "audit":
        code, payload = _run_cve_db_audit(config, args.db_root)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return code
    if args.command == "activate":
        cve_cfg = config["cve_bin_tool"]["db_audit"]["activation_policy"]
        code, payload = _activate_cve_db(
            config,
            candidate_roots=args.candidate_root,
            active_root=args.active_root,
            previous_root=args.previous_root or cve_cfg["previous_dir"],
            temp_root=args.temp_root or cve_cfg["temp_dir"],
            provenance_path=args.provenance_path or cve_cfg["provenance_path"],
        )
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return code
    if args.command == "seed":
        payload = seed_cve_bin_tool_aux_sources(
            args.db_root,
            seed_epss=args.seed_epss,
            seed_rsd=args.seed_rsd,
            osv_ecosystems=args.osv_ecosystem,
            timeout=args.timeout,
        )
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return EXIT_SUCCESS if payload["overall_status"] == "pass" else EXIT_VALIDATION_FAILED
    if args.command == "collect-report":
        target = args.target or None
        output = build_report(
            args.reports_dir, args.output, target, args.display_target or None, args.case_id
        )
        print(json.dumps({"status": "ok", "report": str(output)}, indent=2, ensure_ascii=False))
        return EXIT_SUCCESS
    if args.command == "extract":
        max_member_bytes = (args.max_member_size_mb * 1024 * 1024) if args.max_member_size_mb > 0 else None
        payload = extract_artifacts(
            args.input,
            args.output,
            max_depth=args.max_depth,
            max_files=args.max_files,
            max_bytes=args.max_bytes,
            max_member_size_bytes=max_member_bytes,
            skip_extensions=tuple(args.skip_ext) if args.skip_ext else None,
        )
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        input_is_file = Path(args.input).resolve().is_file()
        if input_is_file and int(payload.get("extracted_count", 0)) == 0:
            return EXIT_VALIDATION_FAILED
        return EXIT_SUCCESS if payload["status"] in {"pass", "warn"} else EXIT_VALIDATION_FAILED
    if args.command == "render-flags":
        print(_render_trivy_flags(config))
        return EXIT_SUCCESS
    if args.command == "freshness":
        from .enrichment import evaluate_enrichment_policy

        verdict = evaluate_enrichment_policy(config)
        print(json.dumps(verdict, indent=2, ensure_ascii=False))
        return EXIT_VALIDATION_FAILED if verdict["should_fail"] else EXIT_SUCCESS
    if args.command == "scan":
        from .scan import build_plan, format_plan, run_scan

        if args.dry_run:
            plan = build_plan(
                target=args.target,
                tool=args.tool,
                extract=args.extract,
                sbom_scan=args.sbom_scan,
                timeout=args.timeout,
                update_db=args.update_db,
                profile=args.profile,
            )
            if args.json:
                print(json.dumps({"target": args.target, "plan": plan}, indent=2, ensure_ascii=False))
            else:
                print(format_plan(plan, target=args.target))
            return EXIT_SUCCESS
        result = run_scan(
            target=args.target,
            tool=args.tool,
            extract=args.extract,
            sbom_scan=args.sbom_scan,
            timeout=args.timeout,
            update_db=args.update_db,
            profile=args.profile,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return EXIT_SUCCESS if result["status"] == "ok" else EXIT_ALL_SOURCES_FAILED
    if args.command == "dashboard":
        from .dashboard import create_app

        try:
            import uvicorn
        except ImportError:
            print("dashboard requires uvicorn: pip install 'uvicorn[standard]' fastapi")
            return EXIT_VALIDATION_FAILED
        uvicorn.run(create_app(args.artifacts_dir), host=args.host, port=args.port)
        return EXIT_SUCCESS
    if args.command == "update-doctor":
        from .update_doctor import build_matrix, format_matrix

        matrix = build_matrix(config, timeout=args.timeout)
        if args.json:
            print(json.dumps(matrix, indent=2, ensure_ascii=False))
        else:
            print(format_matrix(matrix))
        unreachable = [tool for tool, chain in matrix["recommended"].items() if chain is None]
        return EXIT_ALL_SOURCES_FAILED if unreachable else EXIT_SUCCESS
    if args.command == "update":
        if args.tool == "vex":
            from .vex import fetch_vex

            payload = fetch_vex(config, session=_session)
            print(json.dumps(payload, indent=2))
            published = payload.get("published") or payload.get("used_last_known_good")
            return EXIT_SUCCESS if published else EXIT_ALL_SOURCES_FAILED
        if args.tool == "grype":
            return update_grype(config, session=_session)
        if args.tool == "trivy":
            trivy_retry = RetryPolicy.from_tool_config(config, "trivy")
            code, payload = _health_summary(
                config,
                "trivy",
                "trivy-db",
                timeout=int(config["trivy"]["source_health_policy"]["healthcheck_timeout_seconds"]),
                retry_count=trivy_retry.retry_count,
                backoff_seconds=int(trivy_retry.backoff_seconds),
                retry_codes=list(trivy_retry.retry_status_codes),
                session=_session,
            )
            print(json.dumps(payload, indent=2))
            return code
        # cve_bin_tool: retry_count lives in source_health_policy; backoff and
        # status codes come from the shared RetryPolicy defaults (same values
        # as the previous hardcoded 1 / 429,500,502,503,504).
        cve_retry = RetryPolicy.from_tool_config(config, "cve_bin_tool")
        code, payload = _health_summary(
            config,
            "cve_bin_tool",
            "cve-bin-tool-mirror",
            timeout=int(config["cve_bin_tool"]["source_health_policy"]["source_timeout_seconds"]),
            retry_count=int(config["cve_bin_tool"]["source_health_policy"]["retry_count"]),
            backoff_seconds=int(cve_retry.backoff_seconds),
            retry_codes=list(cve_retry.retry_status_codes),
            session=_session,
        )
        print(json.dumps(payload, indent=2))
        return code
    if args.command == "write-run-summary":
        from .run_summary import write_to_disk

        written = write_to_disk(args.reports_dir, overwrite=not args.no_overwrite)
        print(
            json.dumps(
                {"status": "ok", "written": {k: str(v) for k, v in written.items()}},
                indent=2,
                ensure_ascii=False,
            )
        )
        return EXIT_SUCCESS
    if args.command == "manifest":
        # Single root file connecting all per-run artefacts.  See
        # docs/audit/20-architecture.md section 4.
        from .manifest import derive_manifest, write_manifest

        payload = derive_manifest(
            args.artifacts_dir,
            case_id=args.case_id,
            target_host=args.target_host,
            target_container=args.target_container,
            run_id=args.run_id,
        )
        out_path = write_manifest(payload, args.output)
        print(
            json.dumps(
                {"status": "ok", "output": str(out_path), "run_id": payload["run_id"]},
                indent=2,
                ensure_ascii=False,
            )
        )
        return EXIT_SUCCESS
    if args.command == "scanner-diff":
        from .scanner_diff import diff_runs, to_markdown

        summary = diff_runs(args.before, args.after)
        fmt = args.format
        if args.output != "-" and not args.format:
            fmt = "md" if args.output.lower().endswith(".md") else "json"
        if fmt == "md":
            payload = to_markdown(
                summary,
                before_label=str(args.before),
                after_label=str(args.after),
            )
        else:
            payload = json.dumps(summary.to_dict(), indent=2, ensure_ascii=False)
        if args.output == "-":
            print(payload)
        else:
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(payload + ("\n" if fmt == "json" else ""), encoding="utf-8")
            print(json.dumps({"status": "ok", "output": str(out)}, indent=2, ensure_ascii=False))
        return EXIT_SUCCESS
    if args.command == "proxy-status":
        # Import lazily so users on older configs (no proxy.chains) never load
        # the new module just to run the legacy CLI commands.
        from .proxy_chain import ProxyRouter

        router = ProxyRouter.from_config(config)
        if router is None:
            print(
                json.dumps(
                    {
                        "status": "no-chains-configured",
                        "message": "feed_sources.yaml uses the legacy flat proxy: block. "
                        "Add proxy.chains / proxy.policies to enable the router.",
                        "active_session_proxies": dict(_session.proxies),
                    },
                    indent=2,
                    ensure_ascii=False,
                )
            )
            return EXIT_SUCCESS
        payload = {
            "status": "ok",
            "chains": router.healthcheck_all(force=args.force),
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        try:
            router.write_provenance(args.provenance_path)
        except Exception as exc:  # pragma: no cover - filesystem-level failure surfaces in logs
            print(f"[proxy-status] WARN: failed to write provenance: {exc}", flush=True)
        # Exit non-zero only when EVERY chain is down — partial outages stay 0
        # so a scheduled healthcheck doesn't page on a single flaky route.
        if all(item["status"] != "ok" for item in payload["chains"].values()):
            return EXIT_ALL_SOURCES_FAILED
        return EXIT_SUCCESS
    return EXIT_SUCCESS


if __name__ == "__main__":
    raise SystemExit(main())
