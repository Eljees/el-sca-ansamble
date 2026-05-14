from __future__ import annotations

from argparse import ArgumentParser
from datetime import datetime, timezone
from pathlib import Path
import json
import tarfile
from typing import Any
from urllib.parse import urljoin
from urllib.parse import urlparse

import requests

from .artifact_store import build_last_known_good, ensure_directory, file_sha256
from .atomic_publish import publish_directory
from .config import DEFAULT_CONFIG_PATH, load_config, parse_duration_hours, parse_proxy_config, validate_config_data
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
    """Return unique sources from attempt list (retries cause duplicates)."""
    seen: dict[str, dict[str, Any]] = {}
    for item in attempts:
        seen[item.source.name] = item.source.to_dict()
    return list(seen.values())


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _latest_mtime(path: Path) -> float | None:
    if not path.exists():
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
    if tool == "cve-bin-tool" and path.exists():
        cve_db = next(path.rglob("cve.db"), None) if path.is_dir() else None
        if cve_db is None:
            return {
                "tool": tool,
                "path": str(path),
                "exists": path.exists(),
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
            "exists": path.exists(),
            "age_hours": None,
            "warning_age_hours": warning_hours,
            "warning": False,
            "message": "database path is empty or missing",
            "timestamp_utc": _now_iso(),
        }
    age_hours = round((datetime.now(timezone.utc).timestamp() - latest) / 3600, 2)
    warning = age_hours > warning_hours
    return {
        "tool": tool,
        "path": str(path),
        "exists": path.exists(),
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
    return " ".join(parts)


def _provenance_path(config: dict[str, Any], tool: str) -> Path:
    if tool == "grype":
        return Path(config["grype"]["atomic_activation_policy"]["provenance_path"])
    return Path("artifacts/provenance") / f"{tool}.json"


def _health_summary(config: dict[str, Any], tool: str, layer: str, timeout: int, retry_count: int, backoff_seconds: int, retry_codes: list[int], session: "requests.Session | None" = None) -> tuple[int, dict[str, Any]]:
    source, _payload, attempts = attempt_sources(
        build_sources(config, tool, layer),
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


def _download_text(url: str, timeout: int, session: "requests.Session | None" = None) -> str:
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
    session: "requests.Session | None" = None,
) -> tuple[Path, str | None, str | None]:
    listing_target = temp_dir / f"{source.name}-listing.json"
    archive_target = temp_dir / f"{source.name}-db.archive"
    listing_target.write_bytes(listing_payload)
    archive_url, checksum, built = _resolve_listing(listing_payload, source.url)
    if archive_url.startswith("/"):
        archive_url = urljoin(source.url, archive_url)
    elif not archive_url.startswith(("http://", "https://", "file://")):
        archive_url = urljoin(source.url, archive_url)
    if checksum is None and archive_url.startswith(("http://", "https://")):
        try:
            checksum = _extract_checksum_from_text(_download_text(f"{archive_url}.sha256", int(timeout_cfg["update_download_timeout"]), session=session))
        except Exception:
            checksum = None
    if validation_cfg.get("validate_hash") and not checksum:
        raise ValueError(FailureReason.CHECKSUM_MISMATCH.value)
    archive_name = Path(urlparse(archive_url).path).name or "db.archive"
    archive_target = temp_dir / f"{source.name}-{archive_name}"
    archive_status, archive_payload = fetch_bytes(archive_url, int(timeout_cfg["update_download_timeout"]), session=session)
    if archive_status >= 400:
        raise ValueError(f"http_{archive_status}")
    archive_target.write_bytes(archive_payload)
    _validate_grype_archive(archive_target, checksum if validation_cfg.get("validate_hash") else None)
    if validation_cfg.get("validate_age") and built:
        built_at = datetime.fromisoformat(built.replace("Z", "+00:00"))
        max_age_hours = parse_duration_hours(validation_cfg["max_allowed_built_age"])
        age_hours = (datetime.now(timezone.utc) - built_at).total_seconds() / 3600
        if age_hours > max_age_hours:
            raise ValueError(FailureReason.STALE_DATA.value)
    return archive_target, checksum, built


def update_grype(config: dict[str, Any], session: "requests.Session | None" = None) -> int:
    timeout_cfg = config["grype"]["timeout_policy"]
    validation_cfg = config["grype"]["validation"]
    atomic_cfg = config["grype"]["atomic_activation_policy"]
    lkg_cfg = config["grype"]["last_known_good"]
    retry_codes = [429, 500, 502, 503, 504]

    active_dir = Path(atomic_cfg["active_dir"])
    previous_dir = Path(atomic_cfg["previous_dir"])
    temp_root = ensure_directory(atomic_cfg["temp_dir"])
    temp_dir = ensure_directory(temp_root / f"run-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}")
    attempts = []
    validation_failures: list[dict[str, Any]] = []
    selected_source = None
    selected_archive = None
    checksum = None
    built = None
    for source in build_sources(config, "grype", "grype-db"):
        candidate_source, listing_payload, source_attempts = attempt_sources(
            [source],
            timeout=int(timeout_cfg["update_available_timeout"]),
            retry_count=1,
            backoff_seconds=1,
            retry_status_codes=retry_codes,
            session=session,
        )
        attempts.extend(source_attempts)
        if not candidate_source or not listing_payload:
            continue
        try:
            selected_archive, checksum, built = _download_grype_candidate(
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
                {"source": candidate_source.name, "reason": str(exc), "message": str(exc), "status_code": None}
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
            ] + validation_failures,
            "activation_status": "last-known-good" if lkg.is_usable() else "failed",
            "used_last_known_good": lkg.is_usable(),
            "timestamp_utc": _now_iso(),
        }
        write_provenance(_provenance_path(config, "grype"), payload)
        if any(item["reason"] == FailureReason.STALE_DATA.value for item in validation_failures) and not lkg.is_usable():
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


def _cve_db_policy(config: dict[str, Any]) -> tuple[list[str], dict[str, int], str, list[str]]:
    cve_cfg = config["cve_bin_tool"]
    db_audit = cve_cfg["db_audit"]
    required_sources = [str(item).upper() for item in db_audit.get("required_sources", [])]
    min_entries = {str(key).upper(): int(value) for key, value in db_audit.get("min_entries", {}).items()}
    max_cache_age = str(db_audit.get("max_cache_age", "168h"))
    declared_sources = [str(item).upper() for item in cve_cfg.get("data_sources", [])]
    return required_sources, min_entries, max_cache_age, declared_sources


def _run_cve_db_audit(config: dict[str, Any], db_root: str) -> tuple[int, dict[str, Any]]:
    required_sources, min_entries, max_cache_age, declared_sources = _cve_db_policy(config)
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
    required_sources, min_entries, max_cache_age, declared_sources = _cve_db_policy(config)
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
    collect_report.add_argument("--output", default="artifacts/reports/final/cve_analysis_report_generated_ru.md")
    collect_report.add_argument("--target", default="")
    collect_report.add_argument("--display-target", default="")
    collect_report.add_argument("--case-id", default="CYBERSEC-11531")
    extract = subparsers.add_parser("extract")
    extract.add_argument("--input", required=True)
    extract.add_argument("--output", required=True)
    extract.add_argument("--max-depth", type=int, default=4)
    extract.add_argument("--max-files", type=int, default=20000)
    extract.add_argument("--max-bytes", type=int, default=10 * 1024 * 1024 * 1024)
    render_flags = subparsers.add_parser("render-flags")
    render_flags.add_argument("tool", choices=["trivy"])
    update = subparsers.add_parser("update")
    update.add_argument("tool", choices=["trivy", "grype", "cve-bin-tool"])
    args = parser.parse_args()

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
            "grype": Path(config.get("grype", {}).get("atomic_activation_policy", {}).get("active_dir", "/var/lib/resilient-db/grype/active")),
            "cve-bin-tool": Path("/root/.cache/cve-bin-tool"),
        }
        path = Path(args.path) if args.path else defaults[args.tool]
        payload = _db_status_payload(args.tool, path, args.warning_age)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return EXIT_SUCCESS if payload["exists"] and payload["age_hours"] is not None else EXIT_VALIDATION_FAILED
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
        output = build_report(args.reports_dir, args.output, target, args.display_target or None, args.case_id)
        print(json.dumps({"status": "ok", "report": str(output)}, indent=2, ensure_ascii=False))
        return EXIT_SUCCESS
    if args.command == "extract":
        payload = extract_artifacts(
            args.input,
            args.output,
            max_depth=args.max_depth,
            max_files=args.max_files,
            max_bytes=args.max_bytes,
        )
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return EXIT_SUCCESS if payload["status"] in {"pass", "warn"} else EXIT_VALIDATION_FAILED
    if args.command == "render-flags":
        print(_render_trivy_flags(config))
        return EXIT_SUCCESS
    if args.command == "update":
        if args.tool == "grype":
            return update_grype(config, session=_session)
        if args.tool == "trivy":
            code, payload = _health_summary(
                config,
                "trivy",
                "trivy-db",
                timeout=int(config["trivy"]["source_health_policy"]["healthcheck_timeout_seconds"]),
                retry_count=int(config["trivy"]["retry_backoff_policy"]["retry_count"]),
                backoff_seconds=int(config["trivy"]["retry_backoff_policy"]["backoff_seconds"]),
                retry_codes=list(config["trivy"]["retry_backoff_policy"]["retry_status_codes"]),
                session=_session,
            )
            print(json.dumps(payload, indent=2))
            return code
        code, payload = _health_summary(
            config,
            "cve_bin_tool",
            "cve-bin-tool-mirror",
            timeout=int(config["cve_bin_tool"]["source_health_policy"]["source_timeout_seconds"]),
            retry_count=int(config["cve_bin_tool"]["source_health_policy"]["retry_count"]),
            backoff_seconds=1,
            retry_codes=[429, 500, 502, 503, 504],
            session=_session,
        )
        print(json.dumps(payload, indent=2))
        return code
    return EXIT_SUCCESS


if __name__ == "__main__":
    raise SystemExit(main())
