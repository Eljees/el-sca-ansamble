"""EPSS + CISA KEV enrichment for the final report.

Both feeds are already part of the cve-bin-tool pipeline:
- EPSS lives at ``<DB_ROOT>/epss/epss_scores-current.csv`` after the
  ``seed_epss`` step (see resilient_updates.cve_db_audit.seed_cve_bin_tool_aux_sources).
- CISA KEV is published as ``known_exploited_vulnerabilities.json`` and is
  typically dropped next to the EPSS file or under
  ``<DB_ROOT>/kev/known_exploited_vulnerabilities.json``.

This module does NOT fetch anything from the network — it reads the
already-cached on-disk files.  If the files are missing the enrichers
return an empty mapping so reporting.py degrades gracefully (the report
still builds, just without the extra columns).

Used from ``reporting.build_report()`` once Phase 5.2 wires it in.
"""

from __future__ import annotations

import csv
import datetime

try:
    _UTC = datetime.UTC  # py3.11+
except AttributeError:
    _UTC = datetime.timezone.utc  # noqa: UP017
import json
import os
from collections.abc import Iterable
from pathlib import Path

# Default lookup roots, in priority order.  Override via
# CVE_BIN_TOOL_DB_ROOT or EL_SCA_ENRICHMENT_ROOT env vars.
_DEFAULT_ROOTS = (
    "/root/.cache/cve-bin-tool",
    "/var/lib/resilient-db/cve-bin-tool/active",
)


def _candidate_roots() -> list[Path]:
    custom = os.environ.get("EL_SCA_ENRICHMENT_ROOT")
    roots: list[Path] = []
    if custom:
        roots.append(Path(custom))
    db_root = os.environ.get("CVE_BIN_TOOL_DB_ROOT")
    if db_root:
        roots.append(Path(db_root))
    for path in _DEFAULT_ROOTS:
        roots.append(Path(path))
    return [r for r in roots if r.exists()]


# ---------------------------------------------------------------------------
# EPSS
# ---------------------------------------------------------------------------


def load_epss_scores(roots: Iterable[Path] | None = None) -> dict[str, dict[str, float | str]]:
    """Return ``{cve_id: {"epss": float, "percentile": float, "date": str}}``.

    The file is `epss_scores-current.csv` from FIRST.org, distributed as a
    plain CSV with a one-line ``model_version`` header before the
    ``cve,epss,percentile`` data row.  Empty mapping if the file is missing.
    """
    roots_iter = list(roots) if roots is not None else _candidate_roots()
    out: dict[str, dict[str, float | str]] = {}
    for root in roots_iter:
        candidate = root / "epss" / "epss_scores-current.csv"
        if not candidate.exists():
            continue
        try:
            with candidate.open("r", encoding="utf-8", newline="") as handle:
                reader = csv.reader(handle)
                first = next(reader, None)
                # The real header line may be preceded by a metadata row like
                # "#model_version:v2024.06.01,score_date:2024-06-01T00:00:00+0000"
                if first and first[0].startswith("#"):
                    first = next(reader, None)
                # Expect a header row: ["cve", "epss", "percentile"]
                if not first:
                    return out
                col_map = {name.strip().lower(): idx for idx, name in enumerate(first)}
                cve_idx = col_map.get("cve")
                epss_idx = col_map.get("epss")
                pct_idx = col_map.get("percentile")
                if cve_idx is None or epss_idx is None:
                    return out
                date_value = datetime.datetime.fromtimestamp(
                    candidate.stat().st_mtime, tz=_UTC
                ).isoformat()
                for row in reader:
                    if len(row) <= max(cve_idx, epss_idx):
                        continue
                    try:
                        epss_score = float(row[epss_idx])
                    except ValueError:
                        continue
                    percentile: float | None = None
                    if pct_idx is not None and len(row) > pct_idx:
                        try:
                            percentile = float(row[pct_idx])
                        except ValueError:
                            percentile = None
                    out[row[cve_idx].strip().upper()] = {
                        "epss": epss_score,
                        "percentile": percentile if percentile is not None else "",
                        "mtime": date_value,
                    }
                return out
        except OSError:
            continue
    return out


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------


def load_kev_set(roots: Iterable[Path] | None = None) -> set[str]:
    """Return the set of CVE IDs present in CISA's Known Exploited Vulnerabilities catalog.

    Looks for ``kev/known_exploited_vulnerabilities.json`` and falls back to
    the file lying at the root of the cve-bin-tool DB.  Returns an empty
    set if nothing is on disk — caller treats missing as "no KEV info".
    """
    roots_iter = list(roots) if roots is not None else _candidate_roots()
    for root in roots_iter:
        for relpath in (
            "kev/known_exploited_vulnerabilities.json",
            "known_exploited_vulnerabilities.json",
            "kev/kev.json",
        ):
            candidate = root / relpath
            if not candidate.exists():
                continue
            try:
                data = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            ids = _extract_kev_ids(data)
            if ids:
                return ids
    return set()


def _extract_kev_ids(blob: object) -> set[str]:
    """Pull CVE IDs out of the various CISA KEV JSON shapes seen in the wild."""
    if not isinstance(blob, dict):
        return set()
    entries = blob.get("vulnerabilities") or blob.get("kev_entries") or []
    if not isinstance(entries, list):
        return set()
    ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        cve = entry.get("cveID") or entry.get("cve_id") or entry.get("CVE")
        if cve:
            ids.add(str(cve).strip().upper())
    return ids


# ---------------------------------------------------------------------------
# Application API
# ---------------------------------------------------------------------------


def enrich_findings(
    findings: list[dict[str, object]],
    *,
    epss: dict[str, dict[str, float | str]] | None = None,
    kev: set[str] | None = None,
) -> list[dict[str, object]]:
    """Annotate each finding row with ``epss`` and ``kev`` keys (when known).

    The input rows are not copied — annotation is in place — but the
    function still returns them so the call reads as a transform.
    Missing data is left blank rather than ``None`` so the Markdown
    renderer in reporting.py drops cleanly into table cells.
    """
    epss_map = epss if epss is not None else load_epss_scores()
    kev_set = kev if kev is not None else load_kev_set()
    for row in findings:
        cve_id = str(row.get("id", "")).strip().upper()
        info = epss_map.get(cve_id) if cve_id else None
        if info:
            row.setdefault("epss", info.get("epss", ""))
            row.setdefault("epss_percentile", info.get("percentile", ""))
        else:
            row.setdefault("epss", "")
            row.setdefault("epss_percentile", "")
        row["kev"] = "yes" if cve_id and cve_id in kev_set else ""
    return findings


__all__ = [
    "enrich_findings",
    "load_epss_scores",
    "load_kev_set",
]
