"""Unified scan-pipeline orchestrator (ADR-0005).

**Phase 1** — a pure *plan builder* plus a human-readable formatter for
``cli scan --dry-run``.  :func:`build_plan` returns the ordered list of steps
the full pipeline would run, without touching docker, the network, or the
filesystem, so it is fully unit-testable.  Real execution via ``subprocess``
lands in Phase 2.

Service/command names mirror ``scripts/run-scan.sh`` and the actual
``docker-compose.yml`` service names (``trivy-scanner``, ``grype-scanner``,
``cve-bin-tool-scanner``, ``syft-sbom``, ``artifact-extractor``,
``<tool>-updater``, ``grype-db-importer``, ``db-admin``).
"""

from __future__ import annotations

from typing import Any

ALL_TOOLS = ("syft", "grype", "trivy", "cve-bin-tool")
# Order of the binary/image scanners in the pipeline (syft generates the SBOM
# first and is handled separately).
_SCANNERS = ("grype", "trivy", "cve-bin-tool")
_COMPOSE = ["docker", "compose"]
_CLI = ["python", "-m", "resilient_updates.cli"]


def _selected_tools(tool: str) -> set[str]:
    if tool == "all":
        return set(ALL_TOOLS)
    return {tool}


def build_plan(
    *,
    target: str,
    tool: str = "all",
    extract: bool = False,
    sbom_scan: bool = False,
    timeout: int = 1800,
    update_db: bool = False,
    profile: str = "default",
) -> list[dict[str, Any]]:
    """Return the ordered pipeline steps for the given options.

    Pure: no side effects.  Each step is ``{"step": name, "cmd": [...]}`` with an
    optional ``"timeout"`` (seconds) on the cve-bin-tool scan.  ``sbom_scan``
    does not change the step *sequence* in P1 — it only flips cve-bin-tool's
    input in P2 — but is recorded on the cve-bin-tool scan step for visibility.
    """
    selected = _selected_tools(tool)
    plan: list[dict[str, Any]] = []

    def add(step: str, cmd: list[str], **extra: Any) -> None:
        plan.append({"step": step, "cmd": cmd, **extra})

    add("preflight", [*_COMPOSE, "version"])

    if extract:
        add("extract", [*_COMPOSE, "--profile", "extract", "run", "--rm", "artifact-extractor"])

    if "syft" in selected:
        add("syft-sbom", [*_COMPOSE, "run", "--rm", "syft-sbom"])

    for t in _SCANNERS:
        if t not in selected:
            continue
        if update_db:
            add(f"{t}-update", [*_COMPOSE, "--profile", "update", "run", "--rm", f"{t}-updater"])
            if t == "grype":
                add("grype-db-import", [*_COMPOSE, "--profile", "update", "run", "--rm", "grype-db-importer"])
        add(f"{t}-db-status", [*_COMPOSE, "run", "--rm", "db-admin", "db-status", t])
        if t == "trivy":
            add("trivy-render-flags", [*_CLI, "render-flags", "trivy"])
        scan_cmd = [*_COMPOSE, "--profile", profile, "run", "--rm", f"{t}-scanner"]
        if t == "cve-bin-tool":
            add(f"{t}-scan", scan_cmd, timeout=timeout, sbom_scan=sbom_scan)
        else:
            add(f"{t}-scan", scan_cmd)

    for sub in ("collect-report", "write-run-summary", "scanner-diff", "manifest"):
        add(sub, [*_CLI, sub])

    return plan


def format_plan(plan: list[dict[str, Any]], *, target: str) -> str:
    """Render a plan as a numbered, human-readable dry-run listing."""
    lines = [
        f"# cli scan plan — target: {target}",
        f"# {len(plan)} steps (dry-run; nothing is executed)",
    ]
    for i, step in enumerate(plan, 1):
        suffix = f"   (timeout={step['timeout']}s)" if step.get("timeout") else ""
        lines.append(f"{i:>2}. {step['step']:<20} {' '.join(step['cmd'])}{suffix}")
    return "\n".join(lines)
