"""Ingest SBOMs that arrive *inside* the delivery.

Motivating case (CYBERSEC-13860): the customer shipped two CycloneDX files
instead of the applications themselves.  The pipeline did exactly what it is
built to do — Syft catalogued the *container* of those files (a zip holding
two .json documents), Grype matched that SBOM, and the report honestly said
"nothing found".  Meanwhile the delivered documents listed 713 Maven
components carrying 231 known vulnerabilities, 9 of them Critical.

So: whenever the extracted tree contains SBOM documents, their contents must
be analysed too, not just the files they live in.

What this module does:

* sniff every JSON file in the extracted tree and recognise CycloneDX, SPDX
  and Syft-native documents by content (never by filename — real deliveries
  are called ``CycloneDX-Sbom-BACK-SI.json``, ``bom.json``, ``sbom-final``…);
* normalise each recognised document to CycloneDX components;
* merge them with the SBOM Syft produced for this run into one CycloneDX
  document that the scanners consume.

Merging (rather than replacing) is deliberate: a delivery may contain both an
SBOM *and* real binaries, and dropping either side would lose findings.
Components are de-duplicated on ``purl`` when present, else on
``(name, version)``, so re-running is stable and a component described by both
Syft and the vendor is counted once.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Files bigger than this are not plausible SBOMs and are skipped without a
# read — keeps the sniff cheap on 14 GB trees full of .js.map blobs.
_MAX_SBOM_BYTES = 512 * 1024 * 1024
# Our own generated artefacts must never be ingested as "provided" input,
# otherwise every re-run would fold the previous merge into itself.
_OWN_SBOM_DIRS = ("artifacts/sbom", "artifacts/_sbom_probe")


def _looks_like_json(path: Path) -> bool:
    """Cheap pre-filter: first non-whitespace byte of a JSON document is '{'."""
    try:
        with path.open("rb") as fh:
            head = fh.read(64).lstrip()
        return head.startswith(b"{")
    except OSError:
        return False


def sniff(path: Path) -> str | None:
    """Return ``cyclonedx`` | ``spdx`` | ``syft`` | ``None`` for one file."""
    if not path.is_file():
        return None
    try:
        if path.stat().st_size > _MAX_SBOM_BYTES:
            return None
    except OSError:
        return None
    if not _looks_like_json(path):
        return None
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    if doc.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if doc.get("spdxVersion"):
        return "spdx"
    descriptor = doc.get("descriptor")
    if isinstance(descriptor, dict) and str(descriptor.get("name")) == "syft":
        return "syft"
    return None


def _components_from_cyclonedx(doc: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    stack = list(doc.get("components") or [])
    while stack:  # CycloneDX allows nested components
        comp = stack.pop()
        if not isinstance(comp, dict):
            continue
        stack.extend(comp.get("components") or [])
        if comp.get("name"):
            out.append(comp)
    return out


def _components_from_spdx(doc: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for pkg in doc.get("packages") or []:
        if not isinstance(pkg, dict) or not pkg.get("name"):
            continue
        purl = ""
        for ref in pkg.get("externalRefs") or []:
            if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                purl = str(ref.get("referenceLocator") or "")
                break
        comp: dict[str, Any] = {
            "type": "library",
            "name": str(pkg.get("name")),
            "version": str(pkg.get("versionInfo") or ""),
        }
        if purl:
            comp["purl"] = purl
        out.append(comp)
    return out


def _components_from_syft(doc: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for art in doc.get("artifacts") or []:
        if not isinstance(art, dict) or not art.get("name"):
            continue
        comp: dict[str, Any] = {
            "type": "library",
            "name": str(art.get("name")),
            "version": str(art.get("version") or ""),
        }
        if art.get("purl"):
            comp["purl"] = str(art["purl"])
        out.append(comp)
    return out


def components_of(path: Path, fmt: str) -> list[dict[str, Any]]:
    """Components of one SBOM document, normalised to CycloneDX shape."""
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return []
    if not isinstance(doc, dict):
        return []
    if fmt == "cyclonedx":
        return _components_from_cyclonedx(doc)
    if fmt == "spdx":
        return _components_from_spdx(doc)
    if fmt == "syft":
        return _components_from_syft(doc)
    return []


def _is_own(path: Path, root: Path) -> bool:
    try:
        rel = path.resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return False
    return any(rel.startswith(d) for d in _OWN_SBOM_DIRS)


def detect_sboms(tree: str | Path, *, repo_root: str | Path | None = None) -> list[dict[str, Any]]:
    """Find SBOM documents inside ``tree``.

    Returns a list of ``{"path", "format", "components"}`` sorted by path so
    the merge is deterministic.
    """
    base = Path(tree)
    own_root = Path(repo_root) if repo_root else base
    found: list[dict[str, Any]] = []
    if not base.is_dir():
        return found
    for path in sorted(base.rglob("*.json")):
        if _is_own(path, own_root):
            continue
        fmt = sniff(path)
        if not fmt:
            continue
        comps = components_of(path, fmt)
        if not comps:
            continue
        found.append({"path": str(path), "format": fmt, "components": len(comps)})
    return found


def _key(comp: dict[str, Any]) -> tuple[str, str]:
    purl = str(comp.get("purl") or "").strip()
    if purl:
        return ("purl", purl)
    return ("nv", f"{comp.get('name')}@{comp.get('version')}")


def build_scan_input(
    tree: str | Path,
    *,
    base_cyclonedx: str | Path | None = None,
    output: str | Path,
    repo_root: str | Path | None = None,
) -> dict[str, Any]:
    """Write the CycloneDX document the scanners should consume.

    ``base_cyclonedx`` is the SBOM Syft produced for this run; provided SBOMs
    found under ``tree`` are merged on top.  Always writes ``output`` — even
    when nothing was provided — so downstream stages have one stable path.
    """
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    base_count = 0
    base_path = Path(base_cyclonedx) if base_cyclonedx else None
    if base_path and base_path.is_file():
        try:
            with base_path.open(encoding="utf-8", errors="replace") as fh:
                base_doc = json.load(fh)
            for comp in _components_from_cyclonedx(base_doc):
                merged.setdefault(_key(comp), comp)
            base_count = len(merged)
        except (OSError, ValueError):
            base_count = 0

    provided = detect_sboms(tree, repo_root=repo_root)
    added = 0
    for item in provided:
        for comp in components_of(Path(item["path"]), str(item["format"])):
            key = _key(comp)
            if key not in merged:
                merged[key] = comp
                added += 1

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "el-sca sbom-ingest"}]},
            "properties": [
                {"name": "el-sca:provided-sboms", "value": str(len(provided))},
                {"name": "el-sca:components-from-syft", "value": str(base_count)},
                {"name": "el-sca:components-from-provided", "value": str(added)},
            ],
        },
        "components": list(merged.values()),
    }
    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")

    return {
        "output": str(out),
        "provided_sboms": provided,
        "components_from_syft": base_count,
        "components_from_provided": added,
        "components_total": len(merged),
    }


__all__ = ["sniff", "detect_sboms", "components_of", "build_scan_input"]
