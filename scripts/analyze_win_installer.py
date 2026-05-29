#!/usr/bin/env python3
"""
Windows Installer Analyzer — integrates with the el-sca-ansamble pipeline.

Supports:
  - NSIS installers (.exe) — extracted via 7zip
  - MSI packages (.msi)    — extracted via msiextract (msitools) or 7zip
  - ZIP archives wrapping any of the above

Steps:
  1. Detect format
  2. Extract contents to artifacts/extracted/win-installer/
  3. Scan .exe/.dll PE headers with pefile to collect version metadata
  4. Generate a synthetic syft-compatible SBOM from PE version info
  5. Write text summary to artifacts/reports/win/win_analysis.txt

Usage (inside container):
  python /scripts/analyze_win_installer.py --input /scan-target --output /workspace/artifacts
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import uuid
import zipfile
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def log(msg: str) -> None:
    print(f"[win-analyzer] {msg}", flush=True)


def run(cmd: list[str], check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    log(f"  $ {' '.join(cmd)}")
    return subprocess.run(cmd, check=check, capture_output=True, text=True, **kwargs)


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------


def detect_format(path: Path) -> str:
    """Return 'msi', 'nsis', 'exe', 'zip', or 'unknown'."""
    suffix = path.suffix.lower()
    if suffix == ".msi":
        return "msi"
    if suffix == ".zip":
        return "zip"
    if suffix == ".exe":
        # Try to detect NSIS by magic bytes
        try:
            data = path.read_bytes()
            if b"Nullsoft" in data[:4096] or b"NSIS" in data[:4096]:
                return "nsis"
            # Check PE header
            if data[:2] == b"MZ":
                return "exe"
        except Exception:
            pass
        return "exe"
    return "unknown"


def find_installer(path: Path) -> Path | None:
    """Return the installer file to analyze."""
    if path.is_file():
        return path
    if path.is_dir():
        for ext in ("*.msi", "*.exe"):
            for candidate in sorted(path.rglob(ext)):
                return candidate
    return None


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def _count_files(d: Path) -> int:
    """Count all files under directory d (recursive)."""
    if not d.exists():
        return 0
    return sum(1 for _ in d.rglob("*") if _.is_file())


def extract_7zip(src: Path, dest: Path) -> bool:
    """Extract using 7zip.
    Exit codes on Linux (p7zip / 7zip package):
      0  — OK
      1  — Warning (some files skipped, partial extraction)
      2  — Fatal error (file format not supported, corrupt, etc.)
    We treat code 0 and 1 as potentially usable if files were actually extracted.
    """
    dest.mkdir(parents=True, exist_ok=True)
    try:
        result = run(["7z", "x", str(src), f"-o{dest}", "-y", "-aoa"], check=False)
        n = _count_files(dest)
        if result.returncode == 0 and n > 0:
            log(f"  7zip extraction OK → {dest} ({n} files)")
            return True
        if result.returncode == 1 and n > 0:
            log(f"  7zip extraction with warnings (exit 1) → {dest} ({n} files) — continuing")
            return True
        stderr_snippet = result.stderr.strip()[:400] if result.stderr else "(no stderr)"
        log(f"  7zip failed or produced no files (exit {result.returncode}, {n} files): {stderr_snippet}")
        return False
    except Exception as e:
        log(f"  7zip error: {e}")
        return False


def extract_innoextract(src: Path, dest: Path) -> bool:
    """Extract Inno Setup installer using innoextract. Returns True on success."""
    # First check if this actually is an Inno Setup file
    try:
        probe = run(["innoextract", "--list", "--silent", str(src)], check=False)
        if probe.returncode != 0:
            return False  # Not an Inno Setup file
    except FileNotFoundError:
        log("  innoextract not available")
        return False

    dest.mkdir(parents=True, exist_ok=True)
    try:
        result = run(["innoextract", "--extract", "--output-dir", str(dest), str(src)], check=False)
        n = _count_files(dest)
        if result.returncode == 0 and n > 0:
            log(f"  innoextract OK → {dest} ({n} files)")
            return True
        log(f"  innoextract failed (exit {result.returncode}, {n} files): {result.stderr.strip()[:300]}")
        return False
    except Exception as e:
        log(f"  innoextract error: {e}")
        return False


def extract_msitools(src: Path, dest: Path) -> bool:
    """Extract MSI using msiextract from msitools. Returns True on success."""
    dest.mkdir(parents=True, exist_ok=True)
    try:
        result = run(["msiextract", "--directory", str(dest), str(src)], check=False)
        n = _count_files(dest)
        if result.returncode == 0 and n > 0:
            log(f"  msiextract OK → {dest} ({n} files)")
            return True
        log(f"  msiextract failed (exit {result.returncode}, {n} files): {result.stderr.strip()[:300]}")
        return False
    except FileNotFoundError:
        log("  msiextract not found — falling back to 7zip")
        return False


def extract_zip_for_installer(src: Path, dest: Path) -> Path | None:
    """Extract a ZIP, find the installer inside, return its path."""
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(src, "r") as zf:
            zf.extractall(dest)
        return find_installer(dest)
    except Exception as e:
        log(f"  ZIP extraction failed: {e}")
        return None


# ---------------------------------------------------------------------------
# PE version info extraction
# ---------------------------------------------------------------------------


def read_pe_version(path: Path) -> dict[str, str]:
    """Extract VS_VERSION_INFO from a PE file using pefile."""
    try:
        import pefile  # type: ignore
    except ImportError:
        return {}
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        if not hasattr(pe, "VS_VERSIONINFO"):
            return {}
        info: dict[str, str] = {}
        if hasattr(pe, "FileInfo"):
            for fi in pe.FileInfo:
                for entry in fi:
                    if hasattr(entry, "StringTable"):
                        for st in entry.StringTable:
                            for k, v in st.entries.items():
                                key = k.decode("utf-8", errors="replace").strip("\x00")
                                val = v.decode("utf-8", errors="replace").strip("\x00")
                                info[key] = val
        return info
    except Exception:
        return {}


def collect_binaries(root: Path) -> list[Path]:
    """Find all .exe and .dll files under root."""
    binaries: list[Path] = []
    for ext in ("*.exe", "*.dll", "*.sys", "*.ocx"):
        binaries.extend(root.rglob(ext))
    return sorted(binaries)


def build_component(bin_path: Path, root: Path, version_info: dict[str, str]) -> dict[str, Any]:
    """Build a syft-json artifact entry from PE version info."""
    product = version_info.get("ProductName") or version_info.get("FileDescription") or bin_path.stem
    version = (version_info.get("ProductVersion") or version_info.get("FileVersion") or "unknown").strip()
    company = version_info.get("CompanyName", "")
    rel_path = str(bin_path.relative_to(root)).replace("\\", "/")

    # Normalise version: keep only semver-like prefix
    import re

    m = re.match(r"[\d]+(?:[._][\d]+)*", version)
    version_clean = m.group(0).replace("_", ".") if m else version

    cpe_product = re.sub(r"[^a-z0-9_]", "_", product.lower()).strip("_")
    cpe_vendor = re.sub(r"[^a-z0-9_]", "_", company.lower()).strip("_") or "*"

    return {
        "id": str(uuid.uuid4()),
        "name": product,
        "version": version_clean,
        "type": "binary",
        "foundBy": "win-analyzer-pe",
        "locations": [{"path": f"/{rel_path}"}],
        "licenses": [],
        "language": "",
        "cpes": [f"cpe:2.3:a:{cpe_vendor}:{cpe_product}:{version_clean}:*:*:*:*:*:*:*"]
        if version_clean != "unknown"
        else [],
        "purl": f"pkg:generic/{cpe_product}@{version_clean}",
        "metadataType": "WindowsBinaryMetadata",
        "metadata": {
            "originalFileName": bin_path.name,
            "companyName": company,
            "legalCopyright": version_info.get("LegalCopyright", ""),
        },
    }


# ---------------------------------------------------------------------------
# Syft SBOM builder
# ---------------------------------------------------------------------------

SYFT_SCHEMA = "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.4.json"


def build_syft_sbom(installer_path: Path, components: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "$schema": SYFT_SCHEMA,
        "anchore:schema": "16.0.4",
        "schema": {"version": "16.0.4", "url": SYFT_SCHEMA},
        "artifacts": components,
        "artifactRelationships": [],
        "files": [],
        "distro": {},
        "descriptor": {
            "name": "win-analyzer",
            "version": "1.0.0",
            "configuration": {},
        },
        "source": {
            "id": str(uuid.uuid4()),
            "name": installer_path.name,
            "version": "unknown",
            "type": "file",
            "metadata": {"path": f"/{installer_path.name}"},
        },
    }


# ---------------------------------------------------------------------------
# Text report
# ---------------------------------------------------------------------------


def write_text_report(
    installer_path: Path,
    fmt: str,
    components: list[dict[str, Any]],
    binaries: list[Path],
    report_path: Path,
) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with_version = [c for c in components if c["version"] not in ("unknown", "")]
    lines = [
        "=" * 60,
        "Windows Installer Analysis Report",
        "=" * 60,
        f"File        : {installer_path.name}",
        f"Format      : {fmt.upper()}",
        f"Binaries    : {len(binaries)} total",
        f"Components  : {len(components)} identified ({len(with_version)} with known version)",
        "",
        "Components with version info (top 40):",
    ]
    for c in sorted(components, key=lambda x: x["name"])[:40]:
        lines.append(f"  {c['name']:40s}  {c['version']}")
    if len(components) > 40:
        lines.append(f"  ... and {len(components) - 40} more")
    lines += [
        "",
        "NOTE: cve-bin-tool will scan extracted binaries for additional CVEs.",
        "      CPE matching quality depends on PE version info accuracy.",
        "=" * 60,
    ]
    report_path.write_text("\n".join(lines), encoding="utf-8")
    log(f"  text report → {report_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="Windows installer analyzer for el-sca-ansamble")
    parser.add_argument("--input", default="/scan-target", help="Path to installer or directory")
    parser.add_argument("--output", default="/workspace/artifacts", help="Artifacts output root")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_root = Path(args.output)

    installer = find_installer(input_path)
    if installer is None:
        log(f"ERROR: no installer (.exe/.msi) found at {input_path}")
        return 1

    log(f"Installer: {installer}")
    fmt = detect_format(installer)
    log(f"Format: {fmt}")

    extract_dir = output_root / "extracted" / "win-installer"

    # ── Extraction ──────────────────────────────────────────────────────────
    actual_installer = installer

    if fmt == "zip":
        log("Unwrapping ZIP to find installer inside…")
        inner = extract_zip_for_installer(installer, extract_dir / "_zip_wrapper")
        if inner:
            actual_installer = inner
            fmt = detect_format(inner)
            log(f"  found {actual_installer.name} ({fmt}) inside ZIP")
        else:
            log("  no installer found inside ZIP — scanning ZIP contents directly")
            actual_installer = installer

    if fmt == "msi":
        ok = extract_msitools(actual_installer, extract_dir)
        if not ok:
            ok = extract_7zip(actual_installer, extract_dir)
    else:  # nsis / exe / unknown
        # Try Inno Setup first (common for .NET service installers)
        ok = extract_innoextract(actual_installer, extract_dir)
        if not ok:
            ok = extract_7zip(actual_installer, extract_dir)
        if not ok:
            log("WARNING: all extraction methods failed — SBOM will be minimal")
            log("  Tried: innoextract, 7zip")
            log("  Possible causes: newer NSIS version, InstallShield, encrypted installer")

    extracted_count = _count_files(extract_dir)
    if extracted_count == 0:
        log("WARNING: extraction produced no files — SBOM will be minimal")

    # ── PE scanning ─────────────────────────────────────────────────────────
    binaries = collect_binaries(extract_dir)
    log(f"Found {len(binaries)} PE binaries in extracted content")

    components: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for i, bin_path in enumerate(binaries):
        if i % 50 == 0 and i > 0:
            log(f"  scanned {i}/{len(binaries)}…")
        vi = read_pe_version(bin_path)
        if not vi:
            continue
        comp = build_component(bin_path, extract_dir, vi)
        key = (comp["name"], comp["version"])
        if key not in seen:
            seen.add(key)
            components.append(comp)

    log(f"Unique components with version info: {len(components)}")

    # ── SBOM ────────────────────────────────────────────────────────────────
    sbom_dir = output_root / "sbom"
    sbom_dir.mkdir(parents=True, exist_ok=True)
    sbom = build_syft_sbom(actual_installer, components)
    sbom_path = sbom_dir / "syft.json"
    sbom_path.write_text(json.dumps(sbom, indent=2, ensure_ascii=False), encoding="utf-8")
    log(f"  SBOM ({len(components)} components) → {sbom_path}")

    # ── Text report ─────────────────────────────────────────────────────────
    report_path = output_root / "reports" / "win" / "win_analysis.txt"
    write_text_report(actual_installer, fmt, components, binaries, report_path)

    log("Windows installer analysis complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
