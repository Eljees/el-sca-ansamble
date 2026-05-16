#!/usr/bin/env python3
"""
APK Analyzer — integrates with the el-sca-ansamble pipeline.

Steps:
  1. Parse AndroidManifest.xml + DEX using androguard
  2. Extract native .so libraries from lib/ to artifacts/extracted/apk-native/
  3. Generate a synthetic syft-compatible SBOM (syft.json) with identified components
  4. Write a text summary to artifacts/reports/apk/apk_analysis.txt

Usage (inside container):
  python /scripts/analyze_apk.py --input /scan-target --output /workspace/artifacts
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log(msg: str) -> None:
    print(f"[apk-analyzer] {msg}", flush=True)


def find_apk(path: Path) -> Path | None:
    """Return the APK to analyze.

    Handles:
    1. Direct .apk file
    2. Directory containing a .apk file (recursive search)
    3. ZIP file wrapping an .apk — extracts the inner APK to a temp dir
    4. Directory with extracted APK contents (classes.dex present) — returns the dir itself
       so downstream can analyze it without a .apk container

    Returns None if nothing usable is found.
    """
    import tempfile

    if path.suffix.lower() == ".apk" and path.is_file():
        return path

    if path.is_dir():
        # First: look for a nested .apk file
        for candidate in sorted(path.rglob("*.apk")):
            return candidate
        # Second: APK may have been pre-extracted (artifact-extractor unpacks APK as ZIP)
        # Detect by presence of classes.dex — return the directory itself as a sentinel
        dex_files = sorted(path.rglob("classes.dex"))
        if dex_files:
            log(f"  No .apk file found but found {len(dex_files)} classes.dex — APK was pre-extracted")
            # Return the deepest directory that looks like APK root (has AndroidManifest.xml)
            for dex in dex_files:
                apk_root = dex.parent
                if (apk_root / "AndroidManifest.xml").exists():
                    log(f"  Using extracted APK contents at: {apk_root}")
                    return apk_root  # marker: directory WITH classes.dex
            # Fallback: parent of first classes.dex
            return dex_files[0].parent
        return None

    if path.suffix.lower() == ".zip" and path.is_file():
        # ZIP wrapping an APK — extract the APK to a temp dir
        try:
            with zipfile.ZipFile(path, "r") as zf:
                apk_members = [n for n in zf.namelist() if n.lower().endswith(".apk")]
                if apk_members:
                    tmp = Path(tempfile.mkdtemp(prefix="apk_"))
                    member = apk_members[0]
                    out = tmp / Path(member).name
                    with zf.open(member) as src, open(out, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    log(f"  Extracted inner APK from ZIP: {out.name}")
                    return out
        except Exception as e:
            log(f"  WARNING: failed to extract APK from ZIP: {e}")
        return None

    return None


# ---------------------------------------------------------------------------
# APK parsing via androguard
# ---------------------------------------------------------------------------

def parse_with_androguard(apk_path: Path) -> dict[str, Any]:
    """Use androguard to extract app metadata, declared permissions, and class packages."""
    try:
        from androguard.core.apk import APK  # androguard >= 4.x
    except ImportError:
        try:
            from androguard.core.bytecodes.apk import APK  # androguard 3.x
        except ImportError:
            log("WARNING: androguard not available — skipping DEX analysis")
            return {}

    log(f"Parsing APK with androguard: {apk_path.name}")
    try:
        a = APK(str(apk_path))
    except Exception as e:
        log(f"WARNING: androguard failed to parse APK: {e}")
        return {}

    result: dict[str, Any] = {
        "package": a.get_package() or "unknown",
        "version_name": a.get_androidversion_name() or "0.0",
        "version_code": a.get_androidversion_code() or "0",
        "min_sdk": a.get_min_sdk_version() or "unknown",
        "target_sdk": a.get_target_sdk_version() or "unknown",
        "permissions": sorted(a.get_permissions() or []),
        "libraries": sorted(a.get_libraries() or []),
        "native_libs": [],
        "declared_components": [],
        "third_party_packages": [],
    }

    # Collect .so names from the APK zip entries
    try:
        for name in a.zip.namelist():
            if name.startswith("lib/") and name.endswith(".so"):
                result["native_libs"].append(name)
    except Exception:
        pass

    # Try to get declared activities / services for context
    try:
        result["declared_components"] = [
            a.get_main_activity() or ""
        ]
    except Exception:
        pass

    # Enumerate top-level package names from DEX class list (heuristic for 3rd-party libs)
    try:
        from androguard.misc import AnalyzeAPK  # noqa: F401 — may not exist in all versions
        _, _, dx = AnalyzeAPK(str(apk_path))
        pkgs: set[str] = set()
        for cls in dx.get_classes():
            # cls.name looks like  Lcom/squareup/okhttp/...;
            m = re.match(r"^L([a-z][a-z0-9_/]+)/", cls.name)
            if m:
                parts = m.group(1).split("/")
                if len(parts) >= 3:
                    pkg = ".".join(parts[:3])
                    pkgs.add(pkg)
        # Filter out well-known Android SDK prefixes
        skip = {
            "android", "com.android", "dalvik", "java", "javax",
            "kotlin", "kotlinx", "org.jetbrains",
        }
        result["third_party_packages"] = sorted(
            p for p in pkgs if not any(p.startswith(s) for s in skip)
        )
    except Exception as e:
        log(f"  DEX class enumeration skipped: {e}")

    log(f"  package={result['package']}  version={result['version_name']}")
    log(f"  native libs found: {len(result['native_libs'])}")
    log(f"  3rd-party packages identified: {len(result['third_party_packages'])}")
    return result


# ---------------------------------------------------------------------------
# Extract native .so files
# ---------------------------------------------------------------------------

def extract_native_libs(apk_path: Path, dest: Path) -> list[Path]:
    """Extract all .so files from lib/ inside the APK to *dest*."""
    dest.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for member in zf.namelist():
                if member.startswith("lib/") and member.endswith(".so"):
                    # Flatten: lib/arm64-v8a/libfoo.so → dest/libfoo.so
                    lib_name = Path(member).name
                    out = dest / lib_name
                    if not out.exists():
                        with zf.open(member) as src, open(out, "wb") as dst:
                            shutil.copyfileobj(src, dst)
                        extracted.append(out)
    except Exception as e:
        log(f"WARNING: could not extract native libs: {e}")
    log(f"  extracted {len(extracted)} native .so files → {dest}")
    return extracted


# ---------------------------------------------------------------------------
# Parse pre-extracted APK directory (when artifact-extractor already unpacked it)
# ---------------------------------------------------------------------------

def parse_extracted_apk_dir(apk_dir: Path) -> dict[str, Any]:
    """Parse APK from its extracted directory contents (classes.dex + AndroidManifest.xml)."""
    log(f"Parsing extracted APK directory: {apk_dir}")
    result: dict[str, Any] = {
        "package": apk_dir.name,
        "version_name": "0.0",
        "version_code": "0",
        "min_sdk": "unknown",
        "target_sdk": "unknown",
        "permissions": [],
        "libraries": [],
        "native_libs": [],
        "declared_components": [],
        "third_party_packages": [],
    }

    # Parse binary AndroidManifest.xml with androguard's AXMLPrinter
    manifest_path = apk_dir / "AndroidManifest.xml"
    if manifest_path.exists():
        try:
            try:
                from androguard.core.axml import AXMLPrinter  # androguard 4.x
            except ImportError:
                from androguard.core.bytecodes.axml import AXMLPrinter  # androguard 3.x
            ap = AXMLPrinter(manifest_path.read_bytes())
            xml_str = ap.get_xml_obj()  # returns xml.dom.minidom object or string
            import xml.etree.ElementTree as ET
            try:
                root = ET.fromstring(ap.get_xml())
            except Exception:
                root = None
            if root is not None:
                ns = "http://schemas.android.com/apk/res/android"
                result["package"] = root.get("package", apk_dir.name)
                result["version_name"] = root.get(f"{{{ns}}}versionName", "0.0")
                result["version_code"] = root.get(f"{{{ns}}}versionCode", "0")
                uses_sdk = root.find("uses-sdk")
                if uses_sdk is not None:
                    result["min_sdk"] = uses_sdk.get(f"{{{ns}}}minSdkVersion", "unknown")
                    result["target_sdk"] = uses_sdk.get(f"{{{ns}}}targetSdkVersion", "unknown")
                result["permissions"] = [
                    p.get(f"{{{ns}}}name", "") for p in root.findall("uses-permission")
                ]
            log(f"  package={result['package']}  version={result['version_name']}")
        except Exception as e:
            log(f"  WARNING: AndroidManifest.xml parsing failed: {e}")

    # Find native .so files
    result["native_libs"] = [
        str(p.relative_to(apk_dir)).replace("\\", "/")
        for p in apk_dir.rglob("*.so")
    ]
    log(f"  native libs: {len(result['native_libs'])}")

    # Enumerate Java packages from classes.dex via androguard
    import re
    dex_files = sorted(apk_dir.glob("classes*.dex"))
    if dex_files:
        pkgs: set[str] = set()
        for dex_path in dex_files:
            try:
                try:
                    from androguard.core.dex import DEX  # androguard 4.x
                    d = DEX(dex_path.read_bytes())
                except ImportError:
                    from androguard.core.bytecodes.dvm import DalvikVMFormat  # 3.x
                    d = DalvikVMFormat(dex_path.read_bytes())
                for cls in d.get_classes():
                    m = re.match(r"^L([a-z][a-z0-9_/]+)/", cls.get_name())
                    if m:
                        parts = m.group(1).split("/")
                        if len(parts) >= 3:
                            pkgs.add(".".join(parts[:3]))
            except Exception as e:
                log(f"  DEX parsing of {dex_path.name} skipped: {e}")
        skip = {"android", "com.android", "dalvik", "java", "javax", "kotlin", "kotlinx", "org.jetbrains"}
        result["third_party_packages"] = sorted(p for p in pkgs if not any(p.startswith(s) for s in skip))
        log(f"  3rd-party packages: {len(result['third_party_packages'])}")

    return result


def extract_native_libs_from_dir(apk_dir: Path, dest: Path) -> list[Path]:
    """Copy .so files from extracted APK directory to dest."""
    dest.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []
    for so_path in apk_dir.rglob("*.so"):
        out = dest / so_path.name
        if not out.exists():
            shutil.copy2(so_path, out)
            extracted.append(out)
    log(f"  copied {len(extracted)} native .so files → {dest}")
    return extracted


# ---------------------------------------------------------------------------
# Syft-compatible synthetic SBOM
# ---------------------------------------------------------------------------

SYFT_SCHEMA = "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.4.json"


def build_syft_sbom(apk_path: Path, meta: dict[str, Any], display_name: str | None = None) -> dict[str, Any]:
    """Build a minimal syft-json SBOM from APK metadata."""
    if display_name is None:
        display_name = apk_path.name
    now = datetime.now(timezone.utc).isoformat()
    artifacts: list[dict[str, Any]] = []

    # Main application component
    app_id = str(uuid.uuid4())
    artifacts.append({
        "id": app_id,
        "name": meta.get("package", display_name),
        "version": meta.get("version_name", "0.0"),
        "type": "java-archive",
        "foundBy": "apk-analyzer",
        "locations": [{"path": f"/{apk_path.name}"}],
        "licenses": [],
        "language": "java",
        "cpes": [],
        "purl": f"pkg:apk/android/{meta.get('package', apk_path.stem)}@{meta.get('version_name', '0.0')}",
        "metadataType": "AndroidApkMetadata",
        "metadata": {
            "packageName": meta.get("package", ""),
            "versionCode": str(meta.get("version_code", "")),
            "minSdkVersion": str(meta.get("min_sdk", "")),
            "targetSdkVersion": str(meta.get("target_sdk", "")),
            "permissions": meta.get("permissions", []),
        },
    })

    # Native libraries as separate components
    for so_path in meta.get("native_libs", []):
        lib_name = Path(so_path).name.removesuffix(".so")
        lib_id = str(uuid.uuid4())
        artifacts.append({
            "id": lib_id,
            "name": lib_name,
            "version": "unknown",
            "type": "binary",
            "foundBy": "apk-analyzer",
            "locations": [{"path": so_path}],
            "licenses": [],
            "language": "",
            "cpes": [f"cpe:2.3:a:*:{lib_name}:*:*:*:*:*:android:*:*"],
            "purl": f"pkg:generic/{lib_name}@unknown",
            "metadataType": "",
            "metadata": {},
        })

    # Third-party Java packages (heuristic — version unknown)
    for pkg in meta.get("third_party_packages", [])[:50]:  # cap at 50 to keep SBOM sane
        pkg_id = str(uuid.uuid4())
        short = pkg.split(".")[-1]
        artifacts.append({
            "id": pkg_id,
            "name": pkg,
            "version": "unknown",
            "type": "java-archive",
            "foundBy": "apk-analyzer-dex-heuristic",
            "locations": [{"path": "/classes.dex"}],
            "licenses": [],
            "language": "java",
            "cpes": [],
            "purl": f"pkg:maven/{pkg.replace('.', '/')}/{short}@unknown",
            "metadataType": "",
            "metadata": {},
        })

    sbom = {
        "$schema": SYFT_SCHEMA,
        "anchore:schema": "16.0.4",
        "schema": {"version": "16.0.4", "url": SYFT_SCHEMA},
        "artifacts": artifacts,
        "artifactRelationships": [],
        "files": [],
        "distro": {},
        "descriptor": {
            "name": "apk-analyzer",
            "version": "1.0.0",
            "configuration": {},
        },
        "source": {
            "id": str(uuid.uuid4()),
            "name": display_name,
            "version": meta.get("version_name", "0.0"),
            "type": "file",
            "metadata": {"path": f"/{apk_path.name}"},
        },
    }
    return sbom


# ---------------------------------------------------------------------------
# Text report
# ---------------------------------------------------------------------------

def write_text_report(apk_path: Path, meta: dict[str, Any], report_path: Path) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "=" * 60,
        "APK Analysis Report",
        "=" * 60,
        f"File        : {apk_path.name}",
        f"Package     : {meta.get('package', 'unknown')}",
        f"Version     : {meta.get('version_name', '?')} (code {meta.get('version_code', '?')})",
        f"Min SDK     : {meta.get('min_sdk', '?')}",
        f"Target SDK  : {meta.get('target_sdk', '?')}",
        "",
        f"Native libs ({len(meta.get('native_libs', []))}):",
    ]
    for lib in meta.get("native_libs", []):
        lines.append(f"  {lib}")

    lines += [
        "",
        f"Declared 3rd-party Java packages ({len(meta.get('third_party_packages', []))}) [heuristic]:",
    ]
    for pkg in meta.get("third_party_packages", [])[:30]:
        lines.append(f"  {pkg}")
    if len(meta.get("third_party_packages", [])) > 30:
        lines.append(f"  ... and {len(meta['third_party_packages']) - 30} more")

    lines += [
        "",
        f"Permissions ({len(meta.get('permissions', []))}):",
    ]
    for perm in meta.get("permissions", [])[:20]:
        lines.append(f"  {perm}")

    lines += [
        "",
        "NOTE: Java library versions are unknown (no gradle/maven metadata in APK).",
        "      CVE matching is only reliable for native .so libraries.",
        "      For deeper analysis use MobSF or jadx + manual review.",
        "=" * 60,
    ]
    report_path.write_text("\n".join(lines), encoding="utf-8")
    log(f"  text report → {report_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="APK analyzer for el-sca-ansamble")
    parser.add_argument("--input",  default="/scan-target", help="Path to .apk file or directory")
    parser.add_argument("--output", default="/workspace/artifacts", help="Artifacts output root")
    args = parser.parse_args()

    input_path  = Path(args.input)
    output_root = Path(args.output)

    apk_path = find_apk(input_path)
    if apk_path is None:
        log(f"ERROR: no .apk file found at {input_path}")
        return 1

    is_extracted_dir = apk_path.is_dir()  # True when APK was pre-extracted
    log(f"APK: {apk_path}  (mode: {'extracted-dir' if is_extracted_dir else 'apk-file'})")

    # Parse
    if is_extracted_dir:
        meta = parse_extracted_apk_dir(apk_path)
    else:
        meta = parse_with_androguard(apk_path)

    if not meta:
        # fallback minimal metadata from filename
        stem = apk_path.stem if not is_extracted_dir else apk_path.name
        meta = {
            "package": stem,
            "version_name": "0.0",
            "version_code": "0",
            "min_sdk": "unknown",
            "target_sdk": "unknown",
            "permissions": [],
            "libraries": [],
            "native_libs": [],
            "third_party_packages": [],
        }
        if not is_extracted_dir:
            try:
                with zipfile.ZipFile(apk_path, "r") as zf:
                    meta["native_libs"] = [n for n in zf.namelist() if n.startswith("lib/") and n.endswith(".so")]
            except Exception:
                pass

    # Extract native .so files for cve-bin-tool scanning
    native_dir = output_root / "extracted" / "apk-native"
    if is_extracted_dir:
        extract_native_libs_from_dir(apk_path, native_dir)
    else:
        extract_native_libs(apk_path, native_dir)

    # Use a stable display name regardless of whether we got file or dir
    display_name = apk_path.name if not is_extracted_dir else (meta.get("package") or apk_path.name)

    # Generate SBOM
    sbom_dir = output_root / "sbom"
    sbom_dir.mkdir(parents=True, exist_ok=True)
    sbom = build_syft_sbom(apk_path, meta, display_name)
    sbom_path = sbom_dir / "syft.json"
    sbom_path.write_text(json.dumps(sbom, indent=2, ensure_ascii=False), encoding="utf-8")
    log(f"  SBOM ({len(sbom['artifacts'])} components) → {sbom_path}")

    # Write text report
    report_path = output_root / "reports" / "apk" / "apk_analysis.txt"
    write_text_report(apk_path, meta, report_path)

    log("APK analysis complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
