"""SBOM-ingest: deliveries that ARE an SBOM must still get matched.

Regression cover for CYBERSEC-13860, where two CycloneDX documents (713 Maven
components, 231 known CVEs) were delivered instead of the applications and the
pipeline reported "nothing found" because Syft could only catalogue the files
holding them.
"""

from __future__ import annotations

import json
from pathlib import Path

from resilient_updates.sbom_ingest import build_scan_input, detect_sboms, sniff


def _cyclonedx(*comps: tuple[str, str]) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"type": "library", "name": n, "version": v, "purl": f"pkg:maven/test/{n}@{v}"}
            for n, v in comps
        ],
    }


def _spdx(*comps: tuple[str, str]) -> dict:
    return {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": n,
                "versionInfo": v,
                "externalRefs": [
                    {"referenceType": "purl", "referenceLocator": f"pkg:pypi/{n}@{v}"}
                ],
            }
            for n, v in comps
        ],
    }


def test_sniff_recognises_formats_by_content_not_name(tmp_path: Path):
    cdx = tmp_path / "Weird-Vendor-Name.json"
    cdx.write_text(json.dumps(_cyclonedx(("a", "1"))), encoding="utf-8")
    spdx = tmp_path / "whatever.json"
    spdx.write_text(json.dumps(_spdx(("b", "2"))), encoding="utf-8")
    syft = tmp_path / "s.json"
    syft.write_text(
        json.dumps({"descriptor": {"name": "syft"}, "artifacts": [{"name": "c", "version": "3"}]}),
        encoding="utf-8",
    )
    plain = tmp_path / "config.json"
    plain.write_text(json.dumps({"hello": "world"}), encoding="utf-8")

    assert sniff(cdx) == "cyclonedx"
    assert sniff(spdx) == "spdx"
    assert sniff(syft) == "syft"
    assert sniff(plain) is None


def test_detect_finds_nested_sboms_and_ignores_noise(tmp_path: Path):
    deep = tmp_path / "depth1" / "app_extracted"
    deep.mkdir(parents=True)
    (deep / "bom.json").write_text(json.dumps(_cyclonedx(("x", "1"), ("y", "2"))), encoding="utf-8")
    (tmp_path / "package.json").write_text(json.dumps({"name": "n"}), encoding="utf-8")

    found = detect_sboms(tmp_path)
    assert len(found) == 1
    assert found[0]["format"] == "cyclonedx"
    assert found[0]["components"] == 2


def test_merge_dedupes_on_purl_and_keeps_syft_components(tmp_path: Path):
    tree = tmp_path / "tree"
    tree.mkdir()
    # delivered SBOM shares one component with Syft's own output
    (tree / "delivered.json").write_text(
        json.dumps(_cyclonedx(("shared", "1"), ("only-delivered", "9"))), encoding="utf-8"
    )
    base = tmp_path / "cyclonedx.json"
    base.write_text(json.dumps(_cyclonedx(("shared", "1"), ("only-syft", "5"))), encoding="utf-8")
    out = tmp_path / "scan-input.cdx.json"

    r = build_scan_input(tree, base_cyclonedx=base, output=out)

    assert r["components_from_syft"] == 2
    assert r["components_from_provided"] == 1  # "shared" deduped
    assert r["components_total"] == 3
    names = {c["name"] for c in json.loads(out.read_text(encoding="utf-8"))["components"]}
    assert names == {"shared", "only-syft", "only-delivered"}


def test_output_always_written_even_without_delivered_sboms(tmp_path: Path):
    """Scanners point at one fixed path, so it must exist on every run."""
    tree = tmp_path / "tree"
    tree.mkdir()
    base = tmp_path / "cyclonedx.json"
    base.write_text(json.dumps(_cyclonedx(("solo", "1"))), encoding="utf-8")
    out = tmp_path / "scan-input.cdx.json"

    r = build_scan_input(tree, base_cyclonedx=base, output=out)

    assert out.is_file()
    assert r["provided_sboms"] == []
    assert r["components_total"] == 1


def test_rerun_is_idempotent_and_skips_our_own_output(tmp_path: Path):
    """Re-running must not fold a previous merge into itself."""
    repo = tmp_path
    tree = repo / "artifacts" / "extracted" / "current"
    tree.mkdir(parents=True)
    (tree / "delivered.json").write_text(json.dumps(_cyclonedx(("a", "1"))), encoding="utf-8")
    out = repo / "artifacts" / "sbom" / "scan-input.cdx.json"

    first = build_scan_input(tree, base_cyclonedx=None, output=out, repo_root=repo)
    second = build_scan_input(tree, base_cyclonedx=out, output=out, repo_root=repo)

    assert first["components_total"] == second["components_total"] == 1
