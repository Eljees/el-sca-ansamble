from __future__ import annotations

from pathlib import Path

from resilient_updates.artifact_catalog import ArtifactCatalog, detect_case_id, is_valid_case_id


def test_case_id_helpers():
    assert detect_case_id("foo/CYBERSEC-12345/app.zip") == "CYBERSEC-12345"
    assert detect_case_id("plain.zip") == ""
    assert is_valid_case_id("")
    assert is_valid_case_id("CYBERSEC-1")
    assert not is_valid_case_id("CASE-1")


def test_catalog_create_upload_and_add_run(tmp_path: Path):
    catalog = ArtifactCatalog(tmp_path)
    artifact = catalog.create_upload(filename="CYBERSEC-7-demo.zip", fileobj=_blob(b"PK\x03\x04"))
    assert artifact["case_id"] == "CYBERSEC-7"
    stored = Path(artifact["stored_path"])
    assert stored.is_file()

    run_dir = tmp_path / "runs" / "CYBERSEC-7-20260707-120000"
    catalog.add_run(artifact["id"], run_id=run_dir.name, run_dir=run_dir)
    listed = catalog.list_artifacts()
    assert listed[0]["run_count"] == 1
    assert listed[0]["latest_run_id"] == run_dir.name


def test_catalog_legacy_override_and_hidden_runs(tmp_path: Path):
    catalog = ArtifactCatalog(tmp_path)
    run_dir = tmp_path / "runs" / "legacy-20260707-120000"
    (run_dir / "reports" / "final").mkdir(parents=True)
    (run_dir / "MANIFEST.json").write_text(
        '{"case_id":"CYBERSEC-3","target":{"host":"C:/drops/sample.zip","sha256":"abc"}}',
        encoding="utf-8",
    )
    artifacts = catalog.list_artifacts(
        legacy_runs=[
            {
                "id": run_dir.name,
                "path": str(run_dir),
                "manifest_present": True,
                "provenance_tools": [],
                "report_count": 0,
            }
        ]
    )
    legacy = artifacts[0]
    assert legacy["case_id"] == "CYBERSEC-3"

    patched = catalog.update_artifact(
        legacy["id"],
        case_id="CYBERSEC-44",
        display_name="sample-renamed",
        legacy_runs=[
            {
                "id": run_dir.name,
                "path": str(run_dir),
                "manifest_present": True,
                "provenance_tools": [],
                "report_count": 0,
            }
        ],
    )
    assert patched is not None
    assert patched["display_name"] == "sample-renamed"

    catalog.hide_run(run_dir.name)
    assert catalog.deleted_run_ids() == {run_dir.name}


def test_catalog_dedups_repeated_scans_of_same_artifact(tmp_path: Path):
    # 2026-07-17: re-scanning one .exe must NOT clone a card per run. Two runs
    # of the same input (same sha256) collapse into a single artifact with two
    # runs; a genuinely different file stays a separate card.
    catalog = ArtifactCatalog(tmp_path)

    def _mk_run(run_id: str, sha: str, host: str = "C:/drops/avandoc.exe") -> dict:
        rd = tmp_path / "runs" / run_id
        rd.mkdir(parents=True)
        (rd / "MANIFEST.json").write_text(
            '{"case_id":"CYBERSEC-13388","target":{"host":"%s","sha256":"%s"}}' % (host, sha),
            encoding="utf-8",
        )
        return {"id": run_id, "path": str(rd), "manifest_present": True,
                "provenance_tools": [], "report_count": 0}

    legacy = [
        _mk_run("CYBERSEC-13388-20260717-120000", "aaa"),
        _mk_run("CYBERSEC-13388-20260717-132028", "aaa"),          # same file, rescan
        _mk_run("CYBERSEC-13388-20260717-140000", "bbb", "C:/drops/other.exe"),
    ]
    artifacts = catalog.list_artifacts(legacy_runs=legacy)
    # avandoc collapses to ONE card with TWO runs; other.exe is its own card.
    avandoc = [a for a in artifacts if a["sha256"] == "aaa"]
    assert len(avandoc) == 1
    assert avandoc[0]["run_count"] == 2
    # newest run is surfaced as latest
    assert avandoc[0]["latest_run_id"] == "CYBERSEC-13388-20260717-132028"
    assert len(artifacts) == 2


def _blob(data: bytes):
    import io

    return io.BytesIO(data)
