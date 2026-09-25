"""CYBERSEC-14915: the Windows analyzer opens nested containers (zip here; msi/cab need 7z)."""

from __future__ import annotations

import importlib.util
import io
import zipfile
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "analyze_win_installer", Path(__file__).resolve().parents[1] / "scripts" / "analyze_win_installer.py"
)
awi = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(awi)  # type: ignore[union-attr]


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_nested_zip_is_opened_and_jar_left_alone(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(awi, "NESTED_MIN_BYTES", 1)
    inner = _zip_bytes({"lib/jetty-http-10.0.25.jar": b"PK-jar-bytes", "bin/agent.dll": b"MZ"})
    (tmp_path / "payload").mkdir()
    (tmp_path / "payload" / "gateway.zip").write_bytes(inner)
    (tmp_path / "payload" / "keep.jar").write_bytes(b"PK")

    opened = awi.unpack_nested(tmp_path)

    assert opened == 1
    assert not (tmp_path / "payload" / "gateway.zip").exists()
    assert (tmp_path / "payload" / "gateway.zip_x" / "lib" / "jetty-http-10.0.25.jar").is_file()
    assert (tmp_path / "payload" / "keep.jar").is_file()  # jars are for Trivy, not to be exploded


def test_zip_slip_member_is_skipped(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(awi, "NESTED_MIN_BYTES", 1)
    (tmp_path / "evil.zip").write_bytes(_zip_bytes({"../../escape.txt": b"x", "ok.txt": b"y"}))

    awi.unpack_nested(tmp_path)

    assert not (tmp_path.parent / "escape.txt").exists()
    assert (tmp_path / "evil.zip_x" / "ok.txt").is_file()


def test_broken_zip_is_kept(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(awi, "NESTED_MIN_BYTES", 1)
    (tmp_path / "broken.zip").write_bytes(b"not a zip at all")

    assert awi.unpack_nested(tmp_path) == 0
    assert (tmp_path / "broken.zip").is_file()
    assert not (tmp_path / "broken.zip_x").exists()
