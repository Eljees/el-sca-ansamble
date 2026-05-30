from __future__ import annotations

import io
import json
import tarfile
from copy import deepcopy

try:
    from datetime import UTC  # py3.11+
except ImportError:
    from datetime import timezone as _tz
    UTC = _tz.utc  # noqa: UP017
from datetime import datetime, timedelta
from hashlib import sha256
from pathlib import Path

from resilient_updates.cli import (
    EXIT_ALL_SOURCES_FAILED,
    EXIT_LKG_USED,
    EXIT_STALE_REJECTED,
    EXIT_SUCCESS,
    update_grype,
)
from resilient_updates.config import load_config
from tests.mock_feed_server.app import serve_in_thread


def _make_archive_bytes() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        payload = b"grype db"
        info = tarfile.TarInfo("db/README.txt")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def _listing(base_url: str, archive_bytes: bytes, built: datetime) -> str:
    digest = sha256(archive_bytes).hexdigest()
    return json.dumps(
        {
            "archive_url": f"{base_url}/db.tar.gz",
            "checksum": f"sha256:{digest}",
            "built": built.isoformat().replace("+00:00", "Z"),
        }
    )


def _base_config(tmp_path: Path, base_url: str) -> dict:
    config = load_config("tests/fixtures/feed_sources.example.yaml")
    config = deepcopy(config)
    config["grype"]["upstream_update_urls"] = [
        {"name": "primary", "url": f"{base_url}/primary/listing.json", "priority": 10, "enabled": True},
        {"name": "secondary", "url": f"{base_url}/secondary/listing.json", "priority": 20, "enabled": True},
    ]
    config["grype"]["atomic_activation_policy"]["temp_dir"] = str(tmp_path / "tmp")
    config["grype"]["atomic_activation_policy"]["active_dir"] = str(tmp_path / "active")
    config["grype"]["atomic_activation_policy"]["previous_dir"] = str(tmp_path / "previous")
    config["grype"]["atomic_activation_policy"]["provenance_path"] = str(tmp_path / "prov.json")
    config["grype"]["timeout_policy"]["update_available_timeout"] = 1
    config["grype"]["timeout_policy"]["update_download_timeout"] = 1
    return config


def test_429_falls_back_to_secondary(tmp_path: Path):
    archive = _make_archive_bytes()
    server, thread = serve_in_thread(
        {
            "/primary/listing.json": {"status": 429, "body": "busy", "content_type": "text/plain"},
            "/secondary/listing.json": {
                "status": 200,
                "body": _listing("http://127.0.0.1:0/secondary", archive, datetime.now(UTC)),
                "content_type": "application/json",
            },
            "/secondary/db.tar.gz": {"status": 200, "body": archive},
        }
    )
    host, port = server.server_address
    routes = server.RequestHandlerClass.routes
    routes["/secondary/listing.json"]["body"] = _listing(
        f"http://{host}:{port}/secondary", archive, datetime.now(UTC)
    )
    config = _base_config(tmp_path, f"http://{host}:{port}")
    try:
        result = update_grype(config)
    finally:
        server.shutdown()
        thread.join(timeout=2)
    assert result == EXIT_SUCCESS
    assert (tmp_path / "active" / "db.tar.gz").exists()


def test_corrupt_artifact_uses_last_known_good(tmp_path: Path):
    active = tmp_path / "active"
    active.mkdir()
    (active / "db.tar.gz").write_bytes(_make_archive_bytes())
    archive = b"not-a-tar"
    server, thread = serve_in_thread(
        {
            "/primary/listing.json": {
                "status": 200,
                "body": _listing("http://127.0.0.1:0/primary", archive, datetime.now(UTC)),
                "content_type": "application/json",
            },
            "/primary/db.tar.gz": {"status": 200, "body": archive},
        }
    )
    host, port = server.server_address
    server.RequestHandlerClass.routes["/primary/listing.json"]["body"] = _listing(
        f"http://{host}:{port}/primary", archive, datetime.now(UTC)
    )
    config = _base_config(tmp_path, f"http://{host}:{port}")
    config["grype"]["upstream_update_urls"] = [
        {
            "name": "primary",
            "url": f"http://{host}:{port}/primary/listing.json",
            "priority": 10,
            "enabled": True,
        }
    ]
    try:
        result = update_grype(config)
    finally:
        server.shutdown()
        thread.join(timeout=2)
    assert result == EXIT_LKG_USED
    assert (tmp_path / "active" / "db.tar.gz").exists()


def test_corrupt_primary_falls_back_to_secondary(tmp_path: Path):
    bad_archive = b"not-a-tar"
    good_archive = _make_archive_bytes()
    server, thread = serve_in_thread(
        {
            "/primary/listing.json": {
                "status": 200,
                "body": _listing("http://127.0.0.1:0/primary", bad_archive, datetime.now(UTC)),
                "content_type": "application/json",
            },
            "/primary/db.tar.gz": {"status": 200, "body": bad_archive},
            "/secondary/listing.json": {
                "status": 200,
                "body": _listing("http://127.0.0.1:0/secondary", good_archive, datetime.now(UTC)),
                "content_type": "application/json",
            },
            "/secondary/db.tar.gz": {"status": 200, "body": good_archive},
        }
    )
    host, port = server.server_address
    routes = server.RequestHandlerClass.routes
    routes["/primary/listing.json"]["body"] = _listing(
        f"http://{host}:{port}/primary", bad_archive, datetime.now(UTC)
    )
    routes["/secondary/listing.json"]["body"] = _listing(
        f"http://{host}:{port}/secondary", good_archive, datetime.now(UTC)
    )
    config = _base_config(tmp_path, f"http://{host}:{port}")
    try:
        result = update_grype(config)
    finally:
        server.shutdown()
        thread.join(timeout=2)
    assert result == EXIT_SUCCESS
    assert (tmp_path / "active" / "db.tar.gz").exists()


def test_missing_checksum_is_rejected_when_hash_validation_enabled(tmp_path: Path):
    archive = _make_archive_bytes()
    listing = json.dumps(
        {
            "archive_url": "http://127.0.0.1:0/primary/db.tar.gz",
            "built": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
    )
    server, thread = serve_in_thread(
        {
            "/primary/listing.json": {"status": 200, "body": listing, "content_type": "application/json"},
            "/primary/db.tar.gz": {"status": 200, "body": archive},
        }
    )
    host, port = server.server_address
    server.RequestHandlerClass.routes["/primary/listing.json"]["body"] = json.dumps(
        {
            "archive_url": f"http://{host}:{port}/primary/db.tar.gz",
            "built": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
    )
    config = _base_config(tmp_path, f"http://{host}:{port}")
    config["grype"]["upstream_update_urls"] = [
        {
            "name": "primary",
            "url": f"http://{host}:{port}/primary/listing.json",
            "priority": 10,
            "enabled": True,
        }
    ]
    try:
        result = update_grype(config)
    finally:
        server.shutdown()
        thread.join(timeout=2)
    assert result == EXIT_ALL_SOURCES_FAILED


def test_v6_latest_json_with_relative_path_is_accepted(tmp_path: Path):
    archive = b"\x28\xb5\x2f\xfdnot-real-zstd-but-valid-magic-for-routing"
    digest = sha256(archive).hexdigest()
    server, thread = serve_in_thread(
        {
            "/v6/latest.json": {
                "status": 200,
                "body": json.dumps(
                    {
                        "status": "active",
                        "schemaVersion": "v6.1.4",
                        "built": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                        "path": "vulnerability-db_v6.1.4_test.tar.zst",
                        "checksum": f"sha256:{digest}",
                    }
                ),
                "content_type": "application/json",
            },
            "/v6/vulnerability-db_v6.1.4_test.tar.zst": {"status": 200, "body": archive},
        }
    )
    host, port = server.server_address
    config = _base_config(tmp_path, f"http://{host}:{port}")
    config["grype"]["upstream_update_urls"] = [
        {"name": "primary", "url": f"http://{host}:{port}/v6/latest.json", "priority": 10, "enabled": True}
    ]
    try:
        result = update_grype(config)
    finally:
        server.shutdown()
        thread.join(timeout=2)
    assert result == EXIT_SUCCESS
    assert (tmp_path / "active" / "db.tar.zst").exists()
    assert (tmp_path / "active" / "v6" / "latest.json").exists()


def test_stale_db_is_rejected(tmp_path: Path):
    archive = _make_archive_bytes()
    stale = datetime.now(UTC) - timedelta(days=10)
    server, thread = serve_in_thread(
        {
            "/primary/listing.json": {
                "status": 200,
                "body": _listing("http://127.0.0.1:0/primary", archive, stale),
                "content_type": "application/json",
            },
            "/primary/db.tar.gz": {"status": 200, "body": archive},
        }
    )
    host, port = server.server_address
    server.RequestHandlerClass.routes["/primary/listing.json"]["body"] = _listing(
        f"http://{host}:{port}/primary", archive, stale
    )
    config = _base_config(tmp_path, f"http://{host}:{port}")
    config["grype"]["upstream_update_urls"] = [
        {
            "name": "primary",
            "url": f"http://{host}:{port}/primary/listing.json",
            "priority": 10,
            "enabled": True,
        }
    ]
    try:
        result = update_grype(config)
    finally:
        server.shutdown()
        thread.join(timeout=2)
    assert result == EXIT_STALE_REJECTED


def test_all_sources_down_without_lkg_fails_closed(tmp_path: Path):
    config = _base_config(tmp_path, "http://127.0.0.1:9")
    result = update_grype(config)
    assert result == EXIT_ALL_SOURCES_FAILED


def test_syft_source_policy_lists_explicit_sources():
    config = load_config("tests/fixtures/feed_sources.example.yaml")
    assert "registry" in config["syft"]["scan_sources"]
    assert "dir" in config["syft"]["scan_sources"]
