#!/usr/bin/env sh
set -eu

command -v docker >/dev/null 2>&1 || { echo "docker is required"; exit 3; }
docker compose version >/dev/null 2>&1 || { echo "docker compose is required"; exit 3; }
PYTHON_BIN="$(command -v python || true)"
if [ -z "$PYTHON_BIN" ]; then
  PYTHON_BIN="$(command -v python3 || true)"
fi
[ -n "$PYTHON_BIN" ] || { echo "python is required"; exit 3; }

mkdir -p artifacts/reports artifacts/provenance artifacts/sbom artifacts/cache artifacts/mirror

docker compose --profile default --profile update --profile scan --profile test-failover --profile offline --profile report config >/dev/null
$PYTHON_BIN -m resilient_updates.cli validate-config >/dev/null
pytest -q

echo "smoke test completed"
