#!/usr/bin/env sh
# scan_archive.sh — Linux-эквивалент run-scan.ps1 -Extract
#
# Запускает полный цикл: extract → scan (syft/trivy/grype/cve-bin-tool) → collect-report.
# Результат: artifacts/reports/final/cve_analysis_report_generated_ru.md
#
# Использование:
#   ./scripts/scan_archive.sh <archive_or_dir> [CASE_ID]
#
# Переменные окружения (опциональные):
#   CASE_ID                — идентификатор тикета (по умолчанию: CYBERSEC-UNKNOWN)
#   EXTRACT_OUTPUT_REL     — путь к extracted-dir относительно корня репозитория
#                            (по умолчанию: artifacts/extracted/current)
#   EXTRACT_MAX_DEPTH      — глубина рекурсивного разархивирования (по умолчанию: 4)
#   REPORT_OUTPUT          — путь к итоговому Markdown-отчёту внутри контейнера
#   UPDATE_DB              — если = 1, сначала запустить update-профиль для обновления БД
set -eu

ARCHIVE="${1:-${SCAN_TARGET_HOST:-}}"
CASE_ID="${CASE_ID:-${2:-CYBERSEC-UNKNOWN}}"
EXTRACT_OUTPUT_REL="${EXTRACT_OUTPUT_REL:-artifacts/extracted/current}"
EXTRACT_MAX_DEPTH="${EXTRACT_MAX_DEPTH:-4}"
REPORT_OUTPUT="${REPORT_OUTPUT:-/workspace/artifacts/reports/final/cve_analysis_report_generated_ru.md}"
UPDATE_DB="${UPDATE_DB:-0}"

if [ -z "$ARCHIVE" ]; then
  echo "Использование: $0 <archive_or_dir> [CASE_ID]" >&2
  echo "  или задать SCAN_TARGET_HOST=<path> и вызвать без аргументов" >&2
  exit 2
fi

if [ ! -e "$ARCHIVE" ]; then
  echo "Ошибка: путь не существует: $ARCHIVE" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "[scan_archive] Объект анализа : $ARCHIVE"
echo "[scan_archive] CASE_ID        : $CASE_ID"
echo "[scan_archive] Extracted dir  : $EXTRACT_OUTPUT_REL"

# --------------------------------------------------------------------------
# Рендерим флаги Trivy заранее (python должен быть доступен на хосте)
# --------------------------------------------------------------------------
TRIVY_FLAGS=""
if command -v python >/dev/null 2>&1; then
  TRIVY_FLAGS="$(python -m resilient_updates.cli render-flags trivy 2>/dev/null || true)"
elif command -v python3 >/dev/null 2>&1; then
  TRIVY_FLAGS="$(python3 -m resilient_updates.cli render-flags trivy 2>/dev/null || true)"
fi

# --------------------------------------------------------------------------
# Шаг 0 (опционально): обновление баз данных
# --------------------------------------------------------------------------
if [ "$UPDATE_DB" = "1" ]; then
  echo "[scan_archive] Шаг 0: обновление БД..."
  TRIVY_RENDERED_FLAGS="$TRIVY_FLAGS" \
    docker compose --profile update run --rm trivy-updater
  docker compose --profile update run --rm grype-updater
  docker compose --profile update run --rm grype-db-importer
  docker compose --profile update run --rm cve-bin-tool-updater
fi

# --------------------------------------------------------------------------
# Шаг 1: разархивирование входного объекта
# --------------------------------------------------------------------------
echo "[scan_archive] Шаг 1: разархивирование..."
mkdir -p "$EXTRACT_OUTPUT_REL"

EXTRACT_INPUT_HOST="$ARCHIVE" \
EXTRACT_OUTPUT="/workspace/${EXTRACT_OUTPUT_REL}" \
EXTRACT_MAX_DEPTH="$EXTRACT_MAX_DEPTH" \
  docker compose --profile extract run --rm artifact-extractor

EXTRACTED_HOST="$(pwd)/${EXTRACT_OUTPUT_REL}"
echo "[scan_archive] Extracted dir (host): $EXTRACTED_HOST"

# --------------------------------------------------------------------------
# Шаг 2: сканирование разархивированного содержимого
# Scanners bind-mount SCAN_TARGET_HOST → /scan-target внутри контейнера.
# Ставим SCAN_TARGET_HOST = extracted dir; все SYFT/CVE/TRIVY TARGET → /scan-target.
# --------------------------------------------------------------------------
echo "[scan_archive] Шаг 2: сканирование..."

export SCAN_TARGET_HOST="$EXTRACTED_HOST"
export SCAN_TARGET_CONTAINER="/scan-target"
export SCAN_TARGET_DISPLAY="${ARCHIVE} → ${EXTRACTED_HOST}"
export SYFT_TARGET="/scan-target"
export SYFT_FROM="dir"
export CVE_BIN_TOOL_TARGET="/scan-target"
export TRIVY_TARGET="/scan-target"
export TRIVY_SCAN_KIND="${TRIVY_SCAN_KIND:-fs}"
export TRIVY_RENDERED_FLAGS="$TRIVY_FLAGS"

mkdir -p artifacts/reports/grype artifacts/reports/trivy \
          artifacts/reports/cve-bin-tool artifacts/sbom

docker compose --profile scan run --rm syft-sbom
docker compose --profile scan run --rm -e "TRIVY_RENDERED_FLAGS=${TRIVY_FLAGS}" trivy-scanner
docker compose --profile scan run --rm grype-scanner
docker compose --profile scan run --rm cve-bin-tool-scanner

# --------------------------------------------------------------------------
# Шаг 3: сборка отчёта
# --------------------------------------------------------------------------
echo "[scan_archive] Шаг 3: сборка отчёта..."

CASE_ID="$CASE_ID" \
SCAN_TARGET="$SCAN_TARGET_CONTAINER" \
SCAN_TARGET_HOST="$SCAN_TARGET_HOST" \
SCAN_TARGET_DISPLAY="$SCAN_TARGET_DISPLAY" \
REPORT_OUTPUT="$REPORT_OUTPUT" \
  docker compose --profile report run --rm report-collector

echo "[scan_archive] Готово."
echo "[scan_archive] Отчёт: artifacts/reports/final/cve_analysis_report_generated_ru.md"
