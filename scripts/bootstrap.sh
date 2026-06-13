#!/usr/bin/env bash
# bootstrap.sh — развернуть комплекс «в несколько команд» на чистой машине.
#
# После `git clone` достаточно:
#   ./scripts/bootstrap.sh --update-db        # полный ввод в строй (с базами)
# или по шагам:
#   ./scripts/bootstrap.sh                    # подготовка + сборка + smoke
#   ./scripts/update-db.sh all                # базы отдельно (долго, нужна сеть)
#
# Что делает (идемпотентно — повторный запуск безопасен):
#   1. Проверяет docker + compose v2.
#   2. Создаёт .env из .env.example (если ещё нет).
#   3. Валидирует compose-схему.
#   4. volume-init: нормализует владельца томов/artifacts (uid 1001) —
#      обязательный шаг на Linux, безвредный на Docker Desktop.
#   5. Собирает локальные образы (extractor, cve-bin-tool, updater, ...).
#   6. (--update-db) Обновляет базы всех сканеров с авто-маршрутом.
#   7. Smoke-проверка: compose ps + список сервисов.
#
# Options:
#   -u, --update-db     После сборки сразу обновить базы (update-db.sh all)
#       --no-build      Пропустить сборку образов (только подготовка+smoke)
#   -h, --help          Эта справка
#
# Exit: 0 = комплекс готов; non-zero = смотрите сообщение об ошибке.
set -euo pipefail

UPDATE_DB=0
BUILD=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--update-db) UPDATE_DB=1; shift ;;
    --no-build)     BUILD=0; shift ;;
    -h|--help)
      sed -n '/^# bootstrap.sh/,/^set -euo/p' "$0" | grep "^#" | sed 's/^# \?//'
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

cd "$(dirname "$0")/.."
step() { printf '\n\e[36m── %s ──────────────────────────────\e[0m\n' "$*"; }

step "1/7 Проверка docker"
docker --version
docker compose version

step "2/7 Конфигурация (.env)"
if [[ ! -f .env ]]; then
  cp .env.example .env
  echo ".env создан из .env.example (отредактируйте при необходимости: прокси, NVD ключ)"
else
  echo ".env уже существует — не трогаю"
fi

# Compose интерполирует ${SCAN_TARGET_HOST:?} даже для config/build — дайте
# безвредное значение, чтобы подготовка не требовала настоящей цели скана.
export SCAN_TARGET_HOST="${SCAN_TARGET_HOST:-.}"
export EXTRACT_INPUT_HOST="${EXTRACT_INPUT_HOST:-.}"

step "2.5/7 Хостовые Python-зависимости (CLI + дашборд)"
PYTHON_BIN="$(command -v python3 || command -v python || true)"
if [[ -z "$PYTHON_BIN" ]]; then
  echo "WARN: python не найден — CLI/дашборд без host-Python не запустятся."
else
  PIP_BIN="$PYTHON_BIN -m pip"
  $PIP_BIN install --quiet --break-system-packages \
    "fastapi>=0.110" "uvicorn[standard]>=0.29" "httpx>=0.27" \
    "python-multipart>=0.0.9" "pyyaml>=6.0" "requests>=2.31.0" \
    2>&1 | grep -v "^WARNING.*root\|^WARNING.*venv" || true
  echo "host-deps: OK"
fi

step "3/7 Валидация compose-схемы"
docker compose config -q && echo "compose: OK"

step "4/7 volume-init (права томов под uid 1001)"
docker compose --profile volinit run --rm volume-init \
  || echo "WARN: volume-init не прошёл — на Linux возможны ошибки прав (повторите позже)"

if [[ $BUILD -eq 1 ]]; then
  step "5/7 Сборка локальных образов"
  docker compose --profile scan --profile update --profile extract --profile report build
else
  step "5/7 Сборка пропущена (--no-build)"
fi

if [[ $UPDATE_DB -eq 1 ]]; then
  step "6/7 Обновление баз (route-doctor выберет живой egress)"
  ./scripts/update-db.sh all
else
  step "6/7 Базы НЕ обновлялись (запустите: ./scripts/update-db.sh all)"
fi

step "7/7 Smoke-проверка"
docker compose config --services | sed 's/^/  · /'
docker compose ps || true

printf '\n\e[32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m\n'
printf '\e[32m Комплекс готов.\e[0m Дальше:\n'
printf '   скан:      ./scripts/run-scan.sh -t /path/to/artifact.tar.gz\n'
printf '   resume:    ./scripts/run-scan.sh -t <тот же target> --resume\n'
printf '   монитор:   python3 -m resilient_updates.cli monitor --watch 5\n'
printf '   дашборд:   python3 -m resilient_updates.cli dashboard  # http://127.0.0.1:8080\n'
printf '\e[32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m\n'
