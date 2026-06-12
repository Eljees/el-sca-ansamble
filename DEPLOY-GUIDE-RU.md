# el-sca-ansamble — развёртывание, обновление баз и сканирование

Контейнерный SCA-ансамбль: **Syft** (SBOM) + **Grype** + **Trivy** + **cve-bin-tool**,
агрегированный отчёт (Markdown + HTML). Разворачивается с нуля на чистой машине
несколькими командами — образы с Docker Hub, исходники с GitHub, базы CVE
скачиваются после клонирования.

> Проверено на чистом `git clone` + `docker compose build` (Ubuntu) и на хосте Windows.
> Скрипты `update-db.sh` / `run-scan.sh` сами чинят права на томах (`volume-init`)
> и сами подбирают рабочий выход в сеть (`route-doctor`) — отдельных действий не требуется.

---

## 0. Что нужно на машине

- **Docker Engine + Docker Compose v2** (`docker compose version` ≥ 2.x)
- **git** (на Windows — Git for Windows, даёт `git-bash`)
- ~10 ГБ свободного места (базы Grype ~1.8 ГБ, NVD-фиды cve-bin-tool, кэш Trivy)
- Доступ в интернет (прямой или через прокси/VPN — см. §5)

Ubuntu быстрый старт:
```bash
sudo apt-get update && sudo apt-get install -y git ca-certificates curl
curl -fsSL https://get.docker.com | sudo sh
sudo apt-get install -y docker-compose-plugin
sudo usermod -aG docker "$USER"   # затем перелогиниться
```

---

## 1. Развёртывание с нуля

```bash
# 1.1 Клонируем
git clone https://github.com/Eljees/el-sca-ansamble.git
cd el-sca-ansamble

# 1.2 Конфиг из шаблона
cp .env.example .env
#    Дефолты уже рабочие: режим NVD = feed, политика = degraded-ok.
#    (опционально) для источника GAD/GitHub Advisory впишите токен:
#       GITHUB_TOKEN=ghp_xxxx        # read-only classic PAT, только в .env (в git не коммитить!)
#    (опционально) прокси — см. §5.

# 1.3 Образы: либо СКАЧАТЬ с Docker Hub …
docker compose pull
#    … либо СОБРАТЬ локально из Dockerfile (если pull недоступен):
# docker compose build
```

Образы на Docker Hub (тег `0.1.1`): `elariaphd/el-sca-resilient-updater`,
`el-sca-extractor`, `el-sca-cve-bin-tool`, `el-sca-win-analyzer`, `el-sca-apk-analyzer`.
Сами сканеры (grype/trivy/syft) тянутся с публичных реестров автоматически.

---

## 2. Обновление баз CVE (CLI)

Один скрипт — все базы или по отдельности. Перед обновлением он сам выставляет
права на томах и подбирает живой выход в сеть.

```bash
./scripts/update-db.sh all            # trivy + grype + cve-bin-tool
./scripts/update-db.sh trivy          # только Trivy
./scripts/update-db.sh grype          # только Grype
./scripts/update-db.sh cve-bin-tool   # только cve-bin-tool (NVD/OSV/REDHAT/EPSS/… + GAD при токене)
```

Проверить свежесть баз:
```bash
docker compose run --rm db-admin db-status grype        --path /var/lib/resilient-db/grype/active --warning-age 24h
docker compose run --rm db-admin db-status trivy        --path /var/lib/resilient-db/trivy        --warning-age 24h
docker compose run --rm db-admin db-status cve-bin-tool  --path /home/appuser/.cache/cve-bin-tool  --warning-age 24h
```

> cve-bin-tool без `GITHUB_TOKEN` просто пропускает источник GAD — остальные
> (NVD/OSV/REDHAT/EPSS/PURL2CPE/RSD) обновляются, БД активируется (политика `degraded-ok`).

---

## 3. Сканирование артефакта (CLI)

```bash
./scripts/run-scan.sh -t /путь/к/артефакту.tar.gz --tool all -c
```

- `-t` — путь к файлу или директории (`.tar.gz`, `.zip`, `.apk`, `.exe`, каталог).
  Архивы распаковываются автоматически.
- `--tool` — `all` (по умолчанию) или один из `syft|grype|trivy|cve-bin-tool`.
- `-c` — очистить артефакты прошлого прогона.
- `-u` — дополнительно обновить базы перед сканом (иначе берутся уже скачанные).

Конвейер: `extract → Syft SBOM → Grype + Trivy + cve-bin-tool → агрегированный отчёт`.

**Где смотреть результат:**
- рядом с артефактом — `*_report_<ДАТА>.md` и `*_report_<ДАТА>.html`;
- `artifacts/reports/final/` — сводный отчёт `cve_analysis_report_generated_ru.md` + `index.html`;
- `artifacts/reports/{grype,trivy,cve-bin-tool}/report.json` — «сырой» JSON по каждому инструменту.

---

## 4. То же через графический интерфейс (GUI / дашборд)

Дашборд бывает в двух режимах.

### 4.1 Активный режим — обновление баз + сканы кнопками (запуск на хосте)

Запускается локально на машине (нужен Python ≥ 3.10 + `fastapi` + `uvicorn`):
```bash
pip install "uvicorn[standard]" fastapi          # один раз
python -m resilient_updates.cli dashboard --repo-root . --port 8080
```
Открыть в браузере **http://127.0.0.1:8080**. Возможности:

- **«☢ Обновить ВСЁ»** — полное обновление всех баз; есть кнопки по каждому
  инструменту и по отдельным источникам cve-bin-tool (NVD / OSV / GAD / REDHAT / …).
- **Перетащить артефакт** в зону загрузки (или выбрать файл) → отметить инструменты →
  **«▶ Тулз ок, погнали»**. Прогресс по стадиям (Extract → Syft → Grype → Trivy →
  cve-bin-tool → Отчёт) и живой лог видны на странице; готовый отчёт открывается оттуда же.
- Бейдж сети сверху + **«Перепроверить сеть»** показывают, какой выход в интернет
  выбран (прямой / хост-прокси / сайдкары).

> Активный режим запускает сканы/обновления через тот же `run-scan.sh` на хосте,
> поэтому ему нужен доступ к Docker. Порт меняется флагом `--port` (если 8080 занят).

### 4.2 Только просмотр (read-only) — контейнером

Отдаёт отчёты последнего прогона, ничего не сканирует и не меняет:
```bash
docker compose --profile dashboard up -d        # http://127.0.0.1:8080
docker compose --profile dashboard down          # остановить
```

---

## 5. Сеть / прокси / VPN

По умолчанию — прямое соединение. Если выход в интернет только через прокси,
впишите в `.env` (примеры в самом файле):
```bash
# v2rayN / Xray «mixed» inbound на хосте (типичный порт 10808):
HTTP_PROXY=http://host.docker.internal:10808
HTTPS_PROXY=http://host.docker.internal:10808
ALL_PROXY=socks5h://host.docker.internal:10808
NO_PROXY=localhost,127.0.0.1,grype-static
```
`update-db.sh` / `run-scan.sh` перед стартом сами пробуют доступные маршруты
(`route-doctor`): сайдкары → хост-прокси → прямое. Явно заданный `HTTP_PROXY`/`ALL_PROXY`
всегда в приоритете. Отключить авто-подбор: `--no-auto-route`.

---

## 6. Заметки

- **Windows:** команды запускать в **Git Bash**; путь к артефакту — в стиле
  `/d/dev/.../app.zip`. Если порт 8080 занят/зарезервирован Windows — берите другой
  (`--port 8090`).
- **GAD-токен** (`GITHUB_TOKEN`) кладите только в `.env` (он в `.gitignore`).
  В git коммитить нельзя — GitHub автоматически отзывает запушенные токены.
- **Закрытая сеть к grype.anchore.io / ghcr.io:** на некоторых площадках реестры
  баз могут быть закрыты файрволом. Тогда обновляйте Grype/Trivy там, где сеть есть,
  и переносите готовый том БД (см. `docs/airgap.md`). Сам конвейер при этом не меняется.
- Полезные доки в репозитории: `QUICK_START.md`, `docs/ubuntu-from-github.md`,
  `docs/proxy.md`, `docs/airgap.md`, `docs/runbook.md`.

---

## Короткая шпаргалка

```bash
# развернуть
git clone https://github.com/Eljees/el-sca-ansamble.git && cd el-sca-ansamble
cp .env.example .env            # при необходимости впишите GITHUB_TOKEN / прокси
docker compose pull             # или: docker compose build

# обновить базы
./scripts/update-db.sh all

# просканировать
./scripts/run-scan.sh -t /путь/к/артефакту.zip --tool all -c
#   → отчёт в artifacts/reports/final/ и рядом с артефактом

# GUI (обновление + сканы кнопками)
python -m resilient_updates.cli dashboard --repo-root . --port 8080   # http://127.0.0.1:8080
```
