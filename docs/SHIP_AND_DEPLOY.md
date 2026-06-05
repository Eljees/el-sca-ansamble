# Выгрузка, развёртывание и первый скан

Это руководство описывает полный путь: как выгрузить проект **вместе с текущими
базами уязвимостей** на GitLab и в Docker-реестр, как на другой машине его
скачать, развернуть и подготовить к работе, и как запустить первый скан и
забрать результат.

Базовая модель доставки:

| Что | Куда | Как |
|---|---|---|
| Исходный код | GitLab (git) | `git push` |
| Dockerfile'ы инструментов | GitLab (git) | едут вместе с кодом; образы собираются на цели автоматически при `docker compose up` |
| **Текущие базы (4–8 ГБ)** | GitLab Container Registry | отдельный **data-образ** `db-data`, см. §1.4 / §2.3 |
| Публичные образы (trivy/grype/syft/alpine/python) | docker.io / ghcr.io | тянутся на цели автоматически; для закрытого контура зеркалируйте (см. `docs/airgap.md`) |
| `.env` | **никуда** | создаётся на цели из `.env.example` |
| Секреты (NVD-ключ и пр.) | **никуда** | только локальный `.env.local`, он в `.gitignore` |

Базы по умолчанию **не обновляются** — скан использует уже загруженный снимок.
Обновление запускается отдельно и осознанно (§4).

---

## 0. Перед началом — конкретные значения и нюанс с именем проекта

Задайте один раз (точный адрес реестра показан в GitLab: проект → **Deploy →
Container Registry**, строка `docker push …`; для self-managed это обычно
`registry.<домен-gitlab>`):

```bash
export REG=registry.gitlab01.soc.rt.ru
export IMG=$REG/yurij.m.tumanov/el-sca-ansamble/db-data
```

**Важно (имя проекта = имя томов).** Compose берёт префикс имён томов из имени
проекта — это имя текущей папки либо `COMPOSE_PROJECT_NAME`. Если базы
наполнялись из одной папки, а экспорт запускается из другой (например из
`/mnt/wsl/docker-desktop-bind-mounts/…`), compose обратится к **пустым** томам.
Сначала найдите, где реальные базы:

```bash
docker volume ls --format '{{.Name}}' | grep -E 'cve-bin-tool-cache|grype-db|trivy-cache'
```

Префикс до `_` — имя проекта. Зафиксируйте его и работайте из корня репозитория:

```bash
# реальный каталог этого проекта на машине-источнике:
#   Windows (PowerShell):  D:\dev\el-sca-ansamble
#   WSL / Linux:           /mnt/d/dev/el-sca-ansamble
cd /mnt/d/dev/el-sca-ansamble                 # папка с docker-compose.yml
export COMPOSE_PROJECT_NAME=el-sca-ansamble   # ← префикс из команды выше
```

**docker.io за прокси.** Экспорт/импорт используют `alpine:3.20`; если демон не
достаёт docker.io (`TLS handshake timeout`), подтяните образ один раз при сети:
`docker pull alpine:3.20`. Это прокси **демона** Docker (Docker Desktop →
Settings → Resources → Proxies), а не контейнерный `ALL_PROXY`. Сборка
сервисных образов для самого скана/обновления тоже зависит от доступа демона к
docker.io — но для «проверить и выгрузить базы» сервисные образы не нужны.

---

## 1. Выгрузка (на машине-источнике, где базы уже наполнены)

### 1.1 Код → GitLab

```bash
cd /mnt/d/dev/el-sca-ansamble        # Windows: D:\dev\el-sca-ansamble
git add -A
git commit -m "ваше сообщение"
git push gitlab master
```

### 1.2 Убедиться, что базы наполнены

Если снимок баз ещё не собран на этой машине — соберите его один раз
(нужен сетевой доступ к источникам БД):

```bash
SCAN_TARGET_HOST=/tmp/dummy COMPOSE_PROFILES=update \
  docker compose up --abort-on-container-exit
```

Проверить статус снимка можно в GUI (карточки «Базы инструментов») или:

```bash
docker compose --profile airgap run --rm db-admin \
  audit cve-bin-tool-db --db-root /var/lib/resilient-db/cve-bin-tool/active
```

### 1.3 Войти в Container Registry

```bash
docker login registry.gitlab01.soc.rt.ru
# логин/пароль или Personal Access Token GitLab со scope write_registry
```

### 1.4 Запаковать текущие базы в data-образ и запушить

Одной командой (экспорт томов → сборка образа → push):

```bash
make db-push-image \
  DB_IMAGE=registry.gitlab01.soc.rt.ru/yurij.m.tumanov/el-sca-ansamble/db-data
```

Эквивалент без make:

```bash
./scripts/export_db_image.sh --push \
  --image registry.gitlab01.soc.rt.ru/yurij.m.tumanov/el-sca-ansamble/db-data
```

Windows (PowerShell):

```powershell
docker login registry.gitlab01.soc.rt.ru
.\scripts\windows\export-db-image.ps1 -Push `
  -Image registry.gitlab01.soc.rt.ru/yurij.m.tumanov/el-sca-ansamble/db-data
```

Что происходит: сервис `db-exporter` упаковывает все 5 томов баз
(`trivy-cache`, `grype-db`, `grype-cache`, `cve-bin-tool-cache`,
`internal-mirror-data`) в `./artifacts/db-image/*.tar.gz`, затем из них
собирается образ `db-data:<дата>` и `db-data:latest` и пушится в реестр.

> Без `--push` (`make db-export-image`) образ только собирается локально —
> удобно для проверки или переноса через USB (`docker save db-data:latest`).

---

## 2. Скачать и развернуть (на целевой машине)

Требуется только Docker с Compose v2. Никаких host-specific путей.

### 2.1 Клонировать репозиторий

```bash
git clone https://gitlab01.soc.rt.ru/yurij.m.tumanov/el-sca-ansamble.git
cd el-sca-ansamble
```

### 2.2 Создать локальный конфиг

```bash
cp .env.example .env
# при необходимости отредактируйте .env (прокси, тайм-ауты).
# Для запуска с готовыми базами ничего менять не обязательно.
```

### 2.3 Забрать текущие базы из реестра

```bash
docker login registry.gitlab01.soc.rt.ru
make db-import-image \
  DB_IMAGE=registry.gitlab01.soc.rt.ru/yurij.m.tumanov/el-sca-ansamble/db-data:latest
```

Windows (PowerShell):

```powershell
docker login registry.gitlab01.soc.rt.ru
.\scripts\windows\import-db-image.ps1 `
  -Image registry.gitlab01.soc.rt.ru/yurij.m.tumanov/el-sca-ansamble/db-data:latest
```

Что происходит: образ тянется (`docker pull`), его содержимое
распаковывается в `./incoming`, сервис `db-importer` заливает архивы в тома,
и активируется снимок Grype. После этого стек готов сканировать офлайн.

### 2.4 Подготовка к первому скану

Быстрые проверки (compose интерполирует весь файл, поэтому `SCAN_TARGET_HOST`
нужен даже для `config` — задайте любой непустой путь):

```bash
SCAN_TARGET_HOST=/tmp/x docker compose --profile scan config -q   # компоновка валидна
SCAN_TARGET_HOST=/tmp/x docker compose --profile airgap run --rm db-admin \
  db-status grype --path /var/lib/resilient-db/grype/active        # возраст БД Grype
```

Образы инструментов соберутся/подтянутся автоматически при первом запуске.
Чтобы прогреть их заранее:

```bash
docker compose --profile scan build      # собрать локальные образы
docker compose --profile scan pull       # подтянуть публичные образы
```

---

## 3. Запуск скана и получение результата

### Вариант A — командная строка (docker compose)

Linux/macOS:

```bash
SCAN_TARGET_HOST=/abs/path/to/artifact.tar.gz \
  docker compose --profile scan up --abort-on-container-exit
```

Windows (PowerShell):

```powershell
$env:SCAN_TARGET_HOST = "C:\path\to\artifact.tar.gz"
docker compose --profile scan up --abort-on-container-exit
```

Гарантированно без сети (только локальные базы) — профиль `airgap`:

```bash
SCAN_TARGET_HOST=/abs/path/to/artifact \
  docker compose --profile airgap up --abort-on-container-exit
```

Конвейер: `artifact-extractor` → `syft-sbom` → `grype-scanner` →
`trivy-scanner` → `cve-bin-tool-scanner` → `report-collector`.

### Вариант B — графический интерфейс (drag-and-drop)

```bash
pip install fastapi "uvicorn[standard]" python-multipart
python -m resilient_updates.cli dashboard --repo-root . --port 8080
# открыть http://127.0.0.1:8080
```

Перетащите артефакт в окно — анализ начнётся автоматически, стадии конвейера
подсвечиваются в реальном времени, ниже идёт живой лог. Карточки «Базы
инструментов» показывают версию и время последнего обновления каждой БД.
Кнопка «Обновить базы (разово)» запускает обновление только по требованию.

> GUI запускается **на хосте** (ему нужен доступ к `docker compose`), а не
> внутри compose-сервиса `dashboard` (тот остаётся read-only).

### Где результат

```
artifacts/reports/grype/report.json
artifacts/reports/trivy/report.json
artifacts/reports/cve-bin-tool/report.json
artifacts/sbom/syft.json
artifacts/reports/final/cve_analysis_report_generated_ru.md   ← читать это
artifacts/reports/final/index.html                            ← открыть в браузере
```

На Windows скрипт `scripts/windows/run-scan.ps1` дополнительно кладёт отчёты
рядом с самим артефактом.

---

## 3.5. Полностью офлайн: передать комплекс с образами (ноль закачек на цели)

Чтобы на целевой машине `docker compose up` ничего **не собирал и не качал**
(ни pypi, ни docker.io), образы собираются один раз на машине с сетью и едут
вместе с проектом.

На источнике (есть сеть):

```bash
make images-export          # сборка/pull всех образов -> artifacts/image-bundle/images.tar
make db-export-image        # текущие базы (см. §1.4)
```

`images.tar` содержит все образы стека (сканеры + локально собранные
extractor/cve-bin-tool/report-collector + alpine). Передайте `images.tar`
(и базы) на цель любым каналом.

На целевой машине (без сети):

```bash
docker load -i images.tar          # или: ./scripts/import_images.sh images.tar
./scripts/import_db_image.sh --image <db-data>   # базы (или из своего tar)
```

**Строгий офлайн.** Чтобы запуск гарантированно никогда не тянул образы,
добавьте в `.env` целевой машины:

```
COMPOSE_FILE=docker-compose.yml:docker-compose.offline.yml
```

`docker-compose.offline.yml` выставляет `pull_policy: never` всем сервисам:
если образа нет — compose честно падает, а не скачивает молча. Сборка/обновление
теперь происходят только по явной команде (`docker compose build`,
`--profile update`). Базы и так не обновляются по умолчанию.

---

## 4. Обновление баз (когда понадобится)

По умолчанию обновление выключено. Разово:

```bash
docker compose --profile update up --abort-on-container-exit
# или кнопка «Обновить базы (разово)» в GUI
```

После обновления, чтобы зафиксировать новый снимок для остальных машин —
повторите §1.4 (`make db-push-image`).

---

## 5. Заметки

- Базы живут в 5 docker-томах; перенос — через профиль `db-bundle`
  (`db-exporter` / `db-importer`) и data-образ.
- Для закрытого контура (без интернета на цели) дополнительно зеркалируйте
  публичные образы и проверяйте целостность снимка — см. `docs/airgap.md`.
- Быстрый старт «с нуля» без баз из реестра (online-обновление на цели)
  описан в `QUICK_START.md`.
