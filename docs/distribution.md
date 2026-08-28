# Руководство по распространению el-sca-ansamble

Как поделиться готовым комплексом с другими командами или организациями.

---

## Суть подхода

Комплекс состоит из двух частей:

1. **Конфигурация и скрипты** — хранятся в git-репозитории. Это то, что вы уже разрабатываете.
2. **Docker-образы** — собираются из репозитория и публикуются в реестр (Docker Hub или внутренний).

Получатели делают три шага: клонируют репозиторий → создают `.env` со своими настройками → запускают. На Windows для этого нужен Docker Desktop, на Ubuntu или WSL достаточно Docker Engine и `docker compose`.

---

## Шаг 1: подготовить репозиторий

### Что должно быть в git

Всё что есть сейчас — плюс проверьте `.gitignore`:

```
.env                  ← секреты (NVD API key, прокси) — НЕ коммитить
comands.txt           ← тоже не коммитить
--exps/               ← рабочие артефакты — не коммитить
artifacts/            ← результаты сканирований — не коммитить
```

`.env.example` — коммитить обязательно, это шаблон для новых пользователей.

### Какие файлы надо подготовить и запушить

Чтобы получатель мог просто сделать `git clone`, а потом копировать готовые шаблоны, в git должны лежать:

- [docker-compose.yml](D:/dev/el-sca-ansamble/docker-compose.yml) — основной compose для разработки и запуска;
- [docker-compose.prod.example.yml](D:/dev/el-sca-ansamble/docker-compose.prod.example.yml) — override-файл для запуска из готовых образов;
- [.env.example](D:/dev/el-sca-ansamble/.env.example) — общий пример переменных;
- [receiver.env.example](D:/dev/el-sca-ansamble/receiver.env.example) — готовый шаблон `.env` именно для получателя;
- [scripts/windows/run-scan.ps1](D:/dev/el-sca-ansamble/scripts/windows/run-scan.ps1) — запуск скана на Windows;
- [scripts/scan_archive.sh](D:/dev/el-sca-ansamble/scripts/scan_archive.sh) — запуск скана на Linux / WSL.

Идея простая: вы пушите эти файлы один раз, а получатель уже у себя создаёт только локальные рабочие копии:

- `.env`
- `docker-compose.prod.yml`
- локальные артефакты и отчёты в `artifacts/`

### Создать репозиторий на GitHub/GitLab

```bash
# если ещё нет remote
git remote add origin https://github.com/YOUR_ORG/el-sca-ansamble.git
git push -u origin main
```

Репозиторий может быть приватным — получатели будут клонировать с токеном доступа.

---

## Шаг 2: собрать и опубликовать образы

В проекте три собственных образа (всё остальное берётся из публичных реестров):

| Dockerfile | Образ | Назначение |
|---|---|---|
| `Dockerfile.resilient-updater` | `resilient-updater` | Обновление БД, сбор отчётов, CLI |
| `Dockerfile.cve-bin-tool` | `cve-bin-tool` | Сканер cve-bin-tool |
| `Dockerfile.extractor` | `artifact-extractor` | Распаковка архивов |

### Создать аккаунт на Docker Hub

Зарегистрируйтесь на [hub.docker.com](https://hub.docker.com) и создайте namespace (название организации или пользователя):

```
your-org/el-sca-resilient-updater
your-org/el-sca-cve-bin-tool
your-org/el-sca-extractor
```

### Собрать и запушить

```bash
# задайте свой namespace
REGISTRY="your-org"
VERSION="1.0.0"

# авторизоваться
docker login

# собрать все три образа
docker build -f Dockerfile.resilient-updater \
  -t $REGISTRY/el-sca-resilient-updater:$VERSION \
  -t $REGISTRY/el-sca-resilient-updater:latest .

docker build -f Dockerfile.cve-bin-tool \
  -t $REGISTRY/el-sca-cve-bin-tool:$VERSION \
  -t $REGISTRY/el-sca-cve-bin-tool:latest .

docker build -f Dockerfile.extractor \
  -t $REGISTRY/el-sca-extractor:$VERSION \
  -t $REGISTRY/el-sca-extractor:latest .

# опубликовать
docker push $REGISTRY/el-sca-resilient-updater:$VERSION
docker push $REGISTRY/el-sca-resilient-updater:latest
docker push $REGISTRY/el-sca-cve-bin-tool:$VERSION
docker push $REGISTRY/el-sca-cve-bin-tool:latest
docker push $REGISTRY/el-sca-extractor:$VERSION
docker push $REGISTRY/el-sca-extractor:latest
```

На Windows (PowerShell):

```powershell
$REGISTRY = "elariaphd"
$VERSION = "1.0.0"

docker login

docker build -f Dockerfile.resilient-updater `
  -t "${REGISTRY}/el-sca-resilient-updater:${VERSION}" `
  -t "${REGISTRY}/el-sca-resilient-updater:latest" .

docker build -f Dockerfile.cve-bin-tool `
  -t "${REGISTRY}/el-sca-cve-bin-tool:${VERSION}" `
  -t "${REGISTRY}/el-sca-cve-bin-tool:latest" .

docker build -f Dockerfile.extractor `
  -t "${REGISTRY}/el-sca-extractor:${VERSION}" `
  -t "${REGISTRY}/el-sca-extractor:latest" .

docker push "${REGISTRY}/el-sca-resilient-updater:${VERSION}"
docker push "${REGISTRY}/el-sca-resilient-updater:latest"
docker push "${REGISTRY}/el-sca-cve-bin-tool:${VERSION}"
docker push "${REGISTRY}/el-sca-cve-bin-tool:latest"
docker push "${REGISTRY}/el-sca-extractor:${VERSION}"
docker push "${REGISTRY}/el-sca-extractor:latest"
```

Готовая последовательность для PowerShell целиком:

```powershell
Set-Location "D:\dev\el-sca-ansamble"

$REGISTRY = "elariaphd"
$VERSION = "1.0.0"

# 1. Логин в реестр
docker login

# 2. Сборка образа resilient-updater
docker build -f Dockerfile.resilient-updater `
  -t "${REGISTRY}/el-sca-resilient-updater:${VERSION}" `
  -t "${REGISTRY}/el-sca-resilient-updater:latest" .

# 3. Сборка образа cve-bin-tool
docker build -f Dockerfile.cve-bin-tool `
  -t "${REGISTRY}/el-sca-cve-bin-tool:${VERSION}" `
  -t "${REGISTRY}/el-sca-cve-bin-tool:latest" .

# 4. Сборка образа extractor
docker build -f Dockerfile.extractor `
  -t "${REGISTRY}/el-sca-extractor:${VERSION}" `
  -t "${REGISTRY}/el-sca-extractor:latest" .

# 5. Проверка, что образы действительно собраны локально
docker image ls "${REGISTRY}/el-sca-resilient-updater"
docker image ls "${REGISTRY}/el-sca-cve-bin-tool"
docker image ls "${REGISTRY}/el-sca-extractor"

# 6. Публикация образов
docker push "${REGISTRY}/el-sca-resilient-updater:${VERSION}"
docker push "${REGISTRY}/el-sca-resilient-updater:latest"
docker push "${REGISTRY}/el-sca-cve-bin-tool:${VERSION}"
docker push "${REGISTRY}/el-sca-cve-bin-tool:latest"
docker push "${REGISTRY}/el-sca-extractor:${VERSION}"
docker push "${REGISTRY}/el-sca-extractor:latest"

# 7. Проверка, что теги уже существуют в удалённом реестре
docker pull "${REGISTRY}/el-sca-resilient-updater:${VERSION}"
docker pull "${REGISTRY}/el-sca-cve-bin-tool:${VERSION}"
docker pull "${REGISTRY}/el-sca-extractor:${VERSION}"
```

Если используется не Docker Hub, а внутренний реестр, меняется только значение `$REGISTRY`.

Примеры:

```powershell
$REGISTRY = "registry.gitlab.com/your-group/el-sca-ansamble"
$REGISTRY = "registry.your-org.internal:5000/sca"
$REGISTRY = "ghcr.io/your-org"
```

### Обновить docker-compose.yml

Главная идея такая:

1. Основной [docker-compose.yml](D:/dev/el-sca-ansamble/docker-compose.yml) разработчики не трогают.
2. Для передачи получателю в git кладётся отдельный override-файл.
3. Получатель после `git clone` просто копирует этот override-файл в рабочее имя и запускает Compose с двумя файлами.

То есть не надо вручную редактировать основной compose и не надо копировать YAML из документации.

Как это выглядит на уровне сервиса:

```yaml
# основной compose для разработки:
  grype-updater:
    build:
      context: .
      dockerfile: Dockerfile.resilient-updater

# override-файл для получателя:
  grype-updater:
    image: your-org/el-sca-resilient-updater:1.0.0
    build: !reset null
```

Что делать в репозитории:

- добавить в git файл [docker-compose.prod.example.yml](D:/dev/el-sca-ansamble/docker-compose.prod.example.yml);
- не создавать заранее `docker-compose.prod.yml`, потому что это уже рабочий локальный файл конкретного получателя;
- передавать получателю репозиторий уже с `docker-compose.prod.example.yml`.
- в этом override-файле `build: !reset null` убирает локальную сборку и оставляет только pull готовых образов.

Что делает получатель после `git clone`:

```powershell
Copy-Item .\docker-compose.prod.example.yml .\docker-compose.prod.yml
```

или на Linux:

```bash
cp docker-compose.prod.example.yml docker-compose.prod.yml
```

После этого получатель запускает Compose так:

```powershell
docker compose -f docker-compose.yml -f docker-compose.prod.yml config
docker compose -f docker-compose.yml -f docker-compose.prod.yml pull
```

Готовый шаблон, который надо хранить в git, уже создан как `docker-compose.prod.example.yml`:

```yaml
services:
  stack-info:
    image: ${REGISTRY_NAMESPACE:-el-sca-ansamble}/el-sca-resilient-updater:${IMAGE_TAG:-1.0.0}
    build: null

  grype-updater:
    image: ${REGISTRY_NAMESPACE:-el-sca-ansamble}/el-sca-resilient-updater:${IMAGE_TAG:-1.0.0}
    build: null

  artifact-extractor:
    image: ${REGISTRY_NAMESPACE:-el-sca-ansamble}/el-sca-extractor:${IMAGE_TAG:-1.0.0}
    build: null

  cve-bin-tool-updater:
    image: ${REGISTRY_NAMESPACE:-el-sca-ansamble}/el-sca-cve-bin-tool:${IMAGE_TAG:-1.0.0}
    build: null

  cve-bin-tool-scanner:
    image: ${REGISTRY_NAMESPACE:-el-sca-ansamble}/el-sca-cve-bin-tool:${IMAGE_TAG:-1.0.0}
    build: null

  db-admin:
    image: ${REGISTRY_NAMESPACE:-el-sca-ansamble}/el-sca-resilient-updater:${IMAGE_TAG:-1.0.0}
    build: null

  mock-feed-server:
    image: ${REGISTRY_NAMESPACE:-el-sca-ansamble}/el-sca-resilient-updater:${IMAGE_TAG:-1.0.0}
    build: null

  report-collector:
    image: ${REGISTRY_NAMESPACE:-el-sca-ansamble}/el-sca-resilient-updater:${IMAGE_TAG:-1.0.0}
    build: null
```

Почему так удобнее:

- не надо править YAML руками под каждый новый релиз;
- можно менять только `REGISTRY_NAMESPACE` и `IMAGE_TAG` в `.env`;
- один и тот же шаблон подходит и для GitHub Container Registry, и для GitLab Container Registry, и для внутреннего реестра;
- файл можно коммитить в git и передавать вместе с репозиторием.

Что именно должен изменить получатель:

- `REGISTRY_NAMESPACE` — путь к вашему namespace или registry prefix;
- `IMAGE_TAG` — версия образов.

Примеры значений для `.env`:

```dotenv
REGISTRY_NAMESPACE=elariaphd
IMAGE_TAG=1.0.0
```

```dotenv
REGISTRY_NAMESPACE=registry.gitlab.com/your-group/el-sca-ansamble
IMAGE_TAG=1.0.0
```

```dotenv
REGISTRY_NAMESPACE=registry.your-org.internal:5000/sca
IMAGE_TAG=1.0.0
```

Если всё же хочется жёстко зафиксировать образы прямо в YAML, можно заменить переменные на literal values:

```yaml
image: registry.gitlab.com/your-group/el-sca-ansamble/el-sca-resilient-updater:1.0.0
image: registry.gitlab.com/your-group/el-sca-ansamble/el-sca-cve-bin-tool:1.0.0
image: registry.gitlab.com/your-group/el-sca-ansamble/el-sca-extractor:1.0.0
```

Проверка, что override-файл корректный:

```powershell
docker compose -f docker-compose.yml -f docker-compose.prod.yml config
```

Что передавать получателю вместе с репозиторием:

- `docker-compose.yml`
- `docker-compose.prod.example.yml`
- `.env.example`
- `receiver.env.example`
- `scripts/windows/run-scan.ps1`
- `scripts/scan_archive.sh`

Что НЕ передавать в git как рабочие локальные файлы:

- `.env`
- `docker-compose.prod.yml`
- `artifacts/`
- `--exps/`

Что именно переводится на готовые образы:

```text
stack-info
grype-updater
artifact-extractor
cve-bin-tool-updater
cve-bin-tool-scanner
db-admin
mock-feed-server
report-collector
```

`trivy`, `grype` и `syft` уже и так приходят как внешние `image:` и дополнительной замены не требуют.

---

## Шаг 3: что делает получатель

Ниже даны две готовые последовательности: для Windows и для Linux. Обе исходят из того, что автоматические обновления баз отключены и выполняются только вручную.

### Вариант для Windows (PowerShell)

```powershell
# 1. Клонировать репозиторий
git clone https://github.com/YOUR_ORG/el-sca-ansamble.git
Set-Location .\el-sca-ansamble

# 2. Создать рабочие файлы из шаблонов
Copy-Item .\receiver.env.example .\.env
Copy-Item .\docker-compose.prod.example.yml .\docker-compose.prod.yml

# 3. Заполнить .env
@'
REGISTRY_NAMESPACE=elariaphd
IMAGE_TAG=1.0.0
SCAN_TARGET_HOST=D:\path\to\artifact.tar.gz
SCAN_TARGET_DISPLAY=D:\path\to\artifact.tar.gz
SCAN_TARGET_CONTAINER=/scan-target
SYFT_TARGET=/scan-target
SYFT_FROM=dir
TRIVY_TARGET=/scan-target
CVE_BIN_TOOL_TARGET=/scan-target
REPORT_OUTPUT=/workspace/artifacts/reports/final/cve_analysis_report_generated_ru.md
CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS=600
# NVD_API_KEY=
# NVD_API_KEY_FALLBACK=
# ALL_PROXY=socks5h://host.docker.internal:1080
# NO_PROXY=localhost,127.0.0.1,grype-static
'@ | Set-Content -Encoding UTF8 .\.env

# 4. Проверить итоговый compose
docker compose -f docker-compose.yml -f docker-compose.prod.yml config

# 5. Скачать все образы
docker compose -f docker-compose.yml -f docker-compose.prod.yml pull

# 6. Ручное обновление баз по необходимости
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile update run --rm trivy-updater
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile update run --rm grype-updater
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile update run --rm grype-db-importer
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile update run --rm cve-bin-tool-updater

# 7. Проверить статус баз
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm db-admin db-status trivy --path /var/lib/resilient-db/trivy --warning-age 24h
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm db-admin db-status grype --path /var/lib/resilient-db/grype/active --warning-age 24h
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm db-admin db-status cve-bin-tool --path /root/.cache/cve-bin-tool --warning-age 24h

# 8. Запустить полный скан архива с распаковкой
.\scripts\windows\run-scan.ps1 -Target "D:\path\to\artifact.tar.gz" -Extract -Tool all -Profile scan
```

Итоговый Markdown-отчёт после этого лежит здесь:

```text
artifacts\reports\final\cve_analysis_report_generated_ru.md
```

### Вариант для Linux / WSL / bash

```bash
# 1. Клонировать репозиторий
git clone https://github.com/YOUR_ORG/el-sca-ansamble.git
cd el-sca-ansamble

# 2. Создать рабочие файлы из шаблонов
cp receiver.env.example .env
cp docker-compose.prod.example.yml docker-compose.prod.yml

# 3. Заполнить .env
cat > .env <<'ENV'
REGISTRY_NAMESPACE=elariaphd
IMAGE_TAG=1.0.0
SCAN_TARGET_HOST=/absolute/path/to/artifact.tar.gz
SCAN_TARGET_DISPLAY=/absolute/path/to/artifact.tar.gz
SCAN_TARGET_CONTAINER=/scan-target
SYFT_TARGET=/scan-target
SYFT_FROM=dir
TRIVY_TARGET=/scan-target
CVE_BIN_TOOL_TARGET=/scan-target
REPORT_OUTPUT=/workspace/artifacts/reports/final/cve_analysis_report_generated_ru.md
CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS=600
# NVD_API_KEY=
# NVD_API_KEY_FALLBACK=
# ALL_PROXY=socks5h://host.docker.internal:1080
# NO_PROXY=localhost,127.0.0.1,grype-static
ENV

# 4. Проверить итоговый compose
docker compose -f docker-compose.yml -f docker-compose.prod.yml config

# 5. Скачать все образы
docker compose -f docker-compose.yml -f docker-compose.prod.yml pull

# 6. Ручное обновление баз по необходимости
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile update run --rm trivy-updater
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile update run --rm grype-updater
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile update run --rm grype-db-importer
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile update run --rm cve-bin-tool-updater

# 7. Проверить статус баз
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm db-admin db-status trivy --path /var/lib/resilient-db/trivy --warning-age 24h
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm db-admin db-status grype --path /var/lib/resilient-db/grype/active --warning-age 24h
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm db-admin db-status cve-bin-tool --path /root/.cache/cve-bin-tool --warning-age 24h

# 8. Запустить полный скан архива с распаковкой
./scripts/scan_archive.sh /absolute/path/to/artifact.tar.gz CYBERSEC-TEST
```

Итоговый Markdown-отчёт после этого лежит здесь:

```text
artifacts/reports/final/cve_analysis_report_generated_ru.md
```

### Готовый пример для Ubuntu

На Ubuntu получателю можно делать вот так, если нужен полностью готовый сценарий без додумывания:

```bash
sudo apt-get update
sudo apt-get install -y git docker.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
newgrp docker

git clone https://github.com/YOUR_ORG/el-sca-ansamble.git
cd el-sca-ansamble
cp receiver.env.example .env
cp docker-compose.prod.example.yml docker-compose.prod.yml

sed -i 's|^REGISTRY_NAMESPACE=.*|REGISTRY_NAMESPACE=elariaphd|' .env
sed -i 's|^IMAGE_TAG=.*|IMAGE_TAG=1.0.0|' .env
sed -i 's|^SCAN_TARGET_HOST=.*|SCAN_TARGET_HOST=/absolute/path/to/artifact.tar.gz|' .env
sed -i 's|^SCAN_TARGET_DISPLAY=.*|SCAN_TARGET_DISPLAY=/absolute/path/to/artifact.tar.gz|' .env

docker compose -f docker-compose.yml -f docker-compose.prod.yml config
docker compose -f docker-compose.yml -f docker-compose.prod.yml pull

docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile update run --rm trivy-updater
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile update run --rm grype-updater
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile update run --rm grype-db-importer
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile update run --rm cve-bin-tool-updater

./scripts/scan_archive.sh /absolute/path/to/artifact.tar.gz CYBERSEC-TEST
```

Итоговый отчёт будет здесь:

```text
artifacts/reports/final/cve_analysis_report_generated_ru.md
```

Если получателю не нужны ручные низкоуровневые команды, а нужен только один запуск после настройки, то на Windows используется `.\scripts\windows\run-scan.ps1`, а на Linux `./scripts/scan_archive.sh`.

---

## Вариант: приватный реестр организации

Если Docker Hub не подходит (закрытая сеть, корпоративная политика), используйте внутренний реестр:

```bash
# GitLab Container Registry
REGISTRY="registry.gitlab.com/your-group/el-sca-ansamble"

# Harbor / Nexus / Artifactory
REGISTRY="registry.your-org.internal:5000/sca"

# GitHub Container Registry
REGISTRY="ghcr.io/your-org"
```

Принцип тот же — `docker build`, `docker push`, образ доступен по внутреннему адресу.

---

## Версионирование

Рекомендуемая схема:

```
MAJOR.MINOR.PATCH
  │      │     └── исправления багов, обновления зависимостей
  │      └───── новые функции, обратно совместимые
  └──────────── breaking changes (изменение API, формата конфига)
```

Пример тегов: `1.0.0`, `1.0.1`, `1.1.0`.

Помимо версионных тегов всегда пушите `latest` — это позволяет быстро проверить «свежую» версию.

Зафиксируйте версию в git тегом:

```bash
git tag -a v1.0.0 -m "Initial release"
git push origin v1.0.0
```

---

## Что передать получателю (чеклист)

- [ ] Ссылка на git-репозиторий
- [ ] Токен доступа к репозиторию (если приватный)
- [ ] Ссылка на Docker Hub / внутренний реестр с образами
- [ ] Название namespace и актуальный тег версии
- [ ] Инструкция: `README.md` → раздел «Quick Start»
- [ ] Шаблон конфига: `.env.example` (уже в репо)
- [ ] NVD API key (если нужна свежая БД CVE): получить на `nvd.nist.gov`

---

## Offline-передача (воздушный зазор)

Если у получателя нет доступа к интернету вообще:

```bash
# на машине с интернетом — экспортировать образы в архив
docker save \
  your-org/el-sca-resilient-updater:1.0.0 \
  your-org/el-sca-cve-bin-tool:1.0.0 \
  your-org/el-sca-extractor:1.0.0 \
  aquasec/trivy:0.64.1 \
  anchore/grype:v0.116.1 \
  anchore/syft:v1.50.0 \
  | gzip > el-sca-images-1.0.0.tar.gz

# передать файл (USB / защищённый канал)

# на целевой машине — загрузить
docker load < el-sca-images-1.0.0.tar.gz

# репозиторий передать отдельно (git bundle или zip)
git bundle create el-sca-ansamble-1.0.0.bundle --all
```

Также используйте `--profile offline` при запуске — он отключает попытки обновить БД из интернета и использует только то, что есть локально.

---

## Обновление у получателей

Когда выходит новая версия:

```bash
# на машине разработчика
docker build ... -t your-org/el-sca-resilient-updater:1.1.0 ...
docker push your-org/el-sca-resilient-updater:1.1.0

git tag -a v1.1.0 -m "Release 1.1.0"
git push && git push --tags

# у получателя
git pull
docker compose pull   # скачает новые образы
docker compose --profile scan up
```

---

## Схема в одну картинку

```
Разработчик (вы)                  Получатель
───────────────────                ──────────────────────────────
git push → GitHub/GitLab    ──►   git clone
docker push → Docker Hub    ──►   docker compose pull
                                  Редактирует .env
                                  docker compose --profile scan up
                                         │
                                         ▼
                                  artifacts/reports/final/
                                  cve_analysis_report_generated_ru.md
```
