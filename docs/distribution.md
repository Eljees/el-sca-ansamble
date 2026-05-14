# Руководство по распространению el-sca-ansamble

Как поделиться готовым комплексом с другими командами или организациями.

---

## Суть подхода

Комплекс состоит из двух частей:

1. **Конфигурация и скрипты** — хранятся в git-репозитории. Это то, что вы уже разрабатываете.
2. **Docker-образы** — собираются из репозитория и публикуются в реестр (Docker Hub или внутренний).

Получатели делают три шага: клонируют репозиторий → создают `.env` со своими настройками → запускают. Никаких дополнительных установок, кроме Docker Desktop.

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
$REGISTRY = "your-org"
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

### Обновить docker-compose.yml

После публикации замените `build:` секции на готовые образы, чтобы получатели не пересобирали:

```yaml
# было (собирает локально):
  grype-updater:
    build:
      context: .
      dockerfile: Dockerfile.resilient-updater

# стало (берёт готовый образ):
  grype-updater:
    image: your-org/el-sca-resilient-updater:1.0.0
```

Сделайте это для всех трёх сервисов (`grype-updater`, `cve-bin-tool-updater`, `cve-bin-tool-scanner`, `artifact-extractor`, `report-collector`, `db-admin`, `mock-feed-server`).

Или создайте отдельный `docker-compose.prod.yml` с `image:` вместо `build:` и не трогайте основной файл для разработки.

---

## Шаг 3: что делает получатель

Инструкция для того, кому вы передаёте комплекс:

```bash
# 1. Клонировать репозиторий
git clone https://github.com/YOUR_ORG/el-sca-ansamble.git
cd el-sca-ansamble

# 2. Создать .env из шаблона
cp .env.example .env
# Открыть .env и заполнить:
#   SCAN_TARGET_HOST=C:\путь\к\архиву.tar.gz   (Windows)
#   SCAN_TARGET_HOST=/путь/к/архиву.tar.gz     (Linux)
#   NVD_API_KEY=...                             (опционально)
#   ALL_PROXY=socks5h://...                     (если нужен прокси)

# 3. Скачать образы (не собирать!)
docker compose pull

# 4. Запустить (пример — обновить БД)
docker compose --profile update up

# 5. Запустить сканирование
docker compose --profile scan up
```

На Windows — использовать `.\scripts\windows\run-scan.ps1` из репозитория.

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
  ghcr.io/anchore/grype:v0.112.0 \
  ghcr.io/anchore/syft:v1.20.0 \
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
