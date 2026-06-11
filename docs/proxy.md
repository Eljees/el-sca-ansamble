# Настройка прокси

Этот документ объясняет, как el-sca-ansamble работает через прокси-серверы, и что нужно настроить чтобы всё заработало.

---

## Зачем здесь вообще прокси

SCA-стек состоит из двух слоёв, которые делают сетевые запросы:

1. **Docker-контейнеры** — Trivy, Grype, Syft, cve-bin-tool скачивают базы уязвимостей из интернета.
2. **Python-слой** (`resilient_updates`) — CLI-обёртка, которая управляет обновлением баз, проверяет источники и собирает отчёты. Она тоже делает HTTP-запросы.

Если ваша машина выходит в интернет через прокси, нужно настроить оба слоя.

---

## Ключевая проблема: 127.0.0.1 внутри Docker ≠ 127.0.0.1 снаружи

Это самый частый источник путаницы.

Когда вы запускаете прокси на своей машине и он слушает на `127.0.0.1:1080`, то:

- **Снаружи Docker** (в PowerShell, в терминале): `127.0.0.1:1080` — это ваш прокси. ✅
- **Внутри Docker-контейнера**: `127.0.0.1:1080` — это сам контейнер, никакого прокси там нет. ❌

**Решение:** использовать `host.docker.internal` вместо `127.0.0.1`. Это специальное DNS-имя, которое внутри контейнера резолвится в IP вашей машины.

В `docker-compose.yml` уже прописано:
```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

Это означает: Docker автоматически добавит запись в `/etc/hosts` каждого контейнера, чтобы `host.docker.internal` указывал на хост-машину. Работает на Linux, Windows (Docker Desktop) и macOS.

---

## Быстрый старт

### Шаг 1: Скопируйте `.env.example` в `.env`

```powershell
# Windows
Copy-Item .env.example .env
```

```sh
# Linux
cp .env.example .env
```

### Шаг 2: Укажите адрес прокси в `.env`

Откройте `.env` и заполните нужные строки.

**Если у вас SOCKS5-прокси на локальной машине** (порт, например, 1080):

```dotenv
ALL_PROXY=socks5h://host.docker.internal:1080
NO_PROXY=localhost,127.0.0.1,grype-static
```

**Если у вас корпоративный HTTP/HTTPS прокси** (например, на порту 3128):

```dotenv
HTTP_PROXY=http://proxy.corp.example:3128
HTTPS_PROXY=http://proxy.corp.example:3128
NO_PROXY=localhost,127.0.0.1,grype-static,.corp.example
```

### Шаг 3: Готово

Docker Compose автоматически читает `.env` и прокидывает переменные во все контейнеры. Python-слой подхватывает их тоже.

---

## Все переменные окружения

| Переменная | Для чего | Кто читает |
|---|---|---|
| `HTTP_PROXY` / `http_proxy` | HTTP-запросы | requests, curl, wget, Go net/http |
| `HTTPS_PROXY` / `https_proxy` | HTTPS-запросы | requests, curl, wget, Go net/http |
| `NO_PROXY` / `no_proxy` | Хосты без прокси (через запятую) | все выше |
| `ALL_PROXY` / `all_proxy` | Резервный прокси для обоих протоколов; поддерживает SOCKS5 | requests (через наш код), curl, wget |

**Почему upper- и lower-case?** Разные инструменты читают разные варианты. `curl` и `wget` предпочитают нижний регистр, Go — оба, Python `requests` — оба. Поэтому в `docker-compose.yml` прокидываются обе версии через YAML-якорь `x-proxy-env`.

**Почему `ALL_PROXY` нужно прокидывать вручную?** Python `requests` читает `HTTP_PROXY` и `HTTPS_PROXY` автоматически, но `ALL_PROXY` — нет. Наш `build_session()` в `fallback.py` делает это явно: если `HTTP_PROXY` и `HTTPS_PROXY` не заданы, он берёт `ALL_PROXY` и подставляет его для обоих протоколов.

---

## Схемы прокси

| Схема | Что это | Когда использовать |
|---|---|---|
| `http://` | Обычный HTTP прокси (CONNECT для HTTPS) | Корпоративный прокси |
| `https://` | HTTP прокси с TLS до прокси | Редко, если прокси требует TLS |
| `socks5://` | SOCKS5, DNS резолвит клиент | Когда у вас есть DNS |
| `socks5h://` | SOCKS5, DNS резолвит прокси-сервер | **Рекомендуется** для большинства случаев — безопаснее |
| `socks4://` | SOCKS4 | Устаревший |
| `socks4a://` | SOCKS4a с remote DNS | Устаревший |

`socks5h` — предпочтительный вариант: DNS-запросы идут через прокси, а не утекают напрямую.

---

## Как это работает внутри кода

### Python-слой (`resilient_updates`)

Файл `resilient_updates/fallback.py`, функция `build_session()`:

```python
def build_session(proxies=None):
    sess = requests.Session()
    if proxies:
        # Явный конфиг из feed_sources.yaml — приоритет выше env
        sess.proxies.update(proxies)
    else:
        # requests читает HTTP_PROXY / HTTPS_PROXY автоматически.
        # ALL_PROXY он игнорирует — прокидываем вручную.
        all_proxy = os.environ.get("ALL_PROXY") or os.environ.get("all_proxy")
        if all_proxy:
            sess.proxies.setdefault("http", all_proxy)
            sess.proxies.setdefault("https", all_proxy)
    return sess
```

Сессия создаётся один раз в `cli.py` (`main()`) и передаётся во все функции, которые делают HTTP-запросы: `attempt_sources`, `fetch_bytes`, `_download_text`, `_download_grype_candidate`.

### Docker-контейнеры

В `docker-compose.yml` определён YAML-якорь:

```yaml
x-proxy-env: &proxy-env
  HTTP_PROXY: ${HTTP_PROXY:-}
  HTTPS_PROXY: ${HTTPS_PROXY:-}
  NO_PROXY: ${NO_PROXY:-localhost,127.0.0.1,grype-static}
  ALL_PROXY: ${ALL_PROXY:-}
  http_proxy: ${HTTP_PROXY:-}
  https_proxy: ${HTTPS_PROXY:-}
  no_proxy: ${NO_PROXY:-localhost,127.0.0.1,grype-static}
  all_proxy: ${ALL_PROXY:-}
```

Он подключён через `<<: *proxy-env` ко всем сервисам, которые обращаются в сеть: `trivy-updater`, `trivy-scanner`, `grype-updater`, `syft-sbom`, `cve-bin-tool-updater`.

Сервисы без сетевого доступа (`grype-scanner`, `grype-static`, `cve-bin-tool-scanner`, `artifact-extractor`) прокси не получают — им это не нужно.

### Переопределение только для Python-слоя

Если нужно использовать другой прокси только для Python-слоя (не для Docker), добавьте в `configs/feed_sources.yaml`:

```yaml
proxy:
  http: "socks5h://host.docker.internal:1080"
  https: "socks5h://host.docker.internal:1080"
  no_proxy: "localhost,127.0.0.1,grype-static"
```

Значения здесь имеют приоритет над переменными окружения — только для `resilient_updates`. Все Docker-контейнеры по-прежнему читают только переменные из `.env`.

---

## Диагностика

### Проверить, что прокси применяется

```powershell
# Windows — посмотреть текущие proxy env vars
Get-Item Env:*PROXY* | Format-Table Name, Value
```

```sh
# Linux
env | grep -i proxy
```

### Проверить доступность прокси из контейнера

```sh
docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -e ALL_PROXY=socks5h://host.docker.internal:1080 \
  curlimages/curl:latest \
  curl -v https://httpbin.org/ip
```

Если видите IP вашего прокси-сервера — всё работает.

### Прокси применился, но соединение не проходит

1. Убедитесь, что используете `host.docker.internal`, а не `127.0.0.1`.
2. Проверьте `NO_PROXY` — возможно, нужный хост там заблокирован.
3. Попробуйте схему `socks5h://` вместо `socks5://`.
4. Убедитесь, что прокси-сервер принимает подключения не только с loopback (`0.0.0.0`, не `127.0.0.1`).

### grype-scanner не использует прокси — это нормально

`grype-scanner` работает только с внутренней сетью Docker: он обращается к `grype-static` (внутренний HTTP-сервер на порту 8080). Внешние соединения ему не нужны — прокси не применяется намеренно.

---

## Полный маршрут пакета в сети

```
[ваша машина / Docker host]
    │
    ├─ Python layer (resilient_updates CLI)
    │      └─ requests.Session (build_session)
    │              └─ ALL_PROXY / HTTP_PROXY ──► [прокси] ──► интернет
    │
    └─ Docker containers
           ├─ trivy-updater   ──► HTTP_PROXY / ALL_PROXY ──► [прокси] ──► ghcr.io, ECR
           ├─ trivy-scanner   ──► (только если нужно обновить кэш)
           ├─ grype-updater   ──► HTTP_PROXY / ALL_PROXY ──► [прокси] ──► grype DB source
           ├─ syft-sbom       ──► HTTP_PROXY / ALL_PROXY ──► [прокси] ──► registry (если image scan)
           └─ cve-bin-tool-updater ── HTTP_PROXY ──► [прокси] ──► NVD / OSV
```

---

## Автовыбор маршрута: `route-doctor` (ADR-0007 P2)

«Обновляться из любой точки» означает: не нужно вручную прописывать
`HTTP_PROXY`/`ALL_PROXY` под каждую сеть (корп-прокси, домашний прямой выход,
v2rayN на хосте, VPN, цензурируемый канал). За это отвечает сервис
**`route-doctor`** — он запускается **внутри** `scanner-net`, выясняет, какой
egress жив именно отсюда, и пишет план, который апдейтеры подхватывают сами.

### Что он делает

1. Зондирует **изнутри docker-сети** все кандидатные маршруты:
   - сайдкары `tinyproxy:8888` (HTTP) и `proxy-xray:1080` (SOCKS), если подняты
     (профиль `proxy`);
   - локальный прокси хоста через `host.docker.internal:<порт>` (типовые порты
     v2rayN/xray/sing-box/Tor: 10808, 1080, 8118, 7890, …);
   - прямой выход (`direct`).
2. Для **каждого инструмента** выбирает рабочий маршрут. Жёсткое ограничение:
   **cve-bin-tool не умеет SOCKS** (его Python-клиент понимает только
   `HTTP_PROXY`/`HTTPS_PROXY`), поэтому ему всегда отдаётся `http://`-мост
   (tinyproxy или HTTP-прокси хоста), а не голый `socks5://`. Trivy/Grype (Go +
   `ALL_PROXY`) могут идти по SOCKS.
3. Пишет два артефакта:
   - `artifacts/route-plan.json` — полное решение + матрица достижимости;
   - `artifacts/route-plan.env` — `HTTP_PROXY` / `ALL_PROXY` /
     `CVE_BIN_TOOL_ENRICH_PROXY`, которые апдейтеры берут как окружение.

### Как пользоваться

Чаще всего — никак: автовыбор **включён по умолчанию**.

- Только базы (без скана): `./scripts/update-db.sh [all|trivy|grype|cve-bin-tool]`
  или `make update` (всё) / `make update TOOL=grype` (один). Скрипт сам прогоняет
  `route-doctor`, применяет план и в конце печатает свежесть каждой базы. Каждый
  инструмент обновляется независимо — отказ одного не валит остальные.
- В пайплайне: `./scripts/run-scan.sh -t <target> --update-db` сам запустит
  `route-doctor` перед апдейтерами и подхватит план. Отключить —
  `--no-auto-route` или `EL_SCA_AUTO_ROUTE=0`. Если вы уже задали
  `HTTP_PROXY`/`ALL_PROXY` в окружении — авто-выбор уважает ваш выбор и не лезет.
- Через MCP: `update_db(tool="all"|...)` без аргумента `proxy` сам прогонит
  `route-doctor` (один раз на весь прогон, план кэшируется на 5 мин) и применит
  маршрут для каждого инструмента; явный `proxy=...` всё переопределяет;
  `auto_route=False` отключает. Отдельный read-only тул `route_plan()` просто
  покажет выбранный маршрут per-tool. В веб-дашборде кнопка «🛰 Маршрут» (`POST
  /api/route-plan`) перепроверяет сеть, а кнопки обновления баз применяют план
  автоматически.
- Вручную: `python -m resilient_updates.cli route-plan` (добавьте `--json` для
  машинного вывода). Если ничего не найдено — план пуст, апдейт идёт `direct`,
  как раньше (поведение аддитивно, ничего не ломается).

### Перенастройка egress самого xray

Сайдкар `proxy-xray` — единственное место в docker-сети, где задаётся внешняя
цепочка. Его committed-конфиг жёстко указывает upstream на
`host.docker.internal:10808`. Если ваш локальный прокси слушает другой порт (или
его нет), этот upstream мёртв. Флаг `route-plan --write-xray` (или override
`docker-compose.route-doctor.yml`) перегенерирует
`configs/xray/config.gen.json`, нацелив `upstream` на живой порт хоста (или на
`freedom`/direct, если хостового прокси нет):

```sh
docker compose -f docker-compose.yml -f docker-compose.route-doctor.yml \
  --profile route --profile proxy run --rm route-doctor
docker compose -f docker-compose.yml -f docker-compose.route-doctor.yml \
  --profile proxy up -d --force-recreate proxy-xray
```

Так все средства доставки (trivy/grype/cve-bin-tool) ходят через единый,
автоматически настроенный egress — независимо от конфигурации туннелей, прокси и
VPN на хосте.

Прокси живёт на `127.0.0.1:PORT` (хост-машина) → Docker видит его как `host.docker.internal:PORT`.
