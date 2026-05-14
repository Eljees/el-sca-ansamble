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

Прокси живёт на `127.0.0.1:PORT` (хост-машина) → Docker видит его как `host.docker.internal:PORT`.
