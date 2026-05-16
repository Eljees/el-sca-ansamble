# Пользовательские источники баз уязвимостей

Помимо встроенных upstream'ов (ghcr.io/aquasecurity, anchore.io, NVD, OSV …) проект поддерживает декларацию любых дополнительных зеркал в `configs/feed_sources.yaml`. Это нужно, когда:

- Используется корпоративный OCI-mirror Trivy DB (или Grype DB).
- Внутри сети есть HTTP-зеркало с уже выкачанными `cve-bin-tool` json'ами.
- Файловое зеркало в git/S3, забранное в air-gapped инсталляцию.
- Локальные snapshot'ы DB на тестовом стенде.

---

## 1. Где описывается

Секция `custom_sources` на верхнем уровне `feed_sources.yaml`:

```yaml
custom_sources:
  allow_user_sources: true
  entries:
    - name: example-corporate-grype
      type: http
      url: "https://mirror.example.invalid/grype/listing.json"
      tool: grype
      layer: grype-db
      priority: 50
      auth_env: "GRYPE_CUSTOM_AUTH_TOKEN"
      enabled: false
      trust_level: internal
      notes: "Замените URL и `enabled: true` после прописывания токена в .env"
```

Каждая запись — отдельный source candidate; объединяется с встроенными `*_repositories` / `upstream_update_urls` / `mirrors` через `resilient_updates/source_policy.py:build_sources()` по полям `tool` и `layer`. Дальше отсортировано по `priority` (меньше — раньше). `enabled: false` оставляет запись задокументированной, но не пускает в pipeline.

---

## 2. Допустимые поля

| Поле | Обязательно | Значения | Что делает |
|---|---|---|---|
| `name` | да | строка, уникально | Имя candidate'а в provenance, в `proxy.per_source`, в логах |
| `type` | да | `oci-registry`, `http`, `file`, `git`, `s3-compatible` | Подсказка валидатору; на runtime сейчас читается только `oci-registry` (Trivy --db-repository) и `http` (Python `requests`) |
| `url` | да | URL соответствующей схемы | Без подмеченных секретов; учётки через `auth_env` |
| `tool` | да | `trivy` / `grype` / `cve_bin_tool` / `syft` | Какой инструмент использует этот source |
| `layer` | да | `trivy-db`, `trivy-java-db`, `trivy-checks`, `grype-db`, `cve-bin-tool-export`, `cve-bin-tool-mirror`, `syft-source` | На какой слой подмешивается |
| `priority` | да | int, уникально внутри `entries` | Меньше — раньше пробуем |
| `enabled` | нет | `true` / `false` | Дефолт `true` |
| `auth_env` | нет | имя env-переменной | Имя для `os.environ[…]`; ровно `^[A-Z][A-Z0-9_]*$` |
| `trust_level` | нет | `official` / `internal` / `custom` | Информативно; попадает в provenance |
| `notes` | нет | строка | Свободный текст; полезно для коллег |

Валидация запускается каждый раз при `python -m resilient_updates.cli validate-config`. Невалидные `type` / `tool` / `layer` / `auth_env` приводят к exit code 1.

---

## 3. Связка с прокси-цепочками

С Phase 2 любая запись `custom_sources` может ходить через свою прокси-цепочку. В `feed_sources.yaml`:

```yaml
proxy:
  per_source:
    - source: example-corporate-grype
      chain: corp
    - source: my-secret-mirror
      chain: via-vpn
```

`ProxyRouter.session_for_source()` возьмёт name из записи `entries[].name` и выберет цепочку. Если цепочка нездорова (см. `proxy-status`), будет failover по `policies.failover_order`. Подробнее — `docs/network-design.md`.

---

## 4. Примеры

### 4.1. OCI-mirror Trivy DB через корпоративный прокси

```yaml
custom_sources:
  entries:
    - name: corp-trivy-db
      type: oci-registry
      url: "oci://registry.corp.example/trivy-db"
      tool: trivy
      layer: trivy-db
      priority: 5
      auth_env: "TRIVY_INTERNAL_REGISTRY_PASSWORD"
      enabled: true
      trust_level: internal
      notes: "Зеркало обновляется ежедневно в 03:00 МСК"

proxy:
  per_source:
    - source: corp-trivy-db
      chain: corp
```

`.env`:

```
TRIVY_INTERNAL_REGISTRY_USERNAME=trivy-bot
TRIVY_INTERNAL_REGISTRY_PASSWORD=<token>
```

### 4.2. HTTP-зеркало `listing.json` для Grype

```yaml
custom_sources:
  entries:
    - name: lab-grype-mirror
      type: http
      url: "http://grype-mirror.lab/v6/latest.json"
      tool: grype
      layer: grype-db
      priority: 25
      enabled: true
      trust_level: internal
```

### 4.3. Локальный snapshot для cve-bin-tool

```yaml
custom_sources:
  entries:
    - name: cbt-local-snapshot
      type: file
      url: "file:///workspace/artifacts/mirror/cve-bin-tool-export.json"
      tool: cve_bin_tool
      layer: cve-bin-tool-mirror
      priority: 5
      enabled: true
      trust_level: custom
      notes: "Air-gapped snapshot от 2026-05-01; используется до возврата сети"
```

`fetch_bytes()` понимает `file://`-схему и читает напрямую.

### 4.4. Полностью air-gapped: пин на `internal-*` источники

```yaml
trivy:
  db_repositories:
    - name: internal-trivy-db
      url: "oci://registry.corp.example/trivy-db"
      priority: 10
      enabled: true
    - name: ghcr-trivy-db
      url: "oci://ghcr.io/aquasecurity/trivy-db:2"
      enabled: false           # отключаем внешний
    - name: public-ecr-trivy-db
      url: "oci://public.ecr.aws/aquasecurity/trivy-db:2"
      enabled: false
```

---

## 5. Диагностика

Сразу после изменений:

```sh
python -m resilient_updates.cli validate-config
python -m resilient_updates.cli healthcheck
python -m resilient_updates.cli proxy-status     # если включены chains
```

Каждая команда пишет JSON, по `selected_source` / `attempted_sources` / `failures` видно, какой кандидат был выбран и почему другие отлетели.

Полный аудит хранится в `artifacts/provenance/`:

- `trivy.json`, `grype.json`, `cve-bin-tool.json` — провенанс конкретных update-стадий.
- `proxy.json` — состояние цепочек на момент последнего `proxy-status`.
- `cve-bin-tool-db.json` — аудит активной DB.

Файлы безопасно коммитить в git — секретов в них нет, только имена источников и атрибуты ответа.
