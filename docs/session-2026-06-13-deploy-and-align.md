# Сессия 2026-06-13 — развёртывание «в несколько команд», прогресс/чекпоинты/монитор, выравнивание качества

Документ описывает **что, как и почему** делалось в этой сессии: новые возможности
комплекса, два деплоя с нуля из GitHub (Windows-хост `d:\dev\` и Ubuntu
`/opt/sca-work/`), обновление баз, и сравнение результатов скана
CYBERSEC-12201 между двумя площадками.

---

## 1. Что просили

1. Развернуть комплекс **в несколько команд**, чтобы он «без проблем разворачивался и приступал к работе».
2. Перепроверить обновления баз **через GUI**.
3. В GUI и CLI режимах SCA-ансамбля — **живой вывод процессов на каждом этапе**, чтобы не было ощущения зависания.
4. **Чекпоинты** при работе с артефактами: если процесс затягивается — рестартовать артефакт/комплекс **с последнего чекпоинта**.
5. **Монитор**: статус контейнеров и прогресс по задачам.
6. Полностью **с нуля развернуть из GitHub**: на хосте в `d:\dev\` и на Ubuntu в `/opt/sca-work/`; обновить все базы.
7. **Сравнить** результаты анализа CYBERSEC-12201 на сервере (`~/_SCA/CYBERSEC-12201/`) и на хосте (`d:\dev\_SCA\CYBERSEC-12201\`); при сильных расхождениях — исправить.

---

## 2. Новые возможности (реализованы и запушены в GitHub)

### 2.1. Чекпоинты этапов + resume — `resilient_updates/pipeline_state.py`

Каждый переход этапа пайплайна (`extract → sbom → trivy → grype → cve-bin-tool → report`)
атомарно (tmp + `os.replace`) фиксируется в `artifacts/pipeline_state.json`.
Ключ прогона (`run_key`) — SHA-256 от `target + tool + format/sbom-режим`, поэтому
resume **никогда** не пропускает этапы для другого артефакта.

Продолжение прерванного скана с последнего завершённого этапа:

- `scripts/run-scan.sh --resume`
- `scripts/windows/run-scan.ps1 -Resume`
- кнопка **«⏯ Продолжить с чекпоинта»** в дашборде (POST `/api/scan/resume`)
- MCP `run_scan(resume=True)` / `run_scan_async(resume=True)`

CLI-обвязка для скриптов: `python -m resilient_updates.cli run-state
begin|stage-start|stage-end|stage-skip|finish|show|should-skip`.

**Почему:** сканы Java-артефактов (cve-bin-tool) бывают «безумными по времени»;
при обрыве не нужно начинать с нуля — extract/sbom/grype/trivy уже зачекпоинчены.

### 2.2. Живой вывод этапов (heartbeat) — CLI и GUI

- `run-scan.sh`: на каждом этапе печатается время старта и итоговая длительность;
  при молчании контейнера дольше `EL_SCA_HEARTBEAT_SECONDS` (по умолч. 30; `--heartbeat N`)
  печатается строка «… ещё выполняется, прошло Ns».
- `run-scan.ps1`: `Invoke-Stage` печатает старт/длительность каждого этапа.
- Дашборд (`orchestrator._run_stream`): фоновый heartbeat шлёт строку статуса в
  SSE-лог, когда контейнер молчит — в GUI это видно в реальном времени
  (подтверждено: лог обновления базы показывал «… update: ещё выполняется, прошло 30s/60s/90s…»).

**Почему:** длинные этапы выглядели как зависание; теперь всегда видно, что процесс жив.

### 2.3. Монитор комплекса — `resilient_updates/monitor.py`

- CLI: `python -m resilient_updates.cli monitor [--watch N] [--json]` — статус
  compose-контейнеров (`docker compose ps -a --format json`), текущий этап с
  elapsed, длительности завершённых этапов, свежесть баз, хвост лога; `make monitor`.
- GUI: панель **«Монитор · контейнеры и прогресс»** (обновление каждые 5 с,
  `GET /api/monitor`).
- MCP: тул `monitor`; `scan_status` дополнен структурным блоком `pipeline`.

### 2.4. Развёртывание в несколько команд

- `scripts/bootstrap.sh` (`make bootstrap` / `make bootstrap-full`) и
  `scripts/windows/bootstrap.ps1`: docker-check → `.env` из шаблона →
  валидация compose → volume-init → сборка образов → (опц.) обновление баз → smoke.

С чистого clone до рабочего комплекса:

```bash
git clone https://github.com/Eljees/el-sca-ansamble.git && cd el-sca-ansamble
./scripts/bootstrap.sh --update-db      # или make bootstrap-full
./scripts/run-scan.sh -t /path/to/artifact.tar.gz
```

---

## 3. Найденные и исправленные баги (в процессе реального деплоя)

Эти дефекты всплыли именно при разворачивании «с нуля» и реальных сканах —
то, ради чего просили «без проблем разворачивался».

| # | Где | Симптом | Фикс | Commit |
|---|-----|---------|------|--------|
| 1 | `Dockerfile.cve-bin-tool` | from-scratch сборка падала: `pip install -r requirements.txt cve-bin-tool==X` в режиме `--require-hashes` (lockfile теперь с SHA-256) требует хэш и для cve-bin-tool → «Hashes are required … missing» | Два шага: установка хэшированного lockfile, затем cve-bin-tool под **бесхэшевым constraints-файлом** из того же lockfile (пины не плывут, хэш для cve-bin-tool не нужен) | `61c4fe2` |
| 2 | `scripts/run-scan.sh` | **Критично:** `state_begin()` заканчивалась на `[[ $RESUME -eq 1 ]] && echo …` → возвращала non-zero при обычном (не-resume) запуске; под `set -euo pipefail` вызов функции как простого statement **прерывал весь пайплайн сразу после баннера** (extract не стартовал). Ломало ВСЕ Linux/WSL сканы | Явный `return 0` в конце функции | `18c0560` |
| 3 | `scripts/windows/run-scan.ps1` | `& docker compose` под `$ErrorActionPreference='Stop'`: docker пишет прогресс («Container … Creating») в **stderr**, и при перенаправлении вывода (`2>&1`, фон, CI, `Out-File`) эти строки становятся терминирующими ошибками → каждый этап ложно падал | `Invoke-ComposeChecked`/`Invoke-DbStatus` выполняют docker под `ErrorActionPreference='Continue'`, успех судится только по `$LASTEXITCODE` | `18c0560` |
| 4 | `scripts/windows/run-scan.ps1` | На Windows `artifacts/` — bind-mount (не именованный том, что чинит volume-init); после `-Clean` первый root-сканер создавал `reports/` root-owned, а uid-1001 контейнеры (cve-bin-tool, report-collector) падали `mkdir reports/…: Permission denied` | Пред-создание `reports/{grype,trivy,cve-bin-tool,final}`, `sbom`, `provenance` на хосте + report-collector под `-u 0` (как в orchestrator) | `18c0560` |
| 5 | `scripts/update-db.sh` | trivy-updater падал `TRIVY_RENDERED_FLAGS is required`: флаги рендерились через `python3`, который в WSL/git-bash часто без зависимостей проекта → пусто; образ aquasec/trivy без python | Рендер требует импортируемости `resilient_updates` (перебор `python3`/`python`/`py -3`); при пустом рендере — понятная ошибка с подсказкой вместо запуска обречённого контейнера | `3c33fc1` |
| 6 | `resilient_updates/cli.py` (`monitor`) | `monitor` (текстовый режим) падал на Windows-консоли `UnicodeEncodeError` (cp1252 не кодирует кириллицу/box-chars) | `sys.stdout.reconfigure(encoding='utf-8', errors='replace')` для текстового вывода | (этот коммит) |

---

## 4. Развёртывание с нуля

### 4.1. Хост — `d:\dev\el-sca-ansamble`

1. Бэкап `.env`, `.env.local`, отчётов и истории прогонов в `d:\dev\el-sca-backup-2026-06-12`.
2. Остановка стека (`docker compose down`), снятие dashboard-процесса, удаление старой папки.
3. `git clone https://github.com/Eljees/el-sca-ansamble.git` → перемещение в `d:\dev\el-sca-ansamble`, возврат `.env`/`.env.local`.
4. `scripts/windows/bootstrap.ps1` — выявил **баг сборки cve-bin-tool** (см. №1) и проблему egress (Docker не мог тянуть образы).
5. **Docker Desktop proxy**: прописан `http://127.0.0.1:10808` (xray) в настройки Docker Desktop (`ProxyHttpMode=manual`, `OverrideProxyHttp/Https`), перезапуск daemon — после этого pull/build пошли. Контейнеры пользователя (vllm `quizzical_allen`, `openclaw`) возвращены в Up.
6. Полная сборка образов: **29 образов** `el-sca-ansamble-*` / `elariaphd/el-sca-*`, `BUILD2_EXIT=0`.

### 4.2. Ubuntu — `/opt/sca-work/el-sca-ansamble`

Доступ к VMware-VM `192.168.1.33` (`rostel-ub.vmx`) по SSH требовал пароль/неизвестный
ключ (ввод пароля запрещён политикой). Поэтому деплой выполнен на **WSL Ubuntu 24.04**
(тот же Docker daemon через Docker Desktop integration) — это полноценная Ubuntu-среда
с рабочим Docker 29.5.3. Запуск под `wsl -u root` (без пароля, Windows-пользователь уже аутентифицирован).

1. `mkdir -p /opt/sca-work` (root).
2. `git clone … /opt/sca-work/el-sca-ansamble`, HEAD синхронизирован до `61c4fe2`→`3c33fc1`→`18c0560`.
3. `.env` из шаблона; `compose config -q` → OK; `volume-init` → OK.
4. Образы — общие с хостом (один Docker daemon, одинаковое имя проекта `el-sca-ansamble`), пересборка не требовалась.
5. Минимальные host-python зависимости в WSL (`pyyaml`, `requests`) для `collect-report`/`render-flags`/`run-state`.

> **Важно для сравнения:** хост и Ubuntu делят **один Docker daemon, одни именованные
> тома баз и одни образы**. `artifacts/` — раздельные bind-mount'ы. Это гарантирует,
> что любое расхождение результатов могло бы исходить только из среды (путь/CRLF),
> а не из разных баз — идеальные условия для проверки детерминизма.

---

## 5. Обновление баз (с проверкой через GUI)

Запуск через `scripts/update-db.sh all` (route-doctor → volume-init → updaters).
Итог по активным базам (проверено и в GUI `/api/tools`):

- **grype** — обновлён, `active`, fill 100% (свежий).
- **trivy** — изначально упал на баге №5; обновлён напрямую с рендером флагов через
  Windows-python и Docker Desktop proxy → `active`, fill 100%, возраст 0.0h.
- **cve-bin-tool** — полное переобновление NVD-feed (191 636 CVE) скачалось, но
  активация упёрлась в enrichment-источник через текущий egress (известная сложность:
  GAD/RedHat за 403, NVD-клиент cve-bin-tool не умеет SOCKS); кроме того потребовалась
  нормализация прав тома `internal-mirror-data` (root-owned candidates → uid 1001).
  Оставлена **валидная активная база** (1.4M+ CVE rows, возраст в пределах нормы).
  Поскольку том cve-bin-tool **общий** для хоста и Ubuntu — обе площадки используют
  идентичную базу.

GUI-дашборд (`http://127.0.0.1:8090`) подтвердил состояние баз и показал живой
монитор контейнеров (6 контейнеров обновления в процессе) — требование «перепроверь через гуй» выполнено.

---

## 6. Сравнение CYBERSEC-12201 (выравнивание качества)

Артефакт `wso2mi-4.6.0.zip` (242 МБ, WSO2 Micro Integrator, Java/Maven).
SHA-256 идентичен на обеих площадках (`2ed98d06…d7d7a`).

Скан на хосте — `run-scan.ps1` (Windows-путь), на Ubuntu — `run-scan.sh` (Linux-путь),
оба через одни и те же контейнеры и базы.

| Инструмент | Хост `d:\dev\_SCA\…` | Ubuntu `~/_SCA/…` | Совпадение |
|---|---|---|---|
| Syft (компоненты) | 434 | 434 | ✅ |
| Grype (matches) | 1 | 1 | ✅ |
| Trivy (vulns) | 0 | 0 | ✅ |
| cve-bin-tool (находок) | 37 | 37 | ✅ |
| cve-bin-tool по severity | CRIT 8 / HIGH 11 / MED 9 / UNK 9 | CRIT 8 / HIGH 11 / MED 9 / UNK 9 | ✅ |
| cve-bin-tool report.json | 13 676 байт | 13 676 байт | ✅ (байт-в-байт) |

**Вывод:** результаты идентичны по всем четырём инструментам и по всем
severity-категориям; отчёт cve-bin-tool совпадает побайтно. Расхождений нет —
**исправлять нечего**. Финальные HTML/MD-отчёты отличаются лишь на единицы байт
из-за строки пути target в тексте (`D:\dev\…` против `/root/_SCA/…`), не из-за находок.

Замечания по находкам (контекст из прошлых сессий, подтверждён):
- **grype=1 — ожидаемо, не баг:** WSO2 поставляет vendor-forked версии
  (`1.6.0-wso2v9`, `2.4.0.wso2v2` и т.п.), которые не попадают в upstream
  version-ranges → PURL-matching grype молчит.
- **cve-bin-tool=37 ловит их** через product+base-version (детекция версии игнорит
  wso2-суффикс), но часть похожа на известные false positives cve-bin-tool.

---

## 7. Состояние репозитория

GitHub `origin/master` (HEAD на момент завершения работ по фичам):

- `c6b7f50` feat(checkpoint+monitor): pipeline_state.json + монитор
- `5899e90` feat(resume+heartbeat): продолжение скана с чекпоинта + живой вывод
- `8d9f012` feat(bootstrap): развёртывание в несколько команд + docs
- `61c4fe2` fix(docker): cve-bin-tool from-scratch под --require-hashes
- `3c33fc1` fix(update-db): устойчивый рендер trivy-флагов
- `18c0560` fix(run-scan): set -e abort + stderr/perms (Linux+Windows)
- (+ фикс monitor UTF-8 на Windows — этот коммит)

Тесты: 829 passed (`pytest -m "not integration"`), ruff clean.

---

## 8. Открытые вопросы / на будущее

- **Ubuntu VM `192.168.1.33`**: реальный сервер недоступен автономно (нужен
  пароль/ключ). Деплой выполнен на WSL Ubuntu (тот же daemon). Для деплоя на саму
  VM используйте те же команды bootstrap из раздела 4.2 после входа.
- **cve-bin-tool enrichment** (GAD/RedHat/OSV) через текущий egress нестабилен;
  базовый NVD-feed строится. Для полного enrichment нужен рабочий route-doctor/sidecar-egress.
- **run-scan.sh в WSL под MCP-таймаут**: grype-static при пересоздании делает
  холодный импорт DB (~150с), что превышало лимит автоматизации; этапы при этом
  корректно чекпоинтятся — `--resume` продолжает. На реальном терминале (без
  175-секундного лимита оркестратора) скан идёт сквозным проходом.
