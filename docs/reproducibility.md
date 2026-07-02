# Воспроизводимость: эталон CYBERSEC-11531

`--exps/high_critical_report_2026-04-29_ru.md` — эталонный отчёт по тикету `CYBERSEC-11531`, дата 2026-04-29. Этот документ объясняет, **что именно должно повториться**, **какие параметры стека критичны** и **как запустить репродьюсер**.

---

## 1. Эталон (выжимка)

| Поле | Значение |
|---|---|
| Объект | `prometheus-3.11.0.linux-amd64.tar.gz` |
| SHA-256 | `FF799C3E4C318E17DEC14AAAA406A4DA328FABB4578336B36D96D893870C3B76` |
| Сканер | `cve-bin-tool` (binary scan) |
| Всего находок | **3** |
| Severity-разрез | **CRITICAL × 2**, **UNKNOWN × 1** |
| Именованные CVE | `CVE-2024-3566` (`golang:go 1.23.0`)<br>`CVE-2024-3566` (`golang:go 1.26.1`) |

Третья находка в эталоне не названа (`UNKNOWN` severity). Это типичная картина для `cve-bin-tool`: regex-checker нашёл сигнатуру в бинарнике, но в БД нет привязки к конкретной severity. Не считайте это шумом — `UNKNOWN` лучше пропустить через ручной applicability review.

---

## 2. Два пути воспроизведения

Эталон 2026-04-29 пришёл из **binary scan** (cve-bin-tool гонял regex-checker'ы по каждому ELF-бинарю и находил `golang:go 1.X.Y` строки). С v3.x в пайплайне появилась оптимизация — **SBOM fast-path + Go runtime injection**: вместо часового regex-скана cve-bin-tool читает CycloneDX от Syft, в который `update_cve_bin_tool.sh` дописал компонент `golang:go X.Y.Z`, выдернутый из `go:buildinfo` бинаря. Совпадение по NVD получается то же, но за секунды.

| Путь | Скорость | Сколько находок |
|---|---|---|
| **A. Binary scan** (`--binary-scan` в репродьюсере) | 15–30 мин на Prometheus-class цели | Все Go-версии, найденные cve-bin-tool regex-checker'ом во всех ELF-бинарях |
| **B. SBOM + Go-injection** (default, Phase 5.7) | 5–30 с | Каждая уникальная `go1.X.Y` версия из всех ELF-бинарей инжектится в SBOM отдельным компонентом — итог совпадает с binary scan для Go-runtime CVE |

Раньше путь B давал ровно одну находку (брал первую Go-версию через `head -1` + `break`). С Phase 5.7 он собирает **все уникальные** Go-runtime версии из bundle'а и инжектит каждую — `findings(CVE-2024-3566)` теперь = `unique Go versions`, что совпадает с эталонным binary-scan-выводом.

Используйте `--binary-scan` / `-BinaryScan` только тогда, когда хотите ещё и поймать **не-Go** CVE через regex-checker'ы (рост wall-clock × 50–500 — обычно не оправдан).

### 2.1. Знаковые переменные

| Параметр | Значение в репродьюсере | Зачем |
|---|---|---|
| `CVE_BIN_TOOL_AUTO_SBOM` | `1` по умолчанию, `0` с `--binary-scan` | Включает/выключает SBOM fast-path |
| `CVE_BIN_TOOL_INJECT_GO_RUNTIME` | `1` (всегда в SBOM-режиме) | Иначе `golang:go` не появится в SBOM и Go runtime CVE пропадут |
| `CVE_BIN_TOOL_CHECKERS` | `go,rust` | Авто-детект и так выбирает их для pure-Go, но эталон пинует явно |
| `CVE_BIN_TOOL_MAX_FILE_MB` | `0` (off) | Prometheus binary ~150 MB. Любая фильтрация ниже размера бинаря убьёт binary-scan находки |
| `CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS` | `3600` | На медленных хостах regex-backtracking упирается в дефолтный таймаут |
| `CVE_BIN_TOOL_LOCAL_COPY` | `1` | Copy → tmpfs. Не влияет на находки, ускоряет на Windows × 5–10 |
| **NVD database** | актуальная (≥ Q2 2024) | `CVE-2024-3566` опубликован в NVD в апреле 2024 |
| Цель | директория с распакованным `prometheus`, не `.tar.gz` | `cve-bin-tool` не распаковывает архивы сам; пайплайн всегда сначала прогоняет `artifact-extractor` |

---

## 3. Запуск репродукции

> Специальные скрипты `reproduce-cybersec-11531.{sh,ps1}` удалены при чистке
> 2026-07-02 (SCRIPTS-CLEANUP, см. `docs/audit/520-analysis-2026-06-29.md` §5):
> это был one-off репродьюсер. Всё воспроизводится штатным пайплайном —
> экспортируйте пины из §2 (через `.env` или окружение) и запустите скан цели.

### Linux/macOS

```sh
# Базовый прогон через SBOM + Go injection (пины из §2 — в окружении/.env).
./scripts/run-scan.sh -t --exps/prometheus-3.11.0.linux-amd64.tar.gz

# То же, но сначала обновить cve-bin-tool DB:
./scripts/run-scan.sh -t --exps/prometheus-3.11.0.linux-amd64.tar.gz --update-db
```

### Windows / PowerShell

```powershell
.\scripts\windows\run-scan.ps1 -Target ..\--exps\prometheus-3.11.0.linux-amd64.tar.gz
```

Пайплайн при этом (то, что раньше автоматизировал скрипт):

1. Опционально обновляет БД (`cve-bin-tool-updater`).
2. Распаковывает архив (`artifact-extractor`).
3. Поднимает `syft-sbom` (SBOM fast-path) и запускает `cve-bin-tool-scanner`
   с зафиксированными переменными из §2.

Acceptance проверяется вручную по отчёту (**approximate** эталон):

- **≥ 1** находка,
- **≥ 1** CRITICAL или HIGH,
- `CVE-2024-3566` обязательно присутствует среди именованных находок.

Точный эталон (3 findings, 2 CRITICAL + 1 UNKNOWN) теперь достижим **обоими** путями при условии, что в Prometheus-сборке действительно живут две разных Go-версии. С Phase 5.7 SBOM-путь:

1. находит все ELF-файлы в `$TARGET` по magic-bytes `0x7F ELF` (а не по `find -perm /111`, который не работает на Windows NTFS bind-mount'е);
2. вытаскивает первую `go1.X.Y` строку из каждого ELF;
3. дедуплицирует версии;
4. инжектит каждую уникальную версию в SBOM отдельным `golang:go` компонентом.

В итоге `cve-bin-tool --sbom cyclonedx --sbom-file ...` видит ровно столько Go-runtime компонентов, сколько разных версий было в bundle'е, и матчит каждый против NVD.

---

## 4. Допустимые отклонения

Эталон не требует **точного** совпадения — БД cve-bin-tool обновляется ежедневно, новые CVE для Go runtime регулярно публикуются. Acceptance — approximate:

| Путь | total | CRITICAL/HIGH | CVE-2024-3566 |
|---|---|---|---|
| SBOM + Go-injection (default, Phase 5.7) | ≥ 1 | ≥ 1 | обязателен |
| `--binary-scan` (полный regex-checker pass) | ≥ 1 | ≥ 1 | обязателен |

С Phase 5.7 SBOM-путь честно поднимает все Go-runtime версии до уровня SBOM-компонента, поэтому при наличии в bundle'е двух Go-версий вы увидите два совпадения по `CVE-2024-3566` — то же, что в эталонном binary-scan-отчёте.

**Drift вниз** (меньше находок) почти всегда означает одно из:
- БД пуста/устарела ⇒ `--update-db`;
- checker `go` не запустился ⇒ `CVE_BIN_TOOL_CHECKERS=go,rust`;
- SBOM есть, но Go-injection отключён ⇒ проверить `CVE_BIN_TOOL_INJECT_GO_RUNTIME=1` и что в `artifacts/sbom/cyclonedx.json` появился компонент `golang:go`;
- скан упал в таймаут ⇒ `artifacts/reports/cve-bin-tool/timeout.flag`, см. `docs/runbook.md` §3.2.


---

## 5. Что делать, если репродьюсер не сходится с эталоном

Идём по списку выше → симптом → следующий шаг.

| Симптом | Проверить | Где |
|---|---|---|
| total = 0 | Запустился ли скан вообще? есть ли `report.json`? есть ли `timeout.flag`? | `artifacts/reports/cve-bin-tool/` |
| total > 0, но нет `CVE-2024-3566` | Свежесть БД (`db-admin db-status cve-bin-tool`); audit-результаты | `artifacts/provenance/cve-bin-tool-db.json` |
| В SBOM-режиме нет `CVE-2024-3566` | Go injection не отработал. В логах `update_cve_bin_tool.sh` ищите `SBOM patched: added golang:go X.Y.Z` или `no Go runtime version detected` | вывод контейнера `cve-bin-tool-scanner` |
| В `--binary-scan` есть только одна `golang:go X` версия | Все ли бинари распакованы? `find $EXTRACT_DIR -maxdepth 3 -type f \( -perm /111 -o -size +1M \)` | каталог `extracted/current/.../prometheus-3.11.0.linux-amd64/` |
| Все находки `UNKNOWN`, ни одной `CRITICAL` | NVD severity не загружен в БД | `db-admin audit cve-bin-tool-db --db-root /var/lib/resilient-db/cve-bin-tool/active` |
| total очень большое (десятки) в SBOM-режиме | В SBOM попало больше Go-компонентов (например, vendored toolchain) — это нормально, дрифт вверх допустим | — |
| Таймаут (`timeout.flag` есть, отчёт = `[]`) | поднять `CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS` или включить `LOCAL_COPY` | `.env` или флаг |

---

## 6. Когда обновлять эталон

Эталон осмыслен ровно до тех пор, пока эта же версия Prometheus и эта же эпоха NVD-данных дают тот же набор. После любого из:

- Замена `--exps/prometheus-3.11.0.linux-amd64.tar.gz` на другую версию.
- Серьёзное обновление cve-bin-tool ≥ 3.5.x с переписанным go-checker'ом.
- Большое расширение NVD (например, ретроспективное добавление severity для UNKNOWN-находок).

…пересоберите эталон вручную: запустите прогон, проверьте набор по существу (что это релевантные находки), и обновите ожидания в:

1. `--exps/high_critical_report_2026-04-29_ru.md` или его наследнике.
2. Эта таблица (§4).

Не меняйте константы «чтобы пайплайн зелёный» — каждый сдвиг должен быть подкреплён ручной валидацией нового набора.
