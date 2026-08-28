# Sneakernet-обновление баз cve-bin-tool через Windows-хост (runbook)

Этот документ — самодостаточная инструкция. Её можно целиком отдать
LLM-ассистенту (даже слабой модели) как промпт, и по шагам он справится.
Каждая команда приведена полностью, с ожидаемым результатом.

## 1. Симптом

На дашборде (карта «Базы» / bocce-бочки CVEBT_SOURCES) источники
**OSV, EPSS, PURL2CPE, RSD** красные, а NVD, GAD, REDHAT, CURL — зелёные.
`update-db.sh cve-bin-tool` на ноде не может их скачать.

## 2. Причина (диагноз, проверен 2026-07-17 на ноде 10.2.108.47)

Нода не имеет прямого выхода в интернет: весь egress идёт через
прокси-цепочку (xray/tinyproxy sidecar -> upstream -> VPN-контур РТ).
Контур пропускает hosts NVD (nvd.nist.gov), GAD (gitlab.com),
REDHAT (access.redhat.com), CURL (curl.se), но НЕ пропускает:

| Источник  | Хост                                        |
|-----------|---------------------------------------------|
| OSV       | osv-vulnerabilities.storage.googleapis.com  |
| EPSS      | epss.empiricalsecurity.com (+ api.first.org)|
| PURL2CPE  | github.com (scanoss/purl2cpe)               |
| RSD       | github.com (RustSec/advisory-db)            |

Это сетевая политика, кодом на ноде не чинится. Решение — «sneakernet»:
собрать полную базу на Windows-хосте с нормальным интернетом и залить
на ноду по scp, активировав штатным механизмом кандидатов.

## 3. Как проверить диагноз (диагностика с ноды)

Каждая проверка кодирует результат в exit-код (маска битов), потому что
через Windows-ssh stdout ноды может не доходить (см. §7-Грабли).

```bash
# probe.sh - прямой доступ к 4 падающим хостам (ожидаемо: exit 0 = всё закрыто)
m=0
curl -sS -o /dev/null --max-time 10 "https://osv-vulnerabilities.storage.googleapis.com/" && m=$((m|1))
curl -sS -o /dev/null --max-time 10 "https://epss.empiricalsecurity.com/" && m=$((m|2))
curl -sS -o /dev/null --max-time 10 "https://raw.githubusercontent.com/RustSec/advisory-db/main/README.md" && m=$((m|4))
curl -sS -o /dev/null --max-time 10 "https://github.com/scanoss/purl2cpe" && m=$((m|8))
exit $m
```

Контроль (зелёные хосты, тоже exit 0 => прямого инета нет вообще,
они ходят через прокси): gitlab.com, services.nvd.nist.gov,
access.redhat.com, curl.se тем же шаблоном.

Запуск с Windows-хоста (обратите внимание: через `cmd /c`, НЕ PowerShell):

```
cmd /c "scp -o MACs=hmac-sha2-256 -i C:\Users\<user>\.ssh\<key> probe.sh <user>@10.2.108.47:/tmp/probe.sh && ssh -m hmac-sha2-256 -i C:\Users\<user>\.ssh\<key> <user>@10.2.108.47 bash /tmp/probe.sh & echo MASK=%errorlevel%"
```

`MASK=0` подтверждает диагноз.

## 4. Три бага, найденные и починенные по пути

### 4.1 EPSS: хост переехал (починено в коде, commit d3d7829)

cve-bin-tool 3.4 и наш сидер качали EPSS с `epss.cyentia.com` — хост
мёртв (Cyentia переименовалась в Empirical Security). Живой хост:
`https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`.
`resilient_updates/cve_db_audit.py::seed_cve_bin_tool_aux_sources` теперь
пробует empiricalsecurity первым, cyentia остался фоллбеком.

### 4.2 cve-bin-tool 3.4: metrics-баг ломает вставку ЛЮБОГО источника

Апстрим-баг: `EPSS_id_finder` селектит из пустой таблицы `metrics` ->
IndexError на вставке каждой CVE; таска источника молча умирает, а
asyncio.gather виснет навсегда (CPU 0%, лог замирает после
"Adding ... CVE entries"). Лечится нашим же патчем
`scripts/patches/cve_bin_tool_3.4_fixups.py` — он вшит в образ
`el-sca-cve-bin-tool:0.1.5+`. Если запускаете старый образ (0.1.1) —
патч НУЖНО применить в рантайме до апдейта (контейнер под root):

```sh
python /workspace/scripts/patches/cve_bin_tool_3.4_fixups.py
# ожидаемо: [cve-bin-tool 3.4 fixups] {'epss': 'patched'} ; rc=0
```

### 4.3 Мультиисточниковый прогон виснет на быстрой сети (НЕ починено апстримом)

Даже с патчем 4.2 запуск `cve-bin-tool --update now` с несколькими
источниками сразу стабильно виснет на быстром интернете (гонка в
asyncio; на ноде не проявляется, потому что прокси-канал медленный).
Симптом тот же: CPU 0%, "Getting ..." без продолжения, cve.db не создан.
Обход: **один источник за прогон, каждый в отдельном HOME** (потому что
`--update now` каждый раз пересоздаёт cachedir и затирает предыдущий
результат), затем sqlite-мерж. Готовый скрипт: `scripts/sneakernet_build.sh`.

Важное упрощение: OSV через cve-bin-tool вообще не нужен. Audit и дашборд
считают OSV/EPSS/PURL2CPE/RSD по **файлам в db_root** (osv/, epss/, rsd/,
purl2cpe/ — см. `cve_db_audit`), а файлы качает наш
`seed cve-bin-tool-aux` обычным requests (уважает HTTP(S)_PROXY).
cve-bin-tool-прогоны нужны только для REDHAT/GAD (строки в cve.db).

### 4.5 storage.googleapis.com блокирован и с хоста (РКН)

OSV-хост недоступен из RU-сетей напрямую. Решение: локальный прокси
(v2rayN/xray) на хосте, из контейнера — `http://host.docker.internal:10808`.
Скрипту сборки он передаётся env-переменной `OSV_HTTP_PROXY`; через него
идут NVD-фиды и все сиды.

### 4.4 CURL-source падает rc=33; RSD закрывается сидом

Таска Curl в 3.4 падает с Traceback (ErrorHandler, cli.py:908) даже
одиночным прогоном — исключена из сборки (бочку CURL нода держит зелёной
сама). RSD же закрывается сид-файлами (`--seed-rsd`, gitlab-зеркало
RustSec) — cve-bin-tool-прогон для него не нужен (см. 4.3).

## 5. Процедура sneakernet (полный прогон)

Предусловия на Windows-хосте: Docker Desktop запущен; репо в
`D:\dev\el-sca-ansamble`; локально есть образ
`elariaphd/el-sca-cve-bin-tool:0.1.1` или новее (`docker images`);
ssh-ключ ноды `C:\Users\<user>\.ssh\<key>` работает:
`cmd /c "ssh -m hmac-sha2-256 -i <key> <user>@10.2.108.47 hostname"`.

### Шаг 1. Сборка базы локально (30-60 мин, детачед)

```powershell
cd D:\dev\el-sca-ansamble
$env:SCAN_TARGET_HOST = '.'
$env:EXTRACT_INPUT_HOST = '.'
$env:EL_SCA_VERSION = '0.1.1'   # тег локально существующего образа!
docker rm -f cvebt_build 2>$null
New-Item -ItemType Directory -Force -Path D:\tmp\cvebt_pack, D:\tmp\cvebt_aux | Out-Null
docker compose --profile update run -d --name cvebt_build -u 0 `
  -e HTTP_PROXY= -e HTTPS_PROXY= -e ALL_PROXY= `
  -e http_proxy= -e https_proxy= -e all_proxy= `
  -e OSV_HTTP_PROXY=http://host.docker.internal:10808 `
  -v D:\tmp\cvebt_aux:/aux:ro `
  -v D:\tmp\cvebt_pack:/out `
  --entrypoint sh `
  cve-bin-tool-updater /workspace/scripts/sneakernet_build.sh
```

`OSV_HTTP_PROXY` — HTTP-порт локального прокси на хосте (см. 4.5); без
него NVD-фиды и OSV-сид не скачаются из RU-сети. Проверить порт:
`Invoke-WebRequest -Proxy http://127.0.0.1:10808 -Method Head https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt`
(ожидаемо 200). Прокси должен быть доступен и контейнеру:
порт проверяется коннектом на `host.docker.internal:10808` изнутри.

Важно: если compose лезет собирать образ и падает с
`auth.docker.io ... TLS handshake timeout` — тег `EL_SCA_VERSION` не
существует локально; поставьте тег, который есть в `docker images`.

Скрипт сам: применит fixups (4.2) -> соберёт REDHAT и GAD по одному в
изолированных HOME (4.3; готовые cve.db можно подмонтировать в
`/tmp/b_REDHAT`, `/tmp/b_GAD` — тогда шаг скипается) -> смержит sqlite ->
зальёт NVD из статических фидов (resilient_updates/nvd_feed_import.py,
через прокси) -> посеет OSV+EPSS+RSD файлами (`seed cve-bin-tool-aux
--seed-epss --seed-rsd --osv-ecosystem ...`, через прокси; 4.1/4.3) ->
положит purl2cpe.db из D:\tmp\cvebt_aux -> audit ->
`D:\tmp\cvebt_pack\cvebt_db.tgz`.

Контроль прогресса:

```powershell
docker logs cvebt_build 2>&1 | Select-String -Pattern 'SRC|rc=|TOTAL|PACKED' | Select-Object -Last 10
```

Успех = строки `SRC <имя> rc=0`, `TOTAL cve_severity: <сотни тысяч>`,
`=== PACKED OK ===`.

### Шаг 2. Доставка и активация на ноде

Автоматом: `scripts/sneakernet_export.ps1` (запущенный фоном, он ждёт
контейнер `docker wait cvebt_build` и делает всё сам, лог —
`artifacts\sneakernet.log`). Вручную — три команды:

```powershell
# 2.1 залить архив базы на ноду
cmd /c "scp -o MACs=hmac-sha2-256 -i C:\Users\<user>\.ssh\<key> D:\tmp\cvebt_pack\cvebt_db.tgz <user>@10.2.108.47:/tmp/cvebt_db.tgz & echo RC=%errorlevel%"
# 2.2 залить скрипт импорта
cmd /c "scp -o MACs=hmac-sha2-256 -i C:\Users\<user>\.ssh\<key> D:\dev\el-sca-ansamble\scripts\sneakernet_node_import.sh <user>@10.2.108.47:/tmp/node_import.sh & echo RC=%errorlevel%"
# 2.3 импорт + активация (лог на ноде: /tmp/import.log)
cmd /c "ssh -o ConnectTimeout=20 -m hmac-sha2-256 -i C:\Users\<user>\.ssh\<key> <user>@10.2.108.47 bash /tmp/node_import.sh & echo RC=%errorlevel%"
```

`node_import.sh` на ноде: `git pull` -> распаковка tgz в candidate root
`/var/lib/resilient-db/cve-bin-tool/candidates/windows-sneakernet/...`
внутри контейнера `cve-bin-tool-updater` -> штатные
`resilient_updates.cli audit cve-bin-tool-db` и `activate cve-bin-tool-db`
(бэкап предыдущей базы в previous/, provenance json для дашборда).
RC=0 -> активировано.

### Шаг 3. Верификация

1. На ноде: `cat /tmp/import.log` — в конце `ACTIVATE_RC=0` и `S3_PUSH_RC=0`.
2. Дашборд -> карта баз: OSV, EPSS, PURL2CPE, RSD зелёные.
3. Контрольный скан любого артефакта: находки обогащены EPSS-колонкой.

### Шаг 4. S3-снапшот (чтобы не потерять базу)

`sneakernet_node_import.sh` после успешной активации сам выполняет
`scripts/s3_storage.sh init && scripts/s3_storage.sh db-push` — снапшот
активной базы уезжает в стековый SeaweedFS/S3 (bucket `el-sca`).
Проверка: `sudo bash scripts/s3_storage.sh ls db/` на ноде.
Восстановление: `sudo bash scripts/s3_storage.sh db-pull latest`.

## 6. Регулярность

Сеть ноды не изменится — процедуру повторять раз в неделю (или чаще):
шаг 1 + шаг 2 полностью автоматизируются одним запуском
`scripts/sneakernet_export.ps1` после старта контейнера сборки.

## 7. Грабли Windows-хоста (обязательно к прочтению ассистенту)

1. **ssh/scp только через `cmd /c`**. Вызов `& ssh ...` из PowerShell
   в автоматизации возвращает 255 без вывода. Рабочий шаблон:
   `cmd /c "ssh ... & echo RC=%errorlevel%"`.
2. **stdout с ноды может не доходить** (tty-особенность win-ssh).
   Результат проверок кодируйте в exit-код (битовые маски, `exit $m`),
   логи пишите на ноде в файл (`exec > /tmp/x.log 2>&1`) и проверяйте
   отдельной ssh-командой с RC.
3. **scp-download (нода -> Windows) может молча не создавать файл** при
   RC=0. Доверяйте только upload + удалённому исполнению + RC.
4. **Скрипты для ноды — только LF**. Перед scp конвертируйте:
   `-replace "`r`n","`n"`. CRLF ломает bash молча.
5. **docker.io заблокирован** в контуре: никакой `docker pull/build` с
   выходом в Docker Hub. Использовать только локально существующие теги
   (`docker images`), для ноды — образы уже на ней.
6. **`--update now` cve-bin-tool пересоздаёт cachedir** — нельзя звать
   последовательно в один HOME (каждый вызов стирает прошлый результат).
7. Долгие команды запускать детачед (`docker compose run -d`,
   `Start-Process`), прогресс читать `docker logs`; MCP/оболочки режут
   таймауты ~60-90 сек.

## 8. Карта файлов

| Файл | Роль |
|------|------|
| `scripts/sneakernet_build.sh` | сборщик базы в контейнере (шаг 1) |
| `scripts/sneakernet_export.ps1` | ждёт сборку, scp + импорт (шаг 2) |
| `scripts/sneakernet_node_import.sh` | импорт+активация на ноде |
| `scripts/patches/cve_bin_tool_3.4_fixups.py` | патч metrics/EPSS-бага 3.4 |
| `resilient_updates/cve_db_audit.py` | сидер EPSS (живой хост), audit, activate |
| `resilient_updates/nvd_feed_import.py` | NVD из статических JSON-фидов |
| `docs/db-sneakernet-ru.md` | этот runbook |
