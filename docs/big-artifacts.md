# Большие артефакты (гигабайтные): доставка, регистрация, скан

> Здесь же: [обновление EPSS офлайн](#epss-офлайн-обновление-скорoв) — тот же
> принцип «скачай чистым каналом, довези файлом».

Веб-загрузка через морду годится для файлов до нескольких сотен МБ. Для
гигабайтных артефактов (3–10 ГБ и больше) она **не рекомендуется**: у браузера
нет докачки (обрыв на 90% = всё заново), uvicorn складывает загрузку во
временный файл (двойное место), а VPN-каналы рвутся.

Рабочая схема для больших файлов — три шага:

```
1. доставить файл на сервер (rsync / WinSCP / scp)
2. зарегистрировать его в каталоге БЕЗ загрузки (hardlink, 0 лишних байт)
3. запустить скан — с карточки в морде или флагом -s
```

Проверено на артефакте 3.4 ГБ: доставка 5,5 мин (rsync, ~10 МБ/с через VPN),
регистрация мгновенная, полный скан ~4 мин, файл занимает место на диске
**один раз** независимо от числа прогонов.

## Быстрый рецепт: «мне скинули архив на N ГБ»

Пять шагов от файла на диске до отчёта у себя. Из WSL/Git Bash, ключ
`elaria_rostel`, прямой канал (VPN поднят). Полный проверенный прогон —
CYBERSEC-10661, 10.3 ГБ, 2026-08-18, всё ниже — реальные пути из него.

```bash
# 1. доставка (докачается сама, если оборвётся — просто перезапусти команду)
mkdir -p /home/SCA/_incoming/CYBERSEC-XXXXX  # на сервере, один раз через ssh
rsync -e "ssh -m hmac-sha2-256 -i ~/.ssh/elaria_rostel -o IdentitiesOnly=yes" \
      --partial --append-verify --info=progress2 \
      /путь/к/archive.zip \
      yuriy.tumanov@10.2.108.47:/home/SCA/_incoming/CYBERSEC-XXXXX/

# 2+3. регистрация в каталоге + сразу скан — с сервера
ssh -m hmac-sha2-256 -i ~/.ssh/elaria_rostel yuriy.tumanov@10.2.108.47 \
  'cd /home/SCA/el-sca-ansamble && scripts/register_local_artifact.sh \
     -f /home/SCA/_incoming/CYBERSEC-XXXXX/archive.zip -c CYBERSEC-XXXXX -s'
```

Ответ команды **важно сохранить** — в нём `run_dir`/`log`, по которым
следить и потом забирать отчёт. Реальный пример:

```json
{"job_id":"6680657a0dfb","artifact_id":"artifact-20260818-143319-2fd98f",
 "target":"/home/SCA/el-sca-ansamble/artifacts/uploads/artifact-20260818-143319-2fd98f/archive.zip",
 "run_dir":"/home/SCA/el-sca-ansamble/_SCA_reports/CYBERSEC-XXXXX-20260818-143354",
 "log":"/home/SCA/el-sca-ansamble/_SCA_reports/CYBERSEC-XXXXX-20260818-143354/job.log"}
```

**Регистрация** — это НЕ скан: она просто заводит карточку (hardlink файла +
хэши), выполняется мгновенно. `-s` сразу после неё дёргает API и возвращает
`job_id` немедленно — сам скан идёт в фоне на сервере ещё долго (10 ГБ ≈
15 минут: extract → sbom → grype → trivy → cve-bin-tool → report).

```bash
# 4. следить за прогрессом (Ctrl+C просто перестаёт показывать, скан не прерывает)
ssh -m hmac-sha2-256 -i ~/.ssh/elaria_rostel yuriy.tumanov@10.2.108.47 \
  'tail -f /home/SCA/el-sca-ansamble/_SCA_reports/CYBERSEC-XXXXX-20260818-143354/job.log'
```

Конец лога — `# --- finished status=done rc=0 duration=...s` (готово) или
`status=error` (что-то упало, `--resume` тут не поможет — это ран через
дашборд, не `run-scan.sh`; смотри `job.log` на конкретную упавшую стадию).

```bash
# 5. забрать готовый отчёт к себе — из RUN_DIR/reports/final/
mkdir -p /mnt/w/_dev_common/_SCA/CYBERSEC-XXXXX/report-20260818-143354
scp -o ControlPath=/tmp/ssh-e11 \
  'yuriy.tumanov@10.2.108.47:/home/SCA/el-sca-ansamble/_SCA_reports/CYBERSEC-XXXXX-20260818-143354/reports/final/*' \
  /mnt/w/_dev_common/_SCA/CYBERSEC-XXXXX/report-20260818-143354/
```

Полный список файлов в `reports/final/`: `index.html` (сводная страница,
открывать её — остальное подтянется по ссылкам), `cve_analysis_report_generated_ru.md`,
`grype.html`, `trivy.html`, `cve-bin-tool.html`, `syft.html`.

Либо без ssh вручную — карточка в браузере: `http://10.2.108.47:8088/` →
артефакт `artifact-20260818-143319-2fd98f` → кнопка **Reports**.

## Шаг 1 — доставка на сервер

Целевой каталог — `/home/SCA/_incoming/<CYBERSEC-XXXXX>/` (создать при
необходимости). Он на той же файловой системе, что и каталог артефактов, —
это важно для hardlink-регистрации.

### Вариант А: rsync (рекомендуется — докачка после обрыва)

Из WSL / Linux / Git Bash. Рабочее подключение (прямой маршрут, FortiClient
VPN поднят, без прыжка через `toshiba`) — ключ `elaria_rostel`, шифр MAC
`hmac-sha2-256` (без него у некоторых клиентов алгоритм не согласуется):

```bash
rsync -e "ssh -m hmac-sha2-256 -i ~/.ssh/elaria_rostel -o IdentitiesOnly=yes" \
      --partial --append-verify --info=progress2 \
      /путь/к/artifact.gz \
      yuriy.tumanov@10.2.108.47:/home/SCA/_incoming/CYBERSEC-XXXXX/
```

Из PowerShell/WSL с ключом на Windows-стороне (путь как в личном
однострочнике для `ssh`, см. ниже) — то же самое, просто указывается путь на
диске C:

```bash
rsync -e "ssh -m hmac-sha2-256 -i /mnt/c/Users/314he/.ssh/elaria_rostel -o IdentitiesOnly=yes" \
      --partial --append-verify --info=progress2 \
      /путь/к/artifact.gz \
      yuriy.tumanov@10.2.108.47:/home/SCA/_incoming/CYBERSEC-XXXXX/
```

- `--partial --append-verify` — после обрыва канала перезапусти ту же команду:
  докачает с места разрыва, сверив уже переданный кусок контрольной суммой.
- rsync на сервере установлен (`sudo dnf install rsync`, внутреннее зеркало
  RedOS).
- Если прямой маршрут лежит (VPN не поднят / нет прямой видимости), добавь
  прыжок через `toshiba`: `-e "ssh -m hmac-sha2-256 -J toshiba -i ~/.ssh/elaria_rostel ..."`.
- Оценка времени для 10 ГБ при ~10 МБ/с (как на проверенном 3.4 ГБ-артефакте)
  — около 17 минут; на более быстром канале пропорционально меньше. `--info=progress2`
  покажет текущую скорость и ETA сразу после старта.

### Вариант Б: WinSCP (GUI, докачка встроена)

Прямое подключение (FortiClient VPN поднят):

1. **New Site**: протокол `SFTP`, Host name `10.2.108.47`, порт `22`,
   User name `yuriy.tumanov`, пароль пустой.
2. **Advanced → SSH → Authentication → Private key file**: выбери
   **приватный** ключ (файл `elaria_rostel` *без* расширения; в диалоге выбора
   поставь фильтр «All files»). Файл `.pub` не подойдёт — это публичная
   половина. WinSCP предложит сконвертировать ключ в свой формат `.ppk` —
   соглашайся, он сохранит копию рядом.
3. **Advanced → Connection → Tunnel**: галку «Connect through SSH tunnel»
   **снять** — туннель нужен только для запасного маршрута через промежуточный
   хост (тогда в Tunnel указывается тот хост и его ключ, а основная сессия
   остаётся `10.2.108.47`).
4. Отдельно настраивать MAC (`-m hmac-sha2-256` из OpenSSH-однострочника) не
   нужно: PuTTY-ядро WinSCP договаривается об этом алгоритме само.
5. Докачка больших файлов включена по умолчанию:
   Preferences → Transfer → Endurance → «Enable transfer resume /
   transfer to temporary filename» (порог 100 КБ).

Эквивалент консольного подключения, с которого списаны эти настройки
(рабочий, проверен 2026-08-18):

```text
ssh -m hmac-sha2-256 -i C:\Users\314he\.ssh\elaria_rostel yuriy.tumanov@10.2.108.47
```

### Вариант В: scp (одним куском, без докачки)

```bash
scp -i ~/.ssh/<ключ> /путь/к/artifact.gz \
    yuriy.tumanov@10.2.108.47:/home/SCA/_incoming/CYBERSEC-XXXXX/
```

Годится для стабильного канала; при обрыве начинает заново.

После доставки сверь контрольную сумму с источником:

```bash
# локально                                  # на сервере
sha256sum artifact.gz                       sha256sum /home/SCA/_incoming/.../artifact.gz
```

## Шаг 2 — регистрация в каталоге (без HTTP-загрузки)

На сервере, из корня репозитория:

```bash
cd /home/SCA/el-sca-ansamble
scripts/register_local_artifact.sh \
  -f /home/SCA/_incoming/CYBERSEC-13529/artifact.gz \
  -c CYBERSEC-13529 \
  -s        # сразу запустить скан (опционально)
```

Что делает скрипт:

- **hardlink** файла в `artifacts/uploads/artifact-<ts>-<id>/` — та же файловая
  система, поэтому 0 лишних байт (если ФС другая — автоматически копия);
- считает sha1+sha256 и пишет `artifact.json` в том же формате, что и обычная
  загрузка через морду (`ArtifactCatalog.create_upload`), поэтому карточка
  полноценная: Scan, Reports, переименование, CYBERSEC-тег, «Удалить навсегда»;
- с флагом `-s` дёргает `POST /api/artifacts/<id>/scan` — тот же пайплайн, что
  и кнопка Scan.

Замечание про место: начиная с фикса `ccc9a87` оркестратор тоже **линкует**
входы ≥ 512 МиБ в `_SCA_reports/<run>/input/` вместо копирования. Итого файл
любого размера лежит на диске один раз (`_incoming` + `uploads` + все раны
указывают на один inode). «Удалить навсегда» с карточки убирает только ссылку
из `uploads`; мастер-копия в `_incoming` и evidence в ранах не трогаются.

## Шаг 3 — скан и отчёты

- Скан: кнопка **Scan** на карточке, либо флаг `-s` при регистрации, либо
  вручную: `curl -X POST http://127.0.0.1:8088/api/artifacts/<id>/scan`.
  Ответ — `{"job_id", "run_dir", "log", ...}`, сохрани его: `run_dir` —
  это твой путь ко всему остальному.
- Прогресс — `tail -f <run_dir>/job.log` на сервере; конец —
  `# --- finished status=done rc=0 ...` или `status=error`.
- Готовые отчёты лежат на сервере в **`<run_dir>/reports/final/`**:
  `index.html` (открой её — остальное подтянется по ссылкам),
  `cve_analysis_report_generated_ru.md`, `grype.html`, `trivy.html`,
  `cve-bin-tool.html`, `syft.html`. Забрать одной командой:
  `scp 'yuriy.tumanov@10.2.108.47:<run_dir>/reports/final/*' /mnt/w/_dev_common/_SCA/CYBERSEC-XXXXX/`
- То же самое из браузера: кнопка **Reports** на карточке (открывает
  свежайший ран артефакта), список всех ранов — `/runs`.
- В отчёте проверяй блок «Объект анализа»: имя файла, CYBERSEC-id и полный
  набор хэшей (MD5 + SHA-1 + SHA-256 для входного архива и распакованной цели);
  sha256 входа должен совпасть с тем, что ты считала при доставке.

### Известные пробелы в покрытии распаковки

Экстрактор (`resilient_updates/extractor.py`) может законно **пропустить**
часть содержимого — это не ошибка пайплайна, но отчёт не покроет эти файлы,
и стоит знать, когда перепроверять руками (`extraction_manifest.json` в
`<run_dir>/extracted/current/`, поле `failures`):

- **`unsafe archive member path`** — член zip-архива с абсолютным путём
  (`/foo.sh` вместо `foo.sh`) отклоняется защитой от zip-slip. У некоторых
  вендорских инсталляторов так упакованы `.sh`-скрипты — они не сканируются
  вообще. Если это важные исполняемые файлы — достань и прогони отдельно
  (`unzip -p archive.zip 'foo.sh' > foo.sh`, потом `run-scan.sh -t foo.sh`).
- **`extracted size exceeds max_bytes=...`** — общий объём распаковки упёрся
  в лимит: **10 ГиБ по умолчанию** (`EXTRACT_MAX_BYTES`, `docker-compose.yml`),
  не зависит от размера входа — просто суммарный объём того, что успело
  распаковаться. Для входа под завязку 10 ГБ последние по очереди файлы в
  глубоко вложенных архивах не попадут в отчёт. Поднять лимит: `EXTRACT_MAX_BYTES=<байты>`
  в `.env` перед сканом (например `21474836480` для 20 ГиБ).

## Совсем руками (если скрипт недоступен)

```bash
cd /home/SCA/el-sca-ansamble
TS=$(date -u +%Y%m%d-%H%M%S); AID="artifact-$TS-$(head -c3 /dev/urandom | od -An -tx1 | tr -d ' \n')"
mkdir -p "artifacts/uploads/$AID"
ln /home/SCA/_incoming/CYBERSEC-13529/artifact.gz "artifacts/uploads/$AID/artifact.gz"
SHA256=$(sha256sum "artifacts/uploads/$AID/artifact.gz" | cut -d' ' -f1)
SHA1=$(sha1sum   "artifacts/uploads/$AID/artifact.gz" | cut -d' ' -f1)
SIZE=$(stat -c %s "artifacts/uploads/$AID/artifact.gz")
cat > "artifacts/uploads/$AID/artifact.json" <<EOF
{
  "id": "$AID",
  "kind": "uploaded",
  "original_filename": "artifact.gz",
  "stored_filename": "artifact.gz",
  "stored_path": "/home/SCA/el-sca-ansamble/artifacts/uploads/$AID/artifact.gz",
  "display_name": "artifact",
  "case_id": "CYBERSEC-13529",
  "sha1": "$SHA1",
  "sha256": "$SHA256",
  "size": $SIZE,
  "uploaded_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%S+00:00)",
  "deleted_at": "",
  "runs": []
}
EOF
curl -X POST "http://127.0.0.1:8088/api/artifacts/$AID/scan"
```

Поля — точная копия того, что пишет `create_upload`; после этого карточка
появляется в морде как обычная.

## EPSS: офлайн-обновление скорoв

EPSS CDN (`epss.cyentia.com`) через корп-прокси отдаёт ~450 Б/с — скачивание с
сервера невозможно. С рабочей станции тот же файл (≈2.5 МБ) скачивается за
секунды. Процедура обновления (повторять раз в несколько дней):

```bash
# 1. локально (WSL): скачать свежий CSV
curl -sL -o /tmp/epss.csv.gz https://epss.cyentia.com/epss_scores-current.csv.gz
gunzip -f /tmp/epss.csv.gz

# 2. доставить на сервер
scp /tmp/epss.csv yuriy.tumanov@10.2.108.47:/tmp/epss.csv

# 3. на сервере: разложить в кэш И в candidates (preseed-активация копирует
#    каталог целиком — без второй копии файл сотрётся при следующей активации)
sudo docker run --rm \
  -v el-sca-ansamble_cve-bin-tool-cache:/c \
  -v el-sca-ansamble_internal-mirror-data:/m \
  -v /tmp/epss.csv:/in/epss.csv:ro alpine:3.20 sh -c '
    mkdir -p /c/cve-bin-tool/epss
    cp /in/epss.csv /c/cve-bin-tool/epss/epss_scores-current.csv
    for d in /m/candidates/*/.cache/cve-bin-tool; do
      mkdir -p "$d/epss"; cp /in/epss.csv "$d/epss/epss_scores-current.csv"
    done
    chown -R 1001:1001 /c/cve-bin-tool/epss /m/candidates
    touch /c/cve-bin-tool/epss/epss_scores-current.csv'

# 4. на сервере: разовый ingest (только EPSS; свежий файл парсится локально)
cd /home/SCA/el-sca-ansamble && EL_SCA_VERSION=0.1.1 \
SCAN_TARGET_HOST=/tmp/noscan EXTRACT_INPUT_HOST=/tmp/noscan \
sudo -E docker compose run --rm --entrypoint /bin/sh cve-bin-tool-scanner -c \
  'cve-bin-tool -u latest --disable-data-source "CURL,GAD,NVD,OSV,PURL2CPE,REDHAT,RSD" /tmp'
```

Проверка (работает офлайн — python из образа; `apk add sqlite` в alpine без
сети не поставится, не пытайся):

```bash
sudo docker run --rm -v el-sca-ansamble_cve-bin-tool-cache:/c \
  --entrypoint python elariaphd/el-sca-cve-bin-tool:0.1.1 -c "
import sqlite3
print(sqlite3.connect('/c/cve-bin-tool/cve.db')
      .execute('SELECT COUNT(*) FROM cve_metrics WHERE metric_id=1')
      .fetchone()[0])"
```

Ожидается ~350–360 тыс. Сканы идут с `--metrics`, поэтому каждая находка в
`report.json` несёт `epss_probability` / `epss_percentile`.

Ещё две ожидаемые странности ingest-шага: в конце он падает с
`TypeError: 'NoneType' object is not subscriptable` — это загрузка
KEV-каталога (known-exploited) после EPSS, которой нужен интернет; на данные
не влияет, EPSS к этому моменту уже записан. Rich-консоль cve-bin-tool без
tty буферизует вывод — долгая «тишина» после строк `Disabling data source…`
нормальна (~10 мин на 360 тыс. вставок).

Важно: `-u now` для этого НЕ использовать — он сносит кэш-каталог целиком
вместе с базой. Только `-u latest`.
