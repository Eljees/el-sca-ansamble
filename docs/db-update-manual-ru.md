# Обновление баз — покомандный мануал (без скриптов)

Каждая база: что это, где обновляется, команда за командой, с ожидаемым
результатом. Написано так, чтобы по нему справился человек без контекста
или LLM-ассистент любой силы: копируй команды по одной, сверяй вывод.
Скрипты-обёртки (sneakernet_*.sh) НЕ используются — только голые команды.

Обозначения:
- **[НОДА]** — выполняется на 10.2.108.47 (ssh с Windows-хоста:
  `cmd /c "ssh -m hmac-sha2-256 -i C:\Users\<user>\.ssh\<key> yuriy.tumanov@10.2.108.47 <команда>"`,
  либо интерактивно тем же ssh без команды).
- **[ХОСТ]** — выполняется на Windows-хосте (PowerShell), репо в
  `D:\dev\el-sca-ansamble`.
- Прокси на хосте: `http://127.0.0.1:10808` (v2rayN); из docker-контейнера
  он же — `http://host.docker.internal:10808`.

## 0. Актуальное состояние (2026-07-17)

| База | Бочка | Как обновляется | Почему так |
|------|-------|-----------------|-----------|
| Grype DB | 100% зелёная | [НОДА] штатно, кнопка/команда | anchore-хосты контур пропускает |
| Trivy DB | 100% зелёная | [НОДА] штатно | ghcr-путь работает |
| cvebt: NVD | 100% зелёная | [НОДА] штатно (json-фиды) | nvd.nist.gov пропускается |
| cvebt: GAD | 100% зелёная | [НОДА] штатно | gitlab.com пропускается |
| cvebt: REDHAT | 100% зелёная | [НОДА] штатно | access.redhat.com пропускается |
| cvebt: CURL | 100% зелёная | [НОДА] штатно | curl.se пропускается |
| cvebt: OSV | была красная | [ХОСТ] вручную + scp (§5) | googleapis блокирован у ноды И у хоста (РКН) — только через прокси хоста |
| cvebt: EPSS | была красная | [ХОСТ] вручную + scp (§6) | first.org/empiricalsecurity блокированы у ноды |
| cvebt: PURL2CPE | была красная | [ХОСТ] вручную + scp (§7) | github.com блокирован у ноды |
| cvebt: RSD | была 0% | [ХОСТ] вручную + scp (§8) | github.com блокирован у ноды; зеркало на gitlab работает |

«Штатно» = кнопка «Обновить» на дашборде или команда из §1-§4.
Syft на дашборде — не база, а версия утилиты (n/a — норма).

## 1. Grype DB

[НОДА], сеть штатная.

```bash
cd /home/SCA/el-sca-ansamble
# обновить базу (детачед не нужен, ~1-3 мин):
sudo docker compose --profile update run --rm grype-updater
# проверить: свежая дата в статусе
sudo docker compose --profile update run --rm --entrypoint grype grype-updater db status
```

Ожидаемо: `db status` показывает сегодняшнюю дату Built. Бочка Grype на
дашборде зелёная после «Обновить статус».

## 2. Trivy DB

[НОДА], сеть штатная.

```bash
cd /home/SCA/el-sca-ansamble
sudo docker compose --profile update run --rm trivy-updater
```

Ожидаемо: exit 0, в логе `DB updated`. Бочка Trivy зелёная.

## 3. cve-bin-tool: NVD + GAD + REDHAT + CURL (штатное обновление ноды)

[НОДА]. Эти четыре источника контур пропускает, обновляются одним прогоном
штатного апдейтера (это НЕ скрипт-обёртка из этого мануала, а рабочий
механизм стека — он и красит бочки):

```bash
cd /home/SCA/el-sca-ansamble
sudo docker compose --profile update run --rm cve-bin-tool-updater update
```

Ожидаемо: exit 0 (или 5 = откат на last-known-good). Прогресс NVD виден
на дашборде в бочке. Если упало — лог попыток:

```bash
sudo ls -t artifacts/reports/cve-bin-tool/attempts/ | head -3
sudo tail -50 artifacts/reports/cve-bin-tool/attempts/<свежий>.log
```

ВНИМАНИЕ: штатный прогон ПЕРЕСОЗДАЁТ кандидата с нуля и не умеет качать
OSV/EPSS/PURL2CPE/RSD (сеть) — после него файлы §5-§8 в АКТИВНОЙ базе
сохраняются только если активация не произошла (обычно так: кандидат
без прав не проходит) либо их надо доложить заново по §5-§8 + §9.

## 4. Подготовка к ручным базам (§5-§8): куда класть файлы

Файловые источники cve-bin-tool живут в db_root активной базы на ноде:
`/home/appuser/.cache/cve-bin-tool/` внутри тома `cve-bin-tool-cache`
(снаружи контейнера напрямую НЕ виден). Все «положить файл» ниже делаются
через контейнер, шаблон:

```bash
cd /home/SCA/el-sca-ansamble
sudo docker compose --profile update run --rm -u 0 \
  -v /tmp/ФАЙЛ:/incoming:ro --entrypoint sh cve-bin-tool-updater \
  -c 'mkdir -p /home/appuser/.cache/cve-bin-tool/ПОДДИР && cp /incoming /home/appuser/.cache/cve-bin-tool/ПОДДИР/ИМЯ && chown -R appuser:appuser /home/appuser/.cache/cve-bin-tool/ПОДДИР'
```

Дашборд считает эти источники по НАЛИЧИЮ ФАЙЛОВ в поддирах db_root
(osv/, epss/, purl2cpe/, rsd/) — вставка в cve.db не нужна.

## 5. cve-bin-tool: OSV

[ХОСТ] — качаем 8 зипов экосистем через прокси (напрямую РКН режет):

```powershell
New-Item -ItemType Directory -Force -Path D:\tmp\osv | Out-Null
foreach ($eco in 'Debian','Ubuntu','Alpine','Go','PyPI','Maven','npm','Rust') {
  curl.exe -sS --proxy http://127.0.0.1:10808 -o D:\tmp\osv\$eco.zip `
    "https://osv-vulnerabilities.storage.googleapis.com/$eco/all.zip"
  "OK $eco " + (Get-Item D:\tmp\osv\$eco.zip).Length
}
```

Ожидаемо: 8 строк OK с размерами от единиц до сотен МБ. Затем упаковка
одним архивом и отправка на ноду:

```powershell
tar -czf D:\tmp\osv_pack.tgz -C D:\tmp osv
cmd /c "scp -o MACs=hmac-sha2-256 -i C:\Users\<user>\.ssh\<key> D:\tmp\osv_pack.tgz yuriy.tumanov@10.2.108.47:/tmp/osv_pack.tgz & echo RC=%errorlevel%"
```

[НОДА] — распаковать зипы в osv/ активной базы:

```bash
cd /home/SCA/el-sca-ansamble
sudo docker compose --profile update run --rm -u 0 \
  -v /tmp/osv_pack.tgz:/incoming.tgz:ro --entrypoint sh cve-bin-tool-updater -c '
    set -e
    D=/home/appuser/.cache/cve-bin-tool/osv
    mkdir -p "$D" /tmp/osvz
    tar xzf /incoming.tgz -C /tmp/osvz
    for z in /tmp/osvz/osv/*.zip; do python -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$z" "$D"; done
    chown -R appuser:appuser "$D"
    ls "$D" | wc -l'
```

Ожидаемо: число файлов в последней строке — сотни тысяч.

## 6. cve-bin-tool: EPSS

[ХОСТ] — хост качает напрямую (empiricalsecurity доступен без прокси;
если у вас нет — добавьте `--proxy http://127.0.0.1:10808`):

```powershell
curl.exe -sS -o D:\tmp\epss.csv.gz https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
# распаковать gz штатным tar Windows нельзя - используем PowerShell:
$in=[IO.File]::OpenRead('D:\tmp\epss.csv.gz'); $gz=New-Object IO.Compression.GZipStream($in,[IO.Compression.CompressionMode]::Decompress); $out=[IO.File]::Create('D:\tmp\epss_scores-current.csv'); $gz.CopyTo($out); $out.Close(); $gz.Close(); $in.Close()
Get-Content D:\tmp\epss_scores-current.csv -TotalCount 2
cmd /c "scp -o MACs=hmac-sha2-256 -i C:\Users\<user>\.ssh\<key> D:\tmp\epss_scores-current.csv yuriy.tumanov@10.2.108.47:/tmp/epss_scores-current.csv & echo RC=%errorlevel%"
```

Ожидаемо: первые строки — `#model_version:...` и `cve,epss,percentile`.

[НОДА]:

```bash
cd /home/SCA/el-sca-ansamble
sudo docker compose --profile update run --rm -u 0 \
  -v /tmp/epss_scores-current.csv:/incoming:ro --entrypoint sh cve-bin-tool-updater \
  -c 'mkdir -p /home/appuser/.cache/cve-bin-tool/epss && cp /incoming /home/appuser/.cache/cve-bin-tool/epss/epss_scores-current.csv && chown -R appuser:appuser /home/appuser/.cache/cve-bin-tool/epss && wc -l /home/appuser/.cache/cve-bin-tool/epss/epss_scores-current.csv'
```

Ожидаемо: ~300 тыс. строк.

## 7. cve-bin-tool: PURL2CPE

[ХОСТ] — база лежит на github (у хоста github работает; при блоке —
добавить `--proxy http://127.0.0.1:10808`):

```powershell
curl.exe -sSL -o D:\tmp\purl2cpe.db.zip https://github.com/scanoss/purl2cpe/raw/main/purl2cpe.db.zip
tar -xf D:\tmp\purl2cpe.db.zip -C D:\tmp
cmd /c "scp -o MACs=hmac-sha2-256 -i C:\Users\<user>\.ssh\<key> D:\tmp\purl2cpe.db yuriy.tumanov@10.2.108.47:/tmp/purl2cpe.db & echo RC=%errorlevel%"
```

[НОДА]:

```bash
cd /home/SCA/el-sca-ansamble
sudo docker compose --profile update run --rm -u 0 \
  -v /tmp/purl2cpe.db:/incoming:ro --entrypoint sh cve-bin-tool-updater \
  -c 'mkdir -p /home/appuser/.cache/cve-bin-tool/purl2cpe && cp /incoming /home/appuser/.cache/cve-bin-tool/purl2cpe/purl2cpe.db && chown -R appuser:appuser /home/appuser/.cache/cve-bin-tool/purl2cpe && du -m /home/appuser/.cache/cve-bin-tool/purl2cpe/purl2cpe.db'
```

Ожидаемо: ~490 МБ.

## 8. cve-bin-tool: RSD (RustSec)

[ХОСТ] — github у ноды закрыт, но у RSD есть зеркало на gitlab.com,
которое доступно ДАЖЕ С НОДЫ. Два пути.

Путь А (проще, [НОДА] напрямую — gitlab контур пропускает):

```bash
curl -sSL -o /tmp/rsd.zip "https://gitlab.com/vulnerabilities1/vulnerabities/-/archive/main/vulnerabities-main.zip"
ls -la /tmp/rsd.zip
cd /home/SCA/el-sca-ansamble
sudo docker compose --profile update run --rm -u 0 \
  -v /tmp/rsd.zip:/incoming.zip:ro --entrypoint sh cve-bin-tool-updater -c '
    mkdir -p /home/appuser/.cache/cve-bin-tool/rsd
    python -c "import zipfile; zipfile.ZipFile(\"/incoming.zip\").extractall(\"/home/appuser/.cache/cve-bin-tool/rsd\")"
    chown -R appuser:appuser /home/appuser/.cache/cve-bin-tool/rsd
    find /home/appuser/.cache/cve-bin-tool/rsd -type f | wc -l'
```

Путь Б: то же с [ХОСТ] (curl.exe + scp как в §5-§7), если gitlab с ноды
вдруг закроют.

Ожидаемо: сотни тысяч файлов (зеркало включает и advisory-db).

## 9. Финал после любого ручного обновления: аудит + статус

[НОДА] — пересчитать аудит активной базы (это красит бочки):

```bash
cd /home/SCA/el-sca-ansamble
sudo docker compose --profile update run --rm --entrypoint python cve-bin-tool-updater \
  -m resilient_updates.cli --config configs/feed_sources.yaml audit cve-bin-tool-db \
  --db-root /home/appuser/.cache/cve-bin-tool
```

Ожидаемо: JSON со статусами по источникам; OSV/EPSS/PURL2CPE/RSD — «ok»
при наличии файлов. Затем на дашборде нажать «Обновить статус» — бочки
перечитаются. Если какая-то бочка осталась красной — смотри её evidence
в JSON аудита: он говорит, какой директории/файла не хватает.

## 10. Если совсем с нуля (полная замена базы целиком)

Полная пересборка всей базы на Windows-хосте и заливка одним архивом —
это отдельная процедура: `docs/db-sneakernet-ru.md` (там же — все
известные баги cve-bin-tool 3.4 и обходы). Этот мануал (§1-§9) — для
точечного обновления отдельных баз без полной пересборки.
