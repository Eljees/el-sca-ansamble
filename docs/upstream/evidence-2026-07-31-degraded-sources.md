# cve-bin-tool 3.4 — продовая деградация трёх источников (OSV / PURL2CPE / RSD)

Пакет данных для upstream-кампании. Собран 2026-07-31 на боевой инсталляции
`el-sca-ansamble` (закрытый корпоративный контур, egress только через HTTP-прокси).
**Новые PR не открывались** — слоты в `ossf/cve-bin-tool` заняты (#5781 merged,
#5862 ждёт DCO, #5864 открыт).

---

## 1. Точная версия и способ установки

| Что | Значение |
|---|---|
| `cve-bin-tool --version` | **3.4** |
| pip `Version` | 3.4 |
| `dist-info/INSTALLER` | **pip** (не git) |
| `direct_url.json` | отсутствует → обычный PyPI-релиз, не VCS-инсталл |
| Python | 3.12.13 |
| Базовый образ | `python:3.12-slim` (Debian trixie) |
| Локальные патчи | `data_sources/epss_source.py` — **патчен нами** (el-sca); `cvedb.py` — **pristine 3.4** |

3.4 — последний релиз на PyPI, апгрейдиться некуда.

## 2. Методика

Изоляция каждого источника отключением всех остальных, на **копии** боевой БД
в отдельном docker-томе (прод не затронут — проверено после: `cve_severity`
434 980, EPSS 354 176):

```
cve-bin-tool -u latest --disable-data-source "<все прочие>" /tmp/e
```

Окружение: контейнер `elariaphd/el-sca-cve-bin-tool:0.1.1` (cve-bin-tool 3.4,
uid 1001), `HTTPS_PROXY=http://10.2.204.162:3128/`.

## 3. Результаты — все три источника ведут себя ОДИНАКОВО

| Источник | Длительность до принудительной остановки | CPU | RSS | Сетевой трафик | Вывод после баннера | in-container `timeout` сработал? |
|---|---|---|---|---|---|---|
| **OSV** | 526 с | 0.00 % | 61.68 MiB | 2.32 kB in / 3.98 kB out | нет | **нет** |
| **PURL2CPE** | >8 мин | 0.00 % | 61.68 MiB | 1.73 kB in / 1.13 kB out | нет | **нет** |
| **RSD** | >8 мин | 0.00 % | 61.26 MiB | 1.96 kB in / 1.95 kB out | нет | **нет** |

Полный вывод RSD (13 строк — всё, что напечатано за 8+ минут):

```
[11:16:18] INFO cve_bin_tool - CVE Binary Tool v3.4                      cli.py:624
           INFO cve_bin_tool - This product uses the NVD API but is not
                endorsed or certified by the NVD.                        cli.py:625
           INFO cve_bin_tool - For potentially faster NVD downloads,
                mirrors are available using -n json-mirror               cli.py:628
           INFO cve_bin_tool - Disabling data source CURL                cli.py:771
           INFO cve_bin_tool - Disabling data source EPSS                cli.py:771
           INFO cve_bin_tool - Disabling data source GAD                 cli.py:771
           INFO cve_bin_tool - Disabling data source NVD                 cli.py:771
           INFO cve_bin_tool - Disabling data source OSV                 cli.py:771
           INFO cve_bin_tool - Disabling data source PURL2CPE            cli.py:771
           INFO cve_bin_tool - Disabling data source REDHAT              cli.py:771
<конец — далее тишина, процесс жив, сеть молчит>
```

### Что это значит (классификация по вопросу «падение / пусто / таймаут / OOM»)

Ни одно из четырёх — это **пятое: бесконечное зависание**.

- **не падение**: трейсбека нет, ненулевого кода возврата нет, процесс жив;
- **не OOM**: RSS ровно 61 МБ на всех трёх, при 23.7 ГБ доступных. Память вообще
  не растёт — источник не доходит до обработки данных;
- **не таймаут инструмента**: cve-bin-tool не имеет собственного лимита на этой
  фазе; внешний `timeout N` **не срабатывает** — процесс не реагирует на SIGTERM,
  требуется `docker stop` (SIGKILL);
- **база не портится**: счётчики после прогонов не изменились (`cve_severity`
  434 980 до и после) — просто ничего не добавляется.

Сетевой трафик ~2 КБ означает, что процесс залипает на **первом же запросе**
(TCP/TLS-хендшейк через медленный прокси) и не имеет ни connect-, ни read-таймаута.

### Диагностика ядром

Процесс в состоянии `do_wait`, открытых сокетов у PID нет, blockio = 0 B.

## 4. Сверка с upstream `main`

Клон `intel/cve-bin-tool` (редиректит на актуальный), HEAD **`f419c51`, 2026-07-29**.

| Источник | Состояние на main | Вывод |
|---|---|---|
| **PURL2CPE** | `purl2cpe_source.py` (78 строк): `except Exception → LOGGER.error("Unable to fetch PURL2CPE Data, skipping PURL2CPE.")`; `cvedb.populate_purl2cpe` (стр. 442-449): `if not purl2cpe_dbpath.is_file(): LOGGER.error("PURL2CPE downloaded data not found, skipping!")` | **Уже чинится gracefully** → подтверждает #4889: не PR, а «фикс есть, нужен релиз/бэкпорт» |
| **OSV** | `osv_source.py` вырос до 525 строк; появились `fetch_and_process_ecosystem` («Download, extract, process, and cleanup a single ecosystem») и комментарий «glob returns an iterator, so it is memory efficient» | **Память переработана** → подтверждает #5771 (OOM ушёл). Но зависание — ортогонально и, судя по коду, остаётся |
| **RSD** | `rsd_source.py` на main присутствует | Отдельного фикса не видно |
| **EPSS** (наш патч) | Источник **переписан целиком**: `update_epss(self)` без курсора, `EPSS_id_finder` **удалён** (`grep` пуст), константа `EPSS_METRIC_ID = 1` живёт в `cvedb.py:49`, запись через `cvedb.py:503`; CDN сменён на `epss.empiricalsecurity.com` | Оба бага 3.4 (TypeError + ordering) **на main отсутствуют** → наш патч 3.4-only: не PR, а «починено на main, нужен релиз» |

Последний коммит, трогавший `epss_source.py`/`osv_source.py`, — `f419c51`
(bump scorecard-action), т.е. содержательных правок в этих файлах недавно не было.

## 5. Побочная находка: смена CDN у EPSS

- 3.4 ходит на `epss.cyentia.com`
- main ходит на `epss.empiricalsecurity.com`

Замер с рабочей станции (чистый канал): 2 504 230 байт за **6.9 с** (362 КБ/с).
Замер **с сервера через корпоративный прокси** — оба хоста одинаково задушены:

```
epss.cyentia.com            size=15981  speed=622 B/s  http=200  time=25.7s
epss.empiricalsecurity.com  size=15981  speed=632 B/s  http=200  time=25.3s
```

Ровно 15 981 байт и обрыв в обоих случаях → режет **прокси**, а не CDN.
Для upstream это не баг, но объясняет, почему в закрытых контурах любой источник
с крупной загрузкой требует офлайн-доставки.

## 6. Что из этого — материал для upstream

1. **Самое ценное и, похоже, неотрепорченное:** у загрузок источников нет
   connect/read-таймаута и они игнорируют SIGTERM. В медленной/фильтрованной
   сети `cve-bin-tool -u` зависает навсегда, без единой строки диагностики.
   Воспроизводится на трёх независимых источниках → это не баг источника,
   а общий дефект слоя загрузки. Кандидат в **issue** (не тратит PR-слот).
2. PURL2CPE и EPSS — «уже починено на main, нужен релиз/бэкпорт»: комментарий
   в существующие треды.
3. OSV — память на main переработана; наш кейс добавляет данные о зависании,
   а не об OOM.

## 7. Связка со сравнением сканеров

Grype (`31.07 07:09`) и Trivy (`31.07 07:47`) обновились штатно тем же каналом —
т.е. проблема именно в слое загрузки cve-bin-tool, а не в сети как таковой.
Стек умеет гонять три сканера по одному корпусу, так что расхождения вида
«Trivy видит, Grype нет» на конкретном пакете снимаются в один прогон — отдельный
класс лидов с данными, которых у мейнтейнеров нет.
