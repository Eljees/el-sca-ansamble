# Ручное развёртывание SCA-комплекса на Ubuntu + проверка баз + скан

Пошаговый алгоритм: поднять комплекс с нуля на Ubuntu-сервере, убедиться, что
базы уязвимостей на месте и свежие, и просканировать артефакт
`/home/elaria/_SCA/CYBERSEC-11603/`.

Проверено на: Ubuntu (kernel 6.17), Docker 29.5 + Compose v2, Python 3.12,
сервер `192.168.1.33`, деплой в `/opt/sca-work/`.

> Все «грабли», найденные при реальном прогоне, вынесены в callout-блоки `⚠️`
> и в раздел [Подводные камни](#подводные-камни).

---

## 0. Предусловия (один раз)

```bash
# Docker + Compose v2, git+git-lfs, python3 — должны быть установлены и запущены
docker version              # нужна секция Server
docker compose version      # v2.x
git lfs version
python3 --version           # 3.10+
```

⚠️ **Диск.** Комплекс держит ~30 ГБ в docker-томах (БД) + бандл ~4.3 ГБ.
Убедитесь, что под `/opt/sca-work` смонтирован достаточный диск, а на `/`
(там `/var/lib/docker`) есть запас. Проверка:

```bash
df -h /opt/sca-work /var/lib/docker
```

---

## 1. Очистка прошлого деплоя

⚠️ **Нужен `sudo`.** Сканеры пишут артефакты в `artifacts/` от **root**, поэтому
обычный `rm` от `elaria` оставит «неудаляемые» файлы. Удаляйте через sudo:

```bash
sudo rm -rf /opt/sca-work/el-sca-ansamble
```

---

## 2. Клон с GitHub (с LFS-бандлом ~4.3 ГБ)

```bash
cd /opt/sca-work
git lfs install
GIT_TERMINAL_PROMPT=0 git clone https://github.com/Eljees/el-sca-ansamble.git
cd el-sca-ansamble
# Убедиться, что бандл реально скачан (части по сотни МБ, не указатели):
ls -lh bundle/ | head
```

Если в `bundle/` файлы по ~130 байт — LFS не сработал: `git lfs pull`.

> GitHub LFS в этом контуре тянется быстро (десятки МБ/с). Если GitHub недоступен —
> клонируйте с GitLab: `https://gitlab01.soc.rt.ru/yurij.m.tumanov/el-sca-ansamble.git`.

---

## 3. Развёртывание (офлайн-база из бандла)

```bash
chmod +x scripts/deploy_light.sh
./scripts/deploy_light.sh
```

Скрипт сам: пропишет `.env` (strict offline), пересоберёт бандл из частей,
`docker load` образов, восстановит тома Grype/Trivy/cve-bin-tool, активирует
снимок Grype. Ожидаемый финал: `done — fully offline`.

⚠️ **Баг был исправлен (commit 43e2399):** раньше «голый» `deploy_light.sh` падал
с `open ./el-sca-images-light.tar: no such file` — автодетект бандла не видел
части `*.tar.part*`. Теперь работает без аргумента. На старых клонах — обходной
путь: `./scripts/deploy_light.sh bundle`.

---

## 4. GUI-дашборд

```bash
python3 -m pip install fastapi "uvicorn[standard]" python-multipart   # один раз
# слушать на всех интерфейсах, чтобы открыть с другого хоста:
python3 -m resilient_updates.cli dashboard --repo-root . --host 0.0.0.0 --port 8088
```

Открыть в браузере: `http://192.168.1.33:8088`
(или `http://127.0.0.1:8088` на самом сервере).

> Ставьте пакеты тем же интерпретатором (`python3 -m pip`), иначе будет
> `dashboard requires uvicorn`. На Ubuntu 24 при ошибке
> `externally-managed-environment` добавьте `--break-system-packages`.

---

## 5. Проверка, что базы на месте

Быстрая проверка статуса всех баз (тот же бэкенд, что у GUI):

```bash
curl -s http://127.0.0.1:8088/api/tools | python3 -m json.tool | \
  grep -E '"name"|"db_status"|"db_updated"|"fill"|"count"'
```

Что хотим увидеть:

| База | Норма |
|------|-------|
| **Grype** | `db_status: active`, `fill: 100`, `db_updated` **не старше 5 дней** |
| **Trivy** | `db_status: active`, `fill: 100` |
| **cve-bin-tool** | NVD `count` ~2.5M, REDHAT ~291k (остальные источники могут быть 0 — это норма для этого образа) |

Те же бочки видно в GUI в блоке **«БАЗЫ ИНСТРУМЕНТОВ — БОЧКИ С МУТАГЕНОМ»**;
кнопка **«Обновить статус»** перечитывает наполненность.

⚠️ **Критично для скана: возраст базы Grype.** Сканер grype отвергает БД старше
~5 дней (`failed to load vulnerability db: the vulnerability database was built …
ago`). Бандл-снимок из деплоя часто СТАРШЕ 5 дней → перед сканом базу Grype нужно
обновить онлайн (шаг 6).

---

## 6. Полное онлайн-обновление баз (через GUI)

В браузере `http://192.168.1.33:8088` → блок «БАЗЫ ИНСТРУМЕНТОВ» →
кнопка **«☢ Обновить ВСЁ»** (или per-tool кнопки `⟳`). Внизу панели
«ПРОЦЕСС АНАЛИЗА» идёт лог: сначала `route-doctor` ищет egress, затем тянутся
trivy → grype → cve-bin-tool. По завершении нажать **«Обновить статус»** —
бочки нальются.

⚠️ **Если Grype не качается (троттлинг `grype.anchore.io`).** В некоторых контурах
CDN anchore режется до ~1 КБ/с — скачивание 128-МБ архива «висит». Признак в логе:
`grype.anchore.io … Read timed out`. Что сделано/делать:

1. **Failover уже встроен** (commit 43e2399): таймаут на одном источнике больше не
   роняет обновление, апдейтер переходит к следующему источнику
   (`configs/feed_sources.yaml → grype.upstream_update_urls`).
2. **Для закрытого контура — внутреннее зеркало.** Любая машина С доступом к
   anchore (CI / отдельный сервер) кладёт свежую базу на HTTP-раздачу, а сервер
   тянет её оттуда. Включить источник-зеркало:

   ```bash
   # на машине с доступом — получить свежую v6 и отдать по HTTP:
   #   curl -s https://grype.anchore.io/databases/v6/latest.json -o v6/latest.json
   #   curl -s "https://grype.anchore.io/databases/v6/$(jq -r .path v6/latest.json)" -o v6/<archive>
   #   (в latest.json заменить "path" на имя без двоеточий), затем:
   #   python3 -m http.server 8901 --bind 0.0.0.0
   # на сервере — указать зеркало в configs/feed_sources.yaml:
   #   grype.upstream_update_urls[internal-grype-mirror].url = http://<MIRROR_IP>:8901/v6/latest.json
   #   enabled: true   (priority 10 — пробуется первым)
   ```

3. После любого обновления Grype нужно **импортировать** базу в кэш сканера
   (апдейтер кладёт в `…/active`, сканер читает `grype-cache`):

   ```bash
   docker compose --profile airgap run --rm grype-db-importer
   ```

   Через `./scripts/run-scan.sh --update-db` этот шаг делается автоматически.

Проверить, что Grype активен и свеж:

```bash
python3 -c "import json;d=json.load(open('artifacts/provenance/grype.json'));print(d.get('activation_status'),(d.get('selected_source') or {}).get('name'))"
# ждём: active internal-grype-mirror   (или anchore-public-db)
```

---

## 7. (Опц.) Монитор

```bash
python3 -m resilient_updates.cli monitor --repo-root .   # статус контейнеров + стадия + свежесть БД
```

Либо блок «МОНИТОР · КОНТЕЙНЕРЫ И ПРОГРЕСС» в GUI — он сам обновляется.

---

## 8. Скан артефакта CYBERSEC-11603

⚠️ В имени файла есть пробел и скобка — **обязательно в кавычках**:

```bash
cd /opt/sca-work/el-sca-ansamble
./scripts/run-scan.sh -t "/home/elaria/_SCA/CYBERSEC-11603/makarov-i-686402 (1).gz"
```

Стадии: extract → syft (SBOM) → trivy → grype → cve-bin-tool → report.
Прерванный скан продолжается с места обрыва: добавить `--resume`.

⚠️ **cve-bin-tool теперь НЕ фатален (commit 208bdd1).** Если его offline-скан
падает (`cve_bin_tool - Database does not exist`, exit 40 — feed-собранная
`cve.db` не распознаётся cve-bin-tool 3.4), пайплайн пишет предупреждение и
**идёт дальше к отчёту** grype/trivy. Вернуть жёсткий режим:
`EL_SCA_CVEBT_REQUIRED=1 ./scripts/run-scan.sh -t "…"`.

---

## 9. Результат

```bash
ls -la /home/elaria/_SCA/CYBERSEC-11603/*report*       # .md / .html рядом с артефактом
ls -la artifacts/reports/final/                        # index.html + сводный отчёт
# распределение grype по severity:
python3 - <<'PY'
import json,collections
d=json.load(open('artifacts/reports/grype/report.json'))
c=collections.Counter((m.get('vulnerability') or {}).get('severity') for m in d.get('matches',[]))
print('matches:',len(d.get('matches',[])),dict(c))
PY
```

---

## Подводные камни

| # | Симптом | Причина | Что делать |
|---|---------|---------|-----------|
| 1 | `rm` не удаляет старый клон | артефакты сканов от root | `sudo rm -rf …` |
| 2 | `deploy_light` → `no such file el-sca-images-light.tar` | старый автодетект бандла | обновиться (фикс 43e2399) или `deploy_light.sh bundle` |
| 3 | скан-grype: `database was built … ago` | бандл-БД старше 5 дней | онлайн-обновить Grype (шаг 6) + `grype-db-importer` |
| 4 | grype-update: `anchore.io Read timed out` | троттлинг CDN в контуре | failover/зеркало (шаг 6) |
| 5 | свежий grype-update не виден сканеру | не сделан import в `grype-cache` | `grype-db-importer` или `run-scan --update-db` |
| 6 | cve-bin: `Database does not exist` (exit 40) | feed-`cve.db` не для cve-bin-tool 3.4 --offline | теперь не фатально (208bdd1); отчёт строится без cve-bin |
| 7 | `df /opt` «не меняется» при клоне | `/opt/sca-work` — отдельный диск (sdb1), а df смотрел `/` | смотреть `df /opt/sca-work` |

---

## TL;DR — в несколько команд (контур с доступом к интернету)

```bash
sudo rm -rf /opt/sca-work/el-sca-ansamble
cd /opt/sca-work && git lfs install && \
  git clone https://github.com/Eljees/el-sca-ansamble.git && cd el-sca-ansamble
./scripts/deploy_light.sh
python3 -m pip install fastapi "uvicorn[standard]" python-multipart
python3 -m resilient_updates.cli dashboard --repo-root . --host 0.0.0.0 --port 8088 &
# → браузер http://<IP>:8088 → «☢ Обновить ВСЁ» → «Обновить статус»
./scripts/run-scan.sh -t "/home/elaria/_SCA/CYBERSEC-11603/makarov-i-686402 (1).gz" --update-db
```
