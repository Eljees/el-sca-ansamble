# Audit 2026-05-25 — Конкретные дефекты

> Каждый пункт — `файл:строка`, цитата, последствие, ссылка на фазу
> исправления. Категории: **BUG** (поведение неверно), **SECURITY**
> (риск утечки/повышения привилегий), **SMELL** (хрупкость или
> подверженность поломке при изменениях), **INCONSISTENT** (две правды
> в одном проекте).

## 1. Секреты в `.env`

**SECURITY**, фаза A.

`.env` в рабочей копии:

```
NVD_API_KEY=41c8fd79-db9a-4b2f-bf23-92c0276b390b
NVD_API_KEY_FALLBACK=cf3e99dd-7112-479a-ba60-fc8fc772f067
CVE_BIN_TOOL_DB_POLICY=lkg-ok
```

- Файл в `.gitignore`, в `git log .env` отсутствует, в репозиторий не
  попал. Угроза не «утечка через git», а «файл лежит в
  `D:\!ya_drive_sync\YandexDisk\…` и синхронизируется в облако».
- **Действие**: ротировать оба ключа в NVD, оставить в `.env` пустые
  значения, ключи держать только в `.env.local` (он тоже в
  `.gitignore`). `docker-compose.yml` уже умеет читать оба источника
  через `${NVD_API_KEY:-}` / `${NVD_API_KEY_FALLBACK:-}`.

## 2. ~~`db_policy` игнорируется~~ — **FALSE POSITIVE, исключено из плана**

> Изначальный отчёт автоматического анализатора утверждал, что `db_policy`
> не используется. Перепроверка показала обратное:
>
> - `cli.py:356-364` (`_cve_db_policy`) парсит `CVE_BIN_TOOL_DB_POLICY` из env / yaml.
> - `cli.py:384-395` (поток активации) прокидывает значение в `activate_best_cve_bin_tool_db(db_policy=db_policy)`.
> - `cve_db_audit.py:271-283` валидирует значение и через `_policy_allows_status(db_policy, health_status)` управляет тем, какой candidate выбирается.
> - `cve_db_audit.py:315` — ветка `lkg-ok` действительно разрешает fallback на last-known-good.
>
> Подчёркивание в `cli.py:368` (`_db_policy = _cve_db_policy(...)`) —
> это Python-конвенция «параметр сознательно не используется», потому
> что `_run_cve_db_audit` отвечает только за **аудит**, а решение об
> активации принимает отдельный flow в `cli.py:384-395`.
>
> Поведение `strict / degraded-ok / lkg-ok` реально различается.
> Никаких правок не требуется.

## 3. `proxy_chain._probe_chain` классифицирует 4xx как «ok»

**BUG**, фаза A.

`resilient_updates/proxy_chain.py:356` — после `requests.get(healthcheck_url, ...)`:

```python
status = "ok" if response.status_code < 500 else "down"
```

`generate_204` Google и подобные пробы возвращают `204`, что < 400.
Но если прокси выдаёт `403 Forbidden` (как сейчас в моём sandbox-проксе) или `404 Not Found`, chain считается **здоровым**. В результате `failover_order` не отрабатывает.

**Действие**: заменить на `< 400`, либо явный whitelist `{200, 204}` + опционально `301/302` если разрешены редиректы.

## 4. `fallback.file://` URL на Windows

**BUG**, фаза A.

`resilient_updates/fallback.py:111` — обработка URL со схемой `file://`:

```python
parsed = urlparse(url)
local_path = Path(parsed.path)
```

На Windows `urlparse("file:///C:/x/y").path` → `/C:/x/y`. `Path()` это
принимает как POSIX-путь, и последующий `local_path.read_bytes()`
падает с `FileNotFoundError`. Это бьёт по любому
`custom_sources` с `file://`-URL в air-gapped развёртываниях.

**Действие**: добавить нормализацию для Windows:

```python
if os.name == "nt" and re.match(r"^/[A-Za-z]:/", parsed.path):
    local_path = Path(parsed.path.lstrip("/"))
else:
    local_path = Path(parsed.path)
```

Под тест: `tests/test_fallback_order.py` добавить кейс с `file:///C:/...`.

## 5. Нет `configs/wireguard/`

**BUG**, фаза A.

`docker-compose.yml:479`:

```yaml
wireguard:
  ...
  volumes:
    - ./configs/wireguard:/config
```

Профиль `vpn` объявлен и проходит `docker compose --profile vpn
config -q`, но при `docker compose --profile vpn up` Docker пишет
`failed to populate volume: source path ./configs/wireguard does not exist`.

**Действие**: создать пустой `configs/wireguard/.gitkeep` и `configs/wireguard/wg0.conf.example` с шаблоном (плюс короткая инструкция в `docs/network-design.md`).

## 6. Дубль cve-bin-tool pinning

**SMELL → BUG потенциально**, фаза A.

`Dockerfile.cve-bin-tool` — слой install:

```dockerfile
pip install -r /tmp/requirements.txt && \
pip install cve-bin-tool==3.4
```

Если в `requirements.txt`/`requirements.lock` указана другая версия
`cve-bin-tool` — два install'а в одной build-команде, второй
переустанавливает поверх первой и при этом игнорирует pin из локфайла.
Это снимает гарантии воспроизводимости.

**Действие**: вынести пинг `cve-bin-tool==3.4` в `requirements.in` и удалить
повторный `pip install` из Dockerfile. Источник правды один — `requirements.lock`.

## 7. ~~`run_scan.sh` (с подчёркиванием) — silent fallback~~ — **не дефект, оставлено**

> Перепроверка показала, что код корректен: `exit 3` сразу после ошибки,
> сообщение в stderr. Header-комментарий в начале файла явно
> различает `run_scan.sh` (native per-tool runner без docker) и
> `run-scan.sh` (полный pipeline).
>
> Проблема не в коде, а в потенциальной путанице при tab-completion на
> Windows (case-insensitive FS). Это уже зафиксировано в комментарии
> header'а; превращать в `exec` wrapper нет смысла — теряется
> легитимный native-режим. **Действий не требуется.**

## 8. `update_trivy.sh` — `$FLAGS` без массива

**BUG потенциально**, фаза B.

`scripts/update_trivy.sh:31`:

```sh
# shellcheck disable=SC2086
trivy "$SCAN_KIND" --cache-dir "$CACHE_DIR" $FLAGS ...
```

Если флаг придёт со значением, содержащим пробел/двойную кавычку — word-splitting разрежет
неправильно. Сейчас «работает», потому что флаги хардкод в `TRIVY_RENDERED_FLAGS`, но
маска уже стоит как технический долг.

**Действие**: переписать на массив:

```sh
mapfile -t FLAGS_ARR <<< "$(printf '%s\n' $FLAGS)"
trivy "$SCAN_KIND" --cache-dir "$CACHE_DIR" "${FLAGS_ARR[@]}" ...
```

…или прокидывать `TRIVY_RENDERED_FLAGS` как массив через
`xargs -a`. Сейчас оставить `shellcheck disable=SC2086` нельзя.

## 9. Все `Dockerfile.*` запускаются от root

**SECURITY**, фаза B/F.

Ни в одном из пяти `Dockerfile.*` нет директивы `USER`. Контейнеры
запускаются от root. Для `cve-bin-tool` и `resilient-updater` это
исторически объяснимо (нужен доступ ко всем артефактам), но для
`Dockerfile.extractor`, `Dockerfile.apk-analyzer`, `Dockerfile.win-analyzer`
это лишнее.

**Действие**: добавить непривилегированного пользователя в каждый Dockerfile,
оставив root только в `Dockerfile.resilient-updater` (где нужны named-volume
операции) с явной пометкой `# NOTE: root required for cross-volume copies`.

## 10. `_NON_RETRYABLE_REASONS` vs `retry_status_codes`

**INCONSISTENT**, фаза B.

`resilient_updates/fallback.py:96` — `_NON_RETRYABLE_REASONS` —
хардкод `frozenset({...})` с HTTP-кодами 4xx. Но `attempt_sources`
принимает `retry_status_codes` из конфига. В итоге если пользователь
ставит `retry_status_codes: [401, 403]` в `feed_sources.yaml` —
config'овые retry-коды конфликтуют с хардкодом, поведение зависит от
порядка проверок и неочевидно.

**Действие**: единая точка правды — `RetryPolicy` dataclass, читается из
config один раз, передаётся в `attempt_sources` явно. Хардкод убрать.

## 11. `extractor` — `shlex_quote` свой вместо стандартного

**SMELL**, фаза B.

`resilient_updates/extractor.py:273` — пользовательская функция
`shlex_quote`, missing edge-cases (newline в имени файла,
double-quote). Стандартный `shlex.quote()` уже умеет всё.

**Действие**: заменить на `from shlex import quote`.

## 12. `Path.stem` для archive-name unreliable

**SMELL**, фаза B.

`resilient_updates/extractor.py:143` — для `.tar.gz`/`.tar.bz2`/`.tar.xz`
`Path.stem` отрезает только последнее расширение → имя `foo.tar`. В
`extraction_manifest.json` это создаёт чужеродный артефакт.

**Действие**: использовать `_strip_archive_suffix(name, ARCHIVE_SUFFIXES)` для всех путей; синхронизировать с тестом
`tests/test_extractor.py`.

## 13. `cve_db_audit._activate` Windows-fallback на race

**SMELL**, фаза B.

`resilient_updates/cve_db_audit.py:330-352` — Windows-fallback на atomic publish:

```python
if os.name != "nt":
    raise
shutil.copytree(staging, active_path)   # ← окно для race-condition
```

Между удалением `active_path` и появлением нового — окно, в которое
scan-сервис прочитает пустой каталог. Для cve-bin-tool DB (~6 ГБ)
это секунды.

**Действие**: на Windows писать в `active.new`, затем `os.replace`-style
rename (атомарный в Windows на одном томе), потом удалять старый
`active.bak` асинхронно.

## 14. Дублирующиеся `_sha256_file/_sha512_file`

**SMELL / DUP**, фаза B.

Три модуля содержат свою копию:

- `resilient_updates/reporting.py:26-39`
- `resilient_updates/run_summary.py:57-63`
- `resilient_updates/extractor.py` (через `_strip_archive_suffix`, hash в `_sha256_file` модели похожей)

**Действие**: новый `resilient_updates/_io.py` с
`sha256_file`, `sha512_file`, `read_json`, `read_json_recursive`. Три модуля переключить.

## 15. `cli._dedup_attempted_sources` теряет статус ретрая

**SMELL**, фаза B.

`resilient_updates/cli.py:35-39` — дедуп по `item.source.name`
сохраняет только **последний** attempt. Если у одного source было
два захода с разными `reason` (например, `network` → `stale_data`),
в provenance запишется только последний.

**Действие**: либо сохранять все, либо мерджить с приоритетом «худшего»
статуса.

## 16. `enrichment.date_value` — float как «дата»

**BUG**, фаза D (тестом).

`resilient_updates/enrichment.py:81`:

```python
date_value = candidate.stat().st_mtime  # float
```

…далее это значение записывается в payload как timestamp. Сериализуется
JSON-ом как число, но в Markdown-вывод попадает «как строка float», что
ломает читаемость. Должно быть `datetime.fromtimestamp(...).isoformat()`.

## 17. `windows.override.yml` — асимметричный tmpfs без объяснения

**SMELL**, фаза C/E.

`docker-compose.windows.override.yml` — `cve-bin-tool-scanner` имеет
`tmpfs:/tmp:size=4g`, `cve-bin-tool-updater` — `size=2g`. Никакого
комментария «почему». Если кто-то увеличит `CVE_BIN_TOOL_DB_POLICY=strict`
вместе с большим target, scanner может упасть на out-of-tmpfs.

**Действие**: пометить комментарием «4G — лимит для самых тяжёлых binary
scan'ов; см. docs/runbook.md §3.4», либо параметризовать через env.

## 18. `Dockerfile.apk-analyzer` — hardcoded `JAVA_TOOL_OPTIONS=-Xmx512m`

**SMELL**, фаза E.

`Dockerfile.apk-analyzer` — `ENV JAVA_TOOL_OPTIONS="-Xmx512m"`. На
hosts с памятью >8 GB это слишком мало; на маленьких — может быть много.

**Действие**: оставить дефолт, но добавить переопределение через
`environment:` в compose:

```yaml
apk-analyzer:
  environment:
    JAVA_TOOL_OPTIONS: ${APK_JAVA_TOOL_OPTIONS:--Xmx512m}
```

## 19. `clean_generated.sh` — дубль `git clean -fdX`

**DEAD**, фаза E.

```sh
find . -type d -name __pycache__ -prune -exec rm -rf {} +
rm -rf .pytest_cache
```

То же делает `git clean -fdX` (с учётом `.gitignore`).

**Действие**: либо удалить и заменить `git clean -fdX` в `scripts/README.md`, либо оставить как алиас с комментарием «for non-git checkouts».

## 20. Tracked временные каталоги

**SMELL**, фаза A.

В рабочей копии есть `--exps/`, `-prompts/`, `comands.txt`,
`deep-research-report(4).md`, `_el_cvebt_source_research/`. Все они в `.gitignore`, но если когда-то были добавлены — удалить из tracking через `git rm --cached`.

`git ls-files | grep -E "exps|prompts|comands.txt|deep-research"` — проверить.

---

**См. также:** [00-overview.md](00-overview.md) · [20-architecture.md](20-architecture.md) · [30-tests.md](30-tests.md) · [40-tooling-docs.md](40-tooling-docs.md)
