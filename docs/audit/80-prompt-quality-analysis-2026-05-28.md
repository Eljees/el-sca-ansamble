# Анализ качества промптов — 2026-05-28

> Анализ двух промптов из `-prompts/` в сопоставлении с реальными результатами выполнения.

---

## 0. Исходные данные

| Артефакт | Путь |
|---|---|
| Промпт 1 (research) | `-prompts/cve_bin_tool_sca_db_cache_source_update_validation_prompt.md` |
| Промпт 2 (architecture) | `-prompts/codex_prompt_el_sca_cvebt_resilience.md` |
| Результаты исследования | `_el_cvebt_source_research/20260513_192101/` |
| Текущий прогон | `artifacts/summary.json`, `artifacts/status.json` |
| Аудит кода | `docs/audit/70-fixups-2026-05-27.md` |

---

## 1. Промпт 1: `cve_bin_tool_sca_db_cache_source_update_validation_prompt.md`

### 1.1 Что требовал промпт

- 15 разделов, строгие safety rules, acceptance criteria
- Evidence-based диагностика плохого `sca_db_cache`
- Проверить 30+ URL/источников через HTTP probe
- 11 попыток обновления (T01–T11) в изолированных кешах
- Source matrix (таблица), db_counts до/после каждой попытки
- Финальный Markdown-отчёт с recovery paths и recommendations

### 1.2 Реальные результаты выполнения

**До vs После (из `db_counts_before.json` vs `db_counts_active_fixed.json`):**

| Источник | ДО | ПОСЛЕ |
|---|---|---|
| NVD | 0 ❌ | 210 950 ✅ |
| GAD | 0 ❌ | 29 759 ✅ |
| REDHAT | 23 072 ✅ | 22 309 ✅ |
| CURL | 1 692 ✅ | 1 844 ✅ |
| OSV | 0 | 6 916 ✅ |
| EPSS | 0 | 1 ✅ |
| PURL2CPE | 2 529 460 ✅ | 2 543 156 ✅ |
| RSD | 0 | 363 321 ✅ |
| `overall_status` | **FAIL** | **PASS** |
| `cve.db` размер | 538 MB | 955 MB |

**Попытки обновления (из `db_counts_after_attempts.json`):**

| Попытка | Метод | Exit | Результат |
|---|---|---|---|
| T02 | json-mirror (основной кеш) | 0 ✅ | NVD+GAD восстановлены, 36 мин |
| T02b | json-mirror (изолированный) | 33 ❌ | NVD=0, частично |
| T03 | json-nvd (изолированный) | 33 ❌ | Mismatch 1.1 vs 2.0 schema |
| T04 | api2 (без ключа) | 1 ❌ | 403 Forbidden на dashboard/statistics |
| T05 | GAD только | 33 ❌ | 4056 файлов, но SQLite GAD=0 |
| T06 | CURL только | 33 ❌ | cve_range=188, но severity пуст |
| T07 | PURL2CPE только | 33 ❌ | 2.5M records, но tool exit≠0 |
| T08 | EPSS только | 33 ❌ | Broken get_cve_data() argument |
| T09 | REDHAT только | 0 ✅ | REDHAT=23162, работает |
| T10 | OSV только | timeout 900s ❌ | Убит, слишком медленно |
| T11 | RSD только | 33 ❌ | RSD=0 в изолированном запуске |

### 1.3 Оценка качества промпта

**Сильные стороны:**

- **Acceptance criteria явные** — чёткий список того, что считается успехом; исполнитель не мог «притвориться», что задача выполнена
- **Safety rules конкретные** — запрет удалять кеш без backup, запрет отключать SHA-валидацию соблюдался; в артефактах есть backup
- **Структура артефактов задана** — `_el_cvebt_source_research/YYYYMMDD_HHMMSS/` с чётким списком файлов; реальная директория совпадает с требованием на 90%
- **Evidence-first discipline работала** — перед каждой попыткой обновления делался probe; ни одна попытка не была «вслепую»
- **Source coverage широкий** — 14 источников + 8 кандидатов; реальная source_matrix покрывает все перечисленные в промпте

**Слабые стороны:**

- **Ambiguity в "confirmed_working"** — промпт требовал strictного определения, но T02 (успех) прошёл на основном загрязнённом кеше, а не в изоляции. GAD в итоговом кеше >0, хотя T05 (GAD isolated) = 0. Это не ошибка промпта, но условие активации DB не было чётко разделено от условия "source works"
- **Timeout policy не указана** — промпт разрешал "bounded attempts" и упоминал OSV timeout, но не указал конкретный лимит (300s? 900s?). OSV был killed на 900s — это решение исполнителя, промпт не зафиксировал политику
- **Exit code 33 не объяснён** — промпт не объяснял семантику exit codes cve-bin-tool. Исполнитель наткнулся на exit=33 (partial update) и трактовал как fail — правильно, но промпт мог это явно указать
- **Нет требования к unit-test verify** — после восстановления кеша не требовалось прогнать реальное сканирование для проверки качества результатов

**Вывод по промпту 1: хорошее качество (8/10).** Основная цель достигнута. Структура артефактов совпадает с требованием. Слабости — в пограничных кейсах (GAD isolated vs non-isolated, timeout policy), которые в следующей версии стоит явно прописать.

---

## 2. Промпт 2: `codex_prompt_el_sca_cvebt_resilience.md`

### 2.1 Что требовал промпт

1. Исправить bind mount shadowing (`/opt/app` для кода, `/workspace` для артефактов)
2. Починить docker-compose interpolation + добавить preflight
3. DB update state machine: api2 → json-mirror → json-mirror без OSV → json-nvd retry → bundle → LKG
4. DB health статусы: `fresh/degraded/lkg/failed`
5. Политика `CVE_BIN_TOOL_DB_POLICY=strict|degraded-ok|lkg-ok`
6. Export/import bundle (`cvebt_export_bundle.sh`, `cvebt_import_bundle.sh`)
7. Тесты: compose render, runtime imports, fault injection

### 2.2 Реальные результаты (artifacts/summary.json от 2026-05-27)

```json
{
  "cve_bin_tool_matches": 13,
  "grype_matches": 0,
  "trivy_matches": 0,
  "tool_failures": ["grype", "trivy"],
  "update_cve_db": "unknown",
  "db_drift": "unknown",
  "policy_decision": "no-policy"
}
```

**Из аудита `docs/audit/70-fixups-2026-05-27.md`:**

| Задача | Статус |
|---|---|
| §18 JVM heap configurable | ✅ Исправлено |
| §15 retry count dedup | ✅ Исправлено |
| §13 atomic_publish EXDEV | ✅ Исправлено |
| smoke tests populated | ✅ Исправлено |
| requirements.lock — placeholder | ⏳ Требует действий |
| NVD API key rotation | ⏳ Требует действий |
| Coverage baseline | ⏳ Требует действий |
| **7 файлов truncated** | ⚠️ Восстановлено вторым проходом |

### 2.3 Оценка качества промпта

**Сильные стороны:**

- **Evidence-first требование** — команды диагностики были явно прописаны до любых изменений; это предотвратило «угадывание» причин
- **Жёсткие запреты конкретные** — "не отключать SHA", "не скрывать 403", "не оставлять entrypoint в /workspace" — это actionable guardrails, не абстрактные принципы
- **State machine подробная** — каждый шаг с конкретным условием перехода; исполнитель знал что делать при каждом типе ошибки
- **Controlled bypasses как feature flags** — `CVE_BIN_TOOL_DISABLE_SOURCES_ON_RETRY`, `CVE_BIN_TOOL_PATCH_OSV_MISSING_TYPE` — хороший паттерн

**Слабые стороны — критические:**

- **Промпт слишком большой** — файл > 1000 строк. Это приводит к **context overflow / truncation** в длинных сессиях. 7 truncated файлов — прямое следствие. Промпт должен быть разбит на итерационные фазы с checkpoints
- **Нет явного checkpointing** — промпт требовал сделать всё за один проход (1→2→3→4→5). Реальность: после каждой фазы нужно останавливаться и верифицировать, прежде чем идти дальше
- **grype/trivy не восстановлены** — промпт фокусировался на cve-bin-tool. grype и trivy упоминались только в "не ломать Trivy/Grype/Syft" — но не было явной задачи сделать их working. Результат: `tool_failures: ["grype", "trivy"]` остались
- **`policy_decision: "no-policy"`** — промпт задавал `CVE_BIN_TOOL_DB_POLICY`, но в реальном прогоне policy не применяется. Либо реализация неполная, либо env var не передаётся
- **`update_cve_db: "unknown"`** — DB update state machine из промпта не интегрирована в `run_summary.py`; поле остаётся unknown

**Вывод по промпту 2: среднее качество (5/10) как инструкция для одного прохода, но плохо масштабируется.** Содержательно промпт верный и детальный. Проблема — в формате: монолитный промпт на 1000+ строк неизбежно приводит к truncation и incomplete execution. Нужна итерационная структура.

---

## 3. Общий паттерн: что работает, что нет

### Что работало в обоих промптах

- **Явные acceptance criteria** > implicit "сделай хорошо"
- **Evidence перед патчем** — предотвращает угадывание
- **Safety rules как явные prohibitions** — не советы, а запреты с обоснованием
- **Артефакт-структура заранее** — исполнитель знает куда класть результаты
- **Конкретные команды для проверки** — не "проверь что работает", а конкретный bash/python snippet

### Что не работало

- **Монолитный промпт > ~500 строк** — ведёт к truncation, partial execution, потере контекста
- **Одна большая цель вместо фаз** — без промежуточных stop-and-verify исполнитель продолжает при ошибках
- **Неявные timeout policies** — если промпт не говорит "прервать через N секунд", исполнитель делает произвольный выбор
- **Scope creep** — промпт 2 охватывает bind mount + compose + cve-bin-tool + тесты + отчёт. Слишком широко для одного прохода

---

## 4. Рекомендации для следующих версий промптов

### Промпт 1 (research) → версия 2

- Добавить явный timeout policy: `OSV_UPDATE_TIMEOUT=300s`, `NVD_ATTEMPT_TIMEOUT=600s`
- Разделить "source reachable" и "source activates DB": два отдельных criterion
- Добавить пункт: после восстановления кеша прогнать `cve-bin-tool` на тестовом target и проверить что findings > 0

### Промпт 2 (architecture) → версия 2

- **Разбить на 4 отдельных промпта** (фазы):
  1. Фаза 1: bind mount fix + smoke test (max 200 строк)
  2. Фаза 2: compose preflight + env normalization (max 150 строк)
  3. Фаза 3: cve-bin-tool DB state machine (max 300 строк)
  4. Фаза 4: grype/trivy integration + report collector (max 200 строк)
- Каждая фаза заканчивается **явным stop и verification gate**: "если verification не прошёл — стоп, не иди в следующую фазу"
- Добавить в scope grype и trivy — сейчас они вне scope, но `tool_failures` их включает
- Добавить явную задачу: `update_cve_db` и `update_grype_db` поля в summary.json должны быть не "unknown"

---

## 5. Статус текущей системы (сводка)

| Компонент | Статус |
|---|---|
| cve-bin-tool сканирование | ✅ Работает (13 matches) |
| cve-bin-tool DB quality | ⚠️ unknown (не отслеживается в summary) |
| grype | ❌ tool_failure |
| trivy | ❌ tool_failure |
| DB health statuses (fresh/degraded/lkg) | ❌ не реализованы |
| policy_decision | ❌ "no-policy" |
| requirements.lock | ❌ placeholder |
| NVD API key | ⚠️ requires rotation |
| test coverage baseline | ⚠️ неизвестна |

---

*Создано: 2026-05-28. Автор: automated analysis pass.*
