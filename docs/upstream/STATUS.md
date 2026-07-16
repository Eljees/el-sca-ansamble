# cve-bin-tool EPSS bug — upstream status (2026-07-16)

Проверено по коду тега `v3.4`, ветки `main` и колесу `3.4.1rc0` с PyPI.

## TL;DR

Апстрим-PR **не нужен**: корневая причина уже исправлена в `main`
ossf/cve-bin-tool (изменение «metric ids as constants», ~PR #4473, смержено
в 2025). Апстрим просто **не выпускает релиз**: последний тег — `v3.4`,
стабильный на PyPI — `3.4`. Есть `3.4.1rc0` (2025-06-13), фикс в нём есть.

Прежний бандл из этой папки (патч с переносом `populate_metrics()` перед
сбором источников + PR_BODY/COMMANDS) снят: предлагать его апстриму
бессмысленно — в `main` фаза скачивания вообще больше не читает БД, там
нечего переупорядочивать. Наш образ вместо этого бекпортирует решение
апстрима на 3.4 (`scripts/patches/cve_bin_tool_3.4_fixups.py`).

## Матрица версий

| Версия | TypeError (cursor) | Ordering/EPSS_id_finder | URL EPSS |
|---|---|---|---|
| 3.4 (PyPI stable, наш пин) | есть | есть | cyentia (устарел) |
| 3.4.1rc0 (PyPI, RC) | исправлен | исправлен | cyentia (устарел) |
| main (ossf) | исправлен | исправлен | empiricalsecurity |

## Полезное действие в апстриме

Не PR с кодом, а issue с просьбой выпустить 3.4.1 — шаблон:
`docs/upstream/ISSUE_RELEASE_REQUEST.md`. К нему можно приложить наше
воспроизведение (`tests/test_cve_bin_tool_epss_fixups.py` — офлайн-репро
обоих слоёв бага на 3.4).

## Ссылки

- Репозиторий переехал: intel/cve-bin-tool → ossf/cve-bin-tool.
- Фикс в main: «metric ids as constants» (EPSS_METRIC_ID = 1 в cvedb.py,
  удалён EPSS_id_finder, update_epss(self) без cursor).
- Смена CDN EPSS в main: epss.cyentia.com → epss.empiricalsecurity.com
  (в rc0 ещё старый URL).
