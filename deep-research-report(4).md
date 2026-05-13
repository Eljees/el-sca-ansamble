# Исследование контейнеризации, обновления баз и fallback-механизмов для cve-bin-tool, Trivy, Grype и Syft

## Executive summary

Это исследование показывает, что четыре инструмента находятся на очень разной стадии зрелости именно в части контейнеризации, обновления данных и отказоустойчивости. У **Trivy** уже есть наиболее развитая штатная модель для контейнерной эксплуатации: официальные container images, отдельные внешние базы (`trivy-db`, `trivy-java-db`, `trivy-checks`), поддержка self-hosting через OCI registry, частичный built-in fallback по нескольким `--db-repository`/`--java-db-repository`, а также air-gapped/manual cache population. У **Grype** сильнее, чем у других, проработаны валидируемые обновления БД на стороне клиента: `update-url`, hash validation, age validation, таймауты, max-age и режимы поведения при невозможности проверить обновление; при этом у него нет штатного списка альтернативных URL-источников, поэтому реальный fallback проще всего строить через внутренний mirror/update service. **Syft** вообще не является vulnerability DB scanner: для него задача “обновления баз” в основном сводится не к advisory DB, а к version pinning, контролю scan source, registry auth и стратегии работы с образами/архивами/директориями. **cve-bin-tool** поддерживает офлайн-сценарии, экспорт/импорт БД, отключение отдельных data sources и mirror-режимы, но среди собранных материалов он выглядит наименее “готовым из коробки” к многоисточниковому fallback в контейнерной среде; для него наиболее вероятен wrapper-first подход, а code-level phase имеет наибольшую ценность именно здесь. citeturn18view0turn20view1turn20view0turn44view1turn43view0turn15view0turn16view0

Если цель — сделать **MVP без форка**, самый разумный путь выглядит так:  
**Trivy** и **Grype** использовать через отдельные updater-контейнеры + shared volumes или внутренний mirror; **Syft** запускать как stateless SBOM generator с жёстко заданными источниками (`--from`, registry auth, архивы/директории); **cve-bin-tool** сначала оборачивать wrapper-скриптом и mirror/export-import pipeline, а не пытаться сразу проектировать upstream patch. Если цель — именно единый `docker-compose` pipeline без изменения upstream-кода, это реалистично для всех четырёх, но наиболее “нативно” — для Trivy и Grype; для Syft это просто и уместно, а для cve-bin-tool потребуется больше внешней orchestration-логики. citeturn20view3turn28view2turn44view1turn43view5turn43view0turn15view0turn16view0

Самый важный вывод для последующей работы с Codex: **не надо начинать с code patches**. Для Trivy и Grype сначала нужно зафиксировать no-code architecture и проверить поведение на timeout/429/5xx/corrupt-db/stale-db в controlled experiments. Для cve-bin-tool сначала нужно доказательно выяснить, что wrapper + mirror/export/import недостаточны; только после этого имеет смысл обсуждать изменения в `data_sources`, `cli.py` или `cvedb.py`. Для Syft code-level fallback, скорее всего, вообще не нужен: там выгоднее стандартизовать источники сканирования и канал интеграции с Grype. citeturn15view0turn18view0turn20view1turn44view1turn43view0turn43view5

## Scope and assumptions

Исследование опирается на официальные материалы и исходные репозитории проектов, связанных с entity["organization","Open Source Security Foundation","open source security org"], entity["company","Aqua Security","cloud security company"] и entity["company","Anchore","software company"]. В качестве первичных источников использовались официальная документация и официальные GitHub-репозитории: urlдокументация cve-bin-toolturn1search0, urlдокументация Trivy по базамturn17search0, urlконфигурация Grypeturn37search0, urlдокументация Syft по scan targetsturn41search1, а также связанные official repos и архитектурные документы по build/update pipeline. citeturn1search0turn17search0turn37search0turn41search1turn43view4

Что **исследовалось**: контейнерная пригодность, официальные и производные data sources, офлайн/air-gap/read-through/self-hosted сценарии, наличие built-in fallback, наличие mirrorable artifacts, конфигурационные параметры, likely modification points, и степень зависимости от внешних сервисов вроде OCI registries, GitHub, Maven Central, NVD и vendor advisories. Что **не исследовалось полноценно**: runtime-поведение under load, точное поведение некоторых edge-cases в Windows/PowerShell, точные mount-path примеры для всех инструментов в Docker Desktop, а также внутренний код каждого release workflow до уровня полного patch plan; такие моменты в отчёте явно помечены как `likely`, `unknown` или `requires experiment`. citeturn20view0turn29view0turn44view1turn43view2turn15view0

### Evidence map

| Tool | Claim | Evidence type | URL/file | Confidence |
|---|---|---|---|---|
| cve-bin-tool | Поддерживает несколько data sources и их отключение через CLI | Official manual | urlCVE Binary Tool User Manualturn1search0 | confirmed citeturn7view4 |
| cve-bin-tool | Новый data source добавляется через `cve_bin_tool/data_sources`, `cli.py`, а при необходимости и `cvedb.py` | Official contributor docs | urlAdding a new data source to cve-bin-toolturn14search0 | confirmed citeturn15view0 |
| cve-bin-tool | В официальной документации показан контейнерный запуск через generic container, а не через явно опубликованный upstream image | Official how-to + repo inspection | urlHow to scan a docker imageturn9search2 | confirmed for docs; upstream image not found in collected sources citeturn16view0turn11view0 |
| Trivy | Поддерживает `trivy-db`, `trivy-java-db`, `trivy-checks` и self-hosting этих артефактов | Official docs | urlTrivy Databasesturn17search0 / urlSelf-Hosting Trivy's Databasesturn19search0 | confirmed citeturn18view0turn20view1 |
| Trivy | Есть штатный fallback по нескольким `--db-repository` / `--java-db-repository` на transient 429/5xx | Official docs | urlTrivy Databasesturn17search0 | confirmed citeturn18view0 |
| Trivy | Для checks bundle есть embedded fallback, но нет multi-repository fallback | Official docs | urlTrivy Databasesturn17search0 / urlBuilt-in Policiesturn19search3 | confirmed citeturn18view0turn20view4 |
| Grype | Имеет single configurable `db.update-url`, validate-by-hash, validate-age, max-age и timeouts | Official config reference | urlGrype Configuration Referenceturn37search0 | confirmed citeturn44view1turn44view4 |
| Grype | `grype-db` строится как orchestration layer поверх upstream data и `vunnel` providers | Official architecture docs | urlGrype DB architectureturn41search3 / urlvunnel repoturn37search4 | confirmed citeturn43view4turn39view2 |
| Syft | Поддерживает Docker/Podman/Containerd/registry/archive/dir/file/singularity scan targets | Official docs | urlSupported Scan Targets for Syftturn41search1 | confirmed citeturn43view0turn41search8 |
| Syft | Не использует отдельную vulnerability DB; центральная задача — cataloging и output SBOM | Official docs | urlSyft architectureturn41search5 / urlSBOM Generationturn42search14 | confirmed citeturn41search5turn43view3 |

## cve-bin-tool

### Что именно обновляет и как устроен update path

В официальном manual у cve-bin-tool видны как минимум следующие logical data layers: `CURL`, `EPSS`, `GAD`, `NVD`, `OSV`, `PURL2CPE`, `REDHAT`, `RSD`; те же источники видны и в исходниках `cve_bin_tool/data_sources/__init__.py`, где они импортируются и собираются в общий набор `SOURCES`. Это означает, что у инструмента нет одной монолитной vulnerability DB из одного origin-а: он агрегирует несколько семантически разных слоёв — собственно advisories/records (`NVD`, `OSV`, `GAD`, `REDHAT`, `CURL`), риск/приоритизацию (`EPSS`) и вспомогательное сопоставление (`PURL2CPE`, `RSD`). Последние два я бы классифицировал как **derived/enrichment layers**, а не как “реальные альтернативные vulnerability sources”. Это уже важно для будущего fallback design: переключение с `NVD` на `OSV` — это смена advisory source, а переключение `PURL2CPE` — нет. citeturn7view4turn4view1

У NVD в manual подтверждены несколько retrieval modes: `api`, `api2`, `json`, `json-mirror`, `json-nvd`; при этом отдельная how-to страница прямо говорит, что NVD API может использоваться как backup, если текущий JSON feed retrieval interface будет убран, а также что API поддерживает incremental updates через `-u latest -n api`. Это не multi-source fallback в полном смысле, а **несколько retrieval paths к одному и тому же upstream family**, что полезно, но не решает проблему source priority для независимых advisory origins. citeturn7view4turn12view0

Документация по добавлению нового data source подтверждает, что основной extension point — это новый класс в `cve_bin_tool/data_sources`, затем регистрация в `cli.py`, а при необходимости — адаптация `populatedb()` в `cvedb.py`. Это означает, что code-level добавление fallback возможно минимум на трёх уровнях: wrapper над CLI, source-class logic, и orchestration в `cvedb.py`. Именно поэтому cve-bin-tool выглядит самым естественным кандидатом на будущий minimal fork, если no-code wrapper окажется недостаточным. citeturn15view0turn4view0

### Контейнеризация, offline и mirror-паттерны

Среди собранных официальных источников я **не нашёл подтверждённый upstream container image или официальный Dockerfile**. Зато официальная how-to страница прямо описывает два пути: установить cve-bin-tool внутрь обычного контейнера и сканировать директорию внутри него, либо `docker cp`-нуть нужную директорию на host и сканировать уже на host. Это означает, что контейнерный запуск поддерживается **операционно**, но не как first-class packaged container workflow. Для production-пайплайна это толкает к wrapper image или self-built image почти автоматически. citeturn16view0turn11view0

Документация также содержит официальный offline guide, а в manual присутствуют и специальные параметры, связанные с импортом/экспортом JSON-базы. В сочетании с `--use-mirror` это даёт два практически полезных no-code пути:  
во-первых, подготовка БД на онлайн-машине с последующим переносом в offline environment;  
во-вторых, использование локального mirror/export-import pipeline.  
Иначе говоря, у cve-bin-tool offline/air-gapped режим **есть**, но в терминах отказоустойчивости он больше похож на запланированный bootstrap/transfer workflow, чем на прозрачный runtime fallback. citeturn9search11turn7view4turn8search0

### Где fallback уже есть, а где его нет

Подтверждённо есть: выбор retrieval mode для NVD; single mirror switch `--use-mirror`; отключение отдельных data sources; офлайн-экспорт/импорт; update scheduling (`now`, `daily`, `never`, `latest`). Подтверждения для **списка альтернативных mirror URLs**, **source priority**, **health check per source**, **last-known-good cache activation**, **atomic cache swap** и **freshness policy по каждому source** в собранной документации нет. В contributor docs, напротив, прямо сказано, что новый source должен уметь “fail gracefully if there’s a timeout or something”, но это требование к реализации source-а, а не уже имеющийся оркестратор fallback. citeturn7view4turn15view0

Практически это означает следующее.  
**Wrapper-level fallback** реалистичен: можно внешний updater запускать с retry/backoff, проверкой целостности экспортированного артефакта и atomic publish на shared volume.  
**Mirror/export-import fallback** тоже реалистичен: сначала отдельный online updater, потом offline scanners.  
**Source-class fallback** тоже возможен, но это уже code-level change.  
**Настоящий multi-source priority list inside tool** в собранных материалах не подтверждён и, вероятнее всего, потребует изменений в upstream logic. citeturn15view0turn16view0turn9search11

### Вывод по cve-bin-tool

Для MVP я бы считал cve-bin-tool инструментом категории **wrapper-first**. Его разумно запускать в self-built/wrapper image, с отдельным updater-контейнером, shared cache volume, экспортом/import pipeline для offline-сценариев и строгой фиксацией update policy снаружи. Code-level phase для него выглядит наиболее оправданной среди всех четырёх инструментов, но только после проверки того, что wrapper/mirror/export-import действительно не покрывают ваши target failure modes. citeturn16view0turn15view0turn9search11

## Trivy

### Что именно обновляет и как устроен data plane

Для Trivy официальная документация очень чётко разделяет три внешних базы: `trivy-db` для vulnerabilities, `trivy-java-db` для идентификации Java artifacts, и `trivy-checks` для built-in misconfiguration logic. Отдельно существует VEX Hub как ещё одна внешняя зависимость, а для Java package identification Trivy может обращаться к Maven Central или иным remote repositories, если не включён `--offline-scan`. Это значит, что у Trivy не одна “база”, а несколько независимо жизнеспособных asset layers с разными режимами обновления и разной ценностью в fallback-архитектуре. citeturn22search8turn20view0turn23view2

Официальный `trivy-db` repo подтверждает, что DB build идёт каждые 6 часов, а metadata update interval по умолчанию — 24 часа. `trivy-java-db` обновляется ежедневно. Для checks bundle официальная документация говорит о проверке обновлений каждые 24 часа. Это на практике означает, что separate updater container для Trivy имеет смысл не только ради трафика и rate limits, но и ради воспроизводимости: вы можете отделить момент “pull/update security assets” от момента “run scans”. citeturn18view4turn18view5turn20view4

Архитектура добавления нового advisory source у Trivy formally multi-repo: сначала `vuln-list-update` собирает raw advisories, затем `vuln-list` хранит их как Git-backed dataset, затем `trivy-db` парсит и преобразует в DB schema, затем `trivy` использует эту DB при сканировании. Для уже Git-managed sources шаг `vuln-list-update` можно пропустить, но в общем случае добавление нового официального source — это **цепочка как минимум из трёх репозиториев**, а не локальный patch в одном месте. citeturn20view2turn36view1

### Контейнеризация и self-hosting

У Trivy есть подтверждённые официальные container images в Docker Hub, GHCR и AWS Public ECR. Документация рекомендует монтировать persistent cache dir и, если нужно сканировать образы через local Docker daemon, монтировать engine socket. Кроме standalone mode, у Trivy есть и client/server mode: сервер сам скачивает vulnerability DB и продолжает обновлять её в фоне, а это уже почти готовый шаблон для отдельного updater/scanner deployment. citeturn23view0turn20view3

Self-hosting тоже документирован официально: `trivy-db`, `trivy-java-db` и `trivy-checks` пакуются как OCI artifacts, которые можно скопировать во внутренний registry с помощью `crane`, `oras` или `regclient`, а затем указать Trivy на свои `--db-repository`, `--java-db-repository` и `--checks-bundle-repository`. Есть и manual cache population для air-gapped use case: база скачивается на онлайн-машине, распаковывается и целевым образом копируется в cache directory. Именно поэтому Trivy из всех четырёх проще всего встроить в дизайн “local OCI registry mirror + scanner containers use internal source only”. citeturn20view1turn28view1turn28view2

### Built-in fallback и реальные пробелы

По `trivy-db` и `trivy-java-db` есть встроенный fallback на несколько репозиториев: флаг принимает несколько значений, и при transient errors вроде 429 или 5xx Trivy переключается на альтернативный registry в указанном порядке. По умолчанию в списке уже есть `mirror.gcr.io/aquasec` и `ghcr.io/aquasecurity` для основной БД; Java DB тоже имеет два default repository в config reference. Это важная встроенная возможность, и в этом смысле Trivy — самый сильный кандидат для no-code resilience. Но у неё есть жёсткая граница: официальная документация говорит именно о transient errors; не-транзиентные или неожиданные ошибки не обещают автоматического перехода на следующий registry. citeturn18view0turn24view1turn17search8

Для checks bundle ситуация иная. Official docs прямо говорят, что `--checks-bundle-repository` **не поддерживает fallback через multiple options**, потому что вместо этого Trivy использует embedded checks из бинарника. Это хороший built-in safety net для misconfiguration scanning, но он не равен полноценному source priority list: embedded bundle может быть stale относительно внешнего OCI bundle, а “скачать только checks bundle” отдельной командой сейчас нельзя. citeturn18view0turn20view4

Для air-gapped и restricted network сценариев есть ещё два важных caveat-а.  
Во-первых, VEX Hub по умолчанию ходит в GitHub (`api.github.com`, `codeload.github.com`), но его можно self-host’ить.  
Во-вторых, Java-анализ может ходить в Maven Central для package identification; `--offline-scan` убирает эти запросы, но не отменяет необходимость vulnerability DB, если вы не применяете `--skip-db-update` или заранее не прогрели кэш. Иначе говоря, для truly offline режима Trivy требует не одного переключателя, а осознанной комбинации: local DB cache or self-hosted OCI, `--skip-*update`, `--offline-scan`, а при необходимости — self-hosted VEX Hub. citeturn20view0turn23view2turn25search3

### Supply-chain и эксплуатационный вывод

Trivy официально подписывает binaries и container images через Cosign, и это делает version pinning + signature verification практичным требованием для security pipeline. Это особенно важно потому, что в марте 2026 года Aqua опубликовала официальный security advisory о временной compromise части Trivy ecosystem distribution channels. Для исследуемой задачи это не повод отказаться от Trivy; наоборот, это аргумент за внутренний mirror, pinning по digest и верификацию артефактов до публикации во внутренний registry. citeturn32search13turn32search14turn33search7

### Вывод по Trivy

Если нужен **MVP без форка**, Trivy — лучший первый кандидат. Built-in multi-registry fallback, OCI self-hosting, air-gap/manual cache population и server mode уже дают почти весь необходимый фундамент. Code-level изменения нужны только если вам принципиально важны: fallback на non-transient errors, source health awareness, provenance logging по registry attempts, отдельный fetch-only workflow для checks bundle или более агрессивная last-known-good semantics. citeturn18view0turn20view1turn20view3turn20view0

## Grype

### Что именно обновляет и как устроен build/distribution path

У Grype user-facing data plane проще, чем у Trivy: он работает с локально установленной vulnerability DB и на стороне клиента опирается на один configurable distribution endpoint `db.update-url`. Official configuration reference показывает default `update-url: "https://grype.anchore.io/databases"`, локальный cache-dir `~/.cache/grype/db`, автоматическую проверку обновлений, hash validation, age validation, max allowed built age и отдельные timeouts для check/update phases. То есть Grype имеет зрелую **политику валидируемого потребления** базы, но не встроенную политику множественных источников. citeturn44view1turn44view4

На builder side official architecture docs поясняют, что `grype-db` — это orchestration layer: pull upstream vuln data, build via grype’s build library, package DB for distribution. Отдельно подчёркнута multi-schema support architecture: `grype-db` умеет трансформировать актуальную data shape из `vunnel` во все поддерживаемые DB schema versions. Это важно для будущих code changes, потому что добавление нового upstream source может требовать не только patch в scanner, но и изменение поставщика данных на стороне `vunnel`/`grype-db`. citeturn43view4

`vunnel` в официальном README перечисляет provider model и набор поддерживаемых upstream data sources: Alpine, Amazon, Azure, Debian, Echo, GitHub Security Advisories, NVD, Oracle, Red Hat, SLES, Ubuntu, Wolfi; в списке доступных providers также видны chainguard, mariner и minimos. Следовательно, Grype DB — это именно **derived database over provider ecosystem**, а не прямой runtime consumer отдельных advisories. Это делает внутренний grype-db mirror очень логичным: вместо runtime fallback между провайдерами вы централизуете сбор/ валидацию на publisher side. citeturn39view2turn43view4

### Контейнеризация и mirror/self-host patterns

Grype поддерживает все основные target types, включая Docker/Podman/Containerd/registry, архивы, директории, файлы, SBOMs и отдельные PURL/CPE. Это делает его очень удобным кандидатом для scanner container, который либо сканирует напрямую image/archive, либо читает заранее сгенерированный Syft SBOM. В связке с Syft это особенно удобно: SBOM generation выносится в один step, vulnerability matching — в другой. citeturn43view5turn39view1

С точки зрения resilience у Grype на удивление сильны именно client-side controls:  
`validate-by-hash-on-start: true`,  
`validate-age: true`,  
`max-allowed-built-age: 120h`,  
`require-update-check: false`,  
`update-available-timeout: 30s`,  
`update-download-timeout: 5m`,  
`max-update-check-frequency: 2h`.  
То есть Grype уже умеет отвечать на часть вопросов про stale DB, corrupt DB и bounded waiting time гораздо лучше, чем cve-bin-tool. Но при этом конфигурация всё ещё предполагает **один** `update-url`, а не источник с приоритетами. Поэтому в контейнерной архитектуре у Grype естественный путь — это внутренний HTTP distribution endpoint, за которым уже стоит ваш собственный fan-out/fallback logic. citeturn44view0turn44view1

В issue context уже зафиксирован переход distribution path от старого `toolbox-data.anchore.io/.../listing.json` к новому `grype.anchore.io/databases/v6/latest.json`, а текущая official config reference показывает уже ещё более абстрактный базовый `https://grype.anchore.io/databases`. Для вашей задачи это значит две вещи. Во-первых, старые proxy/mirror recipes могли сломаться при миграции URL scheme. Во-вторых, если вы строите internal mirror, его лучше проектировать не как fragile rewrite поверх старых listing files, а как контролируемый внутренний distribution contract. citeturn40search5turn44view1

### Built-in safeguards и пробелы

У Grype подтверждены сразу несколько важных защитных механизмов: hash validation при старте, age validation, max-age, configurable timeouts и возможность не делать update-check blocking (`require-update-check: false`). Это означает, что поведение вроде “не смог проверить existence/up-to-date источника, но использую уже валидную локальную БД” **частично предусмотрено конфигурацией**, хотя официальная документация в собранных источниках не описывает это как explicit “last-known-good mode”. Поэтому я оцениваю last-known-good как **partial/likely**: локальная действительная БД может пережить сбой update check, но formal activation semantics при разных failure modes надо подтвердить экспериментом. citeturn44view0turn44view1

Чего явно не хватает: списка альтернативных update URLs, приоритетов источников, health reporting на уровне distribution source, provenance log о том, откуда и какой listing/archive был активирован, и явно описанного atomic cache swap. Из issue context видно, что при проблемах обновления пользователь может получить и timeout, и “database does not exist”, и import-related failures; то есть отсутствие robust multi-source distribution внутри Grype остаётся реальным operational gap. citeturn37search1turn38search1turn40search1

### Вывод по Grype

Для Grype наилучший путь — **internal mirror / update service**, но не fork-first. У Grype уже есть всё, чтобы быть хорошим consumer’ом внутреннего источника: configurable URL, hash validation, age policy, timeouts. Поэтому если вам нужен failover между несколькими внешними источниками, выгоднее реализовать его **вне** Grype — в вашем publisher/mirror — и дать Grype один стабильный внутренний endpoint. Code-level phase для Grype оправдана только если вы хотите, чтобы сам Grype умел: multi-URL fallback, primary/secondary priority, explicit last-known-good activation rules, source health telemetry или provenance across mirrors. citeturn44view1turn43view4turn39view2

## Syft

### Что означает “обновление баз” для Syft

Ключевой вывод здесь простой: в собранных официальных материалах Syft не фигурирует как vulnerability DB consumer. Официальная архитектурная страница описывает цепочку `source -> catalog -> format`: пакет `syft/source` создаёт `source.Source`, затем Syft каталогизирует его в `sbom.SBOM`, а `syft/format` кодирует результат в нужные SBOM formats. Отсюда следует, что для Syft вопрос “обновления баз” — это в основном вопрос **версии самого Syft, набора catalogers, порядка разрешения image sources и стабильности registry/auth paths**, а не отдельной advisory DB. citeturn41search5turn43view3

Поэтому отдельный updater-контейнер для Syft как “DB updater” обычно не нужен. Реалистичный operational equivalent для Syft — это:  
pinning версии Syft,  
контроль scan target type через `--from`,  
контроль источника образа (`docker`/`podman`/`containerd`/`registry`/архив/директория),  
контроль auth к registry,  
и при необходимости преобразование/нормализация output форматов.  
Именно в таком виде Syft имеет смысл включать в общий pipeline. citeturn43view0turn43view1turn43view2turn42search15

### Scan targets, catalogers и форматы

Официальные docs подтверждают, что Syft поддерживает Docker, Podman, Containerd, registry, `docker-archive`, `oci-archive`, `oci-dir`, `singularity`, directories и files; тип можно либо автоопределять, либо задавать через `--from`. Command reference отдельно уточняет важную деталь: по умолчанию Syft пытается использовать Docker daemon, а если Docker недоступен, образ тянется напрямую из registry. Это уже само по себе мягкий source fallback на уровне **scan target acquisition**, хотя не на уровне vulnerability data. citeturn43view0turn41search8

Syft генерирует SBOMs в нескольких форматах, включая SPDX, CycloneDX и native Syft JSON; поддерживается и экспериментальная конверсия между форматами. Пакетные catalogers в официальной документации описаны как настройка для обнаружения ПО в language-specific и file-based ecosystems, а contributing/architecture docs объясняют naming/tags model для catalogers. Для данного исследования это означает, что Syft — инструмент про **coverage of package ecosystems and reproducible SBOM generation**, а не про fallback между advisory feeds. citeturn43view3turn42search15turn42search2turn42search4

### Registry auth, network behavior и интеграция с Grype

Официальная документация по private registries общая для Syft и Grype. Она подтверждает, что при `registry` source используется Docker config file и credential helpers; если задать `--from docker`, инструменты делегируют аутентификацию container runtime. Следовательно, для containerized Syft ключевыми volumes и secrets будут не DB volumes, а Docker config / credential helper context, а также, при необходимости, engine socket или архивы. Для полностью контролируемой среды режим `registry` часто лучше, чем daemon-coupled mode, потому что он снимает зависимость от сокета хоста и делает scan source явным. citeturn43view2turn43view0

Интеграция с Grype подтверждена с двух сторон: официальный Syft repo говорит, что он works seamlessly with Grype, а docs Grype подтверждают приём SBOM input в Syft JSON, SPDX и CycloneDX. Поэтому для совместного pipeline лучший практический паттерн выглядит так: Syft генерирует SBOM из image/archive/dir, затем Grype сканирует уже SBOM. Это повышает воспроизводимость и ослабляет runtime-зависимость scanner’а от конкретного image source. citeturn41search4turn43view5

### Вывод по Syft

Для Syft слово “fallback” уместно в основном в трёх местах:  
fallback между image sources (`docker` vs `registry` vs archive),  
fallback между auth mechanisms (runtime auth vs Docker config/credential helpers),  
fallback между output formats и downstream consumers.  
Отдельный code-level phase для “обновления баз” в Syft на текущей evidence base не выглядит оправданным. Если вам нужен единый compose pipeline, Syft — как раз самый простой компонент: stateless job, явный `--from`, явные registry creds, pinned version и общий volume только под входные артефакты/выходные SBOM. citeturn43view0turn43view2turn43view3

## Cross-tool matrices and architecture options

### Data source inventory

| Tool | Source/layer | Name | Primary or mirror | Purpose | Format | Current support | Mirror/fallback potential | Evidence |
|---|---|---|---|---|---|---|---|---|
| cve-bin-tool | Advisory source | NVD (`api`, `api2`, `json`, `json-mirror`, `json-nvd`) | primary source family / retrieval variants | CVE records | API / JSON feeds | already supported | moderate; mirror/export/import possible, but not a true independent alternative source list | citeturn7view4turn12view0 |
| cve-bin-tool | Advisory source | Red Hat | primary | vendor advisories | feed/API-derived ingestion | already supported | mirrorable via external pipeline; built-in source priority not documented | citeturn7view4turn8search1 |
| cve-bin-tool | Advisory source | OSV | primary | ecosystem vulnerability records | JSON API/dataset | already supported | possible via mirror/export pipeline | citeturn7view4turn8search1 |
| cve-bin-tool | Advisory source | GitLab Advisory Database | primary | language/package advisories | Git/JSON | already supported | possible via wrapper/mirror; no documented internal priority list | citeturn7view4turn8search1 |
| cve-bin-tool | Advisory source | curl advisories | primary for curl-specific data | curl vulns | project data | already supported | possible but narrow-scope | citeturn8search1turn7view4 |
| cve-bin-tool | Enrichment | EPSS | derived/enrichment | exploit likelihood | score feed | already supported | not a vulnerability source fallback | citeturn8search5turn7view4 |
| cve-bin-tool | Enrichment | PURL2CPE / RSD | derived/enrichment | package/CPE mapping and related support data | derived dataset | already supported | not a real advisory alternative; code-level additions possible | citeturn7view4turn15view0 |
| Trivy | Derived DB | `trivy-db` | derived official DB | vulnerability scanning | OCI artifact | already supported | very high; official self-hosting + multiple repos + mirror | citeturn22search8turn18view0turn20view1 |
| Trivy | Derived DB | `trivy-java-db` | derived official DB | Java artifact identification | OCI artifact | already supported | very high; official self-hosting + multiple repos | citeturn18view5turn18view0turn20view1 |
| Trivy | Checks bundle | `trivy-checks` | derived official bundle | misconfiguration logic | OCI artifact / embedded fallback | already supported | high for self-hosting, but no multi-repo fallback; embedded fallback exists | citeturn22search8turn20view4turn20view1 |
| Trivy | Raw advisory store | `vuln-list` | upstream source for DB builder | raw advisories | Git repo / JSON | upstream source for DB builder | mirrorable as Git dataset; not consumed directly by Trivy CLI | citeturn36view1 |
| Trivy | Updater/build layer | `vuln-list-update` | upstream source for DB builder | fetch/validate raw advisories | code + cron | upstream source for DB builder | relevant only if building your own DB chain | citeturn20view2turn36view1 |
| Trivy | External connectivity | VEX Hub | external repo | VEX documents | GitHub-hosted repo/archive | already supported | self-hosting officially documented | citeturn20view0turn28view3 |
| Trivy | External metadata | Maven Central / remote repos | API/source for package metadata | Java package identification | HTTP repository metadata | already supported where needed | no true mirror story in collected CLI docs; `--offline-scan` suppresses network lookups | citeturn23view2turn20view0 |
| Grype | Distribution endpoint | `https://grype.anchore.io/databases` | official distribution | client DB update | HTTP listing/archive | supported via config | high for internal HTTP mirror; built-in multi-URL fallback absent | citeturn44view1 |
| Grype | Builder/orchestration | `grype-db` | upstream DB builder | build/package DB | build pipeline | upstream source for DB builder | high if you own publisher side | citeturn43view4 |
| Grype | Provider framework | `vunnel` | upstream source for DB builder | fetch/transform raw upstream vuln data | provider-based cached data | upstream source for DB builder | high if building own DB chain; not used directly by scanner container | citeturn39view2turn43view4 |
| Grype | Upstream providers | Alpine/Amazon/Azure/Debian/Echo/GHSA/NVD/Oracle/RedHat/SLES/Ubuntu/Wolfi + others | primary upstream inputs to builders | advisories and vulnerability records | mixed APIs/feeds/Git | upstream source for DB builder | mirror on builder side, not via scanner config | citeturn39view2 |
| Syft | Scan source | Docker/Podman/Containerd/registry | primary input sources | acquire target contents | runtime / registry | already supported | wrapper can choose preferred order; no vulnerability DB involved | citeturn43view0turn41search8 |
| Syft | Scan source | `docker-archive` / `oci-archive` / `oci-dir` / `singularity` / `dir` / `file` | primary input sources | offline/local analysis | filesystem artifacts | already supported | excellent for air-gapped and reproducible workflows | citeturn43view0 |
| Syft | Output layer | SPDX / CycloneDX / Syft JSON | output formats | SBOM interchange | SBOM documents | already supported | conversion and downstream fallback are straightforward | citeturn43view3turn42search15 |

### Containerization matrix

| Tool | Official image | Self-build viability | Required volumes | Cache/db path | Offline mode | Compose role | Windows/PowerShell notes | Risks |
|---|---|---|---|---|---|---|---|---|
| cve-bin-tool | not found in collected official docs | high | target input, report output, persistent cache/db, optional exported DB bundle | cache under user cache dir per docs/logs; exact path environment-specific | yes, via offline/export-import workflow | updater + scanner + optional mirror/export service | official collected docs use POSIX shell examples; PowerShell path syntax needs experiment | no first-class image workflow, weak built-in fallback, more wrapper logic needed citeturn16view0turn9search11turn10search5 |
| Trivy | confirmed: Docker Hub / GHCR / AWS ECR | high | target input, persistent cache dir, optional Docker socket, registry creds, optional local OCI mirror access | configurable via `--cache-dir` | yes, via self-hosting/manual cache population/skip flags/offline-scan | updater, scanner, optional server, local OCI mirror | official examples are POSIX-oriented; PowerShell scripts should be prepared separately | DB/scanner behavior depends on several external assets unless fully mirrored citeturn23view0turn29view0turn20view1turn20view0 |
| Grype | likely official, but not re-verified from installation docs in this pass | high | target input, DB cache, optional SBOM input/output, registry creds | `~/.cache/grype/db` by default | partial-to-strong, via internal update URL and import/cache workflows | updater + scanner + internal HTTP DB mirror | official PowerShell examples were not collected; treat as requires experiment | single `update-url`, sparse official mirror/import ergonomics compared with Trivy citeturn44view1turn43view5turn40search1 |
| Syft | not re-verified from official install docs in this pass | very high | target input, output SBOM, optional engine socket, registry creds | no vulnerability DB cache requirement established in collected docs | strong for local archives/directories/images already present locally | stateless generator; no dedicated DB updater needed | PowerShell-friendly in principle, but explicit host examples were not collected | main risk is source ambiguity/auth/runtime dependency, not DB freshness citeturn43view0turn43view2turn43view3 |

### Fallback and readiness matrix

| Tool | Built-in fallback | Configurable fallback | Offline support | Last-known-good | Integrity validation | Timeout controls | Main gap |
|---|---|---|---|---|---|---|---|
| cve-bin-tool | retrieval variants for NVD; mirror switch; disable sources | wrapper/mirror/export-import outside tool | yes | unknown | partial/unclear in collected docs; requires experiment | not confirmed in collected user docs | no source priority list, no multi-mirror list, no health/provenance/atomic swap citeturn7view4turn12view0turn15view0 |
| Trivy | multi-repo fallback for DB/Java DB on 429/5xx; embedded checks fallback | `--db-repository`, `--java-db-repository`, self-hosting, skip flags, manual cache population | yes | partial/manual; not a strong automatic stale-cache contract in docs | undocumented for DB artifacts in collected user docs | global timeout present | checks bundle has no multi-repo fallback; non-transient failures are not documented to try next repo citeturn18view0turn20view1turn24view0turn17search8 |
| Grype | validation by hash/age and bounded update behavior; single configured source | internal mirror via `update-url` | yes/likely via import or mirrored distribution | partial/likely if valid cached DB exists, but needs experiment | yes, hash validation | yes, dedicated update timeouts | only one update URL; no ordered fallback, no source health, no provenance log citeturn44view0turn44view1turn37search1 |
| Syft | source auto-detection; can switch to explicit `--from` | wrapper-defined source order and registry auth strategy | yes for local targets | not applicable | not applicable for vulnerability DB | not researched deeply enough | “fallback” mostly external to Syft because there is no advisory DB plane to heal inside the tool citeturn43view0turn43view2 |

### Architecture options

| Variant | Tools covered | Complexity | Code changes | Reliability gain | Maintenance cost | Upstream compatibility | Best use case | Risks |
|---|---|---:|---:|---:|---:|---|---|---|
| Только штатные возможности | best for Trivy; good for Grype; partial for cve-bin-tool; sufficient for Syft | low | none | medium | low | highest | quick pilot, local CI, internet-reachable runners | cve-bin-tool and Grype still have weak multi-source fallback; Trivy still depends on external assets unless mirrored citeturn18view0turn44view1turn15view0turn43view0 |
| Wrapper без изменения upstream-кода | all four | medium | none | high | medium | high | recommended MVP | requires disciplined scripts, health state, digest/schema checks outside tools citeturn20view1turn44view1turn15view0turn43view2 |
| Docker Compose pipeline | all four | medium-high | none | high | medium | high | shared volumes, updater/scanner split, local report collector | socket/auth handling and Windows host ergonomics need testing citeturn23view0turn20view3turn43view2turn16view0 |
| Internal vulnerability data mirror | strongest for Trivy and Grype; partial for cve-bin-tool; not applicable to Syft’s “DB updates” | high | none for consumers | very high | medium-high | high | enterprise CI, air-gap, rate-limit avoidance | publisher itself becomes critical component and needs its own integrity/freshness controls citeturn20view1turn44view1turn43view4turn9search11 |
| Code-level fallback patches | mostly cve-bin-tool; selective for Trivy/Grype; usually not needed for Syft | high | yes | potentially very high | high | lowest | when wrapper/mirror is demonstrably insufficient | fork burden, drift from upstream release flow, higher test/documentation cost citeturn15view0turn20view2turn43view4 |

## Recommended research conclusion

Если ориентироваться на **разумный MVP**, я бы рекомендовал такую последовательность принятия решений.  
Сначала принять **вариант wrapper + compose + внутренний mirror только там, где он уже нативно поддержан**. Практически это означает: Trivy — internal OCI mirror/self-hosting как primary path; Grype — single internal HTTP update URL как primary path; Syft — stateless/pinned/source-controlled; cve-bin-tool — отдельный updater с экспортом/импортом либо локальным mirror/export pipeline. Это даёт заметный прирост надёжности без форка и без раннего погружения в upstream internals. citeturn20view1turn44view1turn43view0turn9search11

Если нужен **первый инструмент для практического старта**, то я бы разделил ответ на два слоя.  
Если говорить о простоте контейнеризации — первым проще всего запускать **Syft**, потому что у него нет отдельного vulnerability DB plane.  
Если говорить о задаче именно “контейнеризация + обновление баз + fallback” — первым надо брать **Trivy**, потому что именно у него strongest native support для self-hosting и built-in fallback.  
**Grype** логично брать вторым, чтобы сравнить “OCI-distributed multi-asset model” против “single internal distribution URL + strong local validation”.  
**cve-bin-tool** разумно оставлять последним в MVP-цепочке, потому что у него больше всего пользы от wrapper orchestration и больше всего шансов, что позднее действительно потребуется code-level phase. citeturn20view1turn18view0turn44view1turn43view0turn16view0

Что делать **без изменения кода**.  
Для Trivy: separate updater container, shared read-only cache after update, внутренний OCI mirror, включённые `--db-repository`/`--java-db-repository` с сохранением default repos там, где интернет ещё разрешён, и явные offline knobs для Java/VEX.  
Для Grype: updater/publisher, который обновляет внутренний HTTP endpoint или локально импортирует DB в shared volume; scan containers читают только внутренний `update-url` и используют built-in hash/age/timeouts.  
Для Syft: единый pinned image/binary, явный `--from`, зафиксированный auth path и optional SBOM handoff в Grype.  
Для cve-bin-tool: wrapper image, update stage отдельно от scan stage, persist cache/export bundle, и максимально явная политика использования зеркала или импортированной базы. citeturn18view0turn20view1turn44view1turn43view0turn15view0turn16view0

Что оставить на **code-level phase**.  
Для cve-bin-tool: source priority, multi-mirror list, source health reporting, atomic cache activation и, возможно, richer provenance around source selection.  
Для Trivy: fallback на non-transient download failures, richer source health/provenance, отдельный checks-bundle prefetch workflow.  
Для Grype: multi-URL update source list, explicit last-known-good state transitions, source provenance and activation logs.  
Для Syft: на текущей evidence base code-level phase по теме “обновления баз” не выглядит целесообразной. citeturn15view0turn18view0turn44view1turn43view0

Какие эксперименты нужны **до** формулирования следующего Codex-prompts.  
Нужно воспроизвести не функциональность сканирования как таковую, а именно отказоустойчивость: timeout на primary source, HTTP 429, HTTP 5xx, повреждённая БД, просроченная БД, запуск со stale cache, и cold-start air-gap bootstrap. Для Trivy и Grype это должно стать первым раундом практической валидации; для cve-bin-tool — вторым, уже после обвязки export/import or mirror wrapper; для Syft — вместо DB failures нужно проверять source selection и registry auth behaviors. citeturn18view0turn20view0turn44view1turn43view2turn15view0

## Материал для следующего Codex-промпта

### Confirmed facts

1. cve-bin-tool агрегирует несколько data layers (`CURL`, `EPSS`, `GAD`, `NVD`, `OSV`, `PURL2CPE`, `REDHAT`, `RSD`), умеет отключать data sources, имеет NVD retrieval variants, offline guide и documented extension points через `data_sources`, `cli.py` и при необходимости `cvedb.py`. citeturn7view4turn15view0turn4view1  
2. Trivy использует три внешних security assets (`trivy-db`, `trivy-java-db`, `trivy-checks`), поддерживает OCI self-hosting, multiple `db-repository`/`java-db-repository` fallback на transient errors, manual cache population и embedded checks fallback. citeturn18view0turn20view1turn20view4  
3. Grype имеет single configurable `db.update-url`, `validate-by-hash-on-start`, `validate-age`, `max-allowed-built-age`, `require-update-check`, dedicated timeouts и multi-schema builder architecture через `grype-db` + `vunnel`. citeturn44view1turn43view4turn39view2  
4. Syft — это source/catalog/format tool для SBOM generation; он поддерживает контейнерные runtime sources, registry, архивы, директории и файлы, а интеграция с Grype официально предусмотрена. citeturn41search5turn43view0turn41search4turn43view5

### Selected architecture

Для первого Codex-этапа стоит выбрать **вариант B/C как основной** и **вариант D как целевое усиление**:  
единый `docker-compose` pipeline с отдельными сервисами updater/scanner/report-collector;  
Trivy получает внутренний OCI mirror или pre-populated cache;  
Grype получает внутренний HTTP DB endpoint или подготовленный DB cache;  
Syft работает как stateless generator SBOM;  
cve-bin-tool работает через wrapper image и отдельный update/export-import stage.  
Code-level changes на этом этапе не выбирать как default path. citeturn20view1turn44view1turn43view0turn15view0

### Files likely to inspect

Для cve-bin-tool:  
`cve_bin_tool/data_sources/__init__.py`, `cve_bin_tool/cli.py`, `cve_bin_tool/cvedb.py`, offline/how-to docs, и места, где обрабатываются `--use-mirror`, импорт/экспорт и update schedule. citeturn4view1turn15view0turn4view0

Для Trivy:  
docs по `configuration/db`, `advanced/self-hosting`, `advanced/air-gap`, config schema, а затем — в code phase — цепочка `vuln-list-update`, `vuln-list`, `trivy-db`, `trivy`. citeturn18view0turn20view1turn20view0turn20view2turn36view1

Для Grype:  
official config reference, architecture docs по `grype-db`, provider layer в `vunnel`, и issue context around URL migration/import behavior. citeturn44view1turn43view4turn39view2turn40search5

Для Syft:  
`Supported Scan Targets`, config reference, private registry docs, SBOM generation docs и architecture docs вокруг `source`, `catalog`, `format`. citeturn43view0turn43view1turn43view2turn43view3turn41search5

### Commands to run

Будущему Codex имеет смысл готовить не Dockerfiles, а verification commands и experiment matrix. Минимальный набор опыта должен покрывать такие сценарии:  
`download/update only` для Trivy и Grype, затем отдельный scan из уже прогретого cache; это проверяет разделение update/scan. citeturn18view0turn44view1  
явный `--from registry` / `--from docker-archive` / `--from oci-archive` / `--from dir` для Syft и Grype; это проверяет воспроизводимость scan target resolution. citeturn43view0turn43view5  
запуск cve-bin-tool в контейнере с persistent cache volume и отдельной offline bootstrap фазой. citeturn16view0turn9search11  
Trivy с `--skip-db-update`, `--skip-java-db-update`, `--skip-check-update`, `--offline-scan` и self-hosted repositories; это проверяет truly restricted-network mode. citeturn18view0turn20view0  
Grype с внутренним `GRYPE_DB_UPDATE_URL`, различными `validate-*` и искусственно просроченной/подменённой БД; это проверяет LKG-like behavior и fail-open/fail-closed semantics. citeturn44view1

### Experiments to perform

Нужен небольшой, но жёсткий экспериментальный протокол:  
primary source timeout;  
HTTP 429;  
HTTP 5xx;  
битая БД/архив;  
БД старше policy age;  
scan при полном отсутствии сети, но с заранее подготовленным cache;  
cold-start air-gap bootstrap;  
два параллельных scanner-контейнера на одном shared cache volume;  
поведение при использовании локального registry mirror и при его отказе.  
Особенно важно проверить, используют ли инструменты stale cache предсказуемо или неожиданно падают после неудачного update attempt. Для Trivy и Grype это критично; для cve-bin-tool — вероятно, именно это и покажет, нужен ли форк; для Syft — акцент на source selection/auth, а не на DB freshness. citeturn29view0turn20view0turn44view1turn15view0

### Risks

Главные риски для следующего этапа такие.  
У Trivy — зависимость не от одной БД, а от нескольких внешних assets и дополнительных network calls вроде VEX Hub/Maven; при неполном mirror вы получите “почти офлайн”, а не настоящий offline. citeturn20view0turn23view2  
У Grype — single update URL и migration-sensitive distribution contract; proxy hacks вокруг legacy listing URLs будут хрупкими. citeturn44view1turn40search5  
У cve-bin-tool — отсутствие подтверждённого first-class container packaging и менее зрелая встроенная fallback-модель. citeturn16view0turn11view0turn15view0  
У Syft — риск лежит не в БД, а в неоднозначности source acquisition и registry auth, особенно в контейнерном окружении без daemon socket. citeturn43view0turn43view2  
Для всех четырёх — отдельный supply-chain риск в неподконтрольных внешних distribution points; отсюда рекомендация pinning, signature/digest verification там, где инструмент это допускает организационно. Для Trivy это особенно актуально после официального advisory 2026 года. citeturn32search13turn32search14

### Open questions for the user

Перед Codex-реализацией нужно заранее зафиксировать ответы на следующие вопросы.  
Есть ли уже локальный проект/репозиторий, в который нужно встраивать compose/wrapper orchestration, или требуется исследовательский prototype с нуля?  
Где должны храниться артефакты: shared volume, локальный HTTP server, OCI registry, object storage, артефактный менеджер?  
Какие инструменты приоритетнее: Trivy/Grype как scanners с update plane, или нужен общий MVP сразу для всех четырёх?  
Нужен ли **no-code wrapper MVP** как обязательный первый шаг, или уже заранее допускается fork/code-level fallback?  
Какие ограничения по сети существуют: полный air-gap, частично разрешённые registries, внутренний proxy, rate-limited GitHub/GHCR, недоступный Docker socket?  
Есть ли уже локальный OCI registry или HTTP mirror, который допустимо использовать как internal source of truth?  
Нужен ли строго воспроизводимый scan result workflow по pinned DB/assets, или достаточно “best effort latest available” внутри контролируемого окна обновления?  
Нужны ли отдельные сценарии для Windows host / Docker Desktop / PowerShell, чтобы Codex сразу готовил cross-platform wrapper scripts, а не только Linux-first orchestration? citeturn20view1turn44view1turn43view2turn16view0