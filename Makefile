# el-sca-ansamble — common developer targets.
#
# Required tools (no `make` step installs them):
#   * docker + docker compose v2
#   * Python 3.12+ (for tests, lint, lock generation)
#   * pre-commit  (`pip install pre-commit` then `make hooks`)
#   * pip-tools   (`pip install pip-tools`)        for `make lock`
#   * ruff, yamllint, hadolint, shellcheck         for `make lint`
#
# Usage:
#   make help            list everything
#   make full TARGET=…   update + scan + report

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

PYTHON         ?= python3
COMPOSE        ?= docker compose
COMPOSE_PROFILES ?= scan,update
# On Linux, Docker enforces host UID on bind mounts and creates named volumes
# as root.  Automatically include the linux overlay so volume-init fixes
# ownership before any writer starts.  On Windows/macOS (Docker Desktop) the
# virtualisation layer neutralises the issue and the overlay is not loaded.
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
COMPOSE_FILE   ?= docker-compose.yml:docker-compose.linux.override.yml
else
COMPOSE_FILE   ?= docker-compose.yml
endif

# Reference target for the pipeline targets below.  Override on the CLI:
#   make full TARGET=/abs/path/to/artifact.tar.gz
TARGET         ?=

# Phase-4 lint command groups.
RUFF       ?= ruff
SHELLCHECK ?= shellcheck
HADOLINT   ?= hadolint
YAMLLINT   ?= yamllint

# Files / globs the linters consume.
PY_SOURCES   := resilient_updates tests
SH_SOURCES   := $(shell find scripts -maxdepth 2 -type f -name '*.sh' -not -path 'scripts/windows/*')
DOCKERFILES  := Dockerfile.resilient-updater Dockerfile.extractor Dockerfile.cve-bin-tool Dockerfile.apk-analyzer Dockerfile.win-analyzer Dockerfile.db-data
YAML_SOURCES := docker-compose.yml docker-compose.windows.override.yml docker-compose.linux.override.yml \
                docker-compose.prod.example.yml \
                configs/feed_sources.yaml .github .pre-commit-config.yaml .yamllint

# ─────────────────────────────────────────────────────────────────────────
# Help (default target)
# ─────────────────────────────────────────────────────────────────────────
.DEFAULT_GOAL := help

.PHONY: help
help:  ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "}; \
	  /^[a-zA-Z0-9_.-]+:.*?## / {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' \
	  $(MAKEFILE_LIST) | sort

# ─────────────────────────────────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────────────────────────────────
.PHONY: validate
validate:  ## Validate feed_sources.yaml + compose schema.
	$(COMPOSE) -f $(COMPOSE_FILE) config -q
	$(PYTHON) -m resilient_updates.cli validate-config

.PHONY: preflight
preflight:  ## Validate env + render compose with strict guards.
	./scripts/preflight_compose.sh

# ─────────────────────────────────────────────────────────────────────────
# Pipeline shortcuts (Linux/macOS).  TARGET= must be set or compose fails.
# ─────────────────────────────────────────────────────────────────────────
.PHONY: update update-compose scan report full
update:  ## Pull fresh CVE databases (all tools, auto-routed). TOOL=trivy|grype|cve-bin-tool for one.
	./scripts/update-db.sh $(or $(TOOL),all)

update-compose:  ## Legacy: raw compose-up of every updater (no auto-route, no trivy flag render).
	COMPOSE_PROFILES=update SCAN_TARGET_HOST="$(TARGET)" $(COMPOSE) up --abort-on-container-exit

scan:  ## Run the scan stage (Syft → Grype → Trivy → cve-bin-tool).
	@[ -n "$(TARGET)" ] || { echo "ERROR: set TARGET=/path/to/artifact" >&2; exit 2; }
	COMPOSE_PROFILES=scan SCAN_TARGET_HOST="$(TARGET)" $(COMPOSE) up --abort-on-container-exit

report:  ## Generate the final aggregated report.
	@[ -n "$(TARGET)" ] || { echo "ERROR: set TARGET=/path/to/artifact" >&2; exit 2; }
	COMPOSE_PROFILES=report SCAN_TARGET_HOST="$(TARGET)" $(COMPOSE) run --rm report-collector

full:  ## Full cycle: update → scan → report.
	@[ -n "$(TARGET)" ] || { echo "ERROR: set TARGET=/path/to/artifact" >&2; exit 2; }
	./scripts/run-scan.sh -t "$(TARGET)" -u -c

.PHONY: cvebt-export-bundle cvebt-import-bundle cvebt-diagnose
cvebt-export-bundle:  ## Export cve-bin-tool DB bundle (+manifest +sha256) from container cache.
	./scripts/cvebt_export_bundle.sh

cvebt-import-bundle:  ## Import a cve-bin-tool DB bundle archive. Use BUNDLE=path/to/*.tar.zst.
	@[ -n "$(BUNDLE)" ] || { echo "ERROR: set BUNDLE=/path/to/cvebt-db-*.tar.zst" >&2; exit 2; }
	./scripts/cvebt_import_bundle.sh "$(BUNDLE)"

cvebt-diagnose:  ## Print cve-bin-tool update capabilities and optional online attempts.
	./scripts/diagnose_cvebt_update.sh

.PHONY: batch
batch:  ## Batch-scan multiple targets.  JOBS_JSON=/path.json or JOBS_CSV=/path.csv.
	@[ -n "$(JOBS_JSON)$(JOBS_CSV)" ] || { echo "ERROR: set JOBS_JSON=/path/to/jobs.json (or JOBS_CSV=/path)" >&2; exit 2; }
	@if [ -n "$(JOBS_JSON)" ]; then \
	  ./scripts/batch-scan.sh --jobs-json "$(JOBS_JSON)" $(if $(UPDATE_DB_ONCE),--update-db-once); \
	else \
	  ./scripts/batch-scan.sh --jobs-csv "$(JOBS_CSV)" $(if $(UPDATE_DB_ONCE),--update-db-once); \
	fi

.PHONY: bench
bench:  ## Wall-clock benchmark: TARGET=/path RUNS=3 [INCLUDE_COLD=1].
	@[ -n "$(TARGET)" ] || { echo "ERROR: set TARGET=/path/to/artifact" >&2; exit 2; }
	./scripts/benchmark.sh --target "$(TARGET)" \
	  --runs $(if $(RUNS),$(RUNS),3) \
	  $(if $(INCLUDE_COLD),--include-cold) \
	  $(if $(UPDATE_DB_ONCE),--update-db-once)

# ─────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────
.PHONY: test
test:  ## Run pytest with coverage (gate: 88%, excludes @integration).
	$(PYTHON) -m pytest -q --disable-warnings -m "not integration" --cov=resilient_updates --cov-report=term-missing --cov-fail-under=88

# ─────────────────────────────────────────────────────────────────────────
# Linters (each target also runs in CI; see .github/workflows/ci.yml).
# ─────────────────────────────────────────────────────────────────────────
.PHONY: lint lint-py lint-sh lint-docker lint-yaml
lint: lint-py lint-sh lint-docker lint-yaml  ## Run every linter.

lint-py:  ## ruff check + format check + byte-compile.
	$(RUFF) check $(PY_SOURCES)
	$(RUFF) format --check $(PY_SOURCES)
	$(PYTHON) -m compileall -q $(PY_SOURCES)

lint-sh:  ## shellcheck for POSIX shell scripts.
	@if [ -z "$(SH_SOURCES)" ]; then echo "No .sh files to check."; else \
	  $(SHELLCHECK) -S warning $(SH_SOURCES); fi

lint-docker:  ## hadolint for every Dockerfile.
	@for df in $(DOCKERFILES); do echo "-- $$df"; $(HADOLINT) --config .hadolint.yaml $$df; done

lint-yaml:  ## yamllint with .yamllint config.
	$(YAMLLINT) -s -c .yamllint $(YAML_SOURCES)

# ─────────────────────────────────────────────────────────────────────────
# Locking + tooling install
# ─────────────────────────────────────────────────────────────────────────
.PHONY: lock hooks
lock:  ## Re-generate requirements.txt from requirements.in via pip-tools.
	pip-compile --strip-extras --generate-hashes --output-file requirements.txt requirements.in

hooks:  ## Install pre-commit hooks locally.
	pre-commit install
	pre-commit install --hook-type pre-push

# ─────────────────────────────────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────────────────────────────────
.PHONY: feeds
feeds:  ## Fetch EPSS + CISA KEV feeds into artifacts/enrichment (enables EPSS/KEV report columns).
	mkdir -p artifacts/enrichment/epss artifacts/enrichment/kev
	curl -fsSL --retry 3 https://epss.cyentia.com/epss_scores-current.csv.gz | gunzip > artifacts/enrichment/epss/epss_scores-current.csv
	curl -fsSL --retry 3 https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -o artifacts/enrichment/kev/known_exploited_vulnerabilities.json
	@echo "feeds ready: artifacts/enrichment/{epss,kev}"

.PHONY: setup-linux
setup-linux:  ## (Linux) Fix named-volume + artifacts/ ownership for appuser (UID 1001). Run once on fresh clone or after make clean-deep.
	docker compose -f docker-compose.yml -f docker-compose.linux.override.yml \
	    --profile update run --rm volume-init

.PHONY: clean clean-deep
clean:  ## Remove scan output (artifacts/) keeping .gitkeep stubs.
	find artifacts -type f ! -name '.gitkeep' -delete 2>/dev/null || true
	find artifacts -mindepth 1 -type d -empty -delete 2>/dev/null || true
	rm -f output.*.json .coverage .coverage.* 2>/dev/null || true

clean-deep: clean  ## Also remove cached caches.  USE WITH CARE — DBs gone.
	$(COMPOSE) down -v --remove-orphans

# ─────────────────────────────────────────────────────────────────────────
# DB bundle shipping (data image — see docs/SHIP_AND_DEPLOY.md)
# ─────────────────────────────────────────────────────────────────────────
.PHONY: db-export-image db-push-image db-import-image
db-export-image:  ## Export current DB volumes into a data image (DB_IMAGE=, DB_TAG=).
	./scripts/export_db_image.sh

db-push-image:  ## Export + push the DB data image to the registry (DB_IMAGE=registry/.../db-data).
	./scripts/export_db_image.sh --push

db-import-image:  ## Pull the DB data image and restore volumes (DB_IMAGE=registry/.../db-data:tag).
	./scripts/import_db_image.sh

.PHONY: images-export images-import
images-export:  ## Build/pull ALL images and save to artifacts/image-bundle/images.tar.
	./scripts/export_images.sh

images-import:  ## Load the stack image bundle (offline).  TAR=path optional.
	./scripts/import_images.sh $(TAR)
