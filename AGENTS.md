# Project Instructions

## Scope

These instructions apply to the whole repository.

## Project Shape

`el-sca-ansamble` is a Docker-based SCA stack for Trivy, Grype, Syft, and
cve-bin-tool. The Python package `resilient_updates` owns orchestration,
fallback/provenance, reporting, run snapshots, and the FastAPI dashboard.

Prefer the wrapper-first architecture: keep resilience and orchestration in
Python/shell wrappers instead of forking upstream scanners.

## Common Commands

Run these before handing off code changes:

```powershell
python -m ruff check .
python -m ruff format --check resilient_updates tests scripts tools
python -m compileall -q resilient_updates tests
python -m pytest -q
```

For compose-only changes, also check:

```powershell
docker compose config -q
docker compose -f docker-compose.yml -f docker-compose.windows.override.yml config -q
docker compose -f docker-compose.yml -f docker-compose.linux.override.yml config -q
docker compose -f docker-compose.yml -f docker-compose.offline.yml config -q
```

## Artifacts And Cleanup

Do not commit runtime artifacts from `artifacts/`, `_SCA_reports/`, caches, or
local `.env` files. Before deleting large scan outputs, make sure the relevant
evidence is either no longer needed or has a per-run snapshot under
`artifacts/runs/<project>-<timestamp>/` or next to the scanned source.

## Workflow

Keep GitHub/GitLab synchronization as a separate pass from code changes.
This repository often carries local commits ahead of one or both remotes, so
inspect `git branch -vv`, `git remote -v`, and diverge counts before pushing.

Prefer small, validated changes over broad refactors. Large modules such as
`resilient_updates/cli.py`, `dashboard.py`, and `orchestrator.py` should be
split only behind focused tests.
