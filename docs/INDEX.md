# Documentation map

This file is a sitemap for the docs.  Pick the lane that matches what you
need to do; each section is ordered by depth (read top-to-bottom).

## I need to scan an artefact (operator)

1. `../README.md` — what the project is and how the pipeline flows.
2. `../QUICK_START.md` — fastest path from clone to a first scan.
3. `operations.md` — exact commands for full and partial cycles.
4. `windows-powershell.md` — Windows-specific notes.
5. `airgap.md` — running without any internet access.

## I need to deploy or operate it (DevOps)

1. `../README.md` — bird's-eye view.
2. `architecture.md` — what each service does, which profile it lives in.
3. `network-design.md` — proxy chain, VPN, sidecars.
4. `operations.md` — runtime command reference.
5. `distribution.md` — image distribution / receiver setup.
6. `runbook.md` — what to do when things break.
7. `proxy.md` — quick reference for proxy configuration.
8. `deployment-example.md` — worked example of one org's full
   deployment (host-specific values — treat as a template, not canon).
9. `remote-analysis.md` — exact repeatable remote-machine sequence for DB refresh + full scan + GUI check.
10. `ubuntu-from-github.md` — the clean GitHub/Docker Hub install path on Ubuntu, without bundled databases.

## I need to review security posture

1. `../SECURITY.md` — reporting policy and threat model.
2. `security-notes.md` — DB validation, secrets handling, threat-model details.
3. `adr/0002-proxy-sidecar.md` — why the proxy stack looks the way it does.
4. `airgap.md` — what the air-gapped guarantees are.

## I need to develop / contribute

1. `../CONTRIBUTING.md` — dev environment, tests, linting, commit conventions.
2. `audit/archive/workspace.md` — local dev-workspace layout and conventions (historical, archived).
3. `architecture.md` — service / module map.
4. `audit/00-overview.md` — current audit findings and phased remediation.
5. `adr/0001-wrapper-first.md` — why we don't fork upstream.
6. `failure-modes.md` — error classification.
7. `reproducibility.md` — how reproducible runs are guaranteed.

## I need to understand the project's current state

1. `audit/00-overview.md` — independent audit summary (2026-05-25).
2. `audit/10-defects.md` — concrete defects with file:line refs.
3. `audit/20-architecture.md` — architectural themes.
4. `audit/30-tests.md` — test coverage map.
5. `audit/40-tooling-docs.md` — CI, pre-commit, doc gaps.
6. `audit/580-analysis-2026-07-02.md` — **latest**: `.gitignore` + 3 stale-docs фиксы; 873 теста, 95% покрытие, 4 коммита впереди GitHub; `scanner-diff` CLI подтверждён как существующий (570 ошибался) (2026-07-02).
7. `audit/570-analysis-2026-07-02.md` — чекап-only: NEW-1 `_SCA_reports/`, flaky-тест мониторить; 873 теста (2026-07-02).
8. `audit/530-analysis-2026-06-30.md` — D1–D20 все закрыты/WORKAROUND/accepted-design (D1=OPEN, нужна ротация NVD); v0.1.5, 868 тестов, 95% покрытие, GitHub синхронизирован (2026-06-30).
9. `audit/520-analysis-2026-06-29.md` — CI/CD раздел в architecture.md, RetryPolicy в таблице модулей (2026-06-29).
8. `audit/350-analysis-2026-06-17.md` — все P1 из 340 закрыты, 11 коммитов: cve-bin-tool HOME+soft-fail, grype failover, «Fixed in» колонка; v0.1.4 (2026-06-17).
9. `audit/310-analysis-2026-06-13.md` — 835 tests, v0.1.3 bump, monitor.py 100% coverage (2026-06-13).
10. `audit/270-analysis-2026-06-11.md` — full analysis pass (2026-06-11): D-NEW-1/2, phased plan.
11. `audit/240-analysis-2026-06-08.md` — full analysis pass (2026-06-08).
12. `audit/archive/` — superseded planning notes and older analysis files.
13. `../CHANGELOG.md` — release notes (Keep a Changelog).

## Architectural decisions

- `adr/0001-wrapper-first.md` — wrapper-first vs. fork-and-modify.
- `adr/0002-proxy-sidecar.md` — proxy sidecar chain.
- `adr/0003-vex-feed.md` — VEX feed via Trivy `--vex` (accepted, P3 deferred).
- `adr/0004-epss-kev-freshness.md` — EPSS/KEV freshness/TTL (proposed).
- `adr/0005-unified-cli-scan.md` — unified `cli scan` orchestrator (accepted, Phase 1 shipped).
- `adr/0006-fastapi-dashboard.md` — read-only FastAPI run dashboard (accepted).
- `adr/0007-updates-from-anywhere.md` — resilient DB updates from any network point (accepted).

## Reference

- `failure-modes.md` — failure classification used by `fallback.py`.
- `reproducibility.md` — what "reproducible" means here.
- `custom-sources.md` — how to declare your own upstream sources.

## Tools

- `../tools/docker-mcp/` — MCP server exposing compose stack control (scan, update-db, monitor, route-plan) to Claude / other LLM agents. See `tools/docker-mcp/README.md`.
