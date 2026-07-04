# Documentation map

This file is a sitemap for the docs.  Pick the lane that matches what you
need to do; each section is ordered by depth (read top-to-bottom).

## I need to scan an artefact (operator)

1. `../README.md` — what the project is and how the pipeline flows.
2. `../QUICK_START.md` — fastest path from clone to a first scan.
3. `operations.md` — exact commands for full and partial cycles.
4. `agent-artifact-intake.md` — AI-agent runbook: intake (mail/browser) → uploads → async scan → report + health-watch.
5. `windows-powershell.md` — Windows-specific notes.
6. `airgap.md` — running without any internet access.

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
6. `audit/630-analysis-2026-07-05.md` — **latest**: FUSE-TRUNC (5 файлов) восстановлены; stale lock удалён; STALE-30-BANNER+STALE-DEFENDER-README+LOGGING-FORMAT(A002) исправлены и закоммичены (2026-07-05).
7. `audit/620-analysis-2026-07-04.md` — SCANNER-DIFF-CLI закрыт (ложный carry-forward); 3 стейл-документ. находки; план Фаза 1–4 согласован (2026-07-04).
8. `audit/610-analysis-2026-07-04.md` — FUSE-DOCS закрыт (CONTRIBUTING.md); AUDIT-ARCHIVE закрыт (400–490 → archive); стale INDEX links удалены; 873 тестов ✅ (2026-07-04).
8. `audit/600-analysis-2026-07-03.md` — checkup-only, 0 новых дефектов; план: AUDIT-ARCHIVE, DOCS-INDEX-NUM, FUSE-DOCS (2026-07-03).
9. `audit/590-analysis-2026-07-03.md` — CI-LINUX-INTERNALERROR исправлен (`_is_windows()` хелпер, тест патчит хелпер вместо `os.name`); 873 тестов ✅ (2026-07-03).
10. `audit/580-analysis-2026-07-02.md` — `.gitignore` + 3 stale-docs фиксы; 873 теста, 95% покрытие; `scanner-diff` CLI подтверждён (570 ошибался) (2026-07-02).
11. `audit/570-analysis-2026-07-02.md` — чекап-only: NEW-1 `_SCA_reports/`, flaky-тест мониторить; 873 теста (2026-07-02).
12. `audit/530-analysis-2026-06-30.md` — D1–D20 все закрыты/WORKAROUND/accepted-design (D1=OPEN, нужна ротация NVD); v0.1.5, 868 тестов, 95% покрытие, GitHub синхронизирован (2026-06-30).
13. `audit/520-analysis-2026-06-29.md` — CI/CD раздел в architecture.md, RetryPolicy в таблице модулей (2026-06-29).
14. `audit/archive/` — superseded planning notes and older analysis files (≤ 490-series).
15. `../CHANGELOG.md` — release notes (Keep a Changelog).

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
