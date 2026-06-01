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
8. `../DEPLOYMENT_GUIDE_EXAMPLE.md` — worked example of one org's full
   deployment (host-specific values — treat as a template, not canon).

## I need to review security posture

1. `../SECURITY.md` — reporting policy and threat model.
2. `security-notes.md` — DB validation, secrets handling, threat-model details.
3. `adr/0002-proxy-sidecar.md` — why the proxy stack looks the way it does.
4. `airgap.md` — what the air-gapped guarantees are.

## I need to develop / contribute

1. `../CONTRIBUTING.md` — dev environment, tests, linting, commit conventions.
2. `../README_WORKSPACE.md` — local dev-workspace layout and conventions.
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
6. `audit/100-fixups-2026-05-31.md` — latest remediation pass (start here;
   `00-overview.md` is the 2026-05-25 baseline and is partly superseded).
7. `audit/archive/` — superseded planning notes (`PLAN_2026-05-1x.md`).
8. `../CHANGELOG.md` — release notes (Keep a Changelog).
9. `status-and-roadmap.md` — historical project status (older than audit/).

## Architectural decisions

- `adr/0001-wrapper-first.md` — wrapper-first vs. fork-and-modify.
- `adr/0002-proxy-sidecar.md` — proxy sidecar chain.
- `adr/0003-vex-feed.md` — VEX feed via Trivy `--vex` (proposed).
- `adr/0004-epss-kev-freshness.md` — EPSS/KEV freshness/TTL (proposed).
- `adr/0005-unified-cli-scan.md` — unified `cli scan` orchestrator (proposed).
- `adr/0006-fastapi-dashboard.md` — read-only FastAPI run dashboard (proposed).

## Reference

- `failure-modes.md` — failure classification used by `fallback.py`.
- `reproducibility.md` — what "reproducible" means here.
- `custom-sources.md` — how to declare your own upstream sources.
