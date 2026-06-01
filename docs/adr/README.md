# Architecture Decision Records

Each ADR captures one important decision and the reasoning behind it.
Format follows the Michael Nygard template loosely: Context, Decision,
Status, Consequences.

| # | Title | Status |
|---|---|---|
| [0001](0001-wrapper-first.md) | Wrapper-first orchestration (no upstream forks) | accepted |
| [0002](0002-proxy-sidecar.md) | Sidecar proxy chain (tinyproxy + xray) | accepted |
| [0003](0003-vex-feed.md) | VEX feed — suppress findings via Trivy `--vex` | proposed |
| [0004](0004-epss-kev-freshness.md) | EPSS/KEV freshness (TTL) for enrichment | proposed |
| [0005](0005-unified-cli-scan.md) | Unified `cli scan` — cross-platform pipeline orchestrator | proposed |
| [0006](0006-fastapi-dashboard.md) | FastAPI dashboard — read-only live run browser | proposed |

When you add an ADR:

- Number it sequentially (`0003-…`, `0004-…`).
- Reference it from `docs/INDEX.md` and update this table.
- Cross-link from the affected modules' docstrings where helpful.
