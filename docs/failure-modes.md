# Failure Modes

| Failure mode | Tool | Expected behavior | Fallback path | Fail closed condition | Provenance field |
|---|---|---|---|---|---|
| timeout | Trivy, Grype, cve-bin-tool | retry then move to next source | next configured source or last-known-good | no valid source and no valid last-known-good | `failures[].reason` |
| HTTP 429 | Trivy, Grype, cve-bin-tool | retryable transient failure | next source after retry budget | all sources exhausted | `failures[].status_code` |
| HTTP 5xx | Trivy, Grype, cve-bin-tool | retryable transient failure | next source after retry budget | all sources exhausted | `failures[].status_code` |
| HTTP 404 | Grype, cve-bin-tool | treat as non-retryable for current source | next source if configured | no alternate source | `failures[].reason` |
| corrupt DB | Grype | reject artifact | last-known-good | no valid last-known-good | `activation_status` |
| stale DB | Grype | reject stale artifact | last-known-good if policy allows | stale plus no valid last-known-good | `freshness_metadata` |
| no network | Trivy, Grype, cve-bin-tool | rely on internal mirrors or caches | last-known-good or offline mode | no mirror, no cache, no last-known-good | `used_last_known_good` |
| missing cache | Trivy, Syft | honest failure in offline scan | rerun update stage online | no online path and no internal mirror | `activation_status` |
| invalid config | all | stop early | fix config | any required section missing or unsafe value detected | top-level CLI output |
| auth failure | all remote tools | mark source failed | next source with valid credentials | every source requires unavailable auth | `failures[].reason` |
| OCI protocol not supported | Trivy healthcheck (Python wrapper) | mark source failed immediately without retry | next OCI source in priority order | all OCI sources fail (`selected_source: null`) — Trivy runs with stale/missing DB | `failures[].reason = invalid_schema` |
| syft 0 components | Syft | scan completes but SBOM is empty | none — Grype will also return 0 matches | report shows Consistency warning; run `scan_archive.sh` or `run-scan.ps1 -Extract` | Consistency warnings section in report |
| cve-bin-tool no target | cve-bin-tool | tool exits with `InsufficientArgs`; no report.json produced | `collect_reports.sh` creates empty `[]` placeholder | finding gap: real CVEs missed silently | `host-update.log` shows InsufficientArgs |
| cve-bin-tool scan timeout | cve-bin-tool | scan exceeds `CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS` (default 3600s); `timeout` exits 124 | empty `[]` report written; pipeline continues | missed CVEs from binary scan / SBOM lookup — no longer silent: surfaces as `tool_failures: ['cve-bin-tool']` | `[cve-bin-tool] WARN: scan timed out` in container log; `timeout.flag` in the report dir |
| cve-bin-tool wedged on big Go binary | cve-bin-tool (binary scan path) | regex backtracking in `python`/`php`/`perl` regular checkers hangs for 10–30 min on large Go/JVM monoliths | auto-SBOM uses cyclonedx/spdx (DB lookup, seconds); for pure-Go fallbacks the regular-checker list is pruned to `{go,rust}` | both SBOM missing AND wall-clock timeout (124) | `[cve-bin-tool] auto-detect: go_binaries=N native_so=0` + `[cve-bin-tool] → pure Go target: regular checkers limited to {go,rust}` |
| cve-bin-tool rejects --sbom syft | cve-bin-tool 3.4 | `--sbom` accepts only `cyclonedx`/`spdx`/`swid`; passing `syft` fails with `unrecognized argument` | auto-SBOM skips `syft.json` and uses `cyclonedx.json` or `spdx.json` produced by the same syft-sbom run | both cyclonedx.json and spdx.json missing | `[cve-bin-tool] auto-SBOM: found …cyclonedx.json (format=cyclonedx)` |
| cve-bin-tool excluded oversize binary | cve-bin-tool | files larger than `CVE_BIN_TOOL_MAX_FILE_MB` (default 256 MB) are skipped via `-e EXCLUDE` to bound runtime | report continues; excluded paths logged to `artifacts/reports/cve-bin-tool/excluded.flag` | excluded file actually contained a vulnerable component | `[cve-bin-tool] excluding N file(s) larger than 256 MB` + `excluded.flag` content |
| extractor not run before scan | artifact-extractor | scanners operate on raw archive/dir without unpacking | run `scan_archive.sh` / `run-scan.ps1 -Extract` to trigger extractor first | 0 findings for archive targets (tar.gz, rpm, deb) | Consistency warnings: syft 0 components |
| attempted_sources duplicates | Grype, Trivy provenance | each retry creates a duplicate entry (cosmetic only) | deduplicated automatically since fix in v2 | none — cosmetic issue only | `attempted_sources[]` |

## Development-environment quirks (not pipeline failures)

These bite during development/automation around the pipeline, not during scans
themselves. Documented after the 2026-06-05 debugging session.

| Quirk | Symptom | Workaround |
|---|---|---|
| Bare `python` on host is a broken/permission-denied shim (some WSL setups) | render-flags/collect-report silently skipped or whole pipeline aborts; `[Errno 13] Permission denied: 'python'` | run-scan.sh auto-detects `PYTHON_BIN` (python3 first); MCP server uses `sys.executable`; export `PYTHON_BIN` to override |
| `set -e` + bare `docker compose` inside helper functions | script dies on first non-zero exit before the helper can whitelist it (cve-bin-tool exits 1 on findings!) | helpers use `rc=0; docker compose "$@" \|\| rc=$?` — keep this pattern for new helpers |
| MCP `run_scan` client timeout (−32001) on long scans | client request drops at ~60 s while the host pipeline keeps running (server-side budget 3600 s) | watch `artifacts/run-scan.log`; treat −32001 as "started, still running", not as failure |
| Cowork/agent FUSE mount serves stale copies of freshly edited files | `py_compile`/`pytest` in the sandbox report bogus SyntaxError or test old code | ground truth = direct host file reads / an actual host run; never trust sandbox compile results for files edited seconds ago |
| Extracted tree under `artifacts/extracted/` is root-owned | host-side `rm -rf` fails with EACCES | the extractor purges `current/` itself in-container; use `make clean` (container paths) or PowerShell on Windows for manual cleanup |
