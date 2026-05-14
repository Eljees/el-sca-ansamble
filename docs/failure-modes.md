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
| extractor not run before scan | artifact-extractor | scanners operate on raw archive/dir without unpacking | run `scan_archive.sh` / `run-scan.ps1 -Extract` to trigger extractor first | 0 findings for archive targets (tar.gz, rpm, deb) | Consistency warnings: syft 0 components |
| attempted_sources duplicates | Grype, Trivy provenance | each retry creates a duplicate entry (cosmetic only) | deduplicated automatically since fix in v2 | none — cosmetic issue only | `attempted_sources[]` |
