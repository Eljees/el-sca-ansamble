# commit-fixes.ps1
# Commits all SCA pipeline fixes from the remediation + proxy sessions.
# Run once from the repo root or from any directory:
#   .\scripts\windows\commit-fixes.ps1

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $repoRoot
Write-Host "[commit] Repo root: $repoRoot"

# ------------------------------------------------------------------
# 1. Remove stale index.lock if present (left by interrupted git op)
# ------------------------------------------------------------------
$lockFile = Join-Path $repoRoot ".git\index.lock"
if (Test-Path $lockFile) {
    Remove-Item $lockFile -Force
    Write-Host "[commit] Removed stale .git/index.lock"
}

# ------------------------------------------------------------------
# 2. Stop tracking comands.txt (contains credentials; now in .gitignore)
# ------------------------------------------------------------------
$gitIgnore = Get-Content (Join-Path $repoRoot ".gitignore") -Raw
if ($gitIgnore -match "comands\.txt") {
    $tracked = git ls-files --error-unmatch comands.txt 2>$null
    if ($LASTEXITCODE -eq 0) {
        git rm --cached comands.txt
        Write-Host "[commit] Untracked comands.txt (credentials)"
    }
} else {
    Write-Warning "comands.txt not found in .gitignore — skipping git rm --cached"
}

# ------------------------------------------------------------------
# 3. Stage all fixes (pipeline hardening + proxy support + docs)
# ------------------------------------------------------------------
git add `
    .env.example `
    configs/feed_sources.yaml `
    docker-compose.yml `
    requirements.txt `
    resilient_updates/cli.py `
    resilient_updates/config.py `
    resilient_updates/fallback.py `
    resilient_updates/healthcheck.py `
    resilient_updates/reporting.py `
    tests/test_proxy.py `
    tests/test_fallback_order.py `
    tests/test_reporting.py `
    scripts/scan_archive.sh `
    scripts/update_cve_bin_tool.sh `
    scripts/windows/commit-fixes.ps1 `
    docs/architecture.md `
    docs/distribution.md `
    docs/failure-modes.md `
    docs/operations.md `
    docs/proxy.md `
    docs/status-and-roadmap.md `
    README.md

Write-Host "[commit] Staged files:"
git diff --cached --stat

# ------------------------------------------------------------------
# 4. Commit
# ------------------------------------------------------------------
$commitMsg = @"
fix: harden extract->scan pipeline, add proxy support, update docs

Pipeline hardening:
- fallback.py: classify OCI InvalidSchema as non-retryable; add to
  _NON_RETRYABLE_REASONS so retries are skipped for unsupported protocols
- cli.py: deduplicate attempted_sources in provenance output; retries
  were creating duplicate entries per source
- reporting.py: use Path.resolve() for reports_dir; fix provenance glob
  to work regardless of CWD; emit actionable warning when syft returns
  0 components (extraction not run)
- scripts/scan_archive.sh: Linux equivalent of run-scan.ps1 -Extract;
  wires SCAN_TARGET_HOST, SYFT_FROM=dir, CVE_BIN_TOOL_TARGET, TRIVY_TARGET
  so scanners operate on unpacked archive contents

Proxy support (SOCKS5/HTTP, no hardcoding):
- requirements.txt: add PySocks>=1.7.1 for socks5h:// scheme support
- fallback.py: build_session() reads ALL_PROXY env var (requests ignores
  it natively) and explicit proxy dict from config
- config.py: parse_proxy_config(), validate_proxy_config() — validates
  schemes against allowlist, wired into validate_config_data
- healthcheck.py: pass proxy session to attempt_sources (was bypassed)
- cli.py: create session from config proxy section, pass through all
  HTTP calls (health check, update, download)
- configs/feed_sources.yaml: proxy: section with http/https/no_proxy
- docker-compose.yml: x-proxy-env YAML anchor applied to all services
  that need external network; extra_hosts: host.docker.internal:host-
  gateway so containers can reach host-side SOCKS5 proxy
- .env.example: proxy vars + CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS documented

cve-bin-tool performance (Windows Docker Desktop bind mount):
- scripts/update_cve_bin_tool.sh: timeout wrapper (default 600s);
  local copy of scan target to /tmp/cbt-scan-local (container tmpfs)
  before scanning — avoids WSL2/virtio bind mount 10-100x I/O penalty

Documentation:
- docs/proxy.md: new — full human-readable proxy guide (why, how,
  env vars, schemes, diagnostics, network flow)
- docs/architecture.md: rewritten — component tables, data flow,
  compose profiles, fault tolerance, proxy section
- docs/status-and-roadmap.md: new — phase 1 completed, known defects,
  phase 2 plan
- docs/failure-modes.md: add 5 new rows (OCI invalid schema, syft 0
  components, cve-bin-tool timeout, InsufficientArgs, attempted_sources
  duplicates)
- docs/operations.md: add extract->scan section, proxy config section
- README.md: proxy guide link, cve-bin-tool hang explanation, extract
  warning, commit-fixes.ps1 reference

- .gitignore: stop tracking comands.txt (NVD API credentials); add --exps/
"@

git commit -m $commitMsg
Write-Host "`n[commit] Done. Run 'git log --oneline -3' to verify."
