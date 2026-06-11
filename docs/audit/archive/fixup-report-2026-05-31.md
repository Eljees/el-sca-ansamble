# Fixups audit — 2026-05-31 (automated pass)

> Automated analysis + one targeted fix on top of
> `docs/audit/90-fixups-2026-05-30.md`.

---

## 0. State at start of pass

| Check | Result |
|---|---|
| `git log --oneline -1` | `e1fac23 docs: add audit/90-fixups-2026-05-30.md` |
| `ruff check .` | **0 errors** ✅ |
| `pytest -q` | **242 passed, 0 failed** ✅ |
| Stale git lock files | Still present (`.git/index.lock`, `.git/HEAD.lock`, etc.) — user action required |

---

## 1. Findings

### 1.1 `healthcheck.py` — retry config not routed through `RetryPolicy` (P3, **FIXED**)

`healthcheck.run_healthcheck` contained three separate copies of retry
configuration that should come from `RetryPolicy` (introduced in
`docs/audit/10-defects.md §10` and implemented in `resilient_updates/_retry.py`):

| Section | Problem |
|---|---|
| Trivy | Manually read `config["trivy"]["retry_backoff_policy"]` dict keys inline — duplicating `RetryPolicy.from_tool_config` |
| Grype | Hardcoded `retry_count=1, backoff_seconds=1` — `cli.update_grype` already uses `RetryPolicy.from_tool_config(config, "grype")` |
| cve-bin-tool | Hardcoded `backoff_seconds=1` and a module-level mutable `_DEFAULT_RETRY_STATUS_CODES` list duplicating `RetryPolicy` defaults |

**Fix applied:** `healthcheck.py` now imports `RetryPolicy` from `._retry`
and uses `RetryPolicy.from_tool_config(config, tool)` for each section.
Timeout values that live in separate YAML keys (`source_health_policy.
healthcheck_timeout_seconds`, `timeout_policy.update_available_timeout`)
continue to be read from their respective keys — only the
retry/backoff/status-code parameters are delegated to `RetryPolicy`.
The module-level `_DEFAULT_RETRY_STATUS_CODES` list is removed.

Behaviour is identical to before (the RetryPolicy reads the same YAML values
for trivy and grype; for cve_bin_tool where `retry_backoff_policy` is absent
it returns the same defaults that were previously hardcoded).

### 1.2 `cli.py` `update` subcommand — manual dict reads (P3, identified, not fixed)

Lines 685–698 of `cli.py` (`update trivy` and `update cve_bin_tool` paths)
still read `config["trivy"]["retry_backoff_policy"]` keys manually and hardcode
`backoff_seconds=1` for cve_bin_tool. These are the same patterns just fixed
in `healthcheck.py`.

No behaviour difference; the values read are identical to what `RetryPolicy`
would return. Deferring because this path is exercised by integration tests
only (requires docker) and is low risk.

**Recommended fix:**
```python
# cli.py update-trivy path (~line 685)
trivy_retry = RetryPolicy.from_tool_config(config, "trivy")
code, payload = _health_summary(
    config, "trivy", "trivy-db",
    timeout=int(config["trivy"]["source_health_policy"]["healthcheck_timeout_seconds"]),
    retry_count=trivy_retry.retry_count,
    backoff_seconds=int(trivy_retry.backoff_seconds),
    retry_codes=list(trivy_retry.retry_status_codes),
    session=_session,
)

# cli.py update-cve_bin_tool path (~line 693)
cve_retry = RetryPolicy.from_tool_config(config, "cve_bin_tool")
...
backoff_seconds=int(cve_retry.backoff_seconds),
retry_codes=list(cve_retry.retry_status_codes),
```

### 1.3 `healthcheck.py` missing `trivy-vex` layer probe (P4, identified)

`source_policy.build_sources` maps `"trivy-vex"` → `vex_repositories` and
`configs/feed_sources.yaml` has a `vex_repositories` section, but
`run_healthcheck` only probes `("trivy-db", "trivy-java-db", "trivy-checks")`.
Adding `"trivy-vex"` to the loop is a one-line change.

### 1.4 Coverage gate still unvalidated (NEW-6, P1, carry-forward)

`--cov-fail-under=75` in CI but coverage has never been measured on the host.
From the Linux sandbox `pytest-cov` raises `PermissionError` when trying to
clean up parallel `.coverage.*` temp files on the NTFS mount, so measurement
is not possible here.

**Action required:** on the Windows host, run once:
```powershell
pip install pytest-cov
pytest --cov=resilient_updates --cov-report=term-missing --cov-fail-under=75
```
If the gate fails, add targeted tests for uncovered branches before the
next CI run.

### 1.5 `requirements.lock` placeholder (NEW-3, P1, carry-forward)

`requirements.lock` is still a placeholder with no pinned hashes. Supply-chain
risk: a compromised upstream package could be silently pulled in.

**Action required:** on a host with PyPI access:
```bash
pip install pip-tools
make lock   # or: pip-compile --strip-extras --generate-hashes requirements.in -o requirements.lock
```

### 1.6 Stale git lock files (P1, carry-forward)

Four lock files prevent normal `git add`/`git commit` on the Windows host:

```
.git/index.lock
.git/HEAD.lock
.git/next-index-7.lock
.git/objects/maintenance.lock
```

**Action required (Windows host, safe if no git process is running):**
```powershell
Remove-Item .git\index.lock, .git\HEAD.lock, .git\next-index-7.lock, .git\objects\maintenance.lock -Force
```

### 1.7 NVD API key rotation (NEW-5, P0/security, carry-forward)

`.env.local` contains live NVD API key(s). Recommended:
1. Rotate keys at nvd.nist.gov.
2. Remove tracked binary blobs from git history with `git filter-repo`.

---

## 2. Fix applied this pass

| File | Change |
|---|---|
| `resilient_updates/healthcheck.py` | Import `RetryPolicy`; replace manual dict reads + hardcoded values with `RetryPolicy.from_tool_config`; remove `_DEFAULT_RETRY_STATUS_CODES` |

---

## 3. State at end of pass

| Check | Result |
|---|---|
| `ruff check .` | **0 errors** ✅ |
| `pytest -q` | **242 passed, 0 failed** ✅ |
| `healthcheck.py` uses `RetryPolicy` | ✅ |

---

## 4. Prioritised fix queue

| ID | Sev | Summary | Owner |
|---|---|---|---|
| NEW-5 | P0/sec | Rotate NVD API keys; clean git history | User |
| stale-locks | P1 | Delete `.git/*.lock` files on Windows host | User |
| NEW-3 | P1 | Generate real `requirements.lock` with hashes | User |
| NEW-6 | P1 | Validate `--cov-fail-under=75` on host | User |
| §1.2 | P3 | Migrate `cli.py` `update` paths to `RetryPolicy` | Automated |
| §1.3 | P4 | Add `trivy-vex` to `run_healthcheck` probe loop | Automated |

---

**See also:** [90-fixups-2026-05-30.md](90-fixups-2026-05-30.md) · [10-defects.md](10-defects.md) · [20-architecture.md](20-architecture.md)
