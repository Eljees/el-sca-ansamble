# Automated Fixup Report — el-sca-ansamble — 2026-05-28

## What was found

The previous automated session (2026-05-27, pass 2) applied a batch of
improvements to the project but **left 7 files truncated mid-write**. Each
file ended abruptly — some mid-string-literal, some mid-expression — with no
trailing newline. This caused:

- `atomic_publish.py` to fail Python syntax check (unterminated string literal)
- `cli.py` to be missing its final 8 lines (proxy-status exit + `__main__` guard)
- `extractor.py` to be missing the manifest write and `return` statement
- `run-scan.sh` to be missing `esac`/`fi` and the entire report-collection footer
- `run-scan.ps1` to be missing all report-collection commands
- `test_atomic_publish.py` to be missing 2 new tests
- `test_cli.py` to be missing the last assertion + 6 new dedup tests

## What was fixed

All 7 files were restored with the content the previous session intended to write,
based on the descriptions in `docs/audit/70-fixups-2026-05-27.md`.

### Changes per file

**`resilient_updates/atomic_publish.py`**
Complete EXDEV-safe staging implementation: on cross-device rename, copies
into a sibling `.staging_<name>_<pid>` directory on the destination volume,
then performs a single atomic intra-volume rename. Failed copies clean up
staging without corrupting `dst`.

**`resilient_updates/cli.py`**
- `_dedup_attempted_sources`: accumulates retry counts + outcomes per source
- `extract` command: returns `EXIT_VALIDATION_FAILED` when a file input
  produces zero extracted archives
- Restored `proxy-status` exit logic and `if __name__ == "__main__"` guard

**`resilient_updates/extractor.py`**
- When input is a file and extraction produces zero entries (and no failures),
  a synthetic failure is appended to the manifest so the caller can detect
  unsupported/plain files
- Restored `manifest_path` write and `return manifest`

**`scripts/run-scan.sh`** + **`scripts/windows/run-scan.ps1`**
- 0-PE-binary fallback: if `win-analyzer` reports 0 PE binaries, `cve-bin-tool`
  falls back to scanning the original installer file directly instead of the
  extracted directory
- Restored `esac`/`fi` block, report-collector call, HTML report generation,
  and done banner

**`tests/test_atomic_publish.py`** (2 new tests)
- `test_replace_tree_exdev_cleans_staging_on_copy_failure`: verifies that a
  failed EXDEV copy leaves no orphaned staging dirs and does not corrupt `dst`
- `test_atomic_publish_no_active_dir` (`@pytest.mark.smoke`): covers first-run
  path when `active_dir` does not yet exist

**`tests/test_cli.py`** (6 new tests)
- `test_extract_cli_fails_when_file_input_has_no_extractable_archives`
- `test_dedup_single_attempt_passthrough` (`@pytest.mark.smoke`)
- `test_dedup_retries_accumulate_count`
- `test_dedup_all_failed_source`
- `test_dedup_multiple_sources_preserve_order`
- `test_dedup_empty_input`

**`.github/workflows/ci.yml`**
Completed the `pytest` job that was truncated at `- name`. The job now has
the full install → coverage gate → upload-artifact sequence, and correctly
`needs: [smoke]`.

## Verification

```
python3 -m compileall -q resilient_updates tests  →  no errors
git diff --stat HEAD                               →  9 files, 324 insertions
```

## Action required from you

The git `index.lock` is held by a Windows git process and could not be
released from the Linux sandbox. To commit the fixes:

```bash
# (in the D:\dev\el-sca-ansamble directory)
git add -A
git commit -m "fix: restore 7 files truncated by previous automated pass"
```

## Remaining open items (unchanged)

| ID | Item |
|---|---|
| NEW-3 | Generate a real `requirements.lock` with `pip-compile --generate-hashes` |
| NEW-5 | Rotate NVD API key (was in Yandex Disk); `git rm --cached` large research files |
| NEW-6 | Run `pytest --cov` on Windows host to establish coverage baseline |
