# Contributing to el-sca-ansamble

Quick guide for developers and contributors.  See `docs/INDEX.md` for the
full document map.

## Development environment

Required:

- Python 3.12+
- Docker + docker compose v2
- `pip-tools` (for lockfile regeneration: `pip install pip-tools`)
- `pre-commit` (`pip install pre-commit`)
- `ruff`, `yamllint`, `hadolint`, `shellcheck` for local linting

Bootstrap:

```sh
git clone https://github.com/Eljees/el-sca-ansamble.git
cd el-sca-ansamble
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pip install "pytest>=8" "pytest-cov>=5" pip-tools pre-commit
make hooks    # installs pre-commit + pre-push hooks
```

## Running tests

```sh
make test                          # full pytest with coverage (gate: 88%)
pytest -q tests/test_io.py         # one file
pytest -m smoke                    # only smoke (fast critical-path sanity)
pytest -m "not integration"        # exclude Docker/compose/network tests
pytest -m integration              # only Docker/compose/network tests
```

CI enforces `--cov-fail-under=88`.  Add tests for any new module.

## Linting

```sh
make lint           # all linters at once
make lint-py        # ruff
make lint-sh        # shellcheck
make lint-docker    # hadolint
make lint-yaml      # yamllint
pre-commit run --all-files
```

## Adding a new dependency

`requirements.in` is the human-curated source of truth.  `requirements.txt`
is the generated lockfile.  Pin loosely in `.in`, regenerate the lock:

```sh
make lock
```

Commit both files together.

## Adding a new test

1. File name: `tests/test_<module>.py`.
2. Function name: `test_<what_is_being_verified>`.
3. Mark slow Docker/network tests with `@pytest.mark.integration`; fast
   critical-path sanity tests with `@pytest.mark.smoke`.
4. Prefer `tmp_path` fixture for filesystem tests over manual cleanup.

## Adding a new shell script

1. Linux scripts go under `scripts/`, Windows mirrors under `scripts/windows/`.
2. Naming: `something-action.sh` (dash) for full pipelines, `something_action.sh`
   (underscore) for native per-tool runners.
3. Add an entry to `scripts/README.md`.
4. Set `#!/usr/bin/env sh` and `set -eu` at the top.
5. Run `make lint-sh` before committing.

## Adding a new Dockerfile

1. Name: `Dockerfile.<role>`.
2. Add to `lint-docker` matrix in `.github/workflows/ci.yml`.
3. Add to `docker-build` matrix in the same file.
4. Use `# syntax=docker/dockerfile:1.7` and BuildKit cache mounts.
5. For non-root images: `RUN useradd -m -u 1000 scanner && USER scanner`.

## Commit conventions

We follow Conventional Commits loosely:

- `feat: …`        new user-visible feature
- `fix: …`         bug fix
- `refactor: …`    no behavior change
- `docs: …`        documentation only
- `chore: …`       tooling / CI

Keep commit messages short; details belong in PR description and the
`CHANGELOG.md` Unreleased section.

## Pull request checklist

- [ ] `pre-commit run --all-files` passes
- [ ] `make test` passes with no coverage regression
- [ ] `CHANGELOG.md` updated in Unreleased section
- [ ] Public API changes reflected in `docs/architecture.md`
- [ ] New CLI subcommands documented there too

## Known dev-environment gotchas

### FUSE / cloud-sync stale `.pyc` (Windows + YandexDisk / OneDrive)

If you work from a folder mounted through a FUSE driver (e.g. YandexDisk,
OneDrive, or any cloud-sync FUSE bridge) you may see tests pass in your IDE
but silently load **stale bytecode** in the terminal, producing confusing
failures or wrong coverage numbers.

Root cause: FUSE mounts often do not propagate `mtime` updates for writes
made through the Windows host side.  Python's import machinery compares
`mtime` of the `.py` source against the cached `.pyc` in `__pycache__/`;
if the FUSE layer reports an unchanged `mtime`, Python loads the old `.pyc`
even though the source was just edited.

**Workaround options (pick one):**

1. **Work directly from the non-synced path** — clone or copy the repo to a
   local (non-synced) directory like `D:\dev\el-sca-ansamble` and run tests
   from there.  Symlink or manually copy files to the sync folder only when
   you want to push.

2. **Delete `__pycache__` before running tests** — forces a full recompile:
   ```sh
   find . -type d -name __pycache__ | xargs rm -rf
   pytest -q ...
   ```

3. **Use Desktop Commander or a native shell** for `git` and `pytest` calls
   instead of a sandboxed bash session that reads files through the FUSE
   mount.  The native shell sees real `mtime` values.

This limitation does **not** affect CI (GitHub Actions / GitLab CI always
clone to a local runner disk).

## Reporting bugs / security issues

- Bugs: open an issue with reproduction steps and logs.
- Security: see `SECURITY.md` — do not file public issues for security.
