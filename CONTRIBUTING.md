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
make test                       # full pytest with coverage
pytest -q tests/test_io.py      # one file
pytest -m "not smoke"           # skip integration tests
pytest -m smoke                 # only integration
```

CI enforces `--cov-fail-under=75`.  Add tests for any new module.

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
3. Mark integration tests with `@pytest.mark.smoke`.
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

## Reporting bugs / security issues

- Bugs: open an issue with reproduction steps and logs.
- Security: see `SECURITY.md` — do not file public issues for security.
