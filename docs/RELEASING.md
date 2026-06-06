# Releasing — pre-push checklist

Lightweight versioning so every batch of features/fixes is recorded before it
lands on GitLab. The project uses [SemVer](https://semver.org/):

- **MAJOR** — breaking change to the CLI, compose profiles, or on-disk layout.
- **MINOR** — new feature, new source/channel, new GUI capability (backward-compatible).
- **PATCH** — bug fix, doc/tooling tweak, dependency bump.

Single source of truth for the project version: **`EL_SCA_VERSION`** in
`versions.env`.

## Before every push to GitLab

1. **Update the changelog.** Add what you changed under `## [Unreleased]` in
   `CHANGELOG.md`, grouped into `### Added` / `### Changed` / `### Fixed`
   (newest dated block on top).
2. **Update docs/README** if the change is user-facing (new flag, new env var,
   new workflow). New env vars also go in `.env.example`.
3. **Bump `EL_SCA_VERSION`** in `versions.env` (MAJOR/MINOR/PATCH per above).
4. **Cut the release in the changelog:** rename `## [Unreleased]` to
   `## [X.Y.Z] - YYYY-MM-DD` and add a fresh empty `## [Unreleased]` above it.
5. **Commit** with a clear message, e.g.
   `release: vX.Y.Z — <one-line summary>`.
6. **Tag** the commit so the version is traceable in git:
   ```bash
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push gitlab master --tags
   ```

## Quick path (work-in-progress pushes)

If you're pushing intermediate work and not cutting a release, at minimum do
step 1 (add to `[Unreleased]`) so nothing is lost — bump + tag (steps 3–6) when
the batch is ready.

## Notes

- `versions.env` also pins the upstream scanner/sidecar image tags — those are
  independent of `EL_SCA_VERSION` (the repo's own version).
- The DB bundle in `bundle/` (Git LFS) is data, not code; its freshness is
  tracked by provenance timestamps, not `EL_SCA_VERSION`.
