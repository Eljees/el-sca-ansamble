# Architecture

This stack separates updater containers from scanner containers so that database acquisition, validation, and activation happen before any scan consumes the data.

`Trivy` stays close to upstream behavior. We use native repository flags, shared cache volumes, and optional offline flags instead of rewriting Trivy database logic.

`Grype` receives one stable internal endpoint. The wrapper module fans out across candidate upstream sources, validates the selected archive, writes provenance, and only then activates a new local mirror snapshot.

`Syft` is treated as a stateless SBOM generator. Resilience for Syft means explicit source selection and credential handling, not vulnerability database mirroring.

`cve-bin-tool` follows a wrapper-first pipeline. Update, export, import, and scan are split into separate stages, with room for future code-level changes only if the wrapper proves insufficient.
