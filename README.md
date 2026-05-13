# Resilient Scanner Stack

This repository contains a wrapper-first container stack for `Trivy`, `Grype`, `Syft`, and `cve-bin-tool`.

## Quick start

```powershell
docker compose config
docker compose up stack-info
python -m resilient_updates.cli validate-config
docker compose --profile update up --build
docker compose --profile scan up --build
```

Linux shell works too:

```sh
docker compose config
python -m resilient_updates.cli validate-config
./scripts/smoke_test.sh
```

Generate a combined Russian Markdown report:

```powershell
python -m resilient_updates.cli collect-report --reports-dir artifacts --target D:\path\to\target --output artifacts\reports\final\cve_analysis_report_generated_ru.md
```

For the CYBERSEC-11531 Prometheus directory:

```powershell
.\scripts\windows\run-scan.ps1 -Target "D:\!ya_drive_sync\YandexDisk\rostel\to_analyze\_to_verify_logic_CYBERSEC-11531\test\prometheus-3.11.0.linux-amd64.tar.gz_extracted\prometheus-3.11.0.linux-amd64\prometheus-3.11.0.linux-amd64" -ReportOutput "D:\!ya_drive_sync\YandexDisk\rostel\to_analyze\_to_verify_logic_CYBERSEC-11531\test\cve_analysis_report_2026-05-13_ru.generated.md"
```

## Requirements

- Docker with `docker compose`
- Python 3.12+
- Network access for online update stages, unless you prepared internal mirrors or last-known-good data

## Compose profiles

- `default`: common services
- `update`: updater services only
- `scan`: scanner and SBOM services
- `test-failover`: mock-feed-server plus updater validation
- `report`: final Markdown report collector
- `offline`: services intended for prewarmed caches and internal mirrors

`stack-info` is the unprofiled validation service, so plain `docker compose config` and `docker compose up stack-info` are meaningful even before choosing an update or scan profile.

If Docker Hub is unavailable or slow, pre-pull required images before scan:

```powershell
docker pull anchore/syft:v1.20.0
docker pull anchore/grype:v0.82.0
docker pull aquasec/trivy:0.64.1
```

Clean generated local caches before packaging:

```powershell
.\scripts\windows\clean-generated.ps1
.\scripts\windows\pack-artifacts.ps1
```

## Configuration overview

Central source policy lives in [feed_sources.yaml](/D:/!ya_drive_sync/YandexDisk/rostel/el-sca-ansamble/configs/feed_sources.yaml). It controls Trivy repositories, Grype mirror inputs, cve-bin-tool mirrors, Syft source policy, and user custom sources.

## Artifacts layout

- `artifacts/reports/`: tool reports
- `artifacts/provenance/`: machine-readable provenance JSON
- `artifacts/sbom/`: Syft output
- `artifacts/internal/grype/`: active, previous, and temp Grype mirror state
- `artifacts/mirror/`: exported mirror bundles

## Security notes

Production mode should use pinned image versions, digest verification, checksum or signature validation, and controlled internal mirrors. Real secrets must stay in `.env` or other secret stores, never in YAML checked into source control.

## Known limitations

- Grype direct compatibility with every upstream listing variant is best-effort in this MVP.
- `cve-bin-tool` uses a wrapper-first flow and does not patch upstream source handling.
- `Syft` is intentionally stateless and does not pretend to own a vulnerability DB.
- Direct Compose scans require scanner images to be locally available or pullable from registries.

## Roadmap

- Phase 1: wrapper and no-fork MVP
- Phase 2: source health dashboard
- Phase 3: optional code-level patches
- Phase 4: CI/CD integration

## Troubleshooting

- DB update failed: inspect `artifacts/provenance/*.json`
- No network: switch to internal mirrors or last-known-good artifacts
- Stale DB: adjust update policy or refresh the mirror
- Grype validation failed: confirm checksum and archive integrity
- Trivy repository unavailable: verify repository order in `feed_sources.yaml`
- Syft registry auth failed: provide registry credentials through environment variables
- cve-bin-tool offline bundle missing: export on an online node first
