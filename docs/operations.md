# Operations

Bring up the stack:

```powershell
docker compose up stack-info
docker compose --profile update up --build
docker compose --profile scan up --build
```

Linux shell:

```sh
docker compose up stack-info
docker compose --profile update up --build
docker compose --profile scan up --build
```

Validate config and health:

```powershell
python -m resilient_updates.cli validate-config
python -m resilient_updates.cli healthcheck
```

Look at provenance:

```powershell
python -m resilient_updates.cli provenance
```

Generate a combined Markdown report:

```powershell
python -m resilient_updates.cli collect-report --reports-dir artifacts --output artifacts\reports\final\cve_analysis_report_generated_ru.md
```

`Markdown` is the text report format used for the final human-readable SCA summary.

Pre-pull scanner images when registry timeouts are expected:

```powershell
docker pull anchore/syft:v1.20.0
docker pull anchore/grype:v0.82.0
docker pull aquasec/trivy:0.64.1
```

Clean generated files:

```powershell
.\scripts\windows\clean-generated.ps1
```

Offline mode depends on prewarmed caches or internal mirrors. For Grype, that means a valid active directory or a last-known-good snapshot. For cve-bin-tool, export/import artifacts should already exist.
