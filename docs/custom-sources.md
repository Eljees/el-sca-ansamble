# Custom Sources

Add personal or corporate sources in `configs/feed_sources.yaml` under `custom_sources.entries`.

Supported types in this MVP:

- `oci-registry`
- `http`
- `file`
- `git`
- `s3-compatible`

Credentials should be referenced through placeholder environment variables such as `GRYPE_CUSTOM_AUTH_TOKEN`, not embedded directly in YAML.

Use `priority` to control order. Lower numbers are tried first. Set `enabled: false` to keep a source documented but inactive.

Run:

```powershell
python -m resilient_updates.cli validate-config
python -m resilient_updates.cli healthcheck
```

Read provenance in `artifacts/provenance/` to confirm which source was selected and which ones failed.
