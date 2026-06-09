# Remote analysis runbook

This is the repeatable operator path for a remote machine that needs to:

1. clone or update `el-sca-ansamble`,
2. reach upstream tools through the existing proxy/VPN setup,
3. refresh all DBs,
4. run a full scan for a target artifact,
5. verify the GUI and the generated reports.

The intended compose launch uses only:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml ...
```

Do not mix in local override files when following this runbook.

---

## 1. Inputs

- Repo: `D:\dev\el-sca-ansamble` on the working machine, or the equivalent clone on the remote host.
- Target artifacts:
  - `D:\dev\_SCA\_to_verify_logic_CYBERSEC-11531\`
  - `D:\dev\_SCA\CYBERSEC-11603\`
- Registry images:
  - `elariaphd/el-sca-resilient-updater:1.0.0`
  - `elariaphd/el-sca-extractor:1.0.0`
  - `elariaphd/el-sca-cve-bin-tool:1.0.0`
- Host proxy material:
  - v2rayN / Xray on the Windows host
  - amsterdam / tunnel config set if a VPN route is needed

The proxy material is used only to supply a working outbound route. The containers still talk to Docker through `host.docker.internal`.

---

### Transfer the artifact and record hashes

Do this on the Windows source machine before copying the artefact to the remote host:

```powershell
Set-Location D:\dev\el-sca-ansamble
$Artifact = "D:/dev/_to_verify_logic_CYBERSEC-11531/prometheus-3.11.0.linux-amd64.tar.gz"
Get-FileHash -Algorithm SHA1   $Artifact
Get-FileHash -Algorithm SHA256 $Artifact

scp "D:/dev/_to_verify_logic_CYBERSEC-11531/prometheus-3.11.0.linux-amd64.tar.gz" `
    "elaria@192.168.1.33:/opt/sca-work/_to_verify_logic_CYBERSEC-11531/"
```

On the remote host, verify the copied file before starting the run:

```bash
sha1sum   /opt/sca-work/_to_verify_logic_CYBERSEC-11531/prometheus-3.11.0.linux-amd64.tar.gz
sha256sum /opt/sca-work/_to_verify_logic_CYBERSEC-11531/prometheus-3.11.0.linux-amd64.tar.gz
```

The observed hashes must match the source machine.

---

## 2. Routing choices

Use the simplest route that works:

1. Host proxy only: set `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` to `host.docker.internal:<port>`.
2. Sidecar proxy chain: enable the `proxy` profile and let `tinyproxy -> proxy-xray` handle outbound traffic.
3. VPN sidecar: add the `vpn` profile if the mirror is only reachable inside the tunnel.

The current repo already contains the routing layers and the health commands:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm db-admin proxy-status
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm db-admin db-status trivy --path /var/lib/resilient-db/trivy --warning-age 24h
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm db-admin db-status grype --path /var/lib/resilient-db/grype/active --warning-age 24h
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm db-admin db-status cve-bin-tool --path /root/.cache/cve-bin-tool --warning-age 24h
```

---

## 3. Manual sequence

### Step 1. Prepare the repo

```bash
cd /opt/sca-work
git clone https://github.com/Eljees/el-sca-ansamble.git
cd /opt/sca-work/el-sca-ansamble
cp receiver.env.example .env
cp docker-compose.prod.example.yml docker-compose.prod.yml
```

Set the important fields in `.env`:

```bash
REGISTRY_NAMESPACE=elariaphd
IMAGE_TAG=1.0.0
SCAN_TARGET_HOST=/opt/sca-work/_to_verify_logic_CYBERSEC-11531/prometheus-3.11.0.linux-amd64.tar.gz
EXTRACT_INPUT_HOST=/opt/sca-work/_to_verify_logic_CYBERSEC-11531/prometheus-3.11.0.linux-amd64.tar.gz
SCAN_TARGET_DISPLAY=/opt/sca-work/_to_verify_logic_CYBERSEC-11531/prometheus-3.11.0.linux-amd64.tar.gz
```

If the host only has a SOCKS proxy, use `ALL_PROXY=socks5h://host.docker.internal:<port>`.
If the route is HTTP/HTTPS, set `HTTP_PROXY` and `HTTPS_PROXY` instead.

### Step 2. Render and validate compose

```bash
./scripts/preflight_compose.sh
docker compose -f docker-compose.yml -f docker-compose.prod.yml config
```

The render must not contain unresolved `${...}` or a trailing `}` in the scan target path.

### Step 3. Pull the images

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml pull
```

### Step 4. Refresh the bases

```bash
TRIVY_RENDERED_FLAGS="$(python3 -m resilient_updates.cli render-flags trivy)" \
  docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile update run --rm trivy-updater

docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile update run --rm grype-updater
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile update run --rm grype-db-importer
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile update run --rm cve-bin-tool-updater
```

What to expect:

- Trivy downloads its DB and Java DB.
- Grype downloads an active DB archive and imports it into the runtime cache.
- cve-bin-tool uses the NVD feed import or the selected fallback route from `scripts/update_cve_bin_tool.sh`.

If the cve-bin-tool updater fails on the live API route, the safe fallback order is:

1. `json-mirror`
2. `json-nvd`
3. `api2`
4. internal mirror or bundle import
5. last-known-good

The runbook keeps the DB policy explicit. `strict` is the default for CI; `degraded-ok` and `lkg-ok` are the operational fallbacks.

### Step 5. Check freshness

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm db-admin db-status trivy --path /var/lib/resilient-db/trivy --warning-age 24h
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm db-admin db-status grype --path /var/lib/resilient-db/grype/active --warning-age 24h
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm db-admin db-status cve-bin-tool --path /root/.cache/cve-bin-tool --warning-age 24h
```

If cve-bin-tool is stale but still usable, the report must say so. Do not hide that state.

### Step 6. Run the scan

```bash
./scripts/run-scan.sh -t /opt/sca-work/_to_verify_logic_CYBERSEC-11531/prometheus-3.11.0.linux-amd64.tar.gz -c --case-id CYBERSEC-11531
./scripts/run-scan.sh -t /opt/sca-work/_to_verify_logic_CYBERSEC-11603/<artifact-name> -c --case-id CYBERSEC-11603
```

The command does the full pipeline:

`artifact-extractor -> syft-sbom -> grype-scanner -> trivy-scanner -> cve-bin-tool-scanner -> report-collector`

### Step 7. Verify the GUI

Open the dashboard on the host:

```bash
python -m resilient_updates.cli dashboard --repo-root . --port 8080
```

Check that:

- the tool cards show the expected versions,
- the DB freshness labels match the update step you just ran,
- the latest run is visible,
- the final Markdown and HTML reports exist next to the target artifact.

---

## 4. Repeatable wrapper

Use the repository wrapper when you do not want to type the sequence by hand:

```bash
./scripts/remote_analysis.sh -t /opt/sca-work/_to_verify_logic_CYBERSEC-11531/prometheus-3.11.0.linux-amd64.tar.gz --case-id CYBERSEC-11531
```

It performs the same steps as the manual sequence:

1. preflight,
2. pull,
3. proxy health check,
4. DB refresh,
5. DB freshness check,
6. full scan without another update pass.

---

## 5. Failure handling

- If `proxy-status` fails, the run can still continue when the host route is direct and the DB refresh succeeds.
- If `json-mirror` hits `KeyError: 'type'`, retry with `CVE_BIN_TOOL_DISABLE_SOURCES_ON_RETRY=OSV`.
- If `json-nvd` reports `SHAMismatch`, quarantine the download and retry once before falling back.
- If no online route works, use the internal mirror, then the exported bundle, then last-known-good.
- Do not mark a failed or stale DB as fresh in the report.

---

## 6. Outputs

After a successful run, expect:

- `*_report_<date>.md`
- `*_report_<date>.html`
- `artifacts/reports/final/cve_analysis_report_generated_ru.md`
- `artifacts/provenance/*.json`
- `artifacts/sbom/syft.json`
- `artifacts/reports/{trivy,grype,cve-bin-tool}/report.json`

The final report should also carry the artifact hash and the DB freshness / policy evidence.
