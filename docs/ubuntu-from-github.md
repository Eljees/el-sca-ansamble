# Ubuntu deploy from GitHub

This guide is for the simplest repeatable install path:

- source code comes from GitHub;
- runtime images come from Docker Hub;
- no database dumps or bundled CVE caches are shipped in the repo;
- the databases are refreshed after the clone on the target Ubuntu host.

Use this when you want a clean machine to go from zero to a working scan
stack without any offline bundle.

---

## 1. Install prerequisites

On Ubuntu 22.04/24.04:

```bash
sudo apt-get update
sudo apt-get install -y \
  ca-certificates \
  curl \
  git \
  git-lfs \
  gnupg \
  lsb-release
```

Install Docker Engine and the Compose v2 plugin:

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo apt-get install -y docker-compose-plugin
sudo usermod -aG docker "$USER"
```

Then log out and back in so the `docker` group takes effect.

Verify the tools:

```bash
docker --version
docker compose version
git --version
git lfs version
```

---

## 2. Clone the repository from GitHub

```bash
mkdir -p /opt/sca-work
cd /opt/sca-work
git clone https://github.com/Eljees/el-sca-ansamble.git
cd el-sca-ansamble
git lfs install
git lfs pull
```

If you already cloned it earlier:

```bash
cd /opt/sca-work/el-sca-ansamble
git pull --ff-only origin master
git lfs pull
```

---

## 3. Create local config

Copy the templates and fill in the absolute paths for the target you want to
scan:

```bash
cp receiver.env.example .env
cp docker-compose.prod.example.yml docker-compose.prod.yml
```

For a first scan, keep the defaults simple:

```bash
REGISTRY_NAMESPACE=elariaphd
IMAGE_TAG=1.0.0
SCAN_TARGET_HOST=/opt/sca-work/_incoming/prometheus-3.11.0.linux-amd64.tar.gz
EXTRACT_INPUT_HOST=/opt/sca-work/_incoming/prometheus-3.11.0.linux-amd64.tar.gz
SCAN_TARGET_DISPLAY=/opt/sca-work/_incoming/prometheus-3.11.0.linux-amd64.tar.gz
```

Create the target directory:

```bash
mkdir -p /opt/sca-work/_incoming
```

If you need a proxy, set it in `.env` or export it in the shell before the
`docker compose` commands. For a direct route, leave the proxy settings empty.

---

## 4. Pull the runtime images

The stack uses prebuilt images from Docker Hub:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml pull
```

Expected images:

- `elariaphd/el-sca-resilient-updater:1.0.0`
- `elariaphd/el-sca-extractor:1.0.0`
- `elariaphd/el-sca-cve-bin-tool:1.0.0`

---

## 5. Refresh databases

Run the update profile first:

```bash
export TRIVY_RENDERED_FLAGS="$(python3 -m resilient_updates.cli render-flags trivy)"
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile update run --rm trivy-updater
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile update run --rm grype-updater
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile update run --rm grype-db-importer
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile update run --rm cve-bin-tool-updater
```

Then check freshness:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm db-admin db-status trivy --path /var/lib/resilient-db/trivy --warning-age 24h
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm db-admin db-status grype --path /var/lib/resilient-db/grype/active --warning-age 24h
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm db-admin db-status cve-bin-tool --path /root/.cache/cve-bin-tool --warning-age 24h
```

If `cve-bin-tool` cannot reach the live NVD path, the updater falls back
through the configured mirror and last-known-good flow. That is expected and
should be recorded in the report.

---

## 6. Run the scan

```bash
./scripts/run-scan.sh -t /opt/sca-work/_incoming/prometheus-3.11.0.linux-amd64.tar.gz -c --case-id CYBERSEC-11531
```

For a different artifact, replace the path and case id. The run creates:

- `*_report_<DATE>.md`
- `*_report_<DATE>.html`
- raw JSON evidence under `artifacts/`

---

## 7. Read the results

Open the Markdown report next to the artifact first. Then inspect:

- `artifacts/reports/final/`
- `artifacts/reports/trivy/`
- `artifacts/reports/grype/`
- `artifacts/reports/cve-bin-tool/`

If the scan ends with zero findings, check whether the artifact was actually
extracted and whether the DB freshness banner showed fresh databases.

---

## 8. What is intentionally not shipped

This GitHub-only install path does **not** include:

- bundled NVD feeds;
- prewarmed cache volumes;
- Grype or Trivy DB snapshots;
- any other generated scan evidence.

Those are refreshed on the Ubuntu host after the clone. That keeps the
repository small and makes the deployment repeatable.
