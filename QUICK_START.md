# SCA Pipeline - Quick Start (v3.0)

**TL;DR - Get scanning in 5 minutes**

---

## 🚀 From a fresh clone (any OS, pure Docker Compose)

Nothing host-specific required — only Docker with Compose v2. After `git clone`
(or `git pull`) the pipeline runs in two commands once `.env` is set up:

```bash
# 1. One-time setup: create your local config from the template
cp .env.example .env
#    then edit .env and set SCAN_TARGET_HOST to the absolute path of the
#    archive or directory you want to scan, e.g.
#       SCAN_TARGET_HOST=/data/myapp-1.0.0.tar.gz
#    (set a proxy under "Proxy settings" only if your host needs one;
#     by default the connection is direct)

# 2. One-time: pull the CVE databases (Trivy / Grype / cve-bin-tool)
docker compose --profile update up --abort-on-container-exit

# 3. Run a scan (extract → SBOM → Grype → Trivy → cve-bin-tool → report)
docker compose --profile scan up --abort-on-container-exit
```

Reports land in `artifacts/reports/` (per-tool JSON) and
`artifacts/reports/final/` (aggregated `cve_analysis_report_generated_ru.md`
+ `index.html`). Re-run step 3 for each new target; re-run step 2 to refresh
the databases.

Useful variants:

```bash
docker compose --profile report run --rm report-collector   # re-aggregate only
docker compose down -v                                       # stop + drop DB volumes
```

Notes for a clean machine:

- Images either pull from public registries (`ghcr.io`, `aquasec`,
  `python:3.12-slim`) or build locally from the `Dockerfile.*` in the repo —
  the first `update`/`scan` run does this automatically.
- No secrets are needed for the default `json-mirror` DB route. An NVD API key
  (if you add one) goes in `.env.local`, never in `.env` or git.
- On Windows, `SCAN_TARGET_HOST` may be a Windows path (e.g. `C:\data\app.tar.gz`).

To ship the project to GitLab/Docker **with the current databases bundled**, and
to deploy it elsewhere ready for a first scan, see
[`docs/SHIP_AND_DEPLOY.md`](docs/SHIP_AND_DEPLOY.md).

---

## ⚡ In One Command (Windows)

```powershell
# Terminal 1: Start proxy tunnel
ssh -R 10808:127.0.0.1:10808 elaria@192.168.1.33 -N

# Terminal 2: Run scan
cd "D:\!ya_drive_sync\YandexDisk\rostel\el-sca-ansamble"
.\scripts\windows\run-scan.ps1 -Target "C:\path\to\archive.tar.gz" -Extract -Clean
```

That's it. Reports will be saved next to your archive file.

---

## 📋 Essential Checklist

Before you run:
```
✓ SSH tunnel running (Terminal 1)
✓ X-Ray proxy active (port 10808)
✓ Ubuntu has 8GB+ free disk
✓ Target file exists and is readable
✓ Using production location (D:\!ya_drive_sync\..., not D:\dev\)
```

---

## 🎯 Common Tasks

### Full Scan with Extraction
```powershell
.\scripts\windows\run-scan.ps1 -Target "archive.tar.gz" -Extract -Clean
```

### Just Run Grype
```powershell
.\scripts\windows\run-scan.ps1 -Target "archive.tar.gz" -Tool grype
```

### Update Databases First
```powershell
.\scripts\windows\run-scan.ps1 -Target "archive.tar.gz" -UpdateDb
```

### Run in Background
```powershell
$job = Start-Job { 
  cd "D:\!ya_drive_sync\YandexDisk\rostel\el-sca-ansamble"
  .\scripts\windows\run-scan.ps1 -Target "archive.tar.gz" -Clean 
}
# Check progress
Get-Job $job | Receive-Job -Keep
# Get results when done
Receive-Job $job -Wait -AutoRemoveJob
```

---

## 📊 What You Get

After scan completes, you'll have:

```
archive_report_2026-05-26.md      ← Read this first
archive_report_2026-05-26.html    ← Open in browser
artifacts/sbom/syft.json
artifacts/reports/trivy/report.json
artifacts/reports/grype/report.json
artifacts/reports/cve-bin-tool/report.json
```

---

## ⚠️ Important Notes

1. **SSH tunnel MUST stay open** during entire scan
2. **Always use `-Clean`** between scans to free disk space
3. **Reports saved next to archive** on Windows (not in Docker folder)
4. **CVE-bin-tool exit code 1 is NORMAL** (means CVEs found) — v3.0 handles this
5. **Monitor disk:** Ubuntu has only 20GB total

---

## 🚨 When Things Go Wrong

| Problem | Solution |
|---------|----------|
| "Connection refused" | Verify SSH tunnel running in Terminal 1 |
| "proxy: SOCKS" error | Check X-Ray on port 10808 is active |
| "Disk full" | Use `-Clean` flag, or `rm -rf artifacts/*` on Ubuntu |
| Script exits with error | Check CVE-bin-tool logs: `docker logs <container>` |
| No internet in containers | Restart Docker: `sudo systemctl restart docker` on Ubuntu |

---

## 📁 File Locations

| Purpose | Path |
|---------|------|
| **Use this for scanning** | `D:\!ya_drive_sync\YandexDisk\rostel\el-sca-ansamble` |
| Research workspace | `D:\dev\el-sca-ansamble` |
| Full docs | `DEPLOYMENT_GUIDE_EXAMPLE.md` |
| Changelog | `CHANGELOG.md` |

---

## 🔑 Key Commands (Ubuntu)

```bash
# Check status
docker-compose ps

# View logs
docker-compose logs -f cve-bin-tool-scanner

# Check disk
df -h /opt/sca-work

# View latest report
cat artifacts/reports/final/cve_analysis_report_ru.md | head -100

# Clean up
docker-compose down
rm -rf artifacts/*
```

---

## ⏱️ Typical Timeline

| Stage | Duration |
|-------|----------|
| Extraction | 2-5 min |
| SBOM (Syft) | 2-5 min |
| Trivy scan | 2-5 min |
| Grype scan | 2-5 min |
| CVE-bin-tool | 5-15 min |
| Report generation | 1-2 min |
| **TOTAL** | **15-40 min** |

---

## 💾 Example Full Command

```powershell
# Scan a 995MB archive, extract, clean before
.\scripts\windows\run-scan.ps1 `
  -Target "C:\Downloads\prometheus-3.11.0.linux-amd64.tar.gz" `
  -Extract `
  -Clean `
  -UpdateDb
```

---

## ✅ After Scan Completes

1. Check reports in Windows Explorer next to your file
2. Read the `.md` report (plain text)
3. Open `.html` in browser for formatted view
4. Share `.md` in documentation (markdown)
5. Use JSON files for automation/tooling

---

**For detailed guide:** Read `DEPLOYMENT_GUIDE_EXAMPLE.md`  
**For what changed:** Read `CHANGELOG.md`  
**Status:** ✅ Ready to use | **Version:** 3.0 | **Last Updated:** 2026-05-26
