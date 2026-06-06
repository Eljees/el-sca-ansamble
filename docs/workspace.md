# SCA Development Workspace

**Location:** `D:\dev\el-sca-ansamble`  
**Date Updated:** 2026-05-26  
**Status:** ✅ Production-Ready v3.0

---

## 📌 What Is This?

This is the **development and research workspace** for the SCA (Software Composition Analysis) pipeline project. It contains documentation, analysis files, and reference materials.

### ⚠️ For Active Scanning Use:
**Use the production location instead:**
```
D:\!ya_drive_sync\YandexDisk\rostel\el-sca-ansamble
```

---

## 📁 Workspace Contents

### Documentation
- **DEPLOYMENT_GUIDE_EXAMPLE.md** — Worked deployment & operations example (v3.0)
- **CHANGELOG.md** — Release notes and changelog (Keep a Changelog)
- **README_WORKSPACE.md** — This file

### Research & Analysis
- **_el_cvebt_source_research/** — CVE-bin-tool source code analysis
  - source_code_inspection/ — Python module analysis
  - cache_backups/ — Database backups from testing
- **--exps/** — Experimental scans and results
  - high_critical_report_2026-04-29_ru.md — Sample report

---

## 🎯 How to Use This Workspace

### For Research
```powershell
# Review documentation
notepad DEPLOYMENT_GUIDE_EXAMPLE.md
notepad CHANGELOG.md

# Examine CVE-bin-tool analysis
dir _el_cvebt_source_research
```

### For Scanning (NOT Recommended Here)
If you must use this location, first sync the scripts:
```powershell
# Copy latest scripts from main location
robocopy "D:\!ya_drive_sync\YandexDisk\rostel\el-sca-ansamble\scripts" `
         "D:\dev\el-sca-ansamble\scripts" /S /E /Y

# Then proceed with scan
.\scripts\windows\run-scan.ps1 -Target "archive.tar.gz" -Extract -Clean
```

### Recommended: Use Production Location
```powershell
# Always use this for actual work
cd "D:\!ya_drive_sync\YandexDisk\rostel\el-sca-ansamble"

# Start SSH tunnel (separate terminal)
ssh -R 10808:127.0.0.1:10808 elaria@192.168.1.33 -N

# Run scan
.\scripts\windows\run-scan.ps1 -Target "archive.tar.gz" -Extract -Clean
```

---

## 🔧 v3.0 Key Features

### CVE-bin-tool Exit Code Handling (FIXED)
```powershell
# Before v3.0: Script fails when CVEs are found
# After v3.0: Script completes successfully regardless

.\scripts\windows\run-scan.ps1 -Target "file.tar.gz" -Clean
# ✅ Reports generated, script exits cleanly
```

### Supported Scan Modes
- **Standard:** Complete pipeline (Syft → Trivy → Grype → CVE-bin-tool)
- **Extraction:** Auto-extract archives before scanning
- **Specific Tools:** Run only Syft, Grype, Trivy, or CVE-bin-tool
- **Database Update:** Refresh vulnerability databases before scan

### Output
- Markdown report (`.md`) - Human-readable findings
- HTML report (`.html`) - Formatted for browsers
- JSON artifacts - Machine-readable results

---

## 🌐 Infrastructure Reference

| Component | Address | Role |
|-----------|---------|------|
| Windows Host | 192.168.1.126 | Proxy (port 10808), orchestration |
| Ubuntu Server | 192.168.1.33 | Docker execution, artifact storage |
| X-Ray Proxy | 10808/SOCKS5 | Network access for containers |
| SSH Tunnel | localhost:10808 | Docker → Windows proxy bridge |

---

## 📊 System Requirements

### Windows
- Windows 10/11
- PowerShell 5.0+
- Docker Desktop or Docker installed
- SSH client
- Proxy access (X-Ray/v2rayN on port 10808)

### Ubuntu (192.168.1.33)
- Docker 29.5.0+
- docker-compose 1.29.2+
- SSH server running
- 20GB disk available in `/opt/sca-work`

---

## 🚀 Quick Reference Commands

### Start SSH Tunnel (Windows)
```powershell
ssh -R 10808:127.0.0.1:10808 elaria@192.168.1.33 -N
# Keep this terminal open during scanning
```

### Run Scan (Windows)
```powershell
cd "D:\!ya_drive_sync\YandexDisk\rostel\el-sca-ansamble"
.\scripts\windows\run-scan.ps1 -Target "archive.tar.gz" -Extract -Clean
```

### Monitor Scan (Ubuntu)
```bash
cd /opt/sca-work/el-sca-ansamble
docker-compose logs -f cve-bin-tool-scanner
docker-compose ps
```

### Check Reports
```bash
# On Ubuntu
ls -lh artifacts/reports/final/
cat artifacts/reports/final/cve_analysis_report_ru.md | head -50

# On Windows (after scan completes)
Get-ChildItem "*_report_*.md" -Path "path\to\source"
```

### Clean Up Between Scans
```powershell
# Use -Clean flag in script
.\scripts\windows\run-scan.ps1 -Target "file.tar.gz" -Clean

# Or manually
rm -r artifacts/reports artifacts/sbom artifacts/extracted
```

---

## 🔗 Related Files

**Production Location:**
- `D:\!ya_drive_sync\YandexDisk\rostel\el-sca-ansamble\`

**Proxy Configuration:**
- `D:\!ya_drive_sync\YandexDisk\__Making_ProxY\v2rayN-windows-64\guiConfigs\guiNConfig.json`

**Ubuntu Connection:**
- Host: 192.168.1.33
- User: elaria
- Port: 22 (SSH)

---

## ✅ Checklist Before Scanning

- [ ] SSH tunnel running: `ssh -R 10808:127.0.0.1:10808 elaria@192.168.1.33 -N`
- [ ] X-Ray proxy active on port 10808
- [ ] Docker/docker-compose installed on Windows
- [ ] Target archive file exists and is readable
- [ ] Ubuntu disk has >8GB free: `df -h /opt/sca-work`
- [ ] No conflicting scans running: `docker ps`
- [ ] Using production location for actual scans
- [ ] Will use `-Clean` flag between scans

---

## 📞 Support

### Common Issues
**Docker containers can't reach the internet:**
1. Verify SSH tunnel is running
2. Check X-Ray proxy is active: `netstat -an | grep 10808`
3. Test proxy: `curl -x socks5://127.0.0.1:10808 https://www.google.com -I`

**CVE-bin-tool exits with error:**
- ✅ Exit code 1 is NORMAL (means CVEs found)
- ✅ v3.0 script handles this correctly
- ✅ Reports still generate successfully

**Out of disk space:**
- Use `-Clean` flag between scans
- Check available: `df -h /opt/sca-work`
- Clear artifacts: `rm -rf artifacts/*`

### Documentation
- See **DEPLOYMENT_GUIDE_EXAMPLE.md** for comprehensive guide
- See **CHANGELOG.md** for version history
- Email/contact admin for infrastructure issues

---

**Last Updated:** 2026-05-26  
**Status:** ✅ Production Ready (v3.0)  
**Workspace Type:** Development & Research (Use production location for scanning)
