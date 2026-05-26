# SCA Pipeline - Complete Deployment & Operations Guide

**Version:** 3.0 (Final)  
**Date:** 2026-05-15  
**Status:** ✅ Production Ready

---

## 📋 Table of Contents

1. [Infrastructure Overview](#-infrastructure-overview)
2. [Network Configuration](#-network-configuration)
3. [Phase 1: Ubuntu Diagnostics & Preparation](#phase-1-ubuntu-diagnostics--preparation)
4. [Phase 2: Environment Cleanup & Project Setup](#phase-2-environment-cleanup--project-setup)
5. [Phase 3: Docker Configuration](#phase-3-docker-configuration)
6. [Phase 4: Running the SCA Pipeline](#phase-4-running-the-sca-pipeline)
7. [Troubleshooting & Known Issues](#troubleshooting--known-issues)
8. [Appendix: Tool References](#appendix-tool-references)

---

## 🏗️ Infrastructure Overview

### Hardware Setup

| Component | Specs | Role |
|-----------|-------|------|
| **Local Machine** | Windows 10/11 | Management, proxy, artifact source |
| **Network IP** | 192.168.1.126 | Local management station |
| **Target Server** | Ubuntu 24.04 LTS | SCA pipeline execution host |
| **Server IP** | 192.168.1.33 | Primary deployment target |
| **Storage Disk** | `/dev/sdb1` (20GB) | SCA working directory `/opt/sca-work` |
| **Dev Directory** | `D:\dev\el-sca-ansamble` | Windows development workspace |

### Software Stack

```
Windows Host (D:\dev\el-sca-ansamble)
├─ v2rayN (X-Ray SOCKS5 proxy, port 10808)
├─ PowerShell (pipeline orchestration)
└─ SSH client (reverse tunnel management)

Ubuntu Server (192.168.1.33)
├─ Docker 29.5.0 (container runtime)
├─ docker-compose 1.29.2 (orchestration)
├─ /opt/sca-work/ (project root)
│  └─ el-sca-ansamble/
│     ├─ docker-compose.yml
│     ├─ .env (configuration)
│     ├─ scripts/ (extraction, reporting)
│     └─ artifacts/ (scan results)
└─ Network access via SSH reverse tunnel
```

---

## 🌐 Network Configuration

### X-Ray SOCKS5 Proxy Setup

**Proxy Details:**
- **Server:** Windows host (192.168.1.126)
- **Port:** 10808
- **Protocol:** SOCKS5 (VLESS backend via X-Ray)
- **LAN Access:** Enabled (`AllowLANConn: true` in v2rayN config)
- **Auth:** None required
- **Config File:** `D:\!ya_drive_sync\YandexDisk\__Making_ProxY\v2rayN-windows-64\guiConfigs\guiNConfig.json`

**Key Configuration (from guiNConfig.json):**
```json
{
  "Inbound": [
    {
      "LocalPort": 10808,
      "Protocol": "socks",
      "UdpEnabled": true,
      "SniffingEnabled": true,
      "AllowLANConn": true,
      "User": null,
      "Pass": null
    }
  ]
}
```

### SSH Reverse Tunnel

**Purpose:** Forward proxy from Windows to Docker containers on Ubuntu

**Command (run on Windows):**
```powershell
ssh -R 10808:127.0.0.1:10808 elaria@192.168.1.33 -N
```

**Expected Result:**
```
[Ubuntu side] netstat -tlnp | grep 10808
tcp        0      0 127.0.0.1:10808         0.0.0.0:*        LISTEN
```

**Keep this terminal open during all scanning operations.**

### Docker Proxy Configuration

**File:** `/etc/systemd/system/docker.service.d/http-proxy.conf`

```ini
[Service]
Environment="HTTP_PROXY=socks5://127.0.0.1:10808"
Environment="HTTPS_PROXY=socks5://127.0.0.1:10808"
Environment="NO_PROXY=localhost,127.0.0.1,192.168.1.0/24"
```

**Apply changes:**
```bash
sudo systemctl daemon-reload
sudo systemctl restart docker
```

**Verify proxy works:**
```bash
curl -x socks5://127.0.0.1:10808 https://www.google.com -I
# Expected: HTTP/2 200
```

---

## Phase 1: Ubuntu Diagnostics & Preparation

### Step 1.1: System Information Check

```bash
# Basic system info
uname -a
lsb_release -a
hostnamectl

# Expected output:
# Ubuntu 24.04.4 LTS (noble)
# Linux 6.17.0-23-generic (kernel)
```

### Step 1.2: Disk Space Verification

```bash
# Check all disks
df -h

# Specific SCA storage check
du -sh /opt/sca-work

# Expected for deployment:
# /dev/sdb1: at least 8GB free (we have 7.9GB, sufficient for this scan)
```

### Step 1.3: Docker Verification

```bash
# Check Docker version
docker --version
# Expected: Docker version 29.5.0

# Check docker-compose
docker-compose --version
# Expected: docker-compose version 1.29.2

# Verify no running containers
docker ps -a
# Expected: (empty list)

# Check Docker networks
docker network ls
# Note: el-sca-ansamble_scanner-net should NOT exist yet (we create it fresh)
```

### Step 1.4: Network Connectivity

```bash
# Check IP address
ip addr show

# Test internet
ping -c 3 8.8.8.8

# Check for SSH tunnel (after Windows sets it up)
netstat -tlnp | grep 10808
# Expected: tcp 127.0.0.1:10808 LISTEN
```

### Diagnostic Results (Reference)

✅ **All checks passed on 2026-05-15:**
- OS: Ubuntu 24.04.4 LTS (x86-64, VMware)
- Kernel: Linux 6.17.0-23-generic
- Docker: v29.5.0 ✓
- docker-compose: v1.29.2 ✓
- Disk `/dev/sdb1`: 20GB total, ~7.9GB free ✓
- Network: Internet accessible ✓
- SSH Tunnel: Port 10808 listening ✓

---

## Phase 2: Environment Cleanup & Project Setup

### Step 2.1: Clean Old Docker Data

⚠️ **DESTRUCTIVE** - Only on dedicated SCA disk

```bash
# On Ubuntu, in /opt/sca-work/

# Stop all containers
docker stop $(docker ps -aq) 2>/dev/null || true
docker rm $(docker ps -aq) 2>/dev/null || true

# Remove old snapshotter/daemon data (causes metadata.db issues)
sudo rm -rf /opt/sca-work/docker
sudo rm -rf /opt/sca-work/containerd
sudo rm -rf /opt/sca-work/__projects

# Verify cleanup
ls -lah /opt/sca-work/
df -h /opt/sca-work
```

**Expected Result:**
```
/opt/sca-work nearly empty (only project files if any)
~20GB available for fresh start
```

### Step 2.2: Copy Project to Ubuntu

**Option A: Via ZIP Archive (Recommended - 15 sec transfer)**

```powershell
# On Windows - create archive
cd D:\dev\
tar -czf el-sca-ansamble.tar.gz el-sca-ansamble\
# or use 7-Zip: 7z a el-sca-ansamble.7z el-sca-ansamble\
```

```bash
# On Ubuntu
cd /opt/sca-work
scp elaria@192.168.1.126:/path/to/el-sca-ansamble.tar.gz .
tar -xzf el-sca-ansamble.tar.gz
ls -lah
```

**Option B: Via SCP (Direct but slower for many files)**

```powershell
# On Windows PowerShell
scp -r "D:\dev\el-sca-ansamble\*" elaria@192.168.1.33:/opt/sca-work/
```

### Step 2.3: Verify Project Structure

```bash
cd /opt/sca-work/el-sca-ansamble

# Check key files
ls -lah docker-compose.yml .env README.md 2>/dev/null || echo "Some files missing"

# Find all docker-compose variants
find . -maxdepth 3 -type f \( -name "docker-compose*" -o -name "*.yml" -o -name "*.yaml" \)

# View project structure
tree -L 2 . 2>/dev/null || find . -maxdepth 2 -type d | head -20
```

**Expected structure:**
```
el-sca-ansamble/
├─ docker-compose.yml
├─ .env (or .env.template)
├─ scripts/
│  ├─ windows/
│  │  └─ run-scan.ps1
│  └─ linux/
│     ├─ extract.sh
│     └─ report.sh
├─ artifacts/
│  ├─ sbom/
│  ├─ reports/
│  └─ extracted/
└─ README.md
```

---

## Phase 3: Docker Configuration

### Step 3.1: Create/Verify .env File

**Location:** `/opt/sca-work/el-sca-ansamble/.env`

```bash
cat > /opt/sca-work/el-sca-ansamble/.env << 'EOF'
# ============================================================================
# SCA Pipeline Configuration
# ============================================================================

# ---------------------------------------------------------------------------
# Proxy Settings (X-Ray SOCKS5 via SSH reverse tunnel)
# ---------------------------------------------------------------------------
ALL_PROXY=socks5h://host.docker.internal:10808
HTTP_PROXY=socks5h://host.docker.internal:10808
HTTPS_PROXY=socks5h://host.docker.internal:10808
NO_PROXY=localhost,127.0.0.1,grype-static

# ---------------------------------------------------------------------------
# Docker Container Access
# ---------------------------------------------------------------------------
# These get overridden per run in the PowerShell script
SCAN_TARGET_HOST=/scan-target-will-be-set-per-run
EXTRACT_INPUT_HOST=/scan-target-will-be-set-per-run
TRIVY_TARGET=/scan-target
GRYPE_TARGET=/scan-target
SYFT_TARGET=/scan-target
SYFT_FROM=dir
CVE_BIN_TOOL_TARGET=/scan-target

# ---------------------------------------------------------------------------
# Linux UID/GID for mounted artifacts
# ---------------------------------------------------------------------------
LOCAL_UID=1000
LOCAL_GID=1000

# ---------------------------------------------------------------------------
# CVE Bin Tool Configuration
# ---------------------------------------------------------------------------
CVE_BIN_TOOL_SCAN_TIMEOUT_SECONDS=600
# CVE_BIN_TOOL_NVD_API_KEY=your_api_key_here (optional)

# ---------------------------------------------------------------------------
# Report Configuration
# ---------------------------------------------------------------------------
REPORT_OUTPUT=/workspace/artifacts/reports/final/cve_analysis_report_ru.md

# ---------------------------------------------------------------------------
# Extraction Configuration
# ---------------------------------------------------------------------------
EXTRACT_OUTPUT=/workspace/artifacts/extracted/current
EXTRACT_MAX_DEPTH=4
EXTRACT_MAX_FILES=20000
EXTRACT_MAX_BYTES=10737418240

EOF

# Verify
cat .env | grep -E "PROXY|CVE_BIN|SCAN_TARGET"
```

### Step 3.2: Test Docker Proxy

```bash
# Test that Docker containers can reach the internet
docker run --rm alpine curl -I https://www.google.com

# Expected: HTTP/2 200 (or similar success response)
```

If this fails, verify:
1. SSH reverse tunnel is still running on Windows
2. Port 10808 is listening: `netstat -tlnp | grep 10808`
3. X-Ray proxy is active on Windows

---

## Phase 4: Running the SCA Pipeline

### Step 4.1: Basic Scan (Windows)

**Prerequisite:** SSH tunnel must be running

```powershell
# On Windows, in el-sca-ansamble directory
cd D:\dev\el-sca-ansamble

# Run complete scan with extraction and cleanup
.\scripts\windows\run-scan.ps1 -Target "path\to\archive.tar.gz" -Extract -Clean
```

### Step 4.2: Command-Line Options

```powershell
# All options of run-scan.ps1:

# Basic scan
.\scripts\windows\run-scan.ps1 -Target "C:\path\to\file.tar.gz"

# With extraction
.\scripts\windows\run-scan.ps1 -Target "C:\path\to\file.tar.gz" -Extract

# Specific tool only
.\scripts\windows\run-scan.ps1 -Target "archive.tar.gz" -Tool "grype"
# Valid tools: all, syft, grype, trivy, cve-bin-tool

# Update vulnerability databases before scan
.\scripts\windows\run-scan.ps1 -Target "archive.tar.gz" -UpdateDb

# Run in background
$job = Start-Job { cd D:\dev\el-sca-ansamble; .\scripts\windows\run-scan.ps1 -Target "..." -Clean }
Get-Job -Id $job.Id | Receive-Job -Wait -AutoRemoveJob
```

### Step 4.3: Pipeline Stages

**Standard scan runs these in sequence:**

1. **Extraction** (optional, `-Extract`)
   - Unpacks tar.gz / zip archives
   - Max depth: 4 levels
   - Max files: 20,000
   - Timeout: 10GB extraction limit

2. **SBOM Generation (Syft)**
   - Catalog all components
   - Output: `artifacts/sbom/syft.json`
   - Typical runtime: 2-5 minutes

3. **Vulnerability Scan (Trivy)**
   - Container/package scanning
   - Output: `artifacts/reports/trivy/report.json`
   - Typical runtime: 2-5 minutes

4. **Vulnerability Scan (Grype)**
   - Database-driven detection
   - Output: `artifacts/reports/grype/report.json`
   - Typical runtime: 2-5 minutes

5. **CVE Analysis (CVE-bin-tool)**
   - Binary-level CVE matching
   - Output: `artifacts/reports/cve-bin-tool/report.json`
   - Typical runtime: 5-15 minutes
   - **Exit Code 1 is SUCCESS** (vulnerabilities found)

6. **Report Collection**
   - Consolidate all findings
   - Output: `artifacts/reports/final/cve_analysis_report_ru.md`
   - Output: `artifacts/reports/final/cve_analysis_report_ru.html`

**Total Time: 15-40 minutes** (depending on archive size)

### Step 4.4: Monitor Scan Progress

```powershell
# In another PowerShell window, watch Docker logs
docker logs -f el-sca-ansamble-cve-bin-tool-scanner-1

# Or check artifacts in real-time
Get-ChildItem -Path artifacts/reports -Recurse -File | 
  Sort-Object LastWriteTime -Descending | 
  Select-Object -First 5 FullName, Length, LastWriteTime
```

### Step 4.5: Retrieve Results

**On Windows, reports are saved next to the source file:**
```
path\to\archive_report_2026-05-15.md      (Markdown report)
path\to\archive_report_2026-05-15.html    (HTML report)
```

**Access Docker artifacts (if needed):**
```bash
# On Ubuntu server
ls -lh /opt/sca-work/el-sca-ansamble/artifacts/reports/final/
cat /opt/sca-work/el-sca-ansamble/artifacts/reports/final/*.md | head -50
```

---

## Troubleshooting & Known Issues

### Issue 1: Docker Proxy Not Working

**Symptom:** Docker containers can't reach the internet, or `curl` in containers fails

**Fix:**
1. Verify SSH reverse tunnel is running (Windows):
   ```powershell
   ssh -R 10808:127.0.0.1:10808 elaria@192.168.1.33 -N
   # Keep this terminal open!
   ```

2. Verify Ubuntu can reach it:
   ```bash
   netstat -tlnp | grep 10808
   # Should show: tcp 127.0.0.1:10808 LISTEN
   ```

3. Test manually:
   ```bash
   curl -x socks5://127.0.0.1:10808 https://www.google.com -I
   # Should return HTTP/2 200
   ```

4. Restart Docker if changes made:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl restart docker
   ```

### Issue 2: Container Metadata Errors

**Symptom:** 
```
failed to create /opt/sca-work/containerd/io.containerd.metadata.v1.bolt/db
```

**Fix:** This indicates corrupted containerd state. Clean it completely:
```bash
docker stop $(docker ps -aq) 2>/dev/null || true
docker rm $(docker ps -aq) 2>/dev/null || true
sudo rm -rf /opt/sca-work/docker
sudo rm -rf /opt/sca-work/containerd
sudo systemctl restart docker
```

### Issue 3: CVE-bin-tool Exits with Code 1

**Symptom:** PowerShell script throws exception but reports are created successfully

**Status:** ✅ **FIXED in v3.0**
- CVE-bin-tool exits code 1 when vulnerabilities are detected (not an error)
- New `Invoke-CveBinToolChecked` function treats code 1 as success
- Script now completes cleanly when CVEs are found

### Issue 4: Slow SCP Transfer

**Symptom:** Copying 1000+ files takes hours

**Solution:** Use archive instead:
```powershell
# Windows
tar -czf project.tar.gz el-sca-ansamble\

# Transfer single file (seconds instead of hours)
scp project.tar.gz elaria@192.168.1.33:/opt/sca-work/

# Ubuntu - unpack
tar -xzf project.tar.gz
```

### Issue 5: Out of Disk Space

**Symptom:** Extraction fails with space error

**Check available:**
```bash
df -h /opt/sca-work
du -sh /opt/sca-work/artifacts/
```

**Solution:**
1. Clean old artifacts: `docker compose exec artifact-extractor rm -rf /workspace/artifacts/*`
2. Or delete manually: `rm -rf /opt/sca-work/el-sca-ansamble/artifacts/*`
3. Verify: `df -h /opt/sca-work` should show >8GB free

---

## Appendix: Tool References

### Syft (SBOM Generation)
- **Purpose:** Generate Software Bill of Materials
- **Database:** Grype DB, NVD
- **Output:** JSON SBOM with 763+ components
- **GitHub:** https://github.com/anchore/syft

### Grype (Vulnerability Scanning)
- **Purpose:** Match packages against CVE databases
- **Detection:** 82+ CVE matches typical
- **Database:** Grype DB (updated with `-UpdateDb`)
- **GitHub:** https://github.com/anchore/grype

### Trivy (Container Scanning)
- **Purpose:** Scan containers, OS packages, application dependencies
- **Output:** JSON report with vulnerability details
- **GitHub:** https://github.com/aquasecurity/trivy

### CVE-bin-tool (Binary-Level Analysis)
- **Purpose:** Identify known vulnerabilities in binaries
- **Detection:** Product-level CVEs (e.g., "gcc 4.4.7 has CVE-2021-xxxx")
- **Exit Code 1:** Normal (vulnerabilities found, not an error)
- **GitHub:** https://github.com/intel/cve-bin-tool

### Report Consolidation
- **Tool:** `resilient_updates.cli collect-report`
- **Input:** All scanner JSON outputs
- **Output:** Markdown + HTML reports
- **Language:** Russian (ru) variants available

---

## Quick Reference: Common Commands

```bash
# Check deployment status (Ubuntu)
cd /opt/sca-work/el-sca-ansamble
docker-compose ps
docker-compose logs -f

# View latest report
cat artifacts/reports/final/cve_analysis_report_ru.md | head -100

# Manual SBOM generation
docker-compose run --rm syft-sbom

# Manual Trivy scan
docker-compose run --rm trivy-scanner

# Manual Grype scan
docker-compose run --rm grype-scanner

# Manual CVE-bin-tool scan
docker-compose run --rm cve-bin-tool-scanner

# Cleanup
docker-compose down
rm -rf artifacts/*
```

---

## Support & Next Steps

### For Windows Users
- Check `.\scripts\windows\run-scan.ps1` for latest options
- Reports saved adjacent to source files (same directory)
- All proxy configuration handled automatically

### For Ubuntu Maintenance
- SSH tunnel must remain open during scans
- Monitor disk space in `/opt/sca-work/`
- Update databases weekly: `docker-compose up update`
- Backup important artifacts regularly

### Future Enhancements
- [ ] Automated scheduled scans
- [ ] Email report delivery
- [ ] Database storage (PostgreSQL)
- [ ] Web UI for browse results
- [ ] API endpoint for remote scanning
- [ ] Support for Windows PE/APK analysis

---

**Last Updated:** 2026-05-26 (v3.0)  
**Status:** ✅ Production Ready
