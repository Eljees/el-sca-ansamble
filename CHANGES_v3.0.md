# SCA Pipeline v3.0 - Release Notes

**Date:** 2026-05-15 | **Updated:** 2026-05-26  
**Status:** Production Release  
**Workspace:** `D:\dev\el-sca-ansamble` (Development & Research)

---

## 🔧 Key Changes & Fixes

### Issue Fixed: CVE-bin-tool Exit Code Handling

#### Problem
- CVE-bin-tool legitimately exits with code **1** when vulnerabilities are detected
- PowerShell script treated all non-zero exit codes as fatal errors
- Result: Exception thrown even though scan completed successfully and reports were generated

#### Solution
**New function: `Invoke-CveBinToolChecked`**

```powershell
function Invoke-CveBinToolChecked {
  param([Parameter(Mandatory=$true)][string[]]$Args)
  & docker compose @Args
  # cve-bin-tool exits with 1 when CVEs are found (success state), 0 when none found
  if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1) {
    throw "cve-bin-tool failed (exit $LASTEXITCODE): $($Args -join ' ')"
  }
}
```

**Updated all cve-bin-tool calls to use this function:**
- Line 211: APK format extraction
- Line 239: Windows format extraction  
- Line 260: Standard scan "all" tools
- Line 286: Standalone cve-bin-tool runs

#### Result
✅ Scripts now complete cleanly when vulnerabilities are detected  
✅ Exit code 1 (CVEs found) is properly recognized as success  
✅ Reports generate without exceptions  

---

## 📚 Documentation Improvements

### New: DEPLOYMENT_GUIDE_FINAL.md
Comprehensive single-source reference covering:
- Complete infrastructure overview
- Network configuration (X-Ray SOCKS5 proxy details)
- 4-phase deployment walkthrough
- Troubleshooting guide with known issues
- Tool reference documentation
- Quick command reference

### Retained Guides
- `SCA_DEPLOYMENT_GUIDE_v2.md` - Initial deployment documentation
- `PHASE_2_CLEANUP_AND_PROJECT.md` - Environment cleanup procedures
- `PHASE_3_ENV_SETUP.md` - Docker configuration details
- `SCA_Deployment_Config.md` - Configuration tracking

---

## 🚀 Behavior Changes

### Before v3.0
```powershell
.\scripts\windows\run-scan.ps1 -Target "file.tar.gz" -Clean
# ... scanning completes ...
# Exception: cve-bin-tool failed (exit 1)
# Script halts with error code 1
```

### After v3.0
```powershell
.\scripts\windows\run-scan.ps1 -Target "file.tar.gz" -Clean
# ... scanning completes ...
# ✅ Reports ready:
#    MD  : file_report_2026-05-15.md
#    HTML: file_report_2026-05-15.html
# Script exits cleanly with code 0
```

---

## ✅ Testing & Validation

The fix was validated against:
1. ✅ Archive extraction (tar.gz with 33 packages)
2. ✅ SBOM generation (Syft: 44 executables, 122 files)
3. ✅ Vulnerability scanning (Trivy, Grype)
4. ✅ CVE-bin-tool with findings (GNU gcc 4.4.7, libjpeg 6b)
5. ✅ Report generation (Markdown + HTML)

**Test Results:**
- Syft: 33 packages identified ✓
- Grype: 5 matches (1 HIGH, 4 MEDIUM) ✓
- CVE-bin-tool: 2 products with CVEs ✓
- Reports: Generated successfully ✓

---

## 🔄 Migration from v2.0

No changes required. The script is backward compatible.

Simply update:
```powershell
# Pull latest version
git pull origin main
# or
cd D:\dev\el-sca-ansamble
# Replace run-scan.ps1 with new version
```

---

## 📝 Version History

| Version | Date | Status | Changes |
|---------|------|--------|---------|
| 3.0 | 2026-05-15 | ✅ Stable | CVE-bin-tool exit code fix, comprehensive docs |
| 2.0 | 2026-05-13 | Archived | Initial Windows-based deployment |
| 1.0 | 2026-05-12 | Archived | Ubuntu-only deployment (containerd issues) |

---

---

## 📂 Workspace Organization (Updated 2026-05-26)

### Development Location (This Workspace)
**Path:** `D:\dev\el-sca-ansamble`
- Research and analysis files
- CVE-bin-tool source code inspection
- Experimental scan results
- Documentation copies
- **Use for:** Research, analysis, reference

### Production Location (Recommended for Scans)
**Path:** `D:\!ya_drive_sync\YandexDisk\rostel\el-sca-ansamble`
- Main project repository
- Fixed scripts (v3.0 with CVE-bin-tool exit code handling)
- docker-compose.yml and configuration
- Deployment guides
- **Use for:** Active scanning, production work

### Ubuntu Execution Environment
**Path:** `/opt/sca-work/el-sca-ansamble` (192.168.1.33)
- Docker execution host
- Artifact storage and reports
- Network access via SSH tunnel (port 10808)
- 20GB disk (`/dev/sdb1`) for artifacts

---

## 🚀 Quick Start Guide

```powershell
# 1. Start SSH tunnel (keep open in separate terminal)
ssh -R 10808:127.0.0.1:10808 elaria@192.168.1.33 -N

# 2. Navigate to production location (recommended)
cd "D:\!ya_drive_sync\YandexDisk\rostel\el-sca-ansamble"

# 3. Run scan with extraction and cleanup
.\scripts\windows\run-scan.ps1 -Target "path\to\archive.tar.gz" -Extract -Clean

# 4. Check results (saved next to source file)
Get-ChildItem -Filter "*_report_*.md" -Path "path\to\"
```

---

## 🆘 Support

If you encounter issues:

1. **Check DEPLOYMENT_GUIDE_FINAL.md** - Troubleshooting section
2. **Verify SSH tunnel** is running: `ssh -R 10808:127.0.0.1:10808 elaria@192.168.1.33 -N`
3. **Review script logs**: `docker-compose logs -f cve-bin-tool-scanner`
4. **Clean and retry**: `.\scripts\windows\run-scan.ps1 -Target "file.tar.gz" -Clean`

### Key Points to Remember
- SSH tunnel MUST remain open during scans
- Always use `-Clean` flag between scans
- Reports saved next to source files on Windows
- Monitor `/opt/sca-work` disk space on Ubuntu (~20GB available)

---

**Status:** ✅ Ready for Production Use | **Latest:** v3.0 | **Updated:** 2026-05-26
