#requires -Version 5.1
<#
.SYNOPSIS
  Produce a compact "high/critical" digest in the CYBERSEC-11531 reference
  format from an existing run-scan.ps1 markdown report.

.DESCRIPTION
  The container pipeline already writes a verbose `*_report_<DATE>.md` next
  to every scan target.  Triagers and stakeholders frequently ask for a
  shorter Russian-language doc focused only on Critical and High findings
  plus the artifact SHA-256 — see the reference document
  high_critical_report_2026-04-29_ru.md (CYBERSEC-11531).

  This script takes either a -Target (archive path next to which the
  scan report lives) or an explicit -ReportPath (the markdown report
  itself) and writes a sibling file
      <basename>_high_critical_<REPORT_DATE>_ru.md
  in the same format.

  It does NOT re-run any scanner — it parses the existing scan markdown
  for the "High / Critical findings" table and the "Scanner summary"
  block, then re-renders them.  This keeps the digest reproducible from
  on-disk evidence even days after the original scan.

.PARAMETER Target
  Archive or directory that was scanned (e.g.
  D:\__tests\_SCA\CYBERSEC-12103\avandoc-client-1.0.0.4.tar.gz).
  The script auto-discovers the most recent *_report_*.md sibling.

.PARAMETER ReportPath
  Explicit path to the run-scan markdown report.  Use this when the
  target archive is no longer next to its report.

.PARAMETER Jobs
  Array of hashtables @( @{ Case='…'; Target='…' } … ) — the same
  shape batch-scan.ps1 accepts.  Each entry is processed in turn.

.PARAMETER Runner
  Tooling identifier embedded in the "Методика" section.
  Defaults to "el-sca-ansamble (docker compose)".

.PARAMETER OnlineDb
  Set this switch when the scan was run with -UpdateDb so the digest
  says "локальные базы grype/cve-bin-tool с принудительным обновлением
  перед прогоном" instead of "без online-обновления".

.PARAMETER OutputDir
  Override where the digest is written.  Default = same folder as the
  source markdown report.

.EXAMPLE
  .\scripts\windows\make-high-critical-report.ps1 `
    -Target D:\__tests\_SCA\CYBERSEC-12103\avandoc-client-1.0.0.4.tar.gz

.EXAMPLE
  # Produce all three after a batch run:
  .\scripts\windows\make-high-critical-report.ps1 -Jobs @(
    @{ Case='CYBERSEC-12103'; Target='D:\__tests\_SCA\CYBERSEC-12103\avandoc-client-1.0.0.4.tar.gz' }
    @{ Case='CYBERSEC-12104'; Target='D:\__tests\_SCA\CYBERSEC-12104\DMS_AvandocClientServiceSetup1.zip' }
    @{ Case='CYBERSEC-12080'; Target='D:\__tests\_SCA\CYBERSEC-12080\iDocs11c2781f2-android-build-release-signed.zip' }
  )
#>
[CmdletBinding(DefaultParameterSetName='Single')]
param(
  [Parameter(ParameterSetName='Single')]
  [string]$Target,

  [Parameter(ParameterSetName='Single')]
  [string]$ReportPath,

  [Parameter(ParameterSetName='Batch', Mandatory=$true)]
  [hashtable[]]$Jobs,

  [string]$Runner = "el-sca-ansamble (docker compose)",
  [switch]$OnlineDb,
  [string]$OutputDir
)

$ErrorActionPreference = 'Stop'

# ── Helpers ────────────────────────────────────────────────────────────────

function Get-LatestReport {
  param([Parameter(Mandatory=$true)][string]$TargetPath)
  $dir  = Split-Path -LiteralPath $TargetPath -Parent
  if (-not $dir) { $dir = (Get-Location).Path }
  $base = [IO.Path]::GetFileNameWithoutExtension($TargetPath) -replace '\.tar$',''
  $candidates = Get-ChildItem -LiteralPath $dir -Filter ("${base}_report_*.md") `
                  -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notmatch '_high_critical_' } |
                Sort-Object LastWriteTime -Descending
  if (-not $candidates) { return $null }
  return $candidates[0].FullName
}

function Get-ReportDate {
  param([string]$ReportFileName)
  # Pull yyyy-MM-dd from the report filename when possible, fall back to today.
  if ($ReportFileName -match '_report_(\d{4}-\d{2}-\d{2})\.md$') {
    return $Matches[1]
  }
  return (Get-Date).ToString('yyyy-MM-dd')
}

function Get-Sha256 {
  param([string]$Path)
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Parse-ScanReport {
  <#
    Parses a run-scan.ps1 markdown report and returns a hashtable:
      CaseId         "CYBERSEC-12080"
      TargetDisplay  "/scan-target/iDocs….apk"
      TargetSha      "ABCD…"            (may be $null if header didn't carry it)
      SyftCount      429
      GrypeCount     27
      TrivyCount     0
      CveCount       3
      SeverityCounts hashtable like @{ CRITICAL=2; HIGH=16; MEDIUM=9 }
      Findings       array of pscustomobjects with .Tool .Cve .Severity .Score .Vendor .Product .Version .Source
      ToolFailures   "OK" / "UNKNOWN" / "yes"
      DbDrift        "OK" / etc
  #>
  param([Parameter(Mandatory=$true)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path)) { throw "Report not found: $Path" }
  $lines = Get-Content -LiteralPath $Path

  $out = [ordered]@{
    CaseId         = ""
    TargetDisplay  = ""
    TargetSha      = $null
    DbSnapshot     = ""
    DbDrift        = ""
    ToolFailures   = ""
    SyftCount      = 0
    GrypeCount     = 0
    TrivyCount     = 0
    CveCount       = 0
    SeverityCounts = @{}
    Findings       = @()
  }

  # Header line: "# CYBERSEC-12103: контейнерный SCA-отчет"
  if ($lines.Count -gt 0 -and $lines[0] -match '^#\s+(\S+)') {
    $out.CaseId = $Matches[1].TrimEnd(':')
  }

  for ($i = 0; $i -lt $lines.Count; $i++) {
    $ln = $lines[$i]
    if ($ln -match '^\-\s+Target:\s+`([^`]+)`')                   { $out.TargetDisplay = $Matches[1]; continue }
    if ($ln -match '^\-\s+SHA-256:\s+`([^`]+)`')                  { $out.TargetSha     = $Matches[1]; continue }
    if ($ln -match '^\-\s+DB snapshot:\s+`([^`]+)`')              { $out.DbSnapshot    = $Matches[1]; continue }
    if ($ln -match '^\-\s+DB drift:\s+`([^`]+)`')                 { $out.DbDrift       = $Matches[1]; continue }
    if ($ln -match '^\-\s+Tool failures:\s+`([^`]+)`')            { $out.ToolFailures  = $Matches[1]; continue }
    if ($ln -match '^\-\s+Syft components:\s+`(\d+)`')            { $out.SyftCount     = [int]$Matches[1]; continue }
    if ($ln -match '^\-\s+Grype findings:\s+`(\d+)`')             { $out.GrypeCount    = [int]$Matches[1]; continue }
    if ($ln -match '^\-\s+Trivy findings:\s+`(\d+)`')             { $out.TrivyCount    = [int]$Matches[1]; continue }
    if ($ln -match '^\-\s+cve-bin-tool findings:\s+`(\d+)`')      { $out.CveCount      = [int]$Matches[1]; continue }
    if ($ln -match '^\-\s+Severity counts:\s+`([^`]+)`') {
      # Body looks like  {'CRITICAL': 2, 'HIGH': 16, 'MEDIUM': 9}
      $body = $Matches[1]
      $sev = @{}
      foreach ($m in [regex]::Matches($body, "'([A-Z]+)':\s*(\d+)")) {
        $sev[$m.Groups[1].Value] = [int]$m.Groups[2].Value
      }
      $out.SeverityCounts = $sev
      continue
    }
  }

  # Findings table — lives under "## High / Critical findings".
  $tableStart = -1
  for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^##\s+High\s*/\s*Critical') { $tableStart = $i; break }
  }
  if ($tableStart -ge 0) {
    $headerIdx = -1
    for ($i = $tableStart + 1; $i -lt $lines.Count; $i++) {
      if ($lines[$i] -match '^\|\s*Tool\s*\|') { $headerIdx = $i; break }
      if ($lines[$i] -match '^##\s+')          { break }   # next section, no table
    }
    if ($headerIdx -ge 0) {
      # Header columns — drop empty leading/trailing slots from the split.
      $headerCells = ($lines[$headerIdx].Trim('|')) -split '\s*\|\s*' | ForEach-Object { $_.Trim() }
      # rule line is at $headerIdx + 1 ("|---|---|...|"); rows start at +2
      for ($i = $headerIdx + 2; $i -lt $lines.Count; $i++) {
        $row = $lines[$i]
        if ([string]::IsNullOrWhiteSpace($row)) { break }
        if ($row -notmatch '^\|') { break }
        $cells = ($row.Trim('|')) -split '\s*\|\s*' | ForEach-Object { $_.Trim() }
        $finding = [ordered]@{}
        for ($j = 0; $j -lt $headerCells.Count -and $j -lt $cells.Count; $j++) {
          $finding[$headerCells[$j]] = $cells[$j]
        }
        $out.Findings += [pscustomobject]$finding
      }
    }
  }

  return [pscustomobject]$out
}

function Render-Bullet {
  param(
    [pscustomobject]$Row,
    [switch]$IncludeTool
  )
  # PS 5.1 has no ternary; resolve CVE column name defensively.
  if ($Row.PSObject.Properties['CVE/GHSA']) {
    $cve = $Row.'CVE/GHSA'
  } elseif ($Row.PSObject.Properties['CVE']) {
    $cve = $Row.'CVE'
  } else {
    $cve = ''
  }
  $vendor  = if ($Row.PSObject.Properties['Vendor'])  { $Row.Vendor }  else { '' }
  $product = if ($Row.PSObject.Properties['Product']) { $Row.Product } else { '' }
  $version = if ($Row.PSObject.Properties['Version']) { $Row.Version } else { '' }
  $tool    = if ($Row.PSObject.Properties['Tool'])    { $Row.Tool }    else { '' }
  $source  = if ($Row.PSObject.Properties['Source'])  { $Row.Source }  else { '' }

  if ($vendor -and $product -and $vendor -ne $product) {
    $component = ("{0}:{1} {2}" -f $vendor, $product, $version).Trim()
  } elseif ($product) {
    $component = ("{0} {1}" -f $product, $version).Trim()
  } elseif ($source) {
    $component = $source
  } else {
    $component = "(unknown component)"
  }

  $bt = [char]96  # literal backtick — avoids parser headaches in interpolation
  if ($IncludeTool) {
    return "- $bt$cve$bt - $bt$component$bt - $bt$tool$bt"
  } else {
    return "- $bt$cve$bt - $bt$component$bt"
  }
}

function Build-Digest {
  param(
    [pscustomobject]$Parsed,
    [string]$TargetArchivePath,
    [string]$ArchiveSha,
    [string]$ReportDate,
    [string]$RunnerName,
    [switch]$OnlineDb
  )

  $archiveName  = if ($TargetArchivePath) { Split-Path -Leaf $TargetArchivePath } else { Split-Path -Leaf $Parsed.TargetDisplay }
  $caseId       = if ($Parsed.CaseId) { $Parsed.CaseId } else { "CYBERSEC-UNKNOWN" }
  $shaForHeader = if ($ArchiveSha) { $ArchiveSha } elseif ($Parsed.TargetSha -and $Parsed.TargetSha -ne 'UNKNOWN') { $Parsed.TargetSha } else { "UNKNOWN" }

  $sev          = $Parsed.SeverityCounts
  $critTotal    = if ($sev.ContainsKey('CRITICAL')) { $sev['CRITICAL'] } else { 0 }
  $highTotal    = if ($sev.ContainsKey('HIGH'))     { $sev['HIGH'] }     else { 0 }
  $medTotal     = if ($sev.ContainsKey('MEDIUM'))   { $sev['MEDIUM'] }   else { 0 }
  $lowTotal     = if ($sev.ContainsKey('LOW'))      { $sev['LOW'] }      else { 0 }
  $unkTotal     = if ($sev.ContainsKey('UNKNOWN'))  { $sev['UNKNOWN'] }  else { 0 }

  # Critical / High split from the High/Critical findings table.
  $critical = @($Parsed.Findings | Where-Object { $_.Severity -eq 'CRITICAL' })
  $high     = @($Parsed.Findings | Where-Object { $_.Severity -eq 'HIGH' })

  # Per-tool counts of CRITICAL/HIGH (only what's in the table).
  $perToolCritical = @{}
  $perToolHigh     = @{}
  foreach ($f in $critical) {
    if (-not $perToolCritical.ContainsKey($f.Tool)) { $perToolCritical[$f.Tool] = 0 }
    $perToolCritical[$f.Tool]++
  }
  foreach ($f in $high) {
    if (-not $perToolHigh.ContainsKey($f.Tool)) { $perToolHigh[$f.Tool] = 0 }
    $perToolHigh[$f.Tool]++
  }

  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine("# Отчет по high/critical уязвимостям: $caseId")
  [void]$sb.AppendLine()
  [void]$sb.AppendLine("## Объект анализа")
  [void]$sb.AppendLine("- ``$archiveName``")
  [void]$sb.AppendLine("- SHA-256: ``$shaForHeader``")
  [void]$sb.AppendLine()
  [void]$sb.AppendLine("## Методика")
  [void]$sb.AppendLine("- Контейнерный прогон ``$RunnerName``.")
  if ($OnlineDb) {
    [void]$sb.AppendLine("- Локальные базы ``grype`` и ``cve-bin-tool`` с принудительным online-обновлением перед прогоном.")
  } else {
    [void]$sb.AppendLine("- Локальные базы ``grype`` и ``cve-bin-tool``, без online-обновления.")
  }
  [void]$sb.AppendLine("- Проверены ``summary.json``, ``status.json``, ``syft.json``, ``reports/grype/report.json``, ``reports/cve-bin-tool/report.json``.")
  if ($Parsed.DbSnapshot -and $Parsed.DbSnapshot -ne 'UNKNOWN') {
    [void]$sb.AppendLine("- DB snapshot: ``$($Parsed.DbSnapshot)``.")
  }
  if ($Parsed.DbDrift -and $Parsed.DbDrift -ne 'UNKNOWN') {
    [void]$sb.AppendLine("- DB drift: ``$($Parsed.DbDrift)``.")
  }
  if ($Parsed.ToolFailures -and $Parsed.ToolFailures -ne 'UNKNOWN') {
    [void]$sb.AppendLine("- Tool failures: ``$($Parsed.ToolFailures)``.")
  }
  [void]$sb.AppendLine()

  [void]$sb.AppendLine("## Что обнаружено")
  [void]$sb.AppendLine("- ``syft components=$($Parsed.SyftCount)``")
  [void]$sb.AppendLine("- ``grype matches=$($Parsed.GrypeCount)``")
  [void]$sb.AppendLine("- ``cve-bin-tool findings=$($Parsed.CveCount)``")
  if ($Parsed.TrivyCount -gt 0) {
    [void]$sb.AppendLine("- ``trivy findings=$($Parsed.TrivyCount)``")
  }
  [void]$sb.AppendLine("- ``severity totals``:")
  [void]$sb.AppendLine("  - ``CRITICAL=$critTotal``")
  [void]$sb.AppendLine("  - ``HIGH=$highTotal``")
  [void]$sb.AppendLine("  - ``MEDIUM=$medTotal``")
  [void]$sb.AppendLine("  - ``LOW=$lowTotal``")
  if ($unkTotal -gt 0) {
    [void]$sb.AppendLine("  - ``UNKNOWN=$unkTotal``")
  }
  [void]$sb.AppendLine()

  [void]$sb.AppendLine("## High / Critical")
  [void]$sb.AppendLine()

  # Critical block — list everything from the table where Severity=CRITICAL,
  # tool name appended (as in the reference doc).
  [void]$sb.AppendLine("### Critical")
  [void]$sb.AppendLine()
  if ($critical.Count -eq 0) {
    [void]$sb.AppendLine("- Critical-находок не зафиксировано.")
  } else {
    foreach ($row in $critical | Sort-Object Tool, 'CVE/GHSA') {
      [void]$sb.AppendLine((Render-Bullet -Row $row -IncludeTool))
    }
  }
  [void]$sb.AppendLine()

  # High block — group by tool, as in the reference doc.
  [void]$sb.AppendLine("### High")
  [void]$sb.AppendLine()

  $toolsForHigh = ($high | ForEach-Object { $_.Tool } | Sort-Object -Unique)
  if (-not $toolsForHigh) {
    [void]$sb.AppendLine("- High-находок не зафиксировано.")
    [void]$sb.AppendLine()
  } else {
    foreach ($tool in $toolsForHigh) {
      [void]$sb.AppendLine("#### ``$tool``")
      [void]$sb.AppendLine()
      $rows = @($high | Where-Object { $_.Tool -eq $tool } | Sort-Object 'CVE/GHSA', Product, Version)
      foreach ($row in $rows) {
        [void]$sb.AppendLine((Render-Bullet -Row $row))
      }
      [void]$sb.AppendLine()
    }
  }

  $tableSeverityTotal = $critical.Count + $high.Count
  $aggregateSeverityTotal = $critTotal + $highTotal
  if ($aggregateSeverityTotal -gt $tableSeverityTotal) {
    $extra = $aggregateSeverityTotal - $tableSeverityTotal
    [void]$sb.AppendLine("Примечание: ``severity totals`` показывает CRITICAL+HIGH=$aggregateSeverityTotal, тогда как уникальных записей в таблице — $tableSeverityTotal. Разница в $extra строки приходится на дубли по разным бинарям/локациям внутри одного bundle (deduplication по (id, product, version, tool)).")
    [void]$sb.AppendLine()
  }

  [void]$sb.AppendLine("## Практический вывод")
  if ($critTotal -gt 0 -or $highTotal -gt 0) {
    [void]$sb.AppendLine("- Для ``$caseId`` high/critical уязвимости подтверждены сканерами.")
    [void]$sb.AppendLine("- Перед допуском требуется ручной applicability review по каждой строке: проверить, что версия компонента и contextual exploitability действительно применимы к поставке.")
    [void]$sb.AppendLine("- Хранить вместе с этим digest-ом исходный ``$archiveName`` SHA-256 ``$shaForHeader`` и сканер-отчёт ``$(Split-Path -Leaf $Parsed.TargetDisplay)``.")
  } else {
    [void]$sb.AppendLine("- Для ``$caseId`` high/critical находок не зафиксировано в текущем прогоне.")
    [void]$sb.AppendLine("- Файл сохраняется как формальное подтверждение чистого результата на дату ``$ReportDate``.")
  }
  [void]$sb.AppendLine()

  return $sb.ToString()
}

function Process-One {
  param(
    [string]$TargetArchivePath,
    [string]$ReportPath,
    [string]$RunnerName,
    [switch]$OnlineDb,
    [string]$OutputDir
  )

  # Resolve report path if not provided.
  if (-not $ReportPath -and $TargetArchivePath) {
    $ReportPath = Get-LatestReport -TargetPath $TargetArchivePath
    if (-not $ReportPath) {
      Write-Host ("   ! не найден scan-отчёт рядом с " + $TargetArchivePath) -ForegroundColor Red
      return $null
    }
  }
  if (-not (Test-Path -LiteralPath $ReportPath)) {
    Write-Host ("   ! отсутствует " + $ReportPath) -ForegroundColor Red
    return $null
  }

  $parsed     = Parse-ScanReport -Path $ReportPath
  $reportDate = Get-ReportDate -ReportFileName (Split-Path -Leaf $ReportPath)
  $archiveSha = if ($TargetArchivePath) { Get-Sha256 -Path $TargetArchivePath } else { $null }

  $digest = Build-Digest `
              -Parsed $parsed `
              -TargetArchivePath $TargetArchivePath `
              -ArchiveSha $archiveSha `
              -ReportDate $reportDate `
              -RunnerName $RunnerName `
              -OnlineDb:$OnlineDb

  $base   = [IO.Path]::GetFileNameWithoutExtension($ReportPath) -replace '_report_\d{4}-\d{2}-\d{2}$',''
  $outDir = if ($OutputDir) { $OutputDir } else { Split-Path -LiteralPath $ReportPath -Parent }
  if (-not (Test-Path -LiteralPath $outDir)) { New-Item -Path $outDir -ItemType Directory -Force | Out-Null }
  $outPath = Join-Path $outDir ("${base}_high_critical_${reportDate}_ru.md")
  Set-Content -LiteralPath $outPath -Value $digest -Encoding UTF8
  Write-Host ("   high/critical digest -> " + $outPath) -ForegroundColor Green
  return $outPath
}

# ── Main dispatch ──────────────────────────────────────────────────────────
$produced = @()

switch ($PSCmdlet.ParameterSetName) {
  'Single' {
    if (-not $Target -and -not $ReportPath) {
      throw "Provide -Target <archive_path> or -ReportPath <markdown>."
    }
    $produced += (Process-One -TargetArchivePath $Target -ReportPath $ReportPath `
                              -RunnerName $Runner -OnlineDb:$OnlineDb -OutputDir $OutputDir)
  }
  'Batch' {
    foreach ($job in $Jobs) {
      $t = $job.Target ; if (-not $t) { $t = $job.target }
      if (-not $t) { continue }
      Write-Host ""
      Write-Host ("========== high/critical: " + (Split-Path -Leaf $t)) -ForegroundColor Cyan
      $produced += (Process-One -TargetArchivePath $t -RunnerName $Runner -OnlineDb:$OnlineDb -OutputDir $OutputDir)
    }
  }
}

# Done — emit a small summary so the user sees what was written.
Write-Host ""
Write-Host "=========== high/critical SUMMARY ===========" -ForegroundColor Cyan
foreach ($p in $produced) {
  if ($p) { Write-Host (" - " + $p) -ForegroundColor Green }
}
exit 0
