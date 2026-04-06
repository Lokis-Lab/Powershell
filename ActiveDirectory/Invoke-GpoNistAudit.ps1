<#
.SYNOPSIS
  NIST / Microsoft GPO Compliance Audit: download security baselines, build a master
  template, compare it against your domain GPOs, review diffs with risk-acceptance
  annotations, and export remediation packages.

.DESCRIPTION
  A six-stage Windows Forms wizard that covers the full GPO audit lifecycle:

  Stage 1 - Download Baselines
    Pulls the latest NIST/DISA STIG GPO package and the Microsoft Security Compliance
    Toolkit (SCT) baseline for Windows 11 and Windows Server.  Checks for cached copies
    so repeated runs do not re-download.  Extracts the ZIP archives into
    <OutDir>\Baselines\.

  Stage 2 - Build Master Template
    Parses every GPO XML in both baseline sets and normalises them into a flat list of
    settings (extension | category | key | value).  When the same key exists in both
    baselines the user chooses which source "wins" via a conflict-resolution grid.  The
    winning rows form the Master Template CSV.

  Stage 3 - Pull Domain GPOs
    Queries Active Directory and enumerates every OU / GPO link so the tree mirrors
    the layout in Group Policy Management Console.  GPO XML reports are exported and
    parsed the same way as the baselines.

  Stage 4 - Compare & Contrast
    Compares the Master Template against each top-level GPO and its OU children.
    Produces a colour-coded diff grid: missing settings (in template, not in GPO),
    extra settings (in GPO, not in template), and value mismatches.

  Stage 5 - Review Diff / Risk Acceptance
    Lets the reviewer de-select individual diff rows and attach a free-text justification
    ("Accepted Risk" comment).  Deselected rows are treated as accepted deviations and
    excluded from the export.

  Stage 6 - Export
    Writes an HTML compliance report, a PowerShell remediation script (Set-GPRegistryValue
    / Set-GPPermissions stubs), and a GPO backup folder that can be imported directly via
    Import-GPO.

.PARAMETER OutDir
  Root folder for all output.  Defaults to C:\Temp\GpoNistAudit.

.PARAMETER DomainDnsName
  Target AD domain DNS name.  Defaults to the machine's joined domain.

.PARAMETER SkipAfterHoursCheck
  By default the script warns (but does not block) if launched before 17:00.
  Supply this switch to suppress the check entirely.

.PARAMETER Mode
  Non-interactive entry point for automation:
    DownloadBaselines   - Step 1 only.
    BuildTemplate       - Step 2 only (requires already-downloaded baselines).
    PullDomainGpos      - Step 3 only.
    RunAudit            - Steps 1-6 fully automated, no GUI.

.EXAMPLES
  # Interactive wizard (default when no -Mode supplied)
  .\Invoke-GpoNistAudit.ps1

  # Automated full audit
  .\Invoke-GpoNistAudit.ps1 -Mode RunAudit -OutDir C:\Audits\2026-Q2

  # Refresh baselines only
  .\Invoke-GpoNistAudit.ps1 -Mode DownloadBaselines -OutDir C:\Audits\Baselines

.REQUIREMENTS
  - Windows PowerShell 5.1 or PowerShell 7+ (Windows edition)
  - RSAT Group Policy Management (GroupPolicy module)
  - RSAT Active Directory (ActiveDirectory module) for OU tree walk
  - Internet access for baseline downloads (or pre-cached ZIPs in <OutDir>\Baselines)
  - Run from an elevated ("Run as Administrator") PowerShell host

.NOTES
  Author:  Lokis-Lab
  License: MIT
  Version: 1.0.0
  This script is an original work and is not derived from any prior employer codebase.
  All design, parsing logic, and UI are written from scratch after hours.
#>

[CmdletBinding(DefaultParameterSetName = 'Gui')]
param(
  [Parameter(ParameterSetName = 'Gui')]
  [Parameter(ParameterSetName = 'Auto')]
  [string]$OutDir = 'C:\Temp\GpoNistAudit',

  [Parameter(ParameterSetName = 'Gui')]
  [Parameter(ParameterSetName = 'Auto')]
  [string]$DomainDnsName,

  [Parameter(ParameterSetName = 'Gui')]
  [Parameter(ParameterSetName = 'Auto')]
  [switch]$SkipAfterHoursCheck,

  [Parameter(ParameterSetName = 'Auto', Mandatory)]
  [ValidateSet('DownloadBaselines', 'BuildTemplate', 'PullDomainGpos', 'RunAudit')]
  [string]$Mode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================
# SECTION 0 — Constants & module bootstrap
# ============================================================

$script:VERSION          = '1.0.0'
$script:TITLE            = "NIST / Microsoft GPO Compliance Audit v$script:VERSION"
$script:AFTER_HOURS_WARN = 17   # warn if launched before 5 PM

# Baseline source catalogue.  Each entry drives Stage 1 download logic.
# Direct links may rotate when new releases are published; the script will
# fall back to the library page URL if the direct link returns a non-success
# HTTP status so the user can download manually.
$script:BASELINE_SOURCES = @(
  [pscustomobject]@{
    Name        = 'Microsoft SCT - Windows 11 v24H2'
    ShortName   = 'MS_Win11_v24H2'
    Vendor      = 'Microsoft'
    DirectUrl   = 'https://download.microsoft.com/download/sctools/Windows-11-v24H2-Security-Baseline.zip'
    FallbackUrl = 'https://aka.ms/SCT'
    FileName    = 'Windows-11-v24H2-Security-Baseline.zip'
  }
  [pscustomobject]@{
    Name        = 'Microsoft SCT - Windows Server 2025'
    ShortName   = 'MS_Server2025'
    Vendor      = 'Microsoft'
    DirectUrl   = 'https://download.microsoft.com/download/sctools/Windows-Server-2025-Security-Baseline.zip'
    FallbackUrl = 'https://aka.ms/SCT'
    FileName    = 'Windows-Server-2025-Security-Baseline.zip'
  }
  [pscustomobject]@{
    Name        = 'DISA STIG GPO Package (latest quarterly)'
    ShortName   = 'DISA_STIG_GPO'
    Vendor      = 'DISA'
    DirectUrl   = 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_STIG_GPO_Package_October_2025.zip'
    FallbackUrl = 'https://public.cyber.mil/stigs/gpo/'
    FileName    = 'U_STIG_GPO_Package_October_2025.zip'
  }
)

# Sentinel file dropped into each extracted baseline folder to record source metadata.
$script:BASELINE_META_FILE = '.gpo_nist_audit_meta.json'

# ============================================================
# SECTION 1 — Utility helpers
# ============================================================

function Write-NistLog {
  param(
    [Parameter(Mandatory)][string]$Message,
    [ValidateSet('Info', 'Warn', 'Error', 'Success')][string]$Level = 'Info'
  )
  $ts = (Get-Date).ToString('HH:mm:ss')
  $colour = switch ($Level) {
    'Warn'    { 'Yellow' }
    'Error'   { 'Red' }
    'Success' { 'Green' }
    default   { 'Cyan' }
  }
  Write-Host "[$ts] $Message" -ForegroundColor $colour
}

function Show-FatalError {
  param([Parameter(Mandatory)][string]$Message)
  Write-NistLog -Message $Message -Level Error
  try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    [System.Windows.Forms.MessageBox]::Show($Message, $script:TITLE, 'OK', 'Error') | Out-Null
  } catch {
    try { Read-Host 'Press Enter to exit' } catch { }
  }
  exit 1
}

trap {
  $msg = if ($_.Exception.Message) { $_.Exception.Message } else { "$_" }
  Show-FatalError $msg
}

function Ensure-Folder {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function New-SafeName {
  param([Parameter(Mandatory)][string]$InputString)
  $InputString -replace '[^\w\.-]+', '_'
}

function Get-Timestamp { (Get-Date).ToString('yyyyMMdd_HHmmss') }

function Test-AfterHours {
  (Get-Date).Hour -ge $script:AFTER_HOURS_WARN
}

function Confirm-AfterHoursOrContinue {
  if ($SkipAfterHoursCheck) { return }
  if (-not (Test-AfterHours)) {
    $now = (Get-Date).ToString('HH:mm')
    $msg = "It is currently $now.`n`nThis tool is designed to be run after 5 PM (17:00) to avoid disrupting production operations.`n`nContinue anyway?"
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    $r = [System.Windows.Forms.MessageBox]::Show(
      $msg, $script:TITLE, 'YesNo', 'Warning')
    if ($r -eq 'No') { exit 0 }
  }
}

# ============================================================
# SECTION 2 — Module bootstrap
# ============================================================

function Import-GroupPolicyModule {
  if (Get-Module -Name GroupPolicy -ErrorAction SilentlyContinue) { return }
  try {
    Import-Module GroupPolicy -ErrorAction Stop
  } catch {
    Show-FatalError "The GroupPolicy module is required.`nInstall RSAT: Group Policy Management and restart PowerShell.`n`n$($_.Exception.Message)"
  }
}

function Import-ActiveDirectoryModule {
  if (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue) { return }
  $m = Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue
  if (-not $m) {
    throw "The Active Directory PowerShell module (RSAT) is not available.`nInstall: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
  }
  Import-Module ActiveDirectory -ErrorAction Stop
}

function Initialize-AdContext {
  param([string]$DomainDns)
  Import-ActiveDirectoryModule
  if ([string]::IsNullOrWhiteSpace($DomainDns)) {
    $d = Get-ADDomain -ErrorAction Stop
  } else {
    $t = $DomainDns.Trim()
    $d = Get-ADDomain -Identity $t -Server $t -ErrorAction Stop
  }
  $script:AdDomainDns = $d.DNSRoot
  $script:AdServer    = if ($d.PDCEmulator) { $d.PDCEmulator } else { $d.DNSRoot }
  $script:AdDomainDN  = $d.DistinguishedName
}

$script:AdDomainDns = $null
$script:AdServer    = $null
$script:AdDomainDN  = $null

function Get-GpoDomainSplat {
  if ($script:AdDomainDns) { return @{ Domain = $script:AdDomainDns } }
  return @{}
}

# ============================================================
# SECTION 3 — Baseline download (Stage 1)
# ============================================================

function Get-BaselineFolder {
  param([Parameter(Mandatory)][string]$RootDir)
  Join-Path $RootDir 'Baselines'
}

function Get-BaselineSourceFolder {
  param(
    [Parameter(Mandatory)][string]$BaselineDir,
    [Parameter(Mandatory)][string]$ShortName
  )
  Join-Path $BaselineDir $ShortName
}

function Test-BaselineCached {
  <#
  .SYNOPSIS
    Returns $true when a previously extracted baseline folder contains the sentinel metadata file.
  #>
  param(
    [Parameter(Mandatory)][string]$BaselineDir,
    [Parameter(Mandatory)][object]$Source
  )
  $folder = Get-BaselineSourceFolder -BaselineDir $BaselineDir -ShortName $Source.ShortName
  $meta   = Join-Path $folder $script:BASELINE_META_FILE
  return (Test-Path -LiteralPath $meta)
}

function Get-BaselineCacheInfo {
  <#
  .SYNOPSIS
    Reads the metadata JSON from a cached baseline folder; returns $null if not present.
  #>
  param(
    [Parameter(Mandatory)][string]$BaselineDir,
    [Parameter(Mandatory)][object]$Source
  )
  $folder = Get-BaselineSourceFolder -BaselineDir $BaselineDir -ShortName $Source.ShortName
  $meta   = Join-Path $folder $script:BASELINE_META_FILE
  if (Test-Path -LiteralPath $meta) {
    try {
      return (Get-Content -LiteralPath $meta -Raw | ConvertFrom-Json)
    } catch { return $null }
  }
  return $null
}

function Invoke-DownloadBaseline {
  <#
  .SYNOPSIS
    Downloads and extracts a single baseline ZIP.  Writes a sentinel JSON file on success.
    Returns $true on success, $false on failure.
  #>
  param(
    [Parameter(Mandatory)][string]$BaselineDir,
    [Parameter(Mandatory)][object]$Source,
    [Parameter(Mandatory)][ref]$StatusMessage
  )

  $folder  = Get-BaselineSourceFolder -BaselineDir $BaselineDir -ShortName $Source.ShortName
  $zipPath = Join-Path $BaselineDir "$($Source.ShortName).zip"

  Ensure-Folder -Path $folder

  # Try direct URL, fall back gracefully
  $downloaded = $false
  foreach ($url in @($Source.DirectUrl, $Source.FallbackUrl)) {
    if ([string]::IsNullOrWhiteSpace($url)) { continue }
    try {
      Write-NistLog "Downloading: $($Source.Name) from $url"
      $wc = [System.Net.WebClient]::new()
      $wc.Headers.Add('User-Agent', "GpoNistAudit/$script:VERSION PowerShell/$($PSVersionTable.PSVersion)")
      $wc.DownloadFile($url, $zipPath)
      $downloaded = $true
      break
    } catch {
      Write-NistLog "Download attempt failed ($url): $($_.Exception.Message)" -Level Warn
    }
  }

  if (-not $downloaded) {
    $StatusMessage.Value = "FAILED: Could not download '$($Source.Name)'. Visit $($Source.FallbackUrl) and place the ZIP at: $zipPath, then re-run."
    return $false
  }

  # Extract
  try {
    Write-NistLog "Extracting $zipPath -> $folder"
    if (Get-Command Expand-Archive -ErrorAction SilentlyContinue) {
      Expand-Archive -LiteralPath $zipPath -DestinationPath $folder -Force
    } else {
      Add-Type -AssemblyName System.IO.Compression.FileSystem
      [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $folder)
    }
  } catch {
    $StatusMessage.Value = "FAILED: Could not extract '$($Source.Name)': $($_.Exception.Message)"
    return $false
  }

  # Write sentinel
  $meta = [pscustomobject]@{
    Name         = $Source.Name
    ShortName    = $Source.ShortName
    Vendor       = $Source.Vendor
    DownloadedAt = (Get-Date -Format 'o')
    SourceUrl    = $Source.DirectUrl
  }
  $meta | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $folder $script:BASELINE_META_FILE) -Encoding UTF8

  $StatusMessage.Value = "OK: $($Source.Name)"
  return $true
}

function Invoke-AllBaselineDownloads {
  <#
  .SYNOPSIS
    Iterates all baseline sources and downloads those not already cached.
    Returns a hashtable of ShortName -> status string.
  #>
  param(
    [Parameter(Mandatory)][string]$OutDir,
    [switch]$ForceRefresh
  )
  $baselineDir = Get-BaselineFolder -RootDir $OutDir
  Ensure-Folder -Path $baselineDir

  $results = [ordered]@{}
  foreach ($src in $script:BASELINE_SOURCES) {
    if (-not $ForceRefresh -and (Test-BaselineCached -BaselineDir $baselineDir -Source $src)) {
      $info = Get-BaselineCacheInfo -BaselineDir $baselineDir -Source $src
      $age  = if ($info -and $info.DownloadedAt) {
        $dl = [datetime]::Parse($info.DownloadedAt)
        "cached $(([datetime]::Now - $dl).Days)d ago"
      } else { 'cached' }
      Write-NistLog "Skipping '$($src.Name)' — $age" -Level Info
      $results[$src.ShortName] = "CACHED: $age"
      continue
    }
    $msg = [ref]''
    $ok  = Invoke-DownloadBaseline -BaselineDir $baselineDir -Source $src -StatusMessage $msg
    $results[$src.ShortName] = $msg.Value
    if ($ok) { Write-NistLog $msg.Value -Level Success }
    else      { Write-NistLog $msg.Value -Level Warn }
  }
  return $results
}

# ============================================================
# SECTION 4 — Baseline / GPO XML parsing → normalised rows
# ============================================================

function Get-XPathNodesSafe {
  param([Parameter(Mandatory)][xml]$Xml, [Parameter(Mandatory)][string]$XPath)
  try {
    $n = $Xml.SelectNodes($XPath)
    if ($null -eq $n) { return @() }
    return $n
  } catch { return @() }
}

function Get-FirstNodeText {
  param([Parameter(Mandatory)][System.Xml.XmlNode]$Node, [Parameter(Mandatory)][string]$XPath)
  try {
    $hit = $Node.SelectNodes($XPath) | Select-Object -First 1
    if ($hit) { return $hit.InnerText }
  } catch { }
  return $null
}

function Get-NodeScope {
  param([Parameter(Mandatory)][System.Xml.XmlNode]$Node)
  $blob = ($Node.OuterXml + ' ' + ($Node.ParentNode.OuterXml)) -replace '\s+', ' '
  if ($blob -match '(?i)\bcomputer\b') { return 'Computer' }
  if ($blob -match '(?i)\buser\b')     { return 'User' }
  return 'Both'
}

function New-SettingRow {
  param(
    [string]$SourceGpo,
    [string]$Scope,
    [string]$Extension,
    [string]$Category,
    [string]$SettingName,
    [string]$SettingValue,
    [string]$DataType,
    [string]$RegistryKey,
    [string]$ValueName
  )
  $key = "$Scope|$Extension|$Category|$SettingName"
  if ($RegistryKey) { $key = "$Scope|Registry|$RegistryKey|$ValueName" }
  [pscustomobject]@{
    SourceGpo    = $SourceGpo
    Scope        = $Scope
    Extension    = $Extension
    Category     = $Category
    SettingName  = $SettingName
    SettingValue = $SettingValue
    DataType     = $DataType
    RegistryKey  = $RegistryKey
    ValueName    = $ValueName
    NormKey      = $key
  }
}

function Convert-GpoXmlToRows {
  <#
  .SYNOPSIS
    Parses a Get-GPOReport XML (or SCT/STIG ADMX-backed GpoReport.xml) into normalised setting rows.
  #>
  param(
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)][string]$GpoName
  )
  $rows = [System.Collections.Generic.List[object]]::new()

  # --- Admin Template Policies ---
  foreach ($p in (Get-XPathNodesSafe -Xml $Xml -XPath "//*[local-name()='Policy']")) {
    $name  = if ($p.displayName) { $p.displayName } else { $p.name }
    $state = $p.state
    if (-not $state) { $state = Get-FirstNodeText -Node $p -XPath ".//*[local-name()='State']" }
    if (-not $state) { $state = Get-FirstNodeText -Node $p -XPath ".//*[local-name()='Value']" }
    $rows.Add( (New-SettingRow -SourceGpo $GpoName -Scope (Get-NodeScope $p) -Extension 'AdminTemplates' -Category 'Policy' -SettingName ([string]$name) -SettingValue ([string]$state) -DataType 'Policy') )
  }

  # --- Registry settings (ADMX registry, GPP registry) ---
  foreach ($r in (Get-XPathNodesSafe -Xml $Xml -XPath "//*[local-name()='RegistrySettings']//*[local-name()='Registry']")) {
    $props  = $r.SelectSingleNode(".//*[local-name()='Properties']")
    $key    = if ($r.key)       { $r.key }       elseif ($props) { $props.key }       else { '' }
    $vname  = if ($r.valueName) { $r.valueName }  elseif ($props) { $props.valueName } else { '' }
    $val    = if ($props) { $props.value } else { '' }
    $dtype  = if ($props) { $props.type }  else { '' }
    $rows.Add( (New-SettingRow -SourceGpo $GpoName -Scope (Get-NodeScope $r) -Extension 'Registry' -Category 'RegistryValue' -SettingName "$key\$vname" -SettingValue ([string]$val) -DataType ([string]$dtype) -RegistryKey ([string]$key) -ValueName ([string]$vname)) )
  }

  # --- Security Settings ---
  foreach ($s in (Get-XPathNodesSafe -Xml $Xml -XPath "//*[local-name()='SecuritySettings']")) {
    foreach ($leaf in $s.SelectNodes(".//*[not(*)]")) {
      if ($leaf.SelectSingleNode("ancestor::*[local-name()='AuditSetting']")) { continue }
      $v = $leaf.InnerText
      if ([string]::IsNullOrWhiteSpace($v)) { continue }
      $rows.Add( (New-SettingRow -SourceGpo $GpoName -Scope (Get-NodeScope $leaf) -Extension 'Security' -Category 'SecuritySetting' -SettingName $leaf.Name -SettingValue $v.Trim() -DataType 'SecuritySetting') )
    }
  }

  # --- Advanced Audit Policy ---
  foreach ($a in (Get-XPathNodesSafe -Xml $Xml -XPath "//*[local-name()='AuditSetting']")) {
    $sub = Get-FirstNodeText -Node $a -XPath ".//*[local-name()='SubcategoryName']"
    if (-not $sub) { try { $sub = $a.SubcategoryName } catch { $sub = '(unknown)' } }
    $inc = Get-FirstNodeText -Node $a -XPath ".//*[local-name()='InclusionSetting']"
    if (-not $inc) { try { $inc = $a.InclusionSetting } catch { $inc = $null } }
    $val = if ($inc) { $inc.Trim() } else { '' }
    $rows.Add( (New-SettingRow -SourceGpo $GpoName -Scope (Get-NodeScope $a) -Extension 'Security' -Category 'AdvancedAudit' -SettingName "Audit: $sub" -SettingValue $val -DataType 'AuditSetting') )
  }

  # --- Services ---
  foreach ($svc in (Get-XPathNodesSafe -Xml $Xml -XPath "//*[local-name()='NTServices']/*[local-name()='NTService']")) {
    $name = $svc.name
    $mode = Get-FirstNodeText -Node $svc -XPath ".//*[local-name()='StartupMode']"
    if (-not $mode) { $mode = $svc.startup }
    $rows.Add( (New-SettingRow -SourceGpo $GpoName -Scope (Get-NodeScope $svc) -Extension 'Security' -Category 'Service' -SettingName ([string]$name) -SettingValue ([string]$mode) -DataType 'Service') )
  }

  return $rows
}

function Get-AllBaselineXmlFiles {
  <#
  .SYNOPSIS
    Recursively finds all GPO report XML files under a baseline extraction folder.
    Looks for GpoReport.xml, *.xml under a 'GPOs' subfolder, etc.
  #>
  param([Parameter(Mandatory)][string]$SourceFolder)
  if (-not (Test-Path -LiteralPath $SourceFolder)) { return @() }
  # DISA/MS packages put GPO XML in various subfolders; gather all .xml that look like GPO reports
  $xmlFiles = Get-ChildItem -LiteralPath $SourceFolder -Recurse -Filter '*.xml' -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -gt 500 }
  return @($xmlFiles)
}

function Build-BaselineSettingsMap {
  <#
  .SYNOPSIS
    Parses all GPO XMLs from a single baseline source into a settings dictionary keyed by NormKey.
  #>
  param(
    [Parameter(Mandatory)][string]$BaselineDir,
    [Parameter(Mandatory)][object]$Source
  )
  $folder = Get-BaselineSourceFolder -BaselineDir $BaselineDir -ShortName $Source.ShortName
  $xmlFiles = Get-AllBaselineXmlFiles -SourceFolder $folder

  $map = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($f in $xmlFiles) {
    try {
      [xml]$x = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8
      $gpoName = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
      $rows = Convert-GpoXmlToRows -Xml $x -GpoName "$($Source.ShortName)\$gpoName"
      foreach ($r in $rows) {
        if (-not $map.ContainsKey($r.NormKey)) {
          $map[$r.NormKey] = $r
        }
      }
    } catch {
      Write-NistLog "Parse warning ($($f.Name)): $($_.Exception.Message)" -Level Warn
    }
  }
  return $map
}

# ============================================================
# SECTION 5 — Master Template build + conflict resolution
# ============================================================

function Invoke-BuildMasterTemplate {
  <#
  .SYNOPSIS
    Merges all downloaded baselines into a Master Template CSV.
    When the same NormKey appears in multiple sources, the winner is determined by
    $ConflictWinnerMap (ShortName -> 'Win') or defaults to the first vendor found.

    Returns the path to the Master Template CSV.
  #>
  param(
    [Parameter(Mandatory)][string]$OutDir,
    [hashtable]$ConflictWinnerMap   # NormKey -> winning ShortName; $null = auto (first)
  )

  $baselineDir = Get-BaselineFolder -RootDir $OutDir
  $templateDir = Join-Path $OutDir 'Templates'
  Ensure-Folder -Path $templateDir

  # Build per-source maps
  $sourceMaps = [ordered]@{}
  foreach ($src in $script:BASELINE_SOURCES) {
    if (-not (Test-BaselineCached -BaselineDir $baselineDir -Source $src)) {
      Write-NistLog "'$($src.Name)' not cached — run DownloadBaselines first." -Level Warn
      continue
    }
    Write-NistLog "Parsing baseline: $($src.Name)"
    $sourceMaps[$src.ShortName] = Build-BaselineSettingsMap -BaselineDir $baselineDir -Source $src
  }

  if ($sourceMaps.Count -eq 0) {
    throw "No baselines available.  Run Step 1 (Download Baselines) first."
  }

  # Gather all unique NormKeys
  $allKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($sm in $sourceMaps.Values) {
    foreach ($k in $sm.Keys) { [void]$allKeys.Add($k) }
  }

  $masterRows  = [System.Collections.Generic.List[object]]::new()
  $conflictLog = [System.Collections.Generic.List[object]]::new()

  foreach ($key in ($allKeys | Sort-Object)) {
    $candidates = [ordered]@{}
    foreach ($sname in $sourceMaps.Keys) {
      if ($sourceMaps[$sname].ContainsKey($key)) {
        $candidates[$sname] = $sourceMaps[$sname][$key]
      }
    }

    if ($candidates.Count -eq 1) {
      $winner = @($candidates.Values)[0]
      $winner | Add-Member -NotePropertyName TemplateSource -NotePropertyValue (@($candidates.Keys)[0]) -Force
      $masterRows.Add($winner)
      continue
    }

    # Conflict: multiple sources define this key
    $winnerName = $null
    if ($ConflictWinnerMap -and $ConflictWinnerMap.ContainsKey($key)) {
      $winnerName = $ConflictWinnerMap[$key]
    }
    if (-not $winnerName) {
      # Default: Microsoft wins over DISA if present, else first source
      if ($candidates.ContainsKey('MS_Win11_v24H2'))  { $winnerName = 'MS_Win11_v24H2' }
      elseif ($candidates.ContainsKey('MS_Server2025')) { $winnerName = 'MS_Server2025' }
      else { $winnerName = @($candidates.Keys)[0] }
    }

    $winRow = $candidates[$winnerName]
    $winRow | Add-Member -NotePropertyName TemplateSource -NotePropertyValue $winnerName -Force

    $loserValues = ($candidates.GetEnumerator() | Where-Object { $_.Key -ne $winnerName } |
      ForEach-Object { "$($_.Key)=$($_.Value.SettingValue)" }) -join '; '
    $conflictLog.Add([pscustomobject]@{
      NormKey      = $key
      Winner       = $winnerName
      WinnerValue  = $winRow.SettingValue
      LoserSources = $loserValues
    })

    $masterRows.Add($winRow)
  }

  $masterCsv   = Join-Path $templateDir "MasterTemplate_$(Get-Timestamp).csv"
  $conflictCsv = Join-Path $templateDir "ConflictLog_$(Get-Timestamp).csv"

  $masterRows  | Export-Csv -LiteralPath $masterCsv   -NoTypeInformation -Encoding UTF8
  $conflictLog | Export-Csv -LiteralPath $conflictCsv -NoTypeInformation -Encoding UTF8

  Write-NistLog "Master Template: $masterCsv ($($masterRows.Count) settings)" -Level Success
  Write-NistLog "Conflict Log:    $conflictCsv ($($conflictLog.Count) conflicts)" -Level Info

  return $masterCsv
}

# ============================================================
# SECTION 6 — AD OU hierarchy + domain GPO pull (Stage 3)
# ============================================================

function Get-OuGpoTree {
  <#
  .SYNOPSIS
    Walks AD and returns a list of OU nodes, each with a .LinkedGpos array.
    The tree mirrors GPMC's layout so children appear under their parent OU.
  #>
  param([string]$DomainDns)
  Initialize-AdContext -DomainDns $DomainDns
  Import-GroupPolicyModule

  $server  = $script:AdServer
  $domDns  = $script:AdDomainDns
  $domDN   = $script:AdDomainDN
  $gpoDom  = Get-GpoDomainSplat

  # All OUs + domain NC
  $allOus = @(Get-ADOrganizationalUnit -Filter * -Properties Name, DistinguishedName, canonicalName -Server $server -ErrorAction SilentlyContinue | Sort-Object DistinguishedName)

  # GPO link info: Get-ADDomain has LinkedGroupPolicyObjects on the domain NC
  $domainObj = Get-ADDomain -Server $server -ErrorAction Stop
  $domainGpoLinks = @($domainObj.LinkedGroupPolicyObjects)

  # Build GPO GUID -> GPO object map
  $allGpos = @(Get-GPO @gpoDom -All | Sort-Object DisplayName)
  $gpoById = @{}
  foreach ($g in $allGpos) { $gpoById[$g.Id.ToString().Trim('{}').ToUpperInvariant()] = $g }

  function Resolve-GpoGuids {
    param([string[]]$DistinguishedNames)
    $result = [System.Collections.Generic.List[object]]::new()
    foreach ($dn in $DistinguishedNames) {
      if ($dn -match '\{([A-F0-9\-]+)\}') {
        $guid = $Matches[1].ToUpperInvariant()
        if ($gpoById.ContainsKey($guid)) { $result.Add($gpoById[$guid]) }
      }
    }
    return $result
  }

  $treeNodes = [System.Collections.Generic.List[object]]::new()

  # Domain root node
  $rootGpos = Resolve-GpoGuids -DistinguishedNames $domainGpoLinks
  $treeNodes.Add([pscustomobject]@{
    Depth              = 0
    DN                 = $domDN
    DisplayPath        = $domDns
    Name               = $domDns
    ParentDN           = $null
    LinkedGpos         = $rootGpos
    IsOu               = $false
  })

  # Recursion helper: compute depth from domain NC
  function Get-OuDepth {
    param([string]$DN)
    $relative = $DN -replace [regex]::Escape(",$domDN"), ''
    ($relative -split ',').Count
  }

  foreach ($ou in $allOus) {
    $ouDn = $ou.DistinguishedName

    # Get GPO links for this OU
    $ouObj = Get-ADOrganizationalUnit -Identity $ouDn -Properties gpLink -Server $server -ErrorAction SilentlyContinue
    $ouLinks = @()
    if ($ouObj -and $ouObj.gpLink) {
      $raw = $ouObj.gpLink
      $ouLinks = [regex]::Matches($raw, '\[LDAP://cn=(\{[A-F0-9\-]+\})') |
        ForEach-Object { $_.Groups[1].Value }
    }
    $linked = Resolve-GpoGuids -DistinguishedNames $ouLinks

    # Parent DN
    $parentDN = $ouDn -replace '^[^,]+,', ''

    $treeNodes.Add([pscustomobject]@{
      Depth       = Get-OuDepth -DN $ouDn
      DN          = $ouDn
      DisplayPath = if ($ou.canonicalName) { $ou.canonicalName.TrimEnd('/') } else { $ouDn }
      Name        = $ou.Name
      ParentDN    = $parentDN
      LinkedGpos  = $linked
      IsOu        = $true
    })
  }

  return ($treeNodes | Sort-Object Depth, DisplayPath)
}

function Export-DomainGpoXmls {
  <#
  .SYNOPSIS
    Exports Get-GPOReport XML for every GPO in the domain, stored under <OutDir>\DomainGPOs\.
    Returns a hashtable of GPO.Id -> xml file path.
  #>
  param(
    [Parameter(Mandatory)][string]$OutDir,
    [int]$Throttle = 4
  )
  Import-GroupPolicyModule
  $gpoDom    = Get-GpoDomainSplat
  $gpoDir    = Join-Path $OutDir 'DomainGPOs'
  Ensure-Folder -Path $gpoDir

  $allGpos   = @(Get-GPO @gpoDom -All | Sort-Object DisplayName)
  $domDns    = $script:AdDomainDns
  $idToPath  = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)

  $hasPS7 = $PSVersionTable.PSVersion.Major -ge 7
  if ($hasPS7) {
    $results = $allGpos | ForEach-Object -Parallel {
      try {
        $safe = $_.DisplayName -replace '[^\w\.-]+', '_'
        $file = Join-Path $using:gpoDir "$safe.xml"
        $dp = @{}; if ($using:domDns) { $dp['Domain'] = $using:domDns }
        Get-GPOReport @dp -Name $_.DisplayName -ReportType XML -Path $file
        [pscustomobject]@{ Id = $_.Id.ToString(); Path = $file }
      } catch {
        Write-Warning "GPO export failed '$($_.DisplayName)': $($_.Exception.Message)"
        $null
      }
    } -ThrottleLimit $Throttle
    foreach ($r in ($results | Where-Object { $_ })) { $idToPath[$r.Id] = $r.Path }
  } else {
    foreach ($g in $allGpos) {
      try {
        $safe = New-SafeName $g.DisplayName
        $file = Join-Path $gpoDir "$safe.xml"
        Get-GPOReport @gpoDom -Name $g.DisplayName -ReportType XML -Path $file
        $idToPath[$g.Id.ToString()] = $file
      } catch {
        Write-Warning "GPO export failed '$($g.DisplayName)': $($_.Exception.Message)"
      }
    }
  }
  return $idToPath
}

# ============================================================
# SECTION 7 — Compliance comparison engine (Stage 4)
# ============================================================

function Compare-GpoAgainstTemplate {
  <#
  .SYNOPSIS
    Compares a parsed GPO's rows against the master template rows.
    Returns a list of diff objects with Status: Missing | Extra | Mismatch | Match.
  #>
  param(
    [Parameter(Mandatory)][object[]]$TemplateRows,
    [Parameter(Mandatory)][object[]]$GpoRows,
    [Parameter(Mandatory)][string]$GpoName
  )

  $templateMap = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($r in $TemplateRows) { $templateMap[$r.NormKey] = $r }

  $gpoMap = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($r in $GpoRows) { $gpoMap[$r.NormKey] = $r }

  $diffs = [System.Collections.Generic.List[object]]::new()

  foreach ($k in ($templateMap.Keys | Sort-Object)) {
    $tRow = $templateMap[$k]
    if ($gpoMap.ContainsKey($k)) {
      $gRow   = $gpoMap[$k]
      $status = if ([string]::Equals($tRow.SettingValue, $gRow.SettingValue, [StringComparison]::OrdinalIgnoreCase)) { 'Match' } else { 'Mismatch' }
      $diffs.Add([pscustomobject]@{
        GpoName          = $GpoName
        NormKey          = $k
        Scope            = $tRow.Scope
        Extension        = $tRow.Extension
        Category         = $tRow.Category
        SettingName      = $tRow.SettingName
        TemplateValue    = $tRow.SettingValue
        TemplateSource   = $tRow.TemplateSource
        GpoValue         = $gRow.SettingValue
        Status           = $status
        AcceptedRisk     = $false
        RiskJustification= ''
        Selected         = ($status -ne 'Match')
      })
    } else {
      $diffs.Add([pscustomobject]@{
        GpoName          = $GpoName
        NormKey          = $k
        Scope            = $tRow.Scope
        Extension        = $tRow.Extension
        Category         = $tRow.Category
        SettingName      = $tRow.SettingName
        TemplateValue    = $tRow.SettingValue
        TemplateSource   = $tRow.TemplateSource
        GpoValue         = '(not configured)'
        Status           = 'Missing'
        AcceptedRisk     = $false
        RiskJustification= ''
        Selected         = $true
      })
    }
  }

  foreach ($k in ($gpoMap.Keys | Sort-Object)) {
    if ($templateMap.ContainsKey($k)) { continue }
    $gRow = $gpoMap[$k]
    $diffs.Add([pscustomobject]@{
      GpoName          = $GpoName
      NormKey          = $k
      Scope            = $gRow.Scope
      Extension        = $gRow.Extension
      Category         = $gRow.Category
      SettingName      = $gRow.SettingName
      TemplateValue    = '(not in template)'
      TemplateSource   = ''
      GpoValue         = $gRow.SettingValue
      Status           = 'Extra'
      AcceptedRisk     = $false
      RiskJustification= ''
      Selected         = $false
    })
  }

  return $diffs
}

function Invoke-FullAuditCompare {
  <#
  .SYNOPSIS
    Loads master template CSV, loads domain GPO XMLs, and produces a combined diff list.
    Returns ordered hashtable: GpoDisplayName -> @(diffRows)
  #>
  param(
    [Parameter(Mandatory)][string]$OutDir,
    [Parameter(Mandatory)][string]$MasterTemplateCsv,
    [Parameter(Mandatory)][hashtable]$GpoIdToXmlPath
  )

  $templateRows = @(Import-Csv -LiteralPath $MasterTemplateCsv -Encoding UTF8)
  $results      = [ordered]@{}

  foreach ($entry in $GpoIdToXmlPath.GetEnumerator()) {
    $xmlPath = $entry.Value
    if (-not (Test-Path -LiteralPath $xmlPath)) { continue }
    try {
      [xml]$x = Get-Content -LiteralPath $xmlPath -Raw -Encoding UTF8
      # Use the GPO display name from the XML if available
      $gpoName = [System.IO.Path]::GetFileNameWithoutExtension($xmlPath) -replace '_', ' '
      $nameNode = $x.SelectSingleNode("//*[local-name()='Name']")
      if ($nameNode) { $gpoName = $nameNode.InnerText }

      $gpoRows = Convert-GpoXmlToRows -Xml $x -GpoName $gpoName
      $diffs   = Compare-GpoAgainstTemplate -TemplateRows $templateRows -GpoRows $gpoRows -GpoName $gpoName
      $results[$gpoName] = $diffs
    } catch {
      Write-NistLog "Compare failed for $xmlPath : $($_.Exception.Message)" -Level Warn
    }
  }
  return $results
}

# ============================================================
# SECTION 8 — Export: HTML report + remediation script (Stage 6)
# ============================================================

function Export-HtmlReport {
  param(
    [Parameter(Mandatory)][string]$OutDir,
    [Parameter(Mandatory)][ordered]$AuditResults,
    [Parameter(Mandatory)][string]$MasterTemplateCsv
  )
  $rptDir  = Join-Path $OutDir 'Reports'
  Ensure-Folder -Path $rptDir
  $rptFile = Join-Path $rptDir "GpoAuditReport_$(Get-Timestamp).html"

  $totalMissing  = 0; $totalMismatch = 0; $totalExtra = 0; $totalAccepted = 0
  foreach ($diffs in $AuditResults.Values) {
    foreach ($d in $diffs) {
      if ($d.AcceptedRisk) { $totalAccepted++ ; continue }
      switch ($d.Status) {
        'Missing'  { $totalMissing++ }
        'Mismatch' { $totalMismatch++ }
        'Extra'    { $totalExtra++ }
      }
    }
  }

  $sb = [System.Text.StringBuilder]::new()
  [void]$sb.Append(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>$($script:TITLE) - Report</title>
<style>
  body{font-family:Segoe UI,Arial,sans-serif;margin:20px;background:#f5f5f5;color:#222;}
  h1{color:#003366;}h2{color:#336699;border-bottom:2px solid #ccc;padding-bottom:4px;}
  table{border-collapse:collapse;width:100%;margin-bottom:24px;background:#fff;}
  th{background:#003366;color:#fff;padding:6px 10px;text-align:left;}
  td{padding:5px 10px;border:1px solid #ddd;vertical-align:top;font-size:0.85em;}
  tr:nth-child(even){background:#f0f4f8;}
  .Missing{color:#c0392b;font-weight:bold;}
  .Mismatch{color:#e67e22;font-weight:bold;}
  .Extra{color:#8e44ad;}
  .Match{color:#27ae60;}
  .Accepted{color:#7f8c8d;font-style:italic;}
  .summary-box{display:inline-block;padding:12px 20px;margin:8px;border-radius:6px;font-size:1.1em;font-weight:bold;color:#fff;}
  .red{background:#c0392b;}.orange{background:#e67e22;}.purple{background:#8e44ad;}.grey{background:#7f8c8d;}.green{background:#27ae60;}
</style>
</head>
<body>
<h1>$($script:TITLE)</h1>
<p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Template: $(Split-Path $MasterTemplateCsv -Leaf)</p>
<div>
  <span class="summary-box red">Missing: $totalMissing</span>
  <span class="summary-box orange">Mismatch: $totalMismatch</span>
  <span class="summary-box purple">Extra: $totalExtra</span>
  <span class="summary-box grey">Accepted Risk: $totalAccepted</span>
</div>
"@)

  foreach ($gpoName in $AuditResults.Keys) {
    $diffs = $AuditResults[$gpoName] | Where-Object { $_.Status -ne 'Match' }
    if (-not $diffs) { continue }
    [void]$sb.Append("<h2>GPO: $(([System.Web.HttpUtility]::HtmlEncode($gpoName)))</h2>`n")
    [void]$sb.Append("<table><tr><th>Status</th><th>Scope</th><th>Extension</th><th>Setting</th><th>Template Value</th><th>GPO Value</th><th>Template Source</th><th>Risk Notes</th></tr>`n")
    foreach ($d in ($diffs | Sort-Object Status, SettingName)) {
      $css  = if ($d.AcceptedRisk) { 'Accepted' } else { $d.Status }
      $stat = if ($d.AcceptedRisk) { "Accepted ($($d.Status))" } else { $d.Status }
      $just = if ($d.RiskJustification) { [System.Web.HttpUtility]::HtmlEncode($d.RiskJustification) } else { '' }
      [void]$sb.Append("<tr><td class='$css'>$stat</td><td>$($d.Scope)</td><td>$($d.Extension)</td>")
      [void]$sb.Append("<td>$([System.Web.HttpUtility]::HtmlEncode($d.SettingName))</td>")
      [void]$sb.Append("<td>$([System.Web.HttpUtility]::HtmlEncode($d.TemplateValue))</td>")
      [void]$sb.Append("<td>$([System.Web.HttpUtility]::HtmlEncode($d.GpoValue))</td>")
      [void]$sb.Append("<td>$([System.Web.HttpUtility]::HtmlEncode($d.TemplateSource))</td>")
      [void]$sb.Append("<td>$just</td></tr>`n")
    }
    [void]$sb.Append("</table>`n")
  }

  [void]$sb.Append("</body></html>")
  $sb.ToString() | Set-Content -LiteralPath $rptFile -Encoding UTF8
  Write-NistLog "HTML report: $rptFile" -Level Success
  return $rptFile
}

function Export-RemediationScript {
  <#
  .SYNOPSIS
    Generates a PowerShell script with Set-GPRegistryValue stubs for all non-accepted
    Missing / Mismatch diff rows that are registry-backed.
  #>
  param(
    [Parameter(Mandatory)][string]$OutDir,
    [Parameter(Mandatory)][ordered]$AuditResults
  )
  $rptDir  = Join-Path $OutDir 'Reports'
  Ensure-Folder -Path $rptDir
  $psFile  = Join-Path $rptDir "Remediation_$(Get-Timestamp).ps1"

  $lines = [System.Collections.Generic.List[string]]::new()
  $lines.Add('# Auto-generated GPO Remediation Script')
  $lines.Add("# Generated: $(Get-Date -Format 'o')")
  $lines.Add("# Review each Set-GPRegistryValue call before applying in production.`n")
  $lines.Add('$ErrorActionPreference = "Stop"')
  $lines.Add('# Requires: Import-Module GroupPolicy`n')

  foreach ($gpoName in $AuditResults.Keys) {
    $needFix = $AuditResults[$gpoName] | Where-Object {
      -not $_.AcceptedRisk -and $_.Status -in @('Missing','Mismatch') -and $_.RegistryKey
    }
    if (-not $needFix) { continue }
    $lines.Add("# --- GPO: $gpoName ---")
    foreach ($d in $needFix) {
      $lines.Add("Set-GPRegistryValue -Name '$gpoName' -Key '$($d.RegistryKey)' -ValueName '$($d.ValueName)' -Type String -Value '$($d.TemplateValue)'")
    }
    $lines.Add('')
  }

  $lines | Set-Content -LiteralPath $psFile -Encoding UTF8
  Write-NistLog "Remediation script: $psFile" -Level Success
  return $psFile
}

function Export-GpoBackup {
  <#
  .SYNOPSIS
    Backs up every domain GPO that has non-accepted findings to <OutDir>\GpoBackups\.
    Returns the backup root path.
  #>
  param(
    [Parameter(Mandatory)][string]$OutDir,
    [Parameter(Mandatory)][ordered]$AuditResults
  )
  Import-GroupPolicyModule
  $gpoDom  = Get-GpoDomainSplat
  $bakRoot = Join-Path $OutDir 'GpoBackups'
  Ensure-Folder -Path $bakRoot

  $gposToBackup = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($gpoName in $AuditResults.Keys) {
    $hasFinding = $AuditResults[$gpoName] | Where-Object { -not $_.AcceptedRisk -and $_.Status -ne 'Match' }
    if ($hasFinding) { [void]$gposToBackup.Add($gpoName) }
  }

  foreach ($gpoName in $gposToBackup) {
    $safeName = New-SafeName $gpoName
    $bakDir   = Join-Path $bakRoot $safeName
    Ensure-Folder -Path $bakDir
    try {
      Backup-GPO @gpoDom -Name $gpoName -Path $bakDir -ErrorAction Stop | Out-Null
      Write-NistLog "Backed up GPO: $gpoName -> $bakDir" -Level Success
    } catch {
      Write-NistLog "Backup failed for '$gpoName': $($_.Exception.Message)" -Level Warn
    }
  }
  return $bakRoot
}

# ============================================================
# SECTION 9 — Windows Forms GUI wizard
# ============================================================

function Show-NistAuditWizard {
  param(
    [Parameter(Mandatory)][string]$OutDir,
    [string]$DomainDns
  )

  Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
  Add-Type -AssemblyName System.Drawing        -ErrorAction Stop
  # For HTML encoding in the report
  Add-Type -AssemblyName System.Web            -ErrorAction SilentlyContinue

  # ---- Shared state ----
  $script:WizOutDir         = $OutDir
  $script:WizDomainDns      = $DomainDns
  $script:WizMasterCsvPath  = $null   # set after Stage 2
  $script:WizGpoIdToXml     = @{}     # set after Stage 3
  $script:WizOuTree         = @()     # set after Stage 3
  $script:WizAuditResults   = [ordered]@{}  # set after Stage 4
  $script:WizConflictMap    = @{}     # NormKey -> winning ShortName

  # ---- Palette ----
  $colBg     = [System.Drawing.Color]::FromArgb(245, 245, 245)
  $colHeader = [System.Drawing.Color]::FromArgb(0,   51,  102)
  $colAccent = [System.Drawing.Color]::FromArgb(51, 102, 153)
  $colWhite  = [System.Drawing.Color]::White
  $colRed    = [System.Drawing.Color]::FromArgb(192,  57,  43)
  $colOrange = [System.Drawing.Color]::FromArgb(230, 126,  34)
  $colGreen  = [System.Drawing.Color]::FromArgb( 39, 174,  96)
  $colGrey   = [System.Drawing.Color]::FromArgb(127, 140, 141)
  $font      = [System.Drawing.Font]::new('Segoe UI', 9)
  $fontBold  = [System.Drawing.Font]::new('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
  $fontH     = [System.Drawing.Font]::new('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)

  function New-Label {
    param([string]$Text, [int]$X, [int]$Y, [int]$W = 200, [int]$H = 22, [System.Drawing.Font]$F = $null)
    $l = [System.Windows.Forms.Label]::new()
    $l.Text     = $Text
    $l.Location = [System.Drawing.Point]::new($X, $Y)
    $l.Size     = [System.Drawing.Size]::new($W, $H)
    $l.Font     = if ($F) { $F } else { $font }
    return $l
  }

  function New-Button {
    param([string]$Text, [int]$X, [int]$Y, [int]$W = 120, [int]$H = 30, [System.Drawing.Color]$Bg = $colAccent)
    $b = [System.Windows.Forms.Button]::new()
    $b.Text            = $Text
    $b.Location        = [System.Drawing.Point]::new($X, $Y)
    $b.Size            = [System.Drawing.Size]::new($W, $H)
    $b.BackColor       = $Bg
    $b.ForeColor       = $colWhite
    $b.Font            = $fontBold
    $b.FlatStyle       = [System.Windows.Forms.FlatStyle]::Flat
    $b.FlatAppearance.BorderSize = 0
    return $b
  }

  function New-DataGrid {
    param([int]$X, [int]$Y, [int]$W, [int]$H)
    $dg = [System.Windows.Forms.DataGridView]::new()
    $dg.Location                  = [System.Drawing.Point]::new($X, $Y)
    $dg.Size                      = [System.Drawing.Size]::new($W, $H)
    $dg.AllowUserToAddRows        = $false
    $dg.AllowUserToDeleteRows     = $false
    $dg.ReadOnly                  = $false
    $dg.AutoSizeColumnsMode       = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
    $dg.SelectionMode             = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
    $dg.RowHeadersVisible         = $false
    $dg.BackgroundColor           = $colWhite
    $dg.BorderStyle               = [System.Windows.Forms.BorderStyle]::FixedSingle
    $dg.Font                      = $font
    $dg.ColumnHeadersDefaultCellStyle.BackColor = $colHeader
    $dg.ColumnHeadersDefaultCellStyle.ForeColor = $colWhite
    $dg.ColumnHeadersDefaultCellStyle.Font      = $fontBold
    $dg.EnableHeadersVisualStyles = $false
    return $dg
  }

  function New-RichText {
    param([int]$X, [int]$Y, [int]$W, [int]$H, [string]$Text = '')
    $rt = [System.Windows.Forms.RichTextBox]::new()
    $rt.Location   = [System.Drawing.Point]::new($X, $Y)
    $rt.Size       = [System.Drawing.Size]::new($W, $H)
    $rt.Font       = $font
    $rt.BackColor  = $colWhite
    $rt.BorderStyle= [System.Windows.Forms.BorderStyle]::FixedSingle
    $rt.Text       = $Text
    return $rt
  }

  # ================================================================
  # Main form + TabControl
  # ================================================================
  $mainForm = [System.Windows.Forms.Form]::new()
  $mainForm.Text            = $script:TITLE
  $mainForm.Size            = [System.Drawing.Size]::new(1200, 780)
  $mainForm.MinimumSize     = [System.Drawing.Size]::new(900, 640)
  $mainForm.StartPosition   = [System.Windows.Forms.FormStartPosition]::CenterScreen
  $mainForm.BackColor       = $colBg
  $mainForm.Font            = $font

  $tabs = [System.Windows.Forms.TabControl]::new()
  $tabs.Dock     = [System.Windows.Forms.DockStyle]::Fill
  $tabs.Font     = $fontBold
  $mainForm.Controls.Add($tabs)

  function New-Tab {
    param([string]$Title)
    $tp = [System.Windows.Forms.TabPage]::new($Title)
    $tp.BackColor = $colBg
    $tp.Padding   = [System.Windows.Forms.Padding]::new(10)
    $tabs.TabPages.Add($tp)
    return $tp
  }

  # ================================================================
  # Tab 1 — Download Baselines
  # ================================================================
  $tabDownload = New-Tab 'Step 1: Download Baselines'

  $lblDlTitle = New-Label -Text 'Download NIST / DISA / Microsoft Security Baselines' -X 10 -Y 10 -W 700 -H 28 -F $fontH
  $tabDownload.Controls.Add($lblDlTitle)

  $lblDlInfo = New-Label -Text 'Checks local cache first.  Only downloads if not already present (or if Force Refresh is checked).' -X 10 -Y 42 -W 780 -H 20
  $tabDownload.Controls.Add($lblDlInfo)

  $chkForce = [System.Windows.Forms.CheckBox]::new()
  $chkForce.Text     = 'Force re-download (ignore cache)'
  $chkForce.Location = [System.Drawing.Point]::new(10, 66)
  $chkForce.AutoSize = $true
  $tabDownload.Controls.Add($chkForce)

  $lblCacheDir = New-Label -Text "Cache folder: $OutDir\Baselines" -X 10 -Y 90 -W 800 -H 20
  $tabDownload.Controls.Add($lblCacheDir)

  # Status grid
  $dgDl = New-DataGrid -X 10 -Y 116 -W 1140 -H 200
  $tabDownload.Controls.Add($dgDl)
  $dgDl.Columns.Add('Source', 'Baseline Source') | Out-Null
  $dgDl.Columns.Add('Vendor', 'Vendor')          | Out-Null
  $dgDl.Columns.Add('Status', 'Status')          | Out-Null
  $dgDl.ReadOnly = $true

  foreach ($src in $script:BASELINE_SOURCES) {
    $baselineDir = Get-BaselineFolder -RootDir $OutDir
    $cached = Test-BaselineCached -BaselineDir $baselineDir -Source $src
    $status = if ($cached) { 'Cached' } else { 'Not downloaded' }
    $dgDl.Rows.Add($src.Name, $src.Vendor, $status) | Out-Null
  }

  $rtDlLog = New-RichText -X 10 -Y 326 -W 1140 -H 260 -Text 'Download log will appear here...'
  $tabDownload.Controls.Add($rtDlLog)

  $btnDownload = New-Button -Text 'Download / Refresh' -X 10 -Y 596 -W 160 -H 34 -Bg $colHeader
  $tabDownload.Controls.Add($btnDownload)

  $btnDownload.Add_Click({
    $rtDlLog.Text = ''
    $btnDownload.Enabled = $false
    $forceRefresh = $chkForce.Checked
    try {
      $results = Invoke-AllBaselineDownloads -OutDir $script:WizOutDir -ForceRefresh:$forceRefresh
      $dgDl.Rows.Clear()
      $i = 0
      foreach ($src in $script:BASELINE_SOURCES) {
        $st = if ($results.ContainsKey($src.ShortName)) { $results[$src.ShortName] } else { 'Skipped' }
        $dgDl.Rows.Add($src.Name, $src.Vendor, $st) | Out-Null
        $rtDlLog.AppendText("[$($src.ShortName)] $st`r`n")
        $i++
      }
      $rtDlLog.AppendText("`r`nDone. Proceed to Step 2.")
    } catch {
      $rtDlLog.AppendText("ERROR: $($_.Exception.Message)`r`n")
    } finally {
      $btnDownload.Enabled = $true
    }
  })

  # ================================================================
  # Tab 2 — Build Master Template
  # ================================================================
  $tabTemplate = New-Tab 'Step 2: Build Master Template'

  $tabTemplate.Controls.Add( (New-Label -Text 'Merge baselines into Master Template — resolve conflicts' -X 10 -Y 10 -W 700 -H 28 -F $fontH) )
  $tabTemplate.Controls.Add( (New-Label -Text 'Conflicts: same setting defined in multiple baselines. Choose which baseline wins for each conflict.' -X 10 -Y 42 -W 900 -H 20) )

  $btnScanConflicts = New-Button -Text 'Scan for Conflicts' -X 10 -Y 66 -W 160 -H 30 -Bg $colAccent
  $tabTemplate.Controls.Add($btnScanConflicts)

  $dgConflicts = New-DataGrid -X 10 -Y 108 -W 1140 -H 320
  $tabTemplate.Controls.Add($dgConflicts)
  $dgConflicts.Columns.Add('NormKey',      'Setting Key')     | Out-Null
  $dgConflicts.Columns.Add('SettingName',  'Setting Name')    | Out-Null

  # Dropdown column: which source wins
  $winnerCol            = [System.Windows.Forms.DataGridViewComboBoxColumn]::new()
  $winnerCol.HeaderText = 'Winning Source'
  $winnerCol.Name       = 'WinnerSource'
  $winnerCol.FlatStyle  = [System.Windows.Forms.FlatStyle]::Flat
  $dgConflicts.Columns.Add($winnerCol) | Out-Null

  $dgConflicts.Columns.Add('WinValue',    'Winning Value')  | Out-Null
  $dgConflicts.Columns.Add('LoserValues', 'Losing Values')  | Out-Null
  $dgConflicts.ReadOnly = $false

  $btnScanConflicts.Add_Click({
    $btnScanConflicts.Enabled = $false
    $dgConflicts.Rows.Clear()
    try {
      $baselineDir = Get-BaselineFolder -RootDir $script:WizOutDir
      $sourceMaps  = [ordered]@{}
      foreach ($src in $script:BASELINE_SOURCES) {
        if (Test-BaselineCached -BaselineDir $baselineDir -Source $src) {
          $sourceMaps[$src.ShortName] = Build-BaselineSettingsMap -BaselineDir $baselineDir -Source $src
        }
      }
      $allKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      foreach ($sm in $sourceMaps.Values) { foreach ($k in $sm.Keys) { [void]$allKeys.Add($k) } }

      $sourceNames = @($sourceMaps.Keys)
      # Populate combo items
      $winnerCol.Items.Clear()
      foreach ($sn in $sourceNames) { $winnerCol.Items.Add($sn) | Out-Null }

      foreach ($key in ($allKeys | Sort-Object)) {
        $cands = @{}
        foreach ($sn in $sourceNames) {
          if ($sourceMaps[$sn].ContainsKey($key)) { $cands[$sn] = $sourceMaps[$sn][$key] }
        }
        if ($cands.Count -lt 2) { continue }

        $defaultWinner = if ($cands.ContainsKey('MS_Win11_v24H2')) { 'MS_Win11_v24H2' }
                         elseif ($cands.ContainsKey('MS_Server2025')) { 'MS_Server2025' }
                         else { @($cands.Keys)[0] }

        $settingName = $cands[$defaultWinner].SettingName
        $winVal      = $cands[$defaultWinner].SettingValue
        $loserVals   = ($cands.GetEnumerator() | Where-Object { $_.Key -ne $defaultWinner } |
          ForEach-Object { "$($_.Key)=$($_.Value.SettingValue)" }) -join '; '

        $rowIdx = $dgConflicts.Rows.Add($key, $settingName, $defaultWinner, $winVal, $loserVals)
        # Keep the raw candidates in tag for recalc
        $dgConflicts.Rows[$rowIdx].Tag = $cands
      }

      if ($dgConflicts.Rows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('No conflicts found across baselines. Proceed to Build Template.', $script:TITLE, 'OK', 'Information') | Out-Null
      }
    } catch {
      [System.Windows.Forms.MessageBox]::Show("Error scanning conflicts: $($_.Exception.Message)", $script:TITLE, 'OK', 'Error') | Out-Null
    } finally {
      $btnScanConflicts.Enabled = $true
    }
  })

  # Recalc winning value when user changes the winner dropdown
  $dgConflicts.Add_CellValueChanged({
    param($s, $e)
    if ($e.ColumnIndex -lt 0 -or $e.RowIndex -lt 0) { return }
    if ($dgConflicts.Columns[$e.ColumnIndex].Name -ne 'WinnerSource') { return }
    $row   = $dgConflicts.Rows[$e.RowIndex]
    $cands = $row.Tag
    $sel   = [string]$row.Cells['WinnerSource'].Value
    if ($cands -and $cands.ContainsKey($sel)) {
      $row.Cells['WinValue'].Value = $cands[$sel].SettingValue
    }
  })

  $rtTemplateLog = New-RichText -X 10 -Y 440 -W 1140 -H 130 -Text ''
  $tabTemplate.Controls.Add($rtTemplateLog)

  $btnBuildTemplate = New-Button -Text 'Build Master Template' -X 10 -Y 580 -W 200 -H 34 -Bg $colHeader
  $tabTemplate.Controls.Add($btnBuildTemplate)

  $btnBuildTemplate.Add_Click({
    $btnBuildTemplate.Enabled = $false
    try {
      # Harvest conflict overrides from grid
      $conflictMap = @{}
      foreach ($row in $dgConflicts.Rows) {
        $key  = [string]$row.Cells['NormKey'].Value
        $win  = [string]$row.Cells['WinnerSource'].Value
        if ($key -and $win) { $conflictMap[$key] = $win }
      }
      $script:WizConflictMap  = $conflictMap
      $script:WizMasterCsvPath = Invoke-BuildMasterTemplate -OutDir $script:WizOutDir -ConflictWinnerMap $conflictMap
      $rtTemplateLog.Text = "Master Template built: $script:WizMasterCsvPath`r`nProceed to Step 3."
    } catch {
      $rtTemplateLog.Text = "ERROR: $($_.Exception.Message)"
    } finally {
      $btnBuildTemplate.Enabled = $true
    }
  })

  # ================================================================
  # Tab 3 — Pull Domain GPOs
  # ================================================================
  $tabPull = New-Tab 'Step 3: Pull Domain GPOs'
  $tabPull.Controls.Add( (New-Label -Text 'Connect to Active Directory and retrieve GPO tree' -X 10 -Y 10 -W 700 -H 28 -F $fontH) )

  $tabPull.Controls.Add( (New-Label -Text 'Domain DNS name (blank = this machine''s domain):' -X 10 -Y 46 -W 340 -H 20) )
  $txtDomain = [System.Windows.Forms.TextBox]::new()
  $txtDomain.Location = [System.Drawing.Point]::new(360, 43)
  $txtDomain.Size     = [System.Drawing.Size]::new(260, 22)
  $txtDomain.Text     = if ($DomainDns) { $DomainDns } else { '' }
  $tabPull.Controls.Add($txtDomain)

  $tvGpo = [System.Windows.Forms.TreeView]::new()
  $tvGpo.Location    = [System.Drawing.Point]::new(10, 80)
  $tvGpo.Size        = [System.Drawing.Size]::new(540, 540)
  $tvGpo.Font        = $font
  $tvGpo.BackColor   = $colWhite
  $tvGpo.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
  $tabPull.Controls.Add($tvGpo)

  $rtPullLog = New-RichText -X 560 -Y 80 -W 590 -H 400 -Text ''
  $tabPull.Controls.Add($rtPullLog)

  $btnPull = New-Button -Text 'Pull GPO Tree' -X 10 -Y 630 -W 160 -H 34 -Bg $colHeader
  $tabPull.Controls.Add($btnPull)

  $btnPull.Add_Click({
    $btnPull.Enabled = $false
    $tvGpo.Nodes.Clear()
    $rtPullLog.Text = 'Connecting to AD...'
    try {
      $script:WizDomainDns = $txtDomain.Text.Trim()
      Initialize-AdContext -DomainDns $script:WizDomainDns
      $rtPullLog.AppendText("`r`nDomain: $script:AdDomainDns / Server: $script:AdServer")

      $script:WizOuTree    = @(Get-OuGpoTree -DomainDns $script:WizDomainDns)
      $script:WizGpoIdToXml = Export-DomainGpoXmls -OutDir $script:WizOutDir

      # Build tree UI
      $nodesByDn = @{}
      foreach ($n in $script:WizOuTree) {
        $gpoCount  = if ($n.LinkedGpos) { $n.LinkedGpos.Count } else { 0 }
        $nodeText  = "$($n.Name)  [$gpoCount GPO(s)]"
        $tvNode    = [System.Windows.Forms.TreeNode]::new($nodeText)
        $tvNode.Tag = $n

        foreach ($gpo in $n.LinkedGpos) {
          $tvNode.Nodes.Add( [System.Windows.Forms.TreeNode]::new("  GPO: $($gpo.DisplayName)") ) | Out-Null
        }
        $nodesByDn[$n.DN] = $tvNode
      }

      # Wire parent/child
      $root = $null
      foreach ($n in $script:WizOuTree) {
        $tvNode = $nodesByDn[$n.DN]
        if ($null -eq $n.ParentDN -or -not $nodesByDn.ContainsKey($n.ParentDN)) {
          $tvGpo.Nodes.Add($tvNode) | Out-Null
          if ($null -eq $root) { $root = $tvNode }
        } else {
          $nodesByDn[$n.ParentDN].Nodes.Add($tvNode) | Out-Null
        }
      }
      $tvGpo.ExpandAll()
      $rtPullLog.AppendText("`r`n`r`nOU nodes: $($script:WizOuTree.Count)")
      $rtPullLog.AppendText("`r`nGPO XMLs exported: $($script:WizGpoIdToXml.Count)")
      $rtPullLog.AppendText("`r`n`r`nProceed to Step 4.")
    } catch {
      $rtPullLog.AppendText("`r`nERROR: $($_.Exception.Message)")
    } finally {
      $btnPull.Enabled = $true
    }
  })

  # ================================================================
  # Tab 4 — Compare & Contrast
  # ================================================================
  $tabCompare = New-Tab 'Step 4: Compare & Contrast'
  $tabCompare.Controls.Add( (New-Label -Text 'Compare Master Template vs. Domain GPOs' -X 10 -Y 10 -W 700 -H 28 -F $fontH) )
  $tabCompare.Controls.Add( (New-Label -Text 'Select a GPO in the tree then click "Compare Selected GPO" — or run all at once.' -X 10 -Y 42 -W 900 -H 20) )

  # Left: OU/GPO tree (re-populated from step 3 data)
  $tvCmp = [System.Windows.Forms.TreeView]::new()
  $tvCmp.Location    = [System.Drawing.Point]::new(10, 70)
  $tvCmp.Size        = [System.Drawing.Size]::new(280, 560)
  $tvCmp.Font        = $font
  $tvCmp.BackColor   = $colWhite
  $tvCmp.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
  $tabCompare.Controls.Add($tvCmp)

  $dgDiff = New-DataGrid -X 300 -Y 70 -W 860 -H 400
  $tabCompare.Controls.Add($dgDiff)
  $dgDiff.Columns.Add('Status',       'Status')        | Out-Null
  $dgDiff.Columns.Add('Scope',        'Scope')         | Out-Null
  $dgDiff.Columns.Add('Extension',    'Extension')     | Out-Null
  $dgDiff.Columns.Add('Category',     'Category')      | Out-Null
  $dgDiff.Columns.Add('SettingName',  'Setting')       | Out-Null
  $dgDiff.Columns.Add('TemplateValue','Template Value') | Out-Null
  $dgDiff.Columns.Add('GpoValue',     'GPO Value')     | Out-Null
  $dgDiff.Columns.Add('Source',       'Template Source')| Out-Null
  $dgDiff.ReadOnly = $true

  $rtCmpStats = New-RichText -X 300 -Y 480 -W 860 -H 100 -Text ''
  $tabCompare.Controls.Add($rtCmpStats)

  $btnCompareAll = New-Button -Text 'Compare All GPOs' -X 10 -Y 638 -W 160 -H 34 -Bg $colHeader
  $tabCompare.Controls.Add($btnCompareAll)

  $btnCompareSelected = New-Button -Text 'Compare Selected' -X 180 -Y 638 -W 160 -H 34 -Bg $colAccent
  $tabCompare.Controls.Add($btnCompareSelected)

  function Populate-CompareTree {
    $tvCmp.Nodes.Clear()
    $nodesByDn = @{}
    foreach ($n in $script:WizOuTree) {
      $gpoCount = if ($n.LinkedGpos) { $n.LinkedGpos.Count } else { 0 }
      $tvNode = [System.Windows.Forms.TreeNode]::new("$($n.Name) [$gpoCount]")
      $tvNode.Tag = $n
      foreach ($gpo in $n.LinkedGpos) {
        $child = [System.Windows.Forms.TreeNode]::new("GPO: $($gpo.DisplayName)")
        $child.Tag = $gpo
        $tvNode.Nodes.Add($child) | Out-Null
      }
      $nodesByDn[$n.DN] = $tvNode
    }
    foreach ($n in $script:WizOuTree) {
      $tvNode = $nodesByDn[$n.DN]
      if ($null -eq $n.ParentDN -or -not $nodesByDn.ContainsKey($n.ParentDN)) {
        $tvCmp.Nodes.Add($tvNode) | Out-Null
      } else {
        $nodesByDn[$n.ParentDN].Nodes.Add($tvNode) | Out-Null
      }
    }
    $tvCmp.ExpandAll()
  }

  function Show-DiffInGrid {
    param([object[]]$Diffs)
    $dgDiff.Rows.Clear()
    $missing = 0; $mismatch = 0; $extra = 0; $match = 0
    foreach ($d in ($Diffs | Where-Object { $_.Status -ne 'Match' })) {
      $row = $dgDiff.Rows.Add($d.Status, $d.Scope, $d.Extension, $d.Category, $d.SettingName, $d.TemplateValue, $d.GpoValue, $d.TemplateSource)
      $colour = switch ($d.Status) {
        'Missing'  { $colRed }
        'Mismatch' { $colOrange }
        'Extra'    { [System.Drawing.Color]::FromArgb(142,68,173) }
        default    { $colGreen }
      }
      $dgDiff.Rows[$row].DefaultCellStyle.ForeColor = $colour
      switch ($d.Status) { 'Missing' { $missing++ } 'Mismatch' { $mismatch++ } 'Extra' { $extra++ } 'Match' { $match++ } }
    }
    $rtCmpStats.Text = "Missing: $missing  |  Mismatch: $mismatch  |  Extra: $extra  |  Total shown (non-match): $($missing + $mismatch + $extra)"
  }

  $btnCompareAll.Add_Click({
    $btnCompareAll.Enabled = $false
    try {
      if (-not $script:WizMasterCsvPath) { throw 'No Master Template found.  Complete Step 2 first.' }
      if ($script:WizGpoIdToXml.Count -eq 0) { throw 'No domain GPOs found.  Complete Step 3 first.' }
      $script:WizAuditResults = Invoke-FullAuditCompare -OutDir $script:WizOutDir -MasterTemplateCsv $script:WizMasterCsvPath -GpoIdToXmlPath $script:WizGpoIdToXml
      Populate-CompareTree
      # Show aggregate diff
      $allDiffs = [System.Collections.Generic.List[object]]::new()
      foreach ($v in $script:WizAuditResults.Values) { foreach ($d in $v) { $allDiffs.Add($d) } }
      Show-DiffInGrid -Diffs $allDiffs
    } catch {
      $rtCmpStats.Text = "ERROR: $($_.Exception.Message)"
    } finally {
      $btnCompareAll.Enabled = $true
    }
  })

  $tvCmp.Add_NodeMouseClick({
    param($s, $e)
    $tag = $e.Node.Tag
    if ($null -eq $tag) { return }
    # Is it a GPO object?
    if ($tag -is [Microsoft.GroupPolicy.Gpo] -or ($tag.PSObject.Properties['DisplayName'] -and -not $tag.PSObject.Properties['LinkedGpos'])) {
      $gpoName = [string]$tag.DisplayName
      if ($script:WizAuditResults.ContainsKey($gpoName)) {
        Show-DiffInGrid -Diffs $script:WizAuditResults[$gpoName]
      }
    }
  })

  $btnCompareSelected.Add_Click({
    $node = $tvCmp.SelectedNode
    if ($null -eq $node) {
      [System.Windows.Forms.MessageBox]::Show('Select a GPO node in the tree first.', $script:TITLE, 'OK', 'Information') | Out-Null
      return
    }
    $tag = $node.Tag
    $gpoName = if ($tag -and $tag.PSObject.Properties['DisplayName']) { [string]$tag.DisplayName } else { $null }
    if (-not $gpoName) { return }

    if (-not $script:WizMasterCsvPath) {
      [System.Windows.Forms.MessageBox]::Show('No Master Template found.  Complete Step 2 first.', $script:TITLE, 'OK', 'Warning') | Out-Null
      return
    }

    # Find the xml for this gpo
    $xmlPath = $script:WizGpoIdToXml.Values | Where-Object {
      [System.IO.Path]::GetFileNameWithoutExtension($_) -replace '_',' ' -eq $gpoName -or
      [System.IO.Path]::GetFileNameWithoutExtension($_) -eq (New-SafeName $gpoName)
    } | Select-Object -First 1

    if (-not $xmlPath) {
      $rtCmpStats.Text = "No exported XML found for GPO: $gpoName"
      return
    }

    try {
      $templateRows = @(Import-Csv -LiteralPath $script:WizMasterCsvPath -Encoding UTF8)
      [xml]$x = Get-Content -LiteralPath $xmlPath -Raw -Encoding UTF8
      $gpoRows = Convert-GpoXmlToRows -Xml $x -GpoName $gpoName
      $diffs   = Compare-GpoAgainstTemplate -TemplateRows $templateRows -GpoRows $gpoRows -GpoName $gpoName
      $script:WizAuditResults[$gpoName] = $diffs
      Show-DiffInGrid -Diffs $diffs
    } catch {
      $rtCmpStats.Text = "ERROR: $($_.Exception.Message)"
    }
  })

  # ================================================================
  # Tab 5 — Review Diff / Risk Acceptance
  # ================================================================
  $tabRisk = New-Tab 'Step 5: Risk Acceptance'
  $tabRisk.Controls.Add( (New-Label -Text 'Review findings — de-select to mark as Accepted Risk' -X 10 -Y 10 -W 700 -H 28 -F $fontH) )
  $tabRisk.Controls.Add( (New-Label -Text 'Un-check any finding you are accepting as a risk, then enter a justification.  Accepted rows are excluded from the export.' -X 10 -Y 42 -W 1000 -H 20) )

  # GPO selector
  $tabRisk.Controls.Add( (New-Label -Text 'GPO:' -X 10 -Y 68 -W 50 -H 22) )
  $cbRiskGpo = [System.Windows.Forms.ComboBox]::new()
  $cbRiskGpo.Location     = [System.Drawing.Point]::new(65, 65)
  $cbRiskGpo.Size         = [System.Drawing.Size]::new(420, 22)
  $cbRiskGpo.DropDownStyle= [System.Windows.Forms.ComboBoxStyle]::DropDownList
  $tabRisk.Controls.Add($cbRiskGpo)

  # Risk acceptance grid: checkbox | Status | Setting | TemplateValue | GpoValue | Justification
  $dgRisk = New-DataGrid -X 10 -Y 96 -W 1140 -H 440
  $dgRisk.ReadOnly   = $false
  $dgRisk.EditMode   = [System.Windows.Forms.DataGridViewEditMode]::EditOnKeystrokeOrF2
  $tabRisk.Controls.Add($dgRisk)

  $chkCol            = [System.Windows.Forms.DataGridViewCheckBoxColumn]::new()
  $chkCol.HeaderText = 'Remediate?'
  $chkCol.Name       = 'Remediate'
  $chkCol.Width      = 80
  $dgRisk.Columns.Add($chkCol) | Out-Null
  $dgRisk.Columns.Add('RStatus',      'Status')         | Out-Null
  $dgRisk.Columns.Add('RScope',       'Scope')          | Out-Null
  $dgRisk.Columns.Add('RSettingName', 'Setting')        | Out-Null
  $dgRisk.Columns.Add('RTplValue',    'Template Value') | Out-Null
  $dgRisk.Columns.Add('RGpoValue',    'GPO Value')      | Out-Null

  $justCol            = [System.Windows.Forms.DataGridViewTextBoxColumn]::new()
  $justCol.HeaderText = 'Accepted Risk Justification'
  $justCol.Name       = 'Justification'
  $justCol.MinimumWidth = 200
  $dgRisk.Columns.Add($justCol) | Out-Null

  # Read-only for all except Remediate + Justification
  foreach ($col in $dgRisk.Columns) {
    if ($col.Name -notin @('Remediate','Justification')) { $col.ReadOnly = $true }
  }

  $cbRiskGpo.Add_SelectedIndexChanged({
    $gpoName = [string]$cbRiskGpo.SelectedItem
    $dgRisk.Rows.Clear()
    if (-not $gpoName -or -not $script:WizAuditResults.ContainsKey($gpoName)) { return }
    foreach ($d in ($script:WizAuditResults[$gpoName] | Where-Object { $_.Status -ne 'Match' })) {
      $rowIdx = $dgRisk.Rows.Add(
        (-not $d.AcceptedRisk),  # Remediate = true means NOT accepted risk
        $d.Status,
        $d.Scope,
        $d.SettingName,
        $d.TemplateValue,
        $d.GpoValue,
        $d.RiskJustification
      )
      $dgRisk.Rows[$rowIdx].Tag = $d
      $colour = switch ($d.Status) {
        'Missing'  { $colRed }
        'Mismatch' { $colOrange }
        'Extra'    { [System.Drawing.Color]::FromArgb(142,68,173) }
        default    { $colGreen }
      }
      $dgRisk.Rows[$rowIdx].DefaultCellStyle.ForeColor = $colour
    }
  })

  $btnRiskLoad = New-Button -Text 'Load GPO Findings' -X 500 -Y 62 -W 160 -H 30 -Bg $colAccent
  $tabRisk.Controls.Add($btnRiskLoad)
  $btnRiskLoad.Add_Click({
    $cbRiskGpo.Items.Clear()
    foreach ($gpoName in $script:WizAuditResults.Keys) {
      $hasFinding = $script:WizAuditResults[$gpoName] | Where-Object { $_.Status -ne 'Match' }
      if ($hasFinding) { $cbRiskGpo.Items.Add($gpoName) | Out-Null }
    }
    if ($cbRiskGpo.Items.Count -gt 0) { $cbRiskGpo.SelectedIndex = 0 }
    else { [System.Windows.Forms.MessageBox]::Show('No findings to review. Run Step 4 first.', $script:TITLE, 'OK', 'Information') | Out-Null }
  })

  $btnSaveRisk = New-Button -Text 'Save Risk Decisions' -X 10 -Y 548 -W 180 -H 34 -Bg $colHeader
  $tabRisk.Controls.Add($btnSaveRisk)

  $lblRiskSaved = New-Label -Text '' -X 200 -Y 556 -W 600 -H 22
  $lblRiskSaved.ForeColor = $colGreen
  $tabRisk.Controls.Add($lblRiskSaved)

  $btnSaveRisk.Add_Click({
    $gpoName = [string]$cbRiskGpo.SelectedItem
    if (-not $gpoName -or -not $script:WizAuditResults.ContainsKey($gpoName)) { return }
    $saved = 0
    foreach ($row in $dgRisk.Rows) {
      $d = $row.Tag
      if ($null -eq $d) { continue }
      $remediate = [bool]$row.Cells['Remediate'].Value
      $just      = [string]$row.Cells['Justification'].Value
      $d.AcceptedRisk      = -not $remediate
      $d.RiskJustification = $just
      $saved++
    }
    $lblRiskSaved.Text = "Saved decisions for $saved rows in '$gpoName'."
  })

  # ================================================================
  # Tab 6 — Export
  # ================================================================
  $tabExport = New-Tab 'Step 6: Export'
  $tabExport.Controls.Add( (New-Label -Text 'Export Report, Remediation Script, and GPO Backups' -X 10 -Y 10 -W 700 -H 28 -F $fontH) )
  $tabExport.Controls.Add( (New-Label -Text 'Select what to export, then click Export.' -X 10 -Y 42 -W 700 -H 20) )

  $chkExportHtml = [System.Windows.Forms.CheckBox]::new(); $chkExportHtml.Text = 'HTML Compliance Report'; $chkExportHtml.Location = [System.Drawing.Point]::new(10, 66); $chkExportHtml.AutoSize = $true; $chkExportHtml.Checked = $true; $tabExport.Controls.Add($chkExportHtml)
  $chkExportPs   = [System.Windows.Forms.CheckBox]::new(); $chkExportPs.Text   = 'PowerShell Remediation Script'; $chkExportPs.Location = [System.Drawing.Point]::new(10, 90); $chkExportPs.AutoSize = $true; $chkExportPs.Checked = $true; $tabExport.Controls.Add($chkExportPs)
  $chkExportBak  = [System.Windows.Forms.CheckBox]::new(); $chkExportBak.Text  = 'GPO Backups (Backup-GPO for affected GPOs)'; $chkExportBak.Location = [System.Drawing.Point]::new(10, 114); $chkExportBak.AutoSize = $true; $chkExportBak.Checked = $true; $tabExport.Controls.Add($chkExportBak)
  $chkOpenFolder = [System.Windows.Forms.CheckBox]::new(); $chkOpenFolder.Text = 'Open output folder when done'; $chkOpenFolder.Location = [System.Drawing.Point]::new(10, 138); $chkOpenFolder.AutoSize = $true; $chkOpenFolder.Checked = $true; $tabExport.Controls.Add($chkOpenFolder)

  $rtExportLog = New-RichText -X 10 -Y 170 -W 1140 -H 400 -Text ''
  $tabExport.Controls.Add($rtExportLog)

  $btnExport = New-Button -Text 'Export' -X 10 -Y 580 -W 160 -H 34 -Bg $colHeader
  $tabExport.Controls.Add($btnExport)

  $btnExport.Add_Click({
    $btnExport.Enabled = $false
    $rtExportLog.Text  = ''
    try {
      if ($script:WizAuditResults.Count -eq 0) { throw 'No audit results.  Complete Steps 3 & 4 first.' }

      if ($chkExportHtml.Checked) {
        Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
        $f = Export-HtmlReport -OutDir $script:WizOutDir -AuditResults $script:WizAuditResults -MasterTemplateCsv $script:WizMasterCsvPath
        $rtExportLog.AppendText("HTML Report: $f`r`n")
      }
      if ($chkExportPs.Checked) {
        $f = Export-RemediationScript -OutDir $script:WizOutDir -AuditResults $script:WizAuditResults
        $rtExportLog.AppendText("Remediation Script: $f`r`n")
      }
      if ($chkExportBak.Checked) {
        $f = Export-GpoBackup -OutDir $script:WizOutDir -AuditResults $script:WizAuditResults
        $rtExportLog.AppendText("GPO Backups folder: $f`r`n")
      }

      $rtExportLog.AppendText("`r`nAll exports complete.")
      if ($chkOpenFolder.Checked) {
        Start-Process explorer.exe -ArgumentList $script:WizOutDir
      }
    } catch {
      $rtExportLog.AppendText("ERROR: $($_.Exception.Message)")
    } finally {
      $btnExport.Enabled = $true
    }
  })

  # ================================================================
  # Show wizard
  # ================================================================
  Confirm-AfterHoursOrContinue
  [System.Windows.Forms.Application]::Run($mainForm)
}

# ============================================================
# SECTION 10 — Non-interactive (automation) entry points
# ============================================================

function Invoke-RunAuditHeadless {
  param([string]$OutDir, [string]$DomainDns)
  Write-NistLog 'Starting headless full audit run' -Level Info
  Ensure-Folder -Path $OutDir

  # Step 1
  Invoke-AllBaselineDownloads -OutDir $OutDir | Out-Null

  # Step 2
  $masterCsv = Invoke-BuildMasterTemplate -OutDir $OutDir -ConflictWinnerMap $null

  # Step 3
  Initialize-AdContext -DomainDns $DomainDns
  $gpoIdToXml = Export-DomainGpoXmls -OutDir $OutDir

  # Step 4
  $results = Invoke-FullAuditCompare -OutDir $OutDir -MasterTemplateCsv $masterCsv -GpoIdToXmlPath $gpoIdToXml

  # Steps 5 + 6 (no risk acceptance in headless mode)
  Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
  Export-HtmlReport        -OutDir $OutDir -AuditResults $results -MasterTemplateCsv $masterCsv | Out-Null
  Export-RemediationScript -OutDir $OutDir -AuditResults $results | Out-Null
  Export-GpoBackup         -OutDir $OutDir -AuditResults $results | Out-Null

  Write-NistLog "Headless audit complete.  Output: $OutDir" -Level Success
}

# ============================================================
# SECTION 11 — Entry point dispatcher
# ============================================================

Ensure-Folder -Path $OutDir

switch ($Mode) {
  'DownloadBaselines' {
    Import-GroupPolicyModule
    Invoke-AllBaselineDownloads -OutDir $OutDir | Out-Null
  }
  'BuildTemplate' {
    Invoke-BuildMasterTemplate -OutDir $OutDir -ConflictWinnerMap $null | Out-Null
  }
  'PullDomainGpos' {
    Initialize-AdContext -DomainDns $DomainDnsName
    Export-DomainGpoXmls -OutDir $OutDir | Out-Null
  }
  'RunAudit' {
    Import-GroupPolicyModule
    Invoke-RunAuditHeadless -OutDir $OutDir -DomainDns $DomainDnsName
  }
  default {
    # GUI wizard
    Import-GroupPolicyModule
    Show-NistAuditWizard -OutDir $OutDir -DomainDns $DomainDnsName
  }
}
