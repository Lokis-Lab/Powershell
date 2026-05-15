<#
.SYNOPSIS
  GPO Audit Master: export Group Policy XML, flatten settings to CSV, capture and
  compare registry-oriented snapshots, and search all GPOs for settings by partial text.

.DESCRIPTION
  Use this tool to work with Group Policy in Active Directory: export reports,
  analyze them as CSVs, and find where settings are defined without opening each
  GPO in the console.

  - XmlExport / XmlExportAndFlatten: Get-GPOReport XML for selected GPOs (with
    throttling); optionally flatten into CSV in the same run.
  - FlattenXml: Convert XML already under OutDir\Exports into per-GPO CSVs and
    master rollups (administrative templates, registry, GPP, security, advanced
    audit policy, services, local groups, scripts, WLAN, metadata).
  - RegistrySnapshotExport / RegistrySnapshotCompare: Build registry key/value
    views from GPO XML and diff two snapshot folders.
  - SearchSettings: Case-insensitive substring search across flattened settings;
    optional OU link filter and CSV output.

  Filter GPOs by display name list, display name regex, and/or GPO GUID. Use
  -DomainDnsName to target another domain (default: this computer's domain). Omit
  -Mode to run the interactive GUI.

  Requires the Group Policy module (RSAT). The Active Directory module is required
  for domain selection, OU-based search, and GPO link features.

.EXAMPLES
  # 1) Export XML only for a few GPOs
  .\GPO-Audit-Master.ps1 -Mode XmlExport -OutDir C:\Temp\GPO_Audit `
    -IncludeGpoName "SEC - Workstations","SEC - Servers"

  # 2) Export XML for matching GPOs and flatten them to CSVs in one go
  .\GPO-Audit-Master.ps1 -Mode XmlExportAndFlatten -OutDir C:\Temp\GPO_Audit `
    -IncludeGpoNameRegex "^(CIS|STIG) - "

  # 3) Just flatten existing XMLs in OutDir\Exports
  .\GPO-Audit-Master.ps1 -Mode FlattenXml -OutDir C:\Temp\GPO_Audit

  # 4) Take a registry key+value snapshot for a subset of GPOs
  .\GPO-Audit-Master.ps1 -Mode RegistrySnapshotExport `
    -OutDir C:\Temp\GpoSnap\Baseline `
    -IncludeGpoName "SEC - Workstations","SEC - Servers"

  # 5) Compare two registry snapshots previously taken by this script
  .\GPO-Audit-Master.ps1 -Mode RegistrySnapshotCompare `
    -LeftFolder  C:\Temp\GpoSnap\Baseline `
    -RightFolder C:\Temp\GpoSnap\Current `
    -OutFolderCompare C:\Temp\GpoSnap\Diff

  # 6) Find settings whose name, value, or path text contains a phrase (e.g. "turn off") across all GPOs
  .\GPO-Audit-Master.ps1 -Mode SearchSettings -SearchText "turn off"
  .\GPO-Audit-Master.ps1 -Mode SearchSettings -SearchText "active hours" -SearchCsvOut C:\Temp\GpoSearch.csv

  # 7) Same, but only GPOs linked under OUs matching "IT" or "Sales" (substring on OU name or canonical path), including child OUs
  .\GPO-Audit-Master.ps1 -Mode SearchSettings -SearchText "turn off" -SearchOuNameFilter "IT","Sales" -SearchOuIncludeChildren

  # 8) Target a specific domain (DNS name) for GPO + AD; default is this computer's domain. GUI: use the Domain dropdown.
  .\GPO-Audit-Master.ps1 -Mode SearchSettings -SearchText "audit" -DomainDnsName "contoso.com"
#>

[CmdletBinding(DefaultParameterSetName = 'Xml')]
param(
  # What this run should do
  # When not supplied, an interactive menu will prompt for it.
  [Parameter()]
  [ValidateSet('XmlExport','FlattenXml','XmlExportAndFlatten','RegistrySnapshotExport','RegistrySnapshotCompare','SearchSettings')]
  [string]$Mode,

  # Shared: root folder
  [Parameter(ParameterSetName='Xml')]
  [Parameter(ParameterSetName='SnapshotExport')]
  [string]$OutDir = "C:\Temp\GPO_Audit",

  # XML export options
  [Parameter(ParameterSetName='Xml')]
  [Parameter(ParameterSetName='Search')]
  [int]$Throttle = 6,

  # GPO filters (used by XmlExport*, RegistrySnapshotExport, SearchSettings)
  [Parameter(ParameterSetName='Xml')]
  [Parameter(ParameterSetName='SnapshotExport')]
  [Parameter(ParameterSetName='Search')]
  [string[]]$IncludeGpoName,

  [Parameter(ParameterSetName='Xml')]
  [Parameter(ParameterSetName='SnapshotExport')]
  [Parameter(ParameterSetName='Search')]
  [string]$IncludeGpoNameRegex,

  [Parameter(ParameterSetName='Xml')]
  [Parameter(ParameterSetName='SnapshotExport')]
  [Parameter(ParameterSetName='Search')]
  [string[]]$IncludeGpoId,

  # SearchSettings: case-insensitive substring match across flattened setting name, value, category, extension, scope
  [Parameter(ParameterSetName='Search', Mandatory)]
  [string]$SearchText,

  [Parameter(ParameterSetName='Search')]
  [string]$SearchCsvOut,

  # SearchSettings: limit to GPOs linked under OUs whose name or canonical path contains any of these substrings (comma-separated in GUI). Requires ActiveDirectory module.
  [Parameter(ParameterSetName='Search')]
  [string[]]$SearchOuNameFilter,

  [Parameter(ParameterSetName='Search')]
  [switch]$SearchOuIncludeChildren,

  # DNS name of the domain for Group Policy and AD queries (e.g. contoso.com). Omit to use this computer's domain. In the GUI, use the Domain dropdown.
  [Parameter()]
  [string]$DomainDnsName,

  # Registry snapshot compare
  [Parameter(ParameterSetName='SnapshotCompare', Mandatory)]
  [string]$LeftFolder,

  [Parameter(ParameterSetName='SnapshotCompare', Mandatory)]
  [string]$RightFolder,

  [Parameter(ParameterSetName='SnapshotCompare', Mandatory)]
  [string]$OutFolderCompare
)

$ErrorActionPreference = 'Stop'

# Resolved by Initialize-GpoAuditAdContext: target domain DNS name for Get-GPO -Domain, and LDAP server for Get-AD* -Server
$script:GpoAuditDomainDns = $null
$script:GpoAuditAdServer = $null

function Write-FatalError {
  param([Parameter(Mandatory)][string]$Message)
  Write-Host $Message -ForegroundColor Red
  try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    [System.Windows.Forms.MessageBox]::Show($Message, 'GPO Audit Master', 'OK', 'Error')
  } catch {
    try { Read-Host 'Press Enter to exit' } catch { }
  }
  exit 1
}

trap {
  $msg = if ($_.Exception.Message) { $_.Exception.Message } else { $_ | Out-String }
  Write-FatalError $msg
}

try { Import-Module GroupPolicy -ErrorAction Stop } catch {
  Write-FatalError "The GroupPolicy module is required (install RSAT: Group Policy Management).`r`n`r`n$($_.Exception.Message)"
}

function Get-ActiveDirectoryRsatInstallHint {
  $capHint = ''
  try {
    if (Get-Command Get-WindowsCapability -ErrorAction SilentlyContinue) {
      $cap = Get-WindowsCapability -Online -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'Rsat.ActiveDirectory.DS-LDS.Tools*' } |
        Select-Object -First 1
      if ($cap -and $cap.State -ne 'Installed') {
        $capHint = "`r`n`r`nOptional feature status: $($cap.Name) = $($cap.State). Install it, then restart PowerShell."
      }
    }
  } catch { }
  @"
The Active Directory PowerShell module (RSAT) is not available on this computer.

Install on Windows 10/11 (client):
  Settings > Apps > Optional features > Add an optional feature (or View features)
  Search for: Active Directory Domain Services and Lightweight Directory Services Tools
  Or run in an elevated PowerShell:
  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

Install on Windows Server:
  Server Manager > Add Roles and Features > Features > Remote Server Administration Tools >
  Role Administration Tools > AD DS and AD LDS Tools > AD DS Tools

After installing, close all PowerShell windows and try again.
$capHint
"@
}

function Test-ActiveDirectoryModuleAvailable {
  [CmdletBinding()]
  param()
  if (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue) { return $true }
  $m = Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue
  return ($null -ne $m -and @($m).Count -gt 0)
}

function Import-ActiveDirectoryModule {
  [CmdletBinding()]
  param()
  if (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue) { return }
  if (-not (Test-ActiveDirectoryModuleAvailable)) {
    throw (Get-ActiveDirectoryRsatInstallHint)
  }
  try {
    Import-Module ActiveDirectory -ErrorAction Stop
  } catch {
    throw "$(Get-ActiveDirectoryRsatInstallHint)`r`n`r`nImport-Module failed: $($_.Exception.Message)"
  }
}

function Initialize-GpoAuditAdContext {
  <#
  .SYNOPSIS
    Sets script scope for target AD domain: DNS name (for Get-GPO -Domain) and PDC (for Get-AD* -Server).
  #>
  [CmdletBinding()]
  param([string]$DomainDnsName)
  Import-ActiveDirectoryModule
  if ([string]::IsNullOrWhiteSpace($DomainDnsName)) {
    $d = Get-ADDomain -ErrorAction Stop
  } else {
    $t = $DomainDnsName.Trim()
    $d = Get-ADDomain -Identity $t -Server $t -ErrorAction Stop
  }
  $script:GpoAuditDomainDns = $d.DNSRoot
  $script:GpoAuditAdServer = $d.PDCEmulator
  if ([string]::IsNullOrWhiteSpace($script:GpoAuditAdServer)) {
    $script:GpoAuditAdServer = $script:GpoAuditDomainDns
  }
}

function Get-GpoAuditForestDomainDnsNames {
  <#
  .SYNOPSIS
    DNS names of domains to show in the GUI picker (forest domains, or current domain only).
  #>
  [CmdletBinding()]
  param()
  Import-ActiveDirectoryModule
  try {
    $f = Get-ADForest -ErrorAction Stop
    $list = @($f.Domains | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ } | Sort-Object -Unique)
    if ($list.Count -gt 0) { return $list }
  } catch { }
  $d = Get-ADDomain -ErrorAction Stop
  return @($d.DNSRoot)
}

function Get-GpoAuditGpoDomainSplat {
  <#
  .SYNOPSIS
    Splat hashtable for Get-GPO / Get-GPOReport -Domain when a target domain is selected.
  #>
  if ([string]::IsNullOrWhiteSpace($script:GpoAuditDomainDns)) { return @{} }
  return @{ Domain = $script:GpoAuditDomainDns }
}

function Set-GpoAuditRequestedDomain {
  <#
  .SYNOPSIS
    Records an optional domain for GroupPolicy cmdlets without requiring the AD module.
  #>
  param([string]$DomainDnsName)
  if ([string]::IsNullOrWhiteSpace($DomainDnsName)) { return }
  $script:GpoAuditDomainDns = $DomainDnsName.Trim()
}

function Ensure-GpoAuditAdContextInitialized {
  if ([string]::IsNullOrWhiteSpace($script:GpoAuditAdServer)) {
    Initialize-GpoAuditAdContext -DomainDnsName $script:GpoAuditDomainDns
  }
}

function Ensure-Folder {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function New-SafeName {
  param([Parameter(Mandatory)][string]$InputString)
  $InputString -replace '[^\w\.-]+','_'
}

function Select-Gpos {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object[]]$Gpos,
    [string[]]$IncludeGpoName,
    [string]$IncludeGpoNameRegex,
    [string[]]$IncludeGpoId
  )

  $filtered = $Gpos

  if ($IncludeGpoId -and $IncludeGpoId.Count -gt 0) {
    $idSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($id in $IncludeGpoId) {
      if ($null -ne $id) { [void]$idSet.Add(([string]$id).Trim('{}')) }
    }
    $filtered = $filtered | Where-Object { $idSet.Contains(([string]$_.Id).Trim('{}')) }
  }

  if ($IncludeGpoName -and $IncludeGpoName.Count -gt 0) {
    $nameSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $IncludeGpoName) { if ($n) { [void]$nameSet.Add($n) } }
    $filtered = $filtered | Where-Object { $nameSet.Contains($_.DisplayName) }
  }

  if ($IncludeGpoNameRegex -and $IncludeGpoNameRegex.Trim().Length -gt 0) {
    $rx = [regex]::new($IncludeGpoNameRegex, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $filtered = $filtered | Where-Object { $rx.IsMatch($_.DisplayName) }
  }

  $filtered
}

# -------------------- XML export (subset of GPOs) --------------------
function Invoke-XmlExport {
  param(
    [Parameter(Mandatory)][string]$OutDir,
    [int]$Throttle = 6,
    [string[]]$IncludeGpoName,
    [string]$IncludeGpoNameRegex,
    [string[]]$IncludeGpoId
  )

  $exportDir = Join-Path $OutDir 'Exports'
  Ensure-Folder -Path $exportDir

  $gpoDom = Get-GpoAuditGpoDomainSplat
  $allGpos = Get-GPO @gpoDom -All | Sort-Object DisplayName
  $gpos = Select-Gpos -Gpos $allGpos -IncludeGpoName $IncludeGpoName -IncludeGpoNameRegex $IncludeGpoNameRegex -IncludeGpoId $IncludeGpoId

  if (-not $gpos -or $gpos.Count -eq 0) {
    throw "No GPOs matched the supplied filters."
  }

  $hasPS7 = $PSVersionTable.PSVersion.Major -ge 7
  $xmlPaths = @()
  $domDns = $script:GpoAuditDomainDns

  if ($hasPS7) {
    $xmlPaths = $gpos | ForEach-Object -Parallel {
      try {
        $safe = ($PSItem.DisplayName -replace '[^\w\.-]+','_')
        $file = Join-Path $using:exportDir ("{0}.xml" -f $safe)
        $domParams = @{}
        if ($using:domDns) { $domParams['Domain'] = $using:domDns }
        Get-GPOReport @domParams -Name $PSItem.DisplayName -ReportType XML -Path $file
        $file
      } catch {
        Write-Warning "Failed to export '$($PSItem.DisplayName)': $($_.Exception.Message)"
        $null
      }
    } -ThrottleLimit $Throttle
  } else {
    foreach ($g in $gpos) {
      try {
        $safe = New-SafeName $g.DisplayName
        $file = Join-Path $exportDir ("{0}.xml" -f $safe)
        Get-GPOReport @gpoDom -Name $g.DisplayName -ReportType XML -Path $file
        $xmlPaths += $file
      } catch {
        Write-Warning "Failed to export '$($g.DisplayName)': $($_.Exception.Message)"
      }
    }
  }

  $xmlPaths = @($xmlPaths | Where-Object { $_ } | Where-Object { Test-Path -LiteralPath $_ })
  Write-Host "Exported $($xmlPaths.Count) GPO XML files to: $exportDir" -ForegroundColor Cyan
}

# -------------------- Flatten XML (from OutDir\Exports) --------------------
function Get-XPathNodes {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$XPath)
  $n = $Xml.SelectNodes($XPath)
  if ($null -eq $n) { @() } else { $n }
}

function Get-FirstText {
  param([Parameter(Mandatory)][System.Xml.XmlNode]$Node,[Parameter(Mandatory)][string]$XPath)
  $first = $Node.SelectNodes($XPath) | Select-Object -First 1
  if ($first) { $first.InnerText } else { $null }
}

function Get-ScopeFromNode {
  param([Parameter(Mandatory)][System.Xml.XmlNode]$Node)
  $parentOuter = if ($Node.ParentNode) { $Node.ParentNode.OuterXml } else { '' }
  $blob = ($Node.OuterXml + ' ' + $parentOuter) -replace '\s+',' '
  if ($blob -match '(?i)\bcomputer\b') { 'Computer' }
  elseif ($blob -match '(?i)\buser\b') { 'User' }
  else { 'Unknown' }
}

function New-FlattenRow {
  param(
    [Parameter(Mandatory)][string]$Gpo,
    [Parameter(Mandatory)][string]$Scope,
    [Parameter(Mandatory)][string]$Extension,
    [Parameter(Mandatory)][string]$Category,
    [Parameter(Mandatory)][string]$Setting,
    [Parameter()][string]$Value,
    [Parameter()][string]$Type
  )
  [pscustomobject]@{
    GPO            = $Gpo
    Scope          = $Scope
    Extension      = $Extension
    Category       = $Category
    Setting        = $Setting
    Type           = $Type
    Value          = $Value
    Canonical      = '{0}|{1}|{2}|{3}|{4}' -f $Gpo,$Scope,$Extension,$Category,$Setting
    CanonicalNoGpo = '{0}|{1}|{2}|{3}'     -f $Scope,$Extension,$Category,$Setting
  }
}

function Add-FlattenRows {
  param(
    [Parameter(Mandatory)][System.Collections.Generic.List[object]]$Target,
    [Parameter()][AllowNull()]$Items
  )
  if ($null -eq $Items) { return }
  foreach ($i in @($Items)) {
    if ($null -ne $i) { [void]$Target.Add($i) }
  }
}

function Get-AdminTemplatePolicyRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Gpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($p in (Get-XPathNodes -Xml $Xml -XPath "//*[local-name()='Policy']")) {
    $display = $p.displayName; if (-not $display) { $display = $p.name }
    $state   = $p.state
    if (-not $state) { $state = $p.Enabled }
    if (-not $state) { $state = $p.Disable }
    if (-not $state) { $state = Get-FirstText -Node $p -XPath ".//*[local-name()='State']" }
    if (-not $state) { $state = Get-FirstText -Node $p -XPath ".//*[local-name()='Value']" }
    $value   = Get-FirstText -Node $p -XPath ".//*[local-name()='Value']"
    if (-not $value) { $value = [string]$state }
    $rows.Add( (New-FlattenRow -Gpo $Gpo -Scope (Get-ScopeFromNode $p) -Extension 'AdminTemplates' -Category 'Policies' -Setting $display -Value $value -Type 'Policy') )
  }
  return $rows
}

function Get-AdminTemplateRegistryRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Gpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($r in (Get-XPathNodes -Xml $Xml -XPath "//*[local-name()='RegistrySettings']/*[local-name()='Registry']")) {
    $props = $r.SelectSingleNode(".//*[local-name()='Properties']")
    $key   = $r.key
    if (-not $key -and $props) { $key = $props.key }
    $name  = $r.valueName
    if (-not $name -and $props) { $name = $props.valueName }
    if ($props) {
      $val  = $props.value
      $type = $props.type
    } else {
      $val  = $null
      $type = $null
    }
    $setting = ($key, $name) -join '\'
    $rows.Add( (New-FlattenRow -Gpo $Gpo -Scope (Get-ScopeFromNode $r) -Extension 'AdminTemplates' -Category 'Registry' -Setting $setting -Value ([string]$val) -Type ([string]$type)) )
  }
  return $rows
}

function Get-GPPRegistryRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Gpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($it in (Get-XPathNodes -Xml $Xml -XPath "//*[local-name()='RegistrySettings']/*[local-name()='Registry']/*[local-name()='Properties']")) {
    $key    = $it.key; $name = $it.valueName; $val = $it.value; $type = $it.type; $action = $it.action
    $cat    = if ($action) { "GPP (Action:$action)" } else { "GPP" }
    $setting = ($key, $name) -join '\'
    $rows.Add( (New-FlattenRow -Gpo $Gpo -Scope (Get-ScopeFromNode $it) -Extension 'GroupPolicyPreferences' -Category $cat -Setting $setting -Value ([string]$val) -Type ([string]$type)) )
  }
  return $rows
}

function Get-GpoAuditSettingValueDisplay {
  param([string]$Raw)
  if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
  $t = $Raw.Trim()
  switch ($t) {
    '0' { return 'Unchanged' }
    '1' { return 'Success only' }
    '2' { return 'Failure only' }
    '3' { return 'Success and Failure' }
    '4' { return 'No auditing' }
    default { return $t }
  }
}

function Get-AdvancedAuditPolicyRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Gpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($a in (Get-XPathNodes -Xml $Xml -XPath "//*[local-name()='AuditSetting']")) {
    $sub = Get-FirstText -Node $a -XPath ".//*[local-name()='SubcategoryName']"
    if (-not $sub) { $sub = Get-FirstText -Node $a -XPath ".//*[local-name()='Subcategory']" }
    if (-not $sub) { try { $sub = $a.SubcategoryName } catch { $sub = $null } }
    if (-not $sub) { try { $sub = $a.Subcategory } catch { $sub = $null } }
    if (-not $sub) { $sub = '(unknown subcategory)' }

    $inc = Get-FirstText -Node $a -XPath ".//*[local-name()='InclusionSetting']"
    if (-not $inc) { try { $inc = $a.InclusionSetting } catch { $inc = $null } }

    $sv = Get-FirstText -Node $a -XPath ".//*[local-name()='SettingValue']"
    if (-not $sv) { try { $sv = $a.SettingValue } catch { $sv = $null } }

    $val = $null
    if (-not [string]::IsNullOrWhiteSpace($inc)) { $val = $inc.Trim() }
    if ([string]::IsNullOrWhiteSpace($val)) { $val = Get-GpoAuditSettingValueDisplay -Raw $sv }
    if ([string]::IsNullOrWhiteSpace($val)) { $val = [string]$sv }

    $guid = Get-FirstText -Node $a -XPath ".//*[local-name()='SubcategoryGUID']"
    if (-not $guid) { try { $guid = $a.SubcategoryGUID } catch { $guid = $null } }
    if (-not [string]::IsNullOrWhiteSpace($guid)) {
      if ([string]::IsNullOrWhiteSpace($val)) { $val = "GUID=$guid" } else { $val = "$val; GUID=$guid" }
    }

    $setting = "Audit: $sub"
    $rows.Add( (New-FlattenRow -Gpo $Gpo -Scope (Get-ScopeFromNode $a) -Extension 'Security' -Category 'AdvancedAuditPolicy' -Setting $setting -Value $val -Type 'AuditSetting') )
  }
  return $rows
}

function Get-SecuritySettingRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Gpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($s in (Get-XPathNodes -Xml $Xml -XPath "//*[local-name()='SecuritySettings']")) {
    foreach ($n in $s.SelectNodes(".//*[not(*)]")) {
      if ($null -ne $n.SelectSingleNode("ancestor::*[local-name()='AuditSetting']")) { continue }
      $name = $n.Name
      $val  = $n.InnerText
      if ([string]::IsNullOrWhiteSpace($val)) { continue }
      $rows.Add( (New-FlattenRow -Gpo $Gpo -Scope (Get-ScopeFromNode $n) -Extension 'Security' -Category 'SecuritySettings' -Setting $name -Value ($val.Trim()) -Type $null) )
    }
  }
  return $rows
}

function Get-NTServiceRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Gpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($svc in (Get-XPathNodes -Xml $Xml -XPath "//*[local-name()='NTServices']/*[local-name()='NTService']")) {
    $name = $svc.name
    $mode = Get-FirstText -Node $svc -XPath ".//*[local-name()='StartupMode']"
    if (-not $mode) { $mode = $svc.startup }
    $rows.Add( (New-FlattenRow -Gpo $Gpo -Scope (Get-ScopeFromNode $svc) -Extension 'Security' -Category 'Services' -Setting $name -Value ([string]$mode) -Type 'Service') )
  }
  return $rows
}

function Get-LugsRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Gpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($g in (Get-XPathNodes -Xml $Xml -XPath "//*[local-name()='LocalUsersAndGroups']/*[local-name()='Group']")) {
    $groupName = $g.name
    if (-not $groupName) { $groupName = Get-FirstText -Node $g -XPath ".//*[local-name()='Name']" }
    if (-not $groupName) { $groupName = '(unknown)' }
    $action    = $g.action
    $rows.Add( (New-FlattenRow -Gpo $Gpo -Scope (Get-ScopeFromNode $g) -Extension 'GPP' -Category 'LocalGroups' -Setting $groupName -Value ("Action=$action") -Type 'Group') )
    foreach ($m in $g.SelectNodes(".//*[local-name()='Member']|.//*[local-name()='Members']/*")) {
      $memberId = $m.name ?? $m.InnerText
      if ($memberId) {
        $rows.Add( (New-FlattenRow -Gpo $Gpo -Scope (Get-ScopeFromNode $m) -Extension 'GPP' -Category 'LocalGroups\Members' -Setting $groupName -Value ([string]$memberId) -Type 'Member') )
      }
    }
  }
  return $rows
}

function Get-ScriptRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Gpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($s in (Get-XPathNodes -Xml $Xml -XPath "//*[local-name()='Script']")) {
    $scriptName = $s.name
    if (-not $scriptName) { $scriptName = Get-FirstText -Node $s -XPath ".//*[local-name()='Name']" }
    if (-not $scriptName) { $scriptName = Get-FirstText -Node $s -XPath ".//*[local-name()='Command']" }
    if (-not $scriptName) { $scriptName = '(script)' }
    $type = Get-FirstText -Node $s -XPath ".//*[local-name()='Type']"
    if (-not $type) { $type = 'Script' }
    $cmd  = Get-FirstText -Node $s -XPath ".//*[local-name()='Command']"
    if (-not $cmd) { $cmd = Get-FirstText -Node $s -XPath ".//*[local-name()='Parameters']" }
    $rows.Add( (New-FlattenRow -Gpo $Gpo -Scope (Get-ScopeFromNode $s) -Extension 'Scripts' -Category $type -Setting $scriptName -Value ([string]$cmd) -Type 'Script') )
  }
  return $rows
}

function Get-WlanPolicyRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Gpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  $xpath = "//*[local-name()='Extension' and contains(@*, 'WLanSvcSettings')]//*[local-name()='WLanSvcSetting']|//*[local-name()='WLanPolicies']/*"
  foreach ($w in (Get-XPathNodes -Xml $Xml -XPath $xpath)) {
    $policyName = $w.name
    if (-not $policyName) { $policyName = Get-FirstText -Node $w -XPath ".//*[local-name()='Name']" }
    if (-not $policyName) { $policyName = '(WLAN Policy)' }
    $mode = Get-FirstText -Node $w -XPath ".//*[local-name()='Mode']"
    if (-not $mode) { $mode = Get-FirstText -Node $w -XPath ".//*[local-name()='PolicyType']" }
    $rows.Add( (New-FlattenRow -Gpo $Gpo -Scope (Get-ScopeFromNode $w) -Extension 'WLAN' -Category 'WlanPolicies' -Setting $policyName -Value ([string]$mode) -Type 'WLAN') )
  }
  return $rows
}

function Get-AllFlattenedRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Gpo)
  $rows = [System.Collections.Generic.List[object]]::new()

  $gpoName = Get-FirstText -Node $Xml -XPath ".//*[local-name()='GPO']/*[local-name()='Name']"
  if (-not $gpoName) { $gpoName = $Gpo }
  $gpoGuid = Get-FirstText -Node $Xml -XPath ".//*[local-name()='GPO']/*[local-name()='Identifier']"
  if (-not $gpoGuid) { $gpoGuid = Get-FirstText -Node $Xml -XPath ".//*[local-name()='Identifier']" }
  [void]$rows.Add( (New-FlattenRow -Gpo $Gpo -Scope 'N/A' -Extension 'Metadata' -Category 'GPO' -Setting 'Name' -Value $gpoName -Type 'String') )
  if ($gpoGuid) { [void]$rows.Add( (New-FlattenRow -Gpo $Gpo -Scope 'N/A' -Extension 'Metadata' -Category 'GPO' -Setting 'GUID' -Value $gpoGuid -Type 'String') ) }

  Add-FlattenRows -Target $rows -Items (Get-AdminTemplatePolicyRows   -Xml $Xml -Gpo $Gpo)
  Add-FlattenRows -Target $rows -Items (Get-AdminTemplateRegistryRows -Xml $Xml -Gpo $Gpo)
  Add-FlattenRows -Target $rows -Items (Get-GPPRegistryRows           -Xml $Xml -Gpo $Gpo)
  Add-FlattenRows -Target $rows -Items (Get-AdvancedAuditPolicyRows   -Xml $Xml -Gpo $Gpo)
  Add-FlattenRows -Target $rows -Items (Get-SecuritySettingRows       -Xml $Xml -Gpo $Gpo)
  Add-FlattenRows -Target $rows -Items (Get-NTServiceRows             -Xml $Xml -Gpo $Gpo)
  Add-FlattenRows -Target $rows -Items (Get-LugsRows                  -Xml $Xml -Gpo $Gpo)
  Add-FlattenRows -Target $rows -Items (Get-ScriptRows                -Xml $Xml -Gpo $Gpo)
  Add-FlattenRows -Target $rows -Items (Get-WlanPolicyRows            -Xml $Xml -Gpo $Gpo)

  return $rows
}

function Get-AdFriendlyOuPathLabel {
  <#
  .SYNOPSIS
    Safe display label for domain/OU objects: never calls string methods on null.
    Handles canonicalName as string, collection, or missing.
  #>
  param(
    $AdObject,
    [string]$Fallback = ''
  )
  if ($null -eq $AdObject) { return $Fallback }
  try {
    $c = $AdObject.canonicalName
    if ($null -ne $c) {
      $s = $null
      if ($c -is [string]) {
        $s = $c
      } elseif ($c -is [System.Collections.IEnumerable] -and $c -isnot [string]) {
        $first = @($c)[0]
        if ($null -ne $first) {
          try { $s = $first.ToString() } catch { $s = $null }
        }
      } else {
        try { $s = $c.ToString() } catch { $s = $null }
      }
      if (-not [string]::IsNullOrWhiteSpace($s)) {
        return ([string]$s).TrimEnd('/')
      }
    }
    $nm = $AdObject.Name
    if ($null -ne $nm) {
      $ns = $null
      try { $ns = $nm.ToString() } catch { $ns = $null }
      if ($null -ne $ns) {
        $ns = $ns.Trim()
        if ($ns.Length -gt 0) { return $ns }
      }
    }
    $dn = $AdObject.DistinguishedName
    if ($null -ne $dn) {
      $ds = $null
      try { $ds = $dn.ToString() } catch { $ds = $null }
      if (-not [string]::IsNullOrWhiteSpace($ds)) { return $ds }
    }
  } catch {
    return $Fallback
  }
  return $Fallback
}

function Get-SafeAdOuSortKey {
  param($Ou)
  if ($null -eq $Ou) { return '' }
  try {
    $d = $Ou.DistinguishedName
    if ($null -eq $d) { return '' }
    return [string]$d
  } catch {
    return ''
  }
}

function Get-AdDnString {
  <#
  .SYNOPSIS
    Normalized distinguishedName string for hashtable keys (AD sometimes returns ADPropertyValueCollection).
    Strings implement IEnumerable — must test [string] before IEnumerable or only the first character is used.
  #>
  param($ObjectWithDn)
  if ($null -eq $ObjectWithDn) { return '' }
  $d = $null
  try { $d = $ObjectWithDn.DistinguishedName } catch { return '' }
  if ($null -eq $d) { return '' }
  if ($d -is [string]) { return $d.Trim() }
  if ($d -is [char[]]) { return ([string]::new($d)).Trim() }
  if ($d -is [System.Collections.IEnumerable]) {
    $first = $null
    foreach ($x in $d) { $first = $x; break }
    if ($null -eq $first) { return '' }
    return ([string]$first).Trim()
  }
  return ([string]$d).Trim()
}

function Get-AdOuLeafDisplayName {
  <#
  .SYNOPSIS
    Short OU label: leaf name only (AD Name / last segment of canonical), not the full path.
    Domain NC uses DNS root (e.g. FLSEN.GOV).
  #>
  param(
    $AdObject,
    [Parameter(Mandatory)][string]$DomainDistinguishedName,
    [Parameter(Mandatory)][string]$DnsRootFallback
  )
  if ($null -eq $AdObject) { return '' }
  $dnStr = Get-AdDnString -ObjectWithDn $AdObject
  if ([string]::IsNullOrWhiteSpace($dnStr)) { return '' }
  if ([string]::Equals($dnStr.Trim(), $DomainDistinguishedName.Trim(), [StringComparison]::OrdinalIgnoreCase)) {
    $t = $DnsRootFallback.Trim()
    if (-not [string]::IsNullOrWhiteSpace($t)) { return $t }
    return 'Domain'
  }
  $name = $AdObject.Name
  if (-not [string]::IsNullOrWhiteSpace($name)) {
    return $name.Trim()
  }
  $c = $AdObject.canonicalName
  if ($null -ne $c) {
    $cs = $c.ToString().TrimEnd('/')
    $parts = $cs -split '/', [System.StringSplitOptions]::RemoveEmptyEntries
    if ($parts.Length -gt 0) {
      return $parts[$parts.Length - 1].Trim()
    }
  }
  if ($dnStr -match '(?i)OU=([^,]+)') {
    return $Matches[1].Trim()
  }
  return $dnStr
}

function Get-AdOuParentFolderName {
  param($Ou)
  if ($null -eq $Ou) { return '' }
  $c = $Ou.canonicalName
  if ($null -eq $c) { return '' }
  $cs = $c.ToString().TrimEnd('/')
  $parts = $cs -split '/', [System.StringSplitOptions]::RemoveEmptyEntries
  if ($parts.Length -lt 2) { return '' }
  return $parts[$parts.Length - 2].Trim()
}

function Get-AdOuDisambiguatedDisplayMapFromOuList {
  <#
  .SYNOPSIS
    Maps each OU distinguishedName to a short display string; duplicate leaf names get "Leaf (ParentFolder)".
  #>
  param(
    [object[]]$OuList,
    [Parameter(Mandatory)][string]$DomainDistinguishedName,
    [Parameter(Mandatory)][string]$DnsRootFallback
  )
  $domainKey = $DomainDistinguishedName.Trim()
  $map = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
  $rootLabel = $DnsRootFallback.Trim()
  if ([string]::IsNullOrWhiteSpace($rootLabel)) { $rootLabel = 'Domain' }
  $map[$domainKey] = $rootLabel

  $sorted = @($OuList | Where-Object { $null -ne $_ } | Sort-Object { Get-SafeAdOuSortKey $_ })
  $groups = @{}
  foreach ($ou in $sorted) {
    $leaf = Get-AdOuLeafDisplayName -AdObject $ou -DomainDistinguishedName $domainKey -DnsRootFallback $DnsRootFallback
    if ([string]::IsNullOrWhiteSpace($leaf)) { continue }
    $gkey = $leaf.ToLowerInvariant()
    if (-not $groups.ContainsKey($gkey)) {
      $groups[$gkey] = [System.Collections.Generic.List[object]]::new()
    }
    $groups[$gkey].Add($ou)
  }
  foreach ($key in $groups.Keys) {
    $grp = $groups[$key]
    foreach ($ou in $grp) {
      $dnKey = Get-AdDnString -ObjectWithDn $ou
      if ([string]::IsNullOrWhiteSpace($dnKey)) { continue }
      $leaf = Get-AdOuLeafDisplayName -AdObject $ou -DomainDistinguishedName $domainKey -DnsRootFallback $DnsRootFallback
      if ([string]::IsNullOrWhiteSpace($leaf)) { continue }
      if ($grp.Count -gt 1) {
        $parent = Get-AdOuParentFolderName -Ou $ou
        if (-not [string]::IsNullOrWhiteSpace($parent)) {
          $map[$dnKey] = "$leaf ($parent)"
        } else {
          $map[$dnKey] = $leaf
        }
      } else {
        $map[$dnKey] = $leaf
      }
    }
  }

  foreach ($ou in $sorted) {
    $dnKey = Get-AdDnString -ObjectWithDn $ou
    if ([string]::IsNullOrWhiteSpace($dnKey)) { continue }
    if ($map.ContainsKey($dnKey)) { continue }
    $fallback = Get-AdOuLeafDisplayName -AdObject $ou -DomainDistinguishedName $domainKey -DnsRootFallback $DnsRootFallback
    if ([string]::IsNullOrWhiteSpace($fallback) -and $dnKey -match '(?i)OU=([^,]+)') {
      $fallback = $Matches[1].Trim()
    }
    if ([string]::IsNullOrWhiteSpace($fallback)) { $fallback = $dnKey }
    $map[$dnKey] = $fallback
  }
  return $map
}

function Show-GpoAuditOuComboLoadFailure {
  param($ErrorRecord)
  $err = $ErrorRecord
  $detail = ''
  try {
    if ($err.Exception) {
      $msg = $err.Exception.Message
      if ($null -ne $msg -and $msg.ToString().Length -gt 0) {
        $detail = $msg.ToString()
      }
      $inner = $err.Exception.InnerException
      if ($inner -and $null -ne $inner.Message -and $inner.Message.ToString().Length -gt 0) {
        $detail += "`r`n" + $inner.Message.ToString()
      }
    }
    if ([string]::IsNullOrWhiteSpace($detail)) {
      $detail = ($err | Out-String).Trim()
    }
  } catch {
    $detail = 'Error while formatting error details. Original failure occurred while loading OUs.'
  }
  if ([string]::IsNullOrWhiteSpace($detail)) { $detail = 'Unknown error.' }
  [System.Windows.Forms.MessageBox]::Show(
    "Could not load organizational units. Ensure this PC is domain-joined, you have rights to read AD, and RSAT (Active Directory Domain Services) is installed.`r`n`r`n$detail",
    'GPO Audit Master', 'OK', 'Warning')
}

function Invoke-GpoAuditOuComboPopulate {
  <#
  .SYNOPSIS
    Fills the Search OU ComboBox. Disables AutoComplete while loading; sets SelectedIndex and Text so the field is not blank.
  #>
  param(
    [Parameter()]
    [System.Windows.Forms.ComboBox]$Combo
  )
  if ($null -eq $Combo) { return }

  $wasOpen = $Combo.DroppedDown
  if ($wasOpen) { $Combo.DroppedDown = $false }

  $Combo.SuspendLayout()
  $acMode = $Combo.AutoCompleteMode
  $acSrc = $Combo.AutoCompleteSource
  $Combo.AutoCompleteMode = [System.Windows.Forms.AutoCompleteMode]::None
  $Combo.AutoCompleteSource = [System.Windows.Forms.AutoCompleteSource]::None
  try {
    Import-ActiveDirectoryModule
    Ensure-GpoAuditAdContextInitialized
    $domain = Get-ADDomain -Identity $script:GpoAuditDomainDns -Server $script:GpoAuditAdServer -ErrorAction Stop
    if ($null -eq $domain -or [string]::IsNullOrWhiteSpace($domain.DistinguishedName)) {
      throw 'Get-ADDomain did not return a valid DistinguishedName. Is this computer joined to an Active Directory domain?'
    }
    $dn = Get-AdDnString -ObjectWithDn $domain
    if ([string]::IsNullOrWhiteSpace($dn)) {
      $dn = [string]$domain.DistinguishedName
    }
    $dnsRoot = $domain.DNSRoot
    if ([string]::IsNullOrWhiteSpace($dnsRoot)) { $dnsRoot = $dn }

    $ous = @(Get-ADOrganizationalUnit -Filter * -SearchBase $dn -SearchScope Subtree -Server $script:GpoAuditAdServer -Properties CanonicalName, Name, DistinguishedName -ErrorAction Stop |
      Where-Object { $null -ne $_ })
    $ouMap = Get-AdOuDisambiguatedDisplayMapFromOuList -OuList $ous -DomainDistinguishedName $dn -DnsRootFallback $dnsRoot
    $rootLabel = if ($ouMap.ContainsKey($dn)) { $ouMap[$dn] } else { $dnsRoot }
    if ([string]::IsNullOrWhiteSpace($rootLabel)) { $rootLabel = $dnsRoot }
    if ([string]::IsNullOrWhiteSpace($rootLabel)) { $rootLabel = 'Domain' }

    $Combo.Items.Clear()
    [void]$Combo.Items.Add([string]$rootLabel)

    foreach ($ou in ($ous | Sort-Object { Get-SafeAdOuSortKey $_ })) {
      $dnKey = Get-AdDnString -ObjectWithDn $ou
      if ([string]::IsNullOrWhiteSpace($dnKey)) { continue }
      if (-not $ouMap.ContainsKey($dnKey)) { continue }
      $lbl = $ouMap[$dnKey]
      if ([string]::IsNullOrWhiteSpace($lbl)) { continue }
      if ([string]::Equals($lbl, $rootLabel, [StringComparison]::OrdinalIgnoreCase)) { continue }
      [void]$Combo.Items.Add([string]$lbl)
    }

    if ($Combo.Items.Count -gt 0) {
      $Combo.SelectedIndex = 0
      $Combo.Text = [string]$Combo.Items[0]
    }
    $Combo.Tag = $true
  } catch {
    Show-GpoAuditOuComboLoadFailure -ErrorRecord $_
  } finally {
    $Combo.AutoCompleteMode = $acMode
    $Combo.AutoCompleteSource = $acSrc
    $Combo.ResumeLayout()
    $Combo.Refresh()
    if ($wasOpen) {
      $Combo.DroppedDown = $true
    }
  }
}

function Get-GpoOuLinksFromAd {
  <#
  .SYNOPSIS
    Returns each GPO link: Guid, linked OU distinguishedName, and short friendly label (leaf name or disambiguated), not LDAP DN.
  #>
  [CmdletBinding()]
  param()

  Import-ActiveDirectoryModule
  Ensure-GpoAuditAdContextInitialized
  $domain = Get-ADDomain -Identity $script:GpoAuditDomainDns -Server $script:GpoAuditAdServer
  $domainDn = Get-AdDnString -ObjectWithDn $domain
  if ([string]::IsNullOrWhiteSpace($domainDn)) { $domainDn = [string]$domain.DistinguishedName }
  $dnsRoot = $domain.DNSRoot
  $adSrv = $script:GpoAuditAdServer

  $rx = [regex]::new('LDAP://cn=\{([^}]+)\},cn=policies', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
  $out = [System.Collections.Generic.List[object]]::new()

  function Add-LinksFromObject {
    param(
      [Parameter(Mandatory)]$AdObject,
      [Parameter(Mandatory)][string]$FriendlyPath
    )
    if (-not $AdObject.gplink) { return }
    $linkDn = Get-AdDnString -ObjectWithDn $AdObject
    if ([string]::IsNullOrWhiteSpace($linkDn)) { $linkDn = [string]$AdObject.DistinguishedName }
    foreach ($m in $rx.Matches([string]$AdObject.gplink)) {
      $guidStr = $m.Groups[1].Value
      try {
        $gid = [Guid]::Parse($guidStr)
      } catch {
        continue
      }
      $out.Add([pscustomobject]@{
        GpoGuid     = $gid
        LinkedOuDn  = $linkDn
        OuFriendly  = $FriendlyPath
      })
    }
  }

  $domObj = Get-ADObject -Identity $domainDn -Server $adSrv -Properties gplink, canonicalName -ErrorAction Stop
  if (-not $domObj) { throw "Get-ADObject failed for domain DN: $domainDn" }

  $ous = @(Get-ADOrganizationalUnit -Filter * -SearchBase $domainDn -SearchScope Subtree -Server $adSrv -Properties gplink, canonicalName, distinguishedName, name -ErrorAction Stop)
  $ouMap = Get-AdOuDisambiguatedDisplayMapFromOuList -OuList $ous -DomainDistinguishedName $domainDn -DnsRootFallback $dnsRoot

  $domFriendly = if ($ouMap.ContainsKey($domainDn)) { $ouMap[$domainDn] } else { $dnsRoot }
  if ([string]::IsNullOrWhiteSpace($domFriendly)) { $domFriendly = $dnsRoot }
  if ([string]::IsNullOrWhiteSpace($domFriendly)) { $domFriendly = 'Domain' }
  Add-LinksFromObject -AdObject $domObj -FriendlyPath $domFriendly

  foreach ($ou in $ous) {
    $dnKey = Get-AdDnString -ObjectWithDn $ou
    if ([string]::IsNullOrWhiteSpace($dnKey)) { continue }
    $friendly = if ($ouMap.ContainsKey($dnKey)) { $ouMap[$dnKey] } else { '' }
    if ([string]::IsNullOrWhiteSpace($friendly)) { $friendly = $dnKey }
    Add-LinksFromObject -AdObject $ou -FriendlyPath $friendly
  }

  return $out
}

function Get-AllowedOuDnsForSearchFilter {
  param(
    [Parameter(Mandatory)][string[]]$Filters,
    [Parameter(Mandatory)][switch]$IncludeChildren
  )

  Import-ActiveDirectoryModule
  Ensure-GpoAuditAdContextInitialized
  $domain = Get-ADDomain -Identity $script:GpoAuditDomainDns -Server $script:GpoAuditAdServer
  $domainDn = Get-AdDnString -ObjectWithDn $domain
  if ([string]::IsNullOrWhiteSpace($domainDn)) { $domainDn = [string]$domain.DistinguishedName }
  $dnsRoot = $domain.DNSRoot
  $adSrv = $script:GpoAuditAdServer

  $patterns = foreach ($f in $Filters) {
    $t = $f.Trim()
    if ($t.Length -gt 0) { $t }
  }
  if (-not $patterns -or $patterns.Count -eq 0) {
    return [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  }

  $ousOnly = @(
    Get-ADOrganizationalUnit -Filter * -SearchBase $domainDn -SearchScope Subtree -Server $adSrv -Properties distinguishedName, canonicalName, name -ErrorAction Stop
  )
  $ouMap = Get-AdOuDisambiguatedDisplayMapFromOuList -OuList $ousOnly -DomainDistinguishedName $domainDn -DnsRootFallback $dnsRoot

  $candidates = [System.Collections.Generic.List[object]]::new()
  $domCandidate = Get-ADObject -Identity $domainDn -Server $adSrv -Properties distinguishedName, canonicalName, name -ErrorAction Stop
  if ($domCandidate) { [void]$candidates.Add($domCandidate) }
  foreach ($ou in $ousOnly) { [void]$candidates.Add($ou) }

  $matchedBases = [System.Collections.Generic.List[string]]::new()
  foreach ($pat in $patterns) {
    foreach ($obj in $candidates) {
      if ($null -eq $obj -or $null -eq $obj.DistinguishedName) { continue }
      $dnStr = Get-AdDnString -ObjectWithDn $obj
      if ([string]::IsNullOrWhiteSpace($dnStr)) { continue }
      $display = if ($ouMap.ContainsKey($dnStr)) { $ouMap[$dnStr] } else { '' }
      if ([string]::IsNullOrWhiteSpace($display)) {
        $display = Get-AdFriendlyOuPathLabel -AdObject $obj -Fallback $(if ($dnsRoot) { $dnsRoot } else { '' })
      }
      $canon = Get-AdFriendlyOuPathLabel -AdObject $obj -Fallback $(if ($dnsRoot) { $dnsRoot } else { '' })
      if ([string]::IsNullOrWhiteSpace($canon)) { $canon = $dnStr }
      $name = if ($null -ne $obj.Name) { [string]$obj.Name } else { '' }
      $hit = ($display.IndexOf($pat, [StringComparison]::OrdinalIgnoreCase) -ge 0) -or
        ($canon.IndexOf($pat, [StringComparison]::OrdinalIgnoreCase) -ge 0) -or
        ($name.Length -gt 0 -and $name.IndexOf($pat, [StringComparison]::OrdinalIgnoreCase) -ge 0) -or
        ($dnStr.IndexOf($pat, [StringComparison]::OrdinalIgnoreCase) -ge 0)
      if ($hit) { [void]$matchedBases.Add($dnStr) }
    }
  }

  $allowed = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($dn in ($matchedBases | Select-Object -Unique)) {
    if ($IncludeChildren) {
      [void]$allowed.Add($dn)
      Get-ADOrganizationalUnit -Filter * -SearchBase $dn -SearchScope Subtree -Server $adSrv -Properties distinguishedName -ErrorAction Stop |
        ForEach-Object { [void]$allowed.Add($_.DistinguishedName) }
    } else {
      [void]$allowed.Add($dn)
    }
  }
  return $allowed
}

function Invoke-SearchGpoSettings {
  param(
    [Parameter(Mandatory)][string]$SearchText,
    [string[]]$IncludeGpoName,
    [string]$IncludeGpoNameRegex,
    [string[]]$IncludeGpoId,
    [string]$SearchCsvOut,
    [string[]]$SearchOuNameFilter,
    [switch]$SearchOuIncludeChildren
  )

  $needle = $SearchText.Trim()
  if ($needle.Length -eq 0) { throw "SearchText cannot be empty or whitespace." }

  $gpoDom = Get-GpoAuditGpoDomainSplat
  $allGpos = Get-GPO @gpoDom -All -ErrorAction Stop | Sort-Object DisplayName
  $gpos = Select-Gpos -Gpos $allGpos -IncludeGpoName $IncludeGpoName -IncludeGpoNameRegex $IncludeGpoNameRegex -IncludeGpoId $IncludeGpoId

  if (-not $gpos -or $gpos.Count -eq 0) {
    throw "No GPOs matched the supplied filters."
  }

  $ouFilterPatterns = $null
  if ($SearchOuNameFilter -and @($SearchOuNameFilter).Count -gt 0) {
    $ouFilterPatterns = foreach ($s in $SearchOuNameFilter) { if ($s -and $s.Trim().Length -gt 0) { $s.Trim() } }
  }

  $links = @()
  $needsOuLinks = ($ouFilterPatterns -and $ouFilterPatterns.Count -gt 0)
  if ($needsOuLinks -or (Test-ActiveDirectoryModuleAvailable)) {
    try {
      Write-Progress -Activity 'Searching GPO settings' -Status 'Reading GPO links from Active Directory' -PercentComplete 0
      $links = @(Get-GpoOuLinksFromAd)
    } catch {
      $adErr = ''
      if ($_.Exception -and $_.Exception.Message) { $adErr = $_.Exception.Message } else { $adErr = ($_ | Out-String) }
      if ($needsOuLinks) {
        throw "SearchOuNameFilter requires RSAT (Active Directory PowerShell module) and rights to read OU gpLink data.`r`n`r`n$adErr"
      }
      Write-Warning "Could not load GPO-to-OU links; LinkedOUs column will be empty. $adErr"
    }
  } elseif ($needsOuLinks) {
    throw (Get-ActiveDirectoryRsatInstallHint)
  }

  $gpoGuidToFriendlyOus = @{}
  foreach ($L in $links) {
    if (-not $gpoGuidToFriendlyOus.ContainsKey($L.GpoGuid)) {
      $gpoGuidToFriendlyOus[$L.GpoGuid] = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    }
    [void]$gpoGuidToFriendlyOus[$L.GpoGuid].Add($L.OuFriendly)
  }

  if ($ouFilterPatterns -and $ouFilterPatterns.Count -gt 0) {
    if ($links.Count -eq 0) {
      throw "Cannot apply -SearchOuNameFilter because no GPO links were loaded from Active Directory."
    }
    $allowedDns = Get-AllowedOuDnsForSearchFilter -Filters $ouFilterPatterns -IncludeChildren:([bool]$SearchOuIncludeChildren)
    if ($allowedDns.Count -eq 0) {
      throw "No organizational units matched -SearchOuNameFilter patterns: $($ouFilterPatterns -join ', ')"
    }
    $allowedGuids = [System.Collections.Generic.HashSet[Guid]]::new()
    foreach ($L in $links) {
      if ($allowedDns.Contains($L.LinkedOuDn)) { [void]$allowedGuids.Add($L.GpoGuid) }
    }
    $gpos = @($gpos | Where-Object { $allowedGuids.Contains([Guid]$_.Id) })
    if (-not $gpos -or $gpos.Count -eq 0) {
      throw "No GPOs are linked under OUs that matched the OU filter (or no GPOs left after name/regex filters)."
    }
  }

  $hits = [System.Collections.Generic.List[object]]::new()
  $n = 0
  $total = $gpos.Count
  foreach ($g in $gpos) {
    $n++
    Write-Progress -Activity 'Searching GPO settings' -Status $g.DisplayName -PercentComplete (($n / [double][Math]::Max(1, $total)) * 100)
    try {
      $xmlText = Get-GPOReport @gpoDom -Guid $g.Id -ReportType Xml -ErrorAction Stop
      [xml]$xml = $xmlText
      $rows = Get-AllFlattenedRows -Xml $xml -Gpo $g.DisplayName
      $gid = [Guid]$g.Id
      $linkedOuText = ''
      if ($null -ne $gpoGuidToFriendlyOus -and $gpoGuidToFriendlyOus.ContainsKey($gid)) {
        $linkedOuText = ($gpoGuidToFriendlyOus[$gid] | Sort-Object) -join '; '
      }
      foreach ($r in $rows) {
        if ($r.Extension -eq 'Metadata') { continue }
        $hay = "{0} {1} {2} {3} {4} {5}" -f $r.Scope, $r.Extension, $r.Category, $r.Setting, $r.Value, $r.Type
        if ($hay.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
          [void]$hits.Add([pscustomobject]@{
            GpoName   = $g.DisplayName
            GpoId     = '{' + ([string]$g.Id).Trim('{}') + '}'
            LinkedOUs = $linkedOuText
            Scope     = $r.Scope
            Extension = $r.Extension
            Category  = $r.Category
            Setting   = $r.Setting
            Value     = $r.Value
            Type      = $r.Type
          })
        }
      }
    } catch {
      Write-Warning "Failed to search GPO '$($g.DisplayName)': $($_.Exception.Message)"
    }
  }
  Write-Progress -Activity 'Searching GPO settings' -Completed

  $sorted = @($hits | Sort-Object GpoName, Extension, Category, Setting)
  # Format-Table must go to the host only; otherwise it pollutes the output stream and
  # $x = Invoke-SearchGpoSettings merges format objects with the return value (wrong .Count in GUI).
  $sorted | Format-Table -AutoSize | Out-Host
  Write-Host ("Found {0} matching row(s)." -f $sorted.Count) -ForegroundColor Cyan

  if ($SearchCsvOut) {
    $parent = Split-Path -Parent $SearchCsvOut
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
      New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $sorted | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath $SearchCsvOut
    Write-Host "CSV written: $SearchCsvOut" -ForegroundColor Cyan
  }

  return $sorted
}

function Invoke-FlattenXml {
  param(
    [Parameter(Mandatory)][string]$OutDir
  )

  $flattenDir = Join-Path $OutDir 'Flattened'
  Ensure-Folder -Path $flattenDir

  $inDir = Join-Path $OutDir 'Exports'
  $xmlFiles = Get-ChildItem -LiteralPath $inDir -Filter *.xml -File -ErrorAction Stop
  if ($xmlFiles.Count -eq 0) { throw "No XML files found in $inDir" }

  $allRows = [System.Collections.Generic.List[object]]::new()
  $counts  = @()

  foreach ($f in $xmlFiles) {
    $dnSafe = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
    $gpo    = ($dnSafe -replace '_',' ')

    [xml]$xml = [xml]([string](Get-Content -LiteralPath $f.FullName -Raw))

    $rows = Get-AllFlattenedRows -Xml $xml -Gpo $gpo

    $c = [pscustomobject]@{
      GPO                    = $gpo
      AdminTemplate_Policies = (Get-XPathNodes -Xml $xml -XPath "//*[local-name()='Policy']").Count
      AdminTemplate_RegNodes = (Get-XPathNodes -Xml $xml -XPath "//*[local-name()='RegistrySettings']/*[local-name()='Registry']").Count
      GPP_WindowsRegistry    = (Get-XPathNodes -Xml $xml -XPath "//*[local-name()='RegistrySettings']/*[local-name()='Registry']/*[local-name()='Properties']").Count
      SecuritySettings       = (Get-XPathNodes -Xml $xml -XPath "//*[local-name()='SecuritySettings']").Count
      LUGS_Groups            = (Get-XPathNodes -Xml $xml -XPath "//*[local-name()='LocalUsersAndGroups']/*[local-name()='Group']").Count
      NTServices             = (Get-XPathNodes -Xml $xml -XPath "//*[local-name()='NTServices']/*[local-name()='NTService']").Count
      Scripts                = (Get-XPathNodes -Xml $xml -XPath "//*[local-name()='Script']").Count
      WLanSvc                = (Get-XPathNodes -Xml $xml -XPath "//*[local-name()='Extension' and contains(@*, 'WLanSvcSettings')]//*[local-name()='WLanSvcSetting']|//*[local-name()='WLanPolicies']").Count
      TotalFlattenedRows     = $rows.Count
    }
    $counts += $c

    $flattenPath = Join-Path $flattenDir ("Flatten_{0}.csv" -f (New-SafeName $gpo))
    $rows | Sort-Object GPO,Scope,Extension,Category,Setting | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $flattenPath

    foreach ($r in $rows) { [void]$allRows.Add($r) }

    Write-Host ("[{0}] Policies={1} RegNodes={2} GPPRegProps={3} SecRoots={4} LUGS={5} Svc={6} Scripts={7} WLAN={8} Rows={9}" -f
      $gpo,$c.AdminTemplate_Policies,$c.AdminTemplate_RegNodes,$c.GPP_WindowsRegistry,$c.SecuritySettings,
      $c.LUGS_Groups,$c.NTServices,$c.Scripts,$c.WLanSvc,$c.TotalFlattenedRows) -ForegroundColor DarkCyan
  }

  $masterFlatten = Join-Path $OutDir "MasterFlatten_AllGPOs.csv"
  $allRows | Sort-Object GPO,Scope,Extension,Category,Setting | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $masterFlatten

  $countsPath = Join-Path $OutDir "MasterCounts_ByGPO.csv"
  $counts | Sort-Object GPO | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $countsPath

  Write-Host "Flattened CSVs: $flattenDir" -ForegroundColor Cyan
  Write-Host "Master flatten : $masterFlatten" -ForegroundColor Cyan
  Write-Host "Counts summary : $countsPath" -ForegroundColor Cyan
}

# -------------------- Compare two MasterFlatten CSVs (by file path) --------------------
function Invoke-FlattenCompare {
  param(
    [Parameter(Mandatory)][string]$LeftPath,
    [Parameter(Mandatory)][string]$RightPath,
    [Parameter(Mandatory)][string]$OutFolder
  )

  Ensure-Folder -Path $OutFolder

  if (-not (Test-Path -LiteralPath $LeftPath)) {
    throw "Left master flatten CSV not found: $LeftPath"
  }
  if (-not (Test-Path -LiteralPath $RightPath)) {
    throw "Right master flatten CSV not found: $RightPath"
  }

  $L = Import-Csv -LiteralPath $LeftPath
  $R = Import-Csv -LiteralPath $RightPath

  function Make-Id {
    param($x)
    # Compare at the "setting" level (ignoring which GPO set it) and field group.
    # CanonicalNoGpo is: Scope|Extension|Category|Setting
    $x.CanonicalNoGpo
  }

  $lIndex = @{}
  foreach ($x in $L) {
    $id = Make-Id $x
    if ($id) { $lIndex[$id] = $x }
  }

  $rIndex = @{}
  foreach ($x in $R) {
    $id = Make-Id $x
    if ($id) { $rIndex[$id] = $x }
  }

  $allIds = New-Object System.Collections.Generic.HashSet[string]
  foreach ($k in $lIndex.Keys) { [void]$allIds.Add($k) }
  foreach ($k in $rIndex.Keys) { [void]$allIds.Add($k) }

  $out = foreach ($id in ($allIds | Sort-Object)) {
    $l = $lIndex[$id]
    $r = $rIndex[$id]

    if ($null -eq $l) {
      [pscustomobject]@{
        Status        = 'Added'
        Scope         = $r.Scope
        Extension     = $r.Extension
        Category      = $r.Category
        Setting       = $r.Setting
        OldValue      = $null
        NewValue      = $r.Value
        CanonicalNoGpo = $id
      }
      continue
    }

    if ($null -eq $r) {
      [pscustomobject]@{
        Status        = 'Removed'
        Scope         = $l.Scope
        Extension     = $l.Extension
        Category      = $l.Category
        Setting       = $l.Setting
        OldValue      = $l.Value
        NewValue      = $null
        CanonicalNoGpo = $id
      }
      continue
    }

    $changed = ($l.Value -ne $r.Value)

    [pscustomobject]@{
      Status        = $(if ($changed) { 'Changed' } else { 'Unchanged' })
      Scope         = $r.Scope
      Extension     = $r.Extension
      Category      = $r.Category
      Setting       = $r.Setting
      OldValue      = $l.Value
      NewValue      = $r.Value
      CanonicalNoGpo = $id
    }
  }

  $csvOut = Join-Path $OutFolder "Compare-MasterFlatten.csv"
  $out | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath $csvOut

  Write-Host "Flatten compare sheet written to: $csvOut" -ForegroundColor Cyan
}

# -------------------- Compare two single-GPO flatten CSVs --------------------
function Invoke-FlattenGpoCompare {
  param(
    [Parameter(Mandatory)][string]$LeftCsv,
    [Parameter(Mandatory)][string]$RightCsv,
    [Parameter(Mandatory)][string]$OutCsv
  )

  if (-not (Test-Path -LiteralPath $LeftCsv)) {
    throw "Left flatten CSV not found: $LeftCsv"
  }
  if (-not (Test-Path -LiteralPath $RightCsv)) {
    throw "Right flatten CSV not found: $RightCsv"
  }

  $L = Import-Csv -LiteralPath $LeftCsv
  $R = Import-Csv -LiteralPath $RightCsv

  $leftGpoName  = ($L | Select-Object -ExpandProperty GPO -First 1)
  $rightGpoName = ($R | Select-Object -ExpandProperty GPO -First 1)

  function Make-Id {
    param($x)
    # Compare at the "setting" level (ignoring which GPO set it).
    $x.CanonicalNoGpo
  }

  $lIndex = @{}
  foreach ($x in $L) {
    $id = Make-Id $x
    if ($id) { $lIndex[$id] = $x }
  }

  $rIndex = @{}
  foreach ($x in $R) {
    $id = Make-Id $x
    if ($id) { $rIndex[$id] = $x }
  }

  $allIds = New-Object System.Collections.Generic.HashSet[string]
  foreach ($k in $lIndex.Keys) { [void]$allIds.Add($k) }
  foreach ($k in $rIndex.Keys) { [void]$allIds.Add($k) }

  $out = foreach ($id in ($allIds | Sort-Object)) {
    $l = $lIndex[$id]
    $r = $rIndex[$id]

    if ($null -eq $l) {
      $status = 'Added'
      $statusExplanation = 'Setting is only present in the RIGHT GPO (new in right).'
      [pscustomobject]@{
        Key               = $id
        Status            = $status
        StatusExplanation = $statusExplanation
        Scope             = $r.Scope
        Extension         = $r.Extension
        Category          = $r.Category
        Setting           = $r.Setting
        LeftGpo           = $leftGpoName
        LeftValue         = $null
        LeftType          = $null
        RightGpo          = $rightGpoName
        RightValue        = $r.Value
        RightType         = $r.Type
      }
      continue
    }

    if ($null -eq $r) {
      $status = 'Removed'
      $statusExplanation = 'Setting is only present in the LEFT GPO (missing in right).'
      [pscustomobject]@{
        Key               = $id
        Status            = $status
        StatusExplanation = $statusExplanation
        Scope             = $l.Scope
        Extension         = $l.Extension
        Category          = $l.Category
        Setting           = $l.Setting
        LeftGpo           = $leftGpoName
        LeftValue         = $l.Value
        LeftType          = $l.Type
        RightGpo          = $rightGpoName
        RightValue        = $null
        RightType         = $null
      }
      continue
    }

    $changed = ($l.Value -ne $r.Value)
    $status  = if ($changed) { 'Changed' } else { 'Unchanged' }
    $statusExplanation = if ($changed) {
      'Setting exists in both GPOs but the values differ.'
    } else {
      'Setting exists in both GPOs and the values are identical.'
    }

    [pscustomobject]@{
      Key               = $id
      Status            = $status
      StatusExplanation = $statusExplanation
      Scope             = $r.Scope
      Extension         = $r.Extension
      Category          = $r.Category
      Setting           = $r.Setting
      LeftGpo           = $leftGpoName
      LeftValue         = $l.Value
      LeftType          = $l.Type
      RightGpo          = $rightGpoName
      RightValue        = $r.Value
      RightType         = $r.Type
    }
  }

  $out | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath $OutCsv

  Write-Host "GPO-vs-GPO flatten compare written to: $OutCsv" -ForegroundColor Cyan
}

# -------------------- GUI for option 7: two-GPO compare --------------------
function Show-GpoCompareDialog {
  param(
    [string]$DefaultOutDir = "C:\Temp\GPO_Audit",
    [int]$DefaultThrottle = 6
  )

  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing

  $gpos = @()
  try {
    $gpoDom = Get-GpoAuditGpoDomainSplat
    $gpos = Get-GPO @gpoDom -All -ErrorAction Stop | Sort-Object DisplayName | ForEach-Object { $_.DisplayName }
  } catch {
    [System.Windows.Forms.MessageBox]::Show("Could not load GPO list: $($_.Exception.Message)", "GPO Compare", "OK", "Error")
    return $null
  }
  if (-not $gpos -or $gpos.Count -eq 0) {
    [System.Windows.Forms.MessageBox]::Show("No GPOs found in the domain.", "GPO Compare", "OK", "Warning")
    return $null
  }

  $form = New-Object System.Windows.Forms.Form
  $form.Text = "GPO Compare – Export, Flatten & Diff Two GPOs"
  $form.Size = New-Object System.Drawing.Size(540, 420)
  $form.StartPosition = "CenterScreen"
  $form.FormBorderStyle = "FixedDialog"
  $form.MaximizeBox = $false
  $form.MinimizeBox = $true

  $y = 16
  $rowH = 52
  $labelW = 140
  $ctrlX = 150
  $ctrlW = 340
  $btnW = 90

  # First GPO
  $lbl1 = New-Object System.Windows.Forms.Label
  $lbl1.Location = New-Object System.Drawing.Point -ArgumentList 16, $y
  $lbl1.Size = New-Object System.Drawing.Size($labelW, 20)
  $lbl1.Text = "First GPO:"
  $form.Controls.Add($lbl1)
  $y += 22
  $cb1 = New-Object System.Windows.Forms.ComboBox
  $cb1.Location = New-Object System.Drawing.Point -ArgumentList $ctrlX, ($y - 2)
  $cb1.Size = New-Object System.Drawing.Size($ctrlW, 24)
  $cb1.DropDownStyle = "DropDownList"
  $cb1.Sorted = $false
  foreach ($n in $gpos) { [void]$cb1.Items.Add($n) }
  if ($cb1.Items.Count -gt 0) { $cb1.SelectedIndex = 0 }
  $form.Controls.Add($cb1)
  $y += $rowH

  # Second GPO
  $lbl2 = New-Object System.Windows.Forms.Label
  $lbl2.Location = New-Object System.Drawing.Point -ArgumentList 16, $y
  $lbl2.Size = New-Object System.Drawing.Size($labelW, 20)
  $lbl2.Text = "Second GPO:"
  $form.Controls.Add($lbl2)
  $y += 22
  $cb2 = New-Object System.Windows.Forms.ComboBox
  $cb2.Location = New-Object System.Drawing.Point -ArgumentList $ctrlX, ($y - 2)
  $cb2.Size = New-Object System.Drawing.Size($ctrlW, 24)
  $cb2.DropDownStyle = "DropDownList"
  $cb2.Sorted = $false
  foreach ($n in $gpos) { [void]$cb2.Items.Add($n) }
  if ($cb2.Items.Count -gt 1) { $cb2.SelectedIndex = 1 } else { $cb2.SelectedIndex = 0 }
  $form.Controls.Add($cb2)
  $y += $rowH

  # Output folder
  $lblOut = New-Object System.Windows.Forms.Label
  $lblOut.Location = New-Object System.Drawing.Point -ArgumentList 16, $y
  $lblOut.Size = New-Object System.Drawing.Size($labelW, 20)
  $lblOut.Text = "Output folder:"
  $form.Controls.Add($lblOut)
  $y += 22
  $tbOut = New-Object System.Windows.Forms.TextBox
  $tbOut.Location = New-Object System.Drawing.Point -ArgumentList $ctrlX, ($y - 2)
  $tbOut.Size = New-Object System.Drawing.Size(260, 22)
  $tbOut.Text = $DefaultOutDir
  $form.Controls.Add($tbOut)
  $btnBrowse = New-Object System.Windows.Forms.Button
  $btnBrowse.Location = New-Object System.Drawing.Point -ArgumentList ($ctrlX + 268), ($y - 4)
  $btnBrowse.Size = New-Object System.Drawing.Size(74, 26)
  $btnBrowse.Text = "Browse..."
  $btnBrowse.Add_Click({
    $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
    $fbd.Description = "Select output folder for exports and flattened CSVs"
    $fbd.SelectedPath = $tbOut.Text
    if ($fbd.ShowDialog() -eq "OK") { $tbOut.Text = $fbd.SelectedPath }
  })
  $form.Controls.Add($btnBrowse)
  $y += $rowH

  # Throttle
  $lblThr = New-Object System.Windows.Forms.Label
  $lblThr.Location = New-Object System.Drawing.Point -ArgumentList 16, $y
  $lblThr.Size = New-Object System.Drawing.Size($labelW, 20)
  $lblThr.Text = "Parallel throttle:"
  $form.Controls.Add($lblThr)
  $numThrottle = New-Object System.Windows.Forms.NumericUpDown
  $numThrottle.Location = New-Object System.Drawing.Point -ArgumentList $ctrlX, ($y - 2)
  $numThrottle.Size = New-Object System.Drawing.Size(80, 22)
  $numThrottle.Minimum = 1
  $numThrottle.Maximum = 32
  $numThrottle.Value = [Math]::Min([Math]::Max($DefaultThrottle, 1), 32)
  $form.Controls.Add($numThrottle)
  $y += $rowH

  # Diff output path (optional)
  $lblDiff = New-Object System.Windows.Forms.Label
  $lblDiff.Location = New-Object System.Drawing.Point -ArgumentList 16, $y
  $lblDiff.Size = New-Object System.Drawing.Size(400, 20)
  $lblDiff.Text = "Diff CSV path (optional – default: Diffs\Diff_ByGPO_<timestamp>.csv):"
  $form.Controls.Add($lblDiff)
  $y += 22
  $tbDiff = New-Object System.Windows.Forms.TextBox
  $tbDiff.Location = New-Object System.Drawing.Point -ArgumentList $ctrlX, ($y - 2)
  $tbDiff.Size = New-Object System.Drawing.Size($ctrlW, 22)
  $tbDiff.Text = ""
  $form.Controls.Add($tbDiff)
  $y += 36

  # Run / Cancel
  $btnRun = New-Object System.Windows.Forms.Button
  $btnRun.Location = New-Object System.Drawing.Point -ArgumentList $ctrlX, $y
  $btnRun.Size = New-Object System.Drawing.Size($btnW, 28)
  $btnRun.Text = "Run"
  $btnRun.DialogResult = [System.Windows.Forms.DialogResult]::OK
  $form.AcceptButton = $btnRun
  $form.Controls.Add($btnRun)
  $btnCancel = New-Object System.Windows.Forms.Button
  $btnCancel.Location = New-Object System.Drawing.Point -ArgumentList ($ctrlX + 96), $y
  $btnCancel.Size = New-Object System.Drawing.Size($btnW, 28)
  $btnCancel.Text = "Cancel"
  $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
  $form.CancelButton = $btnCancel
  $form.Controls.Add($btnCancel)

  $form.TopMost = $true
  $result = $form.ShowDialog()

  if ($result -ne [System.Windows.Forms.DialogResult]::OK) { return $null }

  $gpo1 = $cb1.SelectedItem
  $gpo2 = $cb2.SelectedItem
  if ([string]::IsNullOrWhiteSpace($gpo1) -or [string]::IsNullOrWhiteSpace($gpo2)) {
    [System.Windows.Forms.MessageBox]::Show("Please select both GPOs.", "GPO Compare", "OK", "Warning")
    return $null
  }
  if ($gpo1 -eq $gpo2) {
    [System.Windows.Forms.MessageBox]::Show("First and Second GPO must be different.", "GPO Compare", "OK", "Warning")
    return $null
  }

  $outDir = $tbOut.Text.Trim()
  if ([string]::IsNullOrWhiteSpace($outDir)) { $outDir = $DefaultOutDir }

  $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
  $diffsDir = Join-Path $outDir 'Diffs'
  $defaultDiffPath = Join-Path $diffsDir ("Diff_ByGPO_{0}.csv" -f $timestamp)
  $comparePath = $tbDiff.Text.Trim()
  if ([string]::IsNullOrWhiteSpace($comparePath)) { $comparePath = $defaultDiffPath }

  @{
    Gpo1        = $gpo1
    Gpo2        = $gpo2
    OutDir      = $outDir
    Throttle    = [int]$numThrottle.Value
    ComparePath = $comparePath
  }
}

# -------------------- Main GUI: all actions in one window --------------------
function Show-GpoAuditMasterMainGui {
  param(
    [string]$DefaultOutDir = "C:\Temp\GPO_Audit",
    [int]$DefaultThrottle = 6,
    [string]$InitialDomainDnsName = $null
  )

  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing

  $actions = @(
    '1. Export GPO XML only',
    '2. Flatten existing XML to CSV',
    '3. Export GPO XML and then flatten',
    '4. Registry key+value snapshot',
    '5. Compare two registry snapshots',
    '6. Export + flatten + compare to previous',
    '7. Export + flatten two GPOs and compare',
    '8. Search settings (text) across GPOs'
  )

  $form = New-Object System.Windows.Forms.Form
  $form.Text = "GPO Audit Master"
  $form.Size = New-Object System.Drawing.Size(736, 640)
  $form.StartPosition = "CenterScreen"
  $form.FormBorderStyle = "FixedDialog"
  $form.MaximizeBox = $false

  # Inner layout (matches content panel width); keeps Browse/Save inside the panel
  $gMarginR = 12
  $gPanelW = 688
  $gCtrlLeft = 150
  $gBrowseBtnW = 72
  $gGap = 8
  $gTextWithBrowseW = [Math]::Max(280, $gPanelW - $gCtrlLeft - $gGap - $gBrowseBtnW - $gMarginR)
  $gTextWNoBtn = [Math]::Max(320, $gPanelW - $gCtrlLeft - $gMarginR)
  $gBrowseX = $gCtrlLeft + $gTextWithBrowseW + $gGap
  $gHintW = $gPanelW - 16

  $y = 12
  $lblDomain = New-Object System.Windows.Forms.Label
  $lblDomain.Location = New-Object System.Drawing.Point -ArgumentList 16, $y
  $lblDomain.Size = New-Object System.Drawing.Size($gPanelW, 20)
  $lblDomain.Text = "Domain (DNS) for GPOs and Active Directory:"
  $form.Controls.Add($lblDomain)
  $y += 24
  $domainCb = New-Object System.Windows.Forms.ComboBox
  $domainCb.Location = New-Object System.Drawing.Point -ArgumentList 16, $y
  $domainCb.Size = New-Object System.Drawing.Size($gPanelW, 24)
  $domainCb.DropDownStyle = "DropDownList"
  $form.Controls.Add($domainCb)
  $y += 36

  $lblAction = New-Object System.Windows.Forms.Label
  $lblAction.Location = New-Object System.Drawing.Point -ArgumentList 16, $y
  $lblAction.Size = New-Object System.Drawing.Size(400, 20)
  $lblAction.Text = "What do you want to do?"
  $form.Controls.Add($lblAction)
  $y += 24
  $cbAction = New-Object System.Windows.Forms.ComboBox
  $cbAction.Location = New-Object System.Drawing.Point -ArgumentList 16, $y
  $cbAction.Size = New-Object System.Drawing.Size($gPanelW, 24)
  $cbAction.DropDownStyle = "DropDownList"
  foreach ($a in $actions) { [void]$cbAction.Items.Add($a) }
  $cbAction.SelectedIndex = 0
  $form.Controls.Add($cbAction)
  $y += 36

  $contentPanel = New-Object System.Windows.Forms.Panel
  $contentPanel.Location = New-Object System.Drawing.Point -ArgumentList 16, $y
  $contentPanel.Size = New-Object System.Drawing.Size($gPanelW, 380)
  $contentPanel.BorderStyle = "FixedSingle"
  $contentPanel.AutoScroll = $true
  $form.Controls.Add($contentPanel)

  $btnRun = New-Object System.Windows.Forms.Button
  $runBtnY = $y + 388
  $btnRun.Location = New-Object System.Drawing.Point -ArgumentList 16, $runBtnY
  $btnRun.Size = New-Object System.Drawing.Size(90, 28)
  $btnRun.Text = "Run"
  $form.Controls.Add($btnRun)
  $btnClose = New-Object System.Windows.Forms.Button
  $btnClose.Location = New-Object System.Drawing.Point -ArgumentList 112, $runBtnY
  $btnClose.Size = New-Object System.Drawing.Size(90, 28)
  $btnClose.Text = "Close"
  $form.Controls.Add($btnClose)

  $statusLabel = New-Object System.Windows.Forms.Label
  $statusLabel.Location = New-Object System.Drawing.Point -ArgumentList 210, ($runBtnY + 6)
  $statusLabel.Size = New-Object System.Drawing.Size(500, 36)
  $statusLabel.AutoSize = $false
  $statusLabel.Text = ""
  $statusLabel.ForeColor = [System.Drawing.Color]::DarkGreen
  $form.Controls.Add($statusLabel)

  function Add-Row { param([System.Windows.Forms.Panel]$P, [ref]$Y, [string]$LabelText, [object]$Control)
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Location = New-Object System.Drawing.Point -ArgumentList 8, $Y.Value
    $lbl.Size = New-Object System.Drawing.Size(136, 20)
    $lbl.Text = $LabelText
    $P.Controls.Add($lbl)
    $ctrl = $Control
    $ctrlY = $Y.Value - 2
    $ctrl.Location = New-Object System.Drawing.Point -ArgumentList $gCtrlLeft, $ctrlY
    if ($ctrl -is [System.Windows.Forms.TextBox]) { $ctrl.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22) }
    elseif ($ctrl -is [System.Windows.Forms.ComboBox]) {
      if ($ctrl.Size.Width -lt 10) { $ctrl.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22) }
      $ctrl.IntegralHeight = $false
    }
    $P.Controls.Add($ctrl)
    $Y.Value += 32
  }
  function Add-BrowseButton { param([System.Windows.Forms.Panel]$P, [int]$X, [int]$Y, [System.Windows.Forms.TextBox]$Tb, [string]$Description)
    $btn = New-Object System.Windows.Forms.Button
    $btn.Location = New-Object System.Drawing.Point -ArgumentList $X, $Y
    $btn.Size = New-Object System.Drawing.Size(70, 24)
    $btn.Text = "Browse..."
    $btn.Add_Click({
      $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
      $fbd.Description = $Description
      $fbd.SelectedPath = $Tb.Text
      if ($fbd.ShowDialog() -eq "OK") { $Tb.Text = $fbd.SelectedPath }
    })
    $P.Controls.Add($btn)
  }

  $script:gpoDomainUiSuppressEvent = $false
  $domainCb.Add_SelectedIndexChanged({
    if ($script:gpoDomainUiSuppressEvent) { return }
    if ($null -eq $domainCb.SelectedItem) { return }
    $sel = [string]$domainCb.SelectedItem
    try {
      Initialize-GpoAuditAdContext -DomainDnsName $sel
      $statusLabel.Text = "Domain: $script:GpoAuditDomainDns"
      if ($script:panelState -and $script:panelState.OuFilterCb) {
        $ou = $script:panelState.OuFilterCb
        $ou.Items.Clear()
        $ou.Tag = $null
        $ou.Text = ''
      }
    } catch {
      [System.Windows.Forms.MessageBox]::Show(
        "Could not connect to domain '$sel': $($_.Exception.Message)",
        'GPO Audit Master', 'OK', 'Error')
    }
  })

  function Build-OptionsPanel {
    param([int]$Index)
    $contentPanel.Controls.Clear()
    $ry = 8
    $outDirTb = $null
    $throttleNum = $null
    $filterChk = $null
    $namesTb = $null
    $regexTb = $null
    $guidsTb = $null
    $leftFolderTb = $null
    $rightFolderTb = $null
    $outFolderTb = $null
    $baselineTb = $null
    $compareOutTb = $null
    $searchTb = $null
    $searchCsvTb = $null
    $ouFilterCb = $null
    $ouChildrenChk = $null

    switch ($Index) {
      0 { # XmlExport
        $outDirTb = New-Object System.Windows.Forms.TextBox; $outDirTb.Text = $DefaultOutDir
        Add-Row $contentPanel ([ref]$ry) "Output folder:" $outDirTb
        $outDirTb.Width = $gTextWithBrowseW
        Add-BrowseButton $contentPanel $gBrowseX ($ry - 10) $outDirTb "Output folder for GPO XML exports"
        $ry += 28
        $throttleNum = New-Object System.Windows.Forms.NumericUpDown
        $throttleNum.Minimum = 1; $throttleNum.Maximum = 32; $throttleNum.Value = $DefaultThrottle; $throttleNum.Size = New-Object System.Drawing.Size(60, 22)
        Add-Row $contentPanel ([ref]$ry) "Parallel throttle:" $throttleNum
        $ry += 8
        $filterChk = New-Object System.Windows.Forms.CheckBox; $filterChk.Text = "Filter to specific GPOs"; $filterChk.Size = New-Object System.Drawing.Size(200, 22)
        Add-Row $contentPanel ([ref]$ry) "" $filterChk
        $namesTb = New-Object System.Windows.Forms.TextBox; $namesTb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22); $namesTb.Height = 22
        $contentPanel.Controls.Add($namesTb); $namesTb.Location = New-Object System.Drawing.Point -ArgumentList $gCtrlLeft, ($ry - 2); $ry += 28
        $l = New-Object System.Windows.Forms.Label; $l.Location = New-Object System.Drawing.Point -ArgumentList 8, $ry; $l.Text = "GPO names (comma):"; $l.Size = New-Object System.Drawing.Size(140, 20); $contentPanel.Controls.Add($l); $ry += 22
        $regexTb = New-Object System.Windows.Forms.TextBox; $regexTb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22)
        $contentPanel.Controls.Add($regexTb); $regexTb.Location = New-Object System.Drawing.Point -ArgumentList $gCtrlLeft, ($ry - 2); $ry += 28
        $l2 = New-Object System.Windows.Forms.Label; $l2.Location = New-Object System.Drawing.Point -ArgumentList 8, $ry; $l2.Text = "Display name regex:"; $l2.Size = New-Object System.Drawing.Size(140, 20); $contentPanel.Controls.Add($l2); $ry += 22
        $guidsTb = New-Object System.Windows.Forms.TextBox; $guidsTb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22)
        $contentPanel.Controls.Add($guidsTb); $guidsTb.Location = New-Object System.Drawing.Point -ArgumentList $gCtrlLeft, ($ry - 2)
      }
      1 { # FlattenXml
        $outDirTb = New-Object System.Windows.Forms.TextBox; $outDirTb.Text = $DefaultOutDir
        Add-Row $contentPanel ([ref]$ry) "Output folder (Exports):" $outDirTb
        $outDirTb.Width = $gTextWithBrowseW
        Add-BrowseButton $contentPanel $gBrowseX ($ry - 10) $outDirTb "Folder containing Exports and where Flattened will be written"
      }
      2 { # XmlExportAndFlatten
        $outDirTb = New-Object System.Windows.Forms.TextBox; $outDirTb.Text = $DefaultOutDir
        Add-Row $contentPanel ([ref]$ry) "Output folder:" $outDirTb
        $outDirTb.Width = $gTextWithBrowseW
        Add-BrowseButton $contentPanel $gBrowseX ($ry - 10) $outDirTb "Output folder"
        $ry += 28
        $throttleNum = New-Object System.Windows.Forms.NumericUpDown
        $throttleNum.Minimum = 1; $throttleNum.Maximum = 32; $throttleNum.Value = $DefaultThrottle; $throttleNum.Size = New-Object System.Drawing.Size(60, 22)
        Add-Row $contentPanel ([ref]$ry) "Parallel throttle:" $throttleNum
        $ry += 8
        $filterChk = New-Object System.Windows.Forms.CheckBox; $filterChk.Text = "Filter to specific GPOs"; $filterChk.Size = New-Object System.Drawing.Size(200, 22)
        Add-Row $contentPanel ([ref]$ry) "" $filterChk
        $namesTb = New-Object System.Windows.Forms.TextBox; $namesTb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22)
        $contentPanel.Controls.Add($namesTb); $namesTb.Location = New-Object System.Drawing.Point -ArgumentList $gCtrlLeft, ($ry - 2); $ry += 28
        $l = New-Object System.Windows.Forms.Label; $l.Location = New-Object System.Drawing.Point -ArgumentList 8, $ry; $l.Text = "GPO names (comma):"; $l.Size = New-Object System.Drawing.Size(140, 20); $contentPanel.Controls.Add($l); $ry += 22
        $regexTb = New-Object System.Windows.Forms.TextBox; $regexTb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22)
        $contentPanel.Controls.Add($regexTb); $regexTb.Location = New-Object System.Drawing.Point -ArgumentList $gCtrlLeft, ($ry - 2); $ry += 28
        $l2 = New-Object System.Windows.Forms.Label; $l2.Location = New-Object System.Drawing.Point -ArgumentList 8, $ry; $l2.Text = "Display name regex:"; $l2.Size = New-Object System.Drawing.Size(140, 20); $contentPanel.Controls.Add($l2); $ry += 22
        $guidsTb = New-Object System.Windows.Forms.TextBox; $guidsTb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22)
        $contentPanel.Controls.Add($guidsTb); $guidsTb.Location = New-Object System.Drawing.Point -ArgumentList $gCtrlLeft, ($ry - 2)
      }
      3 { # RegistrySnapshotExport
        $outDirTb = New-Object System.Windows.Forms.TextBox; $outDirTb.Text = $DefaultOutDir
        Add-Row $contentPanel ([ref]$ry) "Snapshot folder:" $outDirTb
        $outDirTb.Width = $gTextWithBrowseW
        Add-BrowseButton $contentPanel $gBrowseX ($ry - 10) $outDirTb "Snapshot output folder"
        $ry += 8
        $filterChk = New-Object System.Windows.Forms.CheckBox; $filterChk.Text = "Filter to specific GPOs"; $filterChk.Size = New-Object System.Drawing.Size(200, 22)
        Add-Row $contentPanel ([ref]$ry) "" $filterChk
        $namesTb = New-Object System.Windows.Forms.TextBox; $namesTb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22)
        $contentPanel.Controls.Add($namesTb); $namesTb.Location = New-Object System.Drawing.Point -ArgumentList $gCtrlLeft, ($ry - 2); $ry += 28
        $l = New-Object System.Windows.Forms.Label; $l.Location = New-Object System.Drawing.Point -ArgumentList 8, $ry; $l.Text = "GPO names (comma):"; $l.Size = New-Object System.Drawing.Size(140, 20); $contentPanel.Controls.Add($l); $ry += 22
        $regexTb = New-Object System.Windows.Forms.TextBox; $regexTb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22)
        $contentPanel.Controls.Add($regexTb); $regexTb.Location = New-Object System.Drawing.Point -ArgumentList $gCtrlLeft, ($ry - 2); $ry += 28
        $l2 = New-Object System.Windows.Forms.Label; $l2.Location = New-Object System.Drawing.Point -ArgumentList 8, $ry; $l2.Text = "Display name regex:"; $l2.Size = New-Object System.Drawing.Size(140, 20); $contentPanel.Controls.Add($l2); $ry += 22
        $guidsTb = New-Object System.Windows.Forms.TextBox; $guidsTb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22)
        $contentPanel.Controls.Add($guidsTb); $guidsTb.Location = New-Object System.Drawing.Point -ArgumentList $gCtrlLeft, ($ry - 2)
      }
      4 { # RegistrySnapshotCompare
        $leftFolderTb = New-Object System.Windows.Forms.TextBox; $leftFolderTb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22)
        Add-Row $contentPanel ([ref]$ry) "Baseline folder (Left):" $leftFolderTb
        $leftFolderTb.Width = $gTextWithBrowseW
        Add-BrowseButton $contentPanel $gBrowseX ($ry - 10) $leftFolderTb "Baseline snapshot folder"
        $ry += 28
        $rightFolderTb = New-Object System.Windows.Forms.TextBox; $rightFolderTb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22)
        Add-Row $contentPanel ([ref]$ry) "Current folder (Right):" $rightFolderTb
        $rightFolderTb.Width = $gTextWithBrowseW
        Add-BrowseButton $contentPanel $gBrowseX ($ry - 10) $rightFolderTb "Current snapshot folder"
        $ry += 28
        $outFolderTb = New-Object System.Windows.Forms.TextBox; $outFolderTb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22)
        Add-Row $contentPanel ([ref]$ry) "Output folder for diff:" $outFolderTb
        $outFolderTb.Width = $gTextWithBrowseW
        Add-BrowseButton $contentPanel $gBrowseX ($ry - 10) $outFolderTb "Compare output folder"
      }
      5 { # Export + flatten + compare to previous
        $outDirTb = New-Object System.Windows.Forms.TextBox; $outDirTb.Text = $DefaultOutDir
        Add-Row $contentPanel ([ref]$ry) "Output folder (new run):" $outDirTb
        $outDirTb.Width = $gTextWithBrowseW
        Add-BrowseButton $contentPanel $gBrowseX ($ry - 10) $outDirTb "Output folder"
        $ry += 28
        $throttleNum = New-Object System.Windows.Forms.NumericUpDown
        $throttleNum.Minimum = 1; $throttleNum.Maximum = 32; $throttleNum.Value = $DefaultThrottle; $throttleNum.Size = New-Object System.Drawing.Size(60, 22)
        Add-Row $contentPanel ([ref]$ry) "Parallel throttle:" $throttleNum
        $ry += 28
        $baselineTb = New-Object System.Windows.Forms.TextBox; $baselineTb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22)
        Add-Row $contentPanel ([ref]$ry) "Baseline folder:" $baselineTb
        $baselineTb.Width = $gTextWithBrowseW
        Add-BrowseButton $contentPanel $gBrowseX ($ry - 10) $baselineTb "Folder with previous MasterFlatten_AllGPOs.csv"
        $ry += 28
        $compareOutTb = New-Object System.Windows.Forms.TextBox; $compareOutTb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22)
        Add-Row $contentPanel ([ref]$ry) "Compare output folder:" $compareOutTb
        $compareOutTb.Width = $gTextWithBrowseW
        Add-BrowseButton $contentPanel $gBrowseX ($ry - 10) $compareOutTb "Where to write compare CSV"
        $ry += 8
        $filterChk = New-Object System.Windows.Forms.CheckBox; $filterChk.Text = "Filter to specific GPOs"; $filterChk.Size = New-Object System.Drawing.Size(200, 22)
        Add-Row $contentPanel ([ref]$ry) "" $filterChk
        $namesTb = New-Object System.Windows.Forms.TextBox; $namesTb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22)
        $contentPanel.Controls.Add($namesTb); $namesTb.Location = New-Object System.Drawing.Point -ArgumentList $gCtrlLeft, ($ry - 2); $ry += 28
        $l = New-Object System.Windows.Forms.Label; $l.Location = New-Object System.Drawing.Point -ArgumentList 8, $ry; $l.Text = "GPO names (comma):"; $l.Size = New-Object System.Drawing.Size(140, 20); $contentPanel.Controls.Add($l); $ry += 22
        $regexTb = New-Object System.Windows.Forms.TextBox; $regexTb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22)
        $contentPanel.Controls.Add($regexTb); $regexTb.Location = New-Object System.Drawing.Point -ArgumentList $gCtrlLeft, ($ry - 2); $ry += 28
        $l2 = New-Object System.Windows.Forms.Label; $l2.Location = New-Object System.Drawing.Point -ArgumentList 8, $ry; $l2.Text = "Display name regex:"; $l2.Size = New-Object System.Drawing.Size(140, 20); $contentPanel.Controls.Add($l2); $ry += 22
        $guidsTb = New-Object System.Windows.Forms.TextBox; $guidsTb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22)
        $contentPanel.Controls.Add($guidsTb); $guidsTb.Location = New-Object System.Drawing.Point -ArgumentList $gCtrlLeft, ($ry - 2)
      }
      6 { # Two GPO compare
        $info = New-Object System.Windows.Forms.Label
        $info.Location = New-Object System.Drawing.Point -ArgumentList 12, 12
        $info.Size = New-Object System.Drawing.Size(($gPanelW - 24), 80)
        $info.Text = "Click Run to open the GPO selection dialog. You will choose two GPOs, output folder, throttle, and diff file path there."
        $info.AutoSize = $false
        $info.ForeColor = [System.Drawing.Color]::DarkSlateGray
        $contentPanel.Controls.Add($info)
      }
      7 { # Search settings across GPOs
        $searchTb = New-Object System.Windows.Forms.TextBox
        $searchTb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22)
        Add-Row $contentPanel ([ref]$ry) "Search text:" $searchTb
        $hint = New-Object System.Windows.Forms.Label
        $hint.Location = New-Object System.Drawing.Point -ArgumentList 8, $ry
        $hint.MaximumSize = New-Object System.Drawing.Size($gHintW, 0)
        $hint.AutoSize = $true
        $hint.Text = "Case-insensitive substring on policy names, registry paths, values, categories, etc. Example: turn off"
        $hint.ForeColor = [System.Drawing.Color]::DarkSlateGray
        $contentPanel.Controls.Add($hint)
        $ry += 48
        $ouFilterCb = New-Object System.Windows.Forms.ComboBox
        $ouFilterCb.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDown
        $ouFilterCb.AutoCompleteMode = [System.Windows.Forms.AutoCompleteMode]::SuggestAppend
        $ouFilterCb.AutoCompleteSource = [System.Windows.Forms.AutoCompleteSource]::ListItems
        $ouFilterCb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22)
        Add-Row $contentPanel ([ref]$ry) "OU filter (optional):" $ouFilterCb
        $ouHint = New-Object System.Windows.Forms.Label
        $ouHint.Location = New-Object System.Drawing.Point -ArgumentList 8, $ry
        $ouHint.MaximumSize = New-Object System.Drawing.Size($gHintW, 0)
        $ouHint.AutoSize = $true
        $ouHint.Text = "Type to search OU name or path (canonical). Comma = multiple patterns. OU list loads automatically when you choose this action; you can edit the text or pick from the list."
        $ouHint.ForeColor = [System.Drawing.Color]::DarkSlateGray
        $contentPanel.Controls.Add($ouHint)
        $ry += 64
        $adRsatStatus = New-Object System.Windows.Forms.Label
        $adRsatStatus.Location = New-Object System.Drawing.Point -ArgumentList 8, $ry
        $adRsatStatus.MaximumSize = New-Object System.Drawing.Size($gHintW, 0)
        $adRsatStatus.AutoSize = $true
        try {
          if (Test-ActiveDirectoryModuleAvailable) {
            $adRsatStatus.Text = "RSAT Active Directory PowerShell module: installed (module package found on this PC)."
            $adRsatStatus.ForeColor = [System.Drawing.Color]::DarkGreen
          } else {
            $adRsatStatus.Text = "RSAT Active Directory module: NOT found. Install Optional feature: Active Directory Domain Services and Lightweight Directory Services Tools, then restart PowerShell. Required for OU list and LinkedOUs."
            $adRsatStatus.ForeColor = [System.Drawing.Color]::DarkRed
          }
        } catch {
          $adRsatStatus.Text = "Could not verify RSAT Active Directory module (see PowerShell window for errors)."
          $adRsatStatus.ForeColor = [System.Drawing.Color]::DarkOrange
        }
        $contentPanel.Controls.Add($adRsatStatus)
        $ry += 56
        $ouChildrenChk = New-Object System.Windows.Forms.CheckBox
        $ouChildrenChk.Text = "Include child OUs (GPOs linked under matching OU or any descendant)"
        $ouChildrenChk.AutoSize = $false
        $ouChildrenChk.Size = New-Object System.Drawing.Size($gHintW, 36)
        $ouChildrenChk.Location = New-Object System.Drawing.Point -ArgumentList 8, $ry
        $contentPanel.Controls.Add($ouChildrenChk)
        $ry += 40
        $ouComboRef = $ouFilterCb
        # Preload on focus so Items exist before the list opens; DropDown+AutoComplete alone often leaves the list empty.
        $ouFilterCb.Add_GotFocus({ if ($null -ne $ouComboRef) { Invoke-GpoAuditOuComboPopulate -Combo $ouComboRef } })
        $ouFilterCb.Add_DropDown({ if ($null -ne $ouComboRef) { Invoke-GpoAuditOuComboPopulate -Combo $ouComboRef } })
        $searchCsvTb = New-Object System.Windows.Forms.TextBox
        $searchCsvTb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22)
        Add-Row $contentPanel ([ref]$ry) "CSV output (opt):" $searchCsvTb
        $searchCsvTb.Width = $gTextWithBrowseW
        $btnSaveCsv = New-Object System.Windows.Forms.Button
        $btnSaveCsv.Location = New-Object System.Drawing.Point -ArgumentList $gBrowseX, ($ry - 10)
        $btnSaveCsv.Size = New-Object System.Drawing.Size(70, 24)
        $btnSaveCsv.Text = "Save..."
        $btnSaveCsv.Tag = $searchCsvTb
        $btnSaveCsv.Add_Click({
          param($sender, $e)
          $tb = $sender.Tag
          if ($null -eq $tb -or $tb -isnot [System.Windows.Forms.TextBox]) { return }
          $sfd = New-Object System.Windows.Forms.SaveFileDialog
          $sfd.Filter = "CSV (*.csv)|*.csv|All files (*.*)|*.*"
          $sfd.FileName = "GpoSettingSearch.csv"
          if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $tb.Text = $sfd.FileName
          }
        })
        $contentPanel.Controls.Add($btnSaveCsv)
        $ry += 28
        $filterChk = New-Object System.Windows.Forms.CheckBox; $filterChk.Text = "Filter to specific GPOs"; $filterChk.Size = New-Object System.Drawing.Size(200, 22)
        Add-Row $contentPanel ([ref]$ry) "" $filterChk
        $namesTb = New-Object System.Windows.Forms.TextBox; $namesTb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22)
        $contentPanel.Controls.Add($namesTb); $namesTb.Location = New-Object System.Drawing.Point -ArgumentList $gCtrlLeft, ($ry - 2); $ry += 28
        $l = New-Object System.Windows.Forms.Label; $l.Location = New-Object System.Drawing.Point -ArgumentList 8, $ry; $l.Text = "GPO names (comma):"; $l.Size = New-Object System.Drawing.Size(140, 20); $contentPanel.Controls.Add($l); $ry += 22
        $regexTb = New-Object System.Windows.Forms.TextBox; $regexTb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22)
        $contentPanel.Controls.Add($regexTb); $regexTb.Location = New-Object System.Drawing.Point -ArgumentList $gCtrlLeft, ($ry - 2); $ry += 28
        $l2 = New-Object System.Windows.Forms.Label; $l2.Location = New-Object System.Drawing.Point -ArgumentList 8, $ry; $l2.Text = "Display name regex:"; $l2.Size = New-Object System.Drawing.Size(140, 20); $contentPanel.Controls.Add($l2); $ry += 22
        $guidsTb = New-Object System.Windows.Forms.TextBox; $guidsTb.Size = New-Object System.Drawing.Size($gTextWNoBtn, 22)
        $contentPanel.Controls.Add($guidsTb); $guidsTb.Location = New-Object System.Drawing.Point -ArgumentList $gCtrlLeft, ($ry - 2)
      }
    }

    @{
      OutDirTb = $outDirTb; ThrottleNum = $throttleNum; FilterChk = $filterChk
      NamesTb = $namesTb; RegexTb = $regexTb; GuidsTb = $guidsTb
      LeftFolderTb = $leftFolderTb; RightFolderTb = $rightFolderTb; OutFolderTb = $outFolderTb
      BaselineTb = $baselineTb; CompareOutTb = $compareOutTb
      SearchTb = $searchTb; SearchCsvTb = $searchCsvTb
      OuFilterCb = $ouFilterCb; OuChildrenChk = $ouChildrenChk
    }
  }

  $panelState = Build-OptionsPanel 0
  $form.Add_Shown({
    try {
      $script:gpoDomainUiSuppressEvent = $true
      $domainCb.Items.Clear()
      $names = Get-GpoAuditForestDomainDnsNames
      foreach ($n in $names) { [void]$domainCb.Items.Add($n) }
      $idx = 0
      $want = $InitialDomainDnsName
      if (-not [string]::IsNullOrWhiteSpace($want)) {
        $want = $want.Trim()
        for ($i = 0; $i -lt $domainCb.Items.Count; $i++) {
          if ([string]::Equals([string]$domainCb.Items[$i], $want, [StringComparison]::OrdinalIgnoreCase)) {
            $idx = $i
            break
          }
        }
      }
      if ($domainCb.Items.Count -gt 0) { $domainCb.SelectedIndex = $idx }
    } catch {
      [System.Windows.Forms.MessageBox]::Show(
        "Could not list domains (forest or current domain). $($_.Exception.Message)",
        'GPO Audit Master', 'OK', 'Warning')
    } finally {
      $script:gpoDomainUiSuppressEvent = $false
    }
    try {
      if ($domainCb.Items.Count -gt 0 -and $null -ne $domainCb.SelectedItem) {
        Initialize-GpoAuditAdContext -DomainDnsName ([string]$domainCb.SelectedItem)
        $statusLabel.Text = "Domain: $script:GpoAuditDomainDns"
      }
    } catch {
      [System.Windows.Forms.MessageBox]::Show(
        "Could not initialize AD context: $($_.Exception.Message)",
        'GPO Audit Master', 'OK', 'Warning')
    }
    $cbAction.Focus()
  })
  $cbAction.Add_SelectedIndexChanged({
    $script:panelState = Build-OptionsPanel $cbAction.SelectedIndex
    if ($cbAction.SelectedIndex -eq 7) {
      $ouCombo = $script:panelState.OuFilterCb
      if ($null -ne $ouCombo) {
        try {
          # Must call synchronously on the UI thread; BeginInvoke + MethodInvoker does not bind $cb in PowerShell (Combo was null).
          Invoke-GpoAuditOuComboPopulate -Combo $ouCombo
        } catch {
          Show-GpoAuditOuComboLoadFailure -ErrorRecord $_
        }
      }
    }
  })

  function Get-FilterParams {
    param($state)
    $includeNames = $null
    $regex = $null
    $includeIds = $null
    if ($state.FilterChk -and $state.FilterChk.Checked) {
      if ($state.NamesTb -and $state.NamesTb.Text.Trim()) {
        $includeNames = $state.NamesTb.Text.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
      }
      if ($state.RegexTb -and $state.RegexTb.Text.Trim()) { $regex = $state.RegexTb.Text.Trim() }
      if ($state.GuidsTb -and $state.GuidsTb.Text.Trim()) {
        $includeIds = $state.GuidsTb.Text.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
      }
    }
    @{ IncludeGpoName = $includeNames; IncludeGpoNameRegex = $regex; IncludeGpoId = $includeIds }
  }

  $btnRun.Add_Click({
    $statusLabel.Text = ""
    $idx = $cbAction.SelectedIndex
    $state = $script:panelState
    try {
      switch ($idx) {
        0 {
          $outDir = if ($state.OutDirTb.Text.Trim()) { $state.OutDirTb.Text.Trim() } else { $DefaultOutDir }
          $thr = if ($state.ThrottleNum) { [int]$state.ThrottleNum.Value } else { $DefaultThrottle }
          $fp = Get-FilterParams $state
          Invoke-XmlExport -OutDir $outDir -Throttle $thr -IncludeGpoName $fp.IncludeGpoName -IncludeGpoNameRegex $fp.IncludeGpoNameRegex -IncludeGpoId $fp.IncludeGpoId
          $statusLabel.Text = "Export complete: $outDir\Exports"
        }
        1 {
          $outDir = if ($state.OutDirTb.Text.Trim()) { $state.OutDirTb.Text.Trim() } else { $DefaultOutDir }
          Invoke-FlattenXml -OutDir $outDir
          $statusLabel.Text = "Flatten complete: $outDir\Flattened"
        }
        2 {
          $outDir = if ($state.OutDirTb.Text.Trim()) { $state.OutDirTb.Text.Trim() } else { $DefaultOutDir }
          $thr = if ($state.ThrottleNum) { [int]$state.ThrottleNum.Value } else { $DefaultThrottle }
          $fp = Get-FilterParams $state
          Invoke-XmlExport -OutDir $outDir -Throttle $thr -IncludeGpoName $fp.IncludeGpoName -IncludeGpoNameRegex $fp.IncludeGpoNameRegex -IncludeGpoId $fp.IncludeGpoId
          Invoke-FlattenXml -OutDir $outDir
          $statusLabel.Text = "Export + flatten complete: $outDir"
        }
        3 {
          $outDir = if ($state.OutDirTb.Text.Trim()) { $state.OutDirTb.Text.Trim() } else { $DefaultOutDir }
          $fp = Get-FilterParams $state
          Invoke-RegistrySnapshotExport -Folder $outDir -IncludeGpoName $fp.IncludeGpoName -IncludeGpoNameRegex $fp.IncludeGpoNameRegex -IncludeGpoId $fp.IncludeGpoId
          $statusLabel.Text = "Registry snapshot written: $outDir"
        }
        4 {
          $left = $state.LeftFolderTb.Text.Trim()
          $right = $state.RightFolderTb.Text.Trim()
          $outF = $state.OutFolderTb.Text.Trim()
          if (-not $left -or -not $right -or -not $outF) {
            [System.Windows.Forms.MessageBox]::Show("Please fill Baseline, Current, and Output folder.", "GPO Audit Master", "OK", "Warning")
            return
          }
          Invoke-RegistrySnapshotCompare -Left $left -Right $right -OutFolder $outF
          $statusLabel.Text = "Compare written: $outF\Compare-RegistryKeyValue.csv"
        }
        5 {
          $outDir = if ($state.OutDirTb.Text.Trim()) { $state.OutDirTb.Text.Trim() } else { $DefaultOutDir }
          $baseline = $state.BaselineTb.Text.Trim()
          $compareOut = $state.CompareOutTb.Text.Trim(); if (-not $compareOut) { $compareOut = $outDir }
          $thr = if ($state.ThrottleNum) { [int]$state.ThrottleNum.Value } else { $DefaultThrottle }
          $fp = Get-FilterParams $state
          if (-not $baseline) {
            [System.Windows.Forms.MessageBox]::Show("Baseline folder is required.", "GPO Audit Master", "OK", "Warning")
            return
          }
          Invoke-XmlExport -OutDir $outDir -Throttle $thr -IncludeGpoName $fp.IncludeGpoName -IncludeGpoNameRegex $fp.IncludeGpoNameRegex -IncludeGpoId $fp.IncludeGpoId
          Invoke-FlattenXml -OutDir $outDir
          $leftMaster = Join-Path $baseline "MasterFlatten_AllGPOs.csv"
          $rightMaster = Join-Path $outDir "MasterFlatten_AllGPOs.csv"
          Invoke-FlattenCompare -LeftPath $leftMaster -RightPath $rightMaster -OutFolder $compareOut
          $statusLabel.Text = "Export + flatten + compare complete."
        }
        6 {
          $choices = Show-GpoCompareDialog -DefaultOutDir $DefaultOutDir -DefaultThrottle $DefaultThrottle
          if (-not $choices) { $statusLabel.Text = "Cancelled."; return }
          Ensure-Folder -Path (Split-Path -Parent $choices.ComparePath -ErrorAction SilentlyContinue)
          Invoke-XmlExport -OutDir $choices.OutDir -Throttle $choices.Throttle -IncludeGpoName @($choices.Gpo1, $choices.Gpo2)
          Invoke-FlattenXml -OutDir $choices.OutDir
          $leftCsv = Join-Path (Join-Path $choices.OutDir 'Flattened') ("Flatten_{0}.csv" -f (New-SafeName $choices.Gpo1))
          $rightCsv = Join-Path (Join-Path $choices.OutDir 'Flattened') ("Flatten_{0}.csv" -f (New-SafeName $choices.Gpo2))
          Invoke-FlattenGpoCompare -LeftCsv $leftCsv -RightCsv $rightCsv -OutCsv $choices.ComparePath
          $statusLabel.Text = "Done: $($choices.ComparePath)"
        }
        7 {
          $q = if ($state.SearchTb) { $state.SearchTb.Text.Trim() } else { '' }
          if (-not $q) {
            [System.Windows.Forms.MessageBox]::Show("Enter search text (e.g. turn off).", "GPO Audit Master", "OK", "Warning")
            return
          }
          $csvPath = if ($state.SearchCsvTb -and $state.SearchCsvTb.Text.Trim()) { $state.SearchCsvTb.Text.Trim() } else { $null }
          $fp = Get-FilterParams $state
          $ouPatterns = $null
          if ($state.OuFilterCb -and $state.OuFilterCb.Text.Trim()) {
            $ouPatterns = @($state.OuFilterCb.Text.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
          }
          $ouChild = $false
          if ($state.OuChildrenChk) { $ouChild = [bool]$state.OuChildrenChk.Checked }
          $searchHits = @(Invoke-SearchGpoSettings -SearchText $q -IncludeGpoName $fp.IncludeGpoName -IncludeGpoNameRegex $fp.IncludeGpoNameRegex -IncludeGpoId $fp.IncludeGpoId -SearchCsvOut $csvPath -SearchOuNameFilter $ouPatterns -SearchOuIncludeChildren:$ouChild)
          $statusLabel.Text = "Found $($searchHits.Count) match(es).$(if ($csvPath) { " CSV: $csvPath" })"
        }
      }
    } catch {
      [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "GPO Audit Master – Error", "OK", "Error")
      $statusLabel.Text = "Error"
    }
  })

  $btnClose.Add_Click({ $form.Close() })
  [void]$form.ShowDialog()
}

# -------------------- Registry snapshot (export + compare) --------------------
function Get-GpoRegistryRows {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object]$Gpo
  )

  $gpoDom = Get-GpoAuditGpoDomainSplat
  $xmlText = Get-GPOReport @gpoDom -Guid $Gpo.Id -ReportType Xml -ErrorAction Stop
  [xml]$doc = $xmlText

  $nsm = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
  $nsm.AddNamespace("gp", "http://www.microsoft.com/GroupPolicy/Settings")

  $rows = New-Object System.Collections.Generic.List[object]

  function Add-Row {
    param(
      [string]$Scope,
      [string]$KeyPath,
      [string]$ValueName,
      [string]$ValueType,
      [string]$ValueData,
      [string]$Source
    )
    if ([string]::IsNullOrWhiteSpace($KeyPath) -or [string]::IsNullOrWhiteSpace($ValueName)) { return }
    $rows.Add([pscustomobject]@{
      GpoName   = $Gpo.DisplayName
      GpoId     = [string]$Gpo.Id
      Scope     = $Scope
      KeyPath   = $KeyPath
      ValueName = $ValueName
      ValueType = $ValueType
      ValueData = $ValueData
      Source    = $Source
    })
  }

  foreach ($sectionName in @('Computer', 'User')) {
    $sectionNode = $doc.SelectSingleNode("/gp:GPO/gp:$sectionName", $nsm)
    if (-not $sectionNode) { continue }

    $regSettingNodes = $sectionNode.SelectNodes(".//gp:RegistrySetting", $nsm)
    foreach ($rs in $regSettingNodes) {
      $keyPathNode   = $rs.SelectSingleNode("./gp:KeyPath", $nsm)
      $valueNameNode = $rs.SelectSingleNode("./gp:ValueName", $nsm)
      $valueTypeNode = $rs.SelectSingleNode("./gp:ValueType", $nsm)
      $valueNode     = $rs.SelectSingleNode("./gp:Value", $nsm)
      $keyPath   = if ($keyPathNode)   { $keyPathNode.InnerText }   else { $null }
      $valueName = if ($valueNameNode) { $valueNameNode.InnerText } else { $null }
      $valueType = if ($valueTypeNode) { $valueTypeNode.InnerText } else { $null }
      $value     = if ($valueNode)     { $valueNode.InnerText }     else { $null }
      Add-Row -Scope $sectionName -KeyPath $keyPath -ValueName $valueName -ValueType $valueType -ValueData $value -Source 'RegistrySetting'
    }

    $fallbackNodes = $sectionNode.SelectNodes(".//*[gp:KeyPath and (gp:ValueName or gp:Name)]", $nsm)
    foreach ($node in $fallbackNodes) {
      $keyPathNode      = $node.SelectSingleNode("./gp:KeyPath", $nsm)
      $valueNameNode    = $node.SelectSingleNode("./gp:ValueName", $nsm)
      $altValueNameNode = $node.SelectSingleNode("./gp:Name", $nsm)
      $valueTypeNode    = $node.SelectSingleNode("./gp:ValueType", $nsm)
      $valueNode        = $node.SelectSingleNode("./gp:Value", $nsm)

      $keyPath = if ($keyPathNode) { $keyPathNode.InnerText } else { $null }

      if ($valueNameNode) {
        $valueName = $valueNameNode.InnerText
      } elseif ($altValueNameNode) {
        $valueName = $altValueNameNode.InnerText
      } else {
        $valueName = $null
      }

      $valueType = if ($valueTypeNode) { $valueTypeNode.InnerText } else { $null }
      $value     = if ($valueNode)     { $valueNode.InnerText }     else { $null }
      Add-Row -Scope $sectionName -KeyPath $keyPath -ValueName $valueName -ValueType $valueType -ValueData $value -Source 'Fallback'
    }
  }

  # Also capture Group Policy Preferences registry items (not covered by gp:RegistrySetting).
  # These live under RegistrySettings/Registry/Properties in the XML, often in a different namespace.
  $gppNodes = $doc.SelectNodes("//*[local-name()='RegistrySettings']/*[local-name()='Registry']/*[local-name()='Properties']")
  foreach ($it in $gppNodes) {
    $keyPath   = $it.key
    $valueName = $it.valueName
    $valueType = $it.type
    $value     = $it.value
    # Infer scope (Computer/User) heuristically from the surrounding XML, similar to the flatten logic.
    $scope     = Get-ScopeFromNode -Node $it
    Add-Row -Scope $scope -KeyPath $keyPath -ValueName $valueName -ValueType $valueType -ValueData $value -Source 'GPP'
  }

  # Capture Security Options (which are effectively registry-backed settings) by mapping
  # KeyName -> KeyPath and Setting* -> Value. These often do not appear as gp:RegistrySetting.
  $secOptNodes = $doc.SelectNodes("//*[local-name()='SecurityOptions']")
  foreach ($so in $secOptNodes) {
    $keyNameNode      = $so.SelectSingleNode("./*[local-name()='KeyName']")
    $settingStringNode= $so.SelectSingleNode("./*[local-name()='SettingString']")
    $settingNumberNode= $so.SelectSingleNode("./*[local-name()='SettingNumber']")

    if ($null -eq $keyNameNode) { continue }

    $keyPath = $keyNameNode.InnerText
    if ([string]::IsNullOrWhiteSpace($keyPath)) { continue }

    # Use a synthetic "(Default)" value name so we always have a non-empty ValueName.
    $valueName = '(Default)'

    $valueType = if ($settingStringNode) { 'String' }
                 elseif ($settingNumberNode) { 'Number' }
                 else { $null }

    $value = if ($settingStringNode) { $settingStringNode.InnerText }
             elseif ($settingNumberNode) { $settingNumberNode.InnerText }
             else { $null }

    if ($null -eq $value -or ($value -is [string] -and [string]::IsNullOrWhiteSpace($value))) { continue }

    $scope = Get-ScopeFromNode -Node $so
    Add-Row -Scope $scope -KeyPath $keyPath -ValueName $valueName -ValueType $valueType -ValueData $value -Source 'SecurityOptions'
  }

  $rows | Sort-Object GpoId, Scope, KeyPath, ValueName, ValueType, ValueData, Source -Unique
}

function Invoke-RegistrySnapshotExport {
  param(
    [Parameter(Mandatory)][string]$Folder,
    [string[]]$IncludeGpoName,
    [string]$IncludeGpoNameRegex,
    [string[]]$IncludeGpoId
  )

  Ensure-Folder -Path $Folder

  $gpoDom = Get-GpoAuditGpoDomainSplat
  $allGpos = Get-GPO @gpoDom -All -ErrorAction Stop | Sort-Object DisplayName
  $gpos = Select-Gpos -Gpos $allGpos -IncludeGpoName $IncludeGpoName -IncludeGpoNameRegex $IncludeGpoNameRegex -IncludeGpoId $IncludeGpoId

  if (-not $gpos -or $gpos.Count -eq 0) {
    throw "No GPOs matched the supplied filters."
  }

  $allRows = New-Object System.Collections.Generic.List[object]
  foreach ($gpo in $gpos) {
    foreach ($r in (Get-GpoRegistryRows -Gpo $gpo)) { [void]$allRows.Add($r) }
  }

  $meta = [pscustomobject]@{
    CreatedAt           = (Get-Date).ToString('o')
    Domain              = $(if ($script:GpoAuditDomainDns) { $script:GpoAuditDomainDns } else { $env:USERDNSDOMAIN })
    Computer            = $env:COMPUTERNAME
    TotalGpoCount       = $allGpos.Count
    ExportedGpoCount    = $gpos.Count
    RowCount            = $allRows.Count
    IncludeGpoName      = $IncludeGpoName
    IncludeGpoNameRegex = $IncludeGpoNameRegex
    IncludeGpoId        = $IncludeGpoId
  }

  $meta | Export-Clixml -LiteralPath (Join-Path $Folder 'SnapshotMeta.clixml')
  $allRows | Export-Clixml -LiteralPath (Join-Path $Folder 'GpoRegistrySnapshot.clixml')
  $allRows | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $Folder 'GpoRegistrySnapshot.csv')

  Write-Host "Snapshot written to: $Folder"
  Write-Host "Exported GPOs: $($gpos.Count)  Rows: $($allRows.Count)"
}

function Invoke-RegistrySnapshotCompare {
  param(
    [Parameter(Mandatory)][string]$Left,
    [Parameter(Mandatory)][string]$Right,
    [Parameter(Mandatory)][string]$OutFolder
  )

  Ensure-Folder -Path $OutFolder

  $leftPath = Join-Path $Left 'GpoRegistrySnapshot.clixml'
  $rightPath = Join-Path $Right 'GpoRegistrySnapshot.clixml'
  if (-not (Test-Path -LiteralPath $leftPath)) { throw "Missing: $leftPath" }
  if (-not (Test-Path -LiteralPath $rightPath)) { throw "Missing: $rightPath" }

  $L = Import-Clixml -LiteralPath $leftPath
  $R = Import-Clixml -LiteralPath $rightPath

  function Make-Id($x) { "{0}|{1}|{2}|{3}" -f $x.GpoId, $x.Scope, $x.KeyPath, $x.ValueName }

  $lIndex = @{}
  foreach ($x in $L) { $lIndex[(Make-Id $x)] = $x }
  $rIndex = @{}
  foreach ($x in $R) { $rIndex[(Make-Id $x)] = $x }

  $allIds = New-Object System.Collections.Generic.HashSet[string]
  foreach ($k in $lIndex.Keys) { [void]$allIds.Add($k) }
  foreach ($k in $rIndex.Keys) { [void]$allIds.Add($k) }

  $out = foreach ($id in ($allIds | Sort-Object)) {
    $l = $lIndex[$id]
    $r = $rIndex[$id]

    if ($null -eq $l) {
      [pscustomobject]@{
        Status    = 'Added'
        GpoName   = $r.GpoName
        GpoId     = $r.GpoId
        Scope     = $r.Scope
        KeyPath   = $r.KeyPath
        ValueName = $r.ValueName
        OldType   = $null
        OldValue  = $null
        NewType   = $r.ValueType
        NewValue  = $r.ValueData
      }
      continue
    }

    if ($null -eq $r) {
      [pscustomobject]@{
        Status    = 'Removed'
        GpoName   = $l.GpoName
        GpoId     = $l.GpoId
        Scope     = $l.Scope
        KeyPath   = $l.KeyPath
        ValueName = $l.ValueName
        OldType   = $l.ValueType
        OldValue  = $l.ValueData
        NewType   = $null
        NewValue  = $null
      }
      continue
    }

    $changed = ($l.ValueType -ne $r.ValueType) -or ($l.ValueData -ne $r.ValueData)

    [pscustomobject]@{
      Status    = $(if ($changed) { 'Changed' } else { 'Unchanged' })
      GpoName   = $r.GpoName
      GpoId     = $r.GpoId
      Scope     = $r.Scope
      KeyPath   = $r.KeyPath
      OldType   = $l.ValueType
      OldValue  = $l.ValueData
      NewType   = $r.ValueType
      NewValue  = $r.ValueData
    }
  }

  $csvOut = Join-Path $OutFolder 'Compare-RegistryKeyValue.csv'
  $out | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath $csvOut

  Write-Host "Compare sheet written to: $csvOut"
}

# -------- GUI mode (when no -Mode is passed) --------
if (-not $PSBoundParameters.ContainsKey('Mode')) {
  Set-GpoAuditRequestedDomain -DomainDnsName $DomainDnsName
  Show-GpoAuditMasterMainGui -DefaultOutDir $OutDir -DefaultThrottle $Throttle -InitialDomainDnsName $DomainDnsName
  return
}

# -------------------- Main dispatcher --------------------
if (-not $Mode -and $PSBoundParameters.ContainsKey('SearchText')) {
  $Mode = 'SearchSettings'
}

Set-GpoAuditRequestedDomain -DomainDnsName $DomainDnsName

switch ($Mode) {
  'XmlExport' {
    Invoke-XmlExport -OutDir $OutDir -Throttle $Throttle -IncludeGpoName $IncludeGpoName -IncludeGpoNameRegex $IncludeGpoNameRegex -IncludeGpoId $IncludeGpoId
  }
  'FlattenXml' {
    Invoke-FlattenXml -OutDir $OutDir
  }
  'XmlExportAndFlatten' {
    Invoke-XmlExport -OutDir $OutDir -Throttle $Throttle -IncludeGpoName $IncludeGpoName -IncludeGpoNameRegex $IncludeGpoNameRegex -IncludeGpoId $IncludeGpoId
    Invoke-FlattenXml -OutDir $OutDir
  }
  'RegistrySnapshotExport' {
    Invoke-RegistrySnapshotExport -Folder $OutDir -IncludeGpoName $IncludeGpoName -IncludeGpoNameRegex $IncludeGpoNameRegex -IncludeGpoId $IncludeGpoId
  }
  'RegistrySnapshotCompare' {
    Invoke-RegistrySnapshotCompare -Left $LeftFolder -Right $RightFolder -OutFolder $OutFolderCompare
  }
  'SearchSettings' {
    Invoke-SearchGpoSettings -SearchText $SearchText -IncludeGpoName $IncludeGpoName -IncludeGpoNameRegex $IncludeGpoNameRegex -IncludeGpoId $IncludeGpoId -SearchCsvOut $SearchCsvOut -SearchOuNameFilter $SearchOuNameFilter -SearchOuIncludeChildren:$SearchOuIncludeChildren
  }
}