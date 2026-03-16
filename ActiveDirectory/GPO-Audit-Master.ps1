<#
.SYNOPSIS
  Unified GPO audit, export, flatten, snapshot, and comparison tool for Group Policy analysis.

.DESCRIPTION
  This script provides a single entry point for working with Group Policy Objects (GPOs)
  in several different ways. It can export selected GPOs to XML, flatten GPO settings
  into comparison-friendly CSV files, capture registry-based GPO snapshots, compare
  snapshots over time, and compare two individual GPOs side by side.

  The script is designed to help with GPO auditing, baseline creation, drift detection,
  and structured comparison work. It supports both command-line execution and an
  interactive Windows Forms GUI when -Mode is not supplied.

  Core capabilities include:

    - Export GPO reports to XML for one, many, or all matching GPOs
    - Flatten exported XML into normalized CSV output for easier filtering,
      searching, and comparison
    - Build a master flattened CSV covering all processed GPOs
    - Build a per-GPO counts summary showing how many settings were extracted
      from major policy areas
    - Capture registry-style snapshots of GPO-backed settings for baseline tracking
    - Compare two registry snapshots to identify added, removed, changed, and
      unchanged settings
    - Compare two master flatten CSVs to identify differences between baseline
      and current GPO output
    - Export, flatten, and compare two individual GPOs side by side
    - Filter target GPOs by display name list, display name regex, or GPO GUID

  Flattened output is intended to make GPO data easier to review than raw XML by
  standardizing each discovered setting into rows with fields such as GPO, scope,
  extension, category, setting, type, and value.

  Registry snapshot output is intended for baseline and drift analysis, especially
  when you want to compare registry-backed GPO settings between two points in time.

  By default, when no -Mode parameter is supplied, the script launches a GUI that
  exposes these actions:

    1. Export GPO XML only
    2. Flatten existing XML to CSV
    3. Export GPO XML and then flatten
    4. Registry key+value snapshot
    5. Compare two registry snapshots
    6. Export + flatten + compare to previous
    7. Export + flatten two GPOs and compare

  This script combines and extends the logic from earlier standalone scripts such as:

    - All GPO export.ps1
    - Flatten GPOs into CSV file.ps1
    - GPO Snapshot - Registry KeyValue.ps1

.NOTES
  Requirements:
    - Windows PowerShell or PowerShell 7+
    - GroupPolicy module
    - RSAT: Group Policy Management tools installed
    - Access to read GPOs in the target domain

  Output structure commonly includes:
    - OutDir\Exports
    - OutDir\Flattened
    - OutDir\MasterFlatten_AllGPOs.csv
    - OutDir\MasterCounts_ByGPO.csv

  Registry snapshot mode commonly writes:
    - SnapshotMeta.clixml
    - GpoRegistrySnapshot.clixml
    - GpoRegistrySnapshot.csv

  Compare modes commonly write:
    - Compare-RegistryKeyValue.csv
    - Compare-MasterFlatten.csv
    - Diff_ByGPO_<timestamp>.csv

.EXAMPLES
  # 1) Export XML only for a few GPOs
  #    EDIT: replace Example* with your real GPO display names.
  .\GPO Audit Master.ps1 -Mode XmlExport -OutDir C:\Temp\GPO_Audit `
    -IncludeGpoName "Example - Workstations","Example - Servers"

  # 2) Export XML for matching GPOs and flatten them to CSVs in one go
  #    EDIT: adjust the regex to match your own GPO naming convention.
  .\GPO Audit Master.ps1 -Mode XmlExportAndFlatten -OutDir C:\Temp\GPO_Audit `
    -IncludeGpoNameRegex "^Example - "

  # 3) Just flatten existing XMLs in OutDir\Exports
  .\GPO Audit Master.ps1 -Mode FlattenXml -OutDir C:\Temp\GPO_Audit

  # 4) Take a registry key+value snapshot for a subset of GPOs
  #    EDIT: replace Example* with your real GPO display names and snapshot folder.
  .\GPO Audit Master.ps1 -Mode RegistrySnapshotExport `
    -OutDir C:\Temp\GpoSnap\Baseline `
    -IncludeGpoName "Example - Workstations","Example - Servers"

  # 5) Compare two registry snapshots previously taken by this script
  .\GPO Audit Master.ps1 -Mode RegistrySnapshotCompare `
    -LeftFolder  C:\Temp\GpoSnap\Baseline `
    -RightFolder C:\Temp\GpoSnap\Current `
    -OutFolderCompare C:\Temp\GpoSnap\Diff

  # 6) Full audit workflow: export GPO XML, flatten settings, and compare
    the new results to a previous baseline of flattened GPO data.
  .\GPO Audit Master.ps1 -Mode XmlExportAndFlatten `
    -OutDir C:\Temp\GPO_Audit_Current

    Then compare the two flattened outputs:
   (baseline vs new run)
  Invoke-FlattenCompare `
    -LeftPath  C:\Temp\GPO_Audit_Baseline\MasterFlatten_AllGPOs.csv `
    -RightPath C:\Temp\GPO_Audit_Current\MasterFlatten_AllGPOs.csv `
    -OutFolder C:\Temp\GPO_Audit_Diff

  # 7) Compare two specific GPOs by exporting, flattening, and diffing them
     (this workflow is normally launched from the GUI option).
  .\GPO Audit Master.ps1

      Then select:
        "Export + flatten two GPOs and compare"
  
      The script will:
        - Export both GPOs to XML
        - Flatten their settings
        - Generate a CSV diff report showing Added, Removed, and Changed settings
#>

[CmdletBinding(DefaultParameterSetName = 'Xml')]
param(
  # What this run should do
  # When not supplied, an interactive menu will prompt for it.
  [Parameter()]
  [ValidateSet('XmlExport','FlattenXml','XmlExportAndFlatten','RegistrySnapshotExport','RegistrySnapshotCompare')]
  [string]$Mode,

  # Shared: root folder
  [Parameter(ParameterSetName='Xml')]
  [Parameter(ParameterSetName='SnapshotExport')]
  # EDIT: change the default to your preferred base output folder.
  [string]$OutDir = "C:\Temp\GPO_Audit",

  # XML export options
  [Parameter(ParameterSetName='Xml')]
  [int]$Throttle = 6,

  # GPO filters (used by XmlExport*, RegistrySnapshotExport)
  [Parameter(ParameterSetName='Xml')]
  [Parameter(ParameterSetName='SnapshotExport')]
  [string[]]$IncludeGpoName,

  [Parameter(ParameterSetName='Xml')]
  [Parameter(ParameterSetName='SnapshotExport')]
  [string]$IncludeGpoNameRegex,

  [Parameter(ParameterSetName='Xml')]
  [Parameter(ParameterSetName='SnapshotExport')]
  [string[]]$IncludeGpoId,

  # Registry snapshot compare
  [Parameter(ParameterSetName='SnapshotCompare', Mandatory)]
  [string]$LeftFolder,

  [Parameter(ParameterSetName='SnapshotCompare', Mandatory)]
  [string]$RightFolder,

  [Parameter(ParameterSetName='SnapshotCompare', Mandatory)]
  [string]$OutFolderCompare
)

$ErrorActionPreference = 'Stop'

try { Import-Module GroupPolicy -ErrorAction Stop } catch {
  throw "The 'GroupPolicy' module is required (RSAT: Group Policy Management). $_"
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

  $allGpos = Get-GPO -All | Sort-Object DisplayName
  $gpos = Select-Gpos -Gpos $allGpos -IncludeGpoName $IncludeGpoName -IncludeGpoNameRegex $IncludeGpoNameRegex -IncludeGpoId $IncludeGpoId

  if (-not $gpos -or $gpos.Count -eq 0) {
    throw "No GPOs matched the supplied filters."
  }

  $hasPS7 = $PSVersionTable.PSVersion.Major -ge 7
  $xmlPaths = @()

  if ($hasPS7) {
    $xmlPaths = $gpos | ForEach-Object -Parallel {
      try {
        $safe = ($PSItem.DisplayName -replace '[^\w\.-]+','_')
        $file = Join-Path $using:exportDir ("{0}.xml" -f $safe)
        Get-GPOReport -Name $PSItem.DisplayName -ReportType XML -Path $file
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
        Get-GPOReport -Name $g.DisplayName -ReportType XML -Path $file
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

function Get-SecuritySettingRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Gpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($s in (Get-XPathNodes -Xml $Xml -XPath "//*[local-name()='SecuritySettings']")) {
    foreach ($n in $s.SelectNodes(".//*[not(*)]")) {
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
  Add-FlattenRows -Target $rows -Items (Get-SecuritySettingRows       -Xml $Xml -Gpo $Gpo)
  Add-FlattenRows -Target $rows -Items (Get-NTServiceRows             -Xml $Xml -Gpo $Gpo)
  Add-FlattenRows -Target $rows -Items (Get-LugsRows                  -Xml $Xml -Gpo $Gpo)
  Add-FlattenRows -Target $rows -Items (Get-ScriptRows                -Xml $Xml -Gpo $Gpo)
  Add-FlattenRows -Target $rows -Items (Get-WlanPolicyRows            -Xml $Xml -Gpo $Gpo)

  return $rows
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
    $gpos = Get-GPO -All -ErrorAction Stop | Sort-Object DisplayName | ForEach-Object { $_.DisplayName }
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
  # Shift numeric control to the right so the value is clearer.
  $numThrottle.Location = New-Object System.Drawing.Point -ArgumentList ($ctrlX + 140), ($y - 2)
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
  param([string]$DefaultOutDir = "C:\Temp\GPO_Audit", [int]$DefaultThrottle = 6)

  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing

  $actions = @(
    '1. Export GPO XML only',
    '2. Flatten existing XML to CSV',
    '3. Export GPO XML and then flatten',
    '4. Registry key+value snapshot',
    '5. Compare two registry snapshots',
    '6. Export + flatten + compare to previous',
    '7. Export + flatten two GPOs and compare'
  )

  $form = New-Object System.Windows.Forms.Form
  $form.Text = "GPO Audit Master"
  $form.Size = New-Object System.Drawing.Size(560, 480)
  $form.StartPosition = "CenterScreen"
  $form.FormBorderStyle = "FixedDialog"
  $form.MaximizeBox = $false

  $y = 12
  $lblAction = New-Object System.Windows.Forms.Label
  $lblAction.Location = New-Object System.Drawing.Point -ArgumentList 16, $y
  $lblAction.Size = New-Object System.Drawing.Size(200, 20)
  $lblAction.Text = "What do you want to do?"
  $form.Controls.Add($lblAction)
  $y += 24
  $cbAction = New-Object System.Windows.Forms.ComboBox
  $cbAction.Location = New-Object System.Drawing.Point -ArgumentList 16, $y
  $cbAction.Size = New-Object System.Drawing.Size(500, 24)
  $cbAction.DropDownStyle = "DropDownList"
  foreach ($a in $actions) { [void]$cbAction.Items.Add($a) }
  $cbAction.SelectedIndex = 0
  $form.Controls.Add($cbAction)
  $y += 36

  $contentPanel = New-Object System.Windows.Forms.Panel
  $contentPanel.Location = New-Object System.Drawing.Point -ArgumentList 16, $y
  $contentPanel.Size = New-Object System.Drawing.Size(500, 300)
  $contentPanel.BorderStyle = "FixedSingle"
  $contentPanel.AutoScroll = $true
  $form.Controls.Add($contentPanel)

  $btnRun = New-Object System.Windows.Forms.Button
  $runBtnY = $y + 308
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
  $statusLabel.Size = New-Object System.Drawing.Size(320, 20)
  $statusLabel.Text = ""
  $statusLabel.ForeColor = [System.Drawing.Color]::DarkGreen
  $form.Controls.Add($statusLabel)

  function Add-Row { param([System.Windows.Forms.Panel]$P, [ref]$Y, [string]$LabelText, [object]$Control)
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Location = New-Object System.Drawing.Point -ArgumentList 8, $Y.Value
    $lbl.Size = New-Object System.Drawing.Size(140, 20)
    $lbl.Text = $LabelText
    $P.Controls.Add($lbl)
    $ctrl = $Control
    $ctrlY = $Y.Value - 2
    $ctrl.Location = New-Object System.Drawing.Point -ArgumentList 150, $ctrlY
    if ($ctrl -is [System.Windows.Forms.TextBox]) { $ctrl.Size = New-Object System.Drawing.Size(280, 22) }
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

    switch ($Index) {
      0 { # XmlExport
        $outDirTb = New-Object System.Windows.Forms.TextBox; $outDirTb.Text = $DefaultOutDir
        Add-Row $contentPanel ([ref]$ry) "Output folder:" $outDirTb
        Add-BrowseButton $contentPanel 436 ($ry - 10) $outDirTb "Output folder for GPO XML exports"
        $ry += 28
        $throttleNum = New-Object System.Windows.Forms.NumericUpDown
        $throttleNum.Minimum = 1; $throttleNum.Maximum = 32; $throttleNum.Value = $DefaultThrottle; $throttleNum.Size = New-Object System.Drawing.Size(60, 22)
        Add-Row $contentPanel ([ref]$ry) "Parallel throttle:" $throttleNum
        $ry += 8
        $filterChk = New-Object System.Windows.Forms.CheckBox; $filterChk.Text = "Filter to specific GPOs"; $filterChk.Size = New-Object System.Drawing.Size(200, 22)
        Add-Row $contentPanel ([ref]$ry) "" $filterChk
        $namesTb = New-Object System.Windows.Forms.TextBox; $namesTb.Size = New-Object System.Drawing.Size(320, 22); $namesTb.Height = 22
        $contentPanel.Controls.Add($namesTb); $namesTb.Location = New-Object System.Drawing.Point -ArgumentList 150, ($ry - 2); $ry += 28
        $l = New-Object System.Windows.Forms.Label; $l.Location = New-Object System.Drawing.Point -ArgumentList 8, $ry; $l.Text = "GPO names (comma):"; $l.Size = New-Object System.Drawing.Size(140, 20); $contentPanel.Controls.Add($l); $ry += 22
        $regexTb = New-Object System.Windows.Forms.TextBox; $regexTb.Size = New-Object System.Drawing.Size(320, 22)
        $contentPanel.Controls.Add($regexTb); $regexTb.Location = New-Object System.Drawing.Point -ArgumentList 150, ($ry - 2); $ry += 28
        $l2 = New-Object System.Windows.Forms.Label; $l2.Location = New-Object System.Drawing.Point -ArgumentList 8, $ry; $l2.Text = "Display name regex:"; $l2.Size = New-Object System.Drawing.Size(140, 20); $contentPanel.Controls.Add($l2); $ry += 22
        $guidsTb = New-Object System.Windows.Forms.TextBox; $guidsTb.Size = New-Object System.Drawing.Size(320, 22)
        $contentPanel.Controls.Add($guidsTb); $guidsTb.Location = New-Object System.Drawing.Point -ArgumentList 150, ($ry - 2)
      }
      1 { # FlattenXml
        $outDirTb = New-Object System.Windows.Forms.TextBox; $outDirTb.Text = $DefaultOutDir
        Add-Row $contentPanel ([ref]$ry) "Output folder (Exports):" $outDirTb
        Add-BrowseButton $contentPanel 436 ($ry - 10) $outDirTb "Folder containing Exports and where Flattened will be written"
      }
      2 { # XmlExportAndFlatten
        $outDirTb = New-Object System.Windows.Forms.TextBox; $outDirTb.Text = $DefaultOutDir
        Add-Row $contentPanel ([ref]$ry) "Output folder:" $outDirTb
        Add-BrowseButton $contentPanel 436 ($ry - 10) $outDirTb "Output folder"
        $ry += 28
        $throttleNum = New-Object System.Windows.Forms.NumericUpDown
        $throttleNum.Minimum = 1; $throttleNum.Maximum = 32; $throttleNum.Value = $DefaultThrottle; $throttleNum.Size = New-Object System.Drawing.Size(60, 22)
        Add-Row $contentPanel ([ref]$ry) "Parallel throttle:" $throttleNum
        $ry += 8
        $filterChk = New-Object System.Windows.Forms.CheckBox; $filterChk.Text = "Filter to specific GPOs"; $filterChk.Size = New-Object System.Drawing.Size(200, 22)
        Add-Row $contentPanel ([ref]$ry) "" $filterChk
        $namesTb = New-Object System.Windows.Forms.TextBox; $namesTb.Size = New-Object System.Drawing.Size(320, 22)
        $contentPanel.Controls.Add($namesTb); $namesTb.Location = New-Object System.Drawing.Point -ArgumentList 150, ($ry - 2); $ry += 28
        $l = New-Object System.Windows.Forms.Label; $l.Location = New-Object System.Drawing.Point -ArgumentList 8, $ry; $l.Text = "GPO names (comma):"; $l.Size = New-Object System.Drawing.Size(140, 20); $contentPanel.Controls.Add($l); $ry += 22
        $regexTb = New-Object System.Windows.Forms.TextBox; $regexTb.Size = New-Object System.Drawing.Size(320, 22)
        $contentPanel.Controls.Add($regexTb); $regexTb.Location = New-Object System.Drawing.Point -ArgumentList 150, ($ry - 2); $ry += 28
        $l2 = New-Object System.Windows.Forms.Label; $l2.Location = New-Object System.Drawing.Point -ArgumentList 8, $ry; $l2.Text = "Display name regex:"; $l2.Size = New-Object System.Drawing.Size(140, 20); $contentPanel.Controls.Add($l2); $ry += 22
        $guidsTb = New-Object System.Windows.Forms.TextBox; $guidsTb.Size = New-Object System.Drawing.Size(320, 22)
        $contentPanel.Controls.Add($guidsTb); $guidsTb.Location = New-Object System.Drawing.Point -ArgumentList 150, ($ry - 2)
      }
      3 { # RegistrySnapshotExport
        $outDirTb = New-Object System.Windows.Forms.TextBox; $outDirTb.Text = $DefaultOutDir
        Add-Row $contentPanel ([ref]$ry) "Snapshot folder:" $outDirTb
        Add-BrowseButton $contentPanel 436 ($ry - 10) $outDirTb "Snapshot output folder"
        $ry += 8
        $filterChk = New-Object System.Windows.Forms.CheckBox; $filterChk.Text = "Filter to specific GPOs"; $filterChk.Size = New-Object System.Drawing.Size(200, 22)
        Add-Row $contentPanel ([ref]$ry) "" $filterChk
        $namesTb = New-Object System.Windows.Forms.TextBox; $namesTb.Size = New-Object System.Drawing.Size(320, 22)
        $contentPanel.Controls.Add($namesTb); $namesTb.Location = New-Object System.Drawing.Point -ArgumentList 150, ($ry - 2); $ry += 28
        $l = New-Object System.Windows.Forms.Label; $l.Location = New-Object System.Drawing.Point -ArgumentList 8, $ry; $l.Text = "GPO names (comma):"; $l.Size = New-Object System.Drawing.Size(140, 20); $contentPanel.Controls.Add($l); $ry += 22
        $regexTb = New-Object System.Windows.Forms.TextBox; $regexTb.Size = New-Object System.Drawing.Size(320, 22)
        $contentPanel.Controls.Add($regexTb); $regexTb.Location = New-Object System.Drawing.Point -ArgumentList 150, ($ry - 2); $ry += 28
        $l2 = New-Object System.Windows.Forms.Label; $l2.Location = New-Object System.Drawing.Point -ArgumentList 8, $ry; $l2.Text = "Display name regex:"; $l2.Size = New-Object System.Drawing.Size(140, 20); $contentPanel.Controls.Add($l2); $ry += 22
        $guidsTb = New-Object System.Windows.Forms.TextBox; $guidsTb.Size = New-Object System.Drawing.Size(320, 22)
        $contentPanel.Controls.Add($guidsTb); $guidsTb.Location = New-Object System.Drawing.Point -ArgumentList 150, ($ry - 2)
      }
      4 { # RegistrySnapshotCompare
        $leftFolderTb = New-Object System.Windows.Forms.TextBox; $leftFolderTb.Size = New-Object System.Drawing.Size(280, 22)
        Add-Row $contentPanel ([ref]$ry) "Baseline folder (Left):" $leftFolderTb
        Add-BrowseButton $contentPanel 436 ($ry - 10) $leftFolderTb "Baseline snapshot folder"
        $ry += 28
        $rightFolderTb = New-Object System.Windows.Forms.TextBox; $rightFolderTb.Size = New-Object System.Drawing.Size(280, 22)
        Add-Row $contentPanel ([ref]$ry) "Current folder (Right):" $rightFolderTb
        Add-BrowseButton $contentPanel 436 ($ry - 10) $rightFolderTb "Current snapshot folder"
        $ry += 28
        $outFolderTb = New-Object System.Windows.Forms.TextBox; $outFolderTb.Size = New-Object System.Drawing.Size(280, 22)
        Add-Row $contentPanel ([ref]$ry) "Output folder for diff:" $outFolderTb
        Add-BrowseButton $contentPanel 436 ($ry - 10) $outFolderTb "Compare output folder"
      }
      5 { # Export + flatten + compare to previous
        $outDirTb = New-Object System.Windows.Forms.TextBox; $outDirTb.Text = $DefaultOutDir
        Add-Row $contentPanel ([ref]$ry) "Output folder (new run):" $outDirTb
        Add-BrowseButton $contentPanel 436 ($ry - 10) $outDirTb "Output folder"
        $ry += 28
        $throttleNum = New-Object System.Windows.Forms.NumericUpDown
        $throttleNum.Minimum = 1; $throttleNum.Maximum = 32; $throttleNum.Value = $DefaultThrottle; $throttleNum.Size = New-Object System.Drawing.Size(60, 22)
        Add-Row $contentPanel ([ref]$ry) "Parallel throttle:" $throttleNum
        $ry += 28
        $baselineTb = New-Object System.Windows.Forms.TextBox; $baselineTb.Size = New-Object System.Drawing.Size(280, 22)
        Add-Row $contentPanel ([ref]$ry) "Baseline folder:" $baselineTb
        Add-BrowseButton $contentPanel 436 ($ry - 10) $baselineTb "Folder with previous MasterFlatten_AllGPOs.csv"
        $ry += 28
        $compareOutTb = New-Object System.Windows.Forms.TextBox; $compareOutTb.Size = New-Object System.Drawing.Size(280, 22)
        Add-Row $contentPanel ([ref]$ry) "Compare output folder:" $compareOutTb
        Add-BrowseButton $contentPanel 436 ($ry - 10) $compareOutTb "Where to write compare CSV"
        $ry += 8
        $filterChk = New-Object System.Windows.Forms.CheckBox; $filterChk.Text = "Filter to specific GPOs"; $filterChk.Size = New-Object System.Drawing.Size(200, 22)
        Add-Row $contentPanel ([ref]$ry) "" $filterChk
        $namesTb = New-Object System.Windows.Forms.TextBox; $namesTb.Size = New-Object System.Drawing.Size(320, 22)
        $contentPanel.Controls.Add($namesTb); $namesTb.Location = New-Object System.Drawing.Point -ArgumentList 150, ($ry - 2); $ry += 28
        $l = New-Object System.Windows.Forms.Label; $l.Location = New-Object System.Drawing.Point -ArgumentList 8, $ry; $l.Text = "GPO names (comma):"; $l.Size = New-Object System.Drawing.Size(140, 20); $contentPanel.Controls.Add($l); $ry += 22
        $regexTb = New-Object System.Windows.Forms.TextBox; $regexTb.Size = New-Object System.Drawing.Size(320, 22)
        $contentPanel.Controls.Add($regexTb); $regexTb.Location = New-Object System.Drawing.Point -ArgumentList 150, ($ry - 2); $ry += 28
        $l2 = New-Object System.Windows.Forms.Label; $l2.Location = New-Object System.Drawing.Point -ArgumentList 8, $ry; $l2.Text = "Display name regex:"; $l2.Size = New-Object System.Drawing.Size(140, 20); $contentPanel.Controls.Add($l2); $ry += 22
        $guidsTb = New-Object System.Windows.Forms.TextBox; $guidsTb.Size = New-Object System.Drawing.Size(320, 22)
        $contentPanel.Controls.Add($guidsTb); $guidsTb.Location = New-Object System.Drawing.Point -ArgumentList 150, ($ry - 2)
      }
      6 { # Two GPO compare
        $info = New-Object System.Windows.Forms.Label
        $info.Location = New-Object System.Drawing.Point -ArgumentList 12, 12
        $info.Size = New-Object System.Drawing.Size(460, 80)
        $info.Text = "Click Run to open the GPO selection dialog. You will choose two GPOs, output folder, throttle, and diff file path there."
        $info.AutoSize = $false
        $info.ForeColor = [System.Drawing.Color]::DarkSlateGray
        $contentPanel.Controls.Add($info)
      }
    }

    @{
      OutDirTb = $outDirTb; ThrottleNum = $throttleNum; FilterChk = $filterChk
      NamesTb = $namesTb; RegexTb = $regexTb; GuidsTb = $guidsTb
      LeftFolderTb = $leftFolderTb; RightFolderTb = $rightFolderTb; OutFolderTb = $outFolderTb
      BaselineTb = $baselineTb; CompareOutTb = $compareOutTb
    }
  }

  $panelState = Build-OptionsPanel 0
  $cbAction.Add_SelectedIndexChanged({ $script:panelState = Build-OptionsPanel $cbAction.SelectedIndex })

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
      }
    } catch {
      [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "GPO Audit Master – Error", "OK", "Error")
      $statusLabel.Text = "Error"
    }
  })

  $btnClose.Add_Click({ $form.Close() })
  $form.Add_Shown({ $cbAction.Focus() })
  [void]$form.ShowDialog()
}

# -------------------- Registry snapshot (export + compare) --------------------
function Get-GpoRegistryRows {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object]$Gpo
  )

  $xmlText = Get-GPOReport -Guid $Gpo.Id -ReportType Xml -ErrorAction Stop
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

  $allGpos = Get-GPO -All -ErrorAction Stop | Sort-Object DisplayName
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
    Domain              = $env:USERDNSDOMAIN
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
      ValueName = $r.ValueName
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
  Show-GpoAuditMasterMainGui -DefaultOutDir $OutDir -DefaultThrottle $Throttle
  return
}

# -------------------- Main dispatcher --------------------
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
}