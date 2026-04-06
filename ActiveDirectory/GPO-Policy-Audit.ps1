<#
.SYNOPSIS
  GPO Policy Audit: download Microsoft security baseline packages, merge with a NIST-side XML
  baseline, export domain GPOs into an AD-like folder tree, diff against a merged master template,
  review gaps with per-row risk comments, and back up GPOs for import.

.DESCRIPTION
  NIST does not ship Windows Group Policy XML in a single public download; this tool expects
  you to supply NIST-aligned exports (from your agency process or extracted reports) as XML
  under Templates\NIST or via -NistXmlPath. Microsoft baselines are fetched from the Security
  Compliance Toolkit file list (see GPO-PolicyAudit-Downloads.json).

  Requires RSAT: Group Policy Management and Active Directory PowerShell on a domain-joined host.

.PARAMETER Mode
  DownloadTemplates | BuildMaster | ExportDomainTree | Compare | ReviewDiff | BackupGpos | Gui

.EXAMPLE
  .\GPO-Policy-Audit.ps1 -Mode Gui -OutDir C:\Temp\GpoPolicyAudit

.EXAMPLE
  .\GPO-Policy-Audit.ps1 -Mode DownloadTemplates -OutDir C:\Temp\GpoPolicyAudit -MsBaselineId Win11-24H2

.EXAMPLE
  .\GPO-Policy-Audit.ps1 -Mode BuildMaster -OutDir C:\Temp\GpoPolicyAudit -ConflictWinner Microsoft
#>

[CmdletBinding()]
param(
  [ValidateSet('DownloadTemplates','BuildMaster','ExportDomainTree','Compare','ReviewDiff','BackupGpos','Gui')]
  [string]$Mode = 'Gui',

  [string]$OutDir = "C:\Temp\GpoPolicyAudit",

  [string]$DomainDnsName,

  [ValidateSet('Nist','Microsoft')]
  [string]$ConflictWinner = 'Microsoft',

  [string]$MsBaselineId = 'Win11-24H2',

  [string]$NistXmlPath,

  [string]$MsZipPath,

  [string]$RootGpoName,

  [string]$CompareDiffCsvOut,

  [string]$ReviewDiffCsvIn,

  [string]$ReviewDiffCsvOut,

  [string]$BackupFolder,

  [int]$Throttle = 6
)

$ErrorActionPreference = 'Stop'

$scriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptRoot)) { $scriptRoot = (Get-Location).Path }

try { Import-Module GroupPolicy -ErrorAction Stop } catch {
  Write-Error "GroupPolicy module required (RSAT Group Policy Management). $($_.Exception.Message)"
  exit 1
}

. (Join-Path $scriptRoot 'GPO-FlattenHelpers.ps1')
. (Join-Path $scriptRoot 'GPO-AdHelpers.ps1')

function Get-PolicyAuditDownloadCatalog {
  $jsonPath = Join-Path $scriptRoot 'GPO-PolicyAudit-Downloads.json'
  if (-not (Test-Path -LiteralPath $jsonPath)) { throw "Missing catalog: $jsonPath" }
  Get-Content -LiteralPath $jsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Invoke-WebFileIfMissing {
  param(
    [Parameter(Mandatory)][string]$Url,
    [Parameter(Mandatory)][string]$DestinationPath
  )
  if (Test-Path -LiteralPath $DestinationPath) {
    Write-Host "Already present: $DestinationPath" -ForegroundColor DarkGray
    return $DestinationPath
  }
  $parent = Split-Path -Parent $DestinationPath
  if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
  }
  Write-Host "Downloading: $Url" -ForegroundColor Cyan
  $prev = $ProgressPreference
  $ProgressPreference = 'SilentlyContinue'
  try {
    Invoke-WebRequest -Uri $Url -OutFile $DestinationPath -UseBasicParsing
  } finally {
    $ProgressPreference = $prev
  }
  return $DestinationPath
}

function Expand-ZipIfNeeded {
  param(
    [Parameter(Mandatory)][string]$ZipPath,
    [Parameter(Mandatory)][string]$ExtractRoot
  )
  if (-not (Test-Path -LiteralPath $ZipPath)) { throw "ZIP not found: $ZipPath" }
  Ensure-Folder -Path $ExtractRoot
  $marker = Join-Path $ExtractRoot '.extracted'
  if (Test-Path -LiteralPath $marker) {
    Write-Host "Baseline already extracted under: $ExtractRoot" -ForegroundColor DarkGray
    return $ExtractRoot
  }
  Write-Host "Expanding: $ZipPath -> $ExtractRoot" -ForegroundColor Cyan
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $ExtractRoot)
  Set-Content -LiteralPath $marker -Value (Get-Date).ToString('o') -Encoding UTF8
  return $ExtractRoot
}

function Get-XmlFilesRecursive {
  param([Parameter(Mandatory)][string]$RootPath)
  if (-not (Test-Path -LiteralPath $RootPath)) { return @() }
  Get-ChildItem -LiteralPath $RootPath -Recurse -File -Filter *.xml -ErrorAction SilentlyContinue |
    Sort-Object FullName
}

function Find-RepresentativeBaselineGpoXml {
  param([Parameter(Mandatory)][string]$ExtractedBaselineRoot)
  $all = @(Get-XmlFilesRecursive -RootPath $ExtractedBaselineRoot)
  if ($all.Count -eq 0) { return $null }
  $prefer = @($all | Where-Object { $_.FullName -match '\\GPOs\\' -or $_.FullName -match '\\PolicyDefinitions\\' })
  if ($prefer.Count -gt 0) { return $prefer[0].FullName }
  return $all[0].FullName
}

function Import-FlattenRowsFromGpoXmlFile {
  param(
    [Parameter(Mandatory)][string]$XmlPath,
    [Parameter(Mandatory)][string]$LogicalGpoName
  )
  [xml]$doc = Get-Content -LiteralPath $XmlPath -Raw -Encoding UTF8
  return @(Get-AllFlattenedRows -Xml $doc -Gpo $LogicalGpoName)
}

function Merge-PolicyRowsWithWinner {
  param(
    [object[]]$RowsNist,
    [object[]]$RowsMicrosoft,
    [ValidateSet('Nist','Microsoft')][string]$Winner
  )
  $idx = @{}
  function AddOrSet($rows, $sourceTag) {
    foreach ($r in $rows) {
      if ($null -eq $r -or $r.Extension -eq 'Metadata') { continue }
      $k = $r.CanonicalNoGpo
      if ([string]::IsNullOrWhiteSpace($k)) { continue }
      if (-not $idx.ContainsKey($k)) {
        $idx[$k] = [pscustomobject]@{
          CanonicalNoGpo = $k
          Scope          = $r.Scope
          Extension      = $r.Extension
          Category       = $r.Category
          Setting        = $r.Setting
          ValueNist      = $null
          TypeNist       = $null
          ValueMicrosoft = $null
          TypeMicrosoft  = $null
          Winner         = $null
          Value          = $null
          Type           = $null
        }
      }
      $o = $idx[$k]
      if ($sourceTag -eq 'Nist') {
        $o.ValueNist = $r.Value
        $o.TypeNist = $r.Type
      } else {
        $o.ValueMicrosoft = $r.Value
        $o.TypeMicrosoft = $r.Type
      }
    }
  }
  AddOrSet -rows $RowsNist -sourceTag Nist
  AddOrSet -rows $RowsMicrosoft -sourceTag Microsoft

  foreach ($k in @($idx.Keys)) {
    $o = $idx[$k]
    $vn = $o.ValueNist
    $vm = $o.ValueMicrosoft
    if ($null -ne $vn -or $null -ne $vm) {
      if ($Winner -eq 'Nist') {
        $o.Winner = 'Nist'
        $o.Value = $vn
        $o.Type = $o.TypeNist
        if ($null -eq $o.Value -and $null -ne $vm) {
          $o.Winner = 'Microsoft'
          $o.Value = $vm
          $o.Type = $o.TypeMicrosoft
        }
      } else {
        $o.Winner = 'Microsoft'
        $o.Value = $vm
        $o.Type = $o.TypeMicrosoft
        if ($null -eq $o.Value -and $null -ne $vn) {
          $o.Winner = 'Nist'
          $o.Value = $vn
          $o.Type = $o.TypeNist
        }
      }
    }
  }

  $mergedRows = [System.Collections.Generic.List[object]]::new()
  [void]$mergedRows.Add( (New-FlattenRow -Gpo 'MASTER_MERGED' -Scope 'N/A' -Extension 'Metadata' -Category 'PolicyAudit' -Setting 'ConflictWinner' -Value $Winner -Type 'String') )
  foreach ($k in ($idx.Keys | Sort-Object)) {
    $o = $idx[$k]
    [void]$mergedRows.Add( (New-FlattenRow -Gpo 'MASTER_MERGED' -Scope $o.Scope -Extension $o.Extension -Category $o.Category -Setting $o.Setting -Value ([string]$o.Value) -Type ([string]$o.Type)) )
  }
  return @($mergedRows)
}

function Invoke-DownloadTemplatesMode {
  param(
    [Parameter(Mandatory)][string]$OutDir,
    [Parameter(Mandatory)][string]$MsBaselineId
  )
  $cat = Get-PolicyAuditDownloadCatalog
  $entry = @($cat.MicrosoftSecurityBaselines | Where-Object { $_.Id -eq $MsBaselineId })
  if ($entry.Count -eq 0) {
    throw "Unknown MsBaselineId '$MsBaselineId'. Valid: $($cat.MicrosoftSecurityBaselines.Id -join ', ')"
  }
  $url = $entry[0].Url
  $name = [System.IO.Path]::GetFileName(($url -replace '%20',' '))
  $dlDir = Join-Path $OutDir 'Downloads'
  Ensure-Folder -Path $dlDir
  $zipPath = Join-Path $dlDir $name
  Invoke-WebFileIfMissing -Url $url -DestinationPath $zipPath
  $nistDir = Join-Path $OutDir 'Templates\NIST'
  Ensure-Folder -Path $nistDir
  $readme = Join-Path $nistDir 'README.txt'
  if (-not (Test-Path -LiteralPath $readme)) {
    @"
Place NIST-aligned or agency GPO XML exports (*.xml) here, or pass -NistXmlPath to a specific file.

Official NIST publishes SP 800-171 and related guidance as PDFs and spreadsheets, not as GPO XML.
Use your organization's exported baseline or DISA STIG GPO reports if you need a federal baseline.
"@ | Set-Content -LiteralPath $readme -Encoding UTF8
  }
  Write-Host "Microsoft baseline ZIP: $zipPath" -ForegroundColor Green
  Write-Host "NIST template folder (add your XML): $nistDir" -ForegroundColor Green
  if ($cat.NistNotes) { Write-Host "Note: $($cat.NistNotes)" -ForegroundColor DarkYellow }
}

function Invoke-BuildMasterMode {
  param(
    [Parameter(Mandatory)][string]$OutDir,
    [Parameter(Mandatory)][string]$ConflictWinner,
    [string]$MsBaselineId,
    [string]$NistXmlPath,
    [string]$MsZipPath
  )
  $cat = Get-PolicyAuditDownloadCatalog
  if (-not $MsZipPath) {
    $entry = @($cat.MicrosoftSecurityBaselines | Where-Object { $_.Id -eq $MsBaselineId })
    if ($entry.Count -eq 0) { throw "Unknown MsBaselineId: $MsBaselineId" }
    $name = [System.IO.Path]::GetFileName(($entry[0].Url -replace '%20',' '))
    $MsZipPath = Join-Path $OutDir "Downloads\$name"
  }
  if (-not (Test-Path -LiteralPath $MsZipPath)) {
    throw "Microsoft baseline ZIP not found: $MsZipPath. Run -Mode DownloadTemplates first."
  }
  $extractRoot = Join-Path $OutDir "Templates\Microsoft\$MsBaselineId"
  Expand-ZipIfNeeded -ZipPath $MsZipPath -ExtractRoot $extractRoot
  $msXml = Find-RepresentativeBaselineGpoXml -ExtractedBaselineRoot $extractRoot
  if (-not $msXml) { throw "No XML found under extracted baseline: $extractRoot" }

  if (-not $NistXmlPath) {
    $nistDir = Join-Path $OutDir 'Templates\NIST'
    $candidates = @(Get-XmlFilesRecursive -RootPath $nistDir)
    if ($candidates.Count -eq 0) {
      throw "No NIST XML found. Add *.xml under $nistDir or pass -NistXmlPath."
    }
    $NistXmlPath = $candidates[0].FullName
  }
  if (-not (Test-Path -LiteralPath $NistXmlPath)) { throw "NistXmlPath not found: $NistXmlPath" }

  $rowsN = Import-FlattenRowsFromGpoXmlFile -XmlPath $NistXmlPath -LogicalGpoName 'NIST_BASELINE'
  $rowsM = Import-FlattenRowsFromGpoXmlFile -XmlPath $msXml -LogicalGpoName 'MS_SECURITY_BASELINE'
  $merged = Merge-PolicyRowsWithWinner -RowsNist $rowsN -RowsMicrosoft $rowsM -Winner $ConflictWinner

  $masterDir = Join-Path $OutDir 'MasterTemplate'
  Ensure-Folder -Path $masterDir
  $csvPath = Join-Path $masterDir 'MasterFlatten_MERGED.csv'
  $merged | Sort-Object Scope, Extension, Category, Setting |
    Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath $csvPath

  [pscustomobject]@{
    MasterCsv     = $csvPath
    NistXmlUsed   = $NistXmlPath
    MicrosoftXml  = $msXml
    ConflictWinner = $ConflictWinner
  } | Format-List | Out-Host
  Write-Host "Master template CSV: $csvPath" -ForegroundColor Green
}

function Get-GpoChildrenFromLinks {
  param(
    [Parameter(Mandatory)][string]$ParentGpoName,
    [object[]]$AllGpos,
    [object[]]$Links
  )
  $parent = @($AllGpos | Where-Object { $_.DisplayName -eq $ParentGpoName })
  if ($parent.Count -eq 0) { throw "GPO not found: $ParentGpoName" }
  $pg = $parent[0]
  $pgGuid = [Guid]$pg.Id

  $parentOus = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($L in $Links) {
    if ($L.GpoGuid -eq $pgGuid) { [void]$parentOus.Add($L.LinkedOuDn) }
  }
  if ($parentOus.Count -eq 0) {
    Write-Warning "Parent GPO '$ParentGpoName' has no gpLink entries in AD; child list will be empty."
    return @()
  }

  $childNameSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($L in $Links) {
    if ($L.GpoGuid -eq $pgGuid) { continue }
    foreach ($pou in $parentOus) {
      if ($L.LinkedOuDn -eq $pou -or $L.LinkedOuDn.EndsWith(",$pou", [StringComparison]::OrdinalIgnoreCase)) {
        $g = @($AllGpos | Where-Object { ([Guid]$_.Id) -eq $L.GpoGuid })
        if ($g.Count -gt 0 -and $g[0].DisplayName -ne $ParentGpoName) {
          [void]$childNameSet.Add($g[0].DisplayName)
        }
      }
    }
  }
  @($AllGpos | Where-Object { $childNameSet.Contains($_.DisplayName) } | Sort-Object DisplayName)
}

function Invoke-ExportDomainTreeMode {
  param(
    [Parameter(Mandatory)][string]$OutDir,
    [Parameter(Mandatory)][string]$RootGpoName,
    [string]$DomainDnsName,
    [int]$Throttle
  )
  Initialize-GpoAuditAdContext -DomainDnsName $DomainDnsName
  $gpoDom = Get-GpoAuditGpoDomainSplat
  $allGpos = @(Get-GPO @gpoDom -All -ErrorAction Stop | Sort-Object DisplayName)
  $links = @(Get-GpoOuLinksFromAd)
  $children = @(Get-GpoChildrenFromLinks -ParentGpoName $RootGpoName -AllGpos $allGpos -Links $links)

  $treeRoot = Join-Path $OutDir "DomainGpos\$($RootGpoName -replace '[^\w\.-]+','_')"
  Ensure-Folder -Path $treeRoot
  $exportDir = Join-Path $treeRoot 'Exports'
  Ensure-Folder -Path $exportDir

  $toExport = [System.Collections.Generic.List[object]]::new()
  [void]$toExport.Add(($allGpos | Where-Object { $_.DisplayName -eq $RootGpoName } | Select-Object -First 1))
  foreach ($c in $children) { [void]$toExport.Add($c) }

  $meta = @()
  foreach ($g in $toExport) {
    if ($null -eq $g) { continue }
    $safe = New-SafeName $g.DisplayName
    $sub = if ($g.DisplayName -eq $RootGpoName) { 'Parent' } else { 'Children' }
    $dir = Join-Path $exportDir $sub
    Ensure-Folder -Path $dir
    $file = Join-Path $dir ("{0}.xml" -f $safe)
    Get-GPOReport @gpoDom -Guid $g.Id -ReportType XML -Path $file
    $meta += [pscustomobject]@{ Role = $sub; DisplayName = $g.DisplayName; Guid = [string]$g.Id; XmlPath = $file }
  }

  $metaPath = Join-Path $treeRoot 'ExportManifest.csv'
  $meta | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath $metaPath
  Write-Host "Exported $($meta.Count) GPO XML file(s) under: $treeRoot" -ForegroundColor Green
  return $treeRoot
}

function Import-MasterFlattenCsv {
  param([Parameter(Mandatory)][string]$Path)
  Import-Csv -LiteralPath $Path
}

function Combine-EffectiveGpoRows {
  param(
    [Parameter(Mandatory)][object[]]$ParentRows,
    [Parameter(Mandatory)][object[]]$ChildRowsList
  )
  $byKey = @{}
  foreach ($r in $ParentRows) {
    if ($null -eq $r -or $r.Extension -eq 'Metadata') { continue }
    $k = $r.CanonicalNoGpo
    if ([string]::IsNullOrWhiteSpace($k)) { continue }
    $byKey[$k] = $r
  }
  foreach ($childRows in $ChildRowsList) {
    foreach ($r in $childRows) {
      if ($null -eq $r -or $r.Extension -eq 'Metadata') { continue }
      $k = $r.CanonicalNoGpo
      if ([string]::IsNullOrWhiteSpace($k)) { continue }
      $byKey[$k] = $r
    }
  }
  $out = [System.Collections.Generic.List[object]]::new()
  foreach ($k in ($byKey.Keys | Sort-Object)) {
    $r = $byKey[$k]
    [void]$out.Add( (New-FlattenRow -Gpo 'EFFECTIVE_STACK' -Scope $r.Scope -Extension $r.Extension -Category $r.Category -Setting $r.Setting -Value $r.Value -Type $r.Type) )
  }
  return @($out)
}

function Invoke-CompareMode {
  param(
    [Parameter(Mandatory)][string]$OutDir,
    [Parameter(Mandatory)][string]$RootGpoName,
    [string]$DiffCsvPath
  )
  $masterCsv = Join-Path $OutDir 'MasterTemplate\MasterFlatten_MERGED.csv'
  if (-not (Test-Path -LiteralPath $masterCsv)) {
    throw "Master CSV not found: $masterCsv. Run -Mode BuildMaster first."
  }
  $treeRoot = Join-Path $OutDir "DomainGpos\$($RootGpoName -replace '[^\w\.-]+','_')"
  $parentXml = Join-Path $treeRoot 'Exports\Parent'
  $childXmlDir = Join-Path $treeRoot 'Exports\Children'
  if (-not (Test-Path -LiteralPath $parentXml)) {
    throw "Parent export folder missing. Run -Mode ExportDomainTree first. Expected: $parentXml"
  }

  $masterRows = @(Import-MasterFlattenCsv -Path $masterCsv | Where-Object { $_.Extension -ne 'Metadata' })
  $parentFiles = @(Get-ChildItem -LiteralPath $parentXml -Filter *.xml -File)
  if ($parentFiles.Count -eq 0) { throw "No parent XML in $parentXml" }
  [xml]$px = Get-Content -LiteralPath $parentFiles[0].FullName -Raw
  $parentRows = @(Get-AllFlattenedRows -Xml $px -Gpo $RootGpoName)

  $childRowsList = @()
  if (Test-Path -LiteralPath $childXmlDir) {
    foreach ($cf in (Get-ChildItem -LiteralPath $childXmlDir -Filter *.xml -File)) {
      [xml]$cx = Get-Content -LiteralPath $cf.FullName -Raw
      $nm = ($cf.BaseName -replace '_',' ')
      $childRowsList += ,@(Get-AllFlattenedRows -Xml $cx -Gpo $nm)
    }
  }

  $effective = Combine-EffectiveGpoRows -ParentRows $parentRows -ChildRowsList $childRowsList

  $lIndex = @{}
  foreach ($x in $masterRows) {
    $id = $x.CanonicalNoGpo
    if ($id) { $lIndex[$id] = $x }
  }
  $rIndex = @{}
  foreach ($x in $effective) {
    $id = $x.CanonicalNoGpo
    if ($id) { $rIndex[$id] = $x }
  }
  $allIds = New-Object System.Collections.Generic.HashSet[string]
  foreach ($k in $lIndex.Keys) { [void]$allIds.Add($k) }
  foreach ($k in $rIndex.Keys) { [void]$allIds.Add($k) }

  $diffRows = foreach ($id in ($allIds | Sort-Object)) {
    $l = $lIndex[$id]
    $r = $rIndex[$id]
    if ($null -eq $l) {
      [pscustomobject]@{
        Key = $id
        Status = 'OnlyInEnvironment'
        Scope = $r.Scope; Extension = $r.Extension; Category = $r.Category; Setting = $r.Setting
        MasterValue = $null; EnvValue = $r.Value
      }
      continue
    }
    if ($null -eq $r) {
      [pscustomobject]@{
        Key = $id
        Status = 'OnlyInMaster'
        Scope = $l.Scope; Extension = $l.Extension; Category = $l.Category; Setting = $l.Setting
        MasterValue = $l.Value; EnvValue = $null
      }
      continue
    }
    $changed = ($l.Value -ne $r.Value)
    [pscustomobject]@{
      Key = $id
      Status = $(if ($changed) { 'Drift' } else { 'Match' })
      Scope = $r.Scope; Extension = $r.Extension; Category = $r.Category; Setting = $r.Setting
      MasterValue = $l.Value; EnvValue = $r.Value
    }
  }

  $diffDir = Join-Path $OutDir 'Diffs'
  Ensure-Folder -Path $diffDir
  if (-not $DiffCsvPath) {
    $DiffCsvPath = Join-Path $diffDir ("Diff_Master_vs_{0}_{1}.csv" -f (New-SafeName $RootGpoName), (Get-Date -Format 'yyyyMMdd_HHmmss'))
  }
  $diffRows | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath $DiffCsvPath
  Write-Host "Diff written: $DiffCsvPath" -ForegroundColor Green
  return $DiffCsvPath
}

function Invoke-ReviewDiffMode {
  param(
    [Parameter(Mandatory)][string]$DiffCsvIn,
    [Parameter(Mandatory)][string]$DiffCsvOut
  )
  if (-not (Test-Path -LiteralPath $DiffCsvIn)) { throw "Diff CSV not found: $DiffCsvIn" }
  Show-PolicyAuditDiffReviewForm -DiffCsvPath $DiffCsvIn -OutCsvPath $DiffCsvOut
}

function Show-PolicyAuditDiffReviewForm {
  param(
    [Parameter(Mandatory)][string]$DiffCsvPath,
    [Parameter(Mandatory)][string]$OutCsvPath
  )
  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing

  $rows = @(Import-Csv -LiteralPath $DiffCsvPath)
  $form = New-Object System.Windows.Forms.Form
  $form.Text = 'GPO Policy Audit – Review diff (uncheck accepted risk, add comment)'
  $form.Size = New-Object System.Drawing.Size(1100, 600)
  $form.StartPosition = 'CenterScreen'

  $grid = New-Object System.Windows.Forms.DataGridView
  $grid.Dock = 'Fill'
  $grid.AutoGenerateColumns = $false
  $grid.AllowUserToAddRows = $false
  $grid.SelectionMode = 'FullRowSelect'
  $grid.MultiSelect = $false
  [void]$grid.Columns.Add((New-Object System.Windows.Forms.DataGridViewCheckBoxColumn @{ Name = 'IncludeRemediation'; HeaderText = 'Remediate'; Width = 70 }))
  [void]$grid.Columns.Add((New-Object System.Windows.Forms.DataGridViewTextBoxColumn @{ Name = 'Status'; HeaderText = 'Status'; ReadOnly = $true; Width = 110 }))
  [void]$grid.Columns.Add((New-Object System.Windows.Forms.DataGridViewTextBoxColumn @{ Name = 'Scope'; HeaderText = 'Scope'; ReadOnly = $true; Width = 70 }))
  [void]$grid.Columns.Add((New-Object System.Windows.Forms.DataGridViewTextBoxColumn @{ Name = 'Extension'; HeaderText = 'Extension'; ReadOnly = $true; Width = 100 }))
  [void]$grid.Columns.Add((New-Object System.Windows.Forms.DataGridViewTextBoxColumn @{ Name = 'Category'; HeaderText = 'Category'; ReadOnly = $true; Width = 120 }))
  [void]$grid.Columns.Add((New-Object System.Windows.Forms.DataGridViewTextBoxColumn @{ Name = 'Setting'; HeaderText = 'Setting'; ReadOnly = $true; Width = 220 }))
  [void]$grid.Columns.Add((New-Object System.Windows.Forms.DataGridViewTextBoxColumn @{ Name = 'MasterValue'; HeaderText = 'Master'; ReadOnly = $true; Width = 140 }))
  [void]$grid.Columns.Add((New-Object System.Windows.Forms.DataGridViewTextBoxColumn @{ Name = 'EnvValue'; HeaderText = 'Environment'; ReadOnly = $true; Width = 140 }))
  [void]$grid.Columns.Add((New-Object System.Windows.Forms.DataGridViewTextBoxColumn @{ Name = 'RiskComment'; HeaderText = 'Accepted risk / notes'; Width = 240 }))

  foreach ($r in $rows) {
    $remediate = $true
    if ($r.Status -eq 'Match') { $remediate = $false }
    $ix = $grid.Rows.Add(@(
      $remediate,
      $r.Status,
      $r.Scope,
      $r.Extension,
      $r.Category,
      $r.Setting,
      $r.MasterValue,
      $r.EnvValue,
      ''
    ))
    $grid.Rows[$ix].Tag = $r.Key
  }

  $panel = New-Object System.Windows.Forms.Panel
  $panel.Dock = 'Bottom'
  $panel.Height = 44
  $btn = New-Object System.Windows.Forms.Button
  $btn.Text = 'Save reviewed CSV'
  $btn.Dock = 'Right'
  $btn.Width = 160
  $btn.Add_Click({
      $out = [System.Collections.Generic.List[object]]::new()
    foreach ($gr in $grid.Rows) {
      if ($gr.IsNewRow) { continue }
      $out.Add([pscustomobject]@{
        IncludeRemediation = [bool]$gr.Cells['IncludeRemediation'].Value
        Status = [string]$gr.Cells['Status'].Value
        Scope = [string]$gr.Cells['Scope'].Value
        Extension = [string]$gr.Cells['Extension'].Value
        Category = [string]$gr.Cells['Category'].Value
        Setting = [string]$gr.Cells['Setting'].Value
        MasterValue = [string]$gr.Cells['MasterValue'].Value
        EnvValue = [string]$gr.Cells['EnvValue'].Value
        RiskComment = [string]$gr.Cells['RiskComment'].Value
        Key = [string]$gr.Tag
      })
    }
    $parent = Split-Path -Parent $OutCsvPath
    if ($parent) { Ensure-Folder -Path $parent }
    $out | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath $OutCsvPath
    [System.Windows.Forms.MessageBox]::Show("Saved: $OutCsvPath", 'GPO Policy Audit')
    $form.Close()
  })
  $panel.Controls.Add($btn)
  $form.Controls.Add($grid)
  $form.Controls.Add($panel)
  [void]$form.ShowDialog()
}

function Invoke-BackupGposMode {
  param(
    [Parameter(Mandatory)][string]$OutDir,
    [Parameter(Mandatory)][string]$RootGpoName,
    [string]$BackupFolder
  )
  if (-not $BackupFolder) {
    $BackupFolder = Join-Path $OutDir ('GpoBackups_{0}_{1}' -f (New-SafeName $RootGpoName), (Get-Date -Format 'yyyyMMdd_HHmmss'))
  }
  Ensure-Folder -Path $BackupFolder
  Initialize-GpoAuditAdContext -DomainDnsName $DomainDnsName
  $gpoDom = Get-GpoAuditGpoDomainSplat
  $allGpos = @(Get-GPO @gpoDom -All -ErrorAction Stop)
  $links = @(Get-GpoOuLinksFromAd)
  $children = @(Get-GpoChildrenFromLinks -ParentGpoName $RootGpoName -AllGpos $allGpos -Links $links)
  $parent = @($allGpos | Where-Object { $_.DisplayName -eq $RootGpoName } | Select-Object -First 1)
  if (-not $parent) { throw "GPO not found: $RootGpoName" }

  $list = [System.Collections.Generic.List[object]]::new()
  [void]$list.Add($parent)
  foreach ($c in $children) { [void]$list.Add($c) }

  $manifest = @()
  foreach ($g in $list) {
    $sub = Join-Path $BackupFolder (New-SafeName $g.DisplayName)
    Ensure-Folder -Path $sub
    Backup-GPO @gpoDom -Name $g.DisplayName -Path $sub | Out-Null
    $manifest += [pscustomobject]@{ DisplayName = $g.DisplayName; Guid = [string]$g.Id; BackupPath = $sub }
  }
  $manifest | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $BackupFolder 'BackupManifest.csv')
  Write-Host "GPO backup(s) written under: $BackupFolder" -ForegroundColor Green
}

function Show-PolicyAuditGui {
  param([string]$DefaultOutDir)

  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing

  $form = New-Object System.Windows.Forms.Form
  $form.Text = 'GPO Policy Audit'
  $form.Size = New-Object System.Drawing.Size(560, 420)
  $form.StartPosition = 'CenterScreen'

  $y = 16
  $lbl = New-Object System.Windows.Forms.Label
  $lbl.Location = New-Object System.Drawing.Point(16, $y)
  $lbl.Size = New-Object System.Drawing.Size(500, 60)
  $lbl.Text = "Workflow: 1) Download Microsoft baseline ZIP (optional) + add NIST XML to Templates\NIST`r`n2) Build merged master CSV`r`n3) Export parent+child GPO XML to AD-like tree`r`n4) Diff vs master`r`n5) Review diff (risk comments)`r`n6) Backup-GPO for import"
  $form.Controls.Add($lbl)
  $y += 68

  $ld = New-Object System.Windows.Forms.Label; $ld.Text = 'Working folder:'; $ld.Location = New-Object System.Drawing.Point(16, $y); $ld.Size = New-Object System.Drawing.Size(100, 20)
  $form.Controls.Add($ld)
  $tbOut = New-Object System.Windows.Forms.TextBox; $tbOut.Location = New-Object System.Drawing.Point(120, $y-2); $tbOut.Width = 320; $tbOut.Text = $DefaultOutDir
  $form.Controls.Add($tbOut)
  $y += 36

  $lgd = New-Object System.Windows.Forms.Label; $lgd.Text = 'Domain DNS (optional):'; $lgd.Location = New-Object System.Drawing.Point(16, $y); $lgd.Size = New-Object System.Drawing.Size(140, 20)
  $form.Controls.Add($lgd)
  $tbDom = New-Object System.Windows.Forms.TextBox; $tbDom.Location = New-Object System.Drawing.Point(160, $y-2); $tbDom.Width = 280; $tbDom.Text = ''
  $form.Controls.Add($tbDom)
  $y += 36

  $lrg = New-Object System.Windows.Forms.Label; $lrg.Text = 'Root GPO name (parent):'; $lrg.Location = New-Object System.Drawing.Point(16, $y); $lrg.Size = New-Object System.Drawing.Size(160, 20)
  $form.Controls.Add($lrg)
  $tbGpo = New-Object System.Windows.Forms.TextBox; $tbGpo.Location = New-Object System.Drawing.Point(180, $y-2); $tbGpo.Width = 340
  $form.Controls.Add($tbGpo)
  $y += 40

  $cbWin = New-Object System.Windows.Forms.ComboBox
  $cbWin.Location = New-Object System.Drawing.Point(180, $y-2); $cbWin.Width = 200; $cbWin.DropDownStyle = 'DropDownList'
  [void]$cbWin.Items.Add('Microsoft wins conflicts'); $cbWin.Items.Add('NIST wins conflicts')
  $cbWin.SelectedIndex = 0
  $form.Controls.Add((New-Object System.Windows.Forms.Label @{ Text = 'Merge conflict winner:'; Location = New-Object System.Drawing.Point(16, $y); Size = New-Object System.Drawing.Size(160, 20) }))
  $form.Controls.Add($cbWin)
  $y += 40

  $btnRow = $y
  $addBtn = {
    param($text, $xpos)
    $b = New-Object System.Windows.Forms.Button; $b.Text = $text; $b.Location = New-Object System.Drawing.Point($xpos, $btnRow); $b.Width = 160; $b.Height = 28
    $form.Controls.Add($b)
    return $b
  }

  $b1 = & $addBtn '1. Download templates' 16
  $b2 = & $addBtn '2. Build master' 200
  $b3 = & $addBtn '3. Export AD tree' 384
  $btnRow += 36
  $b4 = & $addBtn '4. Compare' 16
  $b5 = & $addBtn '5. Review diff…' 200
  $b6 = & $addBtn '6. Backup GPOs' 384

  $status = New-Object System.Windows.Forms.Label
  $status.Location = New-Object System.Drawing.Point(16, 320)
  $status.Size = New-Object System.Drawing.Size(500, 60)
  $status.Text = ''
  $form.Controls.Add($status)

  $handler = {
    param($action)
    try {
      $domPick = $tbDom.Text.Trim()
      if ([string]::IsNullOrWhiteSpace($domPick)) { $domPick = $null }
      $od = $tbOut.Text.Trim()
      if ([string]::IsNullOrWhiteSpace($od)) { $od = $DefaultOutDir }
      $rg = $tbGpo.Text.Trim()
      $winner = if ($cbWin.SelectedIndex -eq 0) { 'Microsoft' } else { 'Nist' }
      switch ($action) {
        'd' { Invoke-DownloadTemplatesMode -OutDir $od -MsBaselineId $MsBaselineId }
        'b' { Invoke-BuildMasterMode -OutDir $od -ConflictWinner $winner -MsBaselineId $MsBaselineId -NistXmlPath $null -MsZipPath $null }
        'e' {
          if ([string]::IsNullOrWhiteSpace($rg)) { throw 'Enter the root GPO display name.' }
          Initialize-GpoAuditAdContext -DomainDnsName $domPick
          Invoke-ExportDomainTreeMode -OutDir $od -RootGpoName $rg -DomainDnsName $domPick -Throttle 6
        }
        'c' {
          if ([string]::IsNullOrWhiteSpace($rg)) { throw 'Enter the root GPO display name.' }
          Initialize-GpoAuditAdContext -DomainDnsName $domPick
          Invoke-CompareMode -OutDir $od -RootGpoName $rg -DiffCsvPath $null
        }
        'r' {
          $diffs = Get-ChildItem -LiteralPath (Join-Path $od 'Diffs') -Filter *.csv -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
          if (-not $diffs -or $diffs.Count -eq 0) { throw 'No diff CSV in Diffs folder. Run step 4 first.' }
          $reviewOut = Join-Path $od ('Diffs\Reviewed_{0}.csv' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
          Show-PolicyAuditDiffReviewForm -DiffCsvPath $diffs[0].FullName -OutCsvPath $reviewOut
        }
        'k' {
          if ([string]::IsNullOrWhiteSpace($rg)) { throw 'Enter the root GPO display name.' }
          Initialize-GpoAuditAdContext -DomainDnsName $domPick
          Invoke-BackupGposMode -OutDir $od -RootGpoName $rg -BackupFolder $null
        }
      }
      $status.Text = "Last action OK: $action"
      $status.ForeColor = [System.Drawing.Color]::DarkGreen
    } catch {
      $status.Text = $_.Exception.Message
      $status.ForeColor = [System.Drawing.Color]::DarkRed
      [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'GPO Policy Audit', 'OK', 'Error')
    }
  }

  $b1.Add_Click({ & $handler 'd' })
  $b2.Add_Click({ & $handler 'b' })
  $b3.Add_Click({ & $handler 'e' })
  $b4.Add_Click({ & $handler 'c' })
  $b5.Add_Click({ & $handler 'r' })
  $b6.Add_Click({ & $handler 'k' })

  [void]$form.ShowDialog()
}

# --- Dispatcher ---
if ($Mode -eq 'Gui') {
  Show-PolicyAuditGui -DefaultOutDir $OutDir
  return
}

switch ($Mode) {
  'DownloadTemplates' { Invoke-DownloadTemplatesMode -OutDir $OutDir -MsBaselineId $MsBaselineId }
  'BuildMaster'       { Invoke-BuildMasterMode -OutDir $OutDir -ConflictWinner $ConflictWinner -MsBaselineId $MsBaselineId -NistXmlPath $NistXmlPath -MsZipPath $MsZipPath }
  'ExportDomainTree'  {
    Initialize-GpoAuditAdContext -DomainDnsName $DomainDnsName
    Invoke-ExportDomainTreeMode -OutDir $OutDir -RootGpoName $RootGpoName -DomainDnsName $DomainDnsName -Throttle $Throttle
  }
  'Compare'           {
    Initialize-GpoAuditAdContext -DomainDnsName $DomainDnsName
    Invoke-CompareMode -OutDir $OutDir -RootGpoName $RootGpoName -DiffCsvPath $CompareDiffCsvOut
  }
  'ReviewDiff'        { Invoke-ReviewDiffMode -DiffCsvIn $ReviewDiffCsvIn -DiffCsvOut $ReviewDiffCsvOut }
  'BackupGpos'        {
    Initialize-GpoAuditAdContext -DomainDnsName $DomainDnsName
    Invoke-BackupGposMode -OutDir $OutDir -RootGpoName $RootGpoName -BackupFolder $BackupFolder
  }
}
