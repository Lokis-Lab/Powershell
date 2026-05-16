<#
.SYNOPSIS
  After-hours GPO baseline audit workflow (NIST + Microsoft).

.DESCRIPTION
  Builds a fresh, automatable Group Policy audit workflow that:
    1) Pulls the latest Microsoft SCT baseline ZIP(s) and latest NIST GPO package.
    2) Merges both templates into a master baseline with conflict winner selection.
    3) Pulls GPO links from AD and exports a folder layout mirroring AD hierarchy.
    4) Compares the master baseline against linked GPOs for a container and its children.
    5) Produces a diff review file where changes can be deselected with risk comments.
    6) Exports GPO backups and link/import helper artifacts for upload/link operations.

  The script is designed for a domain-joined Windows management host with RSAT
  (GroupPolicy + ActiveDirectory modules) and internet access.

.PARAMETER OutputRoot
  Root folder for all generated data.

.PARAMETER MergeMode
  Conflict winner behavior when Microsoft and NIST disagree on a setting.
  - PreferMicrosoft: Microsoft value wins.
  - PreferNist: NIST value wins.
  - Interactive: prompt for each conflict.

.PARAMETER MicrosoftDownloadPageUrl
  Microsoft Security Compliance Toolkit download page.

.PARAMETER MicrosoftFileNameRegex
  Regex used to choose which Microsoft ZIP files to download from SCT.

.PARAMETER NistFeedZipUrl
  NIST NCP feed ZIP URL.

.PARAMETER NistFeedMetaUrl
  NIST NCP feed META URL used to detect changes.

.PARAMETER NistTitleRegex
  Regex to choose which checklist title is treated as "latest GPO template".

.PARAMETER NistReferenceRegex
  Regex to choose which reference URL in the selected checklist should be downloaded.

.PARAMETER TargetContainerDn
  DistinguishedName to compare (includes linked GPOs in child OUs too).
  Defaults to domain root DN.

.PARAMETER RiskReviewCsvPath
  Optional path to an edited review CSV (ApplyChange + RiskComment) to apply.

.PARAMETER InteractiveRiskReview
  Prompt interactively to keep/deselect each diff item and capture risk comments.

.PARAMETER WorkDnsSuffixes
  Optional DNS suffix list considered "work network". If detected, script exits.

.PARAMETER WorkIpv4Prefixes
  Optional IPv4 prefixes considered "work network" (e.g. "10.", "192.168.40.").

.PARAMETER StartHour24
  After-hours start in 24-hour clock. Default 17 (5 PM).

.PARAMETER BypassAfterHoursGuard
  Skip "must run after StartHour24" check.

.PARAMETER BypassWorkNetworkGuard
  Skip "must not run from work network" check.

.PARAMETER SkipTemplateDownload
  Skip downloading and only use already extracted template content.

.EXAMPLE
  .\Invoke-AfterHoursGpoPolicyAudit.ps1 `
    -OutputRoot "C:\GpoAudit\AfterHours" `
    -MergeMode Interactive `
    -WorkDnsSuffixes "corp.contoso.com" `
    -WorkIpv4Prefixes "10.","172.16." `
    -InteractiveRiskReview

.NOTES
  Requires:
    - GroupPolicy module
    - ActiveDirectory module
    - Domain access for Get-GPOReport / Get-GPInheritance / Backup-GPO
    - Internet access for template sync
#>

[CmdletBinding()]
param(
  [string]$OutputRoot = (Join-Path -Path $PWD.Path -ChildPath 'AfterHours-GpoAudit'),

  [ValidateSet('PreferMicrosoft','PreferNist','Interactive')]
  [string]$MergeMode = 'Interactive',

  [string]$MicrosoftDownloadPageUrl = 'https://www.microsoft.com/en-us/download/details.aspx?id=55319',
  [string]$MicrosoftFileNameRegex = '(?i)Security Baseline\.zip$',

  [string]$NistFeedZipUrl = 'https://ncp.nist.gov/feeds/xml/ncp/checklist-0.1-feed.xml.zip',
  [string]$NistFeedMetaUrl = 'https://ncp.nist.gov/feeds/xml/ncp/checklist-0.1-feed.meta',
  [string]$NistTitleRegex = '(?i)Group Policy Objects|GPO Package|Windows',
  [string]$NistReferenceRegex = '(?i)U_STIG_GPO_Package_.*\.zip$',

  [string]$TargetContainerDn,
  [string]$RiskReviewCsvPath,

  [switch]$InteractiveRiskReview,
  [switch]$BypassAfterHoursGuard,
  [switch]$BypassWorkNetworkGuard,
  [switch]$SkipTemplateDownload,

  [string[]]$WorkDnsSuffixes = @(),
  [string[]]$WorkIpv4Prefixes = @(),

  [ValidateRange(0,23)]
  [int]$StartHour24 = 17
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Stage {
  param([Parameter(Mandatory)][string]$Message)
  Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Message) -ForegroundColor Cyan
}

function Ensure-Directory {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -Path $Path -ItemType Directory -Force | Out-Null
  }
}

function Ensure-ModuleAvailable {
  param([Parameter(Mandatory)][string]$Name)
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    throw "Required module '$Name' is not available. Install RSAT/module first."
  }
  Import-Module $Name -ErrorAction Stop
}

function Get-SafeFileName {
  param([Parameter(Mandatory)][string]$Name)
  $invalid = [System.IO.Path]::GetInvalidFileNameChars()
  $builder = New-Object System.Text.StringBuilder
  foreach ($ch in $Name.ToCharArray()) {
    if ($invalid -contains $ch) {
      [void]$builder.Append('_')
    } else {
      [void]$builder.Append($ch)
    }
  }
  return $builder.ToString().Trim()
}

function Get-ParentDn {
  param([Parameter(Mandatory)][string]$DistinguishedName)
  for ($i = 0; $i -lt $DistinguishedName.Length; $i++) {
    if ($DistinguishedName[$i] -ne ',') { continue }

    $escapeCount = 0
    for ($j = $i - 1; $j -ge 0 -and $DistinguishedName[$j] -eq [char]'\'; $j--) {
      $escapeCount++
    }

    if (($escapeCount % 2) -eq 0) {
      if ($i -ge ($DistinguishedName.Length - 1)) { return $null }
      return $DistinguishedName.Substring($i + 1)
    }
  }

  return $null
}

function Test-AfterHoursWindow {
  param([int]$StartHour = 17)
  $hour = (Get-Date).Hour
  return ($hour -ge $StartHour)
}

function Get-LocalIpv4Addresses {
  $addresses = @()
  try {
    $addresses = @(
      Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $_.IPAddress -and $_.IPAddress -notlike '169.254*' } |
        Select-Object -ExpandProperty IPAddress
    )
  } catch {
    # Fallback for environments lacking Get-NetIPAddress
    try {
      $addresses = @(
        [System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) |
          Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
          ForEach-Object { $_.IPAddressToString }
      )
    } catch {
      $addresses = @()
    }
  }
  return @($addresses | Where-Object { $_ } | Select-Object -Unique)
}

function Get-LocalDnsSuffixes {
  $suffixes = @()
  try {
    $suffixes = @(
      Get-DnsClient -ErrorAction Stop |
        Select-Object -ExpandProperty ConnectionSpecificSuffix
    )
  } catch {
    $suffixes = @()
  }
  return @($suffixes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
}

function Test-WorkNetworkDetected {
  param(
    [string[]]$DnsSuffixes,
    [string[]]$Ipv4Prefixes
  )
  $dnsMatches = @()
  $ipMatches = @()

  if ($DnsSuffixes.Count -gt 0) {
    $localDns = Get-LocalDnsSuffixes
    foreach ($suffix in $DnsSuffixes) {
      $hits = $localDns | Where-Object { $_ -like "*$suffix" }
      if ($hits) {
        $dnsMatches += $hits
      }
    }
  }

  if ($Ipv4Prefixes.Count -gt 0) {
    $localIps = Get-LocalIpv4Addresses
    foreach ($prefix in $Ipv4Prefixes) {
      $hits = $localIps | Where-Object { $_ -like "$prefix*" }
      if ($hits) {
        $ipMatches += $hits
      }
    }
  }

  return [pscustomobject]@{
    IsWorkNetwork = (($dnsMatches.Count -gt 0) -or ($ipMatches.Count -gt 0))
    DnsMatches    = @($dnsMatches | Select-Object -Unique)
    IpMatches     = @($ipMatches | Select-Object -Unique)
  }
}

function Get-RemoteLastModified {
  param([Parameter(Mandatory)][string]$Url)
  try {
    $response = Invoke-WebRequest -Uri $Url -Method Head -UseBasicParsing -ErrorAction Stop
    $header = $response.Headers['Last-Modified']
    if ([string]::IsNullOrWhiteSpace($header)) { return $null }
    return [datetime]::Parse($header).ToUniversalTime()
  } catch {
    return $null
  }
}

function Invoke-DownloadIfNeeded {
  param(
    [Parameter(Mandatory)][string]$Url,
    [Parameter(Mandatory)][string]$DestinationPath
  )
  $download = $true

  if (Test-Path -LiteralPath $DestinationPath) {
    $download = $false
    $remoteUtc = Get-RemoteLastModified -Url $Url
    if ($remoteUtc) {
      $localUtc = (Get-Item -LiteralPath $DestinationPath).LastWriteTimeUtc
      if ($remoteUtc -gt $localUtc) {
        $download = $true
      }
    }
  }

  if ($download) {
    Write-Host "Downloading: $Url" -ForegroundColor Yellow
    Invoke-WebRequest -Uri $Url -OutFile $DestinationPath -UseBasicParsing -ErrorAction Stop
    Write-Host "Saved: $DestinationPath" -ForegroundColor Green
  } else {
    Write-Host "Already current: $DestinationPath" -ForegroundColor DarkGray
  }

  return $DestinationPath
}

function Expand-ZipIfNeeded {
  param(
    [Parameter(Mandatory)][string]$ZipPath,
    [Parameter(Mandatory)][string]$DestinationFolder
  )
  Ensure-Directory -Path $DestinationFolder
  $marker = Join-Path -Path $DestinationFolder -ChildPath '.expanded.marker'
  $shouldExpand = -not (Test-Path -LiteralPath $marker)

  if (-not $shouldExpand) {
    $zipUtc = (Get-Item -LiteralPath $ZipPath).LastWriteTimeUtc
    $markerUtc = (Get-Item -LiteralPath $marker).LastWriteTimeUtc
    $shouldExpand = $zipUtc -gt $markerUtc
  }

  if ($shouldExpand) {
    Get-ChildItem -LiteralPath $DestinationFolder -Force | Remove-Item -Recurse -Force
    Expand-Archive -Path $ZipPath -DestinationPath $DestinationFolder -Force
    Set-Content -LiteralPath $marker -Value ("Expanded {0}" -f (Get-Date).ToString('o')) -Encoding UTF8
  }
}

function Get-MicrosoftSctFileList {
  param(
    [Parameter(Mandatory)][string]$PageUrl,
    [Parameter(Mandatory)][string]$FileNameRegex
  )

  $html = (Invoke-WebRequest -Uri $PageUrl -UseBasicParsing -ErrorAction Stop).Content
  $pattern = '\{"isPrimary":"[^"]*","name":"(?<name>[^"]+)","url":"(?<url>https://download\.microsoft\.com/[^"]+\.zip)","size":"(?<size>\d+)","version":"(?<version>[^"]*)","datePublished":"(?<date>[^"]+)"\}'
  $matches = [regex]::Matches($html, $pattern)
  $files = @()

  foreach ($m in $matches) {
    $name = $m.Groups['name'].Value
    $url = $m.Groups['url'].Value
    if ($name -match $FileNameRegex) {
      $published = $null
      try { $published = [datetime]::Parse($m.Groups['date'].Value) } catch { $published = $null }
      $files += [pscustomobject]@{
        Name          = $name
        Url           = $url
        DatePublished = $published
        Version       = $m.Groups['version'].Value
      }
    }
  }

  if ($files.Count -eq 0) {
    throw "No Microsoft baseline files matched regex '$FileNameRegex'."
  }

  return @($files | Sort-Object -Property Name -Unique)
}

function Get-NistFeedLastModifiedText {
  param([Parameter(Mandatory)][string]$MetaUrl)
  try {
    $content = (Invoke-WebRequest -Uri $MetaUrl -UseBasicParsing -ErrorAction Stop).Content
    $match = [regex]::Match($content, 'lastModifiedDate:(?<dt>[^\s]+)')
    if ($match.Success) { return $match.Groups['dt'].Value }
    return $null
  } catch {
    return $null
  }
}

function Get-NistLatestGpoPackageUrl {
  param(
    [Parameter(Mandatory)][string]$FeedZipPath,
    [Parameter(Mandatory)][string]$TitleRegex,
    [Parameter(Mandatory)][string]$ReferenceRegex
  )

  Add-Type -AssemblyName 'System.IO.Compression.FileSystem' | Out-Null
  $archive = [System.IO.Compression.ZipFile]::OpenRead($FeedZipPath)
  try {
    $entry = $archive.Entries | Where-Object { $_.FullName -match '\.xml$' } | Select-Object -First 1
    if (-not $entry) { throw "NIST feed ZIP did not contain an XML entry." }
    $reader = New-Object System.IO.StreamReader($entry.Open())
    try {
      [xml]$xml = $reader.ReadToEnd()
    } finally {
      $reader.Dispose()
    }
  } finally {
    $archive.Dispose()
  }

  $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
  $ns.AddNamespace('f', 'http://checklists.nist.gov/schema/feed/checklist/0.2')
  $ns.AddNamespace('c', 'http://checklists.nist.gov/schema/checklist/0.2')

  $candidates = [System.Collections.Generic.List[object]]::new()
  $entries = $xml.SelectNodes('//f:entry', $ns)
  foreach ($entryNode in $entries) {
    $titleNodes = $entryNode.SelectNodes('.//c:title', $ns)
    $titleText = (($titleNodes | ForEach-Object { $_.InnerText }) -join ' ').Trim()
    if ($titleText -notmatch $TitleRegex) { continue }

    $modifiedText = $null
    $modifiedNode = $entryNode.SelectSingleNode('.//c:last-modified-datetime', $ns)
    if ($modifiedNode) { $modifiedText = $modifiedNode.InnerText }
    $modified = $null
    try { $modified = [datetime]::Parse($modifiedText) } catch { $modified = [datetime]::MinValue }

    $refNodes = $entryNode.SelectNodes('.//c:reference', $ns)
    foreach ($ref in $refNodes) {
      $href = $ref.Attributes['href']
      if ($href -and $href.Value -match '\.zip$' -and $href.Value -match $ReferenceRegex) {
        $candidates.Add([pscustomobject]@{
          Title       = $titleText
          ModifiedUtc = $modified.ToUniversalTime()
          Url         = $href.Value
        })
      }
    }
  }

  if ($candidates.Count -eq 0) {
    throw "No NIST checklist entries matched title '$TitleRegex' and reference '$ReferenceRegex'."
  }

  return ($candidates | Sort-Object -Property ModifiedUtc -Descending | Select-Object -First 1)
}

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

function New-SettingRow {
  param(
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$TemplatePackage,
    [Parameter(Mandatory)][string]$TemplateGpo,
    [Parameter(Mandatory)][string]$Scope,
    [Parameter(Mandatory)][string]$Extension,
    [Parameter(Mandatory)][string]$Category,
    [Parameter(Mandatory)][string]$Setting,
    [Parameter()][string]$Value,
    [Parameter()][string]$Type
  )

  $normalizedValue = if ($null -eq $Value) { '' } else { ([string]$Value).Trim() }
  [pscustomobject]@{
    Source          = $Source
    TemplatePackage = $TemplatePackage
    TemplateGpo     = $TemplateGpo
    Scope           = $Scope
    Extension       = $Extension
    Category        = $Category
    Setting         = $Setting
    Value           = $normalizedValue
    Type            = $Type
    Key             = '{0}|{1}|{2}|{3}' -f $Scope,$Extension,$Category,$Setting
  }
}

function Add-SettingRows {
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
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Source,[Parameter(Mandatory)][string]$TemplatePackage,[Parameter(Mandatory)][string]$TemplateGpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($p in (Get-XPathNodes -Xml $Xml -XPath "//*[local-name()='Policy']")) {
    $display = $p.displayName
    if (-not $display) { $display = $p.name }
    if (-not $display) { continue }

    $state = $p.state
    if (-not $state) { $state = $p.Enabled }
    if (-not $state) { $state = $p.Disable }
    if (-not $state) { $state = Get-FirstText -Node $p -XPath ".//*[local-name()='State']" }
    if (-not $state) { $state = Get-FirstText -Node $p -XPath ".//*[local-name()='Value']" }
    $value = Get-FirstText -Node $p -XPath ".//*[local-name()='Value']"
    if (-not $value) { $value = [string]$state }

    $rows.Add((New-SettingRow -Source $Source -TemplatePackage $TemplatePackage -TemplateGpo $TemplateGpo -Scope (Get-ScopeFromNode $p) -Extension 'AdminTemplates' -Category 'Policies' -Setting ([string]$display) -Value ([string]$value) -Type 'Policy'))
  }
  return $rows
}

function Get-AdminTemplateRegistryRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Source,[Parameter(Mandatory)][string]$TemplatePackage,[Parameter(Mandatory)][string]$TemplateGpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($r in (Get-XPathNodes -Xml $Xml -XPath "//*[local-name()='RegistrySettings']/*[local-name()='Registry']")) {
    $props = $r.SelectSingleNode(".//*[local-name()='Properties']")
    $key = $r.key
    if (-not $key -and $props) { $key = $props.key }
    $name = $r.valueName
    if (-not $name -and $props) { $name = $props.valueName }
    if (-not $key) { continue }

    $val = $null
    $type = $null
    if ($props) {
      $val = $props.value
      $type = $props.type
    }
    $setting = (($key, $name) -join '\').TrimEnd('\')
    $rows.Add((New-SettingRow -Source $Source -TemplatePackage $TemplatePackage -TemplateGpo $TemplateGpo -Scope (Get-ScopeFromNode $r) -Extension 'AdminTemplates' -Category 'Registry' -Setting $setting -Value ([string]$val) -Type ([string]$type)))
  }
  return $rows
}

function Get-GppRegistryRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Source,[Parameter(Mandatory)][string]$TemplatePackage,[Parameter(Mandatory)][string]$TemplateGpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($it in (Get-XPathNodes -Xml $Xml -XPath "//*[local-name()='RegistrySettings']/*[local-name()='Registry']/*[local-name()='Properties']")) {
    $key = $it.key
    $name = $it.valueName
    if (-not $key) { continue }
    $val = $it.value
    $type = $it.type
    $action = $it.action
    $cat = if ($action) { "GPP (Action:$action)" } else { 'GPP' }
    $setting = (($key, $name) -join '\').TrimEnd('\')
    $rows.Add((New-SettingRow -Source $Source -TemplatePackage $TemplatePackage -TemplateGpo $TemplateGpo -Scope (Get-ScopeFromNode $it) -Extension 'GroupPolicyPreferences' -Category $cat -Setting $setting -Value ([string]$val) -Type ([string]$type)))
  }
  return $rows
}

function Get-AdvancedAuditPolicyRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Source,[Parameter(Mandatory)][string]$TemplatePackage,[Parameter(Mandatory)][string]$TemplateGpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($a in (Get-XPathNodes -Xml $Xml -XPath "//*[local-name()='AuditSetting']")) {
    $sub = Get-FirstText -Node $a -XPath ".//*[local-name()='SubcategoryName']"
    if (-not $sub) { $sub = Get-FirstText -Node $a -XPath ".//*[local-name()='Subcategory']" }
    if (-not $sub) { $sub = '(unknown subcategory)' }
    $inc = Get-FirstText -Node $a -XPath ".//*[local-name()='InclusionSetting']"
    $sv = Get-FirstText -Node $a -XPath ".//*[local-name()='SettingValue']"
    $val = if ($inc) { $inc } else { $sv }
    $setting = "Audit: $sub"
    $rows.Add((New-SettingRow -Source $Source -TemplatePackage $TemplatePackage -TemplateGpo $TemplateGpo -Scope (Get-ScopeFromNode $a) -Extension 'Security' -Category 'AdvancedAuditPolicy' -Setting $setting -Value ([string]$val) -Type 'AuditSetting'))
  }
  return $rows
}

function Get-GenericSecurityRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Source,[Parameter(Mandatory)][string]$TemplatePackage,[Parameter(Mandatory)][string]$TemplateGpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($s in (Get-XPathNodes -Xml $Xml -XPath "//*[local-name()='SecuritySettings']")) {
    foreach ($n in $s.SelectNodes(".//*[not(*)]")) {
      if ($null -ne $n.SelectSingleNode("ancestor::*[local-name()='AuditSetting']")) { continue }
      $name = $n.Name
      $val = $n.InnerText
      if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($val)) { continue }
      $rows.Add((New-SettingRow -Source $Source -TemplatePackage $TemplatePackage -TemplateGpo $TemplateGpo -Scope (Get-ScopeFromNode $n) -Extension 'Security' -Category 'SecuritySettings' -Setting ([string]$name) -Value ([string]$val.Trim()) -Type $null))
    }
  }
  return $rows
}

function Get-GpoRowsFromReportXml {
  param(
    [Parameter(Mandatory)][string]$XmlPath,
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$TemplatePackage
  )

  [xml]$xml = Get-Content -LiteralPath $XmlPath -Raw
  $gpoName = (Get-FirstText -Node $xml -XPath ".//*[local-name()='GPO']/*[local-name()='Name']")
  if (-not $gpoName) {
    $gpoName = [System.IO.Path]::GetFileNameWithoutExtension($XmlPath)
  }

  $rows = [System.Collections.Generic.List[object]]::new()
  Add-SettingRows -Target $rows -Items (Get-AdminTemplatePolicyRows -Xml $xml -Source $Source -TemplatePackage $TemplatePackage -TemplateGpo $gpoName)
  Add-SettingRows -Target $rows -Items (Get-AdminTemplateRegistryRows -Xml $xml -Source $Source -TemplatePackage $TemplatePackage -TemplateGpo $gpoName)
  Add-SettingRows -Target $rows -Items (Get-GppRegistryRows -Xml $xml -Source $Source -TemplatePackage $TemplatePackage -TemplateGpo $gpoName)
  Add-SettingRows -Target $rows -Items (Get-AdvancedAuditPolicyRows -Xml $xml -Source $Source -TemplatePackage $TemplatePackage -TemplateGpo $gpoName)
  Add-SettingRows -Target $rows -Items (Get-GenericSecurityRows -Xml $xml -Source $Source -TemplatePackage $TemplatePackage -TemplateGpo $gpoName)
  return $rows
}

function Get-TemplateRowsFromRoot {
  param(
    [Parameter(Mandatory)][string]$RootFolder,
    [Parameter(Mandatory)][string]$SourceName
  )

  if (-not (Test-Path -LiteralPath $RootFolder)) { return @() }
  $xmlFiles = @(
    Get-ChildItem -Path $RootFolder -Recurse -File -Filter 'gpreport.xml' -ErrorAction SilentlyContinue
  )
  $all = [System.Collections.Generic.List[object]]::new()
  foreach ($file in $xmlFiles) {
    $relative = $file.FullName.Substring($RootFolder.Length).TrimStart('\')
    $package = ($relative -split '\\')[0]
    if ([string]::IsNullOrWhiteSpace($package)) { $package = 'UnknownPackage' }
    $rows = Get-GpoRowsFromReportXml -XmlPath $file.FullName -Source $SourceName -TemplatePackage $package
    Add-SettingRows -Target $all -Items $rows
  }
  return @($all)
}

function Resolve-TemplateConflict {
  param(
    [Parameter(Mandatory)][string]$Key,
    [Parameter(Mandatory)][string]$MicrosoftValue,
    [Parameter(Mandatory)][string]$NistValue
  )
  $choices = [System.Management.Automation.Host.ChoiceDescription[]]@(
    (New-Object System.Management.Automation.Host.ChoiceDescription '&Microsoft', 'Use Microsoft template value'),
    (New-Object System.Management.Automation.Host.ChoiceDescription '&NIST', 'Use NIST template value'),
    (New-Object System.Management.Automation.Host.ChoiceDescription '&Skip', 'Exclude this setting from master template')
  )
  $caption = "Template conflict: $Key"
  $message = "Microsoft: $MicrosoftValue`nNIST: $NistValue"
  $selected = $host.UI.PromptForChoice($caption, $message, $choices, 0)
  switch ($selected) {
    0 { return 'Microsoft' }
    1 { return 'NIST' }
    default { return 'Skip' }
  }
}

function Select-RepresentativeRow {
  param([Parameter(Mandatory)][object[]]$Rows)
  if ($Rows.Count -eq 0) { return $null }
  $grouped = $Rows | Group-Object -Property Value | Sort-Object -Property Count -Descending
  $winnerValue = $grouped[0].Name
  return ($Rows | Where-Object { $_.Value -eq $winnerValue } | Select-Object -First 1)
}

function Merge-TemplateRows {
  param(
    [Parameter(Mandatory)][object[]]$MicrosoftRows,
    [Parameter(Mandatory)][object[]]$NistRows,
    [Parameter(Mandatory)][string]$Mode
  )

  $merged = [System.Collections.Generic.List[object]]::new()
  $conflicts = [System.Collections.Generic.List[object]]::new()

  $allRows = @($MicrosoftRows + $NistRows)
  $byKey = $allRows | Group-Object -Property Key

  foreach ($group in $byKey) {
    $key = $group.Name
    $msGroup = @($group.Group | Where-Object { $_.Source -eq 'Microsoft' })
    $nistGroup = @($group.Group | Where-Object { $_.Source -eq 'NIST' })

    $msRow = if ($msGroup.Count -gt 0) { Select-RepresentativeRow -Rows $msGroup } else { $null }
    $nistRow = if ($nistGroup.Count -gt 0) { Select-RepresentativeRow -Rows $nistGroup } else { $null }

    if ($null -eq $msRow -and $null -eq $nistRow) { continue }

    if ($null -eq $msRow) {
      $winner = $nistRow
      $winnerSource = 'NIST'
    } elseif ($null -eq $nistRow) {
      $winner = $msRow
      $winnerSource = 'Microsoft'
    } elseif ($msRow.Value -eq $nistRow.Value) {
      $winner = $msRow
      $winnerSource = 'Both'
    } else {
      $chosenSource = $null
      switch ($Mode) {
        'PreferMicrosoft' { $chosenSource = 'Microsoft' }
        'PreferNist'      { $chosenSource = 'NIST' }
        'Interactive'     { $chosenSource = Resolve-TemplateConflict -Key $key -MicrosoftValue $msRow.Value -NistValue $nistRow.Value }
      }

      if ($chosenSource -eq 'Skip') {
        $conflicts.Add([pscustomobject]@{
          Key            = $key
          MicrosoftValue = $msRow.Value
          NistValue      = $nistRow.Value
          Winner         = 'Skipped'
        })
        continue
      }

      if ($chosenSource -eq 'Microsoft') {
        $winner = $msRow
      } else {
        $winner = $nistRow
      }
      $winnerSource = $chosenSource

      $conflicts.Add([pscustomobject]@{
        Key            = $key
        MicrosoftValue = $msRow.Value
        NistValue      = $nistRow.Value
        Winner         = $winnerSource
      })
    }

    $merged.Add([pscustomobject]@{
      Key             = $winner.Key
      Scope           = $winner.Scope
      Extension       = $winner.Extension
      Category        = $winner.Category
      Setting         = $winner.Setting
      Value           = $winner.Value
      WinnerSource    = $winnerSource
      Source          = $winner.Source
      TemplatePackage = $winner.TemplatePackage
      TemplateGpo     = $winner.TemplateGpo
      Type            = $winner.Type
    })
  }

  return [pscustomobject]@{
    MasterRows = @($merged | Sort-Object -Property Key)
    Conflicts  = @($conflicts | Sort-Object -Property Key)
  }
}

function Get-DomainContainerInventory {
  $domain = Get-ADDomain
  $rootDn = $domain.DistinguishedName
  $rootCanonical = $domain.DNSRoot

  $nodes = [System.Collections.Generic.List[object]]::new()
  $nodes.Add([pscustomobject]@{
    DistinguishedName = $rootDn
    ParentDn          = $null
    Name              = $domain.DNSRoot
    CanonicalName     = $rootCanonical
    Type              = 'Domain'
    Links             = @()
  })

  $ous = Get-ADOrganizationalUnit -Filter * -SearchBase $rootDn -Properties CanonicalName,DistinguishedName,Name
  foreach ($ou in $ous) {
    $canonical = if ($ou.CanonicalName) { $ou.CanonicalName.TrimEnd('/') } else { $ou.Name }
    $nodes.Add([pscustomobject]@{
      DistinguishedName = $ou.DistinguishedName
      ParentDn          = Get-ParentDn -DistinguishedName $ou.DistinguishedName
      Name              = $ou.Name
      CanonicalName     = $canonical
      Type              = 'OU'
      Links             = @()
    })
  }

  foreach ($node in $nodes) {
    try {
      $inheritance = Get-GPInheritance -Target $node.DistinguishedName
      $links = @()
      foreach ($lnk in @($inheritance.GpoLinks)) {
        $id = $null
        if ($lnk.PSObject.Properties.Match('GpoId').Count -gt 0) { $id = $lnk.GpoId }
        if (-not $id -and $lnk.PSObject.Properties.Match('GPOId').Count -gt 0) { $id = $lnk.GPOId }
        $guidString = $null
        if ($id) {
          try { $guidString = ([guid]$id).Guid } catch { $guidString = [string]$id }
        }

        $links += [pscustomobject]@{
          GpoName  = $lnk.DisplayName
          GpoId    = $guidString
          Enabled  = $lnk.Enabled
          Enforced = $lnk.Enforced
          Order    = $lnk.Order
        }
      }
      $node.Links = @($links)
    } catch {
      Write-Warning "Failed to load links for '$($node.DistinguishedName)': $($_.Exception.Message)"
      $node.Links = @()
    }
  }

  return [pscustomobject]@{
    Domain = $domain
    Nodes  = @($nodes)
  }
}

function Export-DomainHierarchySnapshot {
  param(
    [Parameter(Mandatory)][object[]]$Nodes,
    [Parameter(Mandatory)][string]$OutputFolder
  )

  $treeFolder = Join-Path -Path $OutputFolder -ChildPath 'AD-Tree'
  $reportsFolder = Join-Path -Path $OutputFolder -ChildPath 'GPO-Reports'
  Ensure-Directory -Path $treeFolder
  Ensure-Directory -Path $reportsFolder

  $gpoReportMap = @{}

  $orderedNodes = $Nodes | Sort-Object @{ Expression = { ($_.CanonicalName -split '/').Count } }, CanonicalName
  foreach ($node in $orderedNodes) {
    $relative = $node.CanonicalName -replace '/', '\'
    if ([string]::IsNullOrWhiteSpace($relative)) {
      $relative = Get-SafeFileName -Name $node.Name
    }
    $safeRelative = ($relative -split '\\' | ForEach-Object { Get-SafeFileName -Name $_ }) -join '\'
    $nodeFolder = Join-Path -Path $treeFolder -ChildPath $safeRelative
    Ensure-Directory -Path $nodeFolder

    $linkRows = @($node.Links | Sort-Object -Property Order)
    $nodeData = [pscustomobject]@{
      DistinguishedName = $node.DistinguishedName
      ParentDn          = $node.ParentDn
      Name              = $node.Name
      CanonicalName     = $node.CanonicalName
      Type              = $node.Type
      LinkedGpos        = $linkRows
    }
    $nodeJsonPath = Join-Path -Path $nodeFolder -ChildPath '_node.json'
    $nodeData | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $nodeJsonPath -Encoding UTF8

    foreach ($link in $linkRows) {
      if ([string]::IsNullOrWhiteSpace($link.GpoId)) { continue }
      if ($gpoReportMap.ContainsKey($link.GpoId)) { continue }
      try {
        $reportPath = Join-Path -Path $reportsFolder -ChildPath ("{0}.xml" -f $link.GpoId)
        Get-GPOReport -Guid $link.GpoId -ReportType Xml -Path $reportPath
        $gpoReportMap[$link.GpoId] = $reportPath
      } catch {
        Write-Warning "Failed to export GPO report for '$($link.GpoName)' [$($link.GpoId)]: $($_.Exception.Message)"
      }
    }
  }

  $allLinks = foreach ($n in $Nodes) {
    foreach ($l in @($n.Links)) {
      [pscustomobject]@{
        ContainerDn   = $n.DistinguishedName
        ContainerPath = $n.CanonicalName
        GpoName       = $l.GpoName
        GpoId         = $l.GpoId
        Enabled       = $l.Enabled
        Enforced      = $l.Enforced
        Order         = $l.Order
      }
    }
  }
  $allLinks | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'All-GpoLinks.csv') -NoTypeInformation -Encoding UTF8

  return [pscustomobject]@{
    ReportMap = $gpoReportMap
    AllLinks  = @($allLinks)
  }
}

function Get-DescendantDns {
  param(
    [Parameter(Mandatory)][object[]]$Nodes,
    [Parameter(Mandatory)][string]$RootDn
  )
  $result = [System.Collections.Generic.List[string]]::new()
  $queue = New-Object System.Collections.Generic.Queue[string]
  $queue.Enqueue($RootDn)
  while ($queue.Count -gt 0) {
    $current = $queue.Dequeue()
    [void]$result.Add($current)
    $children = $Nodes | Where-Object { $_.ParentDn -eq $current } | Select-Object -ExpandProperty DistinguishedName
    foreach ($child in $children) {
      $queue.Enqueue($child)
    }
  }
  return @($result | Select-Object -Unique)
}

function Compare-MasterToGpoRows {
  param(
    [Parameter(Mandatory)][object[]]$MasterRows,
    [Parameter(Mandatory)][object[]]$DomainRows,
    [Parameter(Mandatory)][string]$ContainerDn,
    [Parameter(Mandatory)][string]$GpoName,
    [Parameter(Mandatory)][string]$GpoId
  )

  $diffs = [System.Collections.Generic.List[object]]::new()
  $masterMap = @{}
  foreach ($row in $MasterRows) { $masterMap[$row.Key] = $row }

  $domainMap = @{}
  foreach ($row in $DomainRows) {
    if (-not $domainMap.ContainsKey($row.Key)) {
      $domainMap[$row.Key] = $row
    }
  }

  foreach ($key in $masterMap.Keys) {
    $expected = $masterMap[$key]
    if (-not $domainMap.ContainsKey($key)) {
      $diffs.Add([pscustomobject]@{
        DiffId          = ([guid]::NewGuid()).Guid
        ContainerDn     = $ContainerDn
        GpoName         = $GpoName
        GpoId           = $GpoId
        Status          = 'MissingInDomain'
        Key             = $key
        Scope           = $expected.Scope
        Extension       = $expected.Extension
        Category        = $expected.Category
        Setting         = $expected.Setting
        ExpectedValue   = $expected.Value
        CurrentValue    = '<missing>'
        WinnerSource    = $expected.WinnerSource
        TemplatePackage = $expected.TemplatePackage
        TemplateGpo     = $expected.TemplateGpo
      })
      continue
    }

    $actual = $domainMap[$key]
    if ($actual.Value -ne $expected.Value) {
      $diffs.Add([pscustomobject]@{
        DiffId          = ([guid]::NewGuid()).Guid
        ContainerDn     = $ContainerDn
        GpoName         = $GpoName
        GpoId           = $GpoId
        Status          = 'DifferentValue'
        Key             = $key
        Scope           = $expected.Scope
        Extension       = $expected.Extension
        Category        = $expected.Category
        Setting         = $expected.Setting
        ExpectedValue   = $expected.Value
        CurrentValue    = $actual.Value
        WinnerSource    = $expected.WinnerSource
        TemplatePackage = $expected.TemplatePackage
        TemplateGpo     = $expected.TemplateGpo
      })
    }
  }

  foreach ($key in $domainMap.Keys) {
    if ($masterMap.ContainsKey($key)) { continue }
    $actual = $domainMap[$key]
    $diffs.Add([pscustomobject]@{
      DiffId          = ([guid]::NewGuid()).Guid
      ContainerDn     = $ContainerDn
      GpoName         = $GpoName
      GpoId           = $GpoId
      Status          = 'ExtraInDomain'
      Key             = $key
      Scope           = $actual.Scope
      Extension       = $actual.Extension
      Category        = $actual.Category
      Setting         = $actual.Setting
      ExpectedValue   = '<not in master>'
      CurrentValue    = $actual.Value
      WinnerSource    = ''
      TemplatePackage = ''
      TemplateGpo     = ''
    })
  }

  return @($diffs)
}

function Convert-DiffRowsToReviewRows {
  param([Parameter(Mandatory)][object[]]$DiffRows)
  foreach ($d in $DiffRows) {
    [pscustomobject]@{
      DiffId          = $d.DiffId
      ApplyChange     = 'Yes'
      RiskComment     = ''
      Status          = $d.Status
      ContainerDn     = $d.ContainerDn
      GpoName         = $d.GpoName
      GpoId           = $d.GpoId
      Key             = $d.Key
      ExpectedValue   = $d.ExpectedValue
      CurrentValue    = $d.CurrentValue
      WinnerSource    = $d.WinnerSource
      TemplatePackage = $d.TemplatePackage
      TemplateGpo     = $d.TemplateGpo
    }
  }
}

function Invoke-InteractiveRiskTriage {
  param([Parameter(Mandatory)][object[]]$ReviewRows)
  $applyAllRemaining = $false
  foreach ($row in $ReviewRows) {
    if ($applyAllRemaining) {
      $row.ApplyChange = 'Yes'
      continue
    }

    Write-Host ''
    Write-Host ("Diff {0} | {1} | {2}" -f $row.DiffId, $row.GpoName, $row.Key) -ForegroundColor Yellow
    Write-Host ("Expected: {0}" -f $row.ExpectedValue) -ForegroundColor Green
    Write-Host ("Current : {0}" -f $row.CurrentValue) -ForegroundColor Red
    $answer = Read-Host "Apply change? [Y]es / [N]o (accept risk) / [A]pply all remaining"
    switch -Regex ($answer) {
      '^(A|a)$' {
        $row.ApplyChange = 'Yes'
        $applyAllRemaining = $true
      }
      '^(N|n)$' {
        $row.ApplyChange = 'No'
        $comment = Read-Host "Enter required risk acceptance comment"
        while ([string]::IsNullOrWhiteSpace($comment)) {
          $comment = Read-Host "Risk comment is required when deselecting. Enter comment"
        }
        $row.RiskComment = $comment
      }
      default {
        $row.ApplyChange = 'Yes'
      }
    }
  }
  return $ReviewRows
}

function Export-GpoBackupBundle {
  param(
    [Parameter(Mandatory)][object[]]$LinkRows,
    [Parameter(Mandatory)][string]$BundleFolder
  )
  $backupFolder = Join-Path -Path $BundleFolder -ChildPath 'GpoBackups'
  Ensure-Directory -Path $backupFolder

  $backupByGpoId = @{}
  $byGpo = $LinkRows | Where-Object { $_.GpoId } | Group-Object -Property GpoId
  foreach ($grp in $byGpo) {
    $gpoId = $grp.Name
    try {
      $backup = Backup-GPO -Guid $gpoId -Path $backupFolder -Comment ("After-hours audit bundle export {0}" -f (Get-Date -Format s))
      if ($backup) {
        $backupByGpoId[$gpoId] = [pscustomobject]@{
          GpoId    = $gpoId
          BackupId = [string]$backup.Id
          GpoName  = [string]$backup.DisplayName
        }
      }
      Write-Host "Backed up GPO: $gpoId" -ForegroundColor Green
    } catch {
      Write-Warning "Backup-GPO failed for ${gpoId}: $($_.Exception.Message)"
    }
  }

  $planPath = Join-Path -Path $BundleFolder -ChildPath 'LinkPlan.csv'
  $planRows = foreach ($row in $LinkRows) {
    $backupId = $null
    if ($row.GpoId -and $backupByGpoId.ContainsKey($row.GpoId)) {
      $backupId = $backupByGpoId[$row.GpoId].BackupId
    }
    [pscustomobject]@{
      ContainerDn   = $row.ContainerDn
      ContainerPath = $row.ContainerPath
      GpoName       = $row.GpoName
      GpoId         = $row.GpoId
      BackupId      = $backupId
      Enabled       = $row.Enabled
      Enforced      = $row.Enforced
      Order         = $row.Order
    }
  }
  $planRows | Export-Csv -Path $planPath -NoTypeInformation -Encoding UTF8

  $helperScriptPath = Join-Path -Path $BundleFolder -ChildPath 'Import-Link-GpoBundle.ps1'
  @'
param(
  [Parameter(Mandatory=$true)]
  [string]$BackupFolder,

  [Parameter(Mandatory=$true)]
  [string]$LinkPlanCsv
)

Import-Module GroupPolicy -ErrorAction Stop
$plan = Import-Csv -LiteralPath $LinkPlanCsv

foreach ($row in $plan) {
  if ([string]::IsNullOrWhiteSpace($row.GpoName) -or [string]::IsNullOrWhiteSpace($row.ContainerDn)) { continue }
  if ([string]::IsNullOrWhiteSpace($row.BackupId)) {
    Write-Warning "Skipping $($row.GpoName): no BackupId in link plan."
    continue
  }
  try {
    Import-GPO -BackupId $row.BackupId -TargetName $row.GpoName -Path $BackupFolder -CreateIfNeeded -ErrorAction Stop | Out-Null
  } catch {
    Write-Warning "Import-GPO failed for $($row.GpoName): $($_.Exception.Message)"
    continue
  }
  try {
    $enforced = 'No'
    if ($row.Enforced -match '^(?i:true|yes|1)$') {
      $enforced = 'Yes'
    }
    $linkEnabled = 'Yes'
    if ($row.Enabled -match '^(?i:false|no|0)$') {
      $linkEnabled = 'No'
    }
    New-GPLink -Name $row.GpoName -Target $row.ContainerDn -Enforced $enforced -LinkEnabled $linkEnabled -ErrorAction SilentlyContinue | Out-Null
  } catch {
    Write-Warning "New-GPLink failed for $($row.GpoName) -> $($row.ContainerDn): $($_.Exception.Message)"
  }
}
'@ | Set-Content -LiteralPath $helperScriptPath -Encoding UTF8
}

Write-Stage "Validating prerequisites"
Ensure-ModuleAvailable -Name GroupPolicy
Ensure-ModuleAvailable -Name ActiveDirectory

if (-not $BypassAfterHoursGuard) {
  if (-not (Test-AfterHoursWindow -StartHour $StartHour24)) {
    throw "Guard blocked execution: current time is before $StartHour24`:00. Use -BypassAfterHoursGuard to override."
  }
}

if (-not $BypassWorkNetworkGuard) {
  $workCheck = Test-WorkNetworkDetected -DnsSuffixes $WorkDnsSuffixes -Ipv4Prefixes $WorkIpv4Prefixes
  if ($workCheck.IsWorkNetwork) {
    throw ("Guard blocked execution: work network indicators detected. DNS matches: {0}; IP matches: {1}. Use -BypassWorkNetworkGuard to override." -f ($workCheck.DnsMatches -join ', '), ($workCheck.IpMatches -join ', '))
  }
}

$templatesFolder = Join-Path -Path $OutputRoot -ChildPath 'Templates'
$downloadsFolder = Join-Path -Path $templatesFolder -ChildPath 'Downloads'
$expandedFolder = Join-Path -Path $templatesFolder -ChildPath 'Expanded'
$microsoftDownloadFolder = Join-Path -Path $downloadsFolder -ChildPath 'Microsoft'
$nistDownloadFolder = Join-Path -Path $downloadsFolder -ChildPath 'NIST'
$microsoftExpandedFolder = Join-Path -Path $expandedFolder -ChildPath 'Microsoft'
$nistExpandedFolder = Join-Path -Path $expandedFolder -ChildPath 'NIST'
$reportsFolder = Join-Path -Path $OutputRoot -ChildPath 'Reports'
$domainSnapshotFolder = Join-Path -Path $OutputRoot -ChildPath 'DomainSnapshot'
$diffFolder = Join-Path -Path $OutputRoot -ChildPath 'Diff'
$bundleFolder = Join-Path -Path $OutputRoot -ChildPath 'ExportBundle'

foreach ($path in @(
  $OutputRoot,
  $templatesFolder,
  $downloadsFolder,
  $expandedFolder,
  $microsoftDownloadFolder,
  $nistDownloadFolder,
  $microsoftExpandedFolder,
  $nistExpandedFolder,
  $reportsFolder,
  $domainSnapshotFolder,
  $diffFolder,
  $bundleFolder
)) {
  Ensure-Directory -Path $path
}

if (-not $SkipTemplateDownload) {
  Write-Stage "Syncing Microsoft templates"
  $msFiles = Get-MicrosoftSctFileList -PageUrl $MicrosoftDownloadPageUrl -FileNameRegex $MicrosoftFileNameRegex
  foreach ($file in $msFiles) {
    $safeName = Get-SafeFileName -Name $file.Name
    $zipPath = Join-Path -Path $microsoftDownloadFolder -ChildPath $safeName
    Invoke-DownloadIfNeeded -Url $file.Url -DestinationPath $zipPath | Out-Null
    $extractTarget = Join-Path -Path $microsoftExpandedFolder -ChildPath ([System.IO.Path]::GetFileNameWithoutExtension($safeName))
    Expand-ZipIfNeeded -ZipPath $zipPath -DestinationFolder $extractTarget
  }

  Write-Stage "Syncing NIST template"
  $feedZipPath = Join-Path -Path $nistDownloadFolder -ChildPath 'checklist-0.1-feed.xml.zip'
  $feedMetaMarkerPath = Join-Path -Path $nistDownloadFolder -ChildPath 'checklist-0.1-feed.meta.local'
  $remoteMetaText = Get-NistFeedLastModifiedText -MetaUrl $NistFeedMetaUrl
  $existingMetaText = if (Test-Path -LiteralPath $feedMetaMarkerPath) { (Get-Content -LiteralPath $feedMetaMarkerPath -Raw).Trim() } else { '' }
  if (-not (Test-Path -LiteralPath $feedZipPath) -or ($remoteMetaText -and $remoteMetaText -ne $existingMetaText)) {
    Invoke-WebRequest -Uri $NistFeedZipUrl -OutFile $feedZipPath -UseBasicParsing -ErrorAction Stop
    if ($remoteMetaText) {
      Set-Content -LiteralPath $feedMetaMarkerPath -Value $remoteMetaText -Encoding UTF8
    }
  } else {
    Write-Host "NIST feed is current: $feedZipPath" -ForegroundColor DarkGray
  }

  $nistSelection = Get-NistLatestGpoPackageUrl -FeedZipPath $feedZipPath -TitleRegex $NistTitleRegex -ReferenceRegex $NistReferenceRegex
  Write-Host ("NIST selected template: {0}" -f $nistSelection.Title) -ForegroundColor Yellow
  $nistZipName = Get-SafeFileName -Name ([System.IO.Path]::GetFileName($nistSelection.Url))
  $nistZipPath = Join-Path -Path $nistDownloadFolder -ChildPath $nistZipName
  Invoke-DownloadIfNeeded -Url $nistSelection.Url -DestinationPath $nistZipPath | Out-Null
  $nistExtractTarget = Join-Path -Path $nistExpandedFolder -ChildPath ([System.IO.Path]::GetFileNameWithoutExtension($nistZipName))
  Expand-ZipIfNeeded -ZipPath $nistZipPath -DestinationFolder $nistExtractTarget
} else {
  Write-Stage "Skipping template download by request"
}

Write-Stage "Parsing template settings from GPO report XML"
$microsoftTemplateRows = Get-TemplateRowsFromRoot -RootFolder $microsoftExpandedFolder -SourceName 'Microsoft'
$nistTemplateRows = Get-TemplateRowsFromRoot -RootFolder $nistExpandedFolder -SourceName 'NIST'

if ($microsoftTemplateRows.Count -eq 0) { throw "No Microsoft template rows were discovered in $microsoftExpandedFolder." }
if ($nistTemplateRows.Count -eq 0) { throw "No NIST template rows were discovered in $nistExpandedFolder." }

$microsoftTemplateRows | Export-Csv -Path (Join-Path -Path $reportsFolder -ChildPath 'Microsoft-Template-Rows.csv') -NoTypeInformation -Encoding UTF8
$nistTemplateRows | Export-Csv -Path (Join-Path -Path $reportsFolder -ChildPath 'NIST-Template-Rows.csv') -NoTypeInformation -Encoding UTF8

Write-Stage "Merging templates into master baseline"
$merge = Merge-TemplateRows -MicrosoftRows $microsoftTemplateRows -NistRows $nistTemplateRows -Mode $MergeMode
$masterRows = $merge.MasterRows
$conflictRows = $merge.Conflicts

$masterPath = Join-Path -Path $reportsFolder -ChildPath 'Master-Template.csv'
$conflictPath = Join-Path -Path $reportsFolder -ChildPath 'Template-Conflicts.csv'
$masterRows | Export-Csv -Path $masterPath -NoTypeInformation -Encoding UTF8
$conflictRows | Export-Csv -Path $conflictPath -NoTypeInformation -Encoding UTF8

Write-Host ("Master template settings: {0}" -f $masterRows.Count) -ForegroundColor Green
Write-Host ("Template conflicts handled: {0}" -f $conflictRows.Count) -ForegroundColor Green

Write-Stage "Collecting AD hierarchy and linked GPOs"
$inventory = Get-DomainContainerInventory
$nodes = $inventory.Nodes
$domain = $inventory.Domain

if (-not $TargetContainerDn) {
  $TargetContainerDn = $domain.DistinguishedName
}

$targetNode = $nodes | Where-Object { $_.DistinguishedName -eq $TargetContainerDn } | Select-Object -First 1
if (-not $targetNode) {
  throw "TargetContainerDn '$TargetContainerDn' was not found in domain hierarchy."
}

$snapshot = Export-DomainHierarchySnapshot -Nodes $nodes -OutputFolder $domainSnapshotFolder

Write-Stage "Selecting target container and descendants for comparison"
$targetDns = Get-DescendantDns -Nodes $nodes -RootDn $TargetContainerDn
$scopedLinks = @($snapshot.AllLinks | Where-Object { $targetDns -contains $_.ContainerDn })
if ($scopedLinks.Count -eq 0) {
  throw "No linked GPOs were found under target container '$TargetContainerDn'."
}

$uniqueScopedGpoIds = @($scopedLinks | Where-Object { $_.GpoId } | Select-Object -ExpandProperty GpoId -Unique)
Write-Host ("Scoped containers: {0}; Scoped GPOs: {1}" -f $targetDns.Count, $uniqueScopedGpoIds.Count) -ForegroundColor Green

Write-Stage "Comparing master template against scoped GPOs"
$diffRows = [System.Collections.Generic.List[object]]::new()
foreach ($gpoId in $uniqueScopedGpoIds) {
  if (-not $snapshot.ReportMap.ContainsKey($gpoId)) {
    Write-Warning "No report XML was exported for GPO id $gpoId; skipping."
    continue
  }
  $xmlPath = $snapshot.ReportMap[$gpoId]
  $domainRows = Get-GpoRowsFromReportXml -XmlPath $xmlPath -Source 'Domain' -TemplatePackage 'Domain'
  $gpoLinks = @($scopedLinks | Where-Object { $_.GpoId -eq $gpoId })
  $gpoName = ($gpoLinks | Select-Object -First 1).GpoName
  $containerDn = (($gpoLinks | Select-Object -ExpandProperty ContainerDn -Unique) -join ';')
  if ([string]::IsNullOrWhiteSpace($containerDn)) { $containerDn = $TargetContainerDn }
  $gpoDiffs = Compare-MasterToGpoRows -MasterRows $masterRows -DomainRows $domainRows -ContainerDn $containerDn -GpoName $gpoName -GpoId $gpoId
  foreach ($d in $gpoDiffs) { [void]$diffRows.Add($d) }
}

$diffCsvPath = Join-Path -Path $diffFolder -ChildPath 'Master-vs-Domain.diff.csv'
$diffJsonPath = Join-Path -Path $diffFolder -ChildPath 'Master-vs-Domain.diff.json'
$diffRows | Export-Csv -Path $diffCsvPath -NoTypeInformation -Encoding UTF8
$diffRows | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $diffJsonPath -Encoding UTF8

Write-Host ("Diff rows generated: {0}" -f $diffRows.Count) -ForegroundColor Green

Write-Stage "Building risk review sheet (deselect + comment support)"
$reviewRows = @(
  Convert-DiffRowsToReviewRows -DiffRows $diffRows
)
$reviewCsvPath = Join-Path -Path $diffFolder -ChildPath 'Risk-Review.csv'

if ($RiskReviewCsvPath -and (Test-Path -LiteralPath $RiskReviewCsvPath)) {
  Write-Host "Using provided risk review file: $RiskReviewCsvPath" -ForegroundColor Yellow
  $reviewRows = @(Import-Csv -LiteralPath $RiskReviewCsvPath)
} elseif ($InteractiveRiskReview) {
  $reviewRows = Invoke-InteractiveRiskTriage -ReviewRows $reviewRows
}

$reviewRows | Export-Csv -Path $reviewCsvPath -NoTypeInformation -Encoding UTF8

$acceptedRisk = @($reviewRows | Where-Object { $_.ApplyChange -match '^(No|N|False|0)$' })
$approvedChanges = @($reviewRows | Where-Object { $_.ApplyChange -notmatch '^(No|N|False|0)$' })
$acceptedRiskPath = Join-Path -Path $diffFolder -ChildPath 'Accepted-Risk.csv'
$approvedPath = Join-Path -Path $diffFolder -ChildPath 'Approved-Changes.csv'
$acceptedRisk | Export-Csv -Path $acceptedRiskPath -NoTypeInformation -Encoding UTF8
$approvedChanges | Export-Csv -Path $approvedPath -NoTypeInformation -Encoding UTF8

Write-Host ("Approved changes: {0}" -f $approvedChanges.Count) -ForegroundColor Green
Write-Host ("Accepted risks : {0}" -f $acceptedRisk.Count) -ForegroundColor Green

Write-Stage "Exporting GPO backup bundle and link plan"
Export-GpoBackupBundle -LinkRows $scopedLinks -BundleFolder $bundleFolder

$summary = [pscustomobject]@{
  OutputRoot               = $OutputRoot
  MasterTemplateCsv        = $masterPath
  ConflictCsv              = $conflictPath
  DomainSnapshotFolder     = $domainSnapshotFolder
  DiffCsv                  = $diffCsvPath
  RiskReviewCsv            = $reviewCsvPath
  AcceptedRiskCsv          = $acceptedRiskPath
  ApprovedChangesCsv       = $approvedPath
  ExportBundleFolder       = $bundleFolder
  ScopedContainerDn        = $TargetContainerDn
  ScopedContainerCount     = $targetDns.Count
  ScopedLinkedGpoCount     = $uniqueScopedGpoIds.Count
  TotalDiffRows            = $diffRows.Count
}
$summaryPath = Join-Path -Path $OutputRoot -ChildPath 'Run-Summary.json'
$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $summaryPath -Encoding UTF8

Write-Stage "Completed after-hours GPO policy audit workflow"
Write-Host "Summary: $summaryPath" -ForegroundColor Cyan
