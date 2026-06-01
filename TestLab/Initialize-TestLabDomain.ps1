<#
.SYNOPSIS
  Seeds a script-testing Active Directory lab with OUs, users, computers, and GPOs.

.DESCRIPTION
  Creates an intentional mix of NIST-aligned and deliberately weak Group Policy and
  account settings so repo scripts (GPO-Audit-Master, Get-ADPasswordExpiryReport,
  Invoke-AfterHoursGpoPolicyAudit, etc.) have realistic targets.

  Run from a domain-joined Windows host with RSAT (GroupPolicy + ActiveDirectory)
  and Domain Admin rights. Idempotent: skips objects that already exist.

.PARAMETER DomainDnsName
  DNS name of the lab domain (default from lab-manifest.json).

.PARAMETER ManifestPath
  Path to lab-manifest.json.

.PARAMETER DefaultUserPassword
  Initial password for lab users (change after first login in production-like labs).

.PARAMETER SkipGpos
  Create OUs and accounts only; do not create or update GPOs.

.PARAMETER SkipComputers
  Do not create computer accounts.

.PARAMETER WhatIf
  Show planned changes without applying them.

.EXAMPLE
  .\Initialize-TestLabDomain.ps1

.EXAMPLE
  .\Initialize-TestLabDomain.ps1 -DomainDnsName contoso.com -WhatIf

.NOTES
  Lab-only. Default password and weak GPO settings must not be used in production.
  Requires: GroupPolicy, ActiveDirectory modules (RSAT).
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [string]$DomainDnsName,
  [string]$ManifestPath = (Join-Path $PSScriptRoot 'config\lab-manifest.json'),
  [string]$DefaultUserPassword = 'P@ssw0rd!Lab2026',
  [switch]$SkipGpos,
  [switch]$SkipComputers
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-LabStage {
  param([Parameter(Mandatory)][string]$Message)
  Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Message) -ForegroundColor Cyan
}

function Ensure-ModuleLoaded {
  param([Parameter(Mandatory)][string]$Name)
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    throw "Required module '$Name' is not installed. Install RSAT / Group Policy tools."
  }
  Import-Module $Name -ErrorAction Stop
}

function Get-LabManifest {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    throw "Manifest not found: $Path"
  }
  return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Get-DomainDnFromDns {
  param([Parameter(Mandatory)][string]$Dns)
  return ($Dns.Split('.') | ForEach-Object { "DC=$_" }) -join ','
}

function Get-ExistingOu {
  param([Parameter(Mandatory)][string]$DistinguishedName)
  return Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$DistinguishedName'" -ErrorAction SilentlyContinue
}

function New-LabOuTree {
  param(
    [Parameter(Mandatory)][string]$DomainDn,
    [Parameter(Mandatory)][array]$OuNodes,
    [string]$ParentDn
  )

  foreach ($node in $OuNodes) {
    $parent = if ($ParentDn) { $ParentDn } else { $DomainDn }
    $ouDn = "OU=$($node.name),$parent"

    if (-not (Get-ExistingOu -DistinguishedName $ouDn)) {
      if ($PSCmdlet.ShouldProcess($ouDn, 'New-ADOrganizationalUnit')) {
        New-ADOrganizationalUnit -Name $node.name -Path $parent -ProtectedFromAccidentalDeletion $false | Out-Null
        Write-LabStage "Created OU: $ouDn"
      }
    } else {
      Write-Host "OU exists: $ouDn" -ForegroundColor DarkGray
    }

    if ($node.children) {
      New-LabOuTree -DomainDn $DomainDn -OuNodes $node.children -ParentDn $ouDn
    }
  }
}

function Get-LabOuDn {
  param(
    [Parameter(Mandatory)][string]$DomainDn,
    [Parameter(Mandatory)][string]$OuPath
  )
  $parts = $OuPath.Split('/') | Where-Object { $_ }
  $dn = $DomainDn
  foreach ($p in $parts) {
    $dn = "OU=$p,$dn"
  }
  return $dn
}

function New-LabUserIfMissing {
  param(
    [Parameter(Mandatory)][string]$SamAccountName,
    [Parameter(Mandatory)][string]$OuDn,
    [string]$DisplayName,
    [bool]$Enabled = $true,
    [bool]$PasswordNeverExpires = $false
  )

  $existing = Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue
  if ($existing) {
    Write-Host "User exists: $SamAccountName" -ForegroundColor DarkGray
    return $existing
  }

  $secPassword = ConvertTo-SecureString $DefaultUserPassword -AsPlainText -Force
  $params = @{
    SamAccountName          = $SamAccountName
    UserPrincipalName       = "$SamAccountName@$script:LabDomainDns"
    Name                    = if ($DisplayName) { $DisplayName } else { $SamAccountName }
    DisplayName             = if ($DisplayName) { $DisplayName } else { $SamAccountName }
    AccountPassword         = $secPassword
    Enabled                 = $Enabled
    Path                    = $OuDn
    ChangePasswordAtLogon   = $false
    PasswordNeverExpires    = $PasswordNeverExpires
  }

  if ($PSCmdlet.ShouldProcess($SamAccountName, 'New-ADUser')) {
    $user = New-ADUser @params
    Write-LabStage "Created user: $SamAccountName (PasswordNeverExpires=$PasswordNeverExpires)"
    return $user
  }
}

function New-LabComputerIfMissing {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$OuDn
  )

  $existing = Get-ADComputer -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue
  if ($existing) {
    Write-Host "Computer exists: $Name" -ForegroundColor DarkGray
    return
  }

  if ($PSCmdlet.ShouldProcess($Name, 'New-ADComputer')) {
    New-ADComputer -Name $Name -SamAccountName $Name -Path $OuDn -Enabled $true | Out-Null
    Write-LabStage "Created computer: $Name"
  }
}

function Get-GpoSysvolSecEditPath {
  param(
    [Parameter(Mandatory)][guid]$GpoId,
    [Parameter(Mandatory)][string]$DomainDns
  )
  return "\\$DomainDns\SYSVOL\$DomainDns\Policies\{$GpoId}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
}

function Set-LabGpoSecurityTemplate {
  param(
    [Parameter(Mandatory)][string]$GpoName,
    [Parameter(Mandatory)][string]$TemplatePath,
    [Parameter(Mandatory)][string]$DomainDns
  )

  $gpo = Get-GPO -Name $GpoName -ErrorAction Stop
  $dest = Get-GpoSysvolSecEditPath -GpoId $gpo.Id -DomainDns $DomainDns
  $destDir = Split-Path -Parent $dest

  if ($PSCmdlet.ShouldProcess($dest, 'Copy GptTmpl.inf security template')) {
    if (-not (Test-Path -LiteralPath $destDir)) {
      New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }
    Copy-Item -LiteralPath $TemplatePath -Destination $dest -Force
    Write-LabStage "Applied security template to GPO '$GpoName' -> $dest"
  }
}

function Set-LabGpoRegistryValues {
  param(
    [Parameter(Mandatory)][string]$GpoName,
    [Parameter(Mandatory)][hashtable[]]$Values
  )

  foreach ($entry in $Values) {
    $target = "${GpoName}: $($entry.Key)\$($entry.ValueName)"
    if ($PSCmdlet.ShouldProcess($target, 'Set-GPRegistryValue')) {
      Set-GPRegistryValue -Name $GpoName -Key $entry.Key -ValueName $entry.ValueName -Type $entry.Type -Value $entry.Value | Out-Null
    }
  }
}

function Ensure-LabGpo {
  param(
    [Parameter(Mandatory)][string]$Name,
    [string]$Description = 'Script test lab GPO — lab use only'
  )

  $existing = Get-GPO -Name $Name -ErrorAction SilentlyContinue
  if ($existing) {
    Write-Host "GPO exists: $Name" -ForegroundColor DarkGray
    return $existing
  }

  if ($PSCmdlet.ShouldProcess($Name, 'New-GPO')) {
    $gpo = New-GPO -Name $Name -Comment $Description
    Write-LabStage "Created GPO: $Name"
    return $gpo
  }
}

function Set-LabGpoLink {
  param(
    [Parameter(Mandatory)][string]$GpoName,
    [Parameter(Mandatory)][string]$TargetDn,
    [int]$Order = 1,
    [bool]$Enforced = $false
  )

  $already = Get-GPInheritance -Target $TargetDn -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty GpoLinks |
    Where-Object { $_.DisplayName -eq $GpoName }

  if ($already) {
    Write-Host "GPO already linked: $GpoName -> $TargetDn" -ForegroundColor DarkGray
    return
  }

  if ($PSCmdlet.ShouldProcess("$GpoName -> $TargetDn", 'New-GPLink')) {
    New-GPLink -Name $GpoName -Target $TargetDn -LinkEnabled Yes -Enforced $(if ($Enforced) { 'Yes' } else { 'No' }) -Order $Order | Out-Null
    Write-LabStage "Linked GPO '$GpoName' to $TargetDn (order $Order)"
  }
}

function Initialize-LabGroupPolicy {
  param(
    [Parameter(Mandatory)][string]$DomainDns,
    [Parameter(Mandatory)][string]$DomainDn,
    [Parameter(Mandatory)]$Manifest
  )

  $templateRoot = Join-Path $PSScriptRoot 'gpo-templates'

  # --- Compliant-ish workstation baseline (contrast for audits)
  Ensure-LabGpo -Name 'LAB - Baseline Compliant Workstations' -Description 'Reasonable baseline for diff testing' | Out-Null
  Set-LabGpoRegistryValues -GpoName 'LAB - Baseline Compliant Workstations' -Values @(
    @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName = 'EnableLUA'; Type = 'DWord'; Value = 1 }
    @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; ValueName = 'RequireSecuritySignature'; Type = 'DWord'; Value = 1 }
    @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; ValueName = 'LmCompatibilityLevel'; Type = 'DWord'; Value = 5 }
  )
  Set-LabGpoLink -GpoName 'LAB - Baseline Compliant Workstations' -TargetDn "OU=Workstations,$DomainDn" -Order 2

  # --- Deliberately weak workstation GPO (NIST gaps)
  Ensure-LabGpo -Name 'LAB - SEC Insecure Workstations' -Description 'Intentionally weak — do not use in production' | Out-Null
  $insecureWsTemplate = Join-Path $templateRoot 'LAB-SEC-Insecure-Workstations-GptTmpl.inf'
  if (Test-Path -LiteralPath $insecureWsTemplate) {
    Set-LabGpoSecurityTemplate -GpoName 'LAB - SEC Insecure Workstations' -TemplatePath $insecureWsTemplate -DomainDns $DomainDns
  }
  Set-LabGpoRegistryValues -GpoName 'LAB - SEC Insecure Workstations' -Values @(
    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; ValueName = 'EnableFirewall'; Type = 'DWord'; Value = 0 }
    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; ValueName = 'EnableFirewall'; Type = 'DWord'; Value = 0 }
    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; ValueName = 'EnableFirewall'; Type = 'DWord'; Value = 0 }
    @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; ValueName = 'NoDriveTypeAutoRun'; Type = 'DWord'; Value = 0 }
  )
  Set-LabGpoLink -GpoName 'LAB - SEC Insecure Workstations' -TargetDn "OU=Workstations,$DomainDn" -Order 1

  # --- Legacy OU weak GPO
  Ensure-LabGpo -Name 'LAB - SEC Insecure Legacy' -Description 'Legacy OU — weak authentication posture' | Out-Null
  $legacyTemplate = Join-Path $templateRoot 'LAB-SEC-Insecure-Legacy-GptTmpl.inf'
  if (Test-Path -LiteralPath $legacyTemplate) {
    Set-LabGpoSecurityTemplate -GpoName 'LAB - SEC Insecure Legacy' -TemplatePath $legacyTemplate -DomainDns $DomainDns
  }
  $legacyOu = "OU=Legacy,OU=Users,$DomainDn"
  Set-LabGpoLink -GpoName 'LAB - SEC Insecure Legacy' -TargetDn $legacyOu -Order 1

  # --- Hardened servers (aligned)
  Ensure-LabGpo -Name 'LAB - Servers Hardened' -Description 'Server hardening baseline for comparison' | Out-Null
  Set-LabGpoRegistryValues -GpoName 'LAB - Servers Hardened' -Values @(
    @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; ValueName = 'RequireSecuritySignature'; Type = 'DWord'; Value = 1 }
    @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; ValueName = 'RequireSecuritySignature'; Type = 'DWord'; Value = 1 }
    @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; ValueName = 'LmCompatibilityLevel'; Type = 'DWord'; Value = 5 }
  )
  Set-LabGpoLink -GpoName 'LAB - Servers Hardened' -TargetDn "OU=Servers,$DomainDn" -Order 1

  # --- Unlinked GPO for regex/name filter testing (CIS|STIG style names)
  Ensure-LabGpo -Name 'CIS - Dummy Baseline Name' -Description 'Unlinked — for IncludeGpoNameRegex testing only' | Out-Null
}

# --- Main ---
Ensure-ModuleLoaded -Name ActiveDirectory
Ensure-ModuleLoaded -Name GroupPolicy

$manifest = Get-LabManifest -Path $ManifestPath
$script:LabDomainDns = if ($DomainDnsName) { $DomainDnsName } else { $manifest.domain.dnsName }

$domain = Get-ADDomain -Server $script:LabDomainDns -ErrorAction Stop
$domainDn = $domain.DistinguishedName

Write-LabStage "Lab domain: $($domain.DNSRoot) ($domainDn)"

if ($PSCmdlet.ShouldProcess($domainDn, 'Create OU structure')) {
  New-LabOuTree -DomainDn $domainDn -OuNodes $manifest.organizationalUnits
}

foreach ($userDef in $manifest.users) {
  $ouPath = switch ($userDef.ou) {
    'IT' { "OU=IT,OU=Users,$domainDn" }
    'Sales' { "OU=Sales,OU=Users,$domainDn" }
    'Finance' { "OU=Finance,OU=Users,$domainDn" }
    'Legacy' { "OU=Legacy,OU=Users,$domainDn" }
    default { "OU=Users,$domainDn" }
  }

  $enabled = if ($null -ne $userDef.enabled) { [bool]$userDef.enabled } else { $true }
  $pne = if ($null -ne $userDef.passwordNeverExpires) { [bool]$userDef.passwordNeverExpires } else { $false }

  New-LabUserIfMissing -SamAccountName $userDef.samAccountName -OuDn $ouPath -Enabled $enabled -PasswordNeverExpires $pne
}

if (-not $SkipComputers) {
  foreach ($comp in $manifest.computers) {
    $ouDn = switch ($comp.ou) {
      'Workstations' { "OU=Workstations,$domainDn" }
      'Servers' { "OU=Servers,$domainDn" }
      default { "OU=Workstations,$domainDn" }
    }
    New-LabComputerIfMissing -Name $comp.name -OuDn $ouDn
  }
}

if (-not $SkipGpos) {
  Initialize-LabGroupPolicy -DomainDns $script:LabDomainDns -DomainDn $domainDn -Manifest $manifest
}

Write-LabStage 'Lab seed complete.'
Write-Host ''
Write-Host 'Next steps:' -ForegroundColor Green
Write-Host "  1. Point scripts at -DomainDnsName $($domain.DNSRoot)"
Write-Host '  2. Run GPO-Audit-Master.ps1 -Mode SearchSettings -SearchText "LmCompatibility"'
Write-Host '  3. Run Get-ADPasswordExpiryReport.ps1 and review PasswordNeverExpires users'
Write-Host ''
Write-Host 'Default lab user password is in -DefaultUserPassword / lab-manifest.json (lab only).' -ForegroundColor Yellow
