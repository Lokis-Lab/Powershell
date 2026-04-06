# Shared Active Directory + GPO context helpers (dot-sourced by GPO-Audit-Master.ps1 and GPO-Policy-Audit.ps1)

if (-not (Get-Variable -Name GpoAuditDomainDns -Scope Script -ErrorAction SilentlyContinue)) { $script:GpoAuditDomainDns = $null }
if (-not (Get-Variable -Name GpoAuditAdServer -Scope Script -ErrorAction SilentlyContinue)) { $script:GpoAuditAdServer = $null }

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

function Ensure-GpoAuditAdContextInitialized {
  if ([string]::IsNullOrWhiteSpace($script:GpoAuditAdServer)) {
    Initialize-GpoAuditAdContext -DomainDnsName $null
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

function Get-AdFriendlyOuPathLabel {
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
