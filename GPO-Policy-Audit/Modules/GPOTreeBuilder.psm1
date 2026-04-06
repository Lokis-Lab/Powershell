<#
.SYNOPSIS
  Pulls GPOs from the domain, resolves their OU links, and organises
  them into an AD-like hierarchy so you can see parent/child GPO
  relationships as they appear in Group Policy Management.

.DESCRIPTION
  Uses the GroupPolicy and ActiveDirectory PowerShell modules to:
    1. Enumerate all GPOs (or a filtered subset).
    2. Enumerate all OUs and their GPO links (link order, enforced, etc.).
    3. Build a tree of OU → linked GPOs, preserving parent/child OU nesting.
    4. Identify "children" GPOs: GPOs linked to child OUs that inherit or
       are scoped beneath a parent GPO.
    5. Optionally export each GPO's XML report for downstream parsing.

  Requires: RSAT Group Policy + Active Directory modules.
#>

#requires -Version 5.1

#region ── Domain bootstrap ────────────────────────────────────────────

function Initialize-DomainContext {
    <#
    .SYNOPSIS  Resolve the target domain DNS name and a preferred DC.
    #>
    [CmdletBinding()]
    param([string]$DomainDnsName)

    try { Import-Module ActiveDirectory -ErrorAction Stop } catch {
        throw "ActiveDirectory module is required. Install RSAT AD DS tools."
    }
    try { Import-Module GroupPolicy -ErrorAction Stop } catch {
        throw "GroupPolicy module is required. Install RSAT Group Policy Management."
    }

    if ([string]::IsNullOrWhiteSpace($DomainDnsName)) {
        $dom = Get-ADDomain -ErrorAction Stop
    } else {
        $dom = Get-ADDomain -Identity $DomainDnsName.Trim() -Server $DomainDnsName.Trim() -ErrorAction Stop
    }

    $dc = $dom.PDCEmulator
    if ([string]::IsNullOrWhiteSpace($dc)) { $dc = $dom.DNSRoot }

    return [PSCustomObject]@{
        DnsRoot = $dom.DNSRoot
        DC      = $dc
        DomainDN = $dom.DistinguishedName
    }
}

#endregion

#region ── GPO enumeration ─────────────────────────────────────────────

function Get-AllDomainGPOs {
    <#
    .SYNOPSIS  Return every GPO in the domain as a lightweight object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DomainDns,
        [string[]]$NameFilter,
        [string]$NameRegex
    )

    $splat = @{ All = $true; Domain = $DomainDns }
    $all = Get-GPO @splat | ForEach-Object {
        [PSCustomObject]@{
            DisplayName   = $_.DisplayName
            Id            = $_.Id.Guid
            GpoStatus     = $_.GpoStatus
            CreationTime  = $_.CreationTime
            ModificationTime = $_.ModificationTime
            Description   = $_.Description
            WmiFilter     = if ($_.WmiFilter) { $_.WmiFilter.Name } else { '' }
        }
    }

    if ($NameFilter -and $NameFilter.Count -gt 0) {
        $all = $all | Where-Object { $NameFilter -contains $_.DisplayName }
    }
    if ($NameRegex) {
        $all = $all | Where-Object { $_.DisplayName -match $NameRegex }
    }

    return $all
}

#endregion

#region ── OU tree with GPO links ──────────────────────────────────────

function Get-OUTreeWithLinks {
    <#
    .SYNOPSIS
      Build a tree of OUs, each annotated with linked GPOs, preserving
      the AD parent/child nesting.
    .PARAMETER DomainDN
      Distinguished name of the domain root (e.g., DC=contoso,DC=com).
    .PARAMETER DC
      Domain controller to query.
    .OUTPUTS
      Flat list of OU objects, each with: OU, ParentOU, CanonicalName,
      DistinguishedName, LinkedGPOs (array of GPO link detail objects),
      Depth (nesting level).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DomainDN,
        [Parameter(Mandatory)][string]$DC
    )

    $ous = Get-ADOrganizationalUnit -Filter * -Server $DC -Properties CanonicalName, LinkedGroupPolicyObjects, gpLink |
        Sort-Object CanonicalName

    $domainLinks = Get-ADObject -Identity $DomainDN -Server $DC -Properties gpLink

    $tree = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Domain root as the top node
    $rootLinks = Resolve-GpLinks -GpLinkValue $domainLinks.gpLink -DC $DC
    $tree.Add([PSCustomObject]@{
        Name              = '(Domain Root)'
        DistinguishedName = $DomainDN
        CanonicalName     = ''
        ParentDN          = ''
        Depth             = 0
        LinkedGPOs        = $rootLinks
    })

    foreach ($ou in $ous) {
        $parentDN = ($ou.DistinguishedName -replace '^OU=[^,]+,', '')
        $depth    = ($ou.DistinguishedName.Split(',') | Where-Object { $_ -match '^OU=' }).Count

        $links = Resolve-GpLinks -GpLinkValue $ou.gpLink -DC $DC

        $tree.Add([PSCustomObject]@{
            Name              = $ou.Name
            DistinguishedName = $ou.DistinguishedName
            CanonicalName     = $ou.CanonicalName
            ParentDN          = $parentDN
            Depth             = $depth
            LinkedGPOs        = $links
        })
    }

    return $tree
}

function Resolve-GpLinks {
    <#
    .SYNOPSIS  Parse the gpLink attribute string into structured objects.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$GpLinkValue,
        [string]$DC
    )

    if ([string]::IsNullOrWhiteSpace($GpLinkValue)) { return @() }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # gpLink format: [LDAP://cn={GUID},cn=policies,cn=system,DC=...;linkOptions]
    $pattern = '\[LDAP://[Cc][Nn]=\{([0-9a-fA-F\-]+)\}[^;]*;(\d+)\]'
    $matches = [regex]::Matches($GpLinkValue, $pattern)

    $order = 1
    foreach ($m in $matches) {
        $guid   = $m.Groups[1].Value
        $opts   = [int]$m.Groups[2].Value
        $enabled  = ($opts -band 1) -eq 0   # bit 0 = disabled
        $enforced = ($opts -band 2) -ne 0   # bit 1 = enforced

        $gpoName = ''
        try {
            $gpo = Get-GPO -Guid $guid -Domain ($DC -replace ':.*') -ErrorAction SilentlyContinue
            if ($gpo) { $gpoName = $gpo.DisplayName }
        } catch { }

        $results.Add([PSCustomObject]@{
            GpoGuid   = $guid
            GpoName   = $gpoName
            LinkOrder = $order
            Enabled   = $enabled
            Enforced  = $enforced
        })
        $order++
    }

    return $results
}

#endregion

#region ── Build hierarchical GPO view ─────────────────────────────────

function Build-GPOHierarchy {
    <#
    .SYNOPSIS
      Returns a hierarchy of GPOs grouped by OU, showing parent/child
      relationships as they appear in AD.
    .PARAMETER DomainDnsName
      Target domain (or omit for the computer's domain).
    .PARAMETER NameFilter
      Only include GPOs whose DisplayName is in this list.
    .PARAMETER NameRegex
      Only include GPOs whose DisplayName matches this regex.
    .OUTPUTS
      PSCustomObject with: Tree (OU tree), GPOs (flat list), GpoByOU (dict).
    #>
    [CmdletBinding()]
    param(
        [string]$DomainDnsName,
        [string[]]$NameFilter,
        [string]$NameRegex
    )

    $ctx = Initialize-DomainContext -DomainDnsName $DomainDnsName

    Write-Host "`n--- Pulling GPOs from $($ctx.DnsRoot) ---" -ForegroundColor Cyan

    $gpos = Get-AllDomainGPOs -DomainDns $ctx.DnsRoot -NameFilter $NameFilter -NameRegex $NameRegex
    Write-Host "  GPOs found: $($gpos.Count)" -ForegroundColor Gray

    Write-Host "  Building OU tree with GPO links..." -ForegroundColor Gray
    $tree = Get-OUTreeWithLinks -DomainDN $ctx.DomainDN -DC $ctx.DC

    # Build a GPO→OU mapping (which OUs each GPO is linked to)
    $gpoOuMap = @{}
    foreach ($node in $tree) {
        foreach ($link in $node.LinkedGPOs) {
            if (-not $gpoOuMap.ContainsKey($link.GpoGuid)) {
                $gpoOuMap[$link.GpoGuid] = [System.Collections.Generic.List[PSCustomObject]]::new()
            }
            $gpoOuMap[$link.GpoGuid].Add([PSCustomObject]@{
                OuName   = $node.Name
                OuDN     = $node.DistinguishedName
                OuDepth  = $node.Depth
                LinkOrder = $link.LinkOrder
                Enabled   = $link.Enabled
                Enforced  = $link.Enforced
            })
        }
    }

    return [PSCustomObject]@{
        DomainDns = $ctx.DnsRoot
        DC        = $ctx.DC
        DomainDN  = $ctx.DomainDN
        GPOs      = $gpos
        OUTree    = $tree
        GpoOuMap  = $gpoOuMap
    }
}

#endregion

#region ── Display helpers ─────────────────────────────────────────────

function Show-GPOTree {
    <#
    .SYNOPSIS  Print the OU tree with linked GPOs in a human-readable format.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject[]]$OUTree
    )

    Write-Host "`n╔══ GPO Hierarchy (AD OU Tree) ══════════════════════" -ForegroundColor White

    foreach ($node in $OUTree) {
        $indent = '║  ' + ('   ' * $node.Depth)
        $icon   = if ($node.Depth -eq 0) { '[Domain]' } else { '[OU]' }
        Write-Host "$indent$icon $($node.Name)" -ForegroundColor Cyan

        if ($node.LinkedGPOs.Count -gt 0) {
            foreach ($link in ($node.LinkedGPOs | Sort-Object LinkOrder)) {
                $status = @()
                if (-not $link.Enabled)  { $status += 'DISABLED' }
                if ($link.Enforced)      { $status += 'ENFORCED' }
                $statusStr = if ($status.Count) { " ($($status -join ', '))" } else { '' }
                $gpoLabel = if ($link.GpoName) { $link.GpoName } else { $link.GpoGuid }
                Write-Host "$indent   ├─ GPO: $gpoLabel$statusStr" -ForegroundColor Green
            }
        }
    }

    Write-Host "╚═══════════════════════════════════════════════════`n" -ForegroundColor White
}

function Export-GPOTreeReport {
    <#
    .SYNOPSIS  Export the hierarchy view to a CSV and a JSON file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Hierarchy,
        [Parameter(Mandatory)][string]$OutputFolder
    )

    if (-not (Test-Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }

    # Flat table: one row per GPO-link
    $rows = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($node in $Hierarchy.OUTree) {
        foreach ($link in $node.LinkedGPOs) {
            $rows.Add([PSCustomObject]@{
                OuName              = $node.Name
                OuDistinguishedName = $node.DistinguishedName
                OuDepth             = $node.Depth
                GpoName             = $link.GpoName
                GpoGuid             = $link.GpoGuid
                LinkOrder           = $link.LinkOrder
                LinkEnabled         = $link.Enabled
                LinkEnforced        = $link.Enforced
            })
        }
    }

    $csvPath  = Join-Path $OutputFolder 'GPO_Hierarchy.csv'
    $jsonPath = Join-Path $OutputFolder 'GPO_Hierarchy.json'

    $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    $Hierarchy | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8

    Write-Host "  Hierarchy exported:" -ForegroundColor Green
    Write-Host "    CSV  : $csvPath" -ForegroundColor Gray
    Write-Host "    JSON : $jsonPath" -ForegroundColor Gray
}

#endregion

#region ── Export GPO XML reports for parsing ───────────────────────────

function Export-GPOReportsForHierarchy {
    <#
    .SYNOPSIS
      Export Get-GPOReport XML for every GPO in the hierarchy, storing
      them under OutputFolder\GpoReports\{GpoName}.xml.
    .OUTPUTS
      Hashtable: GpoGuid → path to XML report file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Hierarchy,
        [Parameter(Mandatory)][string]$OutputFolder
    )

    $reportDir = Join-Path $OutputFolder 'GpoReports'
    if (-not (Test-Path $reportDir)) { New-Item -Path $reportDir -ItemType Directory -Force | Out-Null }

    $map = @{}

    foreach ($gpo in $Hierarchy.GPOs) {
        $safeName = $gpo.DisplayName -replace '[\\/:*?"<>|]', '_'
        $xmlPath  = Join-Path $reportDir "$safeName.xml"

        if (Test-Path $xmlPath) {
            Write-Host "  [cached] $($gpo.DisplayName)" -ForegroundColor DarkGray
        } else {
            Write-Host "  [export] $($gpo.DisplayName)" -ForegroundColor Cyan
            try {
                Get-GPOReport -Guid $gpo.Id -Domain $Hierarchy.DomainDns -ReportType Xml -Path $xmlPath -ErrorAction Stop
            } catch {
                Write-Warning "  Failed to export $($gpo.DisplayName): $($_.Exception.Message)"
                continue
            }
        }
        $map[$gpo.Id] = $xmlPath
    }

    return $map
}

#endregion

Export-ModuleMember -Function @(
    'Build-GPOHierarchy',
    'Show-GPOTree',
    'Export-GPOTreeReport',
    'Export-GPOReportsForHierarchy',
    'Initialize-DomainContext',
    'Get-AllDomainGPOs',
    'Get-OUTreeWithLinks'
)
