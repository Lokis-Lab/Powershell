<#
.SYNOPSIS
  Compares the merged master baseline template against live domain GPOs
  (and their children GPOs under child OUs), producing a structured diff.

.DESCRIPTION
  For each GPO in the hierarchy the engine:
    1. Parses the GPO's XML report into normalised settings.
    2. Collects settings from any "child" GPOs (linked to child OUs).
    3. Computes the effective settings (child overrides parent by link order).
    4. Diffs the effective settings against the master template.
    5. Classifies each difference: Missing, Extra, ValueMismatch.

  Output is a collection of diff objects that the DiffReviewer can display
  and let the user selectively accept or dismiss.
#>

#requires -Version 5.1

using module .\PolicyParser.psm1

#region ── Diff object model ───────────────────────────────────────────

enum DiffStatus {
    Match
    ValueMismatch
    MissingInGPO
    ExtraInGPO
}

function New-DiffEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Key,
        [string]$Category,
        [string]$SubCategory,
        [string]$SettingName,
        [string]$BaselineValue,
        [string]$GpoValue,
        [DiffStatus]$Status,
        [string]$GpoName,
        [string]$GpoGuid,
        [string]$OuPath
    )

    return [PSCustomObject]@{
        Key            = $Key
        Category       = $Category
        SubCategory    = $SubCategory
        SettingName    = $SettingName
        BaselineValue  = $BaselineValue
        GpoValue       = $GpoValue
        Status         = $Status.ToString()
        GpoName        = $GpoName
        GpoGuid        = $GpoGuid
        OuPath         = $OuPath
        Selected       = $true
        RiskComment    = ''
    }
}

#endregion

#region ── Single GPO comparison ───────────────────────────────────────

function Compare-GpoToBaseline {
    <#
    .SYNOPSIS
      Compare a single GPO's parsed settings against the master template.
    .PARAMETER MasterSettings
      The merged master template settings collection.
    .PARAMETER GpoSettings
      Parsed settings from a GPO report XML.
    .PARAMETER GpoName
      Display name of the GPO (for labelling diffs).
    .PARAMETER GpoGuid
      GUID of the GPO.
    .PARAMETER OuPath
      OU path where this GPO is linked (for context).
    .OUTPUTS
      Array of diff entry objects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject[]]$MasterSettings,
        [Parameter(Mandatory)][PSCustomObject[]]$GpoSettings,
        [string]$GpoName = '',
        [string]$GpoGuid = '',
        [string]$OuPath = '',
        [switch]$IncludeMatches
    )

    $masterDict = [ordered]@{}
    foreach ($s in $MasterSettings) {
        $key = Get-SettingKey -Setting $s
        $masterDict[$key] = $s
    }

    $gpoDict = [ordered]@{}
    foreach ($s in $GpoSettings) {
        $key = Get-SettingKey -Setting $s
        $gpoDict[$key] = $s
    }

    $diffs = [System.Collections.Generic.List[PSCustomObject]]::new()
    $processedKeys = [System.Collections.Generic.HashSet[string]]::new()

    # Walk master: find mismatches and missing-in-GPO
    foreach ($key in $masterDict.Keys) {
        $ms = $masterDict[$key]
        [void]$processedKeys.Add($key)

        if ($gpoDict.Contains($key)) {
            $gs = $gpoDict[$key]
            if ($ms.SettingValue -ne $gs.SettingValue) {
                $diffs.Add((New-DiffEntry -Key $key `
                    -Category $ms.Category -SubCategory $ms.SubCategory `
                    -SettingName $ms.SettingName `
                    -BaselineValue $ms.SettingValue -GpoValue $gs.SettingValue `
                    -Status ValueMismatch -GpoName $GpoName -GpoGuid $GpoGuid -OuPath $OuPath))
            } elseif ($IncludeMatches) {
                $diffs.Add((New-DiffEntry -Key $key `
                    -Category $ms.Category -SubCategory $ms.SubCategory `
                    -SettingName $ms.SettingName `
                    -BaselineValue $ms.SettingValue -GpoValue $gs.SettingValue `
                    -Status Match -GpoName $GpoName -GpoGuid $GpoGuid -OuPath $OuPath))
            }
        } else {
            $diffs.Add((New-DiffEntry -Key $key `
                -Category $ms.Category -SubCategory $ms.SubCategory `
                -SettingName $ms.SettingName `
                -BaselineValue $ms.SettingValue -GpoValue '' `
                -Status MissingInGPO -GpoName $GpoName -GpoGuid $GpoGuid -OuPath $OuPath))
        }
    }

    # Walk GPO: find extras not in master
    foreach ($key in $gpoDict.Keys) {
        if ($processedKeys.Contains($key)) { continue }
        $gs = $gpoDict[$key]
        $diffs.Add((New-DiffEntry -Key $key `
            -Category $gs.Category -SubCategory $gs.SubCategory `
            -SettingName $gs.SettingName `
            -BaselineValue '' -GpoValue $gs.SettingValue `
            -Status ExtraInGPO -GpoName $GpoName -GpoGuid $GpoGuid -OuPath $OuPath))
    }

    return $diffs
}

#endregion

#region ── Effective settings (parent + children merge) ────────────────

function Get-EffectiveGpoSettings {
    <#
    .SYNOPSIS
      Compute effective settings for an OU by layering parent GPO settings
      then child GPO settings (higher link order / child OU overrides parent).
    .PARAMETER GpoReportPaths
      Ordered list of GPO XML report paths, from lowest precedence to highest.
      Typically: parent GPOs first (highest link order), then child GPO overrides.
    .OUTPUTS
      Merged effective settings collection.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$GpoReportPaths
    )

    $effective = [ordered]@{}

    foreach ($path in $GpoReportPaths) {
        if (-not (Test-Path $path)) {
            Write-Warning "GPO report not found: $path"
            continue
        }
        $settings = ConvertFrom-GpoReportXml -Path $path
        foreach ($s in $settings) {
            $key = Get-SettingKey -Setting $s
            $effective[$key] = $s   # later GPOs override earlier ones
        }
    }

    return @($effective.Values)
}

#endregion

#region ── Full hierarchy comparison ───────────────────────────────────

function Compare-HierarchyToBaseline {
    <#
    .SYNOPSIS
      Compare the master template against every GPO in a hierarchy,
      including effective child GPO roll-up per OU.
    .PARAMETER MasterSettings
      Merged master template settings.
    .PARAMETER Hierarchy
      Output from Build-GPOHierarchy.
    .PARAMETER GpoReportMap
      Hashtable of GpoGuid → XML report path (from Export-GPOReportsForHierarchy).
    .PARAMETER IncludeMatches
      If set, include settings that match (no diff). Off by default.
    .OUTPUTS
      PSCustomObject: PerGpoDiffs (dict), PerOuEffectiveDiffs (dict), AllDiffs (flat list).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject[]]$MasterSettings,
        [Parameter(Mandatory)][PSCustomObject]$Hierarchy,
        [Parameter(Mandatory)][hashtable]$GpoReportMap,
        [switch]$IncludeMatches
    )

    $perGpo  = @{}
    $perOu   = @{}
    $allDiffs = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Host "`n--- Comparing GPOs against master template ---" -ForegroundColor Cyan

    # Per-GPO comparison
    foreach ($gpo in $Hierarchy.GPOs) {
        $xmlPath = $GpoReportMap[$gpo.Id]
        if (-not $xmlPath -or -not (Test-Path $xmlPath)) {
            Write-Warning "No XML report for GPO: $($gpo.DisplayName) ($($gpo.Id))"
            continue
        }

        $gpoSettings = ConvertFrom-GpoReportXml -Path $xmlPath
        $ouLinks = if ($Hierarchy.GpoOuMap.ContainsKey($gpo.Id)) {
            ($Hierarchy.GpoOuMap[$gpo.Id] | ForEach-Object { $_.OuName }) -join ' > '
        } else { '' }

        Write-Host "  [compare] $($gpo.DisplayName)" -ForegroundColor Gray
        $diffs = Compare-GpoToBaseline -MasterSettings $MasterSettings -GpoSettings $gpoSettings `
            -GpoName $gpo.DisplayName -GpoGuid $gpo.Id -OuPath $ouLinks -IncludeMatches:$IncludeMatches

        $perGpo[$gpo.Id] = $diffs
        foreach ($d in $diffs) { $allDiffs.Add($d) }
    }

    # Per-OU effective comparison (layering GPOs by link order within each OU subtree)
    foreach ($node in $Hierarchy.OUTree) {
        if ($node.LinkedGPOs.Count -eq 0) { continue }

        $orderedPaths = [System.Collections.Generic.List[string]]::new()

        # Collect GPO report paths in reverse link order (lowest precedence first)
        $sortedLinks = $node.LinkedGPOs | Sort-Object LinkOrder -Descending
        foreach ($link in $sortedLinks) {
            if (-not $link.Enabled) { continue }
            if ($GpoReportMap.ContainsKey($link.GpoGuid) -and (Test-Path $GpoReportMap[$link.GpoGuid])) {
                $orderedPaths.Add($GpoReportMap[$link.GpoGuid])
            }
        }

        if ($orderedPaths.Count -eq 0) { continue }

        $effective = Get-EffectiveGpoSettings -GpoReportPaths $orderedPaths
        $ouDiffs = Compare-GpoToBaseline -MasterSettings $MasterSettings -GpoSettings $effective `
            -GpoName "(Effective @ $($node.Name))" -GpoGuid '' -OuPath $node.DistinguishedName -IncludeMatches:$IncludeMatches

        $perOu[$node.DistinguishedName] = $ouDiffs
    }

    # Summary
    $mismatchCount = ($allDiffs | Where-Object { $_.Status -eq 'ValueMismatch' }).Count
    $missingCount  = ($allDiffs | Where-Object { $_.Status -eq 'MissingInGPO' }).Count
    $extraCount    = ($allDiffs | Where-Object { $_.Status -eq 'ExtraInGPO' }).Count

    Write-Host "`n--- Comparison Summary ---" -ForegroundColor White
    Write-Host "  Value mismatches  : $mismatchCount" -ForegroundColor Yellow
    Write-Host "  Missing in GPOs   : $missingCount" -ForegroundColor Red
    Write-Host "  Extra in GPOs     : $extraCount" -ForegroundColor DarkCyan
    Write-Host "  Total differences : $($allDiffs.Count)" -ForegroundColor Cyan

    return [PSCustomObject]@{
        PerGpoDiffs           = $perGpo
        PerOuEffectiveDiffs   = $perOu
        AllDiffs              = $allDiffs
        Stats                 = [PSCustomObject]@{
            ValueMismatches = $mismatchCount
            MissingInGPO    = $missingCount
            ExtraInGPO      = $extraCount
            Total           = $allDiffs.Count
        }
    }
}

#endregion

#region ── Display helpers ─────────────────────────────────────────────

function Show-DiffSummary {
    <#
    .SYNOPSIS  Display a tabular summary of diffs grouped by GPO.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject[]]$Diffs,
        [int]$MaxRows = 50
    )

    if ($Diffs.Count -eq 0) {
        Write-Host "  No differences found — GPO matches the baseline!" -ForegroundColor Green
        return
    }

    $grouped = $Diffs | Group-Object GpoName

    foreach ($g in $grouped) {
        Write-Host "`n  ┌── $($g.Name) ($($g.Count) differences) ──" -ForegroundColor Yellow

        $shown = 0
        foreach ($d in $g.Group) {
            if ($shown -ge $MaxRows) {
                Write-Host "  │  ... and $($g.Count - $shown) more" -ForegroundColor DarkGray
                break
            }
            $icon = switch ($d.Status) {
                'ValueMismatch' { '~' }
                'MissingInGPO'  { '-' }
                'ExtraInGPO'    { '+' }
                default         { ' ' }
            }
            $colour = switch ($d.Status) {
                'ValueMismatch' { 'Yellow' }
                'MissingInGPO'  { 'Red' }
                'ExtraInGPO'    { 'DarkCyan' }
                default         { 'Gray' }
            }
            Write-Host "  │ [$icon] $($d.SettingName)" -ForegroundColor $colour -NoNewline
            if ($d.Status -eq 'ValueMismatch') {
                Write-Host "  baseline=$($d.BaselineValue)  gpo=$($d.GpoValue)" -ForegroundColor DarkGray
            } else {
                Write-Host ''
            }
            $shown++
        }
        Write-Host "  └──────────────────────────────────" -ForegroundColor Yellow
    }
}

function Export-DiffReport {
    <#
    .SYNOPSIS  Export diffs to CSV and JSON.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject[]]$Diffs,
        [Parameter(Mandatory)][string]$OutputFolder,
        [string]$BaseName = 'DiffReport'
    )

    if (-not (Test-Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }

    $csvPath  = Join-Path $OutputFolder "$BaseName.csv"
    $jsonPath = Join-Path $OutputFolder "$BaseName.json"

    $Diffs | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    $Diffs | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8

    Write-Host "  Diff report exported:" -ForegroundColor Green
    Write-Host "    CSV  : $csvPath" -ForegroundColor Gray
    Write-Host "    JSON : $jsonPath" -ForegroundColor Gray
}

#endregion

Export-ModuleMember -Function @(
    'Compare-GpoToBaseline',
    'Compare-HierarchyToBaseline',
    'Get-EffectiveGpoSettings',
    'Show-DiffSummary',
    'Export-DiffReport',
    'New-DiffEntry'
)
