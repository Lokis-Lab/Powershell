<#
.SYNOPSIS
  Merges NIST/STIG and Microsoft GPO baselines into a single "Master
  Template" with user-controlled conflict resolution.

.DESCRIPTION
  When both baselines define the same setting (matched by
  Category + SubCategory + SettingName), the user picks which source
  "wins".  The winner's value overrides the loser's in the merged
  master template.

  Priority modes:
    MicrosoftWins  – Microsoft value used on conflicts
    StigWins       – NIST/STIG value used on conflicts
    Interactive    – prompt the user for each conflict
    Custom         – supply a hashtable of per-key decisions

  Non-conflicting settings from both sources are always included.
#>

#requires -Version 5.1

using module .\PolicyParser.psm1

#region ── Merge engine ────────────────────────────────────────────────

function Merge-Baselines {
    <#
    .SYNOPSIS
      Merge two parsed baseline collections into a master template.
    .PARAMETER MicrosoftSettings
      Collection from Import-BaselineFolder for the Microsoft baseline.
    .PARAMETER StigSettings
      Collection from Import-BaselineFolder for the STIG baseline.
    .PARAMETER ConflictResolution
      How to resolve conflicts: MicrosoftWins, StigWins, Interactive, Custom.
    .PARAMETER CustomDecisions
      Hashtable keyed by Get-SettingKey, value = 'Microsoft' or 'Stig'.
      Used only when ConflictResolution = 'Custom'.
    .OUTPUTS
      PSCustomObject with: MasterSettings, Conflicts, MicrosoftOnly, StigOnly
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject[]]$MicrosoftSettings,
        [Parameter(Mandatory)][PSCustomObject[]]$StigSettings,
        [ValidateSet('MicrosoftWins','StigWins','Interactive','Custom')]
        [string]$ConflictResolution = 'MicrosoftWins',
        [hashtable]$CustomDecisions = @{}
    )

    # Build dictionaries keyed by composite key
    $msDict   = [ordered]@{}
    $stigDict = [ordered]@{}

    foreach ($s in $MicrosoftSettings) {
        $key = Get-SettingKey -Setting $s
        $msDict[$key] = $s
    }
    foreach ($s in $StigSettings) {
        $key = Get-SettingKey -Setting $s
        $stigDict[$key] = $s
    }

    $master       = [System.Collections.Generic.List[PSCustomObject]]::new()
    $conflicts    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $msOnly       = [System.Collections.Generic.List[PSCustomObject]]::new()
    $stigOnly     = [System.Collections.Generic.List[PSCustomObject]]::new()
    $processedKeys = [System.Collections.Generic.HashSet[string]]::new()

    # Walk Microsoft settings
    foreach ($key in $msDict.Keys) {
        $msSetting = $msDict[$key]
        [void]$processedKeys.Add($key)

        if ($stigDict.Contains($key)) {
            $stigSetting = $stigDict[$key]

            if ($msSetting.SettingValue -eq $stigSetting.SettingValue) {
                # Same value — no conflict
                $merged = Copy-SettingWithSource -Setting $msSetting -MergeSource 'Both (Agree)'
                $master.Add($merged)
            } else {
                $conflictObj = [PSCustomObject]@{
                    Key              = $key
                    Category         = $msSetting.Category
                    SubCategory      = $msSetting.SubCategory
                    SettingName      = $msSetting.SettingName
                    MicrosoftValue   = $msSetting.SettingValue
                    StigValue        = $stigSetting.SettingValue
                    Winner           = ''
                    WinningValue     = ''
                }

                switch ($ConflictResolution) {
                    'MicrosoftWins' {
                        $conflictObj.Winner       = 'Microsoft'
                        $conflictObj.WinningValue = $msSetting.SettingValue
                    }
                    'StigWins' {
                        $conflictObj.Winner       = 'STIG'
                        $conflictObj.WinningValue = $stigSetting.SettingValue
                    }
                    'Interactive' {
                        $choice = Invoke-ConflictPrompt -ConflictObj $conflictObj
                        $conflictObj.Winner       = $choice
                        $conflictObj.WinningValue = if ($choice -eq 'Microsoft') { $msSetting.SettingValue } else { $stigSetting.SettingValue }
                    }
                    'Custom' {
                        if ($CustomDecisions.ContainsKey($key)) {
                            $conflictObj.Winner       = $CustomDecisions[$key]
                            $conflictObj.WinningValue = if ($CustomDecisions[$key] -eq 'Microsoft') { $msSetting.SettingValue } else { $stigSetting.SettingValue }
                        } else {
                            $conflictObj.Winner       = 'Microsoft'
                            $conflictObj.WinningValue = $msSetting.SettingValue
                        }
                    }
                }

                $winnerSetting = if ($conflictObj.Winner -eq 'Microsoft') { $msSetting } else { $stigSetting }
                $merged = Copy-SettingWithSource -Setting $winnerSetting -MergeSource "Conflict: $($conflictObj.Winner) wins"
                $master.Add($merged)
                $conflicts.Add($conflictObj)
            }
        } else {
            $merged = Copy-SettingWithSource -Setting $msSetting -MergeSource 'Microsoft Only'
            $master.Add($merged)
            $msOnly.Add($msSetting)
        }
    }

    # Walk STIG-only settings
    foreach ($key in $stigDict.Keys) {
        if ($processedKeys.Contains($key)) { continue }
        $stigSetting = $stigDict[$key]
        $merged = Copy-SettingWithSource -Setting $stigSetting -MergeSource 'STIG Only'
        $master.Add($merged)
        $stigOnly.Add($stigSetting)
    }

    Write-Host "`n--- Merge Summary ---" -ForegroundColor White
    Write-Host "  Total master settings : $($master.Count)" -ForegroundColor Cyan
    Write-Host "  Conflicts resolved    : $($conflicts.Count)" -ForegroundColor Yellow
    Write-Host "  Microsoft-only        : $($msOnly.Count)" -ForegroundColor DarkCyan
    Write-Host "  STIG-only             : $($stigOnly.Count)" -ForegroundColor DarkCyan

    return [PSCustomObject]@{
        MasterSettings = $master
        Conflicts      = $conflicts
        MicrosoftOnly  = $msOnly
        StigOnly       = $stigOnly
    }
}

#endregion

#region ── Interactive conflict prompt ─────────────────────────────────

function Invoke-ConflictPrompt {
    [CmdletBinding()]
    param([Parameter(Mandatory)][PSCustomObject]$ConflictObj)

    Write-Host "`n╔══ CONFLICT ════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host "║ Setting  : $($ConflictObj.SettingName)" -ForegroundColor White
    Write-Host "║ Category : $($ConflictObj.Category) > $($ConflictObj.SubCategory)" -ForegroundColor Gray
    Write-Host "║" -ForegroundColor Yellow
    Write-Host "║  [M] Microsoft value: $($ConflictObj.MicrosoftValue)" -ForegroundColor Cyan
    Write-Host "║  [S] STIG value     : $($ConflictObj.StigValue)" -ForegroundColor Magenta
    Write-Host "╚═══════════════════════════════════════════════════" -ForegroundColor Yellow

    do {
        $answer = Read-Host "  Choose winner ([M]icrosoft / [S]TIG)"
        $answer = $answer.Trim().ToUpper()
    } while ($answer -notin @('M','S','MICROSOFT','STIG'))

    return if ($answer -in @('M','MICROSOFT')) { 'Microsoft' } else { 'STIG' }
}

#endregion

#region ── Helper: copy setting with MergeSource ───────────────────────

function Copy-SettingWithSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Setting,
        [Parameter(Mandatory)][string]$MergeSource
    )
    $props = @{
        Category     = $Setting.Category
        SubCategory  = $Setting.SubCategory
        SettingName  = $Setting.SettingName
        SettingValue = $Setting.SettingValue
        MergeSource  = $MergeSource
    }
    if ($Setting.PSObject.Properties['RegType']) { $props['RegType'] = $Setting.RegType }
    if ($Setting.PSObject.Properties['Action'])  { $props['Action']  = $Setting.Action }
    if ($Setting.PSObject.Properties['IncExcl']) { $props['IncExcl'] = $Setting.IncExcl }

    return [PSCustomObject]$props
}

#endregion

#region ── Export master template ──────────────────────────────────────

function Export-MasterTemplate {
    <#
    .SYNOPSIS  Save the merged master template to CSV and JSON for downstream use.
    .PARAMETER MasterSettings  The merged setting collection.
    .PARAMETER OutputFolder    Where to write the files.
    .PARAMETER BaseName        File name prefix (default: MasterTemplate).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject[]]$MasterSettings,
        [Parameter(Mandatory)][string]$OutputFolder,
        [string]$BaseName = 'MasterTemplate'
    )

    if (-not (Test-Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }

    $csvPath  = Join-Path $OutputFolder "$BaseName.csv"
    $jsonPath = Join-Path $OutputFolder "$BaseName.json"

    $MasterSettings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    $MasterSettings | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8

    Write-Host "  Master template saved:" -ForegroundColor Green
    Write-Host "    CSV  : $csvPath" -ForegroundColor Gray
    Write-Host "    JSON : $jsonPath" -ForegroundColor Gray

    return [PSCustomObject]@{
        CsvPath  = $csvPath
        JsonPath = $jsonPath
    }
}

#endregion

#region ── Export conflict report ──────────────────────────────────────

function Export-ConflictReport {
    <#
    .SYNOPSIS  Save the conflict detail to CSV.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject[]]$Conflicts,
        [Parameter(Mandatory)][string]$OutputFolder,
        [string]$BaseName = 'ConflictReport'
    )

    if ($Conflicts.Count -eq 0) {
        Write-Host "  No conflicts to report." -ForegroundColor Green
        return $null
    }

    if (-not (Test-Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }

    $csvPath = Join-Path $OutputFolder "$BaseName.csv"
    $Conflicts | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    Write-Host "  Conflict report: $csvPath" -ForegroundColor Gray
    return $csvPath
}

#endregion

Export-ModuleMember -Function @(
    'Merge-Baselines',
    'Export-MasterTemplate',
    'Export-ConflictReport'
)
