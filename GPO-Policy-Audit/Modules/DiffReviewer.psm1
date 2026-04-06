<#
.SYNOPSIS
  Interactive diff review: lets the user walk through each difference
  between the master baseline and the live GPO, selectively deselect
  changes, and annotate risk-acceptance comments.

.DESCRIPTION
  After the compare engine produces diffs, this module presents them
  one-by-one (or in a grid) and lets the operator:

    - Accept a change (keep it selected for GPO export)
    - Deselect a change (mark it as "acceptable risk")
    - Add a free-text comment explaining why the deviation is OK
    - Bulk-accept or bulk-deselect by category/status
    - Save the reviewed diff set (with selections + comments) to
      a JSON "review manifest" that can be reloaded later

  The reviewed diff collection feeds into the GPOExporter to build
  the remediated GPO backup.
#>

#requires -Version 5.1

#region ── Interactive review loop ─────────────────────────────────────

function Start-DiffReview {
    <#
    .SYNOPSIS
      Walk the user through diff entries interactively.
    .PARAMETER Diffs
      Array of diff objects (from Compare-*ToBaseline).
    .PARAMETER ReviewManifestPath
      Optional path to load/save a prior review session.
    .OUTPUTS
      The same array with Updated, Selected, and RiskComment fields.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject[]]$Diffs,
        [string]$ReviewManifestPath
    )

    # Load prior review if available
    if ($ReviewManifestPath -and (Test-Path $ReviewManifestPath)) {
        Write-Host "  Loading prior review from: $ReviewManifestPath" -ForegroundColor Gray
        $prior = Get-Content -Path $ReviewManifestPath -Raw | ConvertFrom-Json
        $priorMap = @{}
        foreach ($p in $prior) { $priorMap[$p.Key] = $p }
        foreach ($d in $Diffs) {
            if ($priorMap.ContainsKey($d.Key)) {
                $d.Selected    = $priorMap[$d.Key].Selected
                $d.RiskComment = $priorMap[$d.Key].RiskComment
            }
        }
    }

    $total = $Diffs.Count
    if ($total -eq 0) {
        Write-Host "`n  No differences to review." -ForegroundColor Green
        return $Diffs
    }

    Write-Host "`n╔══ Diff Review ══════════════════════════════════════" -ForegroundColor White
    Write-Host "║ $total difference(s) to review." -ForegroundColor Cyan
    Write-Host "║ Commands: [A]ccept  [D]eselect  [C]omment  [S]kip" -ForegroundColor Gray
    Write-Host "║           [AA] Accept-All  [DA] Deselect-All" -ForegroundColor Gray
    Write-Host "║           [AC] Accept-by-Category  [Q]uit review" -ForegroundColor Gray
    Write-Host "╚═══════════════════════════════════════════════════`n" -ForegroundColor White

    $index = 0
    while ($index -lt $total) {
        $d = $Diffs[$index]
        $num = $index + 1

        # Display current diff
        $statusIcon = switch ($d.Status) {
            'ValueMismatch' { '~' ; break }
            'MissingInGPO'  { '-' ; break }
            'ExtraInGPO'    { '+' ; break }
            default         { '?' }
        }
        $statusColor = switch ($d.Status) {
            'ValueMismatch' { 'Yellow' }
            'MissingInGPO'  { 'Red' }
            'ExtraInGPO'    { 'DarkCyan' }
            default         { 'Gray' }
        }

        Write-Host "── [$num/$total] ──────────────────────────────" -ForegroundColor White
        Write-Host "  Status      : [$statusIcon] $($d.Status)" -ForegroundColor $statusColor
        Write-Host "  GPO         : $($d.GpoName)" -ForegroundColor Cyan
        Write-Host "  Setting     : $($d.SettingName)" -ForegroundColor White
        Write-Host "  Category    : $($d.Category) > $($d.SubCategory)" -ForegroundColor Gray
        if ($d.BaselineValue) { Write-Host "  Baseline    : $($d.BaselineValue)" -ForegroundColor Green }
        if ($d.GpoValue)      { Write-Host "  GPO Value   : $($d.GpoValue)" -ForegroundColor Magenta }
        if ($d.RiskComment)   { Write-Host "  Comment     : $($d.RiskComment)" -ForegroundColor DarkYellow }
        $selLabel = if ($d.Selected) { 'SELECTED (will be remediated)' } else { 'DESELECTED (accepted risk)' }
        $selColor = if ($d.Selected) { 'Green' } else { 'DarkGray' }
        Write-Host "  Decision    : $selLabel" -ForegroundColor $selColor

        $userChoice = Read-Host "  Action [A/D/C/S/AA/DA/AC/Q]"
        switch ($userChoice.Trim().ToUpper()) {
            'A' {
                $d.Selected = $true
                Write-Host "    -> Accepted (selected for remediation)" -ForegroundColor Green
                $index++
            }
            'D' {
                $d.Selected = $false
                $comment = Read-Host "    Reason this is acceptable risk (or Enter to skip)"
                if ($comment) { $d.RiskComment = $comment }
                Write-Host "    -> Deselected (acceptable risk)" -ForegroundColor DarkGray
                $index++
            }
            'C' {
                $comment = Read-Host "    Enter comment"
                if ($comment) { $d.RiskComment = $comment }
                Write-Host "    -> Comment saved" -ForegroundColor DarkYellow
                # Stay on same item
            }
            'S' {
                $index++
            }
            'AA' {
                foreach ($item in $Diffs) { $item.Selected = $true }
                Write-Host "    -> All $total items accepted" -ForegroundColor Green
                $index = $total
            }
            'DA' {
                $reason = Read-Host "    Reason for deselecting all"
                foreach ($item in $Diffs) {
                    $item.Selected = $false
                    if ($reason) { $item.RiskComment = $reason }
                }
                Write-Host "    -> All $total items deselected" -ForegroundColor DarkGray
                $index = $total
            }
            'AC' {
                $categories = ($Diffs | Select-Object -ExpandProperty Category -Unique) -join ', '
                Write-Host "    Categories: $categories" -ForegroundColor Gray
                $catChoice = Read-Host "    Accept all in which category?"
                $matched = $Diffs | Where-Object { $_.Category -eq $catChoice }
                foreach ($item in $matched) { $item.Selected = $true }
                Write-Host "    -> $($matched.Count) items in '$catChoice' accepted" -ForegroundColor Green
                $index++
            }
            'Q' {
                Write-Host "    -> Review ended early." -ForegroundColor DarkGray
                $index = $total
            }
            default {
                Write-Host "    Unknown command. Use A/D/C/S/AA/DA/AC/Q." -ForegroundColor Red
            }
        }
    }

    # Save review manifest
    if ($ReviewManifestPath) {
        Save-ReviewManifest -Diffs $Diffs -Path $ReviewManifestPath
    }

    # Summary
    $accepted  = ($Diffs | Where-Object { $_.Selected }).Count
    $deselected = ($Diffs | Where-Object { -not $_.Selected }).Count
    Write-Host "`n--- Review Complete ---" -ForegroundColor White
    Write-Host "  Accepted (remediate) : $accepted" -ForegroundColor Green
    Write-Host "  Deselected (risk OK) : $deselected" -ForegroundColor DarkGray

    return $Diffs
}

#endregion

#region ── Non-interactive (batch) review ──────────────────────────────

function Set-DiffSelections {
    <#
    .SYNOPSIS
      Apply selections and comments from a decisions hashtable (non-interactive).
    .PARAMETER Diffs
      Array of diff objects.
    .PARAMETER Decisions
      Hashtable keyed by diff Key. Value = PSCustomObject{ Selected, RiskComment }.
    .OUTPUTS
      Updated diff array.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject[]]$Diffs,
        [Parameter(Mandatory)][hashtable]$Decisions
    )

    foreach ($d in $Diffs) {
        if ($Decisions.ContainsKey($d.Key)) {
            $dec = $Decisions[$d.Key]
            $d.Selected    = $dec.Selected
            $d.RiskComment = if ($dec.PSObject.Properties['RiskComment']) { $dec.RiskComment } else { '' }
        }
    }

    return $Diffs
}

#endregion

#region ── Review manifest persistence ─────────────────────────────────

function Save-ReviewManifest {
    <#
    .SYNOPSIS  Save the reviewed diff set (selections + comments) to JSON.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject[]]$Diffs,
        [Parameter(Mandatory)][string]$Path
    )

    $parent = Split-Path $Path -Parent
    if (-not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }

    $Diffs | ConvertTo-Json -Depth 10 | Set-Content -Path $Path -Encoding UTF8
    Write-Host "  Review manifest saved: $Path" -ForegroundColor Green
}

function Import-ReviewManifest {
    <#
    .SYNOPSIS  Load a previously saved review manifest.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$Path
    )

    $data = Get-Content -Path $Path -Raw | ConvertFrom-Json
    Write-Host "  Loaded review manifest: $Path ($($data.Count) entries)" -ForegroundColor Gray
    return $data
}

#endregion

#region ── HTML report ─────────────────────────────────────────────────

function Export-DiffReviewHtml {
    <#
    .SYNOPSIS  Generate an HTML report of the reviewed diffs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject[]]$Diffs,
        [Parameter(Mandatory)][string]$OutputPath,
        [string]$Title = 'GPO Policy Audit - Diff Review Report'
    )

    $parent = Split-Path $OutputPath -Parent
    if (-not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }

    $accepted  = ($Diffs | Where-Object { $_.Selected }).Count
    $deselected = ($Diffs | Where-Object { -not $_.Selected }).Count
    $total     = $Diffs.Count

    $rows = [System.Text.StringBuilder]::new()
    foreach ($d in $Diffs) {
        $rowClass = switch ($d.Status) {
            'ValueMismatch' { 'mismatch' }
            'MissingInGPO'  { 'missing'  }
            'ExtraInGPO'    { 'extra'    }
            default         { '' }
        }
        $selIcon = if ($d.Selected) { '&#10003;' } else { '&#10007;' }
        $selClass = if ($d.Selected) { 'sel-yes' } else { 'sel-no' }
        $comment = if ($d.RiskComment) { [System.Web.HttpUtility]::HtmlEncode($d.RiskComment) } else { '' }

        [void]$rows.AppendLine("<tr class=`"$rowClass`">")
        [void]$rows.AppendLine("  <td class=`"$selClass`">$selIcon</td>")
        [void]$rows.AppendLine("  <td>$($d.Status)</td>")
        [void]$rows.AppendLine("  <td>$([System.Web.HttpUtility]::HtmlEncode($d.GpoName))</td>")
        [void]$rows.AppendLine("  <td>$([System.Web.HttpUtility]::HtmlEncode($d.SettingName))</td>")
        [void]$rows.AppendLine("  <td>$([System.Web.HttpUtility]::HtmlEncode($d.Category))</td>")
        [void]$rows.AppendLine("  <td>$([System.Web.HttpUtility]::HtmlEncode($d.BaselineValue))</td>")
        [void]$rows.AppendLine("  <td>$([System.Web.HttpUtility]::HtmlEncode($d.GpoValue))</td>")
        [void]$rows.AppendLine("  <td>$comment</td>")
        [void]$rows.AppendLine("</tr>")
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>$Title</title>
<style>
  body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 2em; background: #f8f9fa; color: #222; }
  h1 { border-bottom: 2px solid #0078d4; padding-bottom: 0.3em; }
  .summary { display: flex; gap: 2em; margin: 1em 0; }
  .summary div { padding: 1em; border-radius: 6px; font-size: 1.1em; min-width: 140px; text-align: center; }
  .s-total { background: #e3f2fd; }
  .s-accept { background: #e8f5e9; }
  .s-risk { background: #fff3e0; }
  table { border-collapse: collapse; width: 100%; margin-top: 1em; font-size: 0.9em; }
  th, td { border: 1px solid #ccc; padding: 6px 10px; text-align: left; }
  th { background: #0078d4; color: #fff; position: sticky; top: 0; }
  tr:nth-child(even) { background: #f0f4f8; }
  .mismatch { border-left: 4px solid #f9a825; }
  .missing  { border-left: 4px solid #e53935; }
  .extra    { border-left: 4px solid #1e88e5; }
  .sel-yes  { color: #2e7d32; font-weight: bold; }
  .sel-no   { color: #c62828; font-weight: bold; }
</style>
</head>
<body>
<h1>$Title</h1>
<p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
<div class="summary">
  <div class="s-total"><strong>Total</strong><br/>$total</div>
  <div class="s-accept"><strong>Remediate</strong><br/>$accepted</div>
  <div class="s-risk"><strong>Risk Accepted</strong><br/>$deselected</div>
</div>
<table>
<thead>
<tr>
  <th>Sel</th><th>Status</th><th>GPO</th><th>Setting</th>
  <th>Category</th><th>Baseline Value</th><th>GPO Value</th><th>Risk Comment</th>
</tr>
</thead>
<tbody>
$($rows.ToString())
</tbody>
</table>
</body>
</html>
"@

    $html | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Host "  HTML review report: $OutputPath" -ForegroundColor Green
}

#endregion

Export-ModuleMember -Function @(
    'Start-DiffReview',
    'Set-DiffSelections',
    'Save-ReviewManifest',
    'Import-ReviewManifest',
    'Export-DiffReviewHtml'
)
