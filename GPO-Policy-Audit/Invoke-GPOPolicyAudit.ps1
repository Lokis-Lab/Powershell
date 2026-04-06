<#
.SYNOPSIS
  GPO Policy Audit — compare your domain GPOs against NIST/STIG and
  Microsoft security baselines, review diffs interactively, and export
  remediated GPO backups.

.DESCRIPTION
  End-to-end workflow:
    Step 1  Download / verify NIST and Microsoft baseline templates.
    Step 2  Parse and merge baselines into a single master template,
            letting the user choose which source wins on conflicts.
    Step 3  Pull GPOs from the domain and display them in an AD-like
            OU hierarchy (parent/child relationships).
    Step 4  Compare the master template against every GPO (and the
            effective settings at each OU with child GPOs layered in).
    Step 5  Interactive diff review — accept changes for remediation
            or deselect them with a risk-acceptance comment.
    Step 6  Export remediated GPO backups + an import script so the
            admin can upload and link them in AD.

  Run modes (parameter -Mode):
    Full               Run steps 1-6 sequentially.
    DownloadBaselines  Step 1 only.
    MergeBaselines     Steps 1-2.
    PullHierarchy      Step 3 only (requires domain access).
    CompareOnly        Steps 1-4 (no interactive review).
    ReviewOnly         Step 5 — load prior diff output and review.
    ExportOnly         Step 6 — load prior review and export GPOs.

.PARAMETER Mode
  Which workflow steps to execute. Default: Full.

.PARAMETER OutputDir
  Root folder for all output (baselines, reports, exports).
  Default: .\GPO-Policy-Audit-Output

.PARAMETER DomainDnsName
  Target AD domain DNS name. Omit to use the local computer's domain.

.PARAMETER BaselineRoot
  Folder where baseline templates are downloaded/cached.
  Default: <OutputDir>\Baselines

.PARAMETER MicrosoftProducts
  Which Microsoft baselines to download.
  Default: Windows11, WindowsServer2025, WindowsServer2022

.PARAMETER StigPackageUrl
  Override URL for the DISA STIG GPO package ZIP.

.PARAMETER ConflictResolution
  How to resolve conflicts when merging NIST and Microsoft baselines.
  MicrosoftWins | StigWins | Interactive
  Default: Interactive

.PARAMETER GpoNameFilter
  Only audit GPOs whose DisplayName is in this list.

.PARAMETER GpoNameRegex
  Only audit GPOs whose DisplayName matches this regex.

.PARAMETER Force
  Re-download baselines even if cached.

.PARAMETER SkipDomainCheck
  Skip the domain connectivity check (for offline/testing).

.EXAMPLE
  # Full audit workflow with interactive conflict resolution
  .\Invoke-GPOPolicyAudit.ps1 -Mode Full -OutputDir C:\Audit

.EXAMPLE
  # Just download and verify baselines
  .\Invoke-GPOPolicyAudit.ps1 -Mode DownloadBaselines -OutputDir C:\Audit

.EXAMPLE
  # Merge with Microsoft winning all conflicts
  .\Invoke-GPOPolicyAudit.ps1 -Mode MergeBaselines -ConflictResolution MicrosoftWins

.EXAMPLE
  # Compare only specific GPOs
  .\Invoke-GPOPolicyAudit.ps1 -Mode CompareOnly -GpoNameRegex "^SEC -"

.EXAMPLE
  # Review a previous diff report
  .\Invoke-GPOPolicyAudit.ps1 -Mode ReviewOnly -OutputDir C:\Audit

.NOTES
  Requires PowerShell 5.1+.
  Domain operations require RSAT: Group Policy Management and AD DS Tools.
  Baseline downloads require internet access.
#>
[CmdletBinding()]
param(
    [ValidateSet('Full','DownloadBaselines','MergeBaselines','PullHierarchy',
                 'CompareOnly','ReviewOnly','ExportOnly')]
    [string]$Mode = 'Full',

    [string]$OutputDir = (Join-Path $PSScriptRoot 'GPO-Policy-Audit-Output'),

    [string]$DomainDnsName,

    [string]$BaselineRoot,

    [string[]]$MicrosoftProducts = @('Windows11','WindowsServer2025','WindowsServer2022'),

    [string]$StigPackageUrl = 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_STIG_GPO_Package_April_2025.zip',

    [ValidateSet('MicrosoftWins','StigWins','Interactive')]
    [string]$ConflictResolution = 'Interactive',

    [string[]]$GpoNameFilter,

    [string]$GpoNameRegex,

    [switch]$Force,

    [switch]$SkipDomainCheck
)

$ErrorActionPreference = 'Stop'

#region ── Module loading ─────────────────────────────────────────────

$modulesDir = Join-Path $PSScriptRoot 'Modules'

Import-Module (Join-Path $modulesDir 'PolicyParser.psm1')    -Force -DisableNameChecking
Import-Module (Join-Path $modulesDir 'BaselineDownloader.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $modulesDir 'BaselineMerger.psm1')  -Force -DisableNameChecking
Import-Module (Join-Path $modulesDir 'GPOComparer.psm1')     -Force -DisableNameChecking
Import-Module (Join-Path $modulesDir 'DiffReviewer.psm1')    -Force -DisableNameChecking
Import-Module (Join-Path $modulesDir 'GPOExporter.psm1')     -Force -DisableNameChecking

# GPOTreeBuilder requires RSAT, only load when needed
$needsDomain = $Mode -in @('Full','PullHierarchy','CompareOnly')

#endregion

#region ── Derived paths ──────────────────────────────────────────────

if (-not $BaselineRoot) { $BaselineRoot = Join-Path $OutputDir 'Baselines' }
$mergeDir   = Join-Path $OutputDir 'MergedTemplate'
$hierDir    = Join-Path $OutputDir 'Hierarchy'
$diffDir    = Join-Path $OutputDir 'DiffReports'
$exportDir  = Join-Path $OutputDir 'ExportedGPOs'
$reviewPath = Join-Path $diffDir   'ReviewManifest.json'

foreach ($d in @($OutputDir, $BaselineRoot, $mergeDir, $hierDir, $diffDir, $exportDir)) {
    if (-not (Test-Path $d)) { New-Item -Path $d -ItemType Directory -Force | Out-Null }
}

#endregion

#region ── Banner ─────────────────────────────────────────────────────

Write-Host @"

 ╔══════════════════════════════════════════════════════════════╗
 ║            GPO  POLICY  AUDIT  TOOL                         ║
 ║  NIST/STIG + Microsoft Baseline Comparison Engine           ║
 ╠══════════════════════════════════════════════════════════════╣
 ║  Mode      : $($Mode.PadRight(47))║
 ║  Output    : $($OutputDir.PadRight(47))║
 ║  Baselines : $($BaselineRoot.PadRight(47))║
 ╚══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

#endregion

#region ── Step 1: Download / verify baselines ────────────────────────

if ($Mode -in @('Full','DownloadBaselines','MergeBaselines','CompareOnly')) {
    Write-Host "═══ STEP 1: Download & Verify Baselines ═══════════════" -ForegroundColor White

    $syncResult = Sync-AllBaselines -BaselineRoot $BaselineRoot `
        -MicrosoftProducts $MicrosoftProducts `
        -StigPackageUrl $StigPackageUrl `
        -Force:$Force

    $availableBaselines = Get-AvailableBaselines -BaselineRoot $BaselineRoot
    Write-Host "`n  Available baselines on disk:" -ForegroundColor Gray
    foreach ($bl in $availableBaselines) {
        Write-Host "    [$($bl.Source)] $($bl.Name)" -ForegroundColor DarkCyan
    }
}

if ($Mode -eq 'DownloadBaselines') {
    Write-Host "`nBaseline download complete." -ForegroundColor Green
    exit 0
}

#endregion

#region ── Step 2: Parse & merge baselines ────────────────────────────

if ($Mode -in @('Full','MergeBaselines','CompareOnly')) {
    Write-Host "`n═══ STEP 2: Parse & Merge Baselines ═══════════════════" -ForegroundColor White

    # Parse Microsoft baselines
    Write-Host "  Parsing Microsoft baselines..." -ForegroundColor Gray
    $msSettings = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($msPath in $syncResult.MicrosoftPaths) {
        if ($msPath -and (Test-Path $msPath)) {
            $parsed = Import-BaselineFolder -Path $msPath
            foreach ($p in $parsed) { $msSettings.Add($p) }
            Write-Host "    $msPath : $($parsed.Count) settings" -ForegroundColor DarkGray
        }
    }

    # Parse STIG baselines
    Write-Host "  Parsing STIG baselines..." -ForegroundColor Gray
    $stigSettings = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($syncResult.StigPath -and (Test-Path $syncResult.StigPath)) {
        $parsed = Import-BaselineFolder -Path $syncResult.StigPath
        foreach ($p in $parsed) { $stigSettings.Add($p) }
        Write-Host "    $($syncResult.StigPath) : $($parsed.Count) settings" -ForegroundColor DarkGray
    }

    Write-Host "`n  Microsoft settings: $($msSettings.Count)" -ForegroundColor Cyan
    Write-Host "  STIG settings     : $($stigSettings.Count)" -ForegroundColor Cyan

    # Merge
    Write-Host "`n  Merging baselines (conflict resolution: $ConflictResolution)..." -ForegroundColor Yellow
    $mergeResult = Merge-Baselines -MicrosoftSettings $msSettings -StigSettings $stigSettings `
        -ConflictResolution $ConflictResolution

    # Save master template
    Export-MasterTemplate -MasterSettings $mergeResult.MasterSettings -OutputFolder $mergeDir | Out-Null
    if ($mergeResult.Conflicts.Count -gt 0) {
        Export-ConflictReport -Conflicts $mergeResult.Conflicts -OutputFolder $mergeDir
    }

    $masterSettings = $mergeResult.MasterSettings
}

if ($Mode -eq 'MergeBaselines') {
    Write-Host "`nMerge complete. Master template at: $mergeDir" -ForegroundColor Green
    exit 0
}

#endregion

#region ── Step 3: Pull GPOs & build hierarchy ────────────────────────

if ($needsDomain) {
    Write-Host "`n═══ STEP 3: Pull GPOs & Build OU Hierarchy ════════════" -ForegroundColor White

    Import-Module (Join-Path $modulesDir 'GPOTreeBuilder.psm1') -Force -DisableNameChecking

    if (-not $SkipDomainCheck) {
        $hierarchy = Build-GPOHierarchy -DomainDnsName $DomainDnsName `
            -NameFilter $GpoNameFilter -NameRegex $GpoNameRegex

        Show-GPOTree -OUTree $hierarchy.OUTree
        Export-GPOTreeReport -Hierarchy $hierarchy -OutputFolder $hierDir

        # Export XML reports for comparison
        Write-Host "`n  Exporting GPO XML reports for comparison..." -ForegroundColor Gray
        $gpoReportMap = Export-GPOReportsForHierarchy -Hierarchy $hierarchy -OutputFolder $hierDir
    } else {
        Write-Host "  [skipped] Domain check skipped (-SkipDomainCheck)" -ForegroundColor DarkGray
    }
}

if ($Mode -eq 'PullHierarchy') {
    Write-Host "`nHierarchy pull complete. Reports at: $hierDir" -ForegroundColor Green
    exit 0
}

#endregion

#region ── Step 4: Compare GPOs vs master template ────────────────────

if ($Mode -in @('Full','CompareOnly') -and -not $SkipDomainCheck) {
    Write-Host "`n═══ STEP 4: Compare GPOs Against Master Template ══════" -ForegroundColor White

    # Load master template if not in memory
    if (-not $masterSettings) {
        $jsonPath = Join-Path $mergeDir 'MasterTemplate.json'
        if (Test-Path $jsonPath) {
            $masterSettings = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
            Write-Host "  Loaded master template: $($masterSettings.Count) settings" -ForegroundColor Gray
        } else {
            Write-Warning "Master template not found. Run mode MergeBaselines first."
            exit 1
        }
    }

    $compResult = Compare-HierarchyToBaseline -MasterSettings $masterSettings `
        -Hierarchy $hierarchy -GpoReportMap $gpoReportMap

    Show-DiffSummary -Diffs $compResult.AllDiffs
    Export-DiffReport -Diffs $compResult.AllDiffs -OutputFolder $diffDir
}

if ($Mode -eq 'CompareOnly') {
    Write-Host "`nComparison complete. Reports at: $diffDir" -ForegroundColor Green
    exit 0
}

#endregion

#region ── Step 5: Interactive diff review ────────────────────────────

if ($Mode -in @('Full','ReviewOnly')) {
    Write-Host "`n═══ STEP 5: Interactive Diff Review ═══════════════════" -ForegroundColor White

    # Load diffs
    $diffsToReview = $null
    if ($Mode -eq 'ReviewOnly' -or -not $compResult) {
        $diffJsonPath = Join-Path $diffDir 'DiffReport.json'
        if (Test-Path $diffJsonPath) {
            $diffsToReview = Get-Content -Path $diffJsonPath -Raw | ConvertFrom-Json
            Write-Host "  Loaded diff report: $($diffsToReview.Count) entries" -ForegroundColor Gray
        } else {
            Write-Warning "No diff report found at $diffJsonPath. Run CompareOnly first."
            exit 1
        }
    } else {
        $diffsToReview = $compResult.AllDiffs
    }

    $reviewedDiffs = Start-DiffReview -Diffs $diffsToReview -ReviewManifestPath $reviewPath

    # Generate HTML report
    $htmlPath = Join-Path $diffDir 'DiffReviewReport.html'
    Export-DiffReviewHtml -Diffs $reviewedDiffs -OutputPath $htmlPath
}

if ($Mode -eq 'ReviewOnly') {
    Write-Host "`nReview complete. Manifest at: $reviewPath" -ForegroundColor Green
    exit 0
}

#endregion

#region ── Step 6: Export remediated GPOs ──────────────────────────────

if ($Mode -in @('Full','ExportOnly')) {
    Write-Host "`n═══ STEP 6: Export Remediated GPO Backups ═════════════" -ForegroundColor White

    # Load reviewed diffs
    if ($Mode -eq 'ExportOnly' -or -not $reviewedDiffs) {
        if (Test-Path $reviewPath) {
            $reviewedDiffs = Import-ReviewManifest -Path $reviewPath
        } else {
            Write-Warning "No review manifest found at $reviewPath. Run ReviewOnly first."
            exit 1
        }
    }

    # Load master template if needed
    if (-not $masterSettings) {
        $jsonPath = Join-Path $mergeDir 'MasterTemplate.json'
        if (Test-Path $jsonPath) {
            $masterSettings = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
        } else {
            Write-Warning "Master template not found. Run MergeBaselines first."
            exit 1
        }
    }

    $backups = Export-RemediatedGPO -ReviewedDiffs $reviewedDiffs `
        -MasterSettings $masterSettings -OutputFolder $exportDir

    if ($backups.Count -gt 0) {
        Write-Host "`n  To import these GPOs into your domain, run:" -ForegroundColor White
        Write-Host "    $(Join-Path $exportDir 'Import-RemediatedGPOs.ps1')" -ForegroundColor Yellow
        Write-Host "  Or use Group Policy Management Console to import each backup manually.`n" -ForegroundColor Gray
    }
}

#endregion

#region ── Final summary ──────────────────────────────────────────────

Write-Host @"

 ╔══════════════════════════════════════════════════════════════╗
 ║                    AUDIT COMPLETE                           ║
 ╠══════════════════════════════════════════════════════════════╣
 ║  Output Folder  : $($OutputDir.PadRight(39))║
 ║  Baselines      : $($BaselineRoot.PadRight(39))║
 ║  Master Template: $(($mergeDir).PadRight(39))║
 ║  Diff Reports   : $($diffDir.PadRight(39))║
 ║  Exported GPOs  : $($exportDir.PadRight(39))║
 ╚══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Green

#endregion
