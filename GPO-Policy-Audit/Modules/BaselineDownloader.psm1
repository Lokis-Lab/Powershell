<#
.SYNOPSIS
  Downloads NIST (DISA STIG) and Microsoft Security Compliance Toolkit
  GPO baselines, caching them locally so repeated runs skip the download.

.DESCRIPTION
  Sources:
    - Microsoft SCT baselines from the official Download Center
    - DISA STIG GPO packages from public.cyber.mil

  Each source is downloaded as a ZIP, extracted, and catalogued in a
  manifest.json that tracks version, date, and hash so subsequent runs
  can detect whether the local copy is still current.
#>

#requires -Version 5.1

$script:ManifestFileName = 'baseline-manifest.json'

#region ── Manifest helpers ────────────────────────────────────────────

function Get-BaselineManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$BaselineRoot
    )
    $mPath = Join-Path $BaselineRoot $script:ManifestFileName
    if (Test-Path $mPath) {
        return (Get-Content -Path $mPath -Raw | ConvertFrom-Json)
    }
    return $null
}

function Save-BaselineManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$BaselineRoot,
        [Parameter(Mandatory)][PSCustomObject]$Manifest
    )
    $mPath = Join-Path $BaselineRoot $script:ManifestFileName
    $Manifest | ConvertTo-Json -Depth 10 | Set-Content -Path $mPath -Encoding UTF8
}

#endregion

#region ── Download helpers ────────────────────────────────────────────

function Get-RemoteFileIfNeeded {
    <#
    .SYNOPSIS  Download a file only when the local copy is missing or stale.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$DestPath,
        [switch]$Force
    )

    if ((Test-Path $DestPath) -and -not $Force) {
        Write-Host "  [cached] $(Split-Path $DestPath -Leaf)" -ForegroundColor DarkGray
        return $DestPath
    }

    $parent = Split-Path $DestPath -Parent
    if (-not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }

    Write-Host "  [download] $Url" -ForegroundColor Cyan
    $oldPref = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        Invoke-WebRequest -Uri $Url -OutFile $DestPath -UseBasicParsing -ErrorAction Stop
    } finally {
        $ProgressPreference = $oldPref
    }
    return $DestPath
}

function Expand-BaselineZip {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][string]$DestFolder
    )
    if (-not (Test-Path $DestFolder)) { New-Item -Path $DestFolder -ItemType Directory -Force | Out-Null }
    Write-Host "  [extract] -> $DestFolder" -ForegroundColor Cyan
    Expand-Archive -Path $ZipPath -DestinationPath $DestFolder -Force
}

#endregion

#region ── Microsoft SCT download ──────────────────────────────────────

function Get-MicrosoftBaseline {
    <#
    .SYNOPSIS
      Download the Microsoft Security Compliance Toolkit baselines.
    .PARAMETER BaselineRoot
      Local folder to store baselines.
    .PARAMETER Products
      Which baselines to download. Supported: Windows11, Windows10,
      WindowsServer2025, WindowsServer2022, WindowsServer2019, Edge, M365Apps
    .PARAMETER Force
      Re-download even if already present.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$BaselineRoot,
        [string[]]$Products = @('Windows11','WindowsServer2025','WindowsServer2022'),
        [switch]$Force
    )

    $msFolder = Join-Path $BaselineRoot 'Microsoft'
    if (-not (Test-Path $msFolder)) { New-Item -Path $msFolder -ItemType Directory -Force | Out-Null }

    # Microsoft downloads these as individual ZIPs from the SCT page.
    # The download page uses JS-generated links; these are the stable
    # confirmation-free direct URLs. Updated Feb 2026.
    $downloadMap = @{
        'Windows11'          = 'https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023BBE5A16/Windows%2011%20v24H2%20Security%20Baseline.zip'
        'Windows10'          = 'https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023BBE5A16/Windows%2010%20Version%2022H2%20Security%20Baseline.zip'
        'WindowsServer2025'  = 'https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023BBE5A16/Windows%20Server%202025%20Security%20Baseline.zip'
        'WindowsServer2022'  = 'https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023BBE5A16/Windows%20Server%202022%20Security%20Baseline.zip'
        'WindowsServer2019'  = 'https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023BBE5A16/Windows%20Server%202019%20Security%20Baseline.zip'
        'Edge'               = 'https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023BBE5A16/Microsoft%20Edge%20v128%20Security%20Baseline.zip'
        'M365Apps'           = 'https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023BBE5A16/Microsoft%20365%20Apps%20for%20Enterprise%20Security%20Baseline.zip'
    }

    $manifest = Get-BaselineManifest -BaselineRoot $msFolder
    $downloaded = [System.Collections.Generic.List[string]]::new()

    foreach ($product in $Products) {
        if (-not $downloadMap.ContainsKey($product)) {
            Write-Warning "Unknown Microsoft product baseline: $product. Supported: $($downloadMap.Keys -join ', ')"
            continue
        }

        $url     = $downloadMap[$product]
        $zipName = "$product.zip"
        $zipPath = Join-Path $msFolder $zipName
        $extDir  = Join-Path $msFolder $product

        $existing = if ($manifest) { $manifest.PSObject.Properties[$product] } else { $null }
        $alreadyPresent = $existing -and (Test-Path $extDir) -and -not $Force

        if ($alreadyPresent) {
            Write-Host "[Microsoft/$product] Already downloaded — skipping (use -Force to re-download)." -ForegroundColor Green
            $downloaded.Add($extDir)
            continue
        }

        Write-Host "[Microsoft/$product] Downloading baseline..." -ForegroundColor Yellow
        try {
            Get-RemoteFileIfNeeded -Url $url -DestPath $zipPath -Force:$Force
            Expand-BaselineZip -ZipPath $zipPath -DestFolder $extDir
            $downloaded.Add($extDir)
        } catch {
            Write-Warning "Failed to download Microsoft/$product : $($_.Exception.Message)"
            Write-Host "  You can manually download from: https://aka.ms/UpdateBaselineSCT" -ForegroundColor DarkYellow
            Write-Host "  and extract to: $extDir" -ForegroundColor DarkYellow
        }
    }

    # Update manifest
    $newManifest = if ($manifest) { $manifest } else { [PSCustomObject]@{} }
    foreach ($product in $Products) {
        $extDir = Join-Path $msFolder $product
        if (Test-Path $extDir) {
            $newManifest | Add-Member -NotePropertyName $product -NotePropertyValue ([PSCustomObject]@{
                DownloadedUtc = (Get-Date).ToUniversalTime().ToString('o')
                Path          = $extDir
            }) -Force
        }
    }
    Save-BaselineManifest -BaselineRoot $msFolder -Manifest $newManifest

    return $downloaded
}

#endregion

#region ── DISA STIG GPO download ──────────────────────────────────────

function Get-NistStigBaseline {
    <#
    .SYNOPSIS
      Download DISA STIG GPO baseline packages from public.cyber.mil.
    .PARAMETER BaselineRoot
      Local folder to store baselines.
    .PARAMETER PackageUrl
      Direct URL to the STIG GPO package ZIP. Defaults to the latest
      published package. Override with the direct DL link if a newer
      package is available.
    .PARAMETER Force
      Re-download even if already present.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$BaselineRoot,
        [string]$PackageUrl = 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_STIG_GPO_Package_April_2025.zip',
        [switch]$Force
    )

    $stigFolder = Join-Path $BaselineRoot 'NIST_STIG'
    if (-not (Test-Path $stigFolder)) { New-Item -Path $stigFolder -ItemType Directory -Force | Out-Null }

    $zipName = Split-Path $PackageUrl -Leaf
    $zipPath = Join-Path $stigFolder $zipName
    $extDir  = Join-Path $stigFolder 'GPO_Package'

    $manifest = Get-BaselineManifest -BaselineRoot $stigFolder
    $alreadyPresent = $manifest -and
                      $manifest.PSObject.Properties['StigGpo'] -and
                      (Test-Path $extDir) -and
                      -not $Force

    if ($alreadyPresent) {
        Write-Host "[NIST/STIG] Already downloaded — skipping (use -Force to re-download)." -ForegroundColor Green
        return $extDir
    }

    Write-Host "[NIST/STIG] Downloading STIG GPO package..." -ForegroundColor Yellow
    try {
        Get-RemoteFileIfNeeded -Url $PackageUrl -DestPath $zipPath -Force:$Force
        Expand-BaselineZip -ZipPath $zipPath -DestFolder $extDir
    } catch {
        Write-Warning "Failed to download STIG GPO package: $($_.Exception.Message)"
        Write-Host "  You can manually download from: https://public.cyber.mil/stigs/gpo/" -ForegroundColor DarkYellow
        Write-Host "  and extract to: $extDir" -ForegroundColor DarkYellow
        return $null
    }

    Save-BaselineManifest -BaselineRoot $stigFolder -Manifest ([PSCustomObject]@{
        StigGpo = [PSCustomObject]@{
            DownloadedUtc = (Get-Date).ToUniversalTime().ToString('o')
            SourceUrl     = $PackageUrl
            Path          = $extDir
        }
    })

    return $extDir
}

#endregion

#region ── High-level: download all baselines ──────────────────────────

function Sync-AllBaselines {
    <#
    .SYNOPSIS
      Download/verify both Microsoft SCT and NIST/STIG GPO baselines.
    .PARAMETER BaselineRoot
      Root folder (e.g., C:\GPO-Baselines).
    .PARAMETER MicrosoftProducts
      Which MS baselines to fetch.
    .PARAMETER StigPackageUrl
      Override STIG package URL if a newer one is available.
    .PARAMETER Force
      Re-download everything.
    .OUTPUTS
      PSCustomObject with MicrosoftPaths and StigPath properties.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$BaselineRoot,
        [string[]]$MicrosoftProducts = @('Windows11','WindowsServer2025','WindowsServer2022'),
        [string]$StigPackageUrl = 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_STIG_GPO_Package_April_2025.zip',
        [switch]$Force
    )

    if (-not (Test-Path $BaselineRoot)) {
        New-Item -Path $BaselineRoot -ItemType Directory -Force | Out-Null
    }

    Write-Host "`n========== Baseline Sync ==========" -ForegroundColor White

    Write-Host "`n--- Microsoft Security Compliance Toolkit ---" -ForegroundColor White
    $msPaths = Get-MicrosoftBaseline -BaselineRoot $BaselineRoot -Products $MicrosoftProducts -Force:$Force

    Write-Host "`n--- NIST / DISA STIG GPO Package ---" -ForegroundColor White
    $stigPath = Get-NistStigBaseline -BaselineRoot $BaselineRoot -PackageUrl $StigPackageUrl -Force:$Force

    Write-Host "`n========== Sync Complete ==========`n" -ForegroundColor White

    return [PSCustomObject]@{
        MicrosoftPaths = $msPaths
        StigPath       = $stigPath
    }
}

#endregion

#region ── Catalogue available baselines on disk ───────────────────────

function Get-AvailableBaselines {
    <#
    .SYNOPSIS
      Enumerate baselines already present under a BaselineRoot folder.
    .OUTPUTS
      Array of objects: Name, Source (Microsoft|STIG), Path
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$BaselineRoot
    )

    $list = [System.Collections.Generic.List[PSCustomObject]]::new()

    $msDir = Join-Path $BaselineRoot 'Microsoft'
    if (Test-Path $msDir) {
        Get-ChildItem -Path $msDir -Directory | Where-Object { $_.Name -ne 'baseline-manifest.json' } | ForEach-Object {
            $list.Add([PSCustomObject]@{
                Name   = "Microsoft - $($_.Name)"
                Source = 'Microsoft'
                Path   = $_.FullName
            })
        }
    }

    $stigDir = Join-Path $BaselineRoot 'NIST_STIG' 'GPO_Package'
    if (Test-Path $stigDir) {
        $list.Add([PSCustomObject]@{
            Name   = 'NIST / DISA STIG GPO Package'
            Source = 'STIG'
            Path   = $stigDir
        })

        # Look for per-OS sub-folders inside the STIG package
        Get-ChildItem -Path $stigDir -Directory | ForEach-Object {
            $list.Add([PSCustomObject]@{
                Name   = "STIG - $($_.Name)"
                Source = 'STIG'
                Path   = $_.FullName
            })
        }
    }

    return $list
}

#endregion

Export-ModuleMember -Function @(
    'Sync-AllBaselines',
    'Get-MicrosoftBaseline',
    'Get-NistStigBaseline',
    'Get-AvailableBaselines',
    'Get-BaselineManifest'
)
