<#
.SYNOPSIS
  Downloads CVE records from the NVD API and stores them locally in CSV files.

.DESCRIPTION
  This script uses the NVD REST API to fetch CVE data in batches.  
  Results are stored in CSV files with a maximum of 1 million records per file.  
  Only CVEs published after December 31, 2005 are included.  
  Handles API rate limits (50 requests per 30 seconds).

.PARAMETER ApiKey
  Your NVD API key. Required for authenticated requests.

.PARAMETER CsvFolder
  Destination folder for CSV files. Default: C:\Reports\CVERepo

.EXAMPLE
  .\Build-CVELocalRepository.ps1 -ApiKey "<YOUR_API_KEY>" -CsvFolder "C:\Data\CVERepo"

.NOTES
  - Requires a valid API key from NVD (https://nvd.nist.gov/developers/request-an-api-key).
  - Respects NVD API rate limits.
#>

param(
  [Parameter(Mandatory=$true)][string]$ApiKey,  
  [string]$CsvFolder = "C:\Reports\CVERepo"
)

# --- API Base URL
$BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# --- Function: Fetch CVE records
function Fetch-CVERecords {
    param([int]$StartIndex = 0)

    $Headers = @{ "apiKey" = $ApiKey }
    $Params  = @{ "startIndex" = $StartIndex; "resultsPerPage" = 2000 }

    try {
        return Invoke-RestMethod -Uri $BASE_URL -Headers $Headers -Method Get -Body $Params
    } catch {
        Write-Warning "Error fetching data at index ${StartIndex}: $($_.Exception.Message)"
        return $null
    }
}

# --- Function: Store CVEs to CSV (split by 1M rows)
function Get-CveSyncStatePath {
    param([Parameter(Mandatory)][string]$CsvFolder)
    Join-Path $CsvFolder '.cve_sync_state.json'
}

function Read-CveSyncState {
    param([Parameter(Mandatory)][string]$CsvFolder)

    $path = Get-CveSyncStatePath -CsvFolder $CsvFolder
    if (-not (Test-Path -LiteralPath $path)) {
        return [pscustomobject]@{ startIndex = 0; totalResults = $null }
    }

    try {
        $state = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        return [pscustomobject]@{
            startIndex    = [int]$state.startIndex
            totalResults  = if ($null -ne $state.totalResults) { [int]$state.totalResults } else { $null }
        }
    } catch {
        Write-Warning "Ignoring invalid CVE sync state at ${path}: $($_.Exception.Message)"
        return [pscustomobject]@{ startIndex = 0; totalResults = $null }
    }
}

function Write-CveSyncState {
    param(
        [Parameter(Mandatory)][string]$CsvFolder,
        [Parameter(Mandatory)][int]$StartIndex,
        [Parameter(Mandatory)][int]$TotalResults
    )

    $obj = [ordered]@{
        startIndex   = $StartIndex
        totalResults = $TotalResults
        updatedAt    = (Get-Date).ToString('o')
    }
    $obj | ConvertTo-Json | Set-Content -LiteralPath (Get-CveSyncStatePath -CsvFolder $CsvFolder) -Encoding utf8
}

function Clear-CveSyncState {
    param([Parameter(Mandatory)][string]$CsvFolder)
    Remove-Item -LiteralPath (Get-CveSyncStatePath -CsvFolder $CsvFolder) -Force -ErrorAction SilentlyContinue
}

function Store-CVEInCSV {
    param(
        [Parameter(Mandatory=$true)][PSObject]$CVERecords,
        [string]$CsvFolder
    )

    if (-not (Test-Path -Path $CsvFolder)) {
        New-Item -Path $CsvFolder -ItemType Directory | Out-Null
    }

    $csvIndex = 1
    $currentCsvPath = $null
    $recordCount = 0

    function Get-CsvRecordCount {
        param([Parameter(Mandatory=$true)][string]$Path)
        $rows = Import-Csv -Path $Path
        if ($null -eq $rows) { return 0 }
        return @($rows).Count
    }

    while ($true) {
        $currentCsvPath = Join-Path $CsvFolder "cve_repository_$csvIndex.csv"

        if (-not (Test-Path -Path $currentCsvPath)) {
            "id,published_date" | Out-File -FilePath $currentCsvPath -Encoding utf8
            $recordCount = 0
            break
        }

        $recordCount = Get-CsvRecordCount -Path $currentCsvPath
        if ($recordCount -lt 1000000) {
            break
        }

        $csvIndex++
    }

    foreach ($cve in $CVERecords.vulnerabilities) {
        $cveId = $cve.cve.id
        $publishedDate = $cve.cve.published

        if ([datetime]$publishedDate -gt [datetime]"2005-12-31") {
            if ($recordCount -ge 1000000) {
                do {
                    $csvIndex++
                    $currentCsvPath = Join-Path $CsvFolder "cve_repository_$csvIndex.csv"
                    if (-not (Test-Path -Path $currentCsvPath)) {
                        "id,published_date" | Out-File -FilePath $currentCsvPath -Encoding utf8
                        $recordCount = 0
                    } else {
                        $recordCount = Get-CsvRecordCount -Path $currentCsvPath
                    }
                } while ($recordCount -ge 1000000)
            }

            "$cveId,$publishedDate" | Add-Content -Path $currentCsvPath
            Write-Host "Stored CVE $cveId ($publishedDate)"
            $recordCount++
        }
    }
}

# --- Function: Build local CVE repository
function Create-LocalCVERepository {
    $state = Read-CveSyncState -CsvFolder $CsvFolder
    $startIndex = $state.startIndex
    $totalResults = if ($state.totalResults) { [int]$state.totalResults } else { 1 }
    $requestCount = 0

    if ($state.totalResults -and $startIndex -ge $totalResults) {
        Write-Host "CVE repository already synced ($startIndex / $totalResults records). Delete CSV files and .cve_sync_state.json to rebuild." -ForegroundColor Green
        return
    }

    while ($startIndex -lt $totalResults) {
        if ($requestCount -ge 50) {
            Write-Host "Rate limit reached. Sleeping 30s..." -ForegroundColor Yellow
            Start-Sleep -Seconds 30
            $requestCount = 0
        }

        $cveData = Fetch-CVERecords -StartIndex $startIndex
        if (-not $cveData) {
            throw "Failed to fetch CVE records at startIndex ${startIndex}. Sync state preserved for resume."
        }

        $pageCount = @($cveData.vulnerabilities).Count
        if ($pageCount -eq 0) {
            throw "NVD API returned zero vulnerabilities at startIndex ${startIndex} (totalResults=$($cveData.totalResults)). Aborting to avoid an infinite loop."
        }

        Store-CVEInCSV -CVERecords $cveData -CsvFolder $CsvFolder

        $totalResults = [int]$cveData.totalResults
        $startIndex += $pageCount
        Write-CveSyncState -CsvFolder $CsvFolder -StartIndex $startIndex -TotalResults $totalResults
        $requestCount++
        Start-Sleep -Seconds 1
    }

    Clear-CveSyncState -CsvFolder $CsvFolder
    Write-Host "CVE repository sync complete ($totalResults records)." -ForegroundColor Green
}

# --- Run
if ($MyInvocation.InvocationName -match '\.ps1$') {
    Create-LocalCVERepository
}
