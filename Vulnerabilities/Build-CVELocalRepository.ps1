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

    function Set-WritableCsvTarget {
        while ($true) {
            $currentCsvPath = Join-Path $CsvFolder "cve_repository_$csvIndex.csv"

            if (-not (Test-Path -Path $currentCsvPath)) {
                "id,published_date" | Out-File -FilePath $currentCsvPath -Encoding utf8
                $recordCount = 0
                return [pscustomobject]@{
                    Path  = $currentCsvPath
                    Count = $recordCount
                }
            }

            $recordCount = Get-CsvRecordCount -Path $currentCsvPath
            if ($recordCount -lt 1000000) {
                return [pscustomobject]@{
                    Path  = $currentCsvPath
                    Count = $recordCount
                }
            }

            $csvIndex++
        }
    }

    $target = Set-WritableCsvTarget
    $currentCsvPath = $target.Path
    $recordCount = $target.Count

    foreach ($cve in $CVERecords.vulnerabilities) {
        $cveId = $cve.cve.id
        $publishedDate = $cve.cve.published

        if ([datetime]$publishedDate -gt [datetime]"2005-12-31") {
            if ($recordCount -ge 1000000) {
                $csvIndex++
                $target = Set-WritableCsvTarget
                $currentCsvPath = $target.Path
                $recordCount = $target.Count
            }

            "$cveId,$publishedDate" | Add-Content -Path $currentCsvPath
            Write-Host "Stored CVE $cveId ($publishedDate)"
            $recordCount++
        }
    }
}

# --- Function: Build local CVE repository
function Create-LocalCVERepository {
    $startIndex = 0
    $totalResults = 1
    $requestCount = 0

    while ($startIndex -lt $totalResults) {
        if ($requestCount -ge 50) {
            Write-Host "Rate limit reached. Sleeping 30s..." -ForegroundColor Yellow
            Start-Sleep -Seconds 30
            $requestCount = 0
        }

        $cveData = Fetch-CVERecords -StartIndex $startIndex
        if (-not $cveData) { break }

        Store-CVEInCSV -CVERecords $cveData -CsvFolder $CsvFolder

        $totalResults = $cveData.totalResults
        $startIndex += $cveData.vulnerabilities.Count
        $requestCount++
        Start-Sleep -Seconds 1
    }
}

# --- Run
Create-LocalCVERepository
