Describe 'Create-LocalCVERepository pagination guards' {
  It 'throws when a fetch returns null instead of silently exiting' {
    function Fetch-CVERecords { param([int]$StartIndex = 0) return $null }
    function Store-CVEInCSV { param($CVERecords, $CsvFolder) }

    {
      $startIndex = 0
      $totalResults = 100
      $cveData = Fetch-CVERecords -StartIndex $startIndex
      if (-not $cveData) {
        throw "Failed to fetch CVE data at startIndex $startIndex. Sync aborted to avoid an incomplete repository."
      }
    } | Should -Throw '*Sync aborted*'
  }

  It 'throws when an empty page would stall pagination' {
  {
      $startIndex = 0
      $totalResults = 100
      $cveData = [pscustomobject]@{
        totalResults = $totalResults
        vulnerabilities = @()
      }
      $pageCount = @($cveData.vulnerabilities).Count
      if ($pageCount -eq 0 -and $startIndex -lt $totalResults) {
        throw "NVD returned zero vulnerabilities at startIndex $startIndex while $totalResults total results remain. Sync aborted."
      }
    } | Should -Throw '*Sync aborted*'
  }
}
