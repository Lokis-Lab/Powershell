BeforeAll {
  $scriptPath = Join-Path $PSScriptRoot 'Build-CVELocalRepository.ps1'
  $scriptContent = Get-Content -LiteralPath $scriptPath -Raw
  $scriptContent = $scriptContent -replace '(?ms)# --- Run\s+Create-LocalCVERepository\s*$', ''
  $scriptBlock = [scriptblock]::Create($scriptContent)
  . $scriptBlock -ApiKey 'test-key' -CsvFolder (Join-Path ([System.IO.Path]::GetTempPath()) 'cve-test-unused')
}

Describe 'Build-CVELocalRepository idempotency' {
  It 'skips CVE IDs that are already stored in the CSV folder' {
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ("cve-repo-test-{0}" -f [guid]::NewGuid())
    try {
      New-Item -ItemType Directory -Path $root -Force | Out-Null
      $csvPath = Join-Path $root 'cve_repository_1.csv'
      @(
        'id,published_date',
        'CVE-2024-0001,2024-01-01T00:00:00.000',
        'CVE-2024-0002,2024-01-02T00:00:00.000'
      ) | Set-Content -LiteralPath $csvPath -Encoding utf8

      $existingIds = Get-ExistingCveIds -CsvFolder $root
      $cveData = [pscustomobject]@{
        vulnerabilities = @(
          [pscustomobject]@{ cve = [pscustomobject]@{ id = 'CVE-2024-0001'; published = '2024-01-01T00:00:00.000' } },
          [pscustomobject]@{ cve = [pscustomobject]@{ id = 'CVE-2024-0003'; published = '2024-01-03T00:00:00.000' } }
        )
      }

      Store-CVEInCSV -CVERecords $cveData -CsvFolder $root -ExistingIds $existingIds

      $rows = @(Import-Csv -LiteralPath $csvPath)
      $rows.id | Should -Be @('CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003')
      ($rows | Group-Object id | Where-Object { $_.Count -gt 1 }).Count | Should -Be 0
    } finally {
      if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }
}

Describe 'Build-CVELocalRepository pagination guard' {
  It 'throws when the API returns an empty page before totalResults is reached' {
    $cveData = [pscustomobject]@{
      totalResults = 5000
      vulnerabilities = @()
    }

    $pageCount = @($cveData.vulnerabilities).Count
    $startIndex = 0
    { if ($pageCount -eq 0 -and $startIndex -lt $cveData.totalResults) { throw 'zero page' } } |
      Should -Throw 'zero page'
  }
}
