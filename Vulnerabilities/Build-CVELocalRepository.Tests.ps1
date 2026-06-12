BeforeAll {
  . (Join-Path $PSScriptRoot 'Build-CVELocalRepository.ps1') -ApiKey 'test-key'
}

Describe 'Get-CvePageCount' {
  It 'returns 0 when vulnerabilities is null' {
    Get-CvePageCount -CveData ([pscustomobject]@{ vulnerabilities = $null }) | Should -Be 0
  }

  It 'returns the number of vulnerabilities on the page' {
    $cveData = [pscustomobject]@{
      vulnerabilities = @(
        [pscustomobject]@{ cve = [pscustomobject]@{ id = 'CVE-1'; published = '2006-01-01' } }
        [pscustomobject]@{ cve = [pscustomobject]@{ id = 'CVE-2'; published = '2006-01-02' } }
      )
    }
    Get-CvePageCount -CveData $cveData | Should -Be 2
  }
}

Describe 'Assert-CveFetchPage' {
  It 'throws when the API returns an empty page before totalResults is reached' {
    $cveData = [pscustomobject]@{
      totalResults = 100
      vulnerabilities = @()
    }

    { Assert-CveFetchPage -CveData $cveData -StartIndex 50 } | Should -Throw '*empty page*'
  }

  It 'throws when the API returns no data' {
    { Assert-CveFetchPage -CveData $null -StartIndex 0 } | Should -Throw '*Failed to fetch CVE records*'
  }

  It 'returns the page count for a valid page' {
    $cveData = [pscustomobject]@{
      totalResults = 100
      vulnerabilities = @(
        [pscustomobject]@{ cve = [pscustomobject]@{ id = 'CVE-1'; published = '2006-01-01' } }
      )
    }

    Assert-CveFetchPage -CveData $cveData -StartIndex 0 | Should -Be 1
  }
}
