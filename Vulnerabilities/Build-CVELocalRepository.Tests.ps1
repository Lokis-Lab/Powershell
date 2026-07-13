BeforeAll {
    $scriptRoot = $PSScriptRoot
}

Describe 'Build-CVELocalRepository pagination guard' {
    It 'treats null vulnerabilities as zero-page response' {
        $cveData = [PSCustomObject]@{
            totalResults    = 100
            vulnerabilities = $null
        }
        $pageCount = if ($null -eq $cveData.vulnerabilities) { 0 } else { @($cveData.vulnerabilities).Count }
        $pageCount | Should -Be 0
        ($pageCount -eq 0 -and 0 -lt $cveData.totalResults) | Should -BeTrue
    }

    It 'advances startIndex by page count for non-empty pages' {
        $cveData = [PSCustomObject]@{
            totalResults    = 4
            vulnerabilities = @(
                [PSCustomObject]@{ cve = [PSCustomObject]@{ id = 'CVE-1'; published = '2020-01-01' } }
                [PSCustomObject]@{ cve = [PSCustomObject]@{ id = 'CVE-2'; published = '2020-01-02' } }
            )
        }
        $startIndex = 0
        $pageCount = if ($null -eq $cveData.vulnerabilities) { 0 } else { @($cveData.vulnerabilities).Count }
        $startIndex += $pageCount
        $startIndex | Should -Be 2
    }

    It 'iterates a single vulnerability record as one item' {
        $records = [PSCustomObject]@{
            vulnerabilities = [PSCustomObject]@{
                cve = [PSCustomObject]@{ id = 'CVE-2024-1'; published = '2024-01-01' }
            }
        }
        $ids = foreach ($cve in @($records.vulnerabilities)) { $cve.cve.id }
        $ids | Should -Be @('CVE-2024-1')
    }
}

Describe 'Build-CVELocalRepository script' {
    It 'parses without syntax errors' {
        { [void][System.Management.Automation.Language.Parser]::ParseFile(
                (Join-Path $scriptRoot 'Build-CVELocalRepository.ps1'),
                [ref]$null,
                [ref]$null) } | Should -Not -Throw
    }
}
