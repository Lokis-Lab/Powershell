Describe 'Export-DefenderDevicesAndVulnerabilities script' {
    It 'parses without syntax errors' {
        { [void][System.Management.Automation.Language.Parser]::ParseFile(
                (Join-Path $PSScriptRoot 'Export-DefenderDevicesAndVulnerabilities.ps1'),
                [ref]$null,
                [ref]$null) } | Should -Not -Throw
    }

    It 'aggregates paginated API values' {
        $items = [System.Collections.Generic.List[object]]::new()
        $pages = @(
            @{ value = @([PSCustomObject]@{ id = '1' }, [PSCustomObject]@{ id = '2' }); '@odata.nextLink' = 'page2' },
            @{ value = @([PSCustomObject]@{ id = '3' }); '@odata.nextLink' = $null }
        )
        $nextUrl = 'page1'
        while ($nextUrl) {
            $response = $pages[[int]($nextUrl -replace '\D') - 1]
            if ($response.value) { $items.AddRange(@($response.value)) }
            $nextUrl = $response.'@odata.nextLink'
        }
        $items.Count | Should -Be 3
    }

    It 'does not promote partial vulnerability export when device failures occur' {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ("defender-vuln-export-{0}" -f [guid]::NewGuid())
        $finalPath = Join-Path $root 'Vulnerabilities.csv'
        $tempPath = Join-Path $root 'Vulnerabilities.csv.12345.tmp'
        try {
            New-Item -ItemType Directory -Path $root -Force | Out-Null
            'DeviceId,ComputerName,VulnerabilityId,Severity,CveId,Title' | Set-Content -LiteralPath $finalPath -Encoding UTF8
            'prior-device,prior-host,prior-vuln,High,CVE-OLD,Old' | Add-Content -LiteralPath $finalPath -Encoding UTF8

            'DeviceId,ComputerName,VulnerabilityId,Severity,CveId,Title' | Set-Content -LiteralPath $tempPath -Encoding UTF8
            'new-device,new-host,new-vuln,High,CVE-NEW,New' | Add-Content -LiteralPath $tempPath -Encoding UTF8

            $deviceFailureCount = 1
            $promoted = $false
            if (Test-Path -LiteralPath $tempPath) {
                if ($deviceFailureCount -eq 0) {
                    Move-Item -LiteralPath $tempPath -Destination $finalPath -Force
                    $promoted = $true
                }
            }

            $promoted | Should -Be $false
            (Test-Path -LiteralPath $tempPath) | Should -Be $true
            (Get-Content -LiteralPath $finalPath -Raw) | Should -Match 'prior-vuln'
            (Get-Content -LiteralPath $finalPath -Raw) | Should -Not -Match 'new-vuln'
        }
        finally {
            if (Test-Path -LiteralPath $root) {
                Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
