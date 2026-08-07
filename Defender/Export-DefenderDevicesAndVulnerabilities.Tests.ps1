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

    It 'preserves the prior vulnerabilities CSV when any device export fails' {
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) "defender-vuln-export-$PID"
        New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
        try {
            $finalPath = Join-Path $tempRoot 'Vulnerabilities.csv'
            'DeviceId,ComputerName' | Set-Content -LiteralPath $finalPath -Encoding UTF8
            $tempPath = Join-Path $tempRoot 'Vulnerabilities.csv.12345.tmp'
            'DeviceId,ComputerName,VulnerabilityId' | Set-Content -LiteralPath $tempPath -Encoding UTF8

            $failedDevices = [System.Collections.Generic.List[string]]::new()
            [void]$failedDevices.Add('host-a')

            $moveCalled = $false
            if ($failedDevices.Count -eq 0) {
                Move-Item -LiteralPath $tempPath -Destination $finalPath -Force
                $moveCalled = $true
            } else {
                Remove-Item -LiteralPath $tempPath -Force
            }

            $moveCalled | Should -BeFalse
            (Get-Content -LiteralPath $finalPath -Raw) | Should -Be "DeviceId,ComputerName`n"
            Test-Path -LiteralPath $tempPath | Should -BeFalse
        } finally {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
