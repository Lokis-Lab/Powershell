Describe 'Get-DefenderMachinesWithSubnets script' {
    It 'parses without syntax errors' {
        { [void][System.Management.Automation.Language.Parser]::ParseFile(
                (Join-Path $PSScriptRoot 'Get-DefenderMachinesWithSubnets.ps1'),
                [ref]$null,
                [ref]$null) } | Should -Not -Throw
    }

    It 'aggregates paginated machine API values' {
        $items = [System.Collections.Generic.List[object]]::new()
        $pages = @(
            @{ value = @([PSCustomObject]@{ id = '1'; computerDnsName = 'a' }, [PSCustomObject]@{ id = '2'; computerDnsName = 'b' }); '@odata.nextLink' = 'page2' },
            @{ value = @([PSCustomObject]@{ id = '3'; computerDnsName = 'c' }); '@odata.nextLink' = $null }
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
}
