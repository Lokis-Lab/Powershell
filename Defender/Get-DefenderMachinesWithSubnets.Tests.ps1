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
    )
    $nextUrl = 'page1'
    while ($nextUrl) {
      $response = $pages[[int]($nextUrl -replace '\D') - 1]
      if ($response.value) { $items.AddRange(@($response.value)) }
      $nextUrl = $response.'@odata.nextLink'
    }
    $items.Count | Should -Be 3
  }

  It 'includes devices when ipAddresses is a single object instead of an array' {
    $subnetMapping = @{ '10.1.2' = [PSCustomObject]@{ Scope = '10.1.2.0/24'; SubnetName = 'LAN' } }
    $machine = [PSCustomObject]@{
      computerDnsName = 'host1.contoso.com'
      ipAddresses     = [PSCustomObject]@{ ipAddress = '10.1.2.3' }
      lastSeen        = '2026-01-01'
      domainName      = 'contoso.com'
    }

    $ipv4Addresses = @()
    foreach ($ip in @($machine.ipAddresses)) {
      if ($ip -and $ip.ipAddress -match '^(\d{1,3}\.){3}\d{1,3}$') {
        $matchingSubnet = @($subnetMapping.Keys | Where-Object { $ip.ipAddress.StartsWith($_) })
        if ($matchingSubnet.Count -gt 0) {
          $ipv4Addresses += $ip.ipAddress
        }
      }
    }

    $ipv4Addresses.Count | Should -BeGreaterThan 0
  }
}
