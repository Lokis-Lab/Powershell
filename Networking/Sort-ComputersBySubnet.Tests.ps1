Describe 'Sort-ComputersBySubnet scalar CSV handling' {
  It 'parses without syntax errors' {
    { [void][System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $PSScriptRoot 'Sort-ComputersBySubnet.ps1'),
        [ref]$null,
        [ref]$null) } | Should -Not -Throw
  }

  It 'wraps Import-Csv results in arrays to avoid property-wise iteration on single-row CSVs' {
    $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Sort-ComputersBySubnet.ps1') -Raw
    $source | Should -Match '\$computers\s*=\s*@\(Import-Csv\s+-Path\s+\$ComputersFile\)'
    $source | Should -Match '\$subnets\s*=\s*@\(Import-Csv\s+-Path\s+\$SubnetsFile\)'
    $source | Should -Match '\$matchingSubnet\s*=\s*@\(\$subnets\s*\|\s*Where-Object'
  }
}
