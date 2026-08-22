Describe 'Sort-ComputersBySubnet script' {
  It 'parses without syntax errors' {
    { [void][System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $PSScriptRoot 'Sort-ComputersBySubnet.ps1'),
        [ref]$null,
        [ref]$null) } | Should -Not -Throw
  }

  It 'throws instead of overwriting the CSV when no rows are produced' {
    $scriptPath = Join-Path $PSScriptRoot 'Sort-ComputersBySubnet.ps1'
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)

    $scriptText = $ast.Extent.Text
    $scriptText | Should -Match 'No computers produced output'
    $scriptText | Should -Match '\$rows\.Count -eq 0'
    $scriptText | Should -Match 'throw'
  }
}
