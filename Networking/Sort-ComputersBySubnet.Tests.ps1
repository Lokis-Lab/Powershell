Describe 'Sort-ComputersBySubnet script' {
  It 'parses without syntax errors' {
    { [void][System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $PSScriptRoot 'Sort-ComputersBySubnet.ps1'),
        [ref]$null,
        [ref]$null) } | Should -Not -Throw
  }

  It 'throws instead of overwriting the CSV when no parseable IP addresses are found' {
    $scriptPath = Join-Path $PSScriptRoot 'Sort-ComputersBySubnet.ps1'
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)

    $guardAst = $ast.EndBlock.Statements | Where-Object {
      $_.Extent.Text -match 'No computers with parseable IP addresses were found'
    }

    $guardAst | Should -Not -BeNullOrEmpty
    $guardAst.Extent.Text | Should -Match '\$sortedComputers'
    $guardAst.Extent.Text | Should -Match 'throw'
  }
}
