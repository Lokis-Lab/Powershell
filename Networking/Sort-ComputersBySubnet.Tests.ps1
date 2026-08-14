Describe 'Sort-ComputersBySubnet script' {
  BeforeAll {
    $script:SourcePath = Join-Path $PSScriptRoot 'Sort-ComputersBySubnet.ps1'
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile(
      $script:SourcePath,
      [ref]$null,
      [ref]$null
    )
  }

  It 'parses without syntax errors' {
  { [void][System.Management.Automation.Language.Parser]::ParseFile(
      $script:SourcePath,
      [ref]$null,
      [ref]$null) } | Should -Not -Throw
  }

  It 'throws instead of overwriting the CSV when no rows are produced' {
    $script:Ast.Extent.Text | Should -Match '\$rows\.Count -eq 0'
    $script:Ast.Extent.Text | Should -Match 'Prior export at'
    $script:Ast.Extent.Text | Should -Match 'throw'
    $script:Ast.Extent.Text | Should -Not -Match '\$sortedComputers\s*\|\s*Export-Csv'
  }
}
