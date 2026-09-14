Describe 'Get-ADPasswordExpiryReport script' {
  BeforeAll {
    $script:SourcePath = Join-Path $PSScriptRoot 'Get-ADPasswordExpiryReport.ps1'
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

  It 'throws instead of overwriting the CSV when no results are produced' {
    $script:Ast.Extent.Text | Should -Match '\$rows\.Count -eq 0'
    $script:Ast.Extent.Text | Should -Match 'Prior export at'
    $script:Ast.Extent.Text | Should -Match 'throw'
  }
}
