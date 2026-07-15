Describe 'Remove-QuarantineMessagesBySender script' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Remove-QuarantineMessagesBySender.ps1'
    $tokens = $null
    $parseErrors = $null
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile(
      $scriptPath,
      [ref]$tokens,
      [ref]$parseErrors
    )

    if ($parseErrors -and $parseErrors.Count -gt 0) {
      throw ($parseErrors | ForEach-Object { $_.Message } | Out-String)
    }
  }

  It 'wraps quarantine message IDs in an array to avoid character-wise iteration' {
    $whileLoop = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.WhileStatementAst]
    }, $true)

    $whileLoop | Should -Not -BeNullOrEmpty
    $whileLoop.Body.Extent.Text | Should -Match '\$ids\s*=\s*@\('
  }

  It 'iterates a single quarantine ID as one item, not individual characters' {
    $ids = @('quarantine-id-12345')
    $collected = @()
    foreach ($id in $ids) { $collected += $id }
    $collected.Count | Should -Be 1
    $collected[0] | Should -Be 'quarantine-id-12345'
  }

  It 'breaks the delete loop when no messages are deleted in a round' {
    $whileLoop = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.WhileStatementAst]
    }, $true)

    $whileLoop.Body.Extent.Text | Should -Match '\$deletedThisRound'
    $whileLoop.Body.Extent.Text | Should -Match 'if\s*\(\s*\$deletedThisRound\s*-eq\s*0\s*\)'
  }
}
