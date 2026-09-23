Describe 'Invoke-AADConnectSync script' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Invoke-AADConnectSync.ps1'
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

  It 'parses without dollar-colon variable reference errors' {
    $parseErrors | Should -BeNullOrEmpty
  }

  It 'uses braced variable syntax before colons in error messages' {
    $script:Ast.Extent.Text | Should -Match '\$\{ServerName\}:'
  }

  It 'rethrows sync and scheduler failures so scheduled tasks do not treat errors as success' {
    $catchBlocks = $script:Ast.FindAll({
      param($node)
      $node -is [System.Management.Automation.Language.CatchClauseAst]
    }, $true)

    $catchBlocks.Count | Should -BeGreaterOrEqual 2
    foreach ($catch in $catchBlocks) {
      $catch.Body.Extent.Text | Should -Match 'throw'
    }
  }
}
