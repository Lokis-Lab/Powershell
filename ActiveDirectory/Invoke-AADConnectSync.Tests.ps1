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
}
