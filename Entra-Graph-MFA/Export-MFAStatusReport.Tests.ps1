Describe 'Export-MFAStatusReport script' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Export-MFAStatusReport.ps1'
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

  It 'escapes apostrophes in Graph sign-in OData filters' {
    $getLastSignIn = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Get-LastSignIn'
    }, $true)

    $getLastSignIn.Body.Extent.Text | Should -Match 'escapedUpn'
    $getLastSignIn.Body.Extent.Text | Should -Match "-replace"
  }

  It 'wraps imported UPNs in an array before foreach' {
    $script:Ast.Extent.Text | Should -Match '\$upns\s*=\s*@\('
  }
}
