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

    $testHasGraphMethods = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Test-HasGraphMethods'
    }, $true)

    if (-not $testHasGraphMethods) {
      throw 'Test-HasGraphMethods was not found in Export-MFAStatusReport.ps1'
    }

    # Define the helper in this scope without executing the full Graph-connected script.
    Invoke-Expression $testHasGraphMethods.Extent.Text
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

  It 'guards Graph auth method counts against null (@($null).Count is 1)' {
    $getMfaEnabled = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Get-MFAEnabled'
    }, $true)

    $getMfaEnabled | Should -Not -BeNullOrEmpty
    $getMfaEnabled.Body.Extent.Text | Should -Match 'Test-HasGraphMethods\s+\$auth'
    $getMfaEnabled.Body.Extent.Text | Should -Match 'Test-HasGraphMethods\s+\$fido'
    $getMfaEnabled.Body.Extent.Text | Should -Match 'Test-HasGraphMethods\s+\$oath'
    $getMfaEnabled.Body.Extent.Text | Should -Match 'Test-HasGraphMethods\s+\$whfb'
    $getMfaEnabled.Body.Extent.Text | Should -Match 'Test-HasGraphMethods\s+\$tap'

    # Must not use the unsafe bare @($x).Count -gt 0 pattern on Graph results.
    $getMfaEnabled.Body.Extent.Text | Should -Not -Match 'if\s*\(\s*@\(\$(auth|fido|oath|whfb|tap)\)\.Count\s+-gt\s*0\s*\)'
  }

  It 'does not treat a null Graph method result as MFA-enabled' {
    # Documents the PowerShell gotcha this fix addresses.
    (@($null).Count -gt 0) | Should -BeTrue

    Test-HasGraphMethods $null | Should -BeFalse
    Test-HasGraphMethods @() | Should -BeFalse
  }

  It 'treats a single method object and a multi-item collection as present' {
    $one = [pscustomobject]@{ Id = 'method-1' }
    $many = @(
      [pscustomobject]@{ Id = 'method-1' },
      [pscustomobject]@{ Id = 'method-2' }
    )

    Test-HasGraphMethods $one | Should -BeTrue
    Test-HasGraphMethods $many | Should -BeTrue
  }

  It 'throws instead of overwriting reports when no users are resolved' {
    $script:Ast.Extent.Text | Should -Match '\$targetUsers\.Count -eq 0'
    $script:Ast.Extent.Text | Should -Match 'Prior reports at'
  }
}
