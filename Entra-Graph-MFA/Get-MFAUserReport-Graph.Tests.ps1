Describe 'Get-MFAUserReport-Graph script' {
  BeforeAll {
    $script:SourcePath = Join-Path $PSScriptRoot 'Get-MFAUserReport-Graph.ps1'
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile(
      $script:SourcePath,
      [ref]$null,
      [ref]$null
    )

    $testIsMfa = $script:Ast.Find({
      $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $args[0].Name -eq 'Test-IsMfaAuthenticationMethod'
    }, $true)

    $getMfaMethods = $script:Ast.Find({
      $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $args[0].Name -eq 'Get-MfaAuthenticationMethods'
    }, $true)

    Invoke-Expression $testIsMfa.Extent.Text
    Invoke-Expression $getMfaMethods.Extent.Text
  }

  It 'parses without syntax errors' {
    { [void][System.Management.Automation.Language.Parser]::ParseFile(
        $script:SourcePath,
        [ref]$null,
        [ref]$null) } | Should -Not -Throw
  }

  It 'does not treat password or email authentication methods as MFA' {
    $password = [pscustomobject]@{
      AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.passwordAuthenticationMethod' }
    }
    $email = [pscustomobject]@{
      AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.emailAuthenticationMethod' }
    }
    $authenticator = [pscustomobject]@{
      AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' }
    }

    Test-IsMfaAuthenticationMethod $password | Should -BeFalse
    Test-IsMfaAuthenticationMethod $email | Should -BeFalse
    Test-IsMfaAuthenticationMethod $authenticator | Should -BeTrue
  }

  It 'filters non-MFA methods before setting MFAState' {
    $script:Ast.Extent.Text | Should -Match 'Get-MfaAuthenticationMethods -Methods \$methods'
    $script:Ast.Extent.Text | Should -Match '\$mfaMethods\.Count -gt 0'
    $script:Ast.Extent.Text | Should -Not -Match 'if\s*\(\s*\$methods\s*\)'
  }

  It 'throws instead of overwriting the CSV when no report rows are produced' {
    $script:Ast.Extent.Text | Should -Match '\$Report\.Count -eq 0'
    $script:Ast.Extent.Text | Should -Match 'Prior export at'
    $script:Ast.Extent.Text | Should -Match 'throw'
  }
}
