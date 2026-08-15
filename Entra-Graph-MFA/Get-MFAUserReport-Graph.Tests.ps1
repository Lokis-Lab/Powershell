Describe 'Get-MFAUserReport-Graph script' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Get-MFAUserReport-Graph.ps1'
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

    $testIsMfa = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Test-IsMfaAuthenticationMethod'
    }, $true)

    $getMfaMethods = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Get-MfaAuthenticationMethods'
    }, $true)

    if (-not $testIsMfa) {
      throw 'Test-IsMfaAuthenticationMethod was not found in Get-MFAUserReport-Graph.ps1'
    }
    if (-not $getMfaMethods) {
      throw 'Get-MfaAuthenticationMethods was not found in Get-MFAUserReport-Graph.ps1'
    }

    Invoke-Expression $testIsMfa.Extent.Text
    Invoke-Expression $getMfaMethods.Extent.Text
  }

  It 'parses without syntax errors' {
    $parseErrors | Should -BeNullOrEmpty
  }

  It 'does not treat password-only auth as MFA-enabled' {
    $passwordOnly = [pscustomobject]@{
      AdditionalProperties = @{
        '@odata.type' = '#microsoft.graph.passwordAuthenticationMethod'
      }
    }

    Test-IsMfaAuthenticationMethod $passwordOnly | Should -BeFalse
    (Get-MfaAuthenticationMethods -Methods @($passwordOnly)).Count | Should -Be 0
  }

  It 'does not treat email-only auth as MFA-enabled' {
    $emailOnly = [pscustomobject]@{
      AdditionalProperties = @{
        '@odata.type' = '#microsoft.graph.emailAuthenticationMethod'
      }
    }

    Test-IsMfaAuthenticationMethod $emailOnly | Should -BeFalse
    (Get-MfaAuthenticationMethods -Methods @($emailOnly)).Count | Should -Be 0
  }

  It 'treats registered MFA method types as enabled' {
    $authenticator = [pscustomobject]@{
      AdditionalProperties = @{
        '@odata.type' = '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod'
      }
    }

    Test-IsMfaAuthenticationMethod $authenticator | Should -BeTrue
    (Get-MfaAuthenticationMethods -Methods @($authenticator)).Count | Should -Be 1
  }

  It 'requires a phone number for phone authentication methods' {
    $phoneWithoutNumber = [pscustomobject]@{
      PhoneNumber = $null
      AdditionalProperties = @{
        '@odata.type' = '#microsoft.graph.phoneAuthenticationMethod'
      }
    }
    $phoneWithNumber = [pscustomobject]@{
      PhoneNumber = '+15551234567'
      AdditionalProperties = @{
        '@odata.type' = '#microsoft.graph.phoneAuthenticationMethod'
      }
    }

    Test-IsMfaAuthenticationMethod $phoneWithoutNumber | Should -BeFalse
    Test-IsMfaAuthenticationMethod $phoneWithNumber | Should -BeTrue
  }

  It 'filters password/email methods before setting MFAState' {
    $userLoop = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.ForEachStatementAst] -and
        $node.Variable.Expression.Extent.Text -eq '$Users'
    }, $true)

    $userLoop | Should -Not -BeNullOrEmpty
    $userLoop.Body.Extent.Text | Should -Match 'Get-MfaAuthenticationMethods'
    $userLoop.Body.Extent.Text | Should -Match 'if\s*\(\s*\$mfaMethods\.Count\s+-gt\s*0\s*\)'
    $userLoop.Body.Extent.Text | Should -Not -Match 'if\s*\(\s*\$methods\s*\)'
  }
}
