Describe 'Get-MFAUserReport-Graph script' {
  It 'parses without syntax errors' {
    { [void][System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $PSScriptRoot 'Get-MFAUserReport-Graph.ps1'),
        [ref]$null,
        [ref]$null) } | Should -Not -Throw
  }

  It 'only marks MFA enabled for registered MFA method types' {
    $scriptPath = Join-Path $PSScriptRoot 'Get-MFAUserReport-Graph.ps1'
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)

    $foreachAst = $ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.ForEachStatementAst] -and
        $node.Condition.Extent.Text -match '\$methods'
    }, $true)

    $foreachAst | Should -Not -BeNullOrEmpty
    $loopBody = $foreachAst.Body.Extent.Text

    $loopBody | Should -Match '#microsoft\.graph\.microsoftAuthenticatorAuthenticationMethod'
    $loopBody | Should -Match '\$MFAState\s*=\s*"Enabled"'
    $loopBody | Should -Not -Match 'if\s*\(\s*\$methods\s*\)\s*\{[^\}]*\$MFAState\s*=\s*"Enabled"'
  }
}
