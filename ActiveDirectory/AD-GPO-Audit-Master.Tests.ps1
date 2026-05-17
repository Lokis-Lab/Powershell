Describe 'AD-GPO-Audit-Master group inventory' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'AD-GPO-Audit-Master.ps1'
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

  It 'does not request the non-existent Enabled property from Get-ADGroup' {
    $functionAst = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Get-AdAuditGroupInventory'
    }, $true)

    $functionAst | Should -Not -BeNullOrEmpty

    $stringConstants = @(
      $functionAst.Body.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.StringConstantExpressionAst]
      }, $true) | ForEach-Object { $_.Value }
    )

    $stringConstants | Should -Contain 'GroupCategory'
    $stringConstants | Should -Not -Contain 'Enabled'
  }
}
