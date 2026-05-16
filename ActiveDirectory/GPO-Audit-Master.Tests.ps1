Describe 'GPO-Audit-Master lazy AD dependency handling' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'GPO-Audit-Master.ps1'
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

  It 'opens the two-GPO compare picker without forcing the Active Directory module' {
    $functionAst = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Show-GpoCompareDialog'
    }, $true)

    $functionAst | Should -Not -BeNullOrEmpty

    $commandNames = @(
      $functionAst.Body.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst]
      }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ }
    )

    $commandNames | Should -Contain 'Get-GpoAuditGpoDomainSplat'
    $commandNames | Should -Contain 'Get-GPO'
    $commandNames | Should -Not -Contain 'Ensure-GpoAuditAdContextInitialized'
    $commandNames | Should -Not -Contain 'Initialize-GpoAuditAdContext'
  }

  It 'records an explicit GUI domain before showing the form without initializing AD' {
    $guiModeIf = @(
      $script:Ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.IfStatementAst] -and
          $node.Clauses.Count -gt 0 -and
          $node.Clauses[0].Item1.Extent.Text -like "*PSBoundParameters.ContainsKey('Mode')*"
      }, $true)
    ) | Select-Object -First 1

    $guiModeIf | Should -Not -BeNullOrEmpty

    $commandNames = @(
      $guiModeIf.Clauses[0].Item2.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst]
      }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ }
    )

    $commandNames[0] | Should -Be 'Set-GpoAuditRequestedDomain'
    $commandNames[1] | Should -Be 'Show-GpoAuditMasterMainGui'
    $commandNames | Should -Not -Contain 'Initialize-GpoAuditAdContext'
    $commandNames | Should -Not -Contain 'Ensure-GpoAuditAdContextInitialized'
  }
}

Describe 'AD-GPO-Audit-Master combined GUI option binding' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'AD-GPO-Audit-Master.ps1'
    $tokens = $null
    $parseErrors = $null
    $script:CombinedAst = [System.Management.Automation.Language.Parser]::ParseFile(
      $scriptPath,
      [ref]$tokens,
      [ref]$parseErrors
    )

    if ($parseErrors -and $parseErrors.Count -gt 0) {
      throw ($parseErrors | ForEach-Object { $_.Message } | Out-String)
    }
  }

  It 'uses the AD OU filter combo box state when running duplicate audits' {
    $functionAst = $script:CombinedAst.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Show-AdGpoAuditMasterMainGui'
    }, $true)

    $functionAst | Should -Not -BeNullOrEmpty

    $memberNames = @(
      $functionAst.Body.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.MemberExpressionAst]
      }, $true) | ForEach-Object {
        if ($_.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
          $_.Member.Value
        }
      } | Where-Object { $_ }
    )

    $memberNames | Should -Contain 'OuFilterCb'
    $memberNames | Should -Not -Contain 'OuFilterTb'
  }
}
