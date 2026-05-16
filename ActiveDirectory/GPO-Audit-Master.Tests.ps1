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

Describe 'Invoke-AfterHoursGpoPolicyAudit correctness guards' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Invoke-AfterHoursGpoPolicyAudit.ps1'
    $script:AfterHoursText = Get-Content -LiteralPath $scriptPath -Raw
    $tokens = $null
    $parseErrors = $null
    $script:AfterHoursAst = [System.Management.Automation.Language.Parser]::ParseFile(
      $scriptPath,
      [ref]$tokens,
      [ref]$parseErrors
    )

    if ($parseErrors -and $parseErrors.Count -gt 0) {
      throw ($parseErrors | ForEach-Object { $_.Message } | Out-String)
    }
  }

  It 'parses DN parents without splitting escaped commas inside OU names' {
    $functionAst = $script:AfterHoursAst.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Get-ParentDn'
    }, $true)

    $functionAst | Should -Not -BeNullOrEmpty
    Invoke-Expression $functionAst.Extent.Text

    Get-ParentDn -DistinguishedName 'OU=Child,OU=Legal\, Corp,DC=contoso,DC=com' |
      Should -Be 'OU=Legal\, Corp,DC=contoso,DC=com'
    Get-ParentDn -DistinguishedName 'OU=Legal\, Corp,OU=Parent,DC=contoso,DC=com' |
      Should -Be 'OU=Parent,DC=contoso,DC=com'
  }

  It 're-expands template ZIPs when the downloaded archive is newer than the marker' {
    $functionAst = $script:AfterHoursAst.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Expand-ZipIfNeeded'
    }, $true)

    $functionAst | Should -Not -BeNullOrEmpty
    $functionText = $functionAst.Extent.Text
    $functionText | Should -Match 'LastWriteTimeUtc'
    $functionText | Should -Match '\$zipUtc\s+-gt\s+\$markerUtc'
    $functionText | Should -Match 'Remove-Item\s+-Recurse\s+-Force'
  }

  It 'preserves disabled GPO links in the generated import helper' {
    $script:AfterHoursText | Should -Match '\$row\.Enabled'
    $script:AfterHoursText | Should -Match '\$linkEnabled\s*=\s*''No'''
    $script:AfterHoursText | Should -Match 'New-GPLink[^\r\n]+-LinkEnabled\s+\$linkEnabled'
  }

  It 'attributes diff rows to scoped link containers instead of the target root' {
    $script:AfterHoursText | Should -Match '\$gpoLinks\s*=\s*@\(\$scopedLinks'
    $script:AfterHoursText | Should -Match '\$containerDn\s*='
    $script:AfterHoursText | Should -Not -Match 'Compare-MasterToGpoRows[^\r\n]+-ContainerDn\s+\$TargetContainerDn'
  }
}
