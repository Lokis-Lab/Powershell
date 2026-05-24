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

  It 'uses the XML report display name for per-GPO flatten CSV paths' {
    $script:Ast.FindAll({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $true) | ForEach-Object {
      . ([scriptblock]::Create($_.Extent.Text))
    }

    $root = Join-Path ([System.IO.Path]::GetTempPath()) ("gpo-audit-master-test-{0}" -f ([guid]::NewGuid().ToString('N')))
    try {
      $exports = Join-Path $root 'Exports'
      New-Item -ItemType Directory -Path $exports -Force | Out-Null

      $displayName = 'SEC__Workstations'
      $safeName = New-SafeName $displayName
      $xmlPath = Join-Path $exports ("{0}.xml" -f $safeName)
      @"
<GPO>
  <Name>$displayName</Name>
  <Identifier>{11111111-1111-1111-1111-111111111111}</Identifier>
</GPO>
"@ | Set-Content -LiteralPath $xmlPath -Encoding UTF8

      Invoke-FlattenXml -OutDir $root

      $flattenDir = Join-Path $root 'Flattened'
      $expectedPath = Join-Path $flattenDir ("Flatten_{0}.csv" -f (New-SafeName $displayName))
      $collapsedPath = Join-Path $flattenDir 'Flatten_SEC_Workstations.csv'
      Test-Path -LiteralPath $expectedPath | Should -BeTrue
      Test-Path -LiteralPath $collapsedPath | Should -BeFalse

      $rows = @(Import-Csv -LiteralPath $expectedPath)
      $rows[0].GPO | Should -Be $displayName
    } finally {
      if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
      }
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
