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

    $script:GetParsedFunctionAst = {
      param([Parameter(Mandatory)][string]$Name)
      $script:Ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
          $node.Name -eq $Name
      }, $true)
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

  It 'uses GPO GUIDs when naming and exporting XML reports' {
    Invoke-Expression (& $script:GetParsedFunctionAst -Name 'New-SafeName').Extent.Text
    Invoke-Expression (& $script:GetParsedFunctionAst -Name 'Get-GpoAuditExportFileName').Extent.Text

    $first = [pscustomobject]@{
      DisplayName = 'A B'
      Id          = [guid]'00000000-0000-0000-0000-000000000001'
    }
    $second = [pscustomobject]@{
      DisplayName = 'A_B'
      Id          = [guid]'00000000-0000-0000-0000-000000000002'
    }

    Get-GpoAuditExportFileName -Gpo $first | Should -Be '00000000-0000-0000-0000-000000000001_A_B.xml'
    Get-GpoAuditExportFileName -Gpo $second | Should -Be '00000000-0000-0000-0000-000000000002_A_B.xml'
    Get-GpoAuditExportFileName -Gpo $first | Should -Not -Be (Get-GpoAuditExportFileName -Gpo $second)

    $exportText = (& $script:GetParsedFunctionAst -Name 'Invoke-XmlExport').Extent.Text
    $exportText | Should -Match '-Guid\s+\$PSItem\.Id'
    $exportText | Should -Match '-Guid\s+\$g\.Id'
  }

  It 'flattens only provided current-run XML paths and reads the GPO name from XML' {
    $flattenText = (& $script:GetParsedFunctionAst -Name 'Invoke-FlattenXml').Extent.Text

    $flattenText | Should -Match '\[string\[\]\]\$XmlPath'
    $flattenText | Should -Match "PSBoundParameters\.ContainsKey\('XmlPath'\)"
    $flattenText | Should -Match 'Get-GpoDisplayNameFromReportXml'
    $flattenText | Should -Not -Match "-replace '_',' '"
  }

  It 'falls back to row fields when older flatten CSVs lack CanonicalNoGpo' {
    Invoke-Expression (& $script:GetParsedFunctionAst -Name 'Get-FlattenCanonicalNoGpo').Extent.Text

    $oldRow = [pscustomobject]@{
      Scope     = 'Computer'
      Extension = 'Security'
      Category  = 'AdvancedAudit'
      Setting   = 'Audit Logon'
    }
    $newRow = [pscustomobject]@{
      Scope          = 'Computer'
      Extension      = 'Security'
      Category       = 'AdvancedAudit'
      Setting        = 'Audit Logon'
      CanonicalNoGpo = 'Computer|Security|AdvancedAudit|Audit Logon'
    }

    Get-FlattenCanonicalNoGpo -Row $oldRow | Should -Be 'Computer|Security|AdvancedAudit|Audit Logon'
    Get-FlattenCanonicalNoGpo -Row $newRow | Should -Be 'Computer|Security|AdvancedAudit|Audit Logon'
  }
}
