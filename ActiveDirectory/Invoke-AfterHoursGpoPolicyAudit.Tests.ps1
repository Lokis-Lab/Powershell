Describe 'Invoke-AfterHoursGpoPolicyAudit safety checks' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Invoke-AfterHoursGpoPolicyAudit.ps1'
    $script:ScriptText = Get-Content -LiteralPath $scriptPath -Raw
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

  It 'parses successfully' {
    $script:Ast | Should -Not -BeNullOrEmpty
  }

  It 'clears and re-expands stale template ZIP extractions' {
    $functionAst = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Expand-ZipIfNeeded'
    }, $true)
    $functionAst | Should -Not -BeNullOrEmpty

    $functionText = $functionAst.Extent.Text
    $functionText | Should -Match 'Clear-DirectoryContents -Path \$DestinationFolder'
    $functionText | Should -Match '\$markerItem\.LastWriteTimeUtc -lt \$zipItem\.LastWriteTimeUtc'
    $functionText | Should -Match '\.LastWriteTimeUtc = \$zipItem\.LastWriteTimeUtc'
  }

  It 'removes old expanded template packages before syncing current selections' {
    $script:ScriptText | Should -Match 'Clear-DirectoryContents -Path \$microsoftExpandedFolder'
    $script:ScriptText | Should -Match 'Clear-DirectoryContents -Path \$nistExpandedFolder'
  }

  It 'tracks failed GPO report exports in the domain snapshot' {
    $functionAst = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Export-DomainHierarchySnapshot'
    }, $true)
    $functionAst | Should -Not -BeNullOrEmpty

    $functionText = $functionAst.Extent.Text
    $functionText | Should -Match '\$gpoReportFailures\.Add'
    $functionText | Should -Match 'FailedReports = @\(\$gpoReportFailures\)'
  }

  It 'aborts when any scoped GPO report is missing' {
    $script:ScriptText | Should -Match 'Missing-Scoped-GpoReports\.csv'
    $script:ScriptText | Should -Match 'Aborting instead of producing an incomplete audit'
  }

  It 'requires an explicit apply switch before generated bundle import mutates GPOs' {
    $script:ScriptText | Should -Match '\[switch\]\$Apply'
    $script:ScriptText | Should -Match 'This helper imports GPO backups and creates links'
    $script:ScriptText | Should -Match 'New-GPLink .* -ErrorAction Stop'
  }
}
