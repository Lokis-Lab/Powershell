Describe 'Build-CVELocalRepository sync state' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Build-CVELocalRepository.ps1'
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

    . $scriptPath -ApiKey 'unused-for-tests'
  }

  It 'persists and resumes sync progress across runs' {
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ("cve-sync-test-{0}" -f [guid]::NewGuid())
    try {
      New-Item -Path $root -ItemType Directory | Out-Null
      Write-CveSyncState -CsvFolder $root -StartIndex 4000 -TotalResults 10000
      $state = Read-CveSyncState -CsvFolder $root
      $state.startIndex | Should -Be 4000
      $state.totalResults | Should -Be 10000
    } finally {
      Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'aborts when the API returns an empty page instead of looping forever' {
    $functionAst = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Create-LocalCVERepository'
    }, $true)

    $functionAst | Should -Not -BeNullOrEmpty
    $functionAst.Body.Extent.Text | Should -Match 'pageCount\s*=\s*@\(\$cveData\.vulnerabilities\)\.Count'
    $functionAst.Body.Extent.Text | Should -Match 'if\s*\(\$pageCount\s*-eq\s*0\)'
    $functionAst.Body.Extent.Text | Should -Match 'Write-CveSyncState'
  }
}
