Describe 'Build-CVELocalRepository sync guards' {
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
  }

  It 'aborts when the destination folder already contains CVE records' {
    $functionAst = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Create-LocalCVERepository'
    }, $true)

    $functionAst | Should -Not -BeNullOrEmpty
    $functionAst.Body.Extent.Text | Should -Match 'Get-ExistingCveRecordCount'
    $functionAst.Body.Extent.Text | Should -Match 'already contains records'
  }

  It 'throws on fetch failure instead of silently exiting with partial data' {
    $functionAst = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Create-LocalCVERepository'
    }, $true)

    $functionAst.Body.Extent.Text | Should -Match 'Failed to fetch CVE data'
    $functionAst.Body.Extent.Text | Should -Not -Match 'if \(-not \$cveData\) \{ break \}'
  }

  It 'guards against an infinite loop when the API returns an empty page' {
    $functionAst = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Create-LocalCVERepository'
    }, $true)

    $functionAst.Body.Extent.Text | Should -Match '\$pageCount\s*=\s*@\(\$cveData\.vulnerabilities\)\.Count'
    $functionAst.Body.Extent.Text | Should -Match 'empty vulnerabilities page'
  }
}

Describe 'Get-ExistingCveRecordCount row counting' {
  BeforeAll {
    function script:Get-ExistingCveRecordCountForTest {
      param([string]$CsvFolder)

      $total = 0
      $csvIndex = 1
      while ($true) {
        $path = Join-Path $CsvFolder "cve_repository_$csvIndex.csv"
        if (-not (Test-Path -Path $path)) { break }
        $rows = Import-Csv -Path $path -ErrorAction SilentlyContinue
        if ($rows) { $total += @($rows).Count }
        $csvIndex++
      }
      return $total
    }
  }

  It 'counts rows across numbered CSV files' {
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ("cve-count-test-{0}" -f [guid]::NewGuid())
    try {
      New-Item -ItemType Directory -Path $root -Force | Out-Null
      "id,published_date`nCVE-2024-0001,2024-01-01" | Set-Content -LiteralPath (Join-Path $root 'cve_repository_1.csv') -Encoding utf8
      "id,published_date`nCVE-2024-0002,2024-01-02`nCVE-2024-0003,2024-01-03" | Set-Content -LiteralPath (Join-Path $root 'cve_repository_2.csv') -Encoding utf8

      Get-ExistingCveRecordCountForTest -CsvFolder $root | Should -Be 3
    } finally {
      if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }
}
