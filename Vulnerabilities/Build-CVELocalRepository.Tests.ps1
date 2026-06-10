Describe 'Build-CVELocalRepository pagination guard' {
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

  It 'aborts when the NVD API returns zero records while pagination is incomplete' {
    $functionAst = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Create-LocalCVERepository'
    }, $true)

    $functionAst | Should -Not -BeNullOrEmpty
    $functionAst.Body.Extent.Text | Should -Match '\$batchCount\s*=\s*@\(\$cveData\.vulnerabilities\)\.Count'
    $functionAst.Body.Extent.Text | Should -Match '\$batchCount\s*-eq\s*0'
    $functionAst.Body.Extent.Text | Should -Match 'infinite loop'
  }
}
