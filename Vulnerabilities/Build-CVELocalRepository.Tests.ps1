Describe 'Build-CVELocalRepository fetch loop guards' {
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

  It 'throws instead of silently breaking when fetch returns no data' {
    $functionAst = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Create-LocalCVERepository'
    }, $true)

    $functionAst | Should -Not -BeNullOrEmpty
    $body = $functionAst.Body.Extent.Text
    $body | Should -Match 'if \(-not \$cveData\)'
    $body | Should -Match 'throw.*partial repository'
    $body | Should -Not -Match 'if \(-not \$cveData\) \{ break \}'
  }

  It 'throws when the API returns a zero-length page to avoid an infinite loop' {
    $functionAst = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Create-LocalCVERepository'
    }, $true)

    $body = $functionAst.Body.Extent.Text
    $body | Should -Match '\$pageCount = @\(\$cveData\.vulnerabilities\)\.Count'
    $body | Should -Match 'if \(\$pageCount -eq 0\)'
    $body | Should -Match 'infinite loop'
    $body | Should -Match '\$startIndex \+= \$pageCount'
  }
}
