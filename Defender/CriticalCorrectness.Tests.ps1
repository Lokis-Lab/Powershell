Describe 'Scalar collection wrapping' {
  It 'wraps single Advanced Hunting result rows in an array' {
    $scriptPath = Join-Path $PSScriptRoot 'DefenderInternalUsersSummary.ps1'
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
      $scriptPath,
      [ref]$tokens,
      [ref]$parseErrors
    )
    if ($parseErrors -and $parseErrors.Count -gt 0) {
      throw ($parseErrors | ForEach-Object { $_.Message } | Out-String)
    }

    $functionAst = $ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Invoke-DefenderQuery'
    }, $true)

    $functionAst.Body.Extent.Text | Should -Match 'return @\(\$Response\.Results\)'

    $singleRow = [PSCustomObject]@{ Attempts = 3; Category = 'Phish' }
    @($singleRow).Count | Should -Be 1
    foreach ($record in @($singleRow)) {
      $record.Attempts | Should -Be 3
    }
  }

  It 'wraps MDE machine pagination results' {
    $items = [System.Collections.Generic.List[object]]::new()
    $pages = @(
      @{ value = @([PSCustomObject]@{ id = '1' }); '@odata.nextLink' = 'page2' },
      @{ value = @([PSCustomObject]@{ id = '2' }); '@odata.nextLink' = $null }
    )
    $nextUrl = 'page1'
    while ($nextUrl) {
      $response = $pages[[int]($nextUrl -replace '\D') - 1]
      if ($response.value) { $items.AddRange(@($response.value)) }
      $nextUrl = $response.'@odata.nextLink'
    }
    $items.Count | Should -Be 2
  }
}

Describe 'Export-DefenderDevicesAndVulnerabilities vulnerability export safety' {
  It 'writes vulnerabilities to a temp file before replacing the CSV' {
    $scriptPath = Join-Path $PSScriptRoot 'Export-DefenderDevicesAndVulnerabilities.ps1'
    $content = Get-Content -LiteralPath $scriptPath -Raw
    $content | Should -Match '\$vulnTempPath'
    $content | Should -Match 'Move-Item -LiteralPath \$vulnTempPath'
    $content | Should -Match 'preserving existing file'
  }
}
