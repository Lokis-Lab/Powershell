Describe 'Invoke-AfterHoursGpoPolicyAudit generated import helper' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Invoke-AfterHoursGpoPolicyAudit.ps1'
    $source = Get-Content -LiteralPath $scriptPath -Raw
    $match = [regex]::Match(
      $source,
      "(?s)@'\r?\n(?<helper>param\([\s\S]*?)\r?\n'@ \| Set-Content -LiteralPath \$helperScriptPath"
    )

    if (-not $match.Success) {
      throw 'Could not find generated Import-Link-GpoBundle.ps1 helper script content.'
    }

    $script:HelperSource = $match.Groups['helper'].Value

    $tokens = $null
    $parseErrors = $null
    $script:HelperAst = [System.Management.Automation.Language.Parser]::ParseInput(
      $script:HelperSource,
      [ref]$tokens,
      [ref]$parseErrors
    )

    if ($parseErrors -and $parseErrors.Count -gt 0) {
      throw ($parseErrors | ForEach-Object { $_.Message } | Out-String)
    }
  }

  It 'emits a syntactically valid helper script' {
    $script:HelperAst | Should -Not -BeNullOrEmpty
  }

  It 'restores GPO link enabled state, enforcement state, and precedence order' {
    $script:HelperSource | Should -Match 'function ConvertTo-GpLinkOption'
    $script:HelperSource | Should -Match 'New-GPLink[\s\S]*-LinkEnabled \$linkEnabled[\s\S]*-Enforced \$enforced'
    $script:HelperSource | Should -Match 'Set-GPLink[\s\S]*-LinkEnabled \$linkEnabled[\s\S]*-Enforced \$enforced'
    $script:HelperSource | Should -Match 'Set-GPLink[\s\S]*-Order \$order'
    $script:HelperSource | Should -Not -Match '-Enforced:\$enforced'
    $script:HelperSource | Should -Not -Match 'ErrorAction SilentlyContinue'
  }
}
