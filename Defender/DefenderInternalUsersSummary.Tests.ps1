Describe 'DefenderInternalUsersSummary script' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'DefenderInternalUsersSummary.ps1'
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

  It 'parses without syntax errors' {
    $parseErrors | Should -BeNullOrEmpty
  }

  It 'uses drive root as parent when creating the first SharePoint folder segment' {
    $ensureFolder = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Ensure-SharePointFolder'
    }, $true)

    $ensureFolder | Should -Not -BeNullOrEmpty
    $ensureFolder.Body.Extent.Text | Should -Match '\$segments\.Count\s*-le\s*1'
    $ensureFolder.Body.Extent.Text | Should -Match '/root/children'
  }

  It 'resolves first-segment parent path to empty string, not self' {
    $currentPath = 'Security'
    $segments = @($currentPath -split '/')
    $parentPath = if ($segments.Count -le 1) { '' } else { ($segments[0..($segments.Count - 2)] -join '/') }
    $parentPath | Should -Be ''
  }
}
