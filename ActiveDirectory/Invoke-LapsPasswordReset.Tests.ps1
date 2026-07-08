Describe 'Invoke-LapsPasswordReset computer list handling' {
  It 'iterates a single computer name as one item, not individual characters' {
    $computers = @('WORKSTATION01')
    $collected = @()
    foreach ($computer in $computers) { $collected += $computer }
    $collected.Count | Should -Be 1
    $collected[0] | Should -Be 'WORKSTATION01'
  }

  It 'wraps AD and CSV computer queries in array subexpressions' {
    $scriptPath = Join-Path $PSScriptRoot 'Invoke-LapsPasswordReset.ps1'
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

    $switchAst = $ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.SwitchStatementAst]
    }, $true)

    $switchAst | Should -Not -BeNullOrEmpty
    $switchText = $switchAst.Extent.Text
    $switchText | Should -Match '\$computers\s*=\s*@\(Get-ADComputer'
    $switchText | Should -Match '\$computers\s*=\s*@\(Import-Csv'
  }
}
