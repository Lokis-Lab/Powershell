Describe 'Invoke-LapsPasswordReset computer list handling' {
  It 'wraps single-computer AD and CSV results before foreach iteration' {
    $scriptPath = Join-Path $PSScriptRoot 'Invoke-LapsPasswordReset.ps1'
    $content = Get-Content -LiteralPath $scriptPath -Raw
    $content | Should -Match '\$computers = @\(Get-ADComputer'
    $content | Should -Match '\$computers = @\(Import-Csv'

    $singleComputer = 'SERVER01'
    $collected = @()
    foreach ($computer in @($singleComputer)) { $collected += $computer }
    $collected.Count | Should -Be 1
    $collected[0] | Should -Be 'SERVER01'
  }
}
