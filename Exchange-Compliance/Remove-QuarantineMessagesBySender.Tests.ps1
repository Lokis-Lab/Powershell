Describe 'Remove-QuarantineMessagesBySender scalar identity handling' {
  It 'wraps a single quarantine identity before foreach iteration' {
    $scriptPath = Join-Path $PSScriptRoot 'Remove-QuarantineMessagesBySender.ps1'
    $content = Get-Content -LiteralPath $scriptPath -Raw
    $content | Should -Match '\$ids = @\(Get-QuarantineMessage'

    $singleId = 'abc123-def456'
    $collected = @()
    foreach ($id in @($singleId)) { $collected += $id }
    $collected.Count | Should -Be 1
    $collected[0] | Should -Be $singleId
  }
}
