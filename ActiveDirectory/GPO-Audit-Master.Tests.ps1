BeforeAll {
  $script:ScriptUnderTest = Join-Path $PSScriptRoot 'GPO-Audit-Master.ps1'
}

Describe 'GPO registry snapshot compare' {
  It 'preserves ValueName for changed and unchanged registry values' {
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ("GpoAuditCompare_{0}" -f [guid]::NewGuid())
    $left = Join-Path $root 'left'
    $right = Join-Path $root 'right'
    $out = Join-Path $root 'out'

    try {
      New-Item -ItemType Directory -Path $left, $right, $out -Force | Out-Null

      $baseRow = @{
        GpoName = 'Baseline Policy'
        GpoId = '11111111-1111-1111-1111-111111111111'
        Scope = 'Computer'
        KeyPath = 'HKLM\Software\Example'
        ValueType = 'String'
        Source = 'RegistrySetting'
      }

      @(
        [pscustomobject]($baseRow + @{ ValueName = 'SettingA'; ValueData = 'old' })
        [pscustomobject]($baseRow + @{ ValueName = 'SettingB'; ValueData = 'same' })
      ) | Export-Clixml -LiteralPath (Join-Path $left 'GpoRegistrySnapshot.clixml')

      @(
        [pscustomobject]($baseRow + @{ ValueName = 'SettingA'; ValueData = 'new' })
        [pscustomobject]($baseRow + @{ ValueName = 'SettingB'; ValueData = 'same' })
      ) | Export-Clixml -LiteralPath (Join-Path $right 'GpoRegistrySnapshot.clixml')

      function Import-Module {
        [CmdletBinding()]
        param([Parameter(ValueFromRemainingArguments = $true)][object[]]$ArgumentList)
      }

      . $script:ScriptUnderTest -Mode RegistrySnapshotCompare -LeftFolder $left -RightFolder $right -OutFolderCompare $out

      $rows = Import-Csv -LiteralPath (Join-Path $out 'Compare-RegistryKeyValue.csv')

      $rows[0].PSObject.Properties.Name | Should -Contain 'ValueName'
      ($rows | Where-Object ValueName -eq 'SettingA').Status | Should -Be 'Changed'
      ($rows | Where-Object ValueName -eq 'SettingB').Status | Should -Be 'Unchanged'
    } finally {
      if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
      }
    }
  }
}
