Describe 'Invoke-RegistrySnapshotCompare' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'GPO-Audit-Master.ps1'
    $parseErrors = @()
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
      throw ($parseErrors | ForEach-Object { $_.Message }) -join [Environment]::NewLine
    }

    foreach ($functionName in @('Ensure-Folder', 'Invoke-RegistrySnapshotCompare')) {
      $functionAst = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
          $node.Name -eq $functionName
      }, $true)

      if ($null -eq $functionAst) {
        throw "Could not find function '$functionName' in $scriptPath"
      }

      . ([scriptblock]::Create($functionAst.Extent.Text))
    }
  }

  It 'includes ValueName for changed and unchanged registry rows' {
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ("gpo-snapshot-compare-" + [guid]::NewGuid().ToString('N'))
    $left = Join-Path $root 'left'
    $right = Join-Path $root 'right'
    $out = Join-Path $root 'out'

    try {
      New-Item -ItemType Directory -Path $left, $right -Force | Out-Null

      $leftRows = @(
        [pscustomobject]@{
          GpoName   = 'Security Baseline'
          GpoId     = '11111111-1111-1111-1111-111111111111'
          Scope     = 'Computer'
          KeyPath   = 'HKLM\Software\Policies\Example'
          ValueName = 'ChangedSetting'
          ValueType = 'String'
          ValueData = 'Disabled'
          Source    = 'RegistrySetting'
        },
        [pscustomobject]@{
          GpoName   = 'Security Baseline'
          GpoId     = '11111111-1111-1111-1111-111111111111'
          Scope     = 'Computer'
          KeyPath   = 'HKLM\Software\Policies\Example'
          ValueName = 'UnchangedSetting'
          ValueType = 'DWord'
          ValueData = '1'
          Source    = 'RegistrySetting'
        }
      )

      $rightRows = @(
        [pscustomobject]@{
          GpoName   = 'Security Baseline'
          GpoId     = '11111111-1111-1111-1111-111111111111'
          Scope     = 'Computer'
          KeyPath   = 'HKLM\Software\Policies\Example'
          ValueName = 'ChangedSetting'
          ValueType = 'String'
          ValueData = 'Enabled'
          Source    = 'RegistrySetting'
        },
        [pscustomobject]@{
          GpoName   = 'Security Baseline'
          GpoId     = '11111111-1111-1111-1111-111111111111'
          Scope     = 'Computer'
          KeyPath   = 'HKLM\Software\Policies\Example'
          ValueName = 'UnchangedSetting'
          ValueType = 'DWord'
          ValueData = '1'
          Source    = 'RegistrySetting'
        }
      )

      $leftRows | Export-Clixml -LiteralPath (Join-Path $left 'GpoRegistrySnapshot.clixml')
      $rightRows | Export-Clixml -LiteralPath (Join-Path $right 'GpoRegistrySnapshot.clixml')

      Invoke-RegistrySnapshotCompare -Left $left -Right $right -OutFolder $out

      $rows = Import-Csv -LiteralPath (Join-Path $out 'Compare-RegistryKeyValue.csv')
      ($rows | Where-Object Status -eq 'Changed').ValueName | Should -Be 'ChangedSetting'
      ($rows | Where-Object Status -eq 'Unchanged').ValueName | Should -Be 'UnchangedSetting'
    } finally {
      if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
      }
    }
  }
}
