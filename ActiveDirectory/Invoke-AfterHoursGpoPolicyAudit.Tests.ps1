Describe 'Invoke-AfterHoursGpoPolicyAudit safety checks' {
  BeforeAll {
    $script:ScriptPath = Join-Path $PSScriptRoot 'Invoke-AfterHoursGpoPolicyAudit.ps1'
    $script:ScriptText = Get-Content -LiteralPath $script:ScriptPath -Raw
    $tokens = $null
    $parseErrors = $null
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile(
      $script:ScriptPath,
      [ref]$tokens,
      [ref]$parseErrors
    )

    if ($parseErrors -and $parseErrors.Count -gt 0) {
      throw ($parseErrors | ForEach-Object { $_.Message } | Out-String)
    }

    function Ensure-Directory {
      param([Parameter(Mandatory)][string]$Path)
      if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
      }
    }

    $expandFunction = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Expand-ZipIfNeeded'
    }, $true)

    if (-not $expandFunction) {
      throw 'Expand-ZipIfNeeded function was not found.'
    }

    Invoke-Expression $expandFunction.Extent.Text
  }

  It 'refreshes extracted ZIP contents when the archive changes' {
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
    $zipPath = Join-Path $root 'baseline.zip'
    $destination = Join-Path $root 'Expanded'

    try {
      $firstSource = Join-Path $root 'first'
      $secondSource = Join-Path $root 'second'
      New-Item -Path $firstSource -ItemType Directory -Force | Out-Null
      New-Item -Path $secondSource -ItemType Directory -Force | Out-Null
      Set-Content -LiteralPath (Join-Path $firstSource 'stale.xml') -Value '<old />' -Encoding UTF8
      Set-Content -LiteralPath (Join-Path $secondSource 'current.xml') -Value '<new />' -Encoding UTF8

      Compress-Archive -Path (Join-Path $firstSource '*') -DestinationPath $zipPath -Force
      Expand-ZipIfNeeded -ZipPath $zipPath -DestinationFolder $destination

      Test-Path -LiteralPath (Join-Path $destination 'stale.xml') | Should -BeTrue

      Compress-Archive -Path (Join-Path $secondSource '*') -DestinationPath $zipPath -Force
      Expand-ZipIfNeeded -ZipPath $zipPath -DestinationFolder $destination

      Test-Path -LiteralPath (Join-Path $destination 'current.xml') | Should -BeTrue
      Test-Path -LiteralPath (Join-Path $destination 'stale.xml') | Should -BeFalse
    } finally {
      if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
      }
    }
  }

  It 'generates a GPO import helper that preserves link state and order' {
    $script:ScriptText | Should -Match "LinkEnabled\s*=\s*\$linkEnabledText"
    $script:ScriptText | Should -Match "Enforced\s*=\s*\$enforcedText"
    $script:ScriptText | Should -Match "\$linkParams\['Order'\]\s*=\s*\$linkOrder"
    $script:ScriptText | Should -Match "New-GPLink\s+@linkParams"
    $script:ScriptText | Should -Not -Match "New-GPLink[^\r\n]+SilentlyContinue"
  }
}
