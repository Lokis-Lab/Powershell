Describe 'Invoke-AfterHoursGpoPolicyAudit template extraction cache' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Invoke-AfterHoursGpoPolicyAudit.ps1'
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

    foreach ($functionName in @('Ensure-Directory', 'Expand-ZipIfNeeded')) {
      $functionAst = $script:Ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
          $node.Name -eq $functionName
      }, $true)

      $functionAst | Should -Not -BeNullOrEmpty
      Invoke-Expression $functionAst.Extent.Text
    }
  }

  It 're-extracts refreshed ZIP contents and removes stale expanded files' {
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ("gpo-audit-cache-{0}" -f ([guid]::NewGuid()).Guid)
    $source = Join-Path $root 'source'
    $destination = Join-Path $root 'expanded'
    $zipPath = Join-Path $root 'baseline.zip'
    $marker = Join-Path $destination '.expanded.marker'

    try {
      New-Item -Path $source -ItemType Directory -Force | Out-Null
      Set-Content -LiteralPath (Join-Path $source 'baseline.txt') -Value 'old' -Encoding UTF8
      Set-Content -LiteralPath (Join-Path $source 'removed.txt') -Value 'stale' -Encoding UTF8
      Compress-Archive -Path (Join-Path $source '*') -DestinationPath $zipPath -Force

      Expand-ZipIfNeeded -ZipPath $zipPath -DestinationFolder $destination
      (Get-Content -LiteralPath (Join-Path $destination 'baseline.txt') -Raw).Trim() | Should -Be 'old'
      Test-Path -LiteralPath (Join-Path $destination 'removed.txt') | Should -BeTrue
      Test-Path -LiteralPath $marker | Should -BeTrue

      Remove-Item -LiteralPath $source -Recurse -Force
      New-Item -Path $source -ItemType Directory -Force | Out-Null
      Set-Content -LiteralPath (Join-Path $source 'baseline.txt') -Value 'new' -Encoding UTF8
      Compress-Archive -Path (Join-Path $source '*') -DestinationPath $zipPath -Force
      (Get-Item -LiteralPath $zipPath).LastWriteTimeUtc = [datetime]::UtcNow.AddMinutes(5)

      Expand-ZipIfNeeded -ZipPath $zipPath -DestinationFolder $destination

      (Get-Content -LiteralPath (Join-Path $destination 'baseline.txt') -Raw).Trim() | Should -Be 'new'
      Test-Path -LiteralPath (Join-Path $destination 'removed.txt') | Should -BeFalse
    } finally {
      if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
      }
    }
  }

  It 'compares the archive timestamp against the expansion marker' {
    $functionAst = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Expand-ZipIfNeeded'
    }, $true)

    $functionText = $functionAst.Extent.Text
    $functionText | Should -Match '\$zipUtc'
    $functionText | Should -Match '\$markerUtc'
    $functionText | Should -Match '\$zipUtc\s+-gt\s+\$markerUtc'
  }
}
