Describe 'AD-GPO-Audit-Master GUI AD run handler' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'AD-GPO-Audit-Master.ps1'
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

  It 'does not reference the removed OuFilterTb control in the script' {
    $ouFilterTbRefs = @(
      $script:Ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.MemberExpressionAst] -and
          $node.Member.Value -eq 'OuFilterTb'
      }, $true)
    )
    $ouFilterTbRefs | Should -BeNullOrEmpty
  }

  It 'uses OuFilterCb when building AD duplicate audit parameters in the GUI run handler' {
    $guiFunction = $script:Ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Show-AdGpoAuditMasterMainGui'
    }, $true)

    $guiFunction | Should -Not -BeNullOrEmpty
    $guiFunction.Body.Extent.Text | Should -Match 'OuFilterCb'
    $guiFunction.Body.Extent.Text | Should -Not -Match 'OuFilterTb'
  }
}

Describe 'Invoke-AfterHoursGpoPolicyAudit Expand-ZipIfNeeded' {
  BeforeAll {
    function script:Expand-ZipIfNeededForTest {
      param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][string]$DestinationFolder
      )
      if (-not (Test-Path -LiteralPath $DestinationFolder)) {
        New-Item -Path $DestinationFolder -ItemType Directory -Force | Out-Null
      }
      $marker = Join-Path -Path $DestinationFolder -ChildPath '.expanded.marker'
      $needsExpand = -not (Test-Path -LiteralPath $marker)
      if (-not $needsExpand) {
        $zipUtc = (Get-Item -LiteralPath $ZipPath).LastWriteTimeUtc
        $markerItem = Get-Item -LiteralPath $marker -ErrorAction SilentlyContinue
        if ($markerItem) {
          if ($zipUtc -gt $markerItem.LastWriteTimeUtc) { $needsExpand = $true }
        } else {
          $needsExpand = $true
        }
      }
      if ($needsExpand) {
        Get-ChildItem -LiteralPath $DestinationFolder -Force |
          Where-Object { $_.Name -ne '.expanded.marker' } |
          Remove-Item -Recurse -Force -ErrorAction Stop
        Expand-Archive -Path $ZipPath -DestinationPath $DestinationFolder -Force
        Set-Content -LiteralPath $marker -Value ("Expanded {0}" -f (Get-Date).ToString('o')) -Encoding UTF8
      }
    }
  }

  It 'removes files dropped from a newer zip before re-expanding' {
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ("gpo-expand-test-{0}" -f [guid]::NewGuid())
    $zipPath = Join-Path $root 'template.zip'
    $dest = Join-Path $root 'extracted'
    try {
      New-Item -ItemType Directory -Path $root -Force | Out-Null
      'keep-me' | Set-Content -LiteralPath (Join-Path $root 'keep.txt') -Encoding UTF8
      'drop-me' | Set-Content -LiteralPath (Join-Path $root 'removed.txt') -Encoding UTF8
      Compress-Archive -Path @(
        (Join-Path $root 'keep.txt'),
        (Join-Path $root 'removed.txt')
      ) -DestinationPath $zipPath -Force
      Expand-ZipIfNeededForTest -ZipPath $zipPath -DestinationFolder $dest
      Test-Path -LiteralPath (Join-Path $dest 'removed.txt') | Should -BeTrue

      Start-Sleep -Seconds 2
      Remove-Item -LiteralPath (Join-Path $root 'removed.txt') -Force
      Compress-Archive -Path (Join-Path $root 'keep.txt') -DestinationPath $zipPath -Force
      Expand-ZipIfNeededForTest -ZipPath $zipPath -DestinationFolder $dest
      Test-Path -LiteralPath (Join-Path $dest 'removed.txt') | Should -BeFalse
      (Get-Content -LiteralPath (Join-Path $dest 'keep.txt') -Raw).Trim() | Should -Be 'keep-me'
    } finally {
      if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It 're-expands when the zip is newer than the expansion marker' {
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ("gpo-expand-test-{0}" -f [guid]::NewGuid())
    $zipPath = Join-Path $root 'template.zip'
    $dest = Join-Path $root 'extracted'
    try {
      New-Item -ItemType Directory -Path $root -Force | Out-Null
      'version-1' | Set-Content -LiteralPath (Join-Path $root 'payload.txt') -Encoding UTF8
      Compress-Archive -Path (Join-Path $root 'payload.txt') -DestinationPath $zipPath -Force
      Expand-ZipIfNeededForTest -ZipPath $zipPath -DestinationFolder $dest
      (Get-Content -LiteralPath (Join-Path $dest 'payload.txt') -Raw).Trim() | Should -Be 'version-1'

      Start-Sleep -Seconds 2
      'version-2' | Set-Content -LiteralPath (Join-Path $root 'payload.txt') -Encoding UTF8
      Compress-Archive -Path (Join-Path $root 'payload.txt') -DestinationPath $zipPath -Force
      Expand-ZipIfNeededForTest -ZipPath $zipPath -DestinationFolder $dest
      (Get-Content -LiteralPath (Join-Path $dest 'payload.txt') -Raw).Trim() | Should -Be 'version-2'
    } finally {
      if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }
}
