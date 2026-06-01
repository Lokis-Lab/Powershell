BeforeAll {
  $manifestPath = Join-Path $PSScriptRoot 'config\lab-manifest.json'
  $script:Manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
}

Describe 'TestLab manifest' {
  It 'has schema version 1' {
    $script:Manifest.schemaVersion | Should -Be 1
  }

  It 'defines insecure and aligned GPOs' {
    $names = @($script:Manifest.groupPolicyObjects | ForEach-Object { $_.name })
    $names | Should -Contain 'LAB - SEC Insecure Workstations'
    $names | Should -Contain 'LAB - Baseline Compliant Workstations'
  }

  It 'includes PasswordNeverExpires lab users' {
    $pne = @($script:Manifest.users | Where-Object { $_.passwordNeverExpires -eq $true })
    $pne.Count | Should -BeGreaterThan 0
    $pne.samAccountName | Should -Contain 'svc_backup'
  }

  It 'has gpo template files on disk' {
    $ws = Join-Path $PSScriptRoot 'gpo-templates\LAB-SEC-Insecure-Workstations-GptTmpl.inf'
    $legacy = Join-Path $PSScriptRoot 'gpo-templates\LAB-SEC-Insecure-Legacy-GptTmpl.inf'
    Test-Path -LiteralPath $ws | Should -BeTrue
    Test-Path -LiteralPath $legacy | Should -BeTrue
  }
}

Describe 'Initialize-TestLabDomain.ps1' {
  It 'exists and documents RSAT requirements' {
    $path = Join-Path $PSScriptRoot 'Initialize-TestLabDomain.ps1'
    Test-Path -LiteralPath $path | Should -BeTrue
    $content = Get-Content -LiteralPath $path -Raw
    $content | Should -Match 'GroupPolicy'
    $content | Should -Match 'ActiveDirectory'
  }
}
