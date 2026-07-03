Describe 'Script parse safety' {
    It 'Invoke-AADConnectSync.ps1 parses without syntax errors' {
        $path = Join-Path $PSScriptRoot 'ActiveDirectory/Invoke-AADConnectSync.ps1'
        $errors = $null
        { [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors) } | Should -Not -Throw
        $errors | Should -BeNullOrEmpty
    }

    It 'Invoke-AfterHoursGpoPolicyAudit.ps1 parses without syntax errors' {
        $path = Join-Path $PSScriptRoot 'ActiveDirectory/Invoke-AfterHoursGpoPolicyAudit.ps1'
        $errors = $null
        { [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors) } | Should -Not -Throw
        $errors | Should -BeNullOrEmpty
    }

    It 'Export-MFAStatusReport.ps1 parses without syntax errors' {
        $path = Join-Path $PSScriptRoot 'Entra-Graph-MFA/Export-MFAStatusReport.ps1'
        $errors = $null
        { [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors) } | Should -Not -Throw
        $errors | Should -BeNullOrEmpty
    }
}
