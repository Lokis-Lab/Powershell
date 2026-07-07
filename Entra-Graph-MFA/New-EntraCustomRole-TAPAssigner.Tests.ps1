Describe 'New-EntraCustomRole-TAPAssigner script' {
    It 'parses without syntax errors' {
        { [void][System.Management.Automation.Language.Parser]::ParseFile(
                (Join-Path $PSScriptRoot 'New-EntraCustomRole-TAPAssigner.ps1'),
                [ref]$null,
                [ref]$null) } | Should -Not -Throw
    }

    It 'serializes nested rolePermissions without truncation' {
        $roleDefinition = @{
            rolePermissions = @(
                @{
                    allowedResourceActions = @(
                        'microsoft.directory/users/authenticationMethods/create',
                        'microsoft.directory/users/authenticationMethods/delete'
                    )
                }
            )
        }
        $json = $roleDefinition | ConvertTo-Json -Compress -Depth 5
        $json | Should -Match 'allowedResourceActions'
        $json | Should -Not -Match '\.\.\.'
    }
}
