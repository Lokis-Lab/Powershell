BeforeAll {
    $script:SourcePath = Join-Path $PSScriptRoot 'DefenderInternalUsersSummary.ps1'
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:SourcePath,
        [ref]$null,
        [ref]$null
    )
}

Describe 'Ensure-SharePointFolder' {
    It 'creates top-level folders under the drive root' {
        $functionAst = $script:Ast.Find({
            $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $args[0].Name -eq 'Ensure-SharePointFolder'
        }, $true)

        $functionAst | Should -Not -BeNullOrEmpty
        $body = $functionAst.Body.Extent.Text
        $body | Should -Match '\$segments\.Count\s+-le\s+1'
        $body | Should -Match "''\s*\}\s*else\s*\{"
    }
}

Describe 'Add-ADAccountStatus' {
    It 'matches AD users by UPN or Mail only, not SamAccountName from the email local-part' {
        $functionAst = $script:Ast.Find({
            $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $args[0].Name -eq 'Add-ADAccountStatus'
        }, $true)

        $functionAst | Should -Not -BeNullOrEmpty
        $body = $functionAst.Body.Extent.Text
        $body | Should -Match 'UserPrincipalName -eq'
        $body | Should -Match 'Mail -eq'
        $body | Should -Not -Match 'SamAccountName -eq'
    }
}
