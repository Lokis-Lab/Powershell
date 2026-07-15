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
