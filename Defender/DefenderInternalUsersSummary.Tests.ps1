BeforeAll {
    $script:SourcePath = Join-Path $PSScriptRoot 'DefenderInternalUsersSummary.ps1'
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:SourcePath,
        [ref]$null,
        [ref]$null
    )
}

Describe 'Invoke-DefenderQuery' {
    It 'wraps Advanced Hunting results in an array' {
        $functionAst = $script:Ast.Find({
            $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $args[0].Name -eq 'Invoke-DefenderQuery'
        }, $true)

        $functionAst | Should -Not -BeNullOrEmpty
        $functionAst.Body.Extent.Text | Should -Match 'return\s+@\(\$Response\.Results\)'
    }
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
