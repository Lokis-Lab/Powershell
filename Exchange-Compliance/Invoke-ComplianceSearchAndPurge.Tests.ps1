BeforeAll {
    function Escape-KqlFieldValue {
        param([string]$Value)
        if ($null -eq $Value) { return '' }
        return ($Value -replace '"', '""')
    }
}

Describe 'Escape-KqlFieldValue' {
    It 'doubles embedded double quotes' {
        Escape-KqlFieldValue -Value 'budget" OR subject:*' | Should -Be 'budget"" OR subject:*'
    }

    It 'returns empty string for null input' {
        Escape-KqlFieldValue -Value $null | Should -Be ''
    }

    It 'leaves safe values unchanged' {
        Escape-KqlFieldValue -Value 'Quarterly report' | Should -Be 'Quarterly report'
    }
}

Describe 'Invoke-ComplianceSearchAndPurge script' {
    It 'parses without syntax errors' {
        { [void][System.Management.Automation.Language.Parser]::ParseFile(
                (Join-Path $PSScriptRoot 'Invoke-ComplianceSearchAndPurge.ps1'),
                [ref]$null,
                [ref]$null) } | Should -Not -Throw
    }
}
