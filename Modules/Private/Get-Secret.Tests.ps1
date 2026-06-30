BeforeAll {
    . (Join-Path $PSScriptRoot 'Get-Secret.ps1')
}

Describe 'Get-SecretValue' {
    It 'reads secrets from environment variables' {
        $name = "TEST_SECRET_$([guid]::NewGuid().ToString('N'))"
        [Environment]::SetEnvironmentVariable($name, 'from-env', 'Process')
        try {
            Get-SecretValue -Name $name | Should -Be 'from-env'
        } finally {
            [Environment]::SetEnvironmentVariable($name, $null, 'Process')
        }
    }

    It 'prefers fallback parameter over environment variable' {
        $name = "TEST_SECRET_$([guid]::NewGuid().ToString('N'))"
        [Environment]::SetEnvironmentVariable($name, 'from-env', 'Process')
        try {
            Get-SecretValue -Name $name -Fallback 'from-param' | Should -Be 'from-param'
        } finally {
            [Environment]::SetEnvironmentVariable($name, $null, 'Process')
        }
    }
}

Describe 'Get-Secret script' {
    It 'parses without syntax errors' {
        { [void][System.Management.Automation.Language.Parser]::ParseFile(
                (Join-Path $PSScriptRoot 'Get-Secret.ps1'),
                [ref]$null,
                [ref]$null) } | Should -Not -Throw
    }
}
