<#
.SYNOPSIS
    Centralized helper to retrieve secrets securely.

.DESCRIPTION
    Looks up a secret by name, checking (in order):
    1. Parameter value (if passed in)
    2. Environment variable
    3. PowerShell SecretManagement vault (if installed)
    4. Prompts the user securely if no value is found

.EXAMPLE
    $apiKey = Get-SecretValue -Name 'NVD_API_KEY'

.EXAMPLE
    # Pass through a parameter first, fall back otherwise
    param([string]$ClientSecret)
    $secret = Get-SecretValue -Name 'GRAPH_CLIENT_SECRET' -Fallback $ClientSecret
#>

function Get-SecretValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [Parameter()]
        [string]$Fallback
    )

    # 1. Fallback parameter
    if ($Fallback) {
        return $Fallback
    }

    # 2. Environment variable
    if ($env:$Name) {
        return $env:$Name
    }

    # 3. SecretManagement vault (optional)
    if (Get-Command Get-Secret -ErrorAction SilentlyContinue) {
        try {
            $val = Get-Secret -Name $Name -ErrorAction Stop
            if ($val) { return $val }
        } catch {
            # ignore if not found
        }
    }

    # 4. Prompt user securely
    Write-Host "Secret '$Name' not found. Please enter it:"
    $secure = Read-Host -AsSecureString
    return [System.Net.NetworkCredential]::new("", $secure).Password
}
