<#
.SYNOPSIS
  Retrieves device names, IP addresses, last online date, domain name, and subnet mapping 
  from Microsoft Defender for Endpoint (via Graph API).

.DESCRIPTION
  This script authenticates to the Microsoft Defender for Endpoint Graph API using an 
  Azure AD app registration, retrieves machine information, and enriches results by 
  mapping IPs to known subnet definitions. Results are exported to CSV.

.EXAMPLE
  .\Get-DefenderMachinesWithSubnets.ps1 -TenantId "<TenantID>" -ClientId "<ClientID>" -ClientSecret "<Secret>"

.PARAMETER TenantId
  Azure AD tenant ID (GUID).

.PARAMETER ClientId
  Application (client) ID of the registered Azure AD app.

.PARAMETER ClientSecret
  Client secret generated for the Azure AD app.

.PARAMETER OutputCsvPath
  Path for the CSV export.

.NOTES
  - Requires Microsoft Defender for Endpoint API access.
  - Script currently assumes GCC (Government Community Cloud) endpoints.
  - Subnet mappings should be customized for your environment.
#>

param(
  [Parameter(Mandatory=$true)][string]$TenantId,     # <-- Your tenant ID
  [Parameter(Mandatory=$true)][string]$ClientId,     # <-- Your app registration client ID
  [Parameter(Mandatory=$true)][string]$ClientSecret, # <-- Your app secret (secure storage recommended)
  [string]$OutputCsvPath = "C:\Reports\ComputerNamesAndIPsWithSubnets.csv"
)

# --- GCC Token and API endpoints
$tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
$apiUrl   = "https://api-gcc.securitycenter.microsoft.us/api/machines"

# --- Request body for token
$body = [Ordered]@{
    client_id     = $ClientId
    scope         = "https://api-gcc.securitycenter.microsoft.us/.default"
    client_secret = $ClientSecret
    grant_type    = "client_credentials"
}

# --- Get access token
$response     = Invoke-RestMethod -Method Post -Uri $tokenUrl -Body $body -ContentType "application/x-www-form-urlencoded"
$accessToken  = $response.access_token

$headers = @{
    Authorization = "Bearer $accessToken"
    "Content-Type" = "application/json"
}

# --- Example subnet mapping (customize for your org)
$subnetMapping = @{
    "10.120.26."   = @{ Scope = "10.120.26.0"; SubnetName = "SCCM Production" }
    "10.120.32."   = @{ Scope = "10.120.32.0"; SubnetName = "Backup - Veeam Storage" }
    "192.168.122." = @{ Scope = "192.168.122.0"; SubnetName = "VM Desktops Internal" }
    "207.126.11."  = @{ Scope = "207.126.11.0"; SubnetName = "Senate Chamber" }
    # ...add more as needed
}

# --- Fetch Defender machines
try {
    $machinesResponse = Invoke-RestMethod -Method Get -Uri $apiUrl -Headers $headers

    $output = $machinesResponse.value | ForEach-Object {
        $ipv4Addresses = @()
        $subnetDetails = @()

        if ($_.ipAddresses -is [array]) {
            foreach ($ip in $_.ipAddresses) {
                if ($ip -and $ip.ipAddress -match "^(\d{1,3}\.){3}\d{1,3}$") {
                    $matchingSubnet = $subnetMapping.Keys | Where-Object { $ip.ipAddress.StartsWith($_) }
                    if ($matchingSubnet) {
                        $ipv4Addresses += $ip.ipAddress
                        $subnetDetails += $subnetMapping[$matchingSubnet]
                    }
                }
            }
        }

        if ($ipv4Addresses.Count -gt 0) {
            [PSCustomObject]@{
                DeviceName  = $_.computerDnsName
                IPAddresses = $ipv4Addresses -join ", "
                LastSeen    = $_.lastSeen
                DomainName  = $_.domainName
                SubnetScope = ($subnetDetails | ForEach-Object { $_.Scope }) -join ", "
                SubnetName  = ($subnetDetails | ForEach-Object { $_.SubnetName }) -join ", "
            }
        }
    }

    $output | Where-Object { $_ } | Export-Csv -Path $OutputCsvPath -NoTypeInformation -Encoding UTF8 -Force

    Write-Host "Data successfully exported to $OutputCsvPath" -ForegroundColor Green
} catch {
    Write-Host "An error occurred: $($_.Exception.Message)" -ForegroundColor Red
}
