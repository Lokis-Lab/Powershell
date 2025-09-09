<#
.SYNOPSIS
  Retrieves Defender for Endpoint devices and maps IPs to subnets.
  Defaults to Commercial cloud; use -Cloud GCCH to target GCC High.

.DESCRIPTION
  Authenticates via app registration (client credentials) and calls the MDE API.
  Use -Cloud to switch endpoints/scopes between Commercial and GCC.
#>

param(
  [Parameter(Mandatory=$true)][string]$TenantId,     # <-- your tenant ID
  [Parameter(Mandatory=$true)][string]$ClientId,     # <-- app (client) ID
  [Parameter(Mandatory=$true)][string]$ClientSecret, # <-- client secret (store securely)
  [ValidateSet('Commercial','GCCH')][string]$Cloud = 'Commercial',
  [string]$OutputCsvPath = "C:\Reports\ComputerNamesAndIPsWithSubnets.csv"
)

# --- Cloud-specific endpoints/scopes
if ($Cloud -eq 'Commercial') {
  $TokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
  $ApiBase  = "https://api.securitycenter.microsoft.com"                # Commercial
  $Scope    = "https://api.securitycenter.microsoft.com/.default"       # Commercial scope
} else {
  $TokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
  $ApiBase  = "https://api-gcc.securitycenter.microsoft.us"             # GCC High
  $Scope    = "https://api-gcc.securitycenter.microsoft.us/.default"    # GCC High scope
  # ^ If using GCC, just set -Cloud GCCH. No other code changes needed.
}

# --- Auth
$body = [Ordered]@{
  client_id     = $ClientId
  scope         = $Scope         # <-- changes by cloud
  client_secret = $ClientSecret
  grant_type    = "client_credentials"
}

$response     = Invoke-RestMethod -Method Post -Uri $TokenUrl -Body $body -ContentType "application/x-www-form-urlencoded"
$accessToken  = $response.access_token
$headers = @{ Authorization = "Bearer $accessToken"; "Content-Type" = "application/json" }

# --- API path
$MachinesEndpoint = "$ApiBase/api/machines"  # <-- changes by cloud

# --- Example subnet mapping (edit for your environment)
$subnetMapping = @{
  "10.120.26."   = @{ Scope = "10.120.26.0";   SubnetName = "SCCM Production" }
  "10.120.32."   = @{ Scope = "10.120.32.0";   SubnetName = "Backup - Veeam Storage" }
  "192.168.122." = @{ Scope = "192.168.122.0"; SubnetName = "VM Desktops Internal" }
  "207.126.11."  = @{ Scope = "207.126.11.0";  SubnetName = "Senate Chamber" }
}

try {
  $machinesResponse = Invoke-RestMethod -Method Get -Uri $MachinesEndpoint -Headers $headers

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
  Write-Host "Data exported to $OutputCsvPath" -ForegroundColor Green
}
catch {
  Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
}
