<#
.SYNOPSIS
  Exports Microsoft Defender for Endpoint device and vulnerability data.

.DESCRIPTION
  This script authenticates to the Defender for Endpoint API (GCC endpoints),
  retrieves device inventory (optionally filtered by OS platform), exports devices
  to CSV, and loops through each device to query vulnerabilities. Results are
  exported to a separate CSV.

.PARAMETER TenantId
  Azure AD tenant ID (GUID).

.PARAMETER ClientId
  Application (client) ID from an app registration with MDE API permissions.

.PARAMETER ClientSecret
  Client secret generated for the Azure AD app.

.PARAMETER DevicesCsvPath
  Path to export the device list (default: C:\Reports\Devices.csv).

.PARAMETER VulnerabilitiesCsvPath
  Path to export vulnerabilities (default: C:\Reports\Vulnerabilities.csv).

.PARAMETER OSPlatform
  (Optional) OS platform filter, e.g., "Windows11", "Windows10", "Linux".
  If not provided, all devices are returned.

.EXAMPLE
  # Export all devices and their vulnerabilities
  .\Export-DefenderDevicesAndVulnerabilities.ps1 -TenantId "<TenantID>" -ClientId "<ClientID>" -ClientSecret "<Secret>"

.EXAMPLE
  # Export only Windows 11 devices
  .\Export-DefenderDevicesAndVulnerabilities.ps1 -TenantId "<TenantID>" -ClientId "<ClientID>" -ClientSecret "<Secret>" -OSPlatform "Windows11"
#>

param(
  [Parameter(Mandatory=$true)][string]$TenantId,
  [Parameter(Mandatory=$true)][string]$ClientId,
  [Parameter(Mandatory=$true)][string]$ClientSecret,
  [string]$DevicesCsvPath         = "C:\Reports\Devices.csv",
  [string]$VulnerabilitiesCsvPath = "C:\Reports\Vulnerabilities.csv",
  [string]$OSPlatform             # Optional filter
)

# --- Auth body
$body = [Ordered]@{
    client_id     = $ClientId
    scope         = "https://api-gcc.securitycenter.microsoft.us/.default"
    client_secret = $ClientSecret
    grant_type    = "client_credentials"
}

try {
    # --- Request token
    $tokenResponse = Invoke-RestMethod -Method Post `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -ContentType "application/x-www-form-urlencoded" -Body $body

    $token = $tokenResponse.access_token
    if (-not $token) { throw "Failed to acquire token. Please check credentials." }

    $header = @{
        Authorization = "Bearer $token"
        "Content-Type" = "application/json"
    }

    # --- Query devices
    $queryUrl = "https://api-gcc.securitycenter.microsoft.us/api/machines"
    $response = Invoke-RestMethod -Method Get -Uri $queryUrl -Headers $header -ErrorAction Stop
    
    if ($response -and $response.value) {
        $devices = $response.value

        # --- Optional filter by OS platform
        if ($OSPlatform) {
            $devices = $devices | Where-Object { $_.osPlatform -eq $OSPlatform }
        }

        # --- Filter out decommissioned / temp devices by name
        $devices = $devices | Where-Object { $_.computerDnsName -notmatch '^(minint-|sen-ready|sen-decomm|sacw|senready)' }

        if ($devices.Count -gt 0) {
            # --- Export devices
            $deviceData = $devices | Select-Object id, computerDnsName, osPlatform, healthStatus, lastSeen
            $deviceData | Export-Csv -Path $DevicesCsvPath -NoTypeInformation -Encoding UTF8 -Force
            Write-Host "Devices exported to $DevicesCsvPath" -ForegroundColor Green

            # --- Loop devices for vulnerabilities
            foreach ($device in $devices) {
                Start-Sleep -Seconds 1  # avoid 429 rate limit
                $deviceId = $device.id
                $vulnQueryUrl = "https://api-gcc.securitycenter.microsoft.us/api/machines/$deviceId/vulnerabilities"
                
                try {
                    $vulnResponse = Invoke-RestMethod -Method Get -Uri $vulnQueryUrl -Headers $header -ErrorAction Stop
                    if ($vulnResponse -and $vulnResponse.value) {
                        $vulnerabilitiesData = $vulnResponse.value | ForEach-Object {
                            [PSCustomObject]@{
                                DeviceId        = $deviceId
                                ComputerName    = $device.computerDnsName
                                VulnerabilityId = $_.id
                                Severity        = $_.severity
                                CveId           = if ($_.cveId) { $_.cveId } else { $_.id }
                                Title           = $_.name
                            }
                        }
                        $vulnerabilitiesData | Export-Csv -Path $VulnerabilitiesCsvPath -NoTypeInformation -Encoding UTF8 -Append
                        Write-Host "Vulnerabilities for $($device.computerDnsName) exported." -ForegroundColor Yellow
                    }
                } catch {
                    Write-Warning "Error for device $deviceId: $($_.Exception.Message)"
                }
            }
        } else {
            Write-Warning "No devices found with the given criteria."
        }
    } else {
        Write-Warning "No device data returned."
    }
}
catch {
    if ($_.Exception.Response.StatusCode -eq 429) {
        Write-Error "Rate limit exceeded. Try again later."
    } else {
        Write-Error "An error occurred: $($_.Exception.Message)"
    }
}
