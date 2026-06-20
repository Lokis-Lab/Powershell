<#
.SYNOPSIS
  Exports Defender for Endpoint devices (optionally filtered by OS) and their vulnerabilities.
  Defaults to Commercial cloud; use -Cloud GCCH for GCC High.

.DESCRIPTION
  Authenticates with client credentials and queries MDE devices + per-device vulnerabilities.
#>

param(
  [Parameter(Mandatory=$true)][string]$TenantId,
  [Parameter(Mandatory=$true)][string]$ClientId,
  [Parameter(Mandatory=$true)][string]$ClientSecret,
  [ValidateSet('Commercial','GCCH')][string]$Cloud = 'Commercial',
  [string]$DevicesCsvPath         = "C:\Reports\Devices.csv",
  [string]$VulnerabilitiesCsvPath = "C:\Reports\Vulnerabilities.csv",
  [string]$OSPlatform             # e.g., Windows11/Windows10/Linux; omit for all
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
  # ^ Switch to GCC via -Cloud GCCH
}

# --- Auth
$body = [Ordered]@{
  client_id     = $ClientId
  scope         = $Scope
  client_secret = $ClientSecret
  grant_type    = "client_credentials"
}
$tokenResponse = Invoke-RestMethod -Method Post -Uri $TokenUrl -ContentType "application/x-www-form-urlencoded" -Body $body
$token = $tokenResponse.access_token
$header = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }

# --- Endpoints
$MachinesUrl = "$ApiBase/api/machines"  # <-- switches with cloud

# --- Devices (follow @odata.nextLink to avoid silent truncation)
$devices = [System.Collections.Generic.List[object]]::new()
$nextUrl = $MachinesUrl
while ($nextUrl) {
  $response = Invoke-RestMethod -Method Get -Uri $nextUrl -Headers $header -ErrorAction Stop
  if ($response.value) { $devices.AddRange(@($response.value)) }
  $nextUrl = $response.'@odata.nextLink'
}
$devices = @($devices)

# Optional filter by OS
if ($OSPlatform) { $devices = $devices | Where-Object { $_.osPlatform -eq $OSPlatform } }

# Filter out temp/decomm names as before
$devices = $devices | Where-Object { $_.computerDnsName -notmatch '^(minint-|sen-ready|sen-decomm|sacw|senready)' }

if (-not $devices -or $devices.Count -eq 0) {
  Write-Warning "No devices found with the given criteria."; return
}

# Export device list
$devices | Select-Object id, computerDnsName, osPlatform, healthStatus, lastSeen |
  Export-Csv -Path $DevicesCsvPath -NoTypeInformation -Encoding UTF8 -Force
Write-Host "Devices exported to $DevicesCsvPath" -ForegroundColor Green

# Per-device vulnerabilities
foreach ($device in $devices) {
  Start-Sleep -Seconds 1
  $vulnUrl = "$ApiBase/api/machines/$($device.id)/vulnerabilities"  # <-- switches with cloud

  try {
    $vulnRows = [System.Collections.Generic.List[object]]::new()
    $vulnNextUrl = $vulnUrl
    while ($vulnNextUrl) {
      $vulnResp = Invoke-RestMethod -Method Get -Uri $vulnNextUrl -Headers $header -ErrorAction Stop
      if ($vulnResp -and $vulnResp.value) {
        foreach ($_ in $vulnResp.value) {
          $vulnRows.Add([PSCustomObject]@{
            DeviceId          = $device.id
            ComputerName      = $device.computerDnsName
            VulnerabilityId   = $_.id
            Severity          = $_.severity
            CveId             = if ($_.cveId) { $_.cveId } else { $_.id }
            Title             = $_.name
          })
        }
      }
      $vulnNextUrl = $vulnResp.'@odata.nextLink'
    }

    if ($vulnRows.Count -gt 0) {
      $vulnRows | Export-Csv -Path $VulnerabilitiesCsvPath -NoTypeInformation -Encoding UTF8 -Append
      Write-Host "Vulnerabilities for $($device.computerDnsName) exported." -ForegroundColor Yellow
    }
  } catch {
    Write-Warning "Error for $($device.computerDnsName): $($_.Exception.Message)"
  }
}
