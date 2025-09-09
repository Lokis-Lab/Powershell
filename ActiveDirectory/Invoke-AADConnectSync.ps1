<#
.SYNOPSIS
  Triggers an Azure AD Connect (ADSync) sync cycle on a remote server and shows scheduler status.

.DESCRIPTION
  Uses PowerShell remoting to invoke Start-ADSyncSyncCycle (Delta or Initial) on the specified
  Azure AD Connect server, waits briefly, then retrieves Get-ADSyncScheduler results.

.PARAMETER ServerName
  FQDN or name of the Azure AD Connect server (e.g., "AADC01.contoso.com").

.PARAMETER PolicyType
  Sync cycle type to run. "Delta" (most common) or "Initial" (full).

.PARAMETER WaitSeconds
  Number of seconds to wait before fetching scheduler status.

.EXAMPLE
  .\Invoke-AADConnectSync.ps1 -ServerName "AADC01.contoso.com" -PolicyType Delta -WaitSeconds 10

.NOTES
  Requirements:
    - PowerShell remoting enabled and accessible to the target server.
    - Run with an account permitted to invoke commands on the AAD Connect server.
    - The ADSync module must be installed on the target server.
#>

param(
  [Parameter(Mandatory=$true)]
  [string]$ServerName = "<AADC_SERVER_FQDN>",  # <-- replace with your AAD Connect server FQDN

  [ValidateSet('Delta','Initial')]
  [string]$PolicyType = 'Delta',               # <-- choose 'Delta' (incremental) or 'Initial' (full)

  [int]$WaitSeconds = 8                        # <-- adjust if your environment needs more time
)

Clear-Host

Write-Host ""
Write-Host "Starting Azure AD Connect sync ($PolicyType) on $ServerName..." -ForegroundColor Cyan
Write-Host ""

# Kick off the sync remotely
try {
  Invoke-Command -ComputerName $ServerName -ErrorAction Stop -ScriptBlock {
    # Ensure ADSync module is available on the remote server
    if (-not (Get-Module -ListAvailable -Name ADSync)) {
      throw "ADSync module not found on this server. Install/verify Azure AD Connect."
    }

    Import-Module ADSync -ErrorAction Stop
    Start-ADSyncSyncCycle -PolicyType $using:PolicyType -ErrorAction Stop
  } | Out-Null

  Write-Host "Sync cycle invoked successfully." -ForegroundColor Green
}
catch {
  Write-Host "Failed to start sync on $ServerName: $($_.Exception.Message)" -ForegroundColor Red
  return
}

# Wait to allow the cycle to register
Write-Host ""
Write-Host ("Waiting {0} seconds for ADSync to progress..." -f $WaitSeconds) -ForegroundColor Yellow
Write-Host ""
Start-Sleep -Seconds $WaitSeconds

# Fetch scheduler status
Write-Host "Retrieving ADSync scheduler status from $ServerName..." -ForegroundColor Cyan
try {
  Invoke-Command -ComputerName $ServerName -ErrorAction Stop -ScriptBlock {
    if (-not (Get-Module -ListAvailable -Name ADSync)) {
      throw "ADSync module not found on this server. Install/verify Azure AD Connect."
    }
    Import-Module ADSync -ErrorAction Stop
    Get-ADSyncScheduler
  }
}
catch {
  Write-Host "Failed to retrieve scheduler status: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "AD Connect sync procedure completed." -ForegroundColor Green
Write-Host ""
