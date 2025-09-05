<#
.SYNOPSIS
  Retrieves Microsoft Defender Antivirus status from all Active Directory computers and exports results to CSV.

.DESCRIPTION
  This script queries all computer accounts from Active Directory, pings each host to check availability, 
  and runs `Get-MpComputerStatus` remotely (if online).  
  It collects Defender engine version, product version, protection settings, tamper protection, 
  and other status details.  
  Errors (offline or unreachable systems) are logged alongside healthy results.

.PARAMETER OutputCsvPath
  Path to save the results CSV.

.EXAMPLE
  .\Get-DefenderStatusADComputers.ps1 -OutputCsvPath "C:\Reports\DefenderStatus.csv"

.NOTES
  Requirements:
    - RSAT: Active Directory module
    - Administrator rights on remote systems
    - PowerShell Remoting (WinRM) must be enabled on target systems
#>

param(
  [string]$OutputCsvPath = "C:\Reports\DefenderStatus.csv"  # <-- Replace with your desired path
)

# --- Import AD module
Import-Module ActiveDirectory

# --- Get all AD computers
$computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

# --- Collect results
$results = foreach ($computerName in $computers) {

    # Replace domain suffix as needed
    $fqdn = "{0}.<YOURDOMAIN>" -f $computerName   # <-- Replace <YOURDOMAIN> with your AD domain (e.g., contoso.com)

    $computerStatus = [PSCustomObject]@{
        Name                        = $fqdn
        AMEngineVersion             = $null
        AMProductVersion            = $null
        AMRunningMode               = $null
        AMServiceEnabled            = $null
        AntivirusEnabled            = $null
        DefenderSignaturesOutOfDate = $null
        IsTamperProtected           = $null
        TamperProtectionSource      = $null
        Status                      = $null
        ErrorMsg                    = $null
        FullScanAge                 = $null
        LastFullScanStartTime       = $null
        BehaviorMonitorEnabled      = $null
        RealTimeProtectionEnabled   = $null
    }

    # --- Ping computer
    $pingResult = Test-Connection -ComputerName $fqdn -Count 2 -Quiet

    if ($pingResult) {
        Write-Host "Scanning $fqdn"
        try {
            $status = Invoke-Command -ComputerName $fqdn -ScriptBlock { Get-MpComputerStatus } -ErrorAction Stop

            # Populate status object
            $computerStatus.AMEngineVersion             = $status.AMEngineVersion
            $computerStatus.AMProductVersion            = $status.AMProductVersion
            $computerStatus.AMRunningMode               = $status.AMRunningMode
            $computerStatus.AMServiceEnabled            = $status.AMServiceEnabled
            $computerStatus.DefenderSignaturesOutOfDate = $status.DefenderSignaturesOutOfDate
            $computerStatus.IsTamperProtected           = $status.IsTamperProtected
            $computerStatus.TamperProtectionSource      = $status.TamperProtectionSource
            $computerStatus.Status                      = "OK"
            $computerStatus.FullScanAge                 = $status.FullScanAge
            $computerStatus.AntivirusEnabled            = $status.AntivirusEnabled
            $computerStatus.BehaviorMonitorEnabled      = $status.BehaviorMonitorEnabled
            $computerStatus.RealTimeProtectionEnabled   = $status.RealTimeProtectionEnabled
        } catch {
            Write-Warning "Failed to retrieve status from $fqdn - $_"
            $computerStatus.Status   = "Error"
            $computerStatus.ErrorMsg = $_.Exception.Message
        }
    } else {
        Write-Warning "$fqdn is offline."
        $computerStatus.Status   = "Offline"
        $computerStatus.ErrorMsg = "Computer not reachable"
    }

    $computerStatus
}

# --- Export results
$results | Export-Csv -Path $OutputCsvPath -NoTypeInformation -Encoding UTF8 -Force

Write-Host "Results exported to $OutputCsvPath" -ForegroundColor Green
