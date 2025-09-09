<#
.SYNOPSIS
  Resets LAPS passwords on a set of computers (queried from AD or imported from CSV).

.DESCRIPTION
  This script can run in two modes:
  - Query Active Directory for computer objects in a specified OU (and sub-OUs).
  - Import a list of external servers from a CSV file.
  
  For each computer, the script checks if it is online and then attempts to reset its LAPS password 
  using `Reset-LapsPassword`. Results are logged and exported to CSV.

.PARAMETER Mode
  Selects input mode: "AD" (query Active Directory) or "CSV" (import from file).

.PARAMETER OU
  DistinguishedName of the top-level OU to search (required if Mode is "AD").

.PARAMETER InputCsvPath
  Path to input CSV containing a column "ComputerName" (required if Mode is "CSV").

.PARAMETER DomainSuffix
  Domain suffix to append to computer names (e.g., "flsen.gov" or "ext.flsen.gov").

.PARAMETER OutputCsvPath
  Path where results will be saved.

.EXAMPLE
  .\Invoke-LapsPasswordReset.ps1 -Mode AD -OU "DC=flsen,DC=gov" -DomainSuffix "flsen.gov" -OutputCsvPath "C:\Reports\laps_reset_results.csv"

.EXAMPLE
  .\Invoke-LapsPasswordReset.ps1 -Mode CSV -InputCsvPath "C:\Reports\EXTservers.csv" -DomainSuffix "ext.flsen.gov" -OutputCsvPath "C:\Reports\EXTlaps_reset_results.csv"

.NOTES
  Requirements:
    - ActiveDirectory PowerShell module (for Mode "AD")
    - LAPS management tools installed
    - Admin rights on target computers
    - PowerShell remoting enabled
#>

param(
  [Parameter(Mandatory=$true)]
  [ValidateSet("AD","CSV")]
  [string]$Mode,

  [string]$OU,                  # Required if Mode = AD
  [string]$InputCsvPath,        # Required if Mode = CSV
  [string]$DomainSuffix,        # e.g., "flsen.gov" or "ext.flsen.gov"
  [string]$OutputCsvPath = "C:\Reports\LAPS_Reset_Results.csv"
)

# --- Import AD module if needed
if ($Mode -eq "AD") {
    Import-Module ActiveDirectory
}

# --- Get list of computers
switch ($Mode) {
    "AD" {
        if (-not $OU) { throw "OU must be specified when using Mode 'AD'." }
        $computers = Get-ADComputer -SearchBase $OU -SearchScope Subtree -Filter * -Property Name |
                     Select-Object -ExpandProperty Name -Unique
    }
    "CSV" {
        if (-not $InputCsvPath) { throw "InputCsvPath must be specified when using Mode 'CSV'." }
        $computers = Import-Csv $InputCsvPath | Select-Object -ExpandProperty ComputerName -Unique
    }
}

# --- Process computers
$results = foreach ($computer in $computers) {
    $fqdn = "{0}.{1}" -f $computer, $DomainSuffix

    $pingResult = Test-Connection -ComputerName $fqdn -Count 1 -Quiet

    if ($pingResult) {
        Write-Host "Computer $fqdn is online. Resetting LAPS password..."
        try {
            Invoke-Command -ComputerName $fqdn -ScriptBlock { Reset-LapsPassword } -ErrorAction Stop
            [PSCustomObject]@{
                ComputerName = $fqdn
                Status       = "Password Reset Successful"
            }
        } catch {
            [PSCustomObject]@{
                ComputerName = $fqdn
                Status       = "Error: $($_.Exception.Message)"
            }
        }
    } else {
        Write-Host "Computer $fqdn is offline. Skipping..."
        [PSCustomObject]@{
            ComputerName = $fqdn
            Status       = "Offline - Skipped"
        }
    }
}

# --- Export results
$results | Export-Csv -Path $OutputCsvPath -NoTypeInformation -Encoding UTF8 -Force

Write-Host "Process completed. Results saved to $OutputCsvPath" -ForegroundColor Green
