<#
.SYNOPSIS
  Sorts computers by matching their IP addresses against a list of subnets.

.DESCRIPTION
  This script reads two CSV files:
   - A list of computers with IP addresses (`ComputersandIPs.csv`)
   - A list of subnets (`Subnets.csv`)
  
  For each computer, it checks each IP address against the subnets using a /24 mask 
  (customizable if needed). Results include computer name, IP, last seen, subnet scope, 
  and subnet name. Non-matching IPs are flagged as "No Match".

.EXAMPLE
  .\Sort-ComputersBySubnet.ps1 -ComputersFile "C:\Data\Computers.csv" -SubnetsFile "C:\Data\Subnets.csv" -OutputFile "C:\Data\SortedComputers.csv"

.PARAMETER ComputersFile
  Path to CSV containing at least `ComputerName`, `IPAddress`, and `LastSeen` columns.

.PARAMETER SubnetsFile
  Path to CSV containing at least `Scope` and `SubnetName` columns.

.PARAMETER OutputFile
  Path for the output CSV.

.NOTES
  - Assumes a /24 subnet mask by default
  - Multiple IPs per computer should be separated by commas, semicolons, or spaces
#>

param(
  [string]$ComputersFile = "C:\Reports\ComputersandIPs.csv",
  [string]$SubnetsFile   = "C:\Reports\Subnets.csv",
  [string]$OutputFile    = "C:\Reports\SortedComputers.csv"
)

# --- Import input CSV files
$computers = Import-Csv -Path $ComputersFile
$subnets   = Import-Csv -Path $SubnetsFile

# --- Function: check if an IP belongs to a subnet
function Match-Subnet {
    param (
        [string]$ipAddress,
        [string]$subnet
    )
    # Default mask: /24
    $mask = "255.255.255.0"

    $ipInt     = [uint32]([ipaddress]$ipAddress).Address
    $subnetInt = [uint32]([ipaddress]$subnet).Address
    $maskInt   = [uint32]([ipaddress]$mask).Address

    return ($ipInt -band $maskInt) -eq ($subnetInt -band $maskInt)
}

# --- Process computers
$sortedComputers = foreach ($computer in $computers) {
    # Split multiple IPs by comma, semicolon, or space
    $ipAddresses = $computer.IPAddress -split '[,;\s]+' | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+' }

    foreach ($ipAddress in $ipAddresses) {
        # Check against each subnet
        $matchingSubnet = $subnets | Where-Object {
            Match-Subnet -ipAddress $ipAddress -subnet $_.Scope
        }

        if ($matchingSubnet) {
            foreach ($sub in $matchingSubnet) {
                [PSCustomObject]@{
                    ComputerName = $computer.ComputerName
                    IPAddress    = $ipAddress
                    LastSeen     = $computer.LastSeen
                    SubnetScope  = $sub.Scope
                    SubnetName   = $sub.SubnetName
                }
            }
        } else {
            [PSCustomObject]@{
                ComputerName = $computer.ComputerName
                IPAddress    = $ipAddress
                LastSeen     = $computer.LastSeen
                SubnetScope  = "No Match"
                SubnetName   = "No Match"
            }
        }
    }
}

# --- Export results
$sortedComputers | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8 -Force

Write-Host "Sorted computers have been exported to $OutputFile" -ForegroundColor Green
