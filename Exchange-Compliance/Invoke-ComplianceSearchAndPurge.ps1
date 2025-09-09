<#
.SYNOPSIS
  Creates and runs an Exchange Online compliance search for emails by subject, sender, and date range,
  with an optional soft purge of matching emails.

.DESCRIPTION
  This script connects to Exchange Online Security & Compliance Center using the ExchangeOnlineManagement module. 
  It prompts the user for search parameters (date range, subject, sender) and ensures the compliance search name 
  is unique (deleting existing searches if chosen).  
  After running the compliance search, it optionally performs a soft purge (permanent delete) of the results.

.EXAMPLE
  .\Invoke-ComplianceSearchAndPurge.ps1

.NOTES
  Requirements:
    - ExchangeOnlineManagement module:
      Install-Module ExchangeOnlineManagement -Force -AllowClobber
    - Appropriate permissions in Microsoft Purview Compliance Portal
    - Purge action is irreversible. Use with caution.
#>

# --- Ensure ExchangeOnlineManagement module is installed
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber
}
Import-Module ExchangeOnlineManagement

# --- Connect to Exchange Online Security & Compliance Center
# Replace with Connect-ExchangeOnline if using EXO directly
Connect-IPPSSession   # <-- interactive login required

# --- Function: Calculate difference in days between two dates
function Calculate-DateDifference {
    param (
        [string]$StartDate,
        [string]$EndDate
    )
    $start = [datetime]::ParseExact($StartDate, 'MM/dd/yyyy', $null)
    $end   = [datetime]::ParseExact($EndDate, 'MM/dd/yyyy', $null)
    return ($end - $start).Days
}

# --- Function: Prompt for a compliance search name and handle conflicts
function Prompt-ComplianceName {
    param ([string]$PromptMessage)

    while ($true) {
        $ComplianceName = Read-Host $PromptMessage
        $existingSearch = Get-ComplianceSearch -Identity $ComplianceName -ErrorAction SilentlyContinue

        if ($existingSearch) {
            $response = Read-Host "A compliance search with the name '$ComplianceName' already exists. Delete it? (Y/N)"
            if ($response -eq 'Y') {
                Remove-ComplianceSearch -Identity $ComplianceName -Confirm:$false
                Write-Host "Deleted existing compliance search '$ComplianceName'."
                return $ComplianceName
            } else {
                Write-Host "Please enter a different compliance search name."
            }
        } else {
            return $ComplianceName
        }
    }
}

# --- Prompt for search name
$ComplianceName = Prompt-ComplianceName "Enter the name of your compliance search"

# --- Prompt for dates and validate they are at least 1 day apart
while ($true) {
    $StartDate = Read-Host "Enter start date of search range (MM/DD/YYYY)"
    $EndDate   = Read-Host "Enter end date of search range (MM/DD/YYYY)"

    $dateDifference = Calculate-DateDifference -StartDate $StartDate -EndDate $EndDate
    if ($dateDifference -ge 1) { break }
    else { Write-Host "End date must be at least one day after start date. Try again." }
}

# --- Prompt for subject and sender
$Subject     = Read-Host "Enter the subject of the email"
$SenderEmail = Read-Host "Enter the sender email address"

# --- Build query string
$queryString = "(Received:`"$StartDate..$EndDate`") AND (Subject:`"$Subject`") AND (from:`"$SenderEmail`")"

# --- Create and run the compliance search
$Search = New-ComplianceSearch -Name $ComplianceName -ExchangeLocation All -ContentMatchQuery $queryString
Start-ComplianceSearch -Identity $ComplianceName

Write-Host "Compliance search started. This may take 5+ minutes..."

# --- Poll search status until completed
$status = Get-ComplianceSearch -Identity $ComplianceName
while ($status.Status -ne 'Completed') {
    Write-Host "Search status: $($status.Status)..."
    Start-Sleep -Seconds 30
    $status = Get-ComplianceSearch -Identity $ComplianceName
}

# --- Display results
Get-ComplianceSearch -Identity $ComplianceName

Read-Host -Prompt "Finished! Press Enter to continue"

# --- Prompt for optional purge
$softPurgeResponse = Read-Host "Do you want to perform a soft purge of the emails found in '$ComplianceName'? (Y/N) [WARNING: This PERMANENTLY deletes emails]"
if ($softPurgeResponse -eq 'Y') {
    New-ComplianceSearchAction -Identity $ComplianceName -Purge -PurgeType SoftDelete
    Write-Host "Soft purge completed." -ForegroundColor Red
} else {
    Write-Host "Purge operation cancelled." -ForegroundColor Yellow
}
