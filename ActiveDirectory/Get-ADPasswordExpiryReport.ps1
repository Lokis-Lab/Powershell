<#
.SYNOPSIS
  Generates a report of Active Directory users and their password expiration status.

.DESCRIPTION
  This script queries Active Directory for all enabled users, checks domain password 
  policy, and calculates each user’s password expiration date.  
  Results are displayed in a table and exported to a CSV file.

.EXAMPLE
  .\Get-ADPasswordExpiryReport.ps1 -OutputCsv "C:\Reports\AD_PasswordExpiryReport.csv"

.PARAMETER OutputCsv
  Path where the report CSV will be saved.

.NOTES
  Requirements:
    - ActiveDirectory PowerShell module (RSAT tools or domain controller)
    - Permissions to query AD user accounts and password policy
#>

param(
  [string]$OutputCsv = "C:\Reports\AD_PasswordExpiryReport.csv"   # <-- Update path as needed
)

# --- Import AD module
Import-Module ActiveDirectory

# --- Get domain password policy settings
$maxPasswordAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge

# --- Get all enabled users with required properties
$users = Get-ADUser -Filter { Enabled -eq $true } -Properties DisplayName, SamAccountName, PasswordNeverExpires, PasswordLastSet

# --- Build results
$results = foreach ($user in $users) {
    $passwordExpires = switch ($true) {
        ($user.PasswordNeverExpires -eq $true) { "Never"; break }
        ($user.PasswordLastSet -ne $null -and $maxPasswordAge.Days -gt 0) { $user.PasswordLastSet.AddDays($maxPasswordAge.Days); break }
        Default { "Not Set" }
    }
    
    [PSCustomObject]@{
        DisplayName          = $user.DisplayName
        SamAccountName       = $user.SamAccountName
        PasswordNeverExpires = $user.PasswordNeverExpires
        PasswordLastSet      = $user.PasswordLastSet
        PasswordExpires      = $passwordExpires
    }
}

# --- Display results
$results | Format-Table -AutoSize

# --- Export results to CSV
$results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

Write-Host "Password expiry report exported to $OutputCsv" -ForegroundColor Green
