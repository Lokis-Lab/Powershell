<#
.SYNOPSIS
  Sets the "PasswordNeverExpires" flag to True for all enabled Active Directory users.

.DESCRIPTION
  This script queries all enabled AD users and checks if their "PasswordNeverExpires" 
  flag is set. If not, it updates the account to set the flag to True.  
  Skips accounts already configured with PasswordNeverExpires.

.EXAMPLE
  .\Set-ADPasswordsNeverExpire.ps1

.NOTES
  Requirements:
    - ActiveDirectory PowerShell module (RSAT tools or run from domain controller)
    - Permissions to modify user account attributes in Active Directory
  ⚠ WARNING: This overrides domain password policies by preventing password expiry for all users. 
  Use with extreme caution.
#>

# --- Import AD module
Import-Module ActiveDirectory

# --- Get all enabled users
$users = Get-ADUser -Filter { Enabled -eq $true } -Properties SamAccountName, PasswordNeverExpires

foreach ($user in $users) {
    if (-not $user.PasswordNeverExpires) {
        try {
            # Set PasswordNeverExpires flag
            Set-ADUser -Identity $user.SamAccountName -PasswordNeverExpires $true
            Write-Host "Password never expires set for: $($user.SamAccountName)" -ForegroundColor Green
        } catch {
            Write-Host "Failed to set PasswordNeverExpires for: $($user.SamAccountName). Error: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Already set to never expire: $($user.SamAccountName)" -ForegroundColor Yellow
    }
}

Write-Host "Operation complete." -ForegroundColor Cyan
