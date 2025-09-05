# Powershell
Repo for useful Powershell scripts. These have been sanatized of any personalization to be modifed by other people to use in their envrionments
----------------------------------------------------------------------------
### Script: Export-MFAStatusReport.ps1

**Purpose**  
Exports user creation date, last sign-in, and MFA status for accounts in Azure AD using Microsoft Graph.

**Usage**  
```powershell
.\Export-MFAStatusReport.ps1 -InputFile .\UsersWithoutMFA.csv -UserDetailsOut .\UserDetails.csv -MFAReportOut .\MFAStatus.csv
```
-----------------------------------------------------------------------
### Script: Get-MFAUserReport-Graph.ps1

**Purpose**  
Generates a report of Azure AD (Entra ID) users with MFA configuration, licensing status, and SMTP addresses.  

**Usage**  
```powershell
.\Get-MFAUserReport-Graph.ps1 -OutputCsv "C:\Reports\MFAUsers.csv"
```
--------------------------------------------------------------------------
### Script: Get-ADPasswordExpiryReport.ps1

**Purpose**  
Generates a report of Active Directory users with password expiration details.  

**Usage**  
```powershell
.\Get-ADPasswordExpiryReport.ps1 -OutputCsv "C:\Reports\AD_PasswordExpiryReport.csv"
```
--------------------------------------------------------------------------------
### Script: Invoke-ComplianceSearchAndPurge.ps1

**Purpose**  
Runs a compliance search in Exchange Online (Purview) based on subject, sender, and date range, with the option to soft purge results.

**Usage**  
```powershell
.\Invoke-ComplianceSearchAndPurge.ps1
```
------------------------------------------------------------------------------------
### Script: Remove-QuarantineMessagesBySender.ps1

**Purpose**  
Connects to Exchange Online and Purview Security & Compliance Center, then deletes all quarantined messages from a specific sender.

**Usage**  
```powershell
.\Remove-QuarantineMessagesBySender.ps1
```
----------------------------------------------------------------------------------------
### Script: Get-DefenderStatusADComputers.ps1

**Purpose**  
Queries all Active Directory computers and retrieves Microsoft Defender Antivirus status details.

**Usage**  
```powershell
.\Get-DefenderStatusADComputers.ps1 -OutputCsvPath "C:\Reports\DefenderStatus.csv"
```
---------------------------------------------------------------------------------------------
### Script: Invoke-LapsPasswordReset.ps1

**Purpose**  
Resets LAPS passwords on a list of computers from Active Directory or a CSV file.  

**Usage**  
- From AD:  
```powershell
.\Invoke-LapsPasswordReset.ps1 -Mode AD -OU "DC=flsen,DC=gov" -DomainSuffix "flsen.gov" -OutputCsvPath "C:\Reports\laps_reset_results.csv"
```
------------------------------------------------------------------------------------------------
### Script: Set-ADPasswordsNeverExpire.ps1

**Purpose**  
Sets the "PasswordNeverExpires" attribute to True for all enabled AD user accounts.

**Usage**  
```powershell
.\Set-ADPasswordsNeverExpire.ps1
```
--------------------------------------------------------------------------------------------------
