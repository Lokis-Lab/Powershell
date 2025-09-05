# Powershell
Repo for useful Powershell scripts. These have been sanatized of any personalization to be modifed by other people to use in their envrionments

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
