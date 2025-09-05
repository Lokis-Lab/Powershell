# Powershell
Repo for useful Powershell scripts

### Script: Export-MFAStatusReport.ps1

**Purpose**  
Exports user creation date, last sign-in, and MFA status for accounts in Azure AD using Microsoft Graph.

**Usage**  
```powershell
.\Export-MFAStatusReport.ps1 -InputFile .\UsersWithoutMFA.csv -UserDetailsOut .\UserDetails.csv -MFAReportOut .\MFAStatus.csv
