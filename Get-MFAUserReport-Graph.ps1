<#
.SYNOPSIS
  Generates a report of Azure Active Directory (Entra ID) user accounts with their MFA state, 
  default method, phone details, licensing status, and SMTP addresses.

.DESCRIPTION
  This script uses the Microsoft Graph PowerShell SDK to retrieve all non-guest Azure AD users. 
  For each user, it checks MFA registration methods, licensing, and proxy addresses. 
  Results are exported to CSV and displayed in a grid view.

.EXAMPLE
  .\Get-MFAUserReport-Graph.ps1

.NOTES
  Requirements:
    - Microsoft.Graph module (v2+). Install once as admin:
      Install-Module Microsoft.Graph -Scope AllUsers
    - Required delegated permissions (scopes):
      User.Read.All, Directory.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All
#>

param(
  [string]$OutputCsv = "C:\Reports\MFAUsers.csv"  # <-- Update export path
)

# --- Ensure Graph module is loaded
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
  throw "Microsoft.Graph module not found. Install it with: Install-Module Microsoft.Graph -Scope CurrentUser"
}
Import-Module Microsoft.Graph

# --- Connect to Graph
$scopes = @(
  "User.Read.All",
  "Directory.Read.All",
  "UserAuthenticationMethod.Read.All"
)

try {
  if (-not (Get-MgContext)) {
    Connect-MgGraph -Scopes $scopes | Out-Null
  } else {
    $haveScopes = (Get-MgContext).Scopes
    if (-not $haveScopes -or ($scopes | Where-Object { $_ -notin $haveScopes })) {
      Disconnect-MgGraph | Out-Null
      Connect-MgGraph -Scopes $scopes | Out-Null
    }
  }
}
catch {
  throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

Write-Host "Finding Azure Active Directory Accounts..." -ForegroundColor Cyan

# --- Get all non-guest users
$Users = Get-MgUser -All -Property "id,displayName,userPrincipalName,userType,identities,proxyAddresses,assignedLicenses" |
          Where-Object { $_.UserType -ne "Guest" }

Write-Host "Processing $($Users.Count) accounts..." -ForegroundColor Cyan

# --- Storage for report
$Report = [System.Collections.Generic.List[Object]]::new()

foreach ($User in $Users) {

    # MFA Methods
    $MFADefaultMethod = "Not enabled"
    $MFAPhoneNumber   = $null
    $MFAState         = "Disabled"

    try {
        $methods = Get-MgUserAuthenticationMethod -UserId $User.Id -ErrorAction Stop
        if ($methods) {
            $MFAState = "Enabled"
            foreach ($m in $methods) {
                switch ($m.AdditionalProperties["@odata.type"]) {
                    "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" { $MFADefaultMethod = "Microsoft Authenticator app" }
                    "#microsoft.graph.phoneAuthenticationMethod" {
                        $MFADefaultMethod = "Phone (SMS/Call)"
                        $MFAPhoneNumber   = $m.PhoneNumber
                    }
                    "#microsoft.graph.fido2AuthenticationMethod" { $MFADefaultMethod = "FIDO2 Security Key" }
                    "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" { $MFADefaultMethod = "Windows Hello for Business" }
                    "#microsoft.graph.softwareOathAuthenticationMethod" { $MFADefaultMethod = "Authenticator app or OATH token" }
                    "#microsoft.graph.temporaryAccessPassAuthenticationMethod" { $MFADefaultMethod = "Temporary Access Pass" }
                }
            }
        }
    } catch {
        Write-Warning "Could not query MFA methods for $($User.UserPrincipalName): $($_.Exception.Message)"
    }

    # Licensing
    $License       = $User.AssignedLicenses.SkuId
    $LicenseStatus = if ($License) { "Licensed" } else { "Unlicensed" }

    # ProxyAddresses
    $PrimarySMTP = $User.ProxyAddresses | Where-Object { $_ -cmatch "^SMTP:" } | ForEach-Object { $_ -replace "SMTP:", "" }
    $Aliases     = $User.ProxyAddresses | Where-Object { $_ -cmatch "^smtp:" } | ForEach-Object { $_ -replace "smtp:", "" }

    # Build report object
    $ReportLine = [PSCustomObject]@{
        UserPrincipalName = $User.UserPrincipalName
        DisplayName       = $User.DisplayName
        MFAState          = $MFAState
        MFADefaultMethod  = $MFADefaultMethod
        MFAPhoneNumber    = $MFAPhoneNumber
        PrimarySMTP       = ($PrimarySMTP -join ',')
        Aliases           = ($Aliases -join ',')
        LicenseStatus     = $LicenseStatus
        LicenseSkuIds     = ($License -join ',')
    }

    $Report.Add($ReportLine)
}

# --- Export results
Write-Host "Exporting report to $OutputCsv" -ForegroundColor Green

$Report | Sort-Object UserPrincipalName |
    Export-Csv -Encoding UTF8 -NoTypeInformation -LiteralPath $OutputCsv

# --- Display in interactive grid
$Report | Sort-Object UserPrincipalName |
    Out-GridView -Title "Azure AD MFA User Report"
