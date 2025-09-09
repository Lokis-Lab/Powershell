<#
.SYNOPSIS
  Exports user created date, last sign-in, and MFA status without hard-coding any client credentials.

.DESCRIPTION
  This script connects interactively to Microsoft Graph using the Microsoft.Graph PowerShell SDK. 
  It retrieves user account details (creation date, last sign-in) and determines MFA registration status. 
  Reports are exported to CSV files.

.PARAMETER InputFile
  Optional path to a CSV containing a column named 'UserPrincipalName'. 
  If omitted, the script queries all users in the tenant.

.PARAMETER UserDetailsOut
  Output CSV file path for user account details (created date, last sign-in).

.PARAMETER MFAReportOut
  Output CSV file path for MFA status (per user).

.EXAMPLE
  .\Export-MFAStatusReport.ps1 -InputFile .\UsersWithoutMFA.csv -UserDetailsOut .\UserDetails.csv -MFAReportOut .\MFAStatus.csv

.NOTES
  Requirements:
    - Microsoft.Graph module (v2+). Install once as admin:
      Install-Module Microsoft.Graph -Scope AllUsers
    - Admin consent for scopes: AuditLog.Read.All, User.Read.All, UserAuthenticationMethod.Read.All
#>

param(
  [string]$InputFile     = "<PATH_TO_CSV>\UsersWithoutMFA.csv",  # <-- Replace with path to input CSV if using
  [string]$UserDetailsOut = "<OUTPUT_PATH>\UserDetails.csv",     # <-- Replace with desired export path
  [string]$MFAReportOut   = "<OUTPUT_PATH>\MFAStatus.csv"        # <-- Replace with desired export path
)

# --- Helper: ensure Graph module is available
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
  throw "Microsoft.Graph module not found. Install it with: Install-Module Microsoft.Graph -Scope CurrentUser"
}
Import-Module Microsoft.Graph

# --- Connect to Graph (interactive; no secrets in script)
$scopes = @(
  "AuditLog.Read.All",
  "User.Read.All",
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

# --- Input set: from CSV (if present) else all users
$targetUsers = @()
if (Test-Path -LiteralPath $InputFile) {
  try {
    $csv = Import-Csv -LiteralPath $InputFile
    if (-not ($csv | Get-Member -Name UserPrincipalName -MemberType NoteProperty)) {
      throw "Input CSV must have a 'UserPrincipalName' column."
    }
    $upns = $csv.UserPrincipalName | Where-Object { $_ -and $_.Trim() -ne "" } | Select-Object -Unique
    foreach ($upn in $upns) {
      try {
        $u = Get-MgUser -UserId $upn -Property "id,displayName,userPrincipalName,createdDateTime" -ErrorAction Stop
        $targetUsers += $u
      } catch {
        Write-Warning "Could not fetch user '$upn': $($_.Exception.Message)"
      }
    }
  } catch {
    throw "Failed to read input CSV '$InputFile': $($_.Exception.Message)"
  }
} else {
  Write-Host "No input CSV found. Querying all users..." -ForegroundColor Yellow
  $targetUsers = Get-MgUser -All -Property "id,displayName,userPrincipalName,createdDateTime"
}

# --- Functions
function Get-LastSignIn {
  param([string]$UserPrincipalName)

  try {
    $signIn = Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$UserPrincipalName'" -Top 1 -Orderby "createdDateTime desc"
    if ($signIn) { return $signIn.createdDateTime }
    else { return $null }
  } catch {
    Write-Warning "Sign-in query failed for $UserPrincipalName: $($_.Exception.Message)"
    return $null
  }
}

function Get-MFAEnabled {
  param([Parameter(Mandatory)] [string]$UserId)

  $hasMfa = $false
  try {
    if (-not $hasMfa) {
      $auth = Get-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $UserId -ErrorAction Stop
      if ($auth.Count -gt 0) { $hasMfa = $true }
    }
    if (-not $hasMfa) {
      $phones = Get-MgUserAuthenticationPhoneMethod -UserId $UserId -ErrorAction Stop
      if ($phones | Where-Object { $_.PhoneType -in @('mobile','alternateMobile','office') -and $_.PhoneNumber }) {
        $hasMfa = $true
      }
    }
    if (-not $hasMfa) {
      $fido = Get-MgUserAuthenticationFido2Method -UserId $UserId -ErrorAction Stop
      if ($fido.Count -gt 0) { $hasMfa = $true }
    }
    if (-not $hasMfa) {
      $oath = Get-MgUserAuthenticationSoftwareOathMethod -UserId $UserId -ErrorAction Stop
      if ($oath.Count -gt 0) { $hasMfa = $true }
    }
    if (-not $hasMfa) {
      $whfb = Get-MgUserAuthenticationWindowsHelloForBusinessMethod -UserId $UserId -ErrorAction Stop
      if ($whfb.Count -gt 0) { $hasMfa = $true }
    }
    if (-not $hasMfa) {
      try {
        $tap = Get-MgUserAuthenticationTemporaryAccessPassMethod -UserId $UserId -ErrorAction Stop
        if ($tap.Count -gt 0) { $hasMfa = $true }
      } catch { } # TAP may not exist everywhere
    }
    return $hasMfa
  }
  catch {
    Write-Warning ("MFA method query failed for {0}: {1}" -f $UserId, $_.Exception.Message)
    return $false
  }
}

# --- Collect details
$userDetails = New-Object System.Collections.Generic.List[object]
$mfaStatus   = New-Object System.Collections.Generic.List[object]

$idx = 0
$total = $targetUsers.Count
foreach ($u in $targetUsers) {
  $idx++
  Write-Progress -Activity "Processing users" -Status "$idx of $total: $($u.userPrincipalName)" -PercentComplete (($idx/$total)*100)

  $created = $u.createdDateTime
  $lastSignIn = Get-LastSignIn -UserPrincipalName $u.userPrincipalName

  $userDetails.Add([PSCustomObject]@{
    UserPrincipalName = $u.userPrincipalName
    DisplayName       = $u.displayName
    CreatedDate       = $created
    LastSignInDate    = if ($lastSignIn) { $lastSignIn } else { "N/A" }
  })

  $mfaEnabled = Get-MFAEnabled -UserId $u.Id
  $mfaStatus.Add([PSCustomObject]@{
    DisplayName       = $u.displayName
    UserPrincipalName = $u.userPrincipalName
    MFAEnabled        = [bool]$mfaEnabled
  })
}

# --- Export
$userDetails | Sort-Object UserPrincipalName | Export-Csv -LiteralPath $UserDetailsOut -NoTypeInformation -Encoding UTF8
$mfaStatus   | Sort-Object UserPrincipalName | Export-Csv -LiteralPath $MFAReportOut   -NoTypeInformation -Encoding UTF8

Write-Host "User details exported to $UserDetailsOut" -ForegroundColor Green
Write-Host "MFA status report exported to $MFAReportOut" -ForegroundColor Green
