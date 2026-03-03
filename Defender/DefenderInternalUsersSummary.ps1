<#
.SYNOPSIS
  Defender Internal Users Email Summary (Cisco ESA replacement-style report).

.DESCRIPTION
  Uses Microsoft Defender for Office / M365 Defender Advanced Hunting API to
  generate an HTML "Internal Users Summary" style report for a given calendar day.

  This version is sanitized for public use. Look for "CONFIG:" comments below
  where you must plug in your own tenant/app/internal-domain details.

.OUTPUTS
  - Timestamped HTML report suitable for publishing or upload.

.NOTES
  - GCC example endpoints are used here. For commercial tenants, update the
    token and API base URLs as indicated in the CONFIG section.
  - Time window is a calendar day (00:00–23:59) in your local time.

CONFIG CHECKLIST (search for 'CONFIG:' below):
  1. CONFIG: Tenant/app registration environment variables (TENANT_ID / CLIENT_ID / CLIENT_SECRET)
  2. CONFIG: Internal SMTP domains list ($InternalDomains)
  3. CONFIG: Cloud endpoints (GCC vs Commercial)
#>

[CmdletBinding()]
param(
    # Where the report HTML will be written
    # CONFIG: Adjust default output path for your environment if desired.
    [string]$OutDir = "$PSScriptRoot\out\Security\User Email Summary",

    # 1 = yesterday (default), 0 = today, 2 = two days ago, etc.
    [ValidateRange(0, 30)]
    [int]$DaysBack = 1
)

# ==========================================================
# CONFIGURATION
# ==========================================================

# CONFIG: Tenant / App Registration
# ---------------------------------
# This script assumes you have an app registration with permissions like:
#   - AdvancedQuery.Read.All / ThreatHunting.Read.All (or equivalent in your environment)
# and that you expose its IDs/secrets as environment variables.
#
#   $env:TENANT_ID     = "<your-tenant-guid>"
#   $env:CLIENT_ID     = "<your-app-client-id>"
#   $env:CLIENT_SECRET = "<your-client-secret>"
#
$TenantId     = $env:TENANT_ID
$ClientId     = $env:CLIENT_ID
$ClientSecret = $env:CLIENT_SECRET

if (-not $TenantId -or -not $ClientId -or -not $ClientSecret) {
    throw "Missing required env vars: TENANT_ID, CLIENT_ID, CLIENT_SECRET (see CONFIG comment in script header)."
}

# CONFIG: Internal SMTP domains
# -----------------------------
# Replace these examples with your actual internal email domains.
# Example:
#   @("contoso.com","fabrikam.com")
$InternalDomains = @(
    "contoso.com",   # TODO: replace with your primary internal SMTP domain
    "fabrikam.com"   # TODO: replace or remove as needed
)
$InternalDomainsDyn = ($InternalDomains | ForEach-Object { '"' + $_ + '"' }) -join ","

# Report date (calendar day)
$ReportDate = (Get-Date).AddDays(-1 * $DaysBack)
$DateLabel  = $ReportDate.ToString("yyyy-MM-dd")
$TimeStamp  = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")

# Output
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$OutputFile = Join-Path $OutDir "UserEmailSummary_$TimeStamp.html"

# CONFIG: Cloud endpoints (GCC vs Commercial)
# -------------------------------------------
# GCC example (as previously used):
$TokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
$ApiBase       = "https://api-gcc.security.microsoft.us"
$MdeScope      = "https://api-gcc.security.microsoft.us/.default"
#
# For Commercial tenants, you would typically use:
#   $ApiBase  = "https://api.security.microsoft.com"
#   $MdeScope = "https://api.security.microsoft.com/.default"
# (Update both values if you are not on GCC.)

# ==========================================================
# AUTHENTICATION (MDE – client credentials)
# ==========================================================

Write-Host "Authenticating to Microsoft Defender..."

$TokenBody = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = $MdeScope
}

try {
    $TokenResponse = Invoke-RestMethod `
        -Method Post `
        -Uri $TokenEndpoint `
        -Body $TokenBody `
        -ContentType "application/x-www-form-urlencoded" `
        -ErrorAction Stop
} catch {
    throw "Failed to get access token: $($_.Exception.Message)"
}

$AccessToken = $TokenResponse.access_token
if (-not $AccessToken) {
    throw "Access token missing from token response."
}

$Headers = @{
    Authorization  = "Bearer $AccessToken"
    "Content-Type" = "application/json"
}

# ==========================================================
# FUNCTION: Run Defender Query (advanced hunting)
# ==========================================================

function Invoke-DefenderQuery {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Query
    )

    $BodyJson = (@{ Query = $Query } | ConvertTo-Json -Depth 10)

    try {
        $Response = Invoke-RestMethod `
            -Method Post `
            -Uri "$ApiBase/api/advancedhunting/run" `
            -Headers $Headers `
            -Body $BodyJson `
            -ErrorAction Stop
    } catch {
        $msg      = $_.Exception.Message
        $bodyText = $null

        if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream()) {
            try {
                $reader   = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $bodyText = $reader.ReadToEnd()
            } catch {}
        }

        if ($bodyText) { Write-Host "Advanced query failed response body:`n$bodyText" }
        throw "Advanced query failed: $msg"
    }

    return $Response.Results
}

# ==========================================================
# TIME WINDOW (calendar day)
# ==========================================================

$DateFilter = "Timestamp between (startofday(datetime($DateLabel)) .. endofday(datetime($DateLabel)))"

# ==========================================================
# QUERY DEFINITIONS
# ==========================================================

# Inbound category summary (Cisco-style)
$InboundCategoryQuery = @"
EmailEvents
| where $DateFilter
| where EmailDirection == "Inbound"
| extend Category =
    case(
        ThreatTypes has "Spam", "Spam Detected",
        ThreatTypes has "Malware", "Malware Detected",
        ThreatTypes has "Phish", "Phishing Detected",
        BulkComplaintLevel > 0, "Bulk Messages",
        isempty(ThreatTypes), "Clean Messages",
        "Other"
    )
| summarize Messages=count() by Category
| order by Messages desc
"@

# Top inbound threat recipients
$TopThreatQuery = @"
EmailEvents
| where $DateFilter
| where EmailDirection == "Inbound"
| where isnotempty(ThreatTypes)
| summarize Messages=count() by RecipientEmailAddress
| top 10 by Messages desc
"@

# Top inbound clean recipients
$TopCleanQuery = @"
EmailEvents
| where $DateFilter
| where EmailDirection == "Inbound"
| where isempty(ThreatTypes)
| summarize Messages=count() by RecipientEmailAddress
| top 10 by Messages desc
"@

# Top inbound graymail/bulk recipients
$TopGrayQuery = @"
EmailEvents
| where $DateFilter
| where EmailDirection == "Inbound"
| where BulkComplaintLevel > 0
| summarize Messages=count() by RecipientEmailAddress
| top 10 by Messages desc
"@

# Outgoing totals (Total/Internal/External) — does NOT rely on EmailDirection == "Outbound"
$OutboundTotalsQuery = @"
let InternalDomains = dynamic([$InternalDomainsDyn]);
EmailEvents
| where $DateFilter
| where isnotempty(RecipientEmailAddress)
| extend From = coalesce(SenderFromAddress, SenderMailFromAddress)
| where isnotempty(From)
| extend SenderDomain = tostring(split(From, "@")[1])
| extend RcptDomain   = tostring(split(RecipientEmailAddress, "@")[1])
| where SenderDomain in~ (InternalDomains)
| extend SentScope = iff(RcptDomain in~ (InternalDomains), "Internal", "External")
| summarize Messages=count() by SentScope
| union (
    EmailEvents
    | where $DateFilter
    | where isnotempty(RecipientEmailAddress)
    | extend From = coalesce(SenderFromAddress, SenderMailFromAddress)
    | where isnotempty(From)
    | extend SenderDomain = tostring(split(From, "@")[1])
    | where SenderDomain in~ (InternalDomains)
    | summarize Messages=count()
    | extend SentScope="Total"
)
| order by case(SentScope=="Total",0, SentScope=="External",1, 2) asc
"@

# Top “sent by us” senders — captures NOREPLY_* + shared mailboxes even if IntraOrg
$OutboundTopSendersQuery = @"
let InternalDomains = dynamic([$InternalDomainsDyn]);
EmailEvents
| where $DateFilter
| where isnotempty(RecipientEmailAddress)
| extend From = coalesce(SenderFromAddress, SenderMailFromAddress)
| where isnotempty(From)
| extend SenderDomain = tostring(split(From, "@")[1])
| where SenderDomain in~ (InternalDomains)
| summarize Messages=count() by From
| top 20 by Messages desc
"@

# ==========================================================
# EXECUTE QUERIES
# ==========================================================

Write-Host "Running queries for date: $DateLabel (DaysBack=$DaysBack)..."

$InboundCategory = Invoke-DefenderQuery $InboundCategoryQuery
$TopThreat       = Invoke-DefenderQuery $TopThreatQuery
$TopClean        = Invoke-DefenderQuery $TopCleanQuery
$TopGray         = Invoke-DefenderQuery $TopGrayQuery
$OutboundTotals  = Invoke-DefenderQuery $OutboundTotalsQuery
$OutboundTop     = Invoke-DefenderQuery $OutboundTopSendersQuery

# ==========================================================
# CALCULATE INBOUND % (Cisco-style)
# ==========================================================

$TotalInbound = ($InboundCategory | Measure-Object Messages -Sum).Sum
if (-not $TotalInbound -or $TotalInbound -eq 0) { $TotalInbound = 0 }

$InboundCategory = $InboundCategory | ForEach-Object {
    $pct = if ($TotalInbound -gt 0) { [math]::Round(($_.Messages / $TotalInbound) * 100, 1) } else { 0.0 }
    $_ | Add-Member -NotePropertyName Percent -NotePropertyValue $pct -Force -PassThru
}

# ==========================================================
# HTML HELPERS
# ==========================================================

if (-not ("System.Net.WebUtility" -as [type])) { Add-Type -AssemblyName System.Net }

function Convert-ToHtmlTable {
    param(
        $Data,
        [string[]]$Columns
    )

    if (-not $Data -or $Data.Count -eq 0) { return "<p><i>No data.</i></p>" }

    $encode = { param($v) [System.Net.WebUtility]::HtmlEncode([string]$v) }

    $Rows = foreach ($row in $Data) {
        $cells = foreach ($col in $Columns) {
            $value = $null
            if ($row.PSObject.Properties.Name -contains $col) { $value = $row.$col }
            "<td style='border:1px solid #ddd;padding:8px;'>$(& $encode $value)</td>"
        }
        "<tr>$($cells -join '')</tr>"
    }

    $headers = $Columns | ForEach-Object {
        "<th style='background:#003366;color:#fff;border:1px solid #ddd;padding:8px;text-align:left;'>$(& $encode $_)</th>"
    }

    "<table style='border-collapse:collapse;margin-bottom:25px;min-width:520px;'><tr>$($headers -join '')</tr>$($Rows -join '')</table>"
}

function Convert-ToCiscoCategoryTable {
    param([Parameter(Mandatory)] $Rows)

    if (-not $Rows -or $Rows.Count -eq 0) { return "<p><i>No data.</i></p>" }

    function Get-Color($cat) {
        switch -Regex ($cat) {
            "Spam"          { "#f1c232" }
            "Virus|Malware" { "#cc0000" }
            "Phish"         { "#e69138" }
            "Marketing"     { "#6aa84f" }
            "Social"        { "#3d85c6" }
            "Bulk"          { "#000000" }
            "Clean"         { "#cfe2f3" }
            default         { "#999999" }
        }
    }

    $encode = { param($v) [System.Net.WebUtility]::HtmlEncode([string]$v) }

    $total = ($Rows | Measure-Object Messages -Sum).Sum
    $totalFmt = if ($total -ge 1000) { "{0:N1}k" -f ($total/1000) } else { "{0:N0}" -f $total }

    $trs = foreach ($r in $Rows) {
        $c   = Get-Color $r.Category
        $pct = "{0:N1}%" -f [double]$r.Percent
        $msg = "{0:N0}" -f [int]$r.Messages

@"
<tr>
  <td style="border:1px solid #ddd;padding:8px;">
    <span style="display:inline-block;width:10px;height:10px;background:$c;border:1px solid #333;margin-right:8px;vertical-align:middle;"></span>
    $(& $encode $r.Category)
  </td>
  <td style="border:1px solid #ddd;padding:8px;text-align:right;">$pct</td>
  <td style="border:1px solid #ddd;padding:8px;text-align:right;">$msg</td>
</tr>
"@
    }

@"
<table style="border-collapse:collapse;margin-bottom:25px;min-width:520px;">
  <tr>
    <th style="background:#6d6d6d;color:#fff;border:1px solid #ddd;padding:8px;text-align:left;">Message Category</th>
    <th style="background:#6d6d6d;color:#fff;border:1px solid #ddd;padding:8px;text-align:right;">%</th>
    <th style="background:#6d6d6d;color:#fff;border:1px solid #ddd;padding:8px;text-align:right;">Messages</th>
  </tr>
  $($trs -join "`n")
  <tr>
    <td style="border:1px solid #ddd;padding:8px;font-weight:700;">Total Attempted Messages:</td>
    <td style="border:1px solid #ddd;padding:8px;"></td>
    <td style="border:1px solid #ddd;padding:8px;text-align:right;font-weight:700;">$totalFmt</td>
  </tr>
</table>
"@
}

# ==========================================================
# HTML REPORT
# ==========================================================

$DomainsLabel = ($InternalDomains -join ", ")

$Html = @"
<html>
<head>
<meta charset="utf-8" />
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 30px; }
h1 { margin-bottom: 0; }
.small { color: #555; margin-top: 6px; }
h2 { color: #003366; margin-top: 26px; }
</style>
</head>
<body>

<h1>User Email Summary</h1>
<p class="small"><b>Date:</b> $DateLabel &nbsp;&nbsp;|&nbsp;&nbsp; <b>Internal Domains:</b> $DomainsLabel</p>

<h2>Incoming Mail</h2>
$(Convert-ToCiscoCategoryTable $InboundCategory)

<h2>Top Users by Threat Messages Received</h2>
$(Convert-ToHtmlTable $TopThreat @("RecipientEmailAddress","Messages"))

<h2>Top Users by Clean Messages Received</h2>
$(Convert-ToHtmlTable $TopClean @("RecipientEmailAddress","Messages"))

<h2>Top Users by Graymail/Bulk Messages Received</h2>
$(Convert-ToHtmlTable $TopGray @("RecipientEmailAddress","Messages"))

<h2>Outgoing Mail (Sent by Us)</h2>
$(Convert-ToHtmlTable $OutboundTotals @("SentScope","Messages"))

<h2>Top Senders (Sent by Us)</h2>
$(Convert-ToHtmlTable $OutboundTop @("From","Messages"))

</body>
</html>
"@

$Html | Out-File $OutputFile -Encoding UTF8
Write-Host "Report saved to: $OutputFile"
Write-Host "Completed successfully."
