# ==========================================================
# Title: Defender Internal Users Summary (Cisco ESA Replacement)
# Author: Kevin Hilt (FLSEN Security)
# Purpose:
#   Replaces Cisco ESA "Internal Users Summary" report using
#   Microsoft Defender Advanced Hunting API (GCC).
#
# Output:
#   - Timestamped DAILY HTML report
#   - Timestamped WEEKLY HTML rollup (Sunday->Sunday) generated ONLY when
#     the REPORT DAY (local) is Sunday (=> intended Monday pipeline run with DaysBack=1)
#
# Optional Upload:
#   - If -UploadToSharePoint is set, uploads generated HTML(s) to SharePoint:
#       <LibraryName>/<FolderPathInLibrary>
#
# Notes:
#   - Defender AH (GCC):
#       Token: https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token
#       API:   https://api-gcc.security.microsoft.us/api/advancedhunting/run
#   - Day/Week windows are computed in Eastern time (handles DST) and converted to UTC.
#   - Fixes PowerShell "$var:" parsing issues by using $($var) and -f formatting where needed.
# ==========================================================

[CmdletBinding()]
param(
    # Local output directory (agent disk or local machine)
    [string]$OutDir = "$PSScriptRoot\out\Security\User Email Summary",

    # 1 = yesterday (default), 0 = today, 2 = two days ago, etc.
    [ValidateRange(0, 90)]
    [int]$DaysBack = 1,

    # Upload to SharePoint after generating the HTML(s)
    [switch]$UploadToSharePoint,

    # SharePoint library + folder (inside the library)
    # IMPORTANT: In your tenant, the "real" Shared Documents often shows as the drive whose webUrl ends with /Shared%20Documents
    [string]$SpLibraryName = "Shared Documents",
    [string]$SpFolderPathInLibrary = "Security/User Email Summary",

    # Graph base (Commercial/GCC: graph.microsoft.com; GCC High: graph.microsoft.us)
    [ValidateSet("https://graph.microsoft.com/v1.0", "https://graph.microsoft.us/v1.0")]
    [string]$GraphBase = "https://graph.microsoft.com/v1.0",

    # Cisco-style calendar timezone
    [string]$ReportTimeZoneId = "Eastern Standard Time",

    # Weekly rollup controls
    [switch]$IncludeWeeklyRollup = $true,

    # Only run weekly when the REPORT DAY (local) is Sunday.
    # With DaysBack=1 and a daily morning schedule, this means weekly runs on Monday.
    [switch]$WeeklyOnlyOnSunday = $true,

    # 14-day recipient validation investigation controls
    [string]$InvestigateDomain = "flsenate.gov",
    [string]$InvestigateUpnSuffix = "FLSEN.GOV",
    [switch]$IncludeQuarantine = $true,
    [string]$AdSearchBase,
    [string]$AdServer
)

$ErrorActionPreference = "Stop"

# ==========================================================
# CONFIGURATION (env vars from pipeline variable group)
# ==========================================================
$TenantId     = $env:TENANT_ID
$ClientId     = $env:CLIENT_ID
$ClientSecret = $env:CLIENT_SECRET

if (-not $TenantId -or -not $ClientId -or -not $ClientSecret) {
    throw "Missing required env vars: TENANT_ID, CLIENT_ID, CLIENT_SECRET"
}

# Internal domains to define "Sent by us" and "Internal vs External"
# NOTE: explicitly excludes leg.state.fl.us
$InternalDomains = @("flsenate.gov", "flsen.gov")
$InternalDomainsDyn = ($InternalDomains | ForEach-Object { '"' + $_ + '"' }) -join ","
$DomainsLabel = ($InternalDomains -join ", ")

# Output folder
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$TimeStamp  = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")

# Defender Advanced Hunting (GCC)
$TokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
$ApiBase       = "https://api-gcc.security.microsoft.us"
$MdeScope      = "https://api-gcc.security.microsoft.us/.default"

# ==========================================================
# TIME WINDOW HELPERS (Local day -> UTC window, end-exclusive)
# ==========================================================
function Get-UtcWindowForLocalDay {
    param(
        [Parameter(Mandatory)] [datetime] $LocalDayDate,
        [Parameter(Mandatory)] [string]   $TimeZoneId
    )

    $tz = [System.TimeZoneInfo]::FindSystemTimeZoneById($TimeZoneId)

    $localStart   = [datetime]::SpecifyKind($LocalDayDate.Date, [DateTimeKind]::Unspecified)
    $localEndExcl = $localStart.AddDays(1)

    $utcStart   = [System.TimeZoneInfo]::ConvertTimeToUtc($localStart, $tz)
    $utcEndExcl = [System.TimeZoneInfo]::ConvertTimeToUtc($localEndExcl, $tz)

    return @{
        LocalStart    = $localStart
        LocalEndExcl  = $localEndExcl
        UtcStart      = $utcStart
        UtcEndExcl    = $utcEndExcl
        UtcStartKql   = $utcStart.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        UtcEndExclKql = $utcEndExcl.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    }
}

# Report day (local)
$Now = Get-Date
$ReportDateLocal = $Now.AddDays(-1 * $DaysBack).Date
$DateLabel = $ReportDateLocal.ToString("yyyy-MM-dd")

# Daily window + KQL filter
$DailyWindow = Get-UtcWindowForLocalDay -LocalDayDate $ReportDateLocal -TimeZoneId $ReportTimeZoneId
$DailyDateFilter = "Timestamp >= datetime($($DailyWindow.UtcStartKql)) and Timestamp < datetime($($DailyWindow.UtcEndExclKql))"

Write-Host ("Report day (local): {0} [{1}] -> UTC: {2} .. {3} (end exclusive)" -f `
    $DateLabel, $ReportTimeZoneId, $DailyWindow.UtcStartKql, $DailyWindow.UtcEndExclKql)

# Weekly gating (Sunday report day => intended Monday run)
$ShouldRunWeekly = $IncludeWeeklyRollup
if ($IncludeWeeklyRollup -and $WeeklyOnlyOnSunday) {
    $ShouldRunWeekly = ($ReportDateLocal.DayOfWeek -eq [DayOfWeek]::Sunday)
}

Write-Host ("Weekly enabled: {0} | WeeklyOnlyOnSunday: {1} | ShouldRunWeekly: {2} | ReportDay(Local): {3} ({4})" -f `
    $IncludeWeeklyRollup, $WeeklyOnlyOnSunday, $ShouldRunWeekly, $DateLabel, $ReportDateLocal.DayOfWeek)

# Weekly window: previous Sunday 00:00 local -> report Sunday end (end-exclusive Monday 00:00 local)
$WeeklyDateFilter = $null
$WeeklyLabel      = $null
$WeeklyWindowStart = $null

if ($ShouldRunWeekly) {
    $WeekStartLocal = $ReportDateLocal.AddDays(-7)   # previous Sunday
    $WeeklyWindowStart = Get-UtcWindowForLocalDay -LocalDayDate $WeekStartLocal -TimeZoneId $ReportTimeZoneId

    $WeeklyDateFilter = "Timestamp >= datetime($($WeeklyWindowStart.UtcStartKql)) and Timestamp < datetime($($DailyWindow.UtcEndExclKql))"
    $WeeklyLabel = ("{0} to {1}" -f $WeekStartLocal.ToString("yyyy-MM-dd"), $ReportDateLocal.ToString("yyyy-MM-dd"))

    Write-Host ("Weekly range (local): {0} [{1}] -> UTC: {2} .. {3} (end exclusive)" -f `
        $WeeklyLabel, $ReportTimeZoneId, $WeeklyWindowStart.UtcStartKql, $DailyWindow.UtcEndExclKql)
}

# Output files
$DailyOutputFile  = Join-Path $OutDir ("UserEmailSummary_Daily_{0}_{1}.html"  -f $DateLabel, $TimeStamp)
$WeeklyOutputFile = Join-Path $OutDir ("UserEmailSummary_Weekly_{0}_{1}.html" -f $DateLabel, $TimeStamp)

# ==========================================================
# AUTHENTICATION (Defender AH – GCC, client credentials)
# ==========================================================
Write-Host "Authenticating to Microsoft Defender (GCC)..."

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
        -ContentType "application/x-www-form-urlencoded"
} catch {
    throw "Failed to get access token (Defender): $($_.Exception.Message)"
}

$AccessToken = $TokenResponse.access_token
if (-not $AccessToken) { throw "Access token missing from token response (Defender)." }

$Headers = @{
    Authorization  = "Bearer $AccessToken"
    "Content-Type" = "application/json"
}

# ==========================================================
# FUNCTION: Run Defender Advanced Hunting Query
# ==========================================================
function Invoke-DefenderQuery {
    param([Parameter(Mandatory)][string]$Query)

    $BodyJson = (@{ Query = $Query } | ConvertTo-Json -Depth 10)

    try {
        $Response = Invoke-RestMethod `
            -Method Post `
            -Uri "$ApiBase/api/advancedhunting/run" `
            -Headers $Headers `
            -Body $BodyJson
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
# HTML helpers + SVG charts
# ==========================================================
if (-not ("System.Net.WebUtility" -as [type])) { Add-Type -AssemblyName System.Net }

function HtmlEncode([object]$v) { [System.Net.WebUtility]::HtmlEncode([string]$v) }

function Convert-ToHtmlTable {
    param(
        $Data,
        [string[]]$Columns,
        [int]$MinWidth = 760
    )

    if (-not $Data -or $Data.Count -eq 0) { return "<p><i>No data.</i></p>" }

    $Rows = foreach ($row in $Data) {
        $cells = foreach ($col in $Columns) {
            $value = $null
            if ($row.PSObject.Properties.Name -contains $col) { $value = $row.$col }
            "<td style='border:1px solid #ddd;padding:8px;'>$(HtmlEncode $value)</td>"
        }
        "<tr>$($cells -join '')</tr>"
    }

    $headers = for ($i = 0; $i -lt $Columns.Count; $i++) {
        $col = $Columns[$i]
        "<th style='background:#003366;color:#fff;border:1px solid #ddd;padding:8px;text-align:left;'>$(HtmlEncode $col)</th>"
    }

    "<table style='border-collapse:collapse;margin-bottom:25px;min-width:${MinWidth}px;'><tr>$($headers -join '')</tr>$($Rows -join '')</table>"
}

function Get-CategoryColor {
    param([string]$Category)

    switch -Regex ($Category) {
        "Spam"          { "#f1c232" }
        "Virus|Malware" { "#cc0000" }
        "Phish"         { "#e69138" }
        "Bulk"          { "#000000" }
        "Clean"         { "#cfe2f3" }
        default         { "#999999" }
    }
}

function Convert-ToCiscoCategoryTable {
    param([Parameter(Mandatory)] $Rows, [int]$MinWidth = 760)

    if (-not $Rows -or $Rows.Count -eq 0) { return "<p><i>No data.</i></p>" }

    $total = ($Rows | Measure-Object Messages -Sum).Sum
    if (-not $total) { $total = 0 }

    $totalFmt = if ($total -ge 1000) { "{0:N1}k" -f ($total/1000) } else { "{0:N0}" -f $total }

    $trs = foreach ($r in $Rows) {
        $c   = Get-CategoryColor ([string]$r.Category)
        $pct = "{0:N1}%" -f [double]$r.Percent
        $msg = "{0:N0}" -f [int]$r.Messages

@"
<tr>
  <td style="border:1px solid #ddd;padding:8px;">
    <span style="display:inline-block;width:10px;height:10px;background:$c;border:1px solid #333;margin-right:8px;vertical-align:middle;"></span>
    $(HtmlEncode $r.Category)
  </td>
  <td style="border:1px solid #ddd;padding:8px;text-align:right;">$pct</td>
  <td style="border:1px solid #ddd;padding:8px;text-align:right;">$msg</td>
</tr>
"@
    }

@"
<table style="border-collapse:collapse;margin-bottom:12px;min-width:${MinWidth}px;">
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

function New-SvgPieChart {
    param(
        [Parameter(Mandatory)] $Rows,   # expects Category + Messages
        [int]$Size = 220
    )

    if (-not $Rows -or $Rows.Count -eq 0) { return "<p><i>No chart data.</i></p>" }

    $total = ($Rows | Measure-Object Messages -Sum).Sum
    if (-not $total -or $total -le 0) { return "<p><i>No chart data.</i></p>" }

    $cx = [math]::Round($Size / 2, 0)
    $cy = [math]::Round($Size / 2, 0)
    $r  = [math]::Round($Size * 0.45, 0)

    $startAngle = 0.0
    $paths = New-Object System.Collections.Generic.List[string]

    foreach ($row in ($Rows | Sort-Object Messages -Descending)) {
        $val = [double]$row.Messages
        if ($val -le 0) { continue }

        $pct = $val / $total
        $sweep = $pct * 360.0
        $endAngle = $startAngle + $sweep

        $a0 = ($startAngle - 90.0) * [math]::PI / 180.0
        $a1 = ($endAngle   - 90.0) * [math]::PI / 180.0

        $x0 = $cx + $r * [math]::Cos($a0)
        $y0 = $cy + $r * [math]::Sin($a0)
        $x1 = $cx + $r * [math]::Cos($a1)
        $y1 = $cy + $r * [math]::Sin($a1)

        $largeArc = if ($sweep -gt 180) { 1 } else { 0 }
        $color = Get-CategoryColor ([string]$row.Category)

        $d = "M $cx $cy L $([math]::Round($x0,2)) $([math]::Round($y0,2)) A $r $r 0 $largeArc 1 $([math]::Round($x1,2)) $([math]::Round($y1,2)) Z"
        $paths.Add("<path d='$d' fill='$color' stroke='#ffffff' stroke-width='1'/>")

        $startAngle = $endAngle
    }

@"
<svg width="$Size" height="$Size" viewBox="0 0 $Size $Size" role="img" aria-label="Inbound category pie chart" style="margin:6px 0 18px 0;">
  $($paths -join "`n  ")
</svg>
"@
}

function New-SvgHourlyTrendChart {
    param(
        [Parameter(Mandatory)] $Rows,   # expects Timestamp (bin 1h), Category, Messages
        [string]$TimeZoneId = "Eastern Standard Time",
        [int]$Width = 900,
        [int]$Height = 260,
        [int]$Padding = 40,
        [string[]]$Categories = @("Clean Messages","Bulk Messages","Malware Detected","Phishing Detected","Spam Detected")
    )

    if (-not $Rows -or $Rows.Count -eq 0) { return "<p><i>No hourly trend data.</i></p>" }

    $tz = [System.TimeZoneInfo]::FindSystemTimeZoneById($TimeZoneId)

    $hoursUtc = $Rows | Select-Object -ExpandProperty Timestamp | ForEach-Object { [datetime]::Parse([string]$_) } | Sort-Object -Unique
    if (-not $hoursUtc -or $hoursUtc.Count -lt 2) { return "<p><i>Insufficient hourly data.</i></p>" }

    $xLabels = @()
    foreach ($hUtc in $hoursUtc) {
        $local = [System.TimeZoneInfo]::ConvertTimeFromUtc($hUtc, $tz)
        $xLabels += $local.ToString("HH:mm")
    }

    $lookup = @{}
    foreach ($r in $Rows) {
        $hUtc = [datetime]::Parse([string]$r.Timestamp)
        $localKey = [System.TimeZoneInfo]::ConvertTimeFromUtc($hUtc, $tz).ToString("HH:mm")
        $lookup["$localKey|$($r.Category)"] = [int]$r.Messages
    }

    $max = 0
    foreach ($t in $xLabels) {
        foreach ($cat in $Categories) {
            $v = 0
            $k = "$t|$cat"
            if ($lookup.ContainsKey($k)) { $v = $lookup[$k] }
            if ($v -gt $max) { $max = $v }
        }
    }
    if ($max -le 0) { $max = 1 }

    $plotW = $Width - (2 * $Padding)
    $plotH = $Height - (2 * $Padding)

    function XtoPx([int]$i, [int]$n, [int]$pad, [int]$w) {
        if ($n -le 1) { return $pad }
        return $pad + ($i * ($w / ($n - 1.0)))
    }
    function YtoPx([int]$v, [int]$vmax, [int]$pad, [int]$h) {
        return $pad + ($h - (($v / [double]$vmax) * $h))
    }

    $grid = New-Object System.Collections.Generic.List[string]
    for ($g = 0; $g -le 4; $g++) {
        $yv = [math]::Round($max * ($g / 4.0), 0)
        $y  = YtoPx -v $yv -vmax $max -pad $Padding -h $plotH
        $grid.Add("<line x1='$Padding' y1='$y' x2='$($Width-$Padding)' y2='$y' stroke='#e5e5e5' stroke-width='1'/>")
        $grid.Add("<text x='8' y='$([int]$y + 4)' font-size='11' fill='#555'>$yv</text>")
    }

    $xText = New-Object System.Collections.Generic.List[string]
    for ($i=0; $i -lt $xLabels.Count; $i++) {
        if ($i % 2 -ne 0) { continue }
        $x = XtoPx -i $i -n $xLabels.Count -pad $Padding -w $plotW
        $xText.Add("<text x='$x' y='$($Height-10)' font-size='10' fill='#555' text-anchor='middle'>$($xLabels[$i])</text>")
    }

    $polys = New-Object System.Collections.Generic.List[string]
    foreach ($cat in $Categories) {
        $pts = New-Object System.Collections.Generic.List[string]
        for ($i=0; $i -lt $xLabels.Count; $i++) {
            $t = $xLabels[$i]
            $v = 0
            $k = "$t|$cat"
            if ($lookup.ContainsKey($k)) { $v = $lookup[$k] }

            $x = XtoPx -i $i -n $xLabels.Count -pad $Padding -w $plotW
            $y = YtoPx -v $v -vmax $max -pad $Padding -h $plotH
            $pts.Add(("{0},{1}" -f [math]::Round($x,2), [math]::Round($y,2)))
        }
        $color = Get-CategoryColor $cat
        $polys.Add("<polyline fill='none' stroke='$color' stroke-width='2' points='$($pts -join " ")'/>")
    }

    $legend = New-Object System.Collections.Generic.List[string]
    $lx = $Padding
    $ly = 16
    $idx = 0
    foreach ($cat in $Categories) {
        $color = Get-CategoryColor $cat
        $x = $lx + ($idx * 160)
        $legend.Add("<rect x='$x' y='$($ly-10)' width='10' height='10' fill='$color' stroke='#333' stroke-width='0.3'/>")
        $legend.Add("<text x='$($x+14)' y='$ly' font-size='11' fill='#333'>$cat</text>")
        $idx++
    }

@"
<svg width="$Width" height="$Height" viewBox="0 0 $Width $Height" role="img" aria-label="Inbound hourly trend">
  $($grid -join "`n  ")
  <line x1='$Padding' y1='$Padding' x2='$Padding' y2='$($Height-$Padding)' stroke='#888' stroke-width='1'/>
  <line x1='$Padding' y1='$($Height-$Padding)' x2='$($Width-$Padding)' y2='$($Height-$Padding)' stroke='#888' stroke-width='1'/>
  $($polys -join "`n  ")
  $($xText -join "`n  ")
  $($legend -join "`n  ")
</svg>
"@
}

function New-SvgHorizontalBarChart {
    param(
        [Parameter(Mandatory)] $Rows,   # expects Label + Messages
        [string]$LabelField = "Subject",
        [string]$ValueField = "Messages",
        [int]$Width  = 1100,
        [int]$BarHeight = 18,
        [int]$BarGap   = 6,
        [int]$LeftMargin = 360,
        [int]$RightMargin = 140,
        [int]$TopMargin = 20,
        [int]$BottomMargin = 40
    )

    if (-not $Rows -or $Rows.Count -eq 0) { return "<p><i>No subject data.</i></p>" }

    $maxVal = ($Rows | Measure-Object -Property $ValueField -Maximum).Maximum
    if (-not $maxVal -or $maxVal -le 0) { return "<p><i>No subject data.</i></p>" }

    $count = $Rows.Count
    $plotHeight = ($count * ($BarHeight + $BarGap))
    $Height = $TopMargin + $plotHeight + $BottomMargin
    $plotWidth = $Width - $LeftMargin - $RightMargin

    function Scale-X([int]$v, [int]$max, [int]$w) {
        if ($max -le 0) { return 0 }
        return [math]::Round(($v / [double]$max) * $w, 2)
    }

    $bars = New-Object System.Collections.Generic.List[string]
    $labels = New-Object System.Collections.Generic.List[string]

    for ($i = 0; $i -lt $count; $i++) {
        $row = $Rows[$i]
        $label = [string]($row.$LabelField)
        # Rough truncation so text doesn't run into the bar.
        # Assume ~7px per character and keep some padding before $LeftMargin.
        $maxLabelPixels = $LeftMargin - 40
        if ($maxLabelPixels -gt 40) {
            $approxCharWidth = 7
            $maxChars = [math]::Floor($maxLabelPixels / $approxCharWidth)
            if ($label.Length -gt $maxChars) {
                $label = $label.Substring(0, [math]::Max(0, $maxChars - 1)) + "…"
            }
        }
        $val   = [int]($row.$ValueField)

        $y = $TopMargin + $i * ($BarHeight + $BarGap)
        $barWidth = Scale-X -v $val -max $maxVal -w $plotWidth

        $bars.Add("<rect x='$LeftMargin' y='$y' width='$barWidth' height='$BarHeight' fill='#6fa8dc' stroke='#333' stroke-width='0.5'/>")
        $labels.Add("<text x='10' y='$(($y + $BarHeight - 3))' font-size='12' fill='#333' text-anchor='start'>$(HtmlEncode $label)</text>")

        $maxLabelX = $Width - 40
        $valX = [math]::Min($LeftMargin + $barWidth - 6, $maxLabelX)
        $labels.Add("<text x='$valX' y='$(($y + $BarHeight - 3))' font-size='12' fill='#333'>$val</text>")
    }

    $grid = New-Object System.Collections.Generic.List[string]
    for ($g = 0; $g -le 4; $g++) {
        $gv = [math]::Round($maxVal * ($g / 4.0), 0)
        $x  = $LeftMargin + (Scale-X -v $gv -max $maxVal -w $plotWidth)
        $grid.Add("<line x1='$x' y1='$TopMargin' x2='$x' y2='$($TopMargin + $plotHeight)' stroke='#e5e5e5' stroke-width='1'/>")
        $grid.Add("<text x='$x' y='$($TopMargin + $plotHeight + 16)' font-size='10' fill='#555' text-anchor='middle'>$gv</text>")
    }

@"
<svg width="$Width" height="$Height" viewBox="0 0 $Width $Height" role="img" aria-label="Top subjects by message count">
  $($grid -join "`n  ")
  $($bars -join "`n  ")
  $($labels -join "`n  ")
</svg>
"@
}

# ==========================================================
# Recipient validation helpers (14-day investigation)
# ==========================================================
function Resolve-NormalizedEmailAddress {
    param([string]$Email)

    if ([string]::IsNullOrWhiteSpace($Email)) { return $null }
    $normalizedEmail = $Email.Trim().ToLowerInvariant()

    if ($normalizedEmail -match '^prvs=[^=]+=(?<address>.+@.+)$') {
        return $Matches.address
    }
    return $normalizedEmail
}

function Convert-CollectionToText {
    param(
        [object]$Value,
        [string]$Separator = "; "
    )

    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [hashtable])) {
        return (@($Value | Where-Object { $null -ne $_ }) -join $Separator)
    }
    return [string]$Value
}

function Get-PreviewText {
    param(
        [string]$Text,
        [int]$MaxLength = 60
    )

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $cleanText = $Text.Trim()
    if ($cleanText.Length -le $MaxLength) { return $cleanText }
    return $cleanText.Substring(0, $MaxLength - 3) + "..."
}

function Add-ADAccountStatus {
    param(
        [Parameter(Mandatory)] [object[]]$Records,
        [string]$IdentityProperty = "RecipientEmailAddress",
        [string]$SearchBase,
        [string]$Server
    )

    foreach ($record in $Records) {
        $rawIdentityValue = [string]$record.$IdentityProperty
        $identityValue = Resolve-NormalizedEmailAddress -Email $rawIdentityValue
        $adUser = $null
        $adMatches = @()

        if (-not [string]::IsNullOrWhiteSpace($identityValue)) {
            $email = $identityValue
            $sam = ($email -split "@")[0]
            $escapedEmail = $email -replace "'", "''"
            $escapedSam = $sam -replace "'", "''"

            $adParams = @{
                Filter      = "UserPrincipalName -eq '$escapedEmail' -or SamAccountName -eq '$escapedSam' -or Mail -eq '$escapedEmail'"
                Properties  = @("Enabled", "Mail", "SamAccountName", "UserPrincipalName", "DisplayName", "DistinguishedName")
                ErrorAction = "SilentlyContinue"
            }
            if ($SearchBase) { $adParams.SearchBase = $SearchBase }
            if ($Server) { $adParams.Server = $Server }

            $adMatches = @(Get-ADUser @adParams)
            if ($adMatches.Count -gt 0) { $adUser = $adMatches | Select-Object -First 1 }
        }

        Add-Member -InputObject $record -NotePropertyName ADAccountExists -NotePropertyValue ([bool]$adUser) -Force
        Add-Member -InputObject $record -NotePropertyName ADMatchCount -NotePropertyValue $adMatches.Count -Force
        Add-Member -InputObject $record -NotePropertyName ADSamAccountName -NotePropertyValue $adUser.SamAccountName -Force
        Add-Member -InputObject $record -NotePropertyName ADUserPrincipalName -NotePropertyValue $adUser.UserPrincipalName -Force
        Add-Member -InputObject $record -NotePropertyName ADDisplayName -NotePropertyValue $adUser.DisplayName -Force
        Add-Member -InputObject $record -NotePropertyName ADMail -NotePropertyValue $adUser.Mail -Force
        Add-Member -InputObject $record -NotePropertyName ADEnabled -NotePropertyValue $adUser.Enabled -Force
    }

    $Records
}

# ==========================================================
# KQL builders
# ==========================================================
$CategoryCase = @"
extend Category =
    case(
        ThreatTypes has "Spam", "Spam Detected",
        ThreatTypes has "Malware", "Malware Detected",
        ThreatTypes has "Phish", "Phishing Detected",
        BulkComplaintLevel > 0, "Bulk Messages",
        isempty(ThreatTypes), "Clean Messages",
        "Other"
    )
"@

function Build-Queries {
    param([Parameter(Mandatory)][string]$DateFilter)

    $q = @{}

    $q.InboundCategory = @"
EmailEvents
| where $DateFilter
| where EmailDirection == "Inbound"
| $CategoryCase
| summarize Messages=count() by Category
| order by Messages desc
"@

    $q.InboundHourlyTrend = @"
EmailEvents
| where $DateFilter
| where EmailDirection == "Inbound"
| $CategoryCase
| summarize Messages=count() by bin(Timestamp, 1h), Category
| order by Timestamp asc
"@

    $q.TopThreat = @"
EmailEvents
| where $DateFilter
| where EmailDirection == "Inbound"
| where isnotempty(ThreatTypes)
| summarize Messages=count() by RecipientEmailAddress
| top 10 by Messages desc
"@

    $q.TopClean = @"
EmailEvents
| where $DateFilter
| where EmailDirection == "Inbound"
| where isempty(ThreatTypes)
| summarize Messages=count() by RecipientEmailAddress
| top 10 by Messages desc
"@

    $q.TopGray = @"
EmailEvents
| where $DateFilter
| where EmailDirection == "Inbound"
| where BulkComplaintLevel > 0
| summarize Messages=count() by RecipientEmailAddress
| top 10 by Messages desc
"@

    $q.TopInboundSenderDomains = @"
EmailEvents
| where $DateFilter
| where EmailDirection == "Inbound"
| extend SenderDomain = coalesce(SenderFromDomain, tostring(split(SenderFromAddress,"@")[1]))
| where isnotempty(SenderDomain)
| summarize Messages=count() by SenderDomain
| top 20 by Messages desc
"@

    $q.TopSpamDomains = @"
EmailEvents
| where $DateFilter
| where EmailDirection == "Inbound"
| where ThreatTypes has "Spam"
| extend SenderDomain = coalesce(SenderFromDomain, tostring(split(SenderFromAddress,"@")[1]))
| where isnotempty(SenderDomain)
| summarize Messages=count() by SenderDomain
| top 20 by Messages desc
"@

    $q.TopPhishDomains = @"
EmailEvents
| where $DateFilter
| where EmailDirection == "Inbound"
| where ThreatTypes has "Phish"
| extend SenderDomain = coalesce(SenderFromDomain, tostring(split(SenderFromAddress,"@")[1]))
| where isnotempty(SenderDomain)
| summarize Messages=count() by SenderDomain
| top 20 by Messages desc
"@

    $q.TopMalwareDomains = @"
EmailEvents
| where $DateFilter
| where EmailDirection == "Inbound"
| where ThreatTypes has "Malware"
| extend SenderDomain = coalesce(SenderFromDomain, tostring(split(SenderFromAddress,"@")[1]))
| where isnotempty(SenderDomain)
| summarize Messages=count() by SenderDomain
| top 20 by Messages desc
"@

    $q.TopPhishRecipients = @"
EmailEvents
| where $DateFilter
| where EmailDirection == "Inbound"
| where ThreatTypes has "Phish"
| summarize Messages=count() by RecipientEmailAddress
| top 20 by Messages desc
"@

    $q.TopPhishCampaigns = @"
EmailEvents
| where $DateFilter
| where EmailDirection == "Inbound"
| where ThreatTypes has "Phish"
| summarize Messages=count() by SenderFromAddress, Subject
| top 25 by Messages desc
"@

    $q.TopSubjects = @"
EmailEvents
| where $DateFilter
| where EmailDirection == "Inbound"
| where isnotempty(Subject)
// Exclude noisy subjects that appear every day
| where Subject !in~ ("Spam Quarantine Notification")
| summarize Messages=count() by Subject
| top 10 by Messages desc
"@

    $q.OutboundTotals = @"
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

    $q.OutboundTopSenders = @"
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

    $q.OutboundExternalBySender = @"
let InternalDomains = dynamic([$InternalDomainsDyn]);
EmailEvents
| where $DateFilter
| where isnotempty(RecipientEmailAddress)
| extend From = coalesce(SenderFromAddress, SenderMailFromAddress)
| where isnotempty(From)
| extend SenderDomain = tostring(split(From, "@")[1])
| extend RcptDomain   = tostring(split(RecipientEmailAddress, "@")[1])
| where SenderDomain in~ (InternalDomains)
| where RcptDomain !in~ (InternalDomains)
| summarize Messages=count() by From, RecipientEmailAddress
| top 25 by Messages desc
"@

    # Legislative Bill Blast Watch
    $q.BillBlastSummary = @"
EmailEvents
| where $DateFilter
| where EmailDirection == "Inbound"
| where isnotempty(Subject)
| extend subj = tostring(Subject)
| extend billRaw = extract(@"(?i)\b((?:CS\/)*(?:HB|SB))\s*([0-9]{1,5})\b", 0, subj)
| where isnotempty(billRaw)
| extend billType = toupper(extract(@"(?i)\b((?:CS\/)*(?:HB|SB))\b", 1, billRaw))
| extend billNum  = tostring(toint(extract(@"(?i)\b(?:CS\/)*(?:HB|SB)\s*([0-9]{1,5})\b", 1, billRaw)))
| extend BillNumber = strcat(iff(billType has "HB","HB","SB"), " ", billNum)
| extend Sender = coalesce(SenderFromAddress, SenderMailFromAddress)
| extend SenderDomain = tostring(split(Sender, "@")[1])
| summarize
    TotalEmails      = count(),
    UniqueRecipients = dcount(RecipientEmailAddress),
    UniqueSenders    = dcount(Sender),
    SenderDomains    = strcat_array(make_set(SenderDomain, 10), " ")
  by BillNumber
| top 25 by TotalEmails desc
"@

    $q.BillBlastTopRecipients = @"
EmailEvents
| where $DateFilter
| where EmailDirection == "Inbound"
| where isnotempty(Subject)
| extend subj = tostring(Subject)
| extend billRaw = extract(@"(?i)\b((?:CS\/)*(?:HB|SB))\s*([0-9]{1,5})\b", 0, subj)
| where isnotempty(billRaw)
| extend billType = toupper(extract(@"(?i)\b((?:CS\/)*(?:HB|SB))\b", 1, billRaw))
| extend billNum  = tostring(toint(extract(@"(?i)\b(?:CS\/)*(?:HB|SB)\s*([0-9]{1,5})\b", 1, billRaw)))
| extend BillNumber = strcat(iff(billType has "HB","HB","SB"), " ", billNum)
| summarize TotalEmails=count() by BillNumber, RecipientEmailAddress
| top 50 by TotalEmails desc
"@

    return $q
}

# ==========================================================
# RUN DAILY QUERIES
# ==========================================================
Write-Host "Running DAILY queries for local date: $DateLabel (DaysBack=$DaysBack)..."

$DailyQ = Build-Queries -DateFilter $DailyDateFilter

$InboundCategory   = Invoke-DefenderQuery $DailyQ.InboundCategory
$InboundHourly     = Invoke-DefenderQuery $DailyQ.InboundHourlyTrend
$TopThreat         = Invoke-DefenderQuery $DailyQ.TopThreat
$TopClean          = Invoke-DefenderQuery $DailyQ.TopClean
$TopGray           = Invoke-DefenderQuery $DailyQ.TopGray
$TopInboundDomains = Invoke-DefenderQuery $DailyQ.TopInboundSenderDomains
$TopSpamDomains    = Invoke-DefenderQuery $DailyQ.TopSpamDomains
$TopPhishDomains   = Invoke-DefenderQuery $DailyQ.TopPhishDomains
$TopMalwareDomains = Invoke-DefenderQuery $DailyQ.TopMalwareDomains
$TopPhishRecipients= Invoke-DefenderQuery $DailyQ.TopPhishRecipients
$TopPhishCampaigns = Invoke-DefenderQuery $DailyQ.TopPhishCampaigns
$TopSubjects       = Invoke-DefenderQuery $DailyQ.TopSubjects
$OutboundTotals    = Invoke-DefenderQuery $DailyQ.OutboundTotals
$OutboundTop       = Invoke-DefenderQuery $DailyQ.OutboundTopSenders
$OutboundRisk      = Invoke-DefenderQuery $DailyQ.OutboundExternalBySender
$BillSummary       = Invoke-DefenderQuery $DailyQ.BillBlastSummary
$BillTopRecipients = Invoke-DefenderQuery $DailyQ.BillBlastTopRecipients

# ==========================================================
# 14-day recipient validation investigation + AD enrichment
# ==========================================================
Import-Module ActiveDirectory -ErrorAction Stop

$investigationCategoryFilter = if ($IncludeQuarantine) {
    'Category in ("Non-Existent User", "Blocked (Pre-Resolution)")'
} else {
    'Category == "Non-Existent User"'
}

$investigationKql = @"
EmailEvents
| where Timestamp > ago(14d)
| where RecipientEmailAddress endswith "@$InvestigateDomain"
| extend Category = case(
    LatestDeliveryLocation == "Failed", "Non-Existent User",
    LatestDeliveryLocation == "Quarantine", "Blocked (Pre-Resolution)",
    LatestDeliveryLocation == "Inbox", "Delivered",
    "Other"
)
| where $investigationCategoryFilter
| extend NormalizedRecipientEmailAddress = replace_regex(tolower(RecipientEmailAddress), @"^prvs=[^=]+=", "")
| summarize
    Attempts = count(),
    SenderCount = dcount(SenderFromAddress),
    Senders = make_set(SenderFromAddress, 20),
    SenderIPs = make_set(SenderIPv4, 20),
    Subjects = make_set(Subject, 10),
    RawEmailVariants = make_set(RecipientEmailAddress, 20)
by NormalizedRecipientEmailAddress, Category, LatestDeliveryLocation
| order by Attempts desc
"@

$investigationRecords = Invoke-DefenderQuery $investigationKql
foreach ($record in $investigationRecords) {
    Add-Member -InputObject $record -NotePropertyName RecipientEmailAddress -NotePropertyValue $record.NormalizedRecipientEmailAddress -Force
}

$investigationRecords = Add-ADAccountStatus `
    -Records $investigationRecords `
    -IdentityProperty "RecipientEmailAddress" `
    -SearchBase $AdSearchBase `
    -Server $AdServer

$recipientValidationRows = foreach ($record in $investigationRecords) {
    $email = Resolve-NormalizedEmailAddress -Email ([string]$record.NormalizedRecipientEmailAddress)
    if ([string]::IsNullOrWhiteSpace($email)) { continue }
    $sam = ($email -split "@")[0]

    [pscustomobject]@{
        Email            = $email
        Category         = [string]$record.Category
        DeliveryLocation = [string]$record.LatestDeliveryLocation
        AD_Status        = if ($record.ADAccountExists) { if ($record.ADEnabled) { "Exists (Enabled)" } else { "Exists (Disabled)" } } else { "NOT FOUND IN AD" }
        SamAccount       = if ($record.ADSamAccountName) { $record.ADSamAccountName } else { $sam }
        UPN              = if ($record.ADUserPrincipalName) { $record.ADUserPrincipalName } else { "$sam@$InvestigateUpnSuffix" }
        Attempts         = [int]$record.Attempts
        SenderCount      = [int]$record.SenderCount
        RawVariantPreview = Get-PreviewText -Text (Convert-CollectionToText -Value $record.RawEmailVariants) -MaxLength 70
        SubjectPreview    = Get-PreviewText -Text (Convert-CollectionToText -Value $record.Subjects) -MaxLength 70
        SenderPreview     = Get-PreviewText -Text (Convert-CollectionToText -Value $record.Senders) -MaxLength 70
    }
}

$recipientValidationRows = $recipientValidationRows |
    Where-Object { $_.AD_Status -in @("NOT FOUND IN AD", "Exists (Disabled)") } |
    Sort-Object @{ Expression = { $_.Attempts }; Descending = $true }, @{ Expression = { $_.Email }; Descending = $false }

$recipientValidationCount = @($recipientValidationRows).Count

# Inbound % for category table (and pie)
$TotalInbound = ($InboundCategory | Measure-Object Messages -Sum).Sum
if (-not $TotalInbound -or $TotalInbound -eq 0) { $TotalInbound = 0 }

$InboundCategory = $InboundCategory | ForEach-Object {
    $pct = if ($TotalInbound -gt 0) { [math]::Round(($_.Messages / $TotalInbound) * 100, 1) } else { 0.0 }
    $_ | Add-Member -NotePropertyName Percent -NotePropertyValue $pct -Force -PassThru
}

# Outbound at-a-glance
function Get-OutCount([string]$scope) {
    $row = $OutboundTotals | Where-Object { $_.SentScope -eq $scope } | Select-Object -First 1
    if ($row -and $row.Messages) { return [int]$row.Messages }
    return 0
}
$OutTotal = Get-OutCount "Total"
$OutExt   = Get-OutCount "External"
$OutInt   = Get-OutCount "Internal"
$OutExtPct = if ($OutTotal -gt 0) { [math]::Round(($OutExt / $OutTotal) * 100, 1) } else { 0.0 }
$OutIntPct = if ($OutTotal -gt 0) { [math]::Round(($OutInt / $OutTotal) * 100, 1) } else { 0.0 }

# Charts
$PieSvg   = New-SvgPieChart -Rows $InboundCategory -Size 220
$TrendSvg = New-SvgHourlyTrendChart -Rows $InboundHourly -TimeZoneId $ReportTimeZoneId -Width 900 -Height 260
$TopSubjectsSvg = New-SvgHorizontalBarChart -Rows $TopSubjects -LabelField "Subject" -ValueField "Messages" -Width 1100

# ==========================================================
# BUILD DAILY HTML
# ==========================================================
$DailyHtml = @"
<html>
<head>
<meta charset="utf-8" />
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 30px; }
h1 { margin-bottom: 0; }
.small { color: #555; margin-top: 6px; }
h2 { color: #003366; margin-top: 26px; }
h3 { margin:10px 0 6px 0; color:#333; }
.hr { height:1px; background:#ddd; border:0; margin: 22px 0; }
.callout { background:#f7f7f7; border:1px solid #ddd; padding:12px 14px; border-radius:8px; margin:10px 0; }
.collapsible { margin: 14px 0 20px 0; padding:0; border:none; background:transparent; }
.collapsible > summary { cursor:pointer; font-weight:600; color:#003366; margin:2px 0 8px 0; }
</style>
</head>
<body>

<h1>User Email Summary</h1>
<p class="small">
  <b>Date (Local):</b> $DateLabel ($ReportTimeZoneId) &nbsp;&nbsp;|&nbsp;&nbsp;
  <b>UTC Window:</b> $($DailyWindow.UtcStartKql) .. $($DailyWindow.UtcEndExclKql) (end exclusive) &nbsp;&nbsp;|&nbsp;&nbsp;
  <b>Internal Domains:</b> $(HtmlEncode $DomainsLabel)
</p>

<div class="callout">
  <b>At-a-glance (Inbound):</b>
  Total inbound messages: <b>$("{0:N0}" -f $TotalInbound)</b>
</div>

<div class="callout">
  <b>At-a-glance (Outbound - Sent by Us):</b>
  Total outbound: <b>$("{0:N0}" -f $OutTotal)</b>
  &nbsp;&nbsp;|&nbsp;&nbsp;
  External: <b>$("{0:N0}" -f $OutExt)</b> (<b>$("{0:N1}" -f $OutExtPct)%</b>)
  &nbsp;&nbsp;|&nbsp;&nbsp;
  Internal: <b>$("{0:N0}" -f $OutInt)</b> (<b>$("{0:N1}" -f $OutIntPct)%</b>)
</div>

<h2>Incoming Mail</h2>
$PieSvg
$(Convert-ToCiscoCategoryTable -Rows $InboundCategory -MinWidth 760)

<h2>Top Subjects (Inbound)</h2>
$TopSubjectsSvg

<h2>Inbound Trend (Hourly)</h2>
$TrendSvg

<hr class="hr"/>

<h2>Top Users by Threat Messages Received</h2>
$(Convert-ToHtmlTable $TopThreat @("RecipientEmailAddress","Messages") 760)

<h2>Top Users by Clean Messages Received</h2>
$(Convert-ToHtmlTable $TopClean @("RecipientEmailAddress","Messages") 760)

<h2>Top Users by Graymail/Bulk Messages Received</h2>
$(Convert-ToHtmlTable $TopGray @("RecipientEmailAddress","Messages") 760)

<hr class="hr"/>

<h2>Top External Sender Domains (All Inbound)</h2>
$(Convert-ToHtmlTable $TopInboundDomains @("SenderDomain","Messages") 760)

<h2>Top Sender Domains by Threat Type</h2>
<h3>Spam</h3>
$(Convert-ToHtmlTable $TopSpamDomains @("SenderDomain","Messages") 760)
<h3>Phish</h3>
$(Convert-ToHtmlTable $TopPhishDomains @("SenderDomain","Messages") 760)
<h3>Malware</h3>
$(Convert-ToHtmlTable $TopMalwareDomains @("SenderDomain","Messages") 760)

<hr class="hr"/>

<h2>Top Internal Recipients of Phish</h2>
$(Convert-ToHtmlTable $TopPhishRecipients @("RecipientEmailAddress","Messages") 760)

<h2>Top Phishing Campaigns (Sender + Subject)</h2>
$(Convert-ToHtmlTable $TopPhishCampaigns @("SenderFromAddress","Subject","Messages") 980)

<hr class="hr"/>

<h2>Legislative Bill Blast Watch (HB/SB #### + CS/HB|SB #### + CS/CS/HB|SB ####)</h2>
<p class="small">Matches patterns like <b>HB 123</b>, <b>SB123</b>, <b>CS/SB 1604</b>, and <b>CS/CS/SB 1632</b>  (case-insensitive).</p>

<h3>Summary by Bill Number</h3>
$(Convert-ToHtmlTable $BillSummary @("BillNumber","TotalEmails","UniqueRecipients","UniqueSenders","SenderDomains") 980)

<h3>Top Recipients (BillNumber + Recipient)</h3>
$(Convert-ToHtmlTable $BillTopRecipients @("BillNumber","RecipientEmailAddress","TotalEmails") 980)

<hr class="hr"/>

<h2>Outgoing Mail (Sent by Us)</h2>
$(Convert-ToHtmlTable $OutboundTotals @("SentScope","Messages") 760)

<h2>Top Senders (Sent by Us)</h2>
$(Convert-ToHtmlTable $OutboundTop @("From","Messages") 760)

<h2>Outbound Risk Watch: Top External Recipients by Internal Sender</h2>
$(Convert-ToHtmlTable $OutboundRisk @("From","RecipientEmailAddress","Messages") 980)

<hr class="hr"/>

<h2>Recipient Validation Investigation (Last 14 Days)</h2>
<p class="small">
  <b>Domain:</b> $(HtmlEncode $InvestigateDomain) &nbsp;&nbsp;|&nbsp;&nbsp;
  <b>Rows:</b> $recipientValidationCount
</p>
<details class="collapsible" open>
  <summary>Show/Hide Recipient Validation Table</summary>
  $(Convert-ToHtmlTable $recipientValidationRows @("Email","Category","DeliveryLocation","AD_Status","Attempts","SenderCount","SamAccount","UPN","RawVariantPreview","SubjectPreview","SenderPreview") 1100)
</details>

</body>
</html>
"@

$DailyHtml | Out-File $DailyOutputFile -Encoding UTF8
Write-Host "Daily report saved locally: $DailyOutputFile"

# ==========================================================
# WEEKLY ROLLUP (only when ShouldRunWeekly)
# ==========================================================
if ($ShouldRunWeekly) {
    Write-Host "Running WEEKLY rollup queries for local range: $WeeklyLabel ..."

    $WeeklyQ = Build-Queries -DateFilter $WeeklyDateFilter

    $InboundCategoryW   = Invoke-DefenderQuery $WeeklyQ.InboundCategory
    $InboundHourlyW     = Invoke-DefenderQuery $WeeklyQ.InboundHourlyTrend
    $TopPhishRecipientsW= Invoke-DefenderQuery $WeeklyQ.TopPhishRecipients
    $TopPhishCampaignsW = Invoke-DefenderQuery $WeeklyQ.TopPhishCampaigns
    $TopSpamDomainsW    = Invoke-DefenderQuery $WeeklyQ.TopSpamDomains
    $OutboundTotalsW    = Invoke-DefenderQuery $WeeklyQ.OutboundTotals
    $OutboundRiskW      = Invoke-DefenderQuery $WeeklyQ.OutboundExternalBySender
    $BillSummaryW       = Invoke-DefenderQuery $WeeklyQ.BillBlastSummary

    $TotalInboundW = ($InboundCategoryW | Measure-Object Messages -Sum).Sum
    if (-not $TotalInboundW -or $TotalInboundW -eq 0) { $TotalInboundW = 0 }

    $InboundCategoryW = $InboundCategoryW | ForEach-Object {
        $pct = if ($TotalInboundW -gt 0) { [math]::Round(($_.Messages / $TotalInboundW) * 100, 1) } else { 0.0 }
        $_ | Add-Member -NotePropertyName Percent -NotePropertyValue $pct -Force -PassThru
    }

    function Get-OutCountW([string]$scope) {
        $row = $OutboundTotalsW | Where-Object { $_.SentScope -eq $scope } | Select-Object -First 1
        if ($row -and $row.Messages) { return [int]$row.Messages }
        return 0
    }
    $OutTotalW = Get-OutCountW "Total"
    $OutExtW   = Get-OutCountW "External"
    $OutIntW   = Get-OutCountW "Internal"
    $OutExtPctW = if ($OutTotalW -gt 0) { [math]::Round(($OutExtW / $OutTotalW) * 100, 1) } else { 0.0 }
    $OutIntPctW = if ($OutTotalW -gt 0) { [math]::Round(($OutIntW / $OutTotalW) * 100, 1) } else { 0.0 }

    $PieSvgW   = New-SvgPieChart -Rows $InboundCategoryW -Size 220
    $TrendSvgW = New-SvgHourlyTrendChart -Rows $InboundHourlyW -TimeZoneId $ReportTimeZoneId -Width 900 -Height 260

    $WeeklyHtml = @"
<html>
<head>
<meta charset="utf-8" />
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 30px; }
h1 { margin-bottom: 0; }
.small { color: #555; margin-top: 6px; }
h2 { color: #003366; margin-top: 26px; }
h3 { margin:10px 0 6px 0; color:#333; }
.hr { height:1px; background:#ddd; border:0; margin: 22px 0; }
.callout { background:#f7f7f7; border:1px solid #ddd; padding:12px 14px; border-radius:8px; margin:10px 0; }
</style>
</head>
<body>

<h1>User Email Summary (Weekly Rollup)</h1>
<p class="small">
  <b>Range (Local):</b> $(HtmlEncode $WeeklyLabel) ($ReportTimeZoneId) &nbsp;&nbsp;|&nbsp;&nbsp;
  <b>UTC Window:</b> $($WeeklyWindowStart.UtcStartKql) .. $($DailyWindow.UtcEndExclKql) (end exclusive) &nbsp;&nbsp;|&nbsp;&nbsp;
  <b>Internal Domains:</b> $(HtmlEncode $DomainsLabel)
</p>

<div class="callout">
  <b>At-a-glance (Inbound):</b>
  Total inbound messages: <b>$("{0:N0}" -f $TotalInboundW)</b>
</div>

<div class="callout">
  <b>At-a-glance (Outbound - Sent by Us):</b>
  Total outbound: <b>$("{0:N0}" -f $OutTotalW)</b>
  &nbsp;&nbsp;|&nbsp;&nbsp;
  External: <b>$("{0:N0}" -f $OutExtW)</b> (<b>$("{0:N1}" -f $OutExtPctW)%</b>)
  &nbsp;&nbsp;|&nbsp;&nbsp;
  Internal: <b>$("{0:N0}" -f $OutIntW)</b> (<b>$("{0:N1}" -f $OutIntPctW)%</b>)
</div>

<h2>Incoming Mail (Weekly)</h2>
$PieSvgW
$(Convert-ToCiscoCategoryTable -Rows $InboundCategoryW -MinWidth 760)

<h2>Inbound Trend (Hourly) (Weekly)</h2>
$TrendSvgW

<hr class="hr"/>

<h2>Top Sender Domains (Spam) - Weekly</h2>
$(Convert-ToHtmlTable $TopSpamDomainsW @("SenderDomain","Messages") 760)

<h2>Top Internal Recipients of Phish - Weekly</h2>
$(Convert-ToHtmlTable $TopPhishRecipientsW @("RecipientEmailAddress","Messages") 760)

<h2>Top Phishing Campaigns (Sender + Subject) - Weekly</h2>
$(Convert-ToHtmlTable $TopPhishCampaignsW @("SenderFromAddress","Subject","Messages") 980)

<hr class="hr"/>

<h2>Legislative Bill Blast Watch (Weekly)</h2>
$(Convert-ToHtmlTable $BillSummaryW @("BillNumber","TotalEmails","UniqueRecipients","UniqueSenders","SenderDomains") 980)

<hr class="hr"/>

<h2>Outgoing Mail (Sent by Us) - Weekly</h2>
$(Convert-ToHtmlTable $OutboundTotalsW @("SentScope","Messages") 760)

<h2>Outbound Risk Watch - Weekly</h2>
$(Convert-ToHtmlTable $OutboundRiskW @("From","RecipientEmailAddress","Messages") 980)

</body>
</html>
"@

    $WeeklyHtml | Out-File $WeeklyOutputFile -Encoding UTF8
    Write-Host "Weekly report saved locally: $WeeklyOutputFile"
} else {
    Write-Host "Weekly rollup skipped (not Sunday report day)."
}

# ==========================================================
# SHAREPOINT UPLOAD (optional, robust drive selection + encoding)
# ==========================================================
function Get-GraphToken {
    param(
        [Parameter(Mandatory)] [string] $TenantId,
        [Parameter(Mandatory)] [string] $ClientId,
        [Parameter(Mandatory)] [string] $ClientSecret,
        [Parameter(Mandatory)] [string] $GraphBase
    )

    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $resource = ($GraphBase -replace "/v1\.0$","")  # https://graph.microsoft.com OR https://graph.microsoft.us

    $body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "$resource/.default"
    }

    $resp = Invoke-RestMethod -Method Post -Uri $tokenUri -Body $body -ContentType "application/x-www-form-urlencoded"
    if (-not $resp.access_token) { throw "Failed to acquire Graph token." }
    return $resp.access_token
}

function Convert-ToGraphPath {
    param([Parameter(Mandatory)][string]$Path)

    $p = $Path.Trim('/')
    if (-not $p) { return "" }

    $segments = $p -split '/'
    $encoded  = $segments | ForEach-Object { [Uri]::EscapeDataString($_) }
    return ($encoded -join '/')
}

function Resolve-DriveId {
    param(
        [Parameter(Mandatory)] [string] $GraphBase,
        [Parameter(Mandatory)] [hashtable] $AuthHeaders,
        [Parameter(Mandatory)] [string] $SiteId,
        [Parameter(Mandatory)] [string] $PreferredName
    )

    $drivesUri = "{0}/sites/{1}/drives" -f $GraphBase, $SiteId
    $drives = Invoke-RestMethod -Method GET -Uri $drivesUri -Headers $AuthHeaders
    if (-not $drives.value) { throw "No drives returned for site." }

    # Prefer the actual Shared Documents drive by webUrl (avoids Shared Documents1)
    if ($PreferredName -in @("Documents","Shared Documents")) {
        $byUrl = $drives.value | Where-Object { $_.webUrl -match "/Shared%20Documents$" } | Select-Object -First 1
        if ($byUrl) {
            Write-Host ("Using drive (webUrl): {0} | id={1} | webUrl={2}" -f $byUrl.name, $byUrl.id, $byUrl.webUrl)
            return $byUrl.id
        }
    }

    # Exact name match
    $drive = $drives.value | Where-Object { $_.name -eq $PreferredName } | Select-Object -First 1
    if ($drive) {
        Write-Host ("Using drive (name): {0} | id={1} | webUrl={2}" -f $drive.name, $drive.id, $drive.webUrl)
        return $drive.id
    }

    # Fallbacks
    foreach ($alt in @("Documents","Shared Documents")) {
        $drive = $drives.value | Where-Object { $_.name -eq $alt } | Select-Object -First 1
        if ($drive) {
            Write-Host ("Using drive (fallback): {0} | id={1} | webUrl={2}" -f $drive.name, $drive.id, $drive.webUrl)
            return $drive.id
        }
    }

    throw "Could not resolve drive. Available: $($drives.value.name -join ', ')"
}

function Ensure-SharePointFolder {
    param(
        [Parameter(Mandatory)] [string] $GraphBase,
        [Parameter(Mandatory)] [hashtable] $AuthHeaders,
        [Parameter(Mandatory)] [string] $DriveId,
        [Parameter(Mandatory)] [string] $FolderPathInLibrary
    )

    $folderPath = $FolderPathInLibrary.Trim('/')
    if (-not $folderPath) { return }

    $parts = $folderPath -split '/'
    $currentPath = ""

    foreach ($part in $parts) {
        $currentPath = if ($currentPath) { "$currentPath/$part" } else { $part }

        $encodedCurrent = Convert-ToGraphPath -Path $currentPath
        $getUri = "{0}/drives/{1}/root:/{2}" -f $GraphBase, $DriveId, $encodedCurrent

        try {
            Invoke-RestMethod -Method GET -Uri $getUri -Headers $AuthHeaders | Out-Null
        } catch {
            $parentPath = ($currentPath -split '/')[0..([Math]::Max(0, ($currentPath -split '/').Count - 2))] -join '/'
            $parentEncoded = Convert-ToGraphPath -Path $parentPath

            $childrenUri = if ($parentPath) {
                "{0}/drives/{1}/root:/{2}:/children" -f $GraphBase, $DriveId, $parentEncoded
            } else {
                "{0}/drives/{1}/root/children" -f $GraphBase, $DriveId
            }

            $body = @{
                name = $part
                folder = @{}
                "@microsoft.graph.conflictBehavior" = "fail"
            } | ConvertTo-Json -Depth 5

            Invoke-RestMethod -Method POST -Uri $childrenUri -Headers $AuthHeaders -Body $body -ContentType "application/json" | Out-Null
        }
    }
}

function Upload-FileToSharePoint {
    param(
        [Parameter(Mandatory)] [string] $GraphBase,
        [Parameter(Mandatory)] [hashtable] $AuthHeaders,
        [Parameter(Mandatory)] [string] $SpHostname,
        [Parameter(Mandatory)] [string] $SpSitePath,
        [Parameter(Mandatory)] [string] $LibraryName,
        [Parameter(Mandatory)] [string] $FolderPathInLibrary,
        [Parameter(Mandatory)] [string] $LocalFilePath
    )

    if (-not (Test-Path $LocalFilePath)) { throw "Local file not found: $LocalFilePath" }

    # Resolve site by host+path (avoid "$var:" issues via -f)
    $siteUri = "{0}/sites/{1}:{2}" -f $GraphBase, $SpHostname, $SpSitePath
    $site = Invoke-RestMethod -Method GET -Uri $siteUri -Headers $AuthHeaders
    if (-not $site.id) { throw "Unable to resolve SharePoint site id." }

    $driveId = Resolve-DriveId -GraphBase $GraphBase -AuthHeaders $AuthHeaders -SiteId $site.id -PreferredName $LibraryName

    Ensure-SharePointFolder -GraphBase $GraphBase -AuthHeaders $AuthHeaders -DriveId $driveId -FolderPathInLibrary $FolderPathInLibrary

    $fileName = Split-Path $LocalFilePath -Leaf
    $targetPathRaw = ($FolderPathInLibrary.Trim('/') + "/" + $fileName).Trim('/')
    $targetPathEnc = Convert-ToGraphPath -Path $targetPathRaw

    $uploadUri = "{0}/drives/{1}/root:/{2}:/content" -f $GraphBase, $driveId, $targetPathEnc
    $bytes = [System.IO.File]::ReadAllBytes($LocalFilePath)

    $item = Invoke-RestMethod -Method PUT -Uri $uploadUri -Headers $AuthHeaders -Body $bytes -ContentType "text/html"
    if ($item.webUrl) { Write-Host "Uploaded item webUrl: $($item.webUrl)" }
}

if ($UploadToSharePoint) {
    $SpHostname = $env:SP_HOSTNAME
    $SpSitePath = $env:SP_SITE_PATH

    if (-not $SpHostname -or -not $SpSitePath) {
        throw "UploadToSharePoint set but missing SP_HOSTNAME and/or SP_SITE_PATH env vars."
    }

    Write-Host "Uploading report(s) to SharePoint..."
    Write-Host ("GraphBase: {0}" -f $GraphBase)
    Write-Host ("Site: https://{0}{1}" -f $SpHostname, $SpSitePath)
    Write-Host ("Target: {0}/{1}" -f $SpLibraryName, $SpFolderPathInLibrary)

    $graphToken = Get-GraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -GraphBase $GraphBase
    $auth = @{
        Authorization = "Bearer $graphToken"
        Accept        = "application/json"
    }

    # Upload Daily
    Upload-FileToSharePoint `
        -GraphBase $GraphBase `
        -AuthHeaders $auth `
        -SpHostname $SpHostname `
        -SpSitePath $SpSitePath `
        -LibraryName $SpLibraryName `
        -FolderPathInLibrary $SpFolderPathInLibrary `
        -LocalFilePath $DailyOutputFile

    # Upload Weekly only when generated
    if ($ShouldRunWeekly -and (Test-Path $WeeklyOutputFile)) {
        Upload-FileToSharePoint `
            -GraphBase $GraphBase `
            -AuthHeaders $auth `
            -SpHostname $SpHostname `
            -SpSitePath $SpSitePath `
            -LibraryName $SpLibraryName `
            -FolderPathInLibrary $SpFolderPathInLibrary `
            -LocalFilePath $WeeklyOutputFile
    }

    Write-Host "SharePoint upload complete."
}

Write-Host "Completed successfully."
