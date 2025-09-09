<# 
Quick registry check (WinRM first, optional DCOM fallback) 
Sanitized version – edit $Servers with your own hostnames
#>

# --- Config ---
$Servers   = @('Server1','Server2','Server3','Server4','Server5')  # replace with your servers
$Hive      = 'HKLM'
$RegPath   = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
$ValueName = 'ScanWithAntiVirus'
$OutCsv    = $null  # e.g. 'C:\Temp\RegCheck.csv' or leave $null to skip

# --- Helper (WinRM only) ---
function Get-RegistryValueRemote {
    param([string]$Computer,[string]$Hive,[string]$RegPath,[string]$ValueName)
    $psPath = Join-Path "$Hive`:" $RegPath
    try {
        Invoke-Command -ComputerName $Computer -ScriptBlock {
            param($psPath,$ValueName)
            if (-not (Test-Path -Path $psPath)) { 
                return [pscustomobject]@{ Status='NoKey'; Value=$null } 
            }
            $item = Get-ItemProperty -Path $psPath -ErrorAction Stop
            if ($null -eq $item.$ValueName) { 
                return [pscustomobject]@{ Status='NotSet'; Value=$null } 
            }
            [pscustomobject]@{ Status='OK'; Value=$item.$ValueName }
        } -ArgumentList $psPath,$ValueName -ErrorAction Stop
    } catch {
        [pscustomobject]@{ Status='Error'; Value=$_.Exception.Message }
    }
}

# --- Run ---
$rows = foreach ($srv in $Servers) {
    $res = Get-RegistryValueRemote -Computer $srv -Hive $Hive -RegPath $RegPath -ValueName $ValueName
    [pscustomobject]@{
        ComputerName = $srv
        Hive         = $Hive
        RegistryPath = $RegPath
        ValueName    = $ValueName
        Status       = $res.Status
        Value        = $res.Value
    }
}

# Show table
$rows | Format-Table -AutoSize

# Optional export
if ($OutCsv) {
    $rows | Export-Csv -NoTypeInformation -Path $OutCsv
    Write-Host "Saved: $OutCsv" -ForegroundColor Green
}
