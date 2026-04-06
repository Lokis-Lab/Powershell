<#
.SYNOPSIS
  Parses Windows Group Policy artefacts (.pol, .inf, audit.csv, GPP XML,
  Registry.pol binary) into normalised PSCustomObject collections.

.DESCRIPTION
  Provides a common object model for GPO settings regardless of their
  on-disk format.  Every parser returns objects with at least:

    Category, SubCategory, SettingName, SettingValue, Source

  Used by the merge and compare engines downstream.
#>

#region ── .pol (Registry.pol binary) parser ───────────────────────────

function ConvertFrom-PolFile {
    <#
    .SYNOPSIS  Parse a Registry.pol binary file into setting objects.
    .PARAMETER Path  Full path to the .pol file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$Path
    )

    $bytes = [System.IO.File]::ReadAllBytes($Path)

    # Registry.pol header: 0x50526567 (PReg) + version 0x01000000
    if ($bytes.Length -lt 8) {
        Write-Warning "PolFile too small: $Path"
        return @()
    }

    $signature = [System.BitConverter]::ToUInt32($bytes, 0)
    $version   = [System.BitConverter]::ToUInt32($bytes, 4)
    if ($signature -ne 0x67655250 -or $version -ne 1) {
        Write-Warning "Invalid Registry.pol signature in $Path"
        return @()
    }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $pos = 8

    while ($pos -lt $bytes.Length) {
        # Each entry: [key;value;type;size;data]
        if ($bytes[$pos] -ne 0x5B -and $bytes[$pos + 1] -ne 0x00) { $pos++; continue }
        $pos += 2  # skip '[' in UTF-16LE

        $keyStart = $pos
        while ($pos + 1 -lt $bytes.Length) {
            if ($bytes[$pos] -eq 0x00 -and $bytes[$pos + 1] -eq 0x00) { break }
            $pos += 2
        }
        $key = [System.Text.Encoding]::Unicode.GetString($bytes, $keyStart, $pos - $keyStart)
        $pos += 2  # null terminator

        # semicolon delimiter
        if ($pos + 1 -lt $bytes.Length -and $bytes[$pos] -eq 0x3B -and $bytes[$pos + 1] -eq 0x00) { $pos += 2 }

        $valStart = $pos
        while ($pos + 1 -lt $bytes.Length) {
            if ($bytes[$pos] -eq 0x00 -and $bytes[$pos + 1] -eq 0x00) { break }
            $pos += 2
        }
        $valueName = [System.Text.Encoding]::Unicode.GetString($bytes, $valStart, $pos - $valStart)
        $pos += 2

        # semicolon
        if ($pos + 1 -lt $bytes.Length -and $bytes[$pos] -eq 0x3B -and $bytes[$pos + 1] -eq 0x00) { $pos += 2 }

        # type (DWORD, 4 bytes)
        $regType = 0
        if ($pos + 3 -lt $bytes.Length) {
            $regType = [System.BitConverter]::ToUInt32($bytes, $pos)
            $pos += 4
        }

        # semicolon
        if ($pos + 1 -lt $bytes.Length -and $bytes[$pos] -eq 0x3B -and $bytes[$pos + 1] -eq 0x00) { $pos += 2 }

        # size (DWORD)
        $dataSize = 0
        if ($pos + 3 -lt $bytes.Length) {
            $dataSize = [System.BitConverter]::ToUInt32($bytes, $pos)
            $pos += 4
        }

        # semicolon
        if ($pos + 1 -lt $bytes.Length -and $bytes[$pos] -eq 0x3B -and $bytes[$pos + 1] -eq 0x00) { $pos += 2 }

        # data
        $dataValue = ''
        if ($dataSize -gt 0 -and ($pos + $dataSize) -le $bytes.Length) {
            switch ($regType) {
                1 { $dataValue = [System.Text.Encoding]::Unicode.GetString($bytes, $pos, $dataSize).TrimEnd("`0") } # REG_SZ
                4 { if ($dataSize -ge 4) { $dataValue = [System.BitConverter]::ToUInt32($bytes, $pos).ToString() } } # REG_DWORD
                default { $dataValue = [System.BitConverter]::ToString($bytes, $pos, $dataSize) }
            }
            $pos += $dataSize
        }

        # closing bracket
        if ($pos + 1 -lt $bytes.Length -and $bytes[$pos] -eq 0x5D -and $bytes[$pos + 1] -eq 0x00) { $pos += 2 }

        $results.Add([PSCustomObject]@{
            Category     = 'Registry Policy'
            SubCategory  = $key
            SettingName  = $valueName
            SettingValue = $dataValue
            RegType      = $regType
            Source        = $Path
        })
    }

    return $results
}

#endregion

#region ── GptTmpl.inf parser ──────────────────────────────────────────

function ConvertFrom-InfFile {
    <#
    .SYNOPSIS  Parse a GptTmpl.inf (Security Template) into setting objects.
    .PARAMETER Path  Full path to the .inf file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$Path
    )

    $results  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $section  = ''

    foreach ($raw in [System.IO.File]::ReadAllLines($Path)) {
        $line = $raw.Trim()
        if (-not $line -or $line.StartsWith(';')) { continue }

        if ($line -match '^\[(.+)\]$') {
            $section = $Matches[1]
            continue
        }

        $parts = $line -split '\s*=\s*', 2
        $name  = $parts[0].Trim()
        $val   = if ($parts.Length -gt 1) { $parts[1].Trim() } else { '' }

        $results.Add([PSCustomObject]@{
            Category     = 'Security Template'
            SubCategory  = $section
            SettingName  = $name
            SettingValue = $val
            Source        = $Path
        })
    }

    return $results
}

#endregion

#region ── Audit.csv parser ────────────────────────────────────────────

function ConvertFrom-AuditCsv {
    <#
    .SYNOPSIS  Parse an audit.csv (Advanced Audit Policy) into setting objects.
    .PARAMETER Path  Full path to the audit.csv file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$Path
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $lines   = [System.IO.File]::ReadAllLines($Path)

    foreach ($line in $lines) {
        if (-not $line.Trim() -or $line.StartsWith('Machine Name')) { continue }
        $cols = $line -split ','
        if ($cols.Length -lt 4) { continue }

        $subcat   = $cols[2].Trim()
        $inclExcl = $cols[3].Trim()
        $val      = $cols[4].Trim() # 0=No Auditing 1=Success 2=Failure 3=Success+Failure

        $readable = switch ($val) {
            '0' { 'No Auditing' }
            '1' { 'Success' }
            '2' { 'Failure' }
            '3' { 'Success and Failure' }
            default { $val }
        }

        $results.Add([PSCustomObject]@{
            Category     = 'Advanced Audit Policy'
            SubCategory  = $subcat
            SettingName  = $subcat
            SettingValue = $readable
            IncExcl      = $inclExcl
            Source        = $Path
        })
    }

    return $results
}

#endregion

#region ── GPP XML parser (Preferences) ────────────────────────────────

function ConvertFrom-GppXml {
    <#
    .SYNOPSIS  Parse Group Policy Preferences XML files into setting objects.
    .PARAMETER Path  Full path to a GPP XML file (e.g., Registry.xml, Services.xml).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$Path
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        [xml]$xml = Get-Content -Path $Path -Raw -ErrorAction Stop
    } catch {
        Write-Warning "Failed to parse GPP XML: $Path - $($_.Exception.Message)"
        return @()
    }

    $root = $xml.DocumentElement
    if (-not $root) { return @() }

    $category = $root.LocalName  # e.g., RegistrySettings, Services, etc.

    foreach ($node in $root.ChildNodes) {
        if ($node.NodeType -ne 'Element') { continue }

        $props = $node.Properties
        if ($props) {
            $settingName  = if ($props.name) { $props.name } elseif ($props.keyName) { $props.keyName } else { $node.name }
            $settingValue = if ($props.value) { $props.value } elseif ($props.startupType) { $props.startupType } else { '' }

            $results.Add([PSCustomObject]@{
                Category     = 'Group Policy Preferences'
                SubCategory  = $category
                SettingName  = $settingName
                SettingValue = $settingValue
                Action       = $props.action
                Source        = $Path
            })
        } else {
            $results.Add([PSCustomObject]@{
                Category     = 'Group Policy Preferences'
                SubCategory  = $category
                SettingName  = $node.name
                SettingValue = $node.InnerText
                Action       = ''
                Source        = $Path
            })
        }
    }

    return $results
}

#endregion

#region ── GPO Report XML parser ───────────────────────────────────────

function ConvertFrom-GpoReportXml {
    <#
    .SYNOPSIS  Parse a Get-GPOReport XML file into normalised setting objects.
    .PARAMETER Path  Full path to the GPO report XML.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$Path
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        [xml]$xml = Get-Content -Path $Path -Raw -ErrorAction Stop
    } catch {
        Write-Warning "Failed to parse GPO report XML: $Path - $($_.Exception.Message)"
        return @()
    }

    $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $ns.AddNamespace('gpo', 'http://www.microsoft.com/GroupPolicy/Settings')
    $ns.AddNamespace('types', 'http://www.microsoft.com/GroupPolicy/Types')
    $ns.AddNamespace('reg', 'http://www.microsoft.com/GroupPolicy/Settings/Registry')
    $ns.AddNamespace('sec', 'http://www.microsoft.com/GroupPolicy/Settings/Security')
    $ns.AddNamespace('audit', 'http://www.microsoft.com/GroupPolicy/Settings/Auditing')
    $ns.AddNamespace('scripts', 'http://www.microsoft.com/GroupPolicy/Settings/Scripts')

    # Extract Computer and User settings
    foreach ($scope in @('Computer', 'User')) {
        $extNodes = $xml.SelectNodes("//gpo:${scope}/gpo:ExtensionData/gpo:Extension", $ns)
        if (-not $extNodes) { continue }

        foreach ($ext in $extNodes) {
            foreach ($child in $ext.ChildNodes) {
                if ($child.NodeType -ne 'Element') { continue }

                $cat = $child.LocalName
                $name  = ''
                $value = ''

                if ($child.Name) { $name = $child.Name }
                if ($child.State) { $value = $child.State }
                if (-not $name -and $child.KeyName) { $name = $child.KeyName }
                if (-not $value -and $child.SettingNumber) { $value = $child.SettingNumber }
                if (-not $value -and $child.InnerText) { $value = $child.InnerText.Substring(0, [Math]::Min(500, $child.InnerText.Length)) }

                if (-not $name) { $name = $cat }

                $results.Add([PSCustomObject]@{
                    Category     = $cat
                    SubCategory  = $scope
                    SettingName  = $name
                    SettingValue = $value
                    Source        = $Path
                })
            }
        }
    }

    return $results
}

#endregion

#region ── Universal baseline folder parser ────────────────────────────

function Import-BaselineFolder {
    <#
    .SYNOPSIS
      Recursively parse all known policy artefacts under a GPO backup folder
      tree and return a unified collection of setting objects.
    .PARAMETER Path
      Root folder containing one or more GPO backup structures.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [string]$Path
    )

    $all = [System.Collections.Generic.List[PSCustomObject]]::new()

    # .pol files
    Get-ChildItem -Path $Path -Filter '*.pol' -Recurse -File | ForEach-Object {
        $parsed = ConvertFrom-PolFile -Path $_.FullName
        foreach ($item in $parsed) { $all.Add($item) }
    }

    # GptTmpl.inf
    Get-ChildItem -Path $Path -Filter 'GptTmpl.inf' -Recurse -File | ForEach-Object {
        $parsed = ConvertFrom-InfFile -Path $_.FullName
        foreach ($item in $parsed) { $all.Add($item) }
    }

    # audit.csv
    Get-ChildItem -Path $Path -Filter 'audit.csv' -Recurse -File | ForEach-Object {
        $parsed = ConvertFrom-AuditCsv -Path $_.FullName
        foreach ($item in $parsed) { $all.Add($item) }
    }

    # GPP XML files
    $gppNames = @('Registry.xml','Services.xml','Files.xml','Folders.xml',
                  'Ini.xml','EnvironmentVariables.xml','ScheduledTasks.xml',
                  'NetworkShares.xml','Printers.xml','Drives.xml',
                  'DataSources.xml','Shortcuts.xml','FolderOptions.xml')
    foreach ($gppFile in $gppNames) {
        Get-ChildItem -Path $Path -Filter $gppFile -Recurse -File | ForEach-Object {
            $parsed = ConvertFrom-GppXml -Path $_.FullName
            foreach ($item in $parsed) { $all.Add($item) }
        }
    }

    # GPO report XMLs (typically named *.xml under a Reports folder)
    Get-ChildItem -Path $Path -Filter '*.xml' -Recurse -File |
        Where-Object {
            $_.Name -notin $gppNames -and
            $_.Directory.Name -ne 'Preferences' -and
            $_.Directory.Name -ne 'Machine' -and
            $_.Directory.Name -ne 'User'
        } | ForEach-Object {
            $content = Get-Content -Path $_.FullName -TotalCount 5 -Raw -ErrorAction SilentlyContinue
            if ($content -match 'GroupPolicy/Settings' -or $content -match '<GPO ') {
                $parsed = ConvertFrom-GpoReportXml -Path $_.FullName
                foreach ($item in $parsed) { $all.Add($item) }
            }
        }

    return $all
}

#endregion

#region ── Unique key helper ───────────────────────────────────────────

function Get-SettingKey {
    <#
    .SYNOPSIS  Generate a unique composite key for a setting object.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][PSCustomObject]$Setting)
    process {
        "$($Setting.Category)|$($Setting.SubCategory)|$($Setting.SettingName)"
    }
}

#endregion

Export-ModuleMember -Function @(
    'ConvertFrom-PolFile',
    'ConvertFrom-InfFile',
    'ConvertFrom-AuditCsv',
    'ConvertFrom-GppXml',
    'ConvertFrom-GpoReportXml',
    'Import-BaselineFolder',
    'Get-SettingKey'
)
