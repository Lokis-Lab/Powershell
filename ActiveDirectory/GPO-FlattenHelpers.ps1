# Shared GPO XML -> flattened row helpers (dot-sourced by GPO-Audit-Master.ps1 and GPO-Policy-Audit.ps1)

function Get-XPathNodes {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$XPath)
  $n = $Xml.SelectNodes($XPath)
  if ($null -eq $n) { @() } else { $n }
}

function Get-FirstText {
  param([Parameter(Mandatory)][System.Xml.XmlNode]$Node,[Parameter(Mandatory)][string]$XPath)
  $first = $Node.SelectNodes($XPath) | Select-Object -First 1
  if ($first) { $first.InnerText } else { $null }
}

function Get-ScopeFromNode {
  param([Parameter(Mandatory)][System.Xml.XmlNode]$Node)
  $parentOuter = if ($Node.ParentNode) { $Node.ParentNode.OuterXml } else { '' }
  $blob = ($Node.OuterXml + ' ' + $parentOuter) -replace '\s+',' '
  if ($blob -match '(?i)\bcomputer\b') { 'Computer' }
  elseif ($blob -match '(?i)\buser\b') { 'User' }
  else { 'Unknown' }
}

function New-FlattenRow {
  param(
    [Parameter(Mandatory)][string]$Gpo,
    [Parameter(Mandatory)][string]$Scope,
    [Parameter(Mandatory)][string]$Extension,
    [Parameter(Mandatory)][string]$Category,
    [Parameter(Mandatory)][string]$Setting,
    [Parameter()][string]$Value,
    [Parameter()][string]$Type
  )
  [pscustomobject]@{
    GPO            = $Gpo
    Scope          = $Scope
    Extension      = $Extension
    Category       = $Category
    Setting        = $Setting
    Type           = $Type
    Value          = $Value
    Canonical      = '{0}|{1}|{2}|{3}|{4}' -f $Gpo,$Scope,$Extension,$Category,$Setting
    CanonicalNoGpo = '{0}|{1}|{2}|{3}'     -f $Scope,$Extension,$Category,$Setting
  }
}

function Add-FlattenRows {
  param(
    [Parameter(Mandatory)][System.Collections.Generic.List[object]]$Target,
    [Parameter()][AllowNull()]$Items
  )
  if ($null -eq $Items) { return }
  foreach ($i in @($Items)) {
    if ($null -ne $i) { [void]$Target.Add($i) }
  }
}

function Get-AdminTemplatePolicyRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Gpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($p in (Get-XPathNodes -Xml $Xml -XPath "//*[local-name()='Policy']")) {
    $display = $p.displayName; if (-not $display) { $display = $p.name }
    $state   = $p.state
    if (-not $state) { $state = $p.Enabled }
    if (-not $state) { $state = $p.Disable }
    if (-not $state) { $state = Get-FirstText -Node $p -XPath ".//*[local-name()='State']" }
    if (-not $state) { $state = Get-FirstText -Node $p -XPath ".//*[local-name()='Value']" }
    $value   = Get-FirstText -Node $p -XPath ".//*[local-name()='Value']"
    if (-not $value) { $value = [string]$state }
    $rows.Add( (New-FlattenRow -Gpo $Gpo -Scope (Get-ScopeFromNode $p) -Extension 'AdminTemplates' -Category 'Policies' -Setting $display -Value $value -Type 'Policy') )
  }
  return $rows
}

function Get-AdminTemplateRegistryRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Gpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($r in (Get-XPathNodes -Xml $Xml -XPath "//*[local-name()='RegistrySettings']/*[local-name()='Registry']")) {
    $props = $r.SelectSingleNode(".//*[local-name()='Properties']")
    $key   = $r.key
    if (-not $key -and $props) { $key = $props.key }
    $name  = $r.valueName
    if (-not $name -and $props) { $name = $props.valueName }
    if ($props) {
      $val  = $props.value
      $type = $props.type
    } else {
      $val  = $null
      $type = $null
    }
    $setting = ($key, $name) -join '\'
    $rows.Add( (New-FlattenRow -Gpo $Gpo -Scope (Get-ScopeFromNode $r) -Extension 'AdminTemplates' -Category 'Registry' -Setting $setting -Value ([string]$val) -Type ([string]$type)) )
  }
  return $rows
}

function Get-GPPRegistryRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Gpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($it in (Get-XPathNodes -Xml $Xml -XPath "//*[local-name()='RegistrySettings']/*[local-name()='Registry']/*[local-name()='Properties']")) {
    $key    = $it.key; $name = $it.valueName; $val = $it.value; $type = $it.type; $action = $it.action
    $cat    = if ($action) { "GPP (Action:$action)" } else { "GPP" }
    $setting = ($key, $name) -join '\'
    $rows.Add( (New-FlattenRow -Gpo $Gpo -Scope (Get-ScopeFromNode $it) -Extension 'GroupPolicyPreferences' -Category $cat -Setting $setting -Value ([string]$val) -Type ([string]$type)) )
  }
  return $rows
}

function Get-GpoAuditSettingValueDisplay {
  param([string]$Raw)
  if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
  $t = $Raw.Trim()
  switch ($t) {
    '0' { return 'Unchanged' }
    '1' { return 'Success only' }
    '2' { return 'Failure only' }
    '3' { return 'Success and Failure' }
    '4' { return 'No auditing' }
    default { return $t }
  }
}

function Get-AdvancedAuditPolicyRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Gpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($a in (Get-XPathNodes -Xml $Xml -XPath "//*[local-name()='AuditSetting']")) {
    $sub = Get-FirstText -Node $a -XPath ".//*[local-name()='SubcategoryName']"
    if (-not $sub) { $sub = Get-FirstText -Node $a -XPath ".//*[local-name()='Subcategory']" }
    if (-not $sub) { try { $sub = $a.SubcategoryName } catch { $sub = $null } }
    if (-not $sub) { try { $sub = $a.Subcategory } catch { $sub = $null } }
    if (-not $sub) { $sub = '(unknown subcategory)' }

    $inc = Get-FirstText -Node $a -XPath ".//*[local-name()='InclusionSetting']"
    if (-not $inc) { try { $inc = $a.InclusionSetting } catch { $inc = $null } }

    $sv = Get-FirstText -Node $a -XPath ".//*[local-name()='SettingValue']"
    if (-not $sv) { try { $sv = $a.SettingValue } catch { $sv = $null } }

    $val = $null
    if (-not [string]::IsNullOrWhiteSpace($inc)) { $val = $inc.Trim() }
    if ([string]::IsNullOrWhiteSpace($val)) { $val = Get-GpoAuditSettingValueDisplay -Raw $sv }
    if ([string]::IsNullOrWhiteSpace($val)) { $val = [string]$sv }

    $guid = Get-FirstText -Node $a -XPath ".//*[local-name()='SubcategoryGUID']"
    if (-not $guid) { try { $guid = $a.SubcategoryGUID } catch { $guid = $null } }
    if (-not [string]::IsNullOrWhiteSpace($guid)) {
      if ([string]::IsNullOrWhiteSpace($val)) { $val = "GUID=$guid" } else { $val = "$val; GUID=$guid" }
    }

    $setting = "Audit: $sub"
    $rows.Add( (New-FlattenRow -Gpo $Gpo -Scope (Get-ScopeFromNode $a) -Extension 'Security' -Category 'AdvancedAuditPolicy' -Setting $setting -Value $val -Type 'AuditSetting') )
  }
  return $rows
}

function Get-SecuritySettingRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Gpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($s in (Get-XPathNodes -Xml $Xml -XPath "//*[local-name()='SecuritySettings']")) {
    foreach ($n in $s.SelectNodes(".//*[not(*)]")) {
      if ($null -ne $n.SelectSingleNode("ancestor::*[local-name()='AuditSetting']")) { continue }
      $name = $n.Name
      $val  = $n.InnerText
      if ([string]::IsNullOrWhiteSpace($val)) { continue }
      $rows.Add( (New-FlattenRow -Gpo $Gpo -Scope (Get-ScopeFromNode $n) -Extension 'Security' -Category 'SecuritySettings' -Setting $name -Value ($val.Trim()) -Type $null) )
    }
  }
  return $rows
}

function Get-NTServiceRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Gpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($svc in (Get-XPathNodes -Xml $Xml -XPath "//*[local-name()='NTServices']/*[local-name()='NTService']")) {
    $name = $svc.name
    $mode = Get-FirstText -Node $svc -XPath ".//*[local-name()='StartupMode']"
    if (-not $mode) { $mode = $svc.startup }
    $rows.Add( (New-FlattenRow -Gpo $Gpo -Scope (Get-ScopeFromNode $svc) -Extension 'Security' -Category 'Services' -Setting $name -Value ([string]$mode) -Type 'Service') )
  }
  return $rows
}

function Get-LugsRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Gpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($g in (Get-XPathNodes -Xml $Xml -XPath "//*[local-name()='LocalUsersAndGroups']/*[local-name()='Group']")) {
    $groupName = $g.name
    if (-not $groupName) { $groupName = Get-FirstText -Node $g -XPath ".//*[local-name()='Name']" }
    if (-not $groupName) { $groupName = '(unknown)' }
    $action    = $g.action
    $rows.Add( (New-FlattenRow -Gpo $Gpo -Scope (Get-ScopeFromNode $g) -Extension 'GPP' -Category 'LocalGroups' -Setting $groupName -Value ("Action=$action") -Type 'Group') )
    foreach ($m in $g.SelectNodes(".//*[local-name()='Member']|.//*[local-name()='Members']/*")) {
      $memberId = if ($null -ne $m.name) { $m.name } else { $m.InnerText }
      if ($memberId) {
        $rows.Add( (New-FlattenRow -Gpo $Gpo -Scope (Get-ScopeFromNode $m) -Extension 'GPP' -Category 'LocalGroups\Members' -Setting $groupName -Value ([string]$memberId) -Type 'Member') )
      }
    }
  }
  return $rows
}

function Get-ScriptRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Gpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($s in (Get-XPathNodes -Xml $Xml -XPath "//*[local-name()='Script']")) {
    $scriptName = $s.name
    if (-not $scriptName) { $scriptName = Get-FirstText -Node $s -XPath ".//*[local-name()='Name']" }
    if (-not $scriptName) { $scriptName = Get-FirstText -Node $s -XPath ".//*[local-name()='Command']" }
    if (-not $scriptName) { $scriptName = '(script)' }
    $type = Get-FirstText -Node $s -XPath ".//*[local-name()='Type']"
    if (-not $type) { $type = 'Script' }
    $cmd  = Get-FirstText -Node $s -XPath ".//*[local-name()='Command']"
    if (-not $cmd) { $cmd = Get-FirstText -Node $s -XPath ".//*[local-name()='Parameters']" }
    $rows.Add( (New-FlattenRow -Gpo $Gpo -Scope (Get-ScopeFromNode $s) -Extension 'Scripts' -Category $type -Setting $scriptName -Value ([string]$cmd) -Type 'Script') )
  }
  return $rows
}

function Get-WlanPolicyRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Gpo)
  $rows = [System.Collections.Generic.List[object]]::new()
  $xpath = "//*[local-name()='Extension' and contains(@*, 'WLanSvcSettings')]//*[local-name()='WLanSvcSetting']|//*[local-name()='WLanPolicies']/*"
  foreach ($w in (Get-XPathNodes -Xml $Xml -XPath $xpath)) {
    $policyName = $w.name
    if (-not $policyName) { $policyName = Get-FirstText -Node $w -XPath ".//*[local-name()='Name']" }
    if (-not $policyName) { $policyName = '(WLAN Policy)' }
    $mode = Get-FirstText -Node $w -XPath ".//*[local-name()='Mode']"
    if (-not $mode) { $mode = Get-FirstText -Node $w -XPath ".//*[local-name()='PolicyType']" }
    $rows.Add( (New-FlattenRow -Gpo $Gpo -Scope (Get-ScopeFromNode $w) -Extension 'WLAN' -Category 'WlanPolicies' -Setting $policyName -Value ([string]$mode) -Type 'WLAN') )
  }
  return $rows
}

function Get-AllFlattenedRows {
  param([Parameter(Mandatory)][xml]$Xml,[Parameter(Mandatory)][string]$Gpo)
  $rows = [System.Collections.Generic.List[object]]::new()

  $gpoName = Get-FirstText -Node $Xml -XPath ".//*[local-name()='GPO']/*[local-name()='Name']"
  if (-not $gpoName) { $gpoName = $Gpo }
  $gpoGuid = Get-FirstText -Node $Xml -XPath ".//*[local-name()='GPO']/*[local-name()='Identifier']"
  if (-not $gpoGuid) { $gpoGuid = Get-FirstText -Node $Xml -XPath ".//*[local-name()='Identifier']" }
  [void]$rows.Add( (New-FlattenRow -Gpo $Gpo -Scope 'N/A' -Extension 'Metadata' -Category 'GPO' -Setting 'Name' -Value $gpoName -Type 'String') )
  if ($gpoGuid) { [void]$rows.Add( (New-FlattenRow -Gpo $Gpo -Scope 'N/A' -Extension 'Metadata' -Category 'GPO' -Setting 'GUID' -Value $gpoGuid -Type 'String') ) }

  Add-FlattenRows -Target $rows -Items (Get-AdminTemplatePolicyRows   -Xml $Xml -Gpo $Gpo)
  Add-FlattenRows -Target $rows -Items (Get-AdminTemplateRegistryRows -Xml $Xml -Gpo $Gpo)
  Add-FlattenRows -Target $rows -Items (Get-GPPRegistryRows           -Xml $Xml -Gpo $Gpo)
  Add-FlattenRows -Target $rows -Items (Get-AdvancedAuditPolicyRows   -Xml $Xml -Gpo $Gpo)
  Add-FlattenRows -Target $rows -Items (Get-SecuritySettingRows       -Xml $Xml -Gpo $Gpo)
  Add-FlattenRows -Target $rows -Items (Get-NTServiceRows             -Xml $Xml -Gpo $Gpo)
  Add-FlattenRows -Target $rows -Items (Get-LugsRows                  -Xml $Xml -Gpo $Gpo)
  Add-FlattenRows -Target $rows -Items (Get-ScriptRows                -Xml $Xml -Gpo $Gpo)
  Add-FlattenRows -Target $rows -Items (Get-WlanPolicyRows            -Xml $Xml -Gpo $Gpo)

  return $rows
}
