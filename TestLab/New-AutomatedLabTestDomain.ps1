<#
.SYNOPSIS
  Provisions a single-domain Hyper-V lab with AutomatedLab for script testing.

.DESCRIPTION
  Creates a forest root DC and a domain-joined management VM. After deployment,
  run Initialize-TestLabDomain.ps1 on the management VM (or from your workstation
  with RSAT, targeting the lab domain).

  Requires: Windows with Hyper-V, AutomatedLab module, ~16 GB RAM free.

.PARAMETER LabName
  AutomatedLab lab name.

.PARAMETER DomainName
  DNS domain name for the new forest.

.PARAMETER AdminPassword
  Domain Administrator password (SecureString or plain string).

.EXAMPLE
  .\New-AutomatedLabTestDomain.ps1

.NOTES
  See https://automatedlab.org/ for module installation and troubleshooting.
#>

[CmdletBinding()]
param(
  [string]$LabName = 'ScriptTestLab',
  [string]$DomainName = 'lab.scripttest.local',
  [string]$AdminPassword = 'P@ssw0rd!Lab2026'
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name AutomatedLab)) {
  throw 'Install-Module AutomatedLab -Scope CurrentUser'
}
Import-Module AutomatedLab -ErrorAction Stop

$secureAdmin = if ($AdminPassword -is [securestring]) { $AdminPassword } else { ConvertTo-SecureString $AdminPassword -AsPlainText -Force }

if (Get-Lab -Name $LabName -ErrorAction SilentlyContinue) {
  Write-Host "Lab '$LabName' already exists. Import with: Import-Lab -Name $LabName" -ForegroundColor Yellow
  return
}

$netbios = ($DomainName.Split('.')[0]).ToUpper()
if ($netbios.Length -gt 15) {
  $netbios = $netbios.Substring(0, 15)
}

$labSources = if ($env:AUTOMATED_LAB_SOURCES) { Get-LabSources -Path $env:AUTOMATED_LAB_SOURCES } else { Get-LabSources }

New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV -VmPath (Join-Path $labSources ISOs '..\VMs') -ErrorAction Stop

Add-LabDomainDefinition -Name $DomainName -NetbiosName $netbios -ForestFunctionalLevel WinThreshold -DomainFunctionalLevel WinThreshold -InstallationCredential (New-Object System.Management.Automation.PSCredential ('Administrator', $secureAdmin))

Add-LabIsoDefinition -Name 'WinServer2022' -Path (Join-Path $labSources ISOs 'Win2022_German_x64.iso') -ErrorAction SilentlyContinue
Add-LabIsoDefinition -Name 'Win11' -Path (Join-Path $labSources ISOs 'Win11_Eval_x64.iso') -ErrorAction SilentlyContinue

$osServer = if (Get-LabAvailableOperatingSystem -Path $labSources.FullName | Where-Object { $_.OperatingSystemName -like '*Server*2022*' }) {
  (Get-LabAvailableOperatingSystem | Where-Object { $_.OperatingSystemName -like '*Server*2022*' } | Select-Object -First 1).OperatingSystemName
} else {
  'Windows Server 2022 Datacenter Evaluation'
}

$osClient = if (Get-LabAvailableOperatingSystem | Where-Object { $_.OperatingSystemName -like '*Windows 11*' }) {
  (Get-LabAvailableOperatingSystem | Where-Object { $_.OperatingSystemName -like '*Windows 11*' } | Select-Object -First 1).OperatingSystemName
} else {
  'Windows 11 Pro'
}

Add-LabMachineDefinition -Name DC1 -Roles RootDC -OperatingSystem $osServer -Memory 4GB -Processors 2
Add-LabMachineDefinition -Name MGMT1 -Roles Client -OperatingSystem $osClient -Memory 4GB -Processors 2

Install-Lab -ErrorAction Stop

Write-Host ''
Write-Host "Lab '$LabName' deployed. Domain: $DomainName" -ForegroundColor Green
Write-Host 'On MGMT1 (or RSAT workstation), run:' -ForegroundColor Green
Write-Host "  .\Initialize-TestLabDomain.ps1 -DomainDnsName $DomainName"
