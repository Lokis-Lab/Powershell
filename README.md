# PowerShell Scripts (Security & IT Ops)

A curated set of PowerShell scripts for Microsoft 365, Entra ID (Azure AD), Microsoft Defender, Exchange Online, and on‑prem Active Directory. Everything is written to be **portable**, **parameterized**, and **safe to adapt** to your environment.

> **Repo goals**
> - Clear categories and guardrails (warnings where risky)
> - No hard‑coded secrets; support for secure auth (Graph/EXO), env vars, or SecretManagement
> - Runnable examples and sensible defaults

---

## 🧰 Prerequisites (per area)

- **Active Directory**: RSAT tools / AD PowerShell module; domain rights as needed
- **Entra / Graph / MFA**: `Microsoft.Graph` PowerShell SDK (v2+); delegated or app permissions with admin consent
- **Defender**: Microsoft 365 Defender / Security Graph API permissions; consider GCC vs Commercial cloud selection where applicable
- **Exchange / Compliance**: `ExchangeOnlineManagement` module; eDiscovery/Compliance permissions
- **Networking & Registry**: Run from an admin PowerShell on a management host with network RPC/SMB access

---

## 🚀 Quick Start

```powershell
# Install core modules (once, elevated)
Install-Module Microsoft.Graph -Scope AllUsers -Force
Install-Module ExchangeOnlineManagement -Scope AllUsers -Force
Install-Module ActiveDirectory -Force  # on a DC or with RSAT

# Connect to core services
Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All","UserAuthenticationMethod.Read.All"
Connect-ExchangeOnline
```

---

## 📚 Script Catalog

### `ActiveDirectory/`

- **[Invoke-GpoNistAudit.ps1](ActiveDirectory/Invoke-GpoNistAudit.ps1)** — Full NIST/Microsoft GPO compliance audit wizard (six-stage Windows Forms GUI).  Downloads the latest DISA STIG and Microsoft SCT baselines, merges them into a user-controlled Master Template, walks the AD OU/GPO tree, produces a colour-coded diff against every GPO, supports per-finding risk acceptance with free-text justification, and exports an HTML report, a PowerShell remediation script, and GPO backups ready for Import-GPO.  Runs headless with `-Mode RunAudit`.
- **[Get-ADPasswordExpiryReport.ps1](ActiveDirectory/Get-ADPasswordExpiryReport.ps1)** — Report AD users close to password expiry (requires RSAT/AD module).
- **[Set-ADPasswordsNeverExpire.ps1](ActiveDirectory/Set-ADPasswordsNeverExpire.ps1)** — Set PasswordNeverExpires for a list of AD users (danger, read warnings).
- **[Invoke-LapsPasswordReset.ps1](ActiveDirectory/Invoke-LapsPasswordReset.ps1)** — Reset LAPS password for a computer or OU (writes to secure log).
- **[Invoke-AADConnectSync.ps1](ActiveDirectory/Invoke-AADConnectSync.ps1)** - Remotely triggers an Azure AD Connect sync cycle (Delta or Initial)
- **[GPO-Audit-Master.ps1](ActiveDirectory/GPO-Audit-Master.ps1)** — Export, flatten, and compare GPOs (XML exports, CSV flattens, and registry snapshot/compare helpers).

### `Entra-Graph-MFA/`

- **[Export-MFAStatusReport.ps1](Entra-Graph-MFA/Export-MFAStatusReport.ps1)** — Export user created date, last sign-in, and MFA status using Microsoft Graph.
- **[Get-MFAUserReport-Graph.ps1](Entra-Graph-MFA/Get-MFAUserReport-Graph.ps1)** — Enumerate user MFA methods/status via Graph SDK (no hard-coded creds).
- **[New-EntraCustomRole-TAPAssigner.ps1](Entra-Graph-MFA/New-EntraCustomRole-TAPAssigner.ps1)** — Create a least-privilege custom role for assigning Temporary Access Pass.

### `Defender/`

- **[Export-DefenderDevicesAndVulnerabilities.ps1](Defender/Export-DefenderDevicesAndVulnerabilities.ps1)** — Export Defender device inventory and vulnerability list via Graph/Sec API.
- **[Get-DefenderMachinesWithSubnets.ps1](Defender/Get-DefenderMachinesWithSubnets.ps1)** — Join Defender devices to subnets for network-aware reporting.
- **[Get-DefenderStatusADComputers.ps1](Defender/Get-DefenderStatusADComputers.ps1)** — Correlate AD computers with Defender status (healthy/at risk).
- **[DefenderInternalUsersSummary.ps1](Defender/DefenderInternalUsersSummary.ps1)** - Uses Microsoft Defender Advanced Hunting API to generate an HTML "Internal Users Summary" report for a given calendar day

### `Exchange-Compliance/`

- **[Invoke-ComplianceSearchAndPurge.ps1](Exchange-Compliance/Invoke-ComplianceSearchAndPurge.ps1)** — Run Content Search + Purge in Microsoft 365 (eDiscovery/Compliance).
- **[Remove-QuarantineMessagesBySender.ps1](Exchange-Compliance/Remove-QuarantineMessagesBySender.ps1)** — Bulk-release or remove quarantined messages by sender in EXO.

### `Networking/`

- **[Sort-ComputersBySubnet.ps1](Networking/Sort-ComputersBySubnet.ps1)** — Sort computer list into subnets using CIDR ranges.

### `Registry/`

- **[Check-RemoteRegistryValue.ps1](Registry/Check-RemoteRegistryValue.ps1)** — Query a remote registry value (no WinRM required).

### `Vulnerabilities/`

- **[Build-CVELocalRepository.ps1](Vulnerabilities/Build-CVELocalRepository.ps1)** — Download CVEs from NVD API into rolling CSVs (handles rate limits).


---

## NIST / Microsoft GPO Compliance Audit — Quick Reference

[`Invoke-GpoNistAudit.ps1`](ActiveDirectory/Invoke-GpoNistAudit.ps1) is the flagship tool in this repo.  It covers the complete GPO audit lifecycle in six stages, each represented as a tab in an interactive Windows Forms wizard.

### Prerequisites

```powershell
# RSAT: Group Policy Management + Active Directory (elevated PowerShell)
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

### Usage — Interactive wizard (recommended)

```powershell
# Launch the six-tab wizard (warns if before 5 PM)
.\ActiveDirectory\Invoke-GpoNistAudit.ps1

# Target a specific domain
.\ActiveDirectory\Invoke-GpoNistAudit.ps1 -DomainDnsName contoso.com

# Suppress after-hours check
.\ActiveDirectory\Invoke-GpoNistAudit.ps1 -SkipAfterHoursCheck
```

### Usage — Headless / automation

```powershell
# Full pipeline, no GUI
.\ActiveDirectory\Invoke-GpoNistAudit.ps1 -Mode RunAudit -OutDir C:\Audits\2026-Q2

# Step 1 only: refresh baseline downloads
.\ActiveDirectory\Invoke-GpoNistAudit.ps1 -Mode DownloadBaselines

# Step 3 only: export domain GPO XMLs
.\ActiveDirectory\Invoke-GpoNistAudit.ps1 -Mode PullDomainGpos -DomainDnsName corp.example.com
```

### Wizard stages

| Tab | What it does |
|-----|-------------|
| Step 1: Download Baselines | Fetches DISA STIG GPO package and Microsoft SCT (Windows 11 + Server 2025).  Caches locally; skips if already present. |
| Step 2: Build Master Template | Parses all baseline GPO XMLs, flags conflicting settings, lets you choose the winning source per conflict, then writes `MasterTemplate_<timestamp>.csv`. |
| Step 3: Pull Domain GPOs | Connects to AD, walks the full OU tree, exports every GPO via `Get-GPOReport`, and renders the hierarchy in a tree view matching GPMC layout. |
| Step 4: Compare & Contrast | Diffs each GPO (and its OU children) against the Master Template.  Missing, mismatch, and extra settings are colour-coded (red / orange / purple). |
| Step 5: Risk Acceptance | Un-check any finding to mark it as an accepted risk; enter a free-text justification.  Accepted rows are excluded from the exported remediation artefacts. |
| Step 6: Export | Writes an HTML compliance report, a `Remediation_<timestamp>.ps1` with `Set-GPRegistryValue` stubs, and `Backup-GPO` archives for all affected GPOs. |

### Output folder layout

```
<OutDir>\
  Baselines\                  # Extracted DISA + MS baseline ZIPs
  Templates\
    MasterTemplate_*.csv      # Merged baseline settings
    ConflictLog_*.csv         # Conflicts and resolution choices
  DomainGPOs\                 # Get-GPOReport XML for every domain GPO
  Reports\
    GpoAuditReport_*.html     # Colour-coded compliance report
    Remediation_*.ps1         # Set-GPRegistryValue remediation stubs
  GpoBackups\                 # Backup-GPO archives (importable via Import-GPO)
```

---

## 🔄 Naming & Headers

All scripts should start with a comment‑based help block including: **SYNOPSIS**, **DESCRIPTION**, **PARAMETERS**, **EXAMPLES**, **REQUIREMENTS**, **WARNINGS**, and **NOTES**. Keep names in **Verb‑Noun** form and prefer **imperative verbs** (`Get`, `Export`, `Invoke`, `Set`, `New`, `Remove`, `Sort`).

---

## ☁️ GCC vs Commercial Notes

Where relevant (e.g., Defender endpoints or Graph audiences), include a `-Cloud "Commercial|GCCH"` parameter with sensible defaults.

---

## 🧪 Quality Gates

- **PSScriptAnalyzer**: style & safety checks
- **Pester**: unit tests for core functions (mock external calls)
- **Markdown lint**: keep docs readable
- **CI**: GitHub Actions to run all of the above on PRs

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---
