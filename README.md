# PowerShell Scripts (Security & IT Ops)

A curated set of PowerShell scripts for Microsoft 365, Entra ID (Azure AD), Microsoft Defender, Exchange Online, and on‑prem Active Directory. Everything is written to be **portable**, **parameterized**, and **safe to adapt** to your environment.

> **Repo goals**
> - Clear categories and guardrails (warnings where risky)
> - No hard‑coded secrets; support for secure auth (Graph/EXO), env vars, or SecretManagement
> - Runnable examples and sensible defaults

> **F5 / load balancing:** I no longer work with F5. Any F5-related scripts that may appear in history or forks are **not maintained** and will **not** receive updates.

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

# Connect to core services (modern auth only — see Exchange Online auth standard below)
Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All","UserAuthenticationMethod.Read.All"
Connect-ExchangeOnline -UserPrincipalName admin@contoso.onmicrosoft.com
```

---

## Exchange Online auth standard (MC1248389)

Microsoft is retiring `-Credential` on `Connect-ExchangeOnline` and `Connect-IPPSSession` in Exchange Online PowerShell module versions released beginning **December 2026** ([MC1248389](https://msmessagecenter.com/MC1248389)). Do **not** pass username/password via `-Credential` for EXO or Security & Compliance PowerShell.

| Scenario | Use this instead |
|---|---|
| Interactive admin | `Connect-ExchangeOnline -UserPrincipalName <upn>` (modern auth + MFA) |
| Unattended outside Azure | App-only certificate: `-AppId`, `-CertificateThumbprint`/`-Certificate`/`-CertificateFilePath`, `-Organization` |
| Unattended in Azure | `-ManagedIdentity -Organization <tenant>.onmicrosoft.com` |

On-prem Exchange `New-PSSession -Credential` (Kerberos/Basic to local servers) is unaffected.

---

## 📚 Script Catalog

### `ActiveDirectory/`

- **[Get-ADPasswordExpiryReport.ps1](ActiveDirectory/Get-ADPasswordExpiryReport.ps1)** — Report AD users and their password expiration status (requires RSAT/AD module).
- **[Set-ADPasswordsNeverExpire.ps1](ActiveDirectory/Set-ADPasswordsNeverExpire.ps1)** — Set PasswordNeverExpires on every enabled AD user (danger: overrides domain password policy).
- **[Invoke-LapsPasswordReset.ps1](ActiveDirectory/Invoke-LapsPasswordReset.ps1)** — Reset LAPS passwords for computers in an OU or from a CSV, and write results to CSV.
- **[Invoke-AADConnectSync.ps1](ActiveDirectory/Invoke-AADConnectSync.ps1)** — Remotely trigger an Azure AD Connect sync cycle (Delta or Initial) and show scheduler status.
- **[GPO-Audit-Master.ps1](ActiveDirectory/GPO-Audit-Master.ps1)** — Export, flatten, search, and compare GPOs (XML, CSV, registry snapshots). Omit `-Mode` for the GUI.
- **[AD-GPO-Audit-Master.ps1](ActiveDirectory/AD-GPO-Audit-Master.ps1)** — Same GPO workflow, plus duplicate-user and duplicate-group audits. Omit `-Mode` for the GUI.
- **[Invoke-AfterHoursGpoPolicyAudit.ps1](ActiveDirectory/Invoke-AfterHoursGpoPolicyAudit.ps1)** — After-hours baseline audit: download Microsoft SCT and NIST GPO templates, compare them to linked GPOs, and write a risk-review CSV. Needs RSAT and internet access for the template download. Optional guards refuse to run during work hours or from a work network.

### `Entra-Graph-MFA/`

- **[Export-MFAStatusReport.ps1](Entra-Graph-MFA/Export-MFAStatusReport.ps1)** — Export user created date, last sign-in, and MFA status using Microsoft Graph.
- **[Get-MFAUserReport-Graph.ps1](Entra-Graph-MFA/Get-MFAUserReport-Graph.ps1)** — Enumerate user MFA methods/status via Graph SDK (no hard-coded creds).
- **[New-EntraCustomRole-TAPAssigner.ps1](Entra-Graph-MFA/New-EntraCustomRole-TAPAssigner.ps1)** — Create a least-privilege custom role for assigning Temporary Access Pass.

### `Defender/`

- **[Export-DefenderDevicesAndVulnerabilities.ps1](Defender/Export-DefenderDevicesAndVulnerabilities.ps1)** — Export Defender for Endpoint devices and their vulnerabilities. Defaults to Commercial; use `-Cloud GCCH` for GCC High.
- **[Get-DefenderMachinesWithSubnets.ps1](Defender/Get-DefenderMachinesWithSubnets.ps1)** — Map Defender device IPs onto a subnet table. The built-in map is a sample (`Example Subnet 1`–`4` on documentation ranges); edit it for your network. Defaults to Commercial; use `-Cloud GCCH` for GCC High.
- **[Get-DefenderStatusADComputers.ps1](Defender/Get-DefenderStatusADComputers.ps1)** — Collect Defender Antivirus status from AD computers over WinRM (`Get-MpComputerStatus`) and export CSV.
- **[DefenderUserEmailSummary.ps1](Defender/DefenderUserEmailSummary.ps1)** — Build a daily HTML mail summary from Defender Advanced Hunting, plus a weekly rollup when the report day is Sunday. The weekly report includes a 7-day recipient validation table. Optional SharePoint upload. Default domains are placeholders (`example.com` / `example.net`); set them for your tenant.

### `Exchange-Compliance/`

- **[Invoke-ComplianceSearchAndPurge.ps1](Exchange-Compliance/Invoke-ComplianceSearchAndPurge.ps1)** — Run Content Search + Purge in Microsoft 365 (eDiscovery/Compliance).
- **[Remove-QuarantineMessagesBySender.ps1](Exchange-Compliance/Remove-QuarantineMessagesBySender.ps1)** — Permanently delete every quarantined message from a sender. This does not release mail. Follow the Exchange Online auth standard above.

### `Networking/`

- **[Sort-ComputersBySubnet.ps1](Networking/Sort-ComputersBySubnet.ps1)** — Match computer IPs from a CSV to a subnet CSV. Matching uses a /24 mask.

### `Registry/`

- **[Check-RemoteRegistryValue.ps1](Registry/Check-RemoteRegistryValue.ps1)** — Read one registry value from remote computers over WinRM. Edit the server list in the script before you run it.

### `Vulnerabilities/`

- **[Build-CVELocalRepository.ps1](Vulnerabilities/Build-CVELocalRepository.ps1)** — Download CVEs from NVD API into rolling CSVs (handles rate limits).

### `Modules/`

- **[Get-Secret.ps1](Modules/Private/Get-Secret.ps1)** — Private helper function for retrieving secrets used by other scripts.


---

## 🔄 Naming & Headers

All scripts should start with a comment‑based help block including: **SYNOPSIS**, **DESCRIPTION**, **PARAMETERS**, **EXAMPLES**, **REQUIREMENTS**, **WARNINGS**, and **NOTES**. Keep names in **Verb‑Noun** form and prefer **imperative verbs** (`Get`, `Export`, `Invoke`, `Set`, `New`, `Remove`, `Sort`).

---

## ☁️ GCC vs Commercial Notes

Where relevant (e.g., Defender endpoints or Graph audiences), include a `-Cloud "Commercial|GCCH"` parameter with sensible defaults.

---

## 🧪 Quality Gates

Pester tests sit next to the scripts they cover (`*.Tests.ps1`). They parse and exercise logic locally; they do not call a live tenant.

```powershell
# From the repo root, with PowerShell 7 and Pester 5+ installed
Invoke-Pester -Path .
Invoke-ScriptAnalyzer -Path . -Recurse -Severity Error,Warning
```

This repo does not currently include a GitHub Actions workflow. Run those checks before you open a pull request. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 📄 Project docs

- [CONTRIBUTING.md](CONTRIBUTING.md) — how to report problems and open pull requests
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [SECURITY.md](SECURITY.md) — how to report a vulnerability privately
- [LICENSE](LICENSE) — MIT License

---
