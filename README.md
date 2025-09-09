# PowerShell Scripts (Security & IT Ops)

A curated set of PowerShell scripts for Microsoft 365, Entra ID (Azure AD), Microsoft Defender, Exchange Online, and on‑prem Active Directory. Everything is written to be **portable**, **parameterized**, and **safe to adapt** to your environment.

> **Repo goals**
> - Clear categories and guardrails (warnings where risky)
> - No hard‑coded secrets; support for secure auth (Graph/EXO), env vars, or SecretManagement
> - Runnable examples and sensible defaults

---

## 📁 Recommended Folder Structure

```
/ActiveDirectory
/Entra-Graph-MFA
/Defender
/Exchange-Compliance
/Networking
/Registry
/Vulnerabilities
/README.md
```

Organize scripts by the primary tech surface area. If a script spans two areas, place it where you’d look first (and cross‑link in its header).

---

## 🔐 Secret Hygiene (scan summary)

This README was generated with a quick heuristic scan over the uploaded ZIP to flag obvious secrets (API keys, client secrets, hardcoded passwords, tokens, private keys).

- **Potential secrets found:** 0
- **Verdict:** No hard‑coded secrets detected. Several scripts accept parameters like `-ClientSecret` or `-ApiKey`, which is expected. Use **secure input** methods below.

**Secure input patterns**
- Prefer `Connect-ExchangeOnline` / `Connect-MgGraph` with device code or interactive login
- For app auth: store secrets in an **Azure Key Vault**, **Windows Credential Manager**, or **Microsoft.PowerShell.SecretManagement**
- Support env vars where useful: e.g. `$env:NVD_API_KEY`, `$env:GRAPH_CLIENT_ID`, `$env:GRAPH_TENANT_ID`, `$env:GRAPH_CLIENT_SECRET`
- Avoid committing real tenant IDs, UPNs, or domain names

> If you want, I can add a small `Private/` module to centralize secret retrieval with fallback to parameters/env vars.

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

- **Get-ADPasswordExpiryReport.ps1** — Report AD users close to password expiry (requires RSAT/AD module).
- **Set-ADPasswordsNeverExpire.ps1** — Set PasswordNeverExpires for a list of AD users (danger, read warnings).
- **Invoke-LapsPasswordReset.ps1** — Reset LAPS password for a computer or OU (writes to secure log).
- **Invoke-AADConnectSync.ps1** - Remotely triggers an Azure AD Connect sync cycle (Delta or Initial)

### `Entra-Graph-MFA/`

- **Export-MFAStatusReport.ps1** — Export user created date, last sign-in, and MFA status using Microsoft Graph.
- **Get-MFAUserReport-Graph.ps1** — Enumerate user MFA methods/status via Graph SDK (no hard-coded creds).
- **New-EntraCustomRole-TAPAssigner.ps1** — Create a least-privilege custom role for assigning Temporary Access Pass.

### `Defender/`

- **Export-DefenderDevicesAndVulnerabilities.ps1** — Export Defender device inventory and vulnerability list via Graph/Sec API.
- **Get-DefenderMachinesWithSubnets.ps1** — Join Defender devices to subnets for network-aware reporting.
- **Get-DefenderStatusADComputers.ps1** — Correlate AD computers with Defender status (healthy/at risk).

### `Exchange-Compliance/`

- **Invoke-ComplianceSearchAndPurge.ps1** — Run Content Search + Purge in Microsoft 365 (eDiscovery/Compliance).
- **Remove-QuarantineMessagesBySender.ps1** — Bulk-release or remove quarantined messages by sender in EXO.

### `Networking/`

- **Sort-ComputersBySubnet.ps1** — Sort computer list into subnets using CIDR ranges.

### `Registry/`

- **Script to Check-RemoteRegistryValue.ps1** — Query a remote registry value (no WinRM required).

### `Vulnerabilities/`

- **Build-CVELocalRepository.ps1** — Download CVEs from NVD API into rolling CSVs (handles rate limits).


---

## 🔄 Naming & Headers

All scripts should start with a comment‑based help block including: **SYNOPSIS**, **DESCRIPTION**, **PARAMETERS**, **EXAMPLES**, **REQUIREMENTS**, **WARNINGS**, and **NOTES**. Keep names in **Verb‑Noun** form and prefer **imperative verbs** (`Get`, `Export`, `Invoke`, `Set`, `New`, `Remove`, `Sort`).

If you want, we can add a `scripts/Generate-ReadmeIndex.ps1` to auto‑index scripts by reading their help headers.

---

## ☁️ GCC vs Commercial Notes

Where relevant (e.g., Defender endpoints or Graph audiences), include a `-Cloud "Commercial|GCCH"` parameter with sensible defaults. Document any differing endpoints or throttling rules (e.g., NVD API 50 req / 30s).

---

## 📦 Suggested Future Structure

```
/ActiveDirectory
/Defender
/Entra-Graph-MFA
/Exchange-Compliance
/Networking
/Registry
/Vulnerabilities
/Modules
  /Private   # secret helpers, input validation, logging
  /Public    # functions shared by multiple scripts
/tests       # Pester tests for critical logic
/.github
  /workflows # CI: PSScriptAnalyzer, Pester, markdown lint
```

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

## 🙋 Support

Open an issue or PR with bug reports, enhancements, or docs fixes. Include PowerShell version, cloud (Commercial/GCC), and module versions.
