# Script Test Lab (Active Directory)

Lab-only domain objects for exercising scripts in this repo: **users**, **OUs**, **computers**, and **GPOs** with both NIST-aligned and **intentionally weak** settings.

> **Warning:** Default passwords and insecure GPOs are for isolated labs only. Never deploy this configuration to production or corporate networks.

## What you get

| Object | Purpose |
|--------|---------|
| OUs `Workstations`, `Servers`, `Users` (IT, Sales, Finance, **Legacy**) | OU filters in `GPO-Audit-Master.ps1` (`SearchOuNameFilter`) |
| Users `alice.it`, `bob.sales`, … | Password expiry / `PasswordNeverExpires` reports |
| Users in **Legacy** (`svc_backup`, `jim.legacy`, …) | Accounts that violate password hygiene |
| GPO `LAB - SEC Insecure Workstations` | Weak password policy, LM/NTLM, no SMB signing, firewall off |
| GPO `LAB - Baseline Compliant Workstations` | Contrast baseline for diffs |
| GPO `CIS - Dummy Baseline Name` | Unlinked; test `IncludeGpoNameRegex '^(CIS\|STIG)'` |

Manifest: [config/lab-manifest.json](config/lab-manifest.json)

## Option A — Windows Server / existing domain (recommended for GPO scripts)

Full **Group Policy** support (`Get-GPO`, `Get-GPOReport`, `GPO-Audit-Master.ps1`).

1. Promote a VM to DC (or use an existing lab forest), e.g. DNS name `lab.scripttest.local`.
2. On a domain-joined machine with **RSAT** (Group Policy + Active Directory modules):

```powershell
cd <repo>\TestLab
.\Initialize-TestLabDomain.ps1
# Preview only:
.\Initialize-TestLabDomain.ps1 -WhatIf
```

3. Point repo scripts at the lab:

```powershell
.\ActiveDirectory\GPO-Audit-Master.ps1 -Mode SearchSettings -SearchText "LmCompatibility" -DomainDnsName lab.scripttest.local
.\ActiveDirectory\Get-ADPasswordExpiryReport.ps1 -OutputCsv C:\Temp\lab-password-expiry.csv
```

Default lab user password: `P@ssw0rd!Lab2026` (override with `-DefaultUserPassword`).

## Option B — AutomatedLab (Hyper-V lab from scratch)

On **Windows 10/11 Pro or Server** with Hyper-V and [AutomatedLab](https://automatedlab.org/):

```powershell
Install-Module AutomatedLab -Force
cd <repo>\TestLab
.\New-AutomatedLabTestDomain.ps1
# After VMs are up, on the mgmt machine:
.\Initialize-TestLabDomain.ps1 -DomainDnsName lab.scripttest.local
```

## Option C — Docker Samba AD (LDAP/users; limited GPO)

For Linux hosts or quick LDAP tests without Windows Server:

```bash
cd TestLab
export LAB_ADMIN_PASSWORD='P@ssw0rd!Lab2026'
docker compose up -d
docker compose exec dc1 /bootstrap/seed-samba-lab.sh
```

Configure clients to use the container DNS. For **full GPO audit workflows**, still run `Initialize-TestLabDomain.ps1` from a Windows RSAT host joined to the Samba domain (or use Option A).

## Intentional NIST gaps (for script testing)

The insecure GPOs deliberately include settings that conflict with common NIST / STIG expectations, for example:

- Minimum password length **7**, complexity **off**
- **LM / NTLMv1** compatibility (`LmCompatibilityLevel = 1`)
- **SMB signing** not required
- **Windows Firewall** disabled via policy
- **Legacy** OU: anonymous enumeration, weak LSA restrictions

Use these only to validate that your audit scripts **detect** misconfiguration.

## Files

| Path | Role |
|------|------|
| `Initialize-TestLabDomain.ps1` | Main seed script (OUs, users, GPOs) |
| `New-AutomatedLabTestDomain.ps1` | Optional Hyper-V lab provisioner |
| `config/lab-manifest.json` | Machine-readable lab inventory |
| `gpo-templates/*.inf` | `GptTmpl.inf` fragments for weak security settings |
| `docker-compose.yml` | Samba AD DC container |
| `bootstrap/seed-samba-lab.sh` | Samba user/OU seeding |
