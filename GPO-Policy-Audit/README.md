# GPO Policy Audit Tool

Compare your domain Group Policy Objects against NIST/DISA STIG and Microsoft Security Compliance Toolkit baselines. Identify gaps, review them interactively, and export remediated GPO backups ready for import.

---

## What It Does

| Step | Description |
|------|-------------|
| **1. Download Baselines** | Fetches NIST/DISA STIG GPO packages and Microsoft SCT baselines. Caches locally so subsequent runs skip the download. |
| **2. Merge Baselines** | Combines both baseline sources into a single "Master Template". When NIST and Microsoft disagree on a setting, the user picks the winner (or set a blanket rule). |
| **3. Pull GPO Hierarchy** | Enumerates GPOs from your AD domain and organises them by OU, preserving parent/child nesting exactly as it appears in Group Policy Management. |
| **4. Compare & Diff** | Diffs the master template against each GPO (and the effective settings per OU when child GPOs layer on top). Reports mismatches, missing settings, and extras. |
| **5. Interactive Review** | Walk through each difference: accept it for remediation or deselect it as "acceptable risk" with a comment explaining why. |
| **6. Export GPOs** | Generates GPO backup folders (GptTmpl.inf, audit.csv, etc.) plus a ready-to-run `Import-RemediatedGPOs.ps1` script to create and link the GPOs in your domain. |

---

## Prerequisites

- **PowerShell 5.1+** (Windows PowerShell or PowerShell 7 on Windows)
- **RSAT: Group Policy Management** — for `Get-GPO`, `Get-GPOReport`, `Import-GPO`
- **RSAT: Active Directory DS Tools** — for `Get-ADDomain`, `Get-ADOrganizationalUnit`
- **Internet access** — for downloading baselines (Step 1 only; offline after first run)
- **Domain credentials** with read access to Group Policy and AD objects

---

## Quick Start

```powershell
# Full end-to-end audit (interactive)
.\Invoke-GPOPolicyAudit.ps1 -Mode Full -OutputDir C:\GPO-Audit

# Just download and cache baselines
.\Invoke-GPOPolicyAudit.ps1 -Mode DownloadBaselines -OutputDir C:\GPO-Audit

# Merge baselines, Microsoft wins all conflicts
.\Invoke-GPOPolicyAudit.ps1 -Mode MergeBaselines -ConflictResolution MicrosoftWins

# Compare only certain GPOs
.\Invoke-GPOPolicyAudit.ps1 -Mode CompareOnly -GpoNameRegex "^SEC -"

# Review a previous diff
.\Invoke-GPOPolicyAudit.ps1 -Mode ReviewOnly -OutputDir C:\GPO-Audit

# Export remediated GPOs from a prior review
.\Invoke-GPOPolicyAudit.ps1 -Mode ExportOnly -OutputDir C:\GPO-Audit
```

---

## Run Modes

| Mode | Steps Executed | Domain Required |
|------|---------------|-----------------|
| `Full` | 1 → 2 → 3 → 4 → 5 → 6 | Yes |
| `DownloadBaselines` | 1 | No |
| `MergeBaselines` | 1 → 2 | No |
| `PullHierarchy` | 3 | Yes |
| `CompareOnly` | 1 → 2 → 3 → 4 | Yes |
| `ReviewOnly` | 5 (loads prior diff) | No |
| `ExportOnly` | 6 (loads prior review) | No |

---

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Mode` | String | `Full` | Workflow to execute (see table above). |
| `-OutputDir` | String | `.\GPO-Policy-Audit-Output` | Root folder for all generated output. |
| `-DomainDnsName` | String | *(auto-detect)* | Target AD domain. |
| `-BaselineRoot` | String | `<OutputDir>\Baselines` | Where baselines are cached. |
| `-MicrosoftProducts` | String[] | `Windows11, WindowsServer2025, WindowsServer2022` | Which Microsoft SCT baselines to download. |
| `-StigPackageUrl` | String | *(latest DISA package)* | Override STIG GPO ZIP URL. |
| `-ConflictResolution` | String | `Interactive` | `MicrosoftWins`, `StigWins`, or `Interactive`. |
| `-GpoNameFilter` | String[] | *(all)* | Only audit GPOs with these exact names. |
| `-GpoNameRegex` | String | *(all)* | Only audit GPOs matching this regex. |
| `-Force` | Switch | | Re-download baselines even if cached. |
| `-SkipDomainCheck` | Switch | | Skip domain connectivity (for testing). |

---

## Output Structure

```
GPO-Policy-Audit-Output/
├── Baselines/
│   ├── Microsoft/
│   │   ├── Windows11/           # Extracted SCT baseline
│   │   ├── WindowsServer2025/
│   │   └── baseline-manifest.json
│   └── NIST_STIG/
│       ├── GPO_Package/         # Extracted STIG GPOs
│       └── baseline-manifest.json
├── MergedTemplate/
│   ├── MasterTemplate.csv       # Combined baseline (all settings)
│   ├── MasterTemplate.json
│   └── ConflictReport.csv       # Which settings conflicted & who won
├── Hierarchy/
│   ├── GPO_Hierarchy.csv        # Flat table of OU→GPO links
│   ├── GPO_Hierarchy.json
│   └── GpoReports/              # Per-GPO XML reports
├── DiffReports/
│   ├── DiffReport.csv           # Full diff: master vs every GPO
│   ├── DiffReport.json
│   ├── DiffReviewReport.html    # Color-coded HTML review report
│   └── ReviewManifest.json      # Selections + risk comments (reloadable)
└── ExportedGPOs/
    ├── REMEDIATION - GPO_Name/  # GPO backup ready for Import-GPO
    │   └── {guid}/
    │       ├── Backup.xml
    │       ├── bkupInfo.xml
    │       └── DomainSysvol/GPO/Machine/...
    ├── Import-RemediatedGPOs.ps1   # One-click import script
    └── RiskAcceptanceReport.csv    # Deselected items with comments
```

---

## Modules

| Module | Purpose |
|--------|---------|
| `PolicyParser.psm1` | Parse `.pol`, `.inf`, `audit.csv`, GPP XML, and GPO report XML into a common object model. |
| `BaselineDownloader.psm1` | Download + cache Microsoft SCT and DISA STIG GPO packages with manifest tracking. |
| `BaselineMerger.psm1` | Merge two baseline sets with configurable conflict resolution (interactive, Microsoft-wins, STIG-wins). |
| `GPOTreeBuilder.psm1` | Pull GPOs from AD, resolve OU links, build parent/child hierarchy. |
| `GPOComparer.psm1` | Diff engine: master template vs individual GPOs and per-OU effective settings. |
| `DiffReviewer.psm1` | Interactive + batch review with accept/deselect/comment per setting. HTML report export. |
| `GPOExporter.psm1` | Generate GPO backup folders + import script from reviewed diffs. |

---

## Conflict Resolution (Step 2)

When NIST and Microsoft define the same setting with different values:

- **Interactive** (default): prompted for each conflict with both values shown.
- **MicrosoftWins**: Microsoft's value always wins.
- **StigWins**: NIST/STIG's value always wins.

Non-conflicting settings from both sources are always included in the master template.

---

## Diff Review (Step 5)

Each difference is presented with:
- Status icon: `~` mismatch, `-` missing in GPO, `+` extra in GPO
- Baseline and GPO values side by side
- Current selection state (remediate vs. risk-accepted)

Commands during review:
- `A` — Accept (selected for remediation)
- `D` — Deselect (mark as acceptable risk, enter reason)
- `C` — Add/edit a comment
- `S` — Skip to next
- `AA` — Accept all remaining
- `DA` — Deselect all remaining
- `AC` — Accept all in a specific category
- `Q` — Quit review early

The review state is saved to `ReviewManifest.json` and can be reloaded with `-Mode ReviewOnly`.

---

## Importing Remediated GPOs (Step 6)

After export, run the generated script on a domain-joined machine with RSAT:

```powershell
# Preview (WhatIf)
.\ExportedGPOs\Import-RemediatedGPOs.ps1 -WhatIf

# Import and link to a specific OU
.\ExportedGPOs\Import-RemediatedGPOs.ps1 -LinkToOU "OU=Servers,DC=contoso,DC=com"

# Import targeting a different domain
.\ExportedGPOs\Import-RemediatedGPOs.ps1 -DomainDnsName "child.contoso.com"
```

---

## Baseline Sources

| Source | URL | Package |
|--------|-----|---------|
| Microsoft SCT | https://aka.ms/UpdateBaselineSCT | Windows 11 24H2, Server 2025/2022/2019, Edge, M365 Apps |
| DISA STIG GPOs | https://public.cyber.mil/stigs/gpo/ | DoD STIG GPO Package (all Windows OS) |
| NIST NCP Checklists | https://ncp.nist.gov | XCCDF, SCAP, GPO formats per OS |

---

## License

MIT — see [LICENSE](../LICENSE).
