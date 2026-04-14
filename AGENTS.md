# AGENTS.md

## Cursor Cloud specific instructions

### Overview

This repository is a collection of standalone PowerShell scripts (`.ps1`) for Microsoft 365 security and IT operations. There is no build step, no package manager lockfile, and no web application. The development toolchain consists of PowerShell 7, PSScriptAnalyzer (linting), and Pester (testing).

### Running the tools

| Task | Command |
|---|---|
| Lint all scripts | `pwsh -NoProfile -Command "Invoke-ScriptAnalyzer -Path /workspace -Recurse -Severity Error,Warning"` |
| Run Pester tests | `pwsh -NoProfile -Command "Invoke-Pester -Path /workspace"` (when `.Tests.ps1` files exist) |
| Run a single script | `pwsh -NoProfile -File /workspace/<Category>/<Script>.ps1 [params]` |

### Caveats

- Most scripts require live Microsoft 365 tenant credentials (Graph API, Exchange Online, Defender) and/or on-premises Active Directory. They cannot be fully exercised in this Linux VM without those services.
- The best candidates for local testing are `Networking/Sort-ComputersBySubnet.ps1` and `Vulnerabilities/Build-CVELocalRepository.ps1` (NVD API only needs internet and an optional API key).
- `Modules/Private/Get-Secret.ps1` has a known parse issue: `$env:$Name` on line 37 is not valid PowerShell syntax. This is a pre-existing repo issue.
- PSScriptAnalyzer reports ~147 warnings (mostly `PSAvoidUsingWriteHost` and `PSUseApprovedVerbs`); there are 0 errors.
