# AGENTS.md

## Cursor Cloud specific instructions

This is a **PowerShell script library** (not a traditional application with services). All 18 `.ps1` scripts target Microsoft 365 / Active Directory / Defender / Exchange Online environments. There are no web servers, databases, or containers to run.

### Runtime

- **PowerShell Core** (`pwsh`) is installed at system level via Microsoft's apt repository for Ubuntu 24.04.
- Most scripts require Windows-only modules (ActiveDirectory RSAT, GroupPolicy) or live Microsoft 365 tenant access, so **full end-to-end execution is not possible on Linux**. The `Networking/Sort-ComputersBySubnet.ps1` script is the exception — it runs entirely locally with CSV input/output and is the best candidate for integration testing.

### Linting

Run PSScriptAnalyzer across all scripts:

```bash
pwsh -NoProfile -Command "Get-ChildItem -Path '/workspace' -Recurse -Filter '*.ps1' | ForEach-Object { Invoke-ScriptAnalyzer -Path \$_.FullName }"
```

### Testing

- **Pester** (v5+) is installed but the repo has no `.Tests.ps1` files yet (README lists Pester as a quality gate).
- Run Pester when test files are added: `pwsh -NoProfile -Command "Invoke-Pester -Path '/workspace'"`

### Hello-world demo

To verify the environment works, run `Sort-ComputersBySubnet.ps1` with sample data:

```bash
pwsh -NoProfile -Command "& '/workspace/Networking/Sort-ComputersBySubnet.ps1' -ComputersFile '<computers.csv>' -SubnetsFile '<subnets.csv>' -OutputFile '/tmp/output.csv'"
```

### Key caveats

- Scripts that call `Connect-MgGraph`, `Connect-ExchangeOnline`, or use the `ActiveDirectory` module will fail on Linux without those modules and proper auth. Only `Sort-ComputersBySubnet.ps1` and `Build-CVELocalRepository.ps1` (with an NVD API key) can run on this platform.
- The `Modules/Private/Get-Secret.ps1` helper uses `$env:$Name` syntax which triggers a PSScriptAnalyzer warning; this is a known pattern that works at runtime but is unconventional.
