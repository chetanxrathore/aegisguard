# AegisGuard

**AegisGuard** is an open-source Windows security auditing tool written in PowerShell. It performs:
- **Compliance checks** aligned to **ISO 27001** and **NIST CSF**
- **Vulnerability assessment** (basic endpoint posture checks)
- **Safe pen-testing simulations** (non-destructive, no exploitation)
- Generates a **rich HTML report** with an **Executive Summary** and visuals

> ⚠️ AegisGuard is designed for defensive auditing and compliance validation. It does **not** exploit vulnerabilities or perform intrusive attacks.

---

## Features

- System, hardware, user-context inventory
- Security & compliance checks:
  - Firewall, RDP hardening, password policy, audit policy
  - SMBv1/signing, shares, null sessions
  - Windows Update health (robust hotfix date parsing)
  - PowerShell policy/logging (where available)
  - UAC, BitLocker, screen lock, event log sizing (depth dependent)
- Vulnerability assessment:
  - Common risky listening ports
  - Sensitive file ACL weakness signals
  - Basic framework/software version checks
- Pen test simulation:
  - Password pattern risk (simulation)
  - Share enumeration (safe)
  - Service privilege/permissions visibility (safe)

---

## Quick Start

### Requirements
- Windows 10/11 or Windows Server
- PowerShell 5.1+ (PowerShell 7 works too)
- **Run as Administrator** (recommended/required for full coverage)

### Run
```powershell
# From repo root:
powershell -ExecutionPolicy Bypass -File .\src\AegisGuard.ps1 -employee-id "EMP-10293"
```

### Recheck BitLocker after a change

Run the same control used by Standard and Comprehensive audits directly on the Windows endpoint. The command returns one PowerShell object and requires no employee ID.

```powershell
.\src\AegisGuard.ps1 -CheckId SEC-012 | Select-Object MountPoint, VolumeStatus, ProtectionStatus, Result, Details
```

For example, a fully encrypted system drive with protection off yields `FAIL`. After planned maintenance, rerun the command to verify that protection is back on and the result is `PASS`. A missing cmdlet or a denied query yields `UNKNOWN` with a reason. The HTML summary shows how many selected checks were assessed. An unknown BitLocker result reduces coverage and carries no score penalty.

### Testing from macOS or Linux

Push a branch or open a pull request to run **Windows audit tests** on GitHub Actions. Once the workflow is on the default branch, you can also select **Actions → Windows audit tests → Run workflow**. Select a job in the run to see the PowerShell version, scan progress, and test result.

The workflow exercises Windows PowerShell 5.1 and PowerShell 7 on Windows Server 2025, plus PowerShell 7 on Windows 11 Arm64. Each job tests BitLocker verdicts against known inputs, then runs a Comprehensive audit without the optional simulations. It verifies the Windows product name, all 17 posture results, and the report summary.

In **Actions → Windows audit tests**, open a run and select **Summary**. Each completed audit shows its pass count and a **View individual checks** table. Select **Open full HTML report** in the corresponding job summary for the inventory, evidence, and recommendations. The same HTML file is available under **Artifacts**, labeled by Windows image, PowerShell engine, and run attempt. Sign in to GitHub to access the artifact. If your browser downloads the file, open it locally.

On macOS or Linux with PowerShell installed, run the same BitLocker examples locally. They supply simulated volume states and collection errors.

```sh
pwsh -NoProfile -File ./tests/BitLocker.ps1
```

To run the same smoke test from an elevated Windows checkout:

```powershell
.\tests\WindowsSmoke.ps1
```
