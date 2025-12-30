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
