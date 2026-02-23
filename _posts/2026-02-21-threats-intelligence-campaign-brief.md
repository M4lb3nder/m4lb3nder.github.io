---
title: "Threat Intelligence 01: The Gentlemen Ransomware"
date: 2026-02-21 18:00:00 +0200
permalink: /posts/2026-02-21-threats-intelligence-campaign-brief/
categories:
  - Threat Intelligence
tags:
  - threat-intelligence
  - ransomware
  - mitre-attack
  - malware-analysis
summary: "The Gentlemen Ransomware is a fast-moving ransomware group that emerged in July-August 2025 and quickly established itself as a global threat. The group operates under a Ransomware-as-a-Service (RaaS) model and provides affiliates with a customizable, cross-platform toolkit."
description: "Technical threat intelligence report on The Gentlemen Ransomware, a fast-moving RaaS operation using double extortion, broad targeting, and adaptive evasion tradecraft."
image:
  path: /assets/img/the-gentlemen-ransomware/gentlemen-cover.webp
  alt: The Gentlemen Ransomware
---

## Executive Summary

**The Gentlemen** is a fast-moving, high-impact ransomware operation that emerged in **July–August 2025** and rapidly evolved into a global threat. The group operates under a **Ransomware-as-a-Service (RaaS)** model, providing affiliates with a customizable, cross-platform toolkit designed for enterprise intrusions.

Since initial observation, The Gentlemen has targeted medium-to-large organizations across **17+ countries**, exerting particular pressure on the manufacturing, construction, healthcare, and insurance sectors. Operations rely on **double extortion tactics**, aggressive defense evasion, and modern cryptography (**ChaCha20 + RSA-4096**) to maximize disruption and negotiation leverage.

![Twitter account](/assets/img/the-gentlemen-ransomware/gentlemen-account.webp)
_Twitter account_

---

## Threat Actor Profile

| Attribute | Detail |
|---|---|
| **Actor Name** | The Gentlemen |
| **First Observed** | July–August 2025 |
| **Operation Type** | Ransomware-as-a-Service (RaaS) |
| **Extortion Method** | Double Extortion |
| **Encryption** | ChaCha20 + RSA-4096 |
| **File Extension** | `.7mzhh` |
| **Ransom Note** | `README-GENTLEMEN.txt` |
| **Countries Targeted** | 17+ |


---

## Attack Chain Overview

The Gentlemen follows a structured intrusion lifecycle — from initial access through to data exfiltration and ransomware deployment. The phases below map the full attack chain as observed across confirmed incidents.

![The Ransomware Attack Chain](/assets/img/the-gentlemen-ransomware/ransomware-attack-chain.webp)
_Trend Micro - The Ransomware Attack Chain_

---

## Phase 1 — Initial Access

**Techniques:** `T1190` · `T1078` · `T1078.002`

The group gains entry through two primary vectors:

- Exploitation of internet-facing services (e.g., VPN appliances, public-facing applications)
- Abuse of compromised **FortiGate** administrative accounts

### C2 & Contact Reference

| Channel | Value |
|---|---|
| **Email** | `negotiation_hapvida@proton.me` |
| **TOX ID** | `ID88984846080D639C9A4EC394E53BA616D550B2B3AD691942EA2CCD33AA5B9340FD1A8FF40E9A` |
| **TOX Download** | `https://tox.chat/download.html` |
| **Leak Site (Tor)** | `http://.onion/` |
| **Tor Browser** | `https://www.torproject.org/download/` |

![The leak website](/assets/img/the-gentlemen-ransomware/ransomware-leak-website.webp)
_The Ransomware Leak Website_

---

## Phase 2 — Reconnaissance & Discovery

**Techniques:** `T1046` · `T1087` · `T1087.002` · `T1482`

Network scanning is performed using **Advanced IP Scanner** and **Nmap**. Operators enumerate local drives and Windows Failover Cluster Shared Volumes (CSV) to identify encryption targets.

### Enable Network Discovery

```powershell
Get-NetFirewallRule -DisplayGroup "Network Discovery" | Enable-NetFirewallRule
```

### Volume Enumeration

```powershell
$volumes = @()
$volumes += Get-WmiObject -Class Win32_Volume |
    Where-Object { $_.Name -like '*:\*' } |
    Select-Object -ExpandProperty Name
try {
    $volumes += Get-ClusterSharedVolume |
        ForEach-Object { $_.SharedVolumeInfo.FriendlyVolumeName }
} catch {}
$volumes
```

### System Banner (Observed in Samples)

```powershell
Write-Host "Windows version <version>" -BackgroundColor Blue -ForegroundColor White
Write-Host "The Gentlemen" -BackgroundColor DarkGray -ForegroundColor White -NoNewline
```

---

## Phase 3 — Privilege Escalation

**Techniques:** `T1068`

Components are executed with elevated privileges to gain full environment control.

| Flag | Description |
|---|---|
| `/RU SYSTEM` | `schtasks` flag — run task as SYSTEM account |
| `--system` | Ransomware flag — encrypt as SYSTEM user |
| `Win32_Process` | WMI class used for elevated process creation |

### WMI Elevated Process Creation

```powershell
$p = [WMICLASS]"\\<target-host>\root\cimv2:Win32_Process"
$p.Create("<command>")
```

---

## Phase 4 — Defense Evasion

**Techniques:** `T1562` · `T1112` · `T1027` · `T1484.001`

Observed evasion techniques include:

- Deployment of **kernel-level anti-AV** utilities
- Configuration of AV/Defender exclusion paths
- Neutralization of **EDR** tools
- Disabling **Microsoft Defender** real-time protection

### Disable & Exclude (Local)

```powershell
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true;
Add-MpPreference -ExclusionPath 'C:\';
Add-MpPreference -ExclusionPath 'C:\Temp';
Add-MpPreference -ExclusionPath '\\<share$>';"
```

### Forced Override

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true -Force
```

### Remote Cross-System Execution

```powershell
Invoke-Command -ComputerName <target-host> -ScriptBlock {
    Set-MpPreference -DisableRealtimeMonitoring $true;
    Add-MpPreference -ExclusionPath 'C:\';
    Add-MpPreference -ExclusionProcess '<process-name>'
}
```

### Log & Artifact Clearing

| Target | Command |
|---|---|
| **Defender Support Logs** | `del /f /q C:\ProgramData\Microsoft\Windows Defender\Support\*.*` |
| **RDP Log Files** | `del /f /q %SystemRoot%\System32\LogFiles\RDP*\*.*` |
| **Windows Prefetch** | `del /f /q C:\Windows\Prefetch\*.*` |

---

## Phase 5 — Lateral Movement & Remote Execution

**Techniques:** `T1021` · `T1021.001` · `T1021.002` · `T1021.004`

Legitimate administration tools are leveraged for payload transfer and execution across systems, including **PsExec**, **PowerRun**, and **PuTTY**.

### Remote Execution via WMI

```powershell
$p = [WMICLASS]"\\<target-host>\root\cimv2:Win32_Process"
$p.Create("<command>")
```

### Remote Execution via Invoke-Command

```powershell
Invoke-Command -ComputerName <target-host> -ScriptBlock {
    Start-Process "<binary-path>"
}
```

---

## Phase 6 — Persistence & Propagation

**Techniques:** `T1547` · `T1136`

Group Policy Object (GPO) manipulation is used for domain-wide payload distribution.

### NETLOGON Share Abuse

This technique enables operators to distribute malicious payloads via the NETLOGON share, enabling near-simultaneous infection across domain-joined machines.

| Reference | Description |
|---|---|
| `\\share$` | UNC path used for payload staging |
| `--shares` | Ransomware flag — encrypt UNC/network shares |
| `NETLOGON` | Referenced in LanmanServer context — domain-wide deployment |
| `autorun.ini` / `autorun.inf` | Potential persistence-related artifacts |

---

## Phase 7 — Data Collection & Exfiltration

**Techniques:** `T1074` · `T1074.001` · `T1039` · `T1048` · `T1048.001`

Sensitive data is staged prior to exfiltration. Exfiltration is conducted over encrypted **SFTP** using **WinSCP**.

```powershell
$volumes += Get-WmiObject -Class Win32_Volume |
    Where-Object { $_.Name -like '*:\*' } |
    Select-Object -ExpandProperty Name
$volumes += Get-ClusterSharedVolume |
    ForEach-Object { $_.SharedVolumeInfo.FriendlyVolumeName }
```

---

## Phase 8 — Ransomware Deployment & Impact

**Techniques:** `T1486` · `T1489` · `T1552`

- Ransomware deployed via **NETLOGON** share using domain admin credentials
- Files encrypted with **`.7mzhh`** extension
- Ransom note dropped as **`README-GENTLEMEN.txt`**
- Backup, database, and security services terminated: **Veeam**, **SQL**, **Oracle**, **SAP**, **Acronis**
- Deletion of shadow copies, event logs, prefetch, and other forensic artifacts

![The ransomware note](/assets/img/the-gentlemen-ransomware/ransomware-note.webp)
_The Ransomware Note_

---

## Victimology

### Target Sectors

`Manufacturing` · `Construction` · `Healthcare` · `Insurance` · `Other`

### Target Regions

`Asia-Pacific` · `South America` · `North America` · `Middle East` · `Other`

> Victims span 17+ countries with no single geographic concentration, indicating opportunistic targeting with broad sector reach.

![Victim Distribution](/assets/img/the-gentlemen-ransomware/victim-distribution.webp)
_Trend Micro - Victim distribution by industry, region, and country_

---
## Technical Analysis

### Execution Arguments
Ransomware performs a command-line argument parsing. These arguments are used to provide detailed control over encryption targets, performance options, and operation modes.

| Argument          | Description                                              |
| ----------------- | -------------------------------------------------------- |
| `--password PASS` | Required to execute ransomware                           |
| `--path DIRS`     | Enumerate directories and disks to encrypt               |
| `--T MIN`         | Delay before encryption                                  |
| `--silent`        | Do not rename files after encryption                     |
| `--system`        | Encrypt local drive only                                 |
| `--shares`        | Encrypt mapped network and available UNC shares only     |
| `--full`          | Encrypt both `--system` and `--shares`                   |
| `--fast`          | Encrypt 9%                                               |
| `--superfast`     | Encrypt 3%                                               |
| `--ultrafast`     | Encrypt 1%                                               |

![Execution Arguments](/assets/img/the-gentlemen-ransomware/execution-argument.webp)
_Ransomware executable arguments_
`--password` is required. If the value is missing or incorrect, the ransomware immediately terminates. This helps ensure execution only in attacker-intended environments and reduces detonation in sandbox analysis environments.
---
### Encryption Algorithm
#### Services Terminated Before Encryption

Commonly terminated services include:
`sql`, `vss`, `VSS`, `VSNAP`, `QBDBMgrN`, `pgAdmin3`, `pgAdmin4`, `Veeam`, `MSSQLServer`, `WSBExchange`, `GxVss`, `SAP`, `MySQL`, `MariaDB`, `PostgreSQL`, `TeamViewer`, `BackupExecAgent`, `BackupExecRPCService`, `BackupExecManagementService`, `BackupExecJobEngine`, `VeeamTransportSvc`, `OracleServiceORCL`, `MSExchange`, `SAPService`, `postmaster`, `CagService`, `DefWatch`, `SccEvtMgr`, `GxClMgr`, `CVMountd`.

#### File Extension Exclusion List

Skipped during encryption:
> .exe .bat .drv .tmp .msp .prf .ms .ci .co .key .ocx .pdb .wp .xhl .pro .mod
> .dll .ps1 .ic .sh .tab .in .cmd .ani .386 .cur .idx .sys .com .sh .sm .pas
> .pl .cp .lad .vic .ms .su .sql .SAP .cvd .vss .Sql .Dir

#### Crypto Engine
- The ransomware contains an embedded attacker public key (decoded in memory).
- For each file, it generates a fresh random 32-byte value and uses **X25519 (ECDH)** with the attacker public key to create a shared secret.
- That shared secret is processed with **HChaCha20** to derive a 32-byte subkey.
- The subkey is then used by **XChaCha20** to encrypt the file (stream cipher).
- Nonce material is also derived from X25519-related output (split into parts for HChaCha20/XChaCha20 nonce construction).
- The malware stores only a Base64-encoded X25519 result in the encrypted file, **not** the temporary random private value.
- Because the victim lacks the attacker private key, recreating the shared secret and decrypting is infeasible.
- Encryption is optimized by size:
    - < ~1 MB (0x100000): full-file encryption
    - > ~1 MB: partial/ranged encryption for speed while still causing high damage

---
## MITRE ATT&CK Mapping

| Tactic               | Technique ID | Technique Name                                        |
| -------------------- | ------------ | ----------------------------------------------------- |
| Initial Access       | T1190        | Exploit Public-Facing Application                     |
| Initial Access       | T1078        | Valid Accounts                                        |
| Initial Access       | T1078.002    | Valid Accounts: Domain Accounts                       |
| Execution            | T1059        | Command and Scripting Interpreter                     |
| Execution            | T1059.001    | PowerShell                                            |
| Execution            | T1059.003    | Windows Command Shell                                 |
| Persistence          | T1547        | Boot or Logon Autostart Execution                     |
| Persistence          | T1136        | Create Account                                        |
| Privilege Escalation | T1068        | Exploitation for Privilege Escalation                 |
| Defense Evasion      | T1562        | Impair Defenses                                       |
| Defense Evasion      | T1112        | Modify Registry                                       |
| Defense Evasion      | T1027        | Obfuscated Files or Information                       |
| Defense Evasion      | T1484.001    | Domain Policy Modification: Group Policy Modification |
| Discovery            | T1046        | Network Service Discovery                             |
| Discovery            | T1087        | Account Discovery                                     |
| Discovery            | T1087.002    | Account Discovery: Domain Account                     |
| Discovery            | T1482        | Domain Trust Discovery                                |
| Lateral Movement     | T1021        | Remote Services                                       |
| Lateral Movement     | T1021.001    | Remote Desktop Protocol                               |
| Lateral Movement     | T1021.002    | SMB/Windows Admin Shares                              |
| Lateral Movement     | T1021.004    | SSH                                                   |
| Collection           | T1074        | Data Staged                                           |
| Collection           | T1074.001    | Local Data Staging                                    |
| Collection           | T1039        | Data from Network Shared Drive                        |
| Exfiltration         | T1048        | Exfiltration Over Alternative Protocol                |
| Exfiltration         | T1048.001    | Unencrypted/Obfuscated Non-C2 Protocol                |
| Command & Control    | T1071        | Application Layer Protocol                            |
| Command & Control    | T1071.001    | Web Protocols                                         |
| Command & Control    | T1219        | Remote Access Software                                |
| Impact               | T1486        | Data Encrypted for Impact                             |
| Impact               | T1489        | Service Stop                                          |
| Impact               | T1552        | Unsecured Credentials                                 |

---

## Recommended Mitigations

- **Patch internet-facing services** — prioritize FortiGate and VPN appliances; apply vendor patches immediately
- **Enforce MFA** on all administrative and domain accounts
- **Monitor and restrict PowerShell** execution policies; enable script block logging
- **Harden NETLOGON share** access and audit GPO modifications
- **Deploy EDR** solutions with tamper protection enabled to resist kernel-level disabling
- **Backup isolation** — ensure backups are offline or air-gapped and protected from domain admin credentials
- **Shadow copy protection** — use Volume Shadow Copy Service (VSS) protections to prevent deletion
- **Network segmentation** — limit lateral movement paths between workstations and servers
- **Hunt for indicators** — scan for `.7mzhh` extensions, `README-GENTLEMEN.txt`, and the TOX ID listed above

---
