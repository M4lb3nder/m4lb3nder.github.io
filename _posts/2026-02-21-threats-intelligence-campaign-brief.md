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

# The Gentlemen Ransomware

The Gentlemen Ransomware is a fast-moving, high-impact threat actor that emerged in **July-August 2025** and rapidly evolved into a global ransomware operation. The group follows a **Ransomware-as-a-Service (RaaS)** model, supplying affiliates with a customizable cross-platform toolkit for enterprise intrusions.

Since first observation, The Gentlemen has targeted medium-to-large organizations across **17+ countries**, with notable pressure on manufacturing, construction, healthcare, and insurance sectors. Its operations rely on **double extortion**, aggressive defense evasion, and modern cryptography (**ChaCha20** + **RSA-4096**) to maximize disruption and negotiation leverage.

![Twitter account](/assets/img/the-gentlemen-ransomware/gentlemen-account.webp)
_Twitter account_

---

## Key Tactics and Techniques

![The Ransomware Attack Chain](/assets/img/the-gentlemen-ransomware/ransomware-attack-chain.webp)
_Trend Micro - The Ransomware Attack Chain_

---

## 1. Initial Access

- Exploitation of internet-facing services
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

## 2. Reconnaissance & Discovery

Network scanning is performed using **Advanced IP Scanner** and **Nmap**. The operators enumerate local drives and Windows Failover Cluster Shared Volumes (CSV) for encryption targeting.

### Enable Network Discovery

```powershell
Get-NetFirewallRule -DisplayGroup "Network Discovery" | Enable-NetFirewallRule
```

### Volume Enumeration

```powershell
$volumes = @()
$volumes += Get-WmiObject -Class Win32_Volume | Where-Object { $_.Name -like '*:\*' } | Select-Object -ExpandProperty Name
try {
    $volumes += Get-ClusterSharedVolume | ForEach-Object { $_.SharedVolumeInfo.FriendlyVolumeName }
} catch {}
$volumes
```

### System Information Banner

```powershell
Write-Host "Windows version <version>" -BackgroundColor Blue -ForegroundColor White
Write-Host "The Gentlemen" -BackgroundColor DarkGray -ForegroundColor White -NoNewline
```

---

## 3. Privilege Escalation

Execution of components with elevated privileges to gain full environment control.

### Elevated Execution Flags

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

## 4. Defense Evasion

- Deployment of **kernel-level anti-AV** utilities
- Configuration of AV/Defender exclusion paths
- Neutralization of **EDR** tools
- Disabling **Microsoft Defender** real-time protection

### Local — Disable & Exclude

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

### Remote — Cross-System Execution

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

## 5. Lateral Movement & Remote Execution

Use of legitimate admin tools (**PsExec**, **PowerRun**, **PuTTY**) to transfer and execute payloads across systems.

### Remote Process Execution via WMI

```powershell
$p = [WMICLASS]"\\<target-host>\root\cimv2:Win32_Process"
$p.Create("<command>")
```

### Remote Process Execution via Invoke-Command

```powershell
Invoke-Command -ComputerName <target-host> -ScriptBlock { Start-Process "<binary-path>" }
```

---

## 6. Persistence & Propagation

Group Policy Object (GPO) manipulation for domain-wide payload distribution.

```powershell
Invoke-Command -ComputerName <target-host> -ScriptBlock {
    Set-MpPreference -DisableRealtimeMonitoring $true;
    Add-MpPreference -ExclusionPath 'C:\';
    Add-MpPreference -ExclusionProcess '<process-name>'
}
```

### NETLOGON / SYSVOL Share Abuse

This technique enables operators to distribute malicious payloads via the NETLOGON share, enabling near-simultaneous infection across domain-joined machines.

| Reference | Description |
|---|---|
| `\\share$` | UNC share path used for payload staging |
| `--shares` | Ransomware flag: encrypt UNC/network shares |
| `NETLOGON` | Referenced in LanmanServer context — domain-wide deployment |
| `autorun.ini` / `autorun.inf` | Potential persistence-related artifacts |

---

## 7. Data Collection & Exfiltration

- Staging of sensitive data prior to exfiltration
- Encrypted **SFTP** exfiltration using **WinSCP**

### Volume Enumeration

```powershell
$volumes += Get-WmiObject -Class Win32_Volume | Where-Object { $_.Name -like '*:\*' } | Select-Object -ExpandProperty Name
$volumes += Get-ClusterSharedVolume | ForEach-Object { $_.SharedVolumeInfo.FriendlyVolumeName }
```

---

## 8. Ransomware Deployment & Impact

- Ransomware deployed via **NETLOGON** share using domain admin credentials
- File encryption with **`.7mzhh`** extension
- Ransom note dropped as **`README-GENTLEMEN.txt`**
- Termination of backup, database, and security services: **Veeam**, **SQL**, **Oracle**, **SAP**, **Acronis**
- Deletion of shadow copies, logs, artifacts, and security event data

![The ransomware note](/assets/img/the-gentlemen-ransomware/ransomware-note.webp)
_The Ransomware Note_

---

## 9. Victimology

### Target Industries

`Manufacturing` · `Construction` · `Healthcare` · `Insurance` · `Others`

### Target Regions

`Asia-Pacific` · `South America` · `North America` · `Middle East` · `Others`

![Victim Distribution](/assets/img/the-gentlemen-ransomware/victim-distribution.webp)
_Trend Micro - Victim distribution by industry, region, and country_

---

## 10. Technical Analysis

### Execution Arguments

When launched, the ransomware executable provides an extensive help message, showing various options and flags available.

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name |
|---|---|---|
| Initial Access | T1190 | Exploit Public-Facing Application |
| Initial Access | T1078 | Valid Accounts |
| Initial Access | T1078.002 | Valid Accounts: Domain Accounts |
| Execution | T1059 | Command and Scripting Interpreter |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell |
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell |
| Persistence | T1547 | Boot or Logon Autostart Execution |
| Persistence | T1136 | Create Account |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation |
| Defense Evasion | T1562 | Impair Defenses |
| Defense Evasion | T1112 | Modify Registry |
| Defense Evasion | T1027 | Obfuscated Files or Information |
| Defense Evasion | T1484.001 | Domain Policy Modification: Group Policy Modification |
| Discovery | T1046 | Network Service Discovery |
| Discovery | T1087 | Account Discovery |
| Discovery | T1087.002 | Account Discovery: Domain Account |
| Discovery | T1482 | Domain Trust Discovery |
| Lateral Movement | T1021 | Remote Services |
| Lateral Movement | T1021.001 | Remote Services: Remote Desktop Protocol |
| Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares |
| Lateral Movement | T1021.004 | Remote Services: SSH |
| Collection & Exfiltration | T1074 | Data Staged |
| Collection & Exfiltration | T1074.001 | Data Staged: Local Data Staging |
| Collection & Exfiltration | T1039 | Data from Network Shared Drive |
| Collection & Exfiltration | T1048 | Exfiltration Over Alternative Protocol |
| Collection & Exfiltration | T1048.001 | Exfiltration Over Alternative Protocol: Unencrypted/Obfuscated Non-C2 Protocol |
| Command & Control | T1071 | Application Layer Protocol |
| Command & Control | T1071.001 | Application Layer Protocol: Web Protocols |
| Command & Control | T1219 | Remote Access Software |
| Impact | T1486 | Data Encrypted for Impact |
| Impact | T1489 | Service Stop |
| Impact | T1552 | Unsecured Credentials |
