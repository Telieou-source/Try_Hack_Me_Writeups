TryHackMe · Memory Forensics

# Pinstripe Moth

2026-10-24 Will Lawson Hard Windows Memory Malware Analysis

## Overview

A Windows memory dump with recovered artefact files from a compromised host. The attack chain runs from a compiled AutoIt3 dropper → PNG steganography → x86 shellcode → PowerShell → AES-256 encrypted document cache. All seven questions answered via Volatility 3 and manual shellcode reverse engineering.

| Detail | Value |
| --- | --- |
| Analysis tool | Volatility 3 (Linux) |
| Shellcode size | 3,939 bytes (after `IEND` in review-cover.png) |
| Architecture | x86 32-bit shellcode, 64-bit host process |
| Key artefacts | `review-cover.png`, `review-cache.dat`, process dumps of `ReviewClient.exe` and `notepad.exe` |

## Questions & Answers

Q1

What is the name of the suspicious process?

AnswerReviewClient.exe

`python3 vol.py -f memory.dmp windows.pslist` — non-standard process with no obvious parent. `windows.pstree` confirmed it spawned `notepad.exe` (PID 6280), the classic process hollowing indicator.

Q2

What process did it inject into?

Answernotepad.exe

`windows.pstree` showed ReviewClient.exe (PID 6260) as direct parent. Cross-confirmed with `windows.malfind` finding injected executable memory regions inside notepad.

Q3

What file contains the hidden payload?

Answerreview-cover.png

Dumped file-backed memory from ReviewClient.exe (`windows.dumpfiles --pid 6260`). Hex inspection revealed 3,939 bytes appended after the `IEND` PNG chunk — EOF steganography.

```
data = open('review-cover.png','rb').read()
iend = data.find(b'IEND')
shellcode_start = iend + 8   # skip IEND + CRC
print(f'Shellcode at offset {shellcode_start}, size {len(data) - shellcode_start}')
```

Q4

At what virtual address does the payload begin in the injected process?

Answer0xe70109d

Searched for the first 16 bytes of the extracted shellcode across the `notepad.exe` memory dump. Also found at `0x3a09d`, `0x9a000`, and `0xe1a909d` within ReviewClient.exe.

Q5

Which Windows API does the payload call to launch its next stage?

Answerkernel32.WinExec

Disassembled with Capstone (x86, 32-bit). The PIC shellcode resolves APIs at runtime via PEB walk: builds `"WinExec\0"` on the stack using push immediates, walks LDR InMemoryOrderModuleList to find `kernel32.dll`, parses the EAT with `repe cmpsb`, resolves the VA, then calls `WinExec(cmd, SW_SHOW)`. Confirmed via speakeasy emulation.

Q6

What encryption key does the decoded stage use to decrypt the document cache?

Answer7d714a7267e88abc1afd223830cb74d7c840f677ff165fbec9c134595f06faa8

### Decode chain

**Step 1** — Shellcode pushes 236 × 4-byte immediates onto the stack (reversed), then subtracts `0x25` from every byte to decode 944 bytes of a PowerShell command.

**Step 2** — Decoded command: `powershell.exe -NoProfile -EncodedCommand <base64>`

**Step 3** — Base64 is UTF-16LE. Decoded PowerShell script:

```
$k=[Convert]::FromBase64String('fXFKcmfoirwa/SI4MMt018hA9nf/Fl++ycE0WV8G+qg=');
$b=[IO.File]::ReadAllBytes('review-cache.dat');
$a=[Security.Cryptography.Aes]::Create();
$a.Key=$k; $a.IV=$b[0..15]; $a.Mode='CBC'; $a.Padding='PKCS7';
$d=$a.CreateDecryptor().TransformFinalBlock($b,16,$b.Length-16);
[IO.File]::WriteAllBytes('review-cache.zip',$d)
```

**Step 4** — Key as hex:

```
import base64
key = base64.b64decode('fXFKcmfoirwa/SI4MMt018hA9nf/Fl++ycE0WV8G+qg=')
print(key.hex())
# → 7d714a7267e88abc1afd223830cb74d7c840f677ff165fbec9c134595f06faa8
```

AES-256-CBC. IV = first 16 bytes of `review-cache.dat`. Decryption uses **.NET `[Security.Cryptography.Aes]`**, not CryptoAPI.

Q7

What is the flag?

AnswerTHM{2b3cc75adab999202e1879af542b2c11}

```
from Crypto.Cipher import AES
import base64, zipfile, io

key = base64.b64decode('fXFKcmfoirwa/SI4MMt018hA9nf/Fl++ycE0WV8G+qg=')
data = open('review-cache.dat', 'rb').read()
iv, ct = data[:16], data[16:]
pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
pt = pt[:-pt[-1]]   # strip PKCS7 padding

z = zipfile.ZipFile(io.BytesIO(pt))
print(z.read('release/approval.txt').decode())
```

`release/approval.txt` contains: *"Approval reference: THM{2b3cc75adab999202e1879af542b2c11}"*

## Full Attack Chain

ReviewClient.exe (AutoIt3 compiled dropper) ├─ Reads review-cover.png ├─ Extracts 3,939-byte x86 shellcode from after IEND chunk ├─ Process hollows notepad.exe (PID 6280) └─ Injects & executes shellcode at 0xe70109d notepad.exe (hollowed — running shellcode) ├─ PEB-walks to kernel32.dll ├─ Resolves WinExec via EAT (8-byte name compare) ├─ Decodes 944-byte stack payload (sub 0x25 per byte) └─ WinExec("powershell.exe -NoProfile -EncodedCommand …", SW_SHOW) powershell.exe ├─ Base64-decodes -EncodedCommand (UTF-16LE) ├─ Reads review-cache.dat ├─ AES-256-CBC decrypt (key = hardcoded base64, IV = first 16 bytes) └─ Writes review-cache.zip review-cache.zip └─ release/approval.txt → flag

## Techniques & Gotchas

| Technique | Detail |
| --- | --- |
| **PNG steganography** | Payload appended after `IEND` — invisible to image viewers, survives casual inspection |
| **PIC shellcode** | No imports, no hardcoded addresses; all APIs resolved at runtime via PEB walk |
| **On-stack string construction** | `"WinExec\0"` assembled from push immediates to avoid static string detection |
| **Stack-based payload encoding** | 236 push immediates build the command in reverse; single-byte decode (`-= 0x25`) |
| **Double base64** | PowerShell command is UTF-16LE base64-encoded; AES key is base64 inside that |
| **.NET AES, not CryptoAPI** | Uses `[Security.Cryptography.Aes]::Create()` — no advapi32, so CryptCreateHash searches are a dead end |
| **IV-in-ciphertext** | First 16 bytes of `review-cache.dat` are the AES IV — skip before decrypting |

## Lessons Learned

01

**Check EOF on all image files.** The PNG passed all structural validation; the payload only appeared past the `IEND` marker.

02

**Trace the API resolution, don't assume.** Following the PEB walk and name comparison byte-by-byte confirmed `WinExec` — not `CreateProcess` or `ShellExecute`.

03

**The decode loop range matters.** The `loop` instruction fires while `ecx != 0`, so the first byte is decoded by a separate `sub byte ptr [esp], 0x25` at `0x0532` — easy to miss.

04

**Disassembly alignment traps.** Starting Capstone mid-instruction produces garbage. Always start from a known clean instruction boundary.