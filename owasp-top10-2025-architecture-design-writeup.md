# TryHackMe: OWASP Top 10 2025 — Architecture & Design Failures — Writeup

**Room:** OWASP Top 10 2025 — Architecture & Design (Module: OWASP Top 10 2025)
**Categories covered:**
- AS02: Security Misconfigurations
- AS03: Software Supply Chain Failures
- AS04: Cryptographic Failures
- AS06: Insecure Design

## Overview

This room covers four categories from the OWASP Top 10 2025 that all trace back to the same root cause: **weak foundations rather than weak code**. Each category is demonstrated with a small, independently running vulnerable web service (one per port), and each challenge asks for a single flag recovered by exploiting that specific flaw.

| Port | Category | Vulnerability Theme |
|---|---|---|
| 5002 | AS02 — Security Misconfigurations | Verbose error messages / stack trace leakage |
| 5003 | AS03 — Software Supply Chain Failures | Unverified third-party library with a hidden debug backdoor |
| 5004 | AS04 — Cryptographic Failures | Hardcoded encryption key + weak cipher mode (AES-ECB) |
| 5005 | AS06 — Insecure Design | Missing authorization on an API the developers assumed only their own mobile app would call |

## AS02 — Security Misconfigurations (Port 5002)

The target exposed a **User Management API** with one documented endpoint:

```
GET /api/user/<user_id>
```

The docs explicitly noted the ID "must be numeric" — a strong hint to test the validation boundary. Supplying a non-numeric value triggered a full, unhandled exception:

```bash
curl -s http://<target>:5002/api/user/abc
```

```json
{
  "error": "Invalid user ID format: abc. Flag: THM{V3RB0S3_3RR0R_L34K}",
  "traceback": "Traceback (most recent call last):\n  File \"/app/app.py\", line 21, in get_user\n    raise ValueError(...)\n..."
}
```

**Flag:** `THM{V3RB0S3_3RR0R_L34K}`

**Root cause:** the application returned raw Python tracebacks and internal file paths directly in the HTTP response instead of a generic error message — classic verbose-error information disclosure, made worse here by the flag being interpolated directly into the exception message itself.

## AS03 — Software Supply Chain Failures (Port 5003)

Task files included the application's `app.py`, which revealed the vulnerable pattern immediately:

```python
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))
from vulnerable_utils import process_data, format_output, debug_info

@app.route('/api/process', methods=['POST'])
def process():
    data = request.json.get('data', '')
    if data == 'debug':
        return jsonify(debug_info())
    ...
```

The app imports an "old" local library (`lib/vulnerable_utils.py`) and blindly exposes whatever that dependency's `debug_info()` function returns whenever the client sends the literal string `"debug"`:

```bash
curl -s -X POST http://<target>:5003/api/process \
  -H "Content-Type: application/json" \
  -d '{"data": "debug"}'
```

```json
{
  "admin_token": "admin_token_12345",
  "flag": "THM{SUPPLY_CH41N_VULN3R4B1L1TY}",
  "internal_secret": "internal_secret_key_2024",
  "version": "1.2.3"
}
```

**Flag:** `THM{SUPPLY_CH41N_VULN3R4B1L1TY}`

**Root cause:** the vulnerability wasn't in the application's own code at all — it lived entirely inside an unverified, outdated local dependency that shipped a debug function leaking admin tokens and internal secrets, and the main app trusted and exposed that function without any access control or code review of what the dependency actually did.

## AS04 — Cryptographic Failures (Port 5004)

The landing page displayed a base64-encoded "encrypted document" and loaded a client-side script, `/static/js/decrypt.js`:

```javascript
const SECRET_KEY = "my-secret-key-16";
const ENCRYPTION_MODE = "ECB";
const KEY_SIZE = 128;
```

Two failures stacked on top of each other: a hardcoded AES key shipped in **client-side JavaScript** (visible to anyone who views source), and the use of **ECB mode**, which is insecure by design regardless of key secrecy. With the key in hand, the ciphertext was decrypted locally:

```bash
python3 -c "
from Crypto.Cipher import AES
import base64

key = b'my-secret-key-16'
ciphertext = base64.b64decode('Nzd42HZGgUIUlpILZRv0jeIXp1WtCErwR+j/w/lnKbmug31opX0BWy+pwK92rkhjwdf94mgHfLtF26X6B3pe2fhHXzIGnnvVruH7683KwvzZ6+QKybFWaedAEtknYkhe')
cipher = AES.new(key, AES.MODE_ECB)
print(cipher.decrypt(ciphertext))
"
```

```
CONFIDENTIAL: The admin password is 'admin123'. Flag: THM{CRYPTO_FAILURE_H4RDCOD3D_K3Y}
```

**Flag:** `THM{CRYPTO_FAILURE_H4RDCOD3D_K3Y}`

**Root cause:** encryption keys must never be shipped to the client, and ECB mode should never be used for anything sensitive — it's deterministic at the block level, leaking structural patterns in the plaintext even without the key. Here the key exposure alone was enough to fully break confidentiality.

## AS06 — Insecure Design (Port 5005)

The landing page ("SecureChat") displayed a message claiming the service was "designed exclusively for mobile devices" and that private messages could only be accessed through the mobile app. No client-side script, cookie, header, or User-Agent variation changed the server's response — extensive enumeration (directory brute-forcing with `gobuster` across multiple large wordlists, Host-header manipulation, query parameter fuzzing, and User-Agent spoofing) all came back empty except for a single decoy route (`/console`, a permanently-400ing dead end).

The actual vulnerable endpoints turned out to be simple, guessable, thematically-named API routes that weren't in any wordlist:

```bash
curl http://<target>:5005/api/users
```
```json
{
  "admin": {"email": "admin@example.com", "name": "Admin", "role": "admin"},
  "user1": {"email": "alice@example.com", "name": "Alice", "role": "user"},
  "user2": {"email": "bob@example.com", "name": "Bob", "role": "user"}
}
```

```bash
curl http://<target>:5005/api/messages/admin
```
```json
{
  "messages": [
    {"content": "Admin panel access key: THM{1NS3CUR3_D35IGN_4SSUMPT10N}", "from": "system"}
  ],
  "user": "admin"
}
```

**Flag:** `THM{1NS3CUR3_D35IGN_4SSUMPT10N}`

**Root cause:** the backend API had **no authentication or authorization at all**. The "mobile-only" messaging on the landing page was purely cosmetic UX copy — it wasn't backed by any actual server-side enforcement. Any client that could guess or discover the API shape (`/api/users` to enumerate accounts, `/api/messages/<username>` to read anyone's messages) could pull private data for every user in the system, including the admin, with zero credentials. This mirrors the room's real-world example (Clubhouse's unauthenticated backend API) almost exactly: the design assumed a single trusted client (the mobile app) would be the only thing ever talking to the API, and built no defense for the case where that assumption breaks.

## Summary

| Category | Flag |
|---|---|
| AS02 — Security Misconfigurations | `THM{V3RB0S3_3RR0R_L34K}` |
| AS03 — Software Supply Chain Failures | `THM{SUPPLY_CH41N_VULN3R4B1L1TY}` |
| AS04 — Cryptographic Failures | `THM{CRYPTO_FAILURE_H4RDCOD3D_K3Y}` |
| AS06 — Insecure Design | `THM{1NS3CUR3_D35IGN_4SSUMPT10N}` |

## Key Takeaways

- **Never return raw stack traces or debug information in production responses.** Even seemingly harmless validation errors can leak file paths, internal logic, and secrets.
- **Every dependency is part of your attack surface.** An "old" or unmaintained local library imported without review can carry backdoors, debug endpoints, or leaked credentials that the importing application never intended to expose.
- **Never ship encryption keys to the client**, and always use an authenticated, non-deterministic cipher mode (AES-GCM, ChaCha20-Poly1305) — never ECB, and never ship keys in code at all, client or server, without a proper secrets manager.
- **Authentication and authorization must be enforced server-side, unconditionally** — assumptions about which client "should" be calling an API (mobile app vs. browser vs. curl) are not a security control. If an endpoint can be reached, it must independently verify the caller is allowed to see the data, regardless of what the marketing copy says the intended access path is.
- **Security-through-obscurity (hidden/undocumented endpoints, "mobile-only" UI messaging) buys nothing** against a determined tester — all four flaws here were found by directly testing the stated business logic, not by any exotic technique.

## Tools Used

- `curl` — endpoint probing, header/method/parameter fuzzing
- `gobuster` — directory and endpoint brute-forcing (dirb and SecLists wordlists)
- `pycryptodome` (Python) — AES-ECB decryption
- `nmap` — port confirmation across the lab host

---
*Writeup based on hands-on completion of the TryHackMe OWASP Top 10 2025 Architecture & Design room.*
