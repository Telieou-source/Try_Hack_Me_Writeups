# TryHackMe: Web Server Attacks (Recon & Misconfiguration) — Writeup

**Platform:** TryHackMe
**Focus:** Reconnaissance and misconfiguration identification across four web servers on one Linux host — Apache2, Python `http.server`, Node.js Express, and Nginx.
**Scope note:** No exploitation — no shells, RCE, or privesc. The goal is to catalogue what's exposed and *why it matters*. Every finding is a server doing exactly what it was configured to do; the vulnerability is configuration and placement, not code.

---

## Setup

Four servers, four ports, one host:

| Port | Server | Default Server Header |
|---|---|---|
| 80 | Apache2 | `Apache/2.4.x (Ubuntu)` |
| 8000 | Python HTTP Server | `SimpleHTTP/0.6 Python/3.x` |
| 3000 | Node.js Express | *none* (Express sets no Server header) |
| 8080 | Nginx | `nginx/1.x (Ubuntu)` |

```bash
export IP=<target>
for p in 80 8000 3000 8080; do echo "=== $p ==="; curl -sI http://$IP:$p/; done
```

---

## Stage 1 — Identifying Web Servers

The `Server` header is the most direct fingerprint; each server formats it distinctly.

```bash
curl -sI http://$IP:8000/ | grep -i server     # Server: SimpleHTTP/0.6 Python/3.12.3
curl -sI http://$IP:3000/ | grep -i powered     # X-Powered-By: Express
curl -sI http://$IP:8080/ | grep -i server      # Server: nginx/1.24.0 (Ubuntu)
```

Key fingerprint facts:
- **Python** returns `HTTP/1.0` (not 1.1) — `http.server` speaks HTTP/1.0, a tell for the "accidental Python server." Zero security headers.
- **Express** sets *no* `Server` header at all — the Node HTTP layer doesn't add one and the dev has to do it explicitly. Its identifier is **`X-Powered-By: Express`**. On this box `/` returns `Content-Type: application/json`, so it's an API, not a static site.
- **Nginx** and **Apache** both over-disclose full versions by default.

Default error pages also fingerprint even with the `Server` header suppressed: Python returns plain text, Nginx puts its version in the HTML footer, Apache names itself in the page body.

---

## Stage 2 — Python HTTP Server (port 8000)

`python3 -m http.server 8000` serves the **entire working directory** — every file, dotfiles included. No auth, no blocklist, no `.htaccess` equivalent. One mode: serve everything.

### Directory listing + dotfile exposure

```bash
curl -s http://$IP:8000/ | grep -iE 'href='
# .env, backup.zip, config.txt, notes.txt

curl -s http://$IP:8000/.env
# SECRET_KEY=dev-secret-key-do-not-use
# DATABASE_URL=postgresql://webapp:S3cur3DBPass!@localhost/production
# DEBUG=True
```

The `.env` — hidden from normal Linux navigation but served like any other file — leaks the DB password (`S3cur3DBPass!`, between `webapp:` and `@` in the connection string).

### Backup archive

```bash
curl -s http://$IP:8000/backup.zip -o backup.zip
mkdir -p backup-contents && unzip -o backup.zip -d backup-contents/
grep -riE 'THM\{|flag' backup-contents/
# backup-contents/db_dump.sql:-- flag: THM{py_server_exposed}
```

**Why it matters:** this is a finding with *no exploit*. The server works exactly as designed — the misconfiguration is that it's running where it shouldn't be, serving files that shouldn't be public. The realistic scenario is a dev spinning it up to share a file and forgetting it for six months.

---

## Stage 3 — Apache2 (port 80)

Apache on Ubuntu defaults to `ServerTokens OS`, disclosing version + OS. Three classic default-config findings: directory listing, `mod_status`, and backup files in the document root.

### Directory listing (`Options +Indexes`)

```bash
curl -s http://$IP/files/
# Index of /files — employees.csv, internal-notes.txt
```

```bash
curl -s http://$IP/files/employees.csv        # PII: names + emails incl. admin@company.com
curl -s http://$IP/files/internal-notes.txt   # flag: THM{apache_dir_listing}
```

`employees.csv` in a listable directory is a PII exposure (and the `admin@` address feeds later credential attacks); the notes file leaks a migration date, a pending "rotate API keys" action item, and the flag — `THM{apache_dir_listing}`.

### mod_status

```bash
curl -s http://$IP/server-status | head
```

`mod_status` ships with `Require local` in `conf-available/security.conf`, but a `Require all granted` anywhere in a vhost config **silently overrides** it — exposing live worker state, request paths, and client IPs to any IP. Always check `/server-status` even on apparently-default servers.

### Unlinked backup file

```bash
curl -s http://$IP/backup.bak
# # DB credentials below
# # user: dbadmin pass: Backup2024!
```

`.bak` files aren't linked anywhere — found via Gobuster:

```bash
gobuster dir -u http://$IP:80 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x bak,txt -t 20
```

The pattern: check the version header, browse listable directories, visit `/server-status`, Gobuster for unlinked files.

---

## Stage 4 — Node.js Express (port 3000)

Express behaves differently — it runs application code, so the mistakes are dev-mode features shipped to production: debug endpoints, verbose errors, exposed env vars. The chain narrows scope at each step: **headers → errors → routes → env → static files.**

### Fingerprint + version

```bash
curl -sI http://$IP:3000/ | grep -i powered   # X-Powered-By: Express
curl -s http://$IP:3000/                       # {"status":"ok","app":"company-portal","version":"1.2.0"}
```

### Verbose error (stack trace leak)

```bash
curl -s http://$IP:3000/api/users | python3 -m json.tool
```

A custom error handler passes full stack traces regardless of `NODE_ENV` — leaking internal file paths (`/opt/nodeapp/app.js`), module structure, and even the failing SQL query (`SELECT * FROM users`).

### Route enumeration via debug endpoint

```bash
curl -s http://$IP:3000/api/routes | python3 -m json.tool
# lists every registered path — the app enumerating its own attack surface
```

### Environment variable exposure

```bash
curl -s http://$IP:3000/api/debug/env | python3 -m json.tool
# NODE_ENV: development   <- dev mode on a live box
# DB_PASSWORD: NodeDBPass2024!
# DB_HOST: localhost:5432
```

`NODE_ENV: development` on a production host is itself the tell it shipped unhardened.

### Static file leak

```bash
curl -s http://$IP:3000/static/config.js
# const API_BASE = 'http://internal-api.company.local:8080';
# const DEBUG = true;
# // flag: THM{node_debug_exposed}
```

`config.js` is "meant to be public" (the browser needs it) — but that's different from "contains only public information." It leaks an internal hostname and a debug flag alongside the flag `THM{node_debug_exposed}`.

> Note: `express.static()` returns 404 for dotfiles by default (opposite of Python's server) — a 404 on `.env` via a static route means the middleware is blocking it, not that it's absent.

---

## Stage 5 — Nginx (port 8080)

Same misconfig categories, different vocabulary. (On this box Nginx is on 8080 because Apache holds 80.)

### Version disclosure

```bash
curl -sI http://$IP:8080/ | grep -i server    # Server: nginx/1.24.0 (Ubuntu)
```

Controlled by `server_tokens` (default `on`), which governs both the header and the error-page version string. `server_tokens off` suppresses both.

### Directory listing (`autoindex on`)

Nginx does **not** list directories by default — it requires `autoindex on;` in a `location` block. When present on a sensitive path, it exposes contents:

```bash
curl -s http://$IP:8080/files/
# deploy-notes.txt, old-backup.tar.gz, server-config.txt

curl -s http://$IP:8080/files/deploy-notes.txt   # flag: THM{nginx_autoindex}
```

Flag: `THM{nginx_autoindex}`.

### nginx_status (stub_status)

```bash
curl -s http://$IP:8080/nginx_status
# Active connections: 1
# server accepts handled requests
#  15 15 15
# Reading: 0 Writing: 1 Waiting: 0
```

The `stub_status` module should be restricted to localhost; `allow all` exposes real-time connection metrics. The three numbers = total accepted, total handled, total requests. Not directly exploitable, but leaks load/usage patterns and confirms the monitoring setup.

---

## Stage 6 — Cross-Server Patterns

### Security header audit

None of the four servers sets security headers by default — they require active configuration and are never present out of the box:

```bash
for port in 80 8000 3000 8080; do
  echo "=== Port $port ===";
  curl -sI http://$IP:$port/ | grep -iE "x-frame-options|x-content-type|content-security-policy|strict-transport|referrer-policy" \
    || echo "(no security headers found)";
done
```

| Header | Protects against | Missing → |
|---|---|---|
| `X-Frame-Options` | Clickjacking | page embeddable in a cross-domain iframe |
| `X-Content-Type-Options` | MIME sniffing | browser guesses content types |
| `Content-Security-Policy` | XSS / resource injection | no origin restriction on scripts/styles |
| `Referrer-Policy` | Referer leakage | full URL sent cross-site |
| `Strict-Transport-Security` | Protocol downgrade | only meaningful over HTTPS (absence expected on this HTTP lab) |

### Automated scan (Nikto)

```bash
nikto -h http://$IP:80 -nointeractive
```

Surfaces the same findings automatically: `Server: Apache/2.4.58`, inode leak via ETags, missing X-Frame-Options, `OSVDB-561 /server-status` info disclosure, and **`OSVDB-3268: /files/: Directory indexing found`**. First-pass triage — fast, noisy, not stealthy.

### The recurring categories

| Misconfiguration | Apache | Python | Node.js | Nginx |
|---|---|---|---|---|
| Version disclosure | Yes | Yes | Partial | Yes |
| Directory listing | `/files/` | root | N/A | `/files/` |
| Status/debug endpoint | `/server-status` | N/A | `/api/debug/env`, `/api/routes` | `/nginx_status` |
| Sensitive files served | `backup.bak`, notes | `.env`, `backup.zip` | `config.js` | `server-config.txt` |
| Missing security headers | All | All | All | All |

Same categories across every server, just different directive vocabulary: Apache's `Options +Indexes` = Nginx's `autoindex on` = Python's default; `/server-status` = `/nginx_status` = `/api/debug/env`.

---

## Defensive Notes

Given all findings are configuration, hardening is direct:

- **Version disclosure:** `ServerTokens Prod` (Apache), `server_tokens off` (Nginx), strip `X-Powered-By` (`app.disable('x-powered-by')` or Helmet).
- **Directory listing:** `Options -Indexes` (Apache), remove `autoindex on` (Nginx), place an `index.html` or don't serve the dir at all (Python — better: don't run `http.server` near a public interface).
- **Status endpoints:** restrict `/server-status` and `/nginx_status` to `127.0.0.1`.
- **Node.js:** `NODE_ENV=production`, remove debug/route-dump endpoints, replace custom error handlers that leak stack traces, keep secrets out of client-served static files.
- **Security headers:** add the full set at the server or reverse-proxy layer.
- **Process hygiene:** the Python-server finding is a lifecycle problem — kill ad-hoc servers and enforce egress/firewall discipline so a "quick file share" can't sit exposed for months.

---

## Flags

| Server | Port | Flag |
|---|---|---|
| Python http.server | 8000 | `THM{py_server_exposed}` |
| Apache2 | 80 | `THM{apache_dir_listing}` |
| Node.js Express | 3000 | `THM{node_debug_exposed}` |
| Nginx | 8080 | `THM{nginx_autoindex}` |

**The thesis:** not one finding needed an exploit. Every server did precisely what it was configured to do — serve files, list directories, echo debug info, report metrics. Defaults optimise for ease of deployment over security, and the misconfiguration is simply that they were never reviewed.

**Room complete.**
