# TryHackMe: The Game — Walkthrough

**Room type:** CTF (Hackfinity Battle 2025)  
**Category:** Game Hacking  
**Difficulty:** Easy  
**Tools:** `file`, `strings`, Python 3  

---

## What This Challenge Is Actually About

This isn't a hack in the traditional CTF sense — no web vulnerabilities, no exploit development, no password cracking. What it teaches is something arguably more useful: **understanding how packaged applications store their data, and how to extract that data without the application's help**.

The target is a Tetris clone called Tetrix. The flag is hidden somewhere inside it. The "hack" is understanding enough about how the game was built to peel it apart and find the secret.

This is a real-world skill. Game modders use these techniques to extract assets. Malware analysts use them to unpack executable files. Reverse engineers use them to understand how software works. The tools and thought process here transfer directly to all of those domains.

---

## Step 1 — Know What You're Dealing With

The first move in any unknown-binary challenge is always `file`. It tells you what you're actually looking at before you start making assumptions:

```bash
file Tetrix.exe
```

```
Tetrix.exe: PE32+ executable for MS Windows 5.02 (GUI), x86-64 (stripped to external PDB), 13 sections
```

It's a 64-bit Windows executable. "Stripped to external PDB" means the debug symbols were removed — the developer didn't leave a roadmap behind. Thirteen sections is slightly unusual for a simple program and suggests there may be embedded data.

---

## Step 2 — What Game Engine Built This?

Before going any deeper, it helps to know what framework was used to build the game. Different engines package their data differently, and knowing the engine tells you exactly where to look.

```bash
strings Tetrix.exe | grep -i "unity\|unreal\|godot\|pygame\|SDL" | head -10
```

```
Godot Game Engine
Godot Engine v4.3.stable.official
```

**Godot Engine** — an open-source game engine that's become extremely popular for indie games. This is important because Godot has a well-documented, publicly understood file format for storing game assets.

### What Is Godot's PCK Format?

Godot stores all of a game's assets — scenes, scripts, images, sounds — in a **PCK file** (short for "pack"). It's essentially a custom archive format, similar to a ZIP but specific to Godot.

The PCK can either sit alongside the executable as `Tetrix.pck`, or it can be **embedded directly inside the executable** at build time. When you distribute a Godot game as a single `.exe` file, the PCK is embedded — Godot just appends the entire archive to the end of the Windows PE binary.

This is the key insight the challenge is built around: **the game's data is literally sitting inside the executable file, we just need to know how to find it.**

---

## Step 3 — Find the Embedded PCK

Godot PCK files start with a magic signature: the four bytes `GDPC`. We can search for this signature to locate the archive:

```bash
python3 -c "
data = open('Tetrix.exe', 'rb').read()
sig = b'GDPC'
offsets = []
start = 0
while True:
    idx = data.find(sig, start)
    if idx == -1:
        break
    offsets.append(idx)
    start = idx + 1
print(f'All GDPC offsets: {[(o, hex(o)) for o in offsets]}')
"
```

```
All GDPC offsets: [(45907339, '0x2bc7d8b'), (45907436, '0x2bc7dec'), 
                   (45907536, '0x2bc7e50'), (45907718, '0x2bc7f06'), 
                   (46318144, '0x2c2c240'), (84108800, '0x5036600'), 
                   (93021724, '0x58b661c')]
```

Seven hits. Most of these are the string `"GDPC"` appearing in error messages or documentation text embedded in the Godot runtime itself. The real PCK will be a structurally valid archive — we can identify it by checking whether the bytes that follow look like a proper PCK header.

The one at `0x5036600` stands out: it's a round number and it's the second-to-last occurrence. The very last one at `0x58b661c` is only 4 bytes from the end of the file — that's Godot's **embedded PCK footer marker**, which tells the engine "look backwards from here to find the embedded archive." The real archive starts at `0x5036600`.

Verify by reading the header:

```python
import struct
data = open('Tetrix.exe', 'rb').read()
offset = 0x5036600

magic   = data[offset:offset+4]       # should be b'GDPC'
version = struct.unpack_from('<I', data, offset+4)[0]
major   = struct.unpack_from('<I', data, offset+8)[0]
minor   = struct.unpack_from('<I', data, offset+12)[0]
patch   = struct.unpack_from('<I', data, offset+16)[0]

print(f'Magic: {magic}')
print(f'PCK version: {version}')
print(f'Godot version: {major}.{minor}.{patch}')
```

```
Magic: b'GDPC'
PCK version: 2
Godot version: 4.3.0
```

That's our archive.

---

## Step 4 — Extract the PCK

Once we know where the PCK starts, extraction is trivial — just slice from that offset to the end of the file:

```python
data = open('Tetrix.exe', 'rb').read()
pck_data = data[0x5036600:]
open('Tetrix.pck', 'wb').write(pck_data)
```

We now have an 8.9 MB standalone PCK file containing all the game's assets.

---

## Step 5 — Reading the PCK Contents (and a Complication)

Attempting to parse the PCK directory structure reveals something interesting:

```
flags=3, file_base=5936, File count: 70
```

`flags=3` means **PACK_DIR_ENCRYPTED** is set — the file directory (the index of what's in the archive) is encrypted. The developer deliberately obscured the file listing, probably to make casual inspection harder.

This is where someone unfamiliar with the format might stop and think "I need to decrypt this." But there's a simpler path.

---

## Step 6 — Skip the Lock, Check the Contents

The directory being encrypted doesn't necessarily mean the **file contents** are encrypted. The encryption flag in Godot 4 encrypts the directory entries — the path names and metadata — but individual files may or may not have their own encryption.

And even if some files are encrypted, others might not be. Rather than fighting the directory encryption, we can just look at the raw bytes of the PCK and search for anything interesting:

```bash
strings Tetrix.pck | grep -i "THM\|flag\|CTF\|cipher\|secret"
```

```
THM{I_CAN_READ_IT_ALL}
```

There it is.

The flag was stored as a plaintext string inside one of the game's scene files or scripts — probably something like a `Label` node's text, or a variable in a GDScript file. The directory encryption hid which file it was in, but the content itself was never encrypted.

**Flag: `THM{I_CAN_READ_IT_ALL}`**

The flag name is the lesson: `I_CAN_READ_IT_ALL`. Hiding data inside a game binary doesn't protect it if the data itself is plaintext.

---

## The Bigger Picture — What This Technique Applies To

This challenge teaches a pattern that appears constantly in real-world software analysis:

### 1. Executables are often archives
Many applications bundle their data inside the executable itself rather than distributing separate files. Godot does it. Python's PyInstaller does it. Electron apps do it. Unity games do it (with a different format). Understanding this means you know to look *inside* the binary, not just alongside it.

### 2. Magic bytes are your map
Every file format has a signature — a known sequence of bytes at a predictable location. `GDPC` for Godot PCK, `PK\x03\x04` for ZIP, `MZ` for Windows PE, `\x7fELF` for Linux ELF binaries. Searching for these lets you find embedded archives, certificates, compressed blobs, and other data structures hiding inside larger files.

### 3. Encryption of metadata ≠ encryption of content
The challenge's directory encryption is a common misdirection. Encrypting the index of what's in an archive (the file names, sizes, offsets) doesn't protect the contents if those contents are stored in plaintext. This distinction matters in real investigations — a database might have an encrypted schema but unencrypted row data, or a network protocol might encrypt the header but not the payload.

### 4. `strings` is underrated
`strings` is one of the oldest and most underrated tools in the arsenal. Before writing a single line of code or spending an hour on decryption, just run `strings` on the target. You'd be surprised how often the answer is sitting in plain sight. The flag in this challenge was literally readable with one command. The challenge is knowing *which file to run it against* — which is what all the preceding work built toward.

---

## Tools That Go Further

If you wanted to go deeper into Godot reverse engineering, the ecosystem has dedicated tools:

**GodotPCKExplorer** — A GUI tool that can browse and extract files from PCK archives, even handling some encryption scenarios with a known key.

**gdsdecomp** — A more powerful tool that can decompile Godot 4 binaries, extract assets, and reconstruct a working project from a distributed game. This is the serious reverse engineer's tool — it can recover GDScript source code, scenes, and resources.

**gdtoolkit** — A Python toolkit for working with GDScript files.

For this challenge, `strings` was sufficient. But for deeper game reversing — recovering source code, understanding game logic, extracting assets — these tools are the next step.

---

## Summary

| Step | Action | Why |
|------|--------|-----|
| `file` | Identify the binary | Know what you're working with |
| `strings` + grep for engine names | Identify the game engine | Engine determines asset format |
| Search for `GDPC` magic bytes | Locate the embedded PCK | Godot embeds game data in the EXE |
| Verify header at candidate offset | Confirm the real PCK location | Multiple false positives from engine strings |
| Extract PCK bytes to file | Isolate the archive | Easier to work with standalone |
| Parse header, note `flags=3` | Discover directory encryption | Explains why file listing fails |
| `strings` on raw PCK | Find plaintext content | Encryption of index ≠ encryption of content |

The through-line is methodical triage: identify → understand the format → locate the data → extract → inspect. No exploits, no brute force — just knowing how software packages itself and using that knowledge to look inside.
