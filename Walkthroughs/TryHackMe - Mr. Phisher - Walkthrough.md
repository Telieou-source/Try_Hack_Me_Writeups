# TryHackMe: Mr. Phisher — Walkthrough

**Room:** Mr. Phisher
**Category:** Malicious document analysis (VBA macros)
**Target:** 10.145.152.194 (files at `/home/ubuntu/mrphisher` on the VM)
**Flag:** `flag{a39a07a239aacd40c948d852a5c9f8d1}`

---

## Scenario

The room's premise is a suspicious email attachment that keeps asking the user to "enable macros." A macro is a VBA program embedded in an Office document, and "Enable Content" is the classic phishing lure, because clicking it executes that code. My goal was to pull the macro out and read it **statically**, without ever opening the document in Word.

---

## Step 1: Enumerate the challenge files

I started by looking at what the room gave me:

```bash
ls -la /home/ubuntu/mrphisher
```

```
-rwxrwxrwx 1 ubuntu ubuntu 63346 Jan 29  2022 MrPhisher.docm
-rw-rw-r-- 1 ubuntu ubuntu 58947 Mar 11  2022 mr-phisher.zip
```

The `.docm` extension told me straight away that this was a macro-enabled Word document, so that was my target. I guessed the zip was just a packaged copy of the same file, so I set it aside.

---

## Step 2: Try olevba (dead end)

My first choice for VBA extraction is `olevba` from oletools, since it decompresses and prints macro source in one shot:

```bash
cd /home/ubuntu/mrphisher && olevba MrPhisher.docm
```

```
olevba: command not found
```

It wasn't installed on the VM, so I had to fall back to doing it by hand.

---

## Step 3: Unzip the .docm and run strings on vbaProject.bin

Modern Office files (OOXML) are just zip archives. The macros live in `word/vbaProject.bin`, an OLE container. I unzipped the document into a scratch directory and ran `strings` over the macro storage:

```bash
mkdir -p /tmp/docm && cd /tmp/docm && unzip -o /home/ubuntu/mrphisher/MrPhisher.docm >/dev/null && strings -n 3 word/vbaProject.bin | head -80
```

The output gave me the structure but not the data. I could see a module named `NewMacros`, a `Sub Format()`, an `Array(` starting `102, 109, ...`, and the fragment `Chr(a(i) Xo` / `r i`. The rest of the array was mangled:

```
pArray(
102, 109
, 9
100
53, B6
>5, 5
*6Z1
...
	b & Chr
(a(i) Xo
r i
```

The reason is that VBA source in `vbaProject.bin` is stored with **MS-OVBA compression** (an LZ77 variant). Literal runs survive `strings`, but repeated sequences are replaced by back-reference tokens, which is why chunks of the number list were missing. Still, this told me the logic: each array element is XORed with its index to build a string. I just needed the complete array.

---

## Step 4: Write a VBA decompressor

With no oletools available, I wrote a small MS-OVBA decompressor in Python. A compressed module starts with signature byte `0x01`, then a 2-byte chunk header, then a flag byte. Since the source begins with `Attribute VB_Name`, I located modules by searching for `\x00Attribut` (flag byte + first literals) and stepped back 3 bytes to the signature.

```bash
cat > /tmp/vbadecomp.py << 'EOF'
import sys
d = open(sys.argv[1], 'rb').read()

def decomp(d, p):
    out = bytearray(); p += 1
    while p + 2 <= len(d):
        hdr = d[p] | d[p+1] << 8
        if (hdr >> 12) & 7 != 3: break
        end = min(p + (hdr & 0xfff) + 3, len(d)); p += 2; start = len(out)
        if not hdr & 0x8000:
            out += d[p:p+4096]; p += 4096; continue
        while p < end:
            flags = d[p]; p += 1
            for b in range(8):
                if p >= end: break
                if not (flags >> b) & 1:
                    out.append(d[p]); p += 1
                else:
                    tok = d[p] | d[p+1] << 8; p += 2
                    bc = max((len(out) - start - 1).bit_length(), 4)
                    off = (tok >> (16 - bc)) + 1; ln = (tok & (0xffff >> bc)) + 3
                    for _ in range(ln): out.append(out[-off])
    return out

i = 0
while (i := d.find(b'\x00Attribut', i + 1)) != -1:
    src = decomp(d, i - 3)
    if b'Xor' in src:
        print(src.decode('latin-1'))
EOF
python3 -I /tmp/vbadecomp.py /tmp/docm/word/vbaProject.bin
```

### Course correction: IndexError

The first run crashed:

```
IndexError: bytearray index out of range
```

My `\x00Attribut` search was matching a spot that wasn't really the start of a compressed module (likely the `ThisDocument` module or other stream data). Decompressing from there produced a back-reference pointing before the start of the output buffer. Rather than make the module locator smarter, I made the decompressor bail out cleanly on an impossible offset, so bad matches return garbage and get filtered out by the `Xor` check:

```bash
sed -i 's/for _ in range(ln): out.append(out\[-off\])/if off > len(out): return out\n                    for _ in range(ln): out.append(out[-off])/' /tmp/vbadecomp.py && python3 -I /tmp/vbadecomp.py /tmp/docm/word/vbaProject.bin
```

This time the full macro came out clean:

```vb
Attribute VB_Name = "NewMacros"
Sub Format()
Dim a()
Dim b As String
a = Array(102, 109, 99, 100, 127, 100, 53, 62, 105, 57, 61, 106, 62, 62, 55, 110, 113, 114, 118, 39, 36, 118, 47, 35, 32, 125, 34, 46, 46, 124, 43, 124, 25, 71, 26, 71, 21, 88)
For i = 0 To UBound(a)
b = b & Chr(a(i) Xor i)
Next
End Sub
```

---

## Step 5: Decode the XOR array

The macro does a simple index-keyed XOR: character `i` = `a(i) XOR i`. A quick sanity check on the first few values confirmed that I was on the right track: `102^0 = 'f'`, `109^1 = 'l'`, `99^2 = 'a'`, `100^3 = 'g'`, `127^4 = '{'`. I decoded the whole thing with a one-liner:

```bash
python3 -c "a=[102,109,99,100,127,100,53,62,105,57,61,106,62,62,55,110,113,114,118,39,36,118,47,35,32,125,34,46,46,124,43,124,25,71,26,71,21,88];print(''.join(chr(x^i) for i,x in enumerate(a)))"
```

```
flag{a39a07a239aacd40c948d852a5c9f8d1}
```

---

## Takeaways

- **`.docm` / `.xlsm` / `.pptm` = macros.** The "m" suffix is the giveaway. Treat these as executable, not as documents.
- **OOXML files are zip archives.** Macros sit in `vbaProject.bin` and can be pulled without Office.
- **`strings` isn't enough for VBA.** Source is MS-OVBA compressed, so expect missing pieces. Use `olevba` (oletools) when it's available, or decompress the stream manually as I did here.
- **Static analysis first.** I never enabled or ran the macro. This one only builds a string, but real phishing macros use the same kind of XOR or `Chr()` obfuscation to hide download URLs and PowerShell commands.
- **Defensive angle:** block macros in documents from the internet (Mark-of-the-Web), and alert on Office processes spawning child processes.
