# TryHackMe: Invite Only — Walkthrough

**Room:** [Invite Only](https://tryhackme.com/room/invite-only) · SOC Level 1 › Threat Analysis Tools · Challenge
**Completed:** 2026-11-24 · 10/10 questions

## Scenario

I'm a SOC analyst at the MSP TrySecureMe, supporting an L3 on IR. An L1 escalated two indicators:

- **IP:** `101[.]99[.]76[.]120`
- **SHA256:** `5d0509f68a9b7c415a726be75a078180e3f02e59866f193b0a99eee8e39c874f`

The job was to enrich them with the in-house TI tool (TryDetectThis2.0) and turn the results into usable intel.

---

## Getting in

My first attempt hit a dead end before the VM was involved: I guessed the room slug as `inviteonly` and the API answered "This room is private." The SOC Level 1 path page listed the real slug as `/room/invite-only`. After joining, I started the lab machine.

The VM was an Ubuntu desktop. Its **TryDetectThis2.0** launcher opens Firefox at `http://127.0.0.1:8000`, an offline VirusTotal clone with Detection / Details / Relations / Behavior / Community tabs.

One trap: the full-screen VM view opened on the *previous* room's machine, because TryHackMe keeps several VMs as tabs along the bottom bar. I switched to the `invite_only-V0.6` tab before doing anything.

## Phase 1: the flagged hash (Q1–Q4)

I searched the flagged SHA256. The header showed:

- **File:** `syshelpers.exe`, Win32 EXE, 214 KB
- **Classification:** `trojan.tedy/fxnp` (trojan, downloader), 51/72 vendors

That answered Q1 (`syshelpers.exe`) and Q2 (`Win32 EXE`).

The detection grid is very long, so I skipped it and opened the **Relations** tab. It holds four panels: Contacted Domains (7: S3, bitbucket, onecdn), Contacted IPs (20), **Execution Parents (2)**, and **Dropped Files (1)**.

**Execution Parents**, oldest first:
| Date | Type | Name | SHA256 |
|---|---|---|---|
| 2025-05-08 | PowerShell | `361GJX7J` | `047c5eec0445746862710d20e50a5dd04510b7e625fa5c1f5d48ce078001c0de` |
| 2025-06-01 | Win32 EXE | `installer.exe` | `fa102d4e3cfbe85f5189da70a52c1d266925f3efd122091cdc8fe0fc39033942` |

**Dropped Files:** `AClient.exe`, `dd02c105809e4ca41a5489e585ba025eddb89a91703b73a566c9903e6406a08c`.

- Q3 → `361GJX7J,installer.exe`
- Q4 → `AClient.exe`

## Phase 2: pivot on the second parent (Q5)

Q5 asked me to research the second execution parent. Clicking the `installer.exe` card did nothing (the cards aren't links), so I pasted its hash into the search bar instead.

`installer.exe` is a 4.7 MB dropper (`trojan.alien/generik`, 24/72). Its Relations tab listed **20 dropped files** in a scrollable box. I scrolled through and noted which ones carried a red ⚠ detection badge rather than a green check:

| # | File | Detections |
|---|---|---|
| 1 | `searchHost.exe` | 37/73 |
| 2 | `syshelpers.exe` | 51/72 (our flagged file, so installer.exe drops it) |
| 3 | `nat1.vbs` | 1/60 |
| — | `2k0om43n.0.cs`, `bitaddress.pdf`, `__PSScriptPolicyTest_*.ps1`, `gcsnn1nn.dll` | clean |
| 4 | `runsys.vbs` | 2/62 |

Q5 → `searchHost.exe,syshelpers.exe,nat1.vbs,runsys.vbs`

This also closed the loop on the chain: PowerShell stager → `installer.exe` → drops `syshelpers.exe` → drops `AClient.exe`.

## Phase 3: the flagged IP (Q6)

Searching `101.99.76.120` gave 12/94 detections, Malaysia, **AS45839 Shinjiru Technology Sdn Bhd** (a bulletproof-friendly host). Relations showed 15 passive DNS entries (`*.101-99-76-120.cpanel.site`, `eucigs.com`) and **8 communicating files** with 34–50 detections each.

The communicating files didn't name a family directly in the offline tool, but the report in Phase 4 lists this IP under its AsyncRAT C2 IOCs. With the 8-character answer format and `AClient.exe` in the chain (a classic AsyncRAT client name), the answer was clear.

Q6 → `AsyncRAT`

## Phase 4: OSINT for the source report (Q7–Q10)

My first web searches on the raw hash and the IP returned only noise: hash-dump pages and neighbouring URLhaus entries. I changed approach and searched on the behaviour instead (Discord + AsyncRAT + Skuld + ClickFix). That surfaced the Check Point Research report, and I confirmed it lists **both** flagged indicators: the hash as the "2nd Stage Downloader (RnrLoader)" and the IP as an AsyncRAT C2.

- Q7 → `From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery` (Check Point Research, 12 June 2025)
- Q8 → `ChromeKatz`, used to dump Chrome cookies around App-Bound Encryption
- Q9 → `ClickFix`, a fake "verify" step that copies a PowerShell command to the clipboard for the victim to run
- Q10 → `Discord`; expired or released vanity invite links were re-registered to redirect users to attacker servers

---

## Answers

| # | Answer |
|---|---|
| 1 | `syshelpers.exe` |
| 2 | `Win32 EXE` |
| 3 | `361GJX7J,installer.exe` |
| 4 | `AClient.exe` |
| 5 | `searchHost.exe,syshelpers.exe,nat1.vbs,runsys.vbs` |
| 6 | `AsyncRAT` |
| 7 | `From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery` |
| 8 | `ChromeKatz` |
| 9 | `ClickFix` |
| 10 | `Discord` |

## Distilled intel

| Type | Value | Role |
|---|---|---|
| SHA256 | `5d0509f6…e39c874f` | `syshelpers.exe`: 2nd-stage downloader (RnrLoader) |
| SHA256 | `fa102d4e…39033942` | `installer.exe`: dropper |
| SHA256 | `047c5eec…8001c0de` | `361GJX7J`: PowerShell stager |
| SHA256 | `dd02c105…6406a08c` | `AClient.exe`: AsyncRAT client |
| IP | `101.99.76.120` (AS45839, MY) | AsyncRAT C2 |
| Domain | `eucigs.com` | Passive DNS on the C2 IP |

## Lessons

- When an execution-parent or dropped-file card isn't a link, copy its hash into search and keep pivoting. The whole chain sat two hops away.
- The badge colour in a related-files list (⚠ vs ✓) is a quick malicious-vs-benign filter for "list the malicious ones" questions.
- Raw IOCs often don't index well on search engines; searching on the TTPs (platform + malware + technique) found the source report fast, and I then confirmed the IOCs inside it.
- Check which VM tab is active. TryHackMe can keep an earlier room's machine alive alongside the new one.
