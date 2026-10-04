# TryHackMe: The O365 Intrusion — Writeup

**Room type:** Guided / Incident Response  
**Category:** DFIR / Cloud / Microsoft 365  
**Tool:** Splunk  

---

## Overview

Someone got into Vantage Dynamics' Microsoft 365 tenant and did a thorough job of it. Our role is incident responder, handed a Splunk instance loaded with O365 unified audit logs and asked to reconstruct exactly what happened. The questions walk us through the intrusion in chronological order — which turns out to be a two-account compromise with a BEC play in the middle and a data exfiltration at the end.

The first thing to do in any log investigation is orient. Before touching a single question, run this to see what we're working with:

```spl
index=* | stats count by sourcetype | sort -count
```

```
o365:management:activity    417
o365:graph:api               75
o365:reporting:messagetrace  22
```

Three sourcetypes. The unified audit log (`o365:management:activity`) is going to carry almost everything — sign-ins, mail access, inbox rules, Teams messages, SharePoint file operations. The message trace (`o365:reporting:messagetrace`) is a separate pipeline that tracks email delivery, which becomes important later when we need to know whether an email actually landed in someone's inbox. We'll keep that one in mind.

---

## Q1 — What is the first timestamp at which a non-macOS device signed into Marcus Webb's account?

**Answer: `2026-08-27 12:28:31`**

The question tells us Marcus normally uses macOS — so the attacker is the first session that isn't. Start by pulling all of Webb's sign-in events and looking for the OS field:

```spl
index=* sourcetype="o365:management:activity" Operation="UserLoggedIn" 
UserId="marcus.webb@vantagedynamics.onmicrosoft.com"
| spath input=_raw path=DeviceProperties{} output=DeviceProperties
| mvexpand DeviceProperties
| spath input=DeviceProperties path=Name output=PropName
| spath input=DeviceProperties path=Value output=PropValue
| where PropName="OS"
| table _time, PropValue, ClientIP
| sort _time
```

The OS field isn't a top-level field — it lives inside a `DeviceProperties` array of name/value pairs nested in the raw JSON. The `spath` + `mvexpand` combo unpacks it. What comes back is a clean picture: every login from 08:19 through 09:23 is MacOS from `41.128.55.10`. Then at 12:28, Windows 10 shows up from `185.220.101.47` — a completely different IP, and a completely different device class.

That's the attacker. But we need to be precise about the timestamp. Adding an `ErrorNumber` filter reveals the problem:

```spl
| spath input=_raw path=ErrorNumber output=ErrorNumber
| where PropValue="Windows10"
| table _time, ErrorNumber, ClientIP
```

The first Windows 10 event at 12:28:17 carries `ErrorNumber: 50140` — Microsoft's code for the "Keep Me Signed In?" prompt. That's an authentication interrupt, not a completed login. The attacker clicked through it, and the actual successful authentication (`ErrorNumber: 0`) landed nine seconds later at **12:28:31**. That's when the clock starts.

---

## Q2 — How many emails were accessed during the attacker's initial window?

**Answer: `22`**

A competent attacker's first move after getting into a mailbox is reconnaissance — read the inbox, understand who this person is, what they're working on, what's sensitive. We'd expect to see a burst of mail access right after login.

The operation to look for is `MailItemsAccessed`. But there's a subtlety: each event can cover multiple emails in one shot, and the raw event has an `OperationCount` field that tells you exactly how many items were touched:

```spl
index=* sourcetype="o365:management:activity" 
UserId="marcus.webb@vantagedynamics.onmicrosoft.com"
Operation="MailItemsAccessed"
| where _time >= strptime("2026-08-27 12:28:31", "%Y-%m-%d %H:%M:%S")
| where _time <= strptime("2026-08-27 12:33:00", "%Y-%m-%d %H:%M:%S")
| spath input=_raw path=OperationCount output=OpCount
| table _time, OpCount, ClientIPAddress
| sort _time
```

Four events in the window:

| Time | OpCount | Source |
|---|---|---|
| 12:28:40 | 6 | 185.220.101.47 (attacker) |
| 12:28:43 | 2 | 185.220.101.47 (attacker) |
| 12:28:53 | 8 | 185.220.101.47 (attacker) |
| 12:29:55 | 6 | 2603:10b6:930:30::7 (Microsoft REST) |

That last event is a Microsoft backend system — not the attacker's browser — but it's still mailbox access in the window, and the question asks for total emails accessed, not just from the attacker's IP. 6 + 2 + 8 + 6 = **22**.

The attacker swept 22 emails in under 90 seconds. That's not casual reading — that's systematic reconnaissance of a mailbox. The subjects they hit included financial notifications, password resets, and a Teams missed-activity email from David Chen. That last one was almost certainly what pointed them at their next target.

We initially tried counting unique `ImmutableId` values across the `FolderItems` arrays, which gave us 14. That was wrong — deduplication undercounted because some items appeared in multiple events. The `OperationCount` sum is more reliable.

---

## Q3 — What subject line does the attacker's inbox rule match on?

**Answer: `invoice`**

Less than two minutes after finishing the inbox sweep, the attacker created an inbox rule. That timing is deliberate: they read the emails, spotted a financial thread, and immediately set up a suppression mechanism before doing anything else.

```spl
index=* sourcetype="o365:management:activity" 
UserId="marcus.webb@vantagedynamics.onmicrosoft.com"
Operation="New-InboxRule"
| table _time, _raw
```

The rule is named "update" — innocuous enough to avoid attention — and its parameters tell the whole story:

```json
{"Name": "SubjectContainsWords", "Value": "invoice"},
{"Name": "DeleteMessage",        "Value": "True"},
{"Name": "StopProcessingRules",  "Value": "True"}
```

Any email with "invoice" in the subject gets silently deleted. `StopProcessingRules: True` means no other rule will run after it. The attacker was planning to send fraudulent invoice communications on Marcus Webb's behalf, and needed to make sure any replies from colleagues — "hey, this looks wrong," "can you confirm this payment?" — would disappear before the real Marcus could see them. Classic BEC playbook.

---

## Q4 — How much time elapsed between the inbox rule being created and a matching reply arriving?

**Answer: `10 minutes 59 seconds`**

The rule was created at 12:30:10. Now we need to find whether an invoice-related email actually arrived in the window — and for that, we pivot to the message trace, because `o365:management:activity` logs mail access but not always delivery:

```spl
index=* sourcetype="o365:reporting:messagetrace"
| where _time > strptime("2026-08-27 12:30:10", "%Y-%m-%d %H:%M:%S")
| search RecipientAddress="marcus.webb@vantagedynamics.onmicrosoft.com"
| table _time, Subject, SenderAddress, Status
```

At 12:41:09, an email with subject **"RE: Meridian invoice batch - please confirm"** arrived from `finance-team@vantagedynamics.onmicrosoft.com` — status: Delivered. Delivered to the server, that is. The inbox rule would have deleted it before Marcus ever saw it.

This is the moment the BEC play completes. The attacker sent some form of fraudulent invoice communication (probably via a separate channel we don't have logs for), the finance team replied to confirm, and the reply vanished. Marcus Webb had no idea any of this happened.

12:41:09 − 12:30:10 = **10 minutes 59 seconds**.

---

## Q5 — What file did the Teams link reference?

**Answer: `Meridian_Invoice_Batch_Aug2026.pdf`**

With the BEC play complete on Marcus Webb's account, the attacker pivoted. At 13:03:38 — about 22 minutes after the invoice reply was intercepted — they sent a Teams message to David Chen using Marcus Webb's account:

```spl
index=* sourcetype="o365:management:activity" 
UserId="marcus.webb@vantagedynamics.onmicrosoft.com"
Operation="MessageCreatedHasLink"
| table _time, _raw
```

The `MessageFiles` array in the raw event contained a SharePoint URL pointing to `Meridian_Invoice_Batch_Aug2026.pdf`. This was the lure — a file with a name that would read as completely normal to a finance or operations contact. "Marcus" was asking David to look at an invoice batch document. The link would either deliver malware or harvest credentials. Whatever it did, it worked: David Chen's account showed a suspicious login 23 minutes later.

---

## Q6 — What OS was used in the suspicious sign-in to David Chen's account?

**Answer: `Linux`**

Same query structure as Q1, different user:

```spl
index=* sourcetype="o365:management:activity" Operation="UserLoggedIn"
UserId="david.chen@vantagedynamics.onmicrosoft.com"
| spath input=_raw path=DeviceProperties{} output=DeviceProperties
| mvexpand DeviceProperties
| spath input=DeviceProperties path=Name output=PropName
| spath input=DeviceProperties path=Value output=PropValue
| where PropName="OS"
| table _time, PropValue, ClientIP
| sort _time
```

David Chen's entire morning was MacOS from `41.128.55.10` — the same IP as Marcus Webb's legitimate sessions, suggesting a corporate proxy or split-tunnel VPN. Then at 13:27, Linux appeared from a new IP. The attacker's tooling changed between the two accounts — Windows 10 browser for Webb, Linux for Chen. Possibly different operator infrastructure, possibly a second stage tool.

---

## Q7 — What IP address was used in this sign-in?

**Answer: `91.219.237.88`**

Same query as Q6. The Linux device at `91.219.237.88` — a different address from the `185.220.101.47` used against Marcus Webb. Two different source IPs for two different account compromises on the same day points to either a VPN infrastructure being rotated between accounts, or a second actor working in parallel.

---

## Q8 — How much time passed between the Teams message and the suspicious sign-in to David Chen's account?

**Answer: `23 minutes 26 seconds`**

The Teams message was sent at 13:03:38. For the sign-in, we apply the same `ErrorNumber` check as Q1 — the first Linux event at 13:27:01 is `ErrorNumber: 50140` (KMSI interrupt again), and the first successful authentication is at 13:27:04.

13:27:04 − 13:03:38 = **23 minutes 26 seconds**.

That 23-minute gap is the time it took David Chen to receive the Teams message, click the link, and get his credentials harvested. From the attacker's perspective, the lure worked faster than most phishing campaigns.

---

## Q9 — The file the attacker downloaded was legitimately modified earlier that day. At what time?

**Answer: `2026-08-27 08:27:03`**

After logging in as David Chen, the attacker went straight to the Leadership SharePoint site — a privileged document library that a standard helpdesk user wouldn't have had access to. The navigation was deliberate: they browsed the folder listing, accessed `Q4_Board_Financial_Summary.xlsx`, and downloaded it at 13:28:31.

To find the legitimate modification time:

```spl
index=* sourcetype="o365:management:activity" 
Operation="FileModified"
SourceFileName="Q4_Board_Financial_Summary.xlsx"
| where _time < strptime("2026-08-27 13:27:04", "%Y-%m-%d %H:%M:%S")
| table _time, UserId, SourceFileName
```

David Chen had modified that file at **08:27:03** — five hours before the attacker downloaded it. Legitimate business activity in the morning, exfiltration in the afternoon. The attacker knew what they were looking for.

---

## Q10 — What file stored on the Leadership site had a sensitivity label applied prior to the incident?

**Answer: `Q4_Board_Financial_Summary.xlsx`**

```spl
index=* sourcetype="o365:management:activity" 
Operation IN ("FileSensitivityLabelApplied", "SensitivityLabelApplied", "SensitivityLabelUpdated")
| table _time, UserId, SourceFileName, ObjectId
```

At 08:27:41 — 38 seconds after modifying it — David Chen applied a sensitivity label to the same file. The organization's data governance had flagged this document as sensitive. The attacker downloaded it anyway, either because they already knew the label existed, or because they were sweeping everything in the Leadership library regardless. Either way, the sensitivity label did nothing to stop the exfiltration — it only helps us identify what was taken as high-value.

---

## Q11 — What file did the attacker create an external sharing link for?

**Answer: `Vendor_Onboarding_Notes.docx`**

The financial summary was the primary target, but the attacker didn't stop there. After downloading it, they created an external sharing link for a second document:

```spl
index=* sourcetype="o365:management:activity"
Operation IN ("SharingInvitationCreated", "SharingSet", "AnonymousLinkUpdated", "SharingLinkUpdated")
| where _time > strptime("2026-08-27 12:28:31", "%Y-%m-%d %H:%M:%S")
| table _time, UserId, Operation, SourceFileName, TargetUserOrGroupName
```

At 14:52, `Vendor_Onboarding_Notes.docx` was shared to an external guest. The file appears in the logs with a double extension — `Vendor_Onboarding_Notes.docx.docx` — which is an artifact of how this particular SharePoint environment names things, not attacker manipulation.

---

## Q12 — What external email address was granted access?

**Answer: `d.reynolds88@protonmail.com`**

From the same query. The `TargetUserOrGroupName` field shows the O365 external guest representation:

```
d.reynolds88_protonmail.com#ext#@vantagedynamics.onmicrosoft.com
```

That resolves to `d.reynolds88@protonmail.com` — ProtonMail, end-to-end encrypted, anonymous by default. This is the attacker's exfiltration address. SharePoint's sharing mechanism does the delivery work for them: instead of uploading the file somewhere, they just grant their own external address read access and let Microsoft's infrastructure handle the transfer.

---

## Q13 — What is the subject line of the notification sent to the external address?

**Answer: `David Chen shared "Vendor_Onboarding_Notes.docx" with you`**

```spl
index=* sourcetype="o365:reporting:messagetrace"
| search RecipientAddress="*reynolds*" OR RecipientAddress="*protonmail*"
| table _time, Subject, SenderAddress, RecipientAddress
```

At 14:52:44 — the exact second the sharing invitation was created — `no-reply@sharepointonline.com` sent the notification. Microsoft's own infrastructure delivered a ready-to-click access link to the attacker's inbox. From `d.reynolds88@protonmail.com`'s perspective, they received a standard SharePoint share notification indistinguishable from a legitimate one.

---

## Full Attack Timeline

```
08:19–09:23     Marcus Webb logs in normally (MacOS, 41.128.55.10)
08:23–09:24     David Chen logs in normally (MacOS, 41.128.55.10)
08:27:03        David Chen modifies Q4_Board_Financial_Summary.xlsx
08:27:41        David Chen applies sensitivity label to the file

12:28:17        Attacker hits Marcus Webb's account (Windows10, 185.220.101.47) — KMSI interrupt
12:28:31        Attacker successfully authenticates as Marcus Webb
12:28:40–53     Attacker reads 22 emails — spots invoice thread and David Chen's missed Teams message
12:30:10        Attacker creates inbox rule: silently delete anything with "invoice" in subject
12:41:09        Finance team's reply "RE: Meridian invoice batch - please confirm" arrives and is auto-deleted
13:03:38        Attacker sends Teams message to David Chen from Marcus's account with malicious SharePoint link
13:27:04        Attacker successfully authenticates as David Chen (Linux, 91.219.237.88)
13:27:41        Attacker browses Leadership SharePoint site
13:28:22        Attacker accesses Q4_Board_Financial_Summary.xlsx
13:28:31        Attacker downloads Q4_Board_Financial_Summary.xlsx
14:52:35        Attacker creates anonymous/sharing link for Vendor_Onboarding_Notes.docx
14:52:44        Attacker creates sharing invitation for d.reynolds88@protonmail.com
14:52:44        SharePoint sends access notification to d.reynolds88@protonmail.com
```

---

## Investigative Notes

**The `DeviceProperties` problem.** O365 unified audit logs store device information — OS, browser, compliance status — inside a nested JSON array, not as flat fields. Splunk won't extract these automatically. The `spath` + `mvexpand` pattern is the standard way to unpack them, and it's something worth having in a saved search for any O365 investigation that involves device attribution.

**`ErrorNumber` matters more than `ResultStatus`.** Both logins initially showed `ResultStatus: Success` in the raw event, but the `ErrorNumber: 50140` on the first Windows 10 event meant the authentication wasn't actually complete. Relying on `ResultStatus` alone would have given us the wrong timestamp for when the attacker was actually inside the account.

**`OperationCount` beats counting individual items.** `MailItemsAccessed` events batch multiple emails together, and the same email can appear in multiple events. Summing `OperationCount` across events gives the total number of mail access operations Microsoft logged — which is what the question was asking for. Trying to deduplicate by `ImmutableId` undercounted because deduplication doesn't account for the batching behavior.

**The message trace is a separate pipeline.** `o365:management:activity` tells you when the inbox rule was created and when `MailItemsAccessed` events happened. But to confirm that the "invoice" email actually arrived and was delivered to the server — which it was, before the rule deleted it — you need `o365:reporting:messagetrace`. These are different systems and they don't always agree on timing or coverage.

**SharePoint sharing as an exfiltration mechanism.** The attacker didn't exfiltrate `Vendor_Onboarding_Notes.docx` by downloading it and uploading it somewhere. They granted their ProtonMail address Guest access via SharePoint's standard sharing feature, then let Microsoft's own notification system deliver the access link. From a network-level perspective, this looks like a normal SharePoint share. The only signal is in the audit log — a `SharingInvitationCreated` event with an external ProtonMail recipient.
