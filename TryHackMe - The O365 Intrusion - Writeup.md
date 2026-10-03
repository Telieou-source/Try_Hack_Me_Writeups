# TryHackMe: The O365 Intrusion — Writeup

**Room type:** Guided / Incident Response  
**Category:** DFIR / Cloud / Microsoft 365  
**Tool:** Splunk  

---

## Scenario

An internal Support Operations Platform for Vantage Dynamics has been compromised. As an incident responder, the task is to reconstruct the attacker's actions across two compromised accounts — Marcus Webb and David Chen — using Microsoft 365 unified audit logs ingested into Splunk.

---

## Data Sources

| Sourcetype | Count | Purpose |
|---|---|---|
| `o365:management:activity` | 417 | Unified audit log — sign-ins, mail, SharePoint, Teams |
| `o365:graph:api` | 75 | Graph API activity |
| `o365:reporting:messagetrace` | 22 | Email delivery records |

The vast majority of investigative work lives in `o365:management:activity`. Email delivery confirmation comes from `o365:reporting:messagetrace`.

---

## Investigation

### Q1 — First non-macOS sign-in to Marcus Webb's account

**Answer: `2026-08-27 12:28:31`**

Marcus Webb's legitimate device was a MacOS machine at IP `41.128.55.10`, logging in consistently from 08:19 through 09:23. At 12:28, a Windows 10 device appeared from `185.220.101.47` — a Tor exit node.

The OS field lives inside a nested `DeviceProperties` JSON array. Extracting it requires `spath` with `mvexpand`:

```spl
index=* sourcetype="o365:management:activity" Operation="UserLoggedIn" 
UserId="marcus.webb@vantagedynamics.onmicrosoft.com"
| spath input=_raw path=DeviceProperties{} output=DeviceProperties
| mvexpand DeviceProperties
| spath input=DeviceProperties path=Name output=PropName
| spath input=DeviceProperties path=Value output=PropValue
| where PropName="OS" AND PropValue="Windows10"
| spath input=_raw path=ErrorNumber output=ErrorNumber
| table _time, ErrorNumber, PropValue, ClientIP
| sort _time
```

The first Windows10 event at 12:28:17 carried `ErrorNumber: 50140` — a "Keep Me Signed In" interrupt, not a completed authentication. The first successful login (`ErrorNumber: 0`) was at **12:28:31**.

---

### Q2 — Emails accessed in the first few minutes of the attacker's session

**Answer: `22`**

`MailItemsAccessed` events contain an `OperationCount` field reflecting the number of mail items touched per event. Four events occurred in the window following the 12:28:31 login:

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

| Time | OpCount | IP |
|---|---|---|
| 12:28:40 | 6 | 185.220.101.47 (attacker) |
| 12:28:43 | 2 | 185.220.101.47 (attacker) |
| 12:28:53 | 8 | 185.220.101.47 (attacker) |
| 12:29:55 | 6 | 2603:10b6:930:30::7 (Microsoft REST) |

Total: 6 + 2 + 8 + 6 = **22**. The attacker swept the inbox within 90 seconds of gaining access.

---

### Q3 — Subject line matched by the attacker's inbox rule

**Answer: `invoice`**

At 12:30:10 — less than two minutes after finishing the inbox sweep — the attacker created an inbox rule named "update":

```spl
index=* sourcetype="o365:management:activity" 
UserId="marcus.webb@vantagedynamics.onmicrosoft.com"
Operation="New-InboxRule"
| table _time, _raw
```

The rule parameters:

```json
{"Name": "SubjectContainsWords", "Value": "invoice"},
{"Name": "DeleteMessage", "Value": "True"},
{"Name": "StopProcessingRules", "Value": "True"}
```

Any email with "invoice" in the subject would be silently deleted before Marcus could see it — a business email compromise (BEC) pattern designed to intercept financial replies.

---

### Q4 — Time between inbox rule creation and a matching reply arriving

**Answer: `10 minutes 59 seconds`**

The message trace revealed the matching email:

```spl
index=* sourcetype="o365:reporting:messagetrace"
| where _time > strptime("2026-08-27 12:30:10", "%Y-%m-%d %H:%M:%S")
| search RecipientAddress="marcus.webb@vantagedynamics.onmicrosoft.com"
| table _time, Subject, SenderAddress
```

A reply with subject **"RE: Meridian invoice batch - please confirm"** arrived from `finance-team@vantagedynamics.onmicrosoft.com` at 12:41:09 and was delivered — then immediately deleted by the rule before Marcus saw it.

Rule created: 12:30:10  
Email arrived: 12:41:09  
Elapsed: **10 minutes 59 seconds**

---

### Q5 — File referenced in the attacker's Teams message

**Answer: `Meridian_Invoice_Batch_Aug2026.pdf`**

At 13:03:38, the attacker sent a Teams message to David Chen containing a SharePoint link:

```spl
index=* sourcetype="o365:management:activity" 
UserId="marcus.webb@vantagedynamics.onmicrosoft.com"
Operation="MessageCreatedHasLink"
| table _time, _raw
```

The `MessageFiles` field contained:

```
https://vantagedynamics.sharepoint.com/Shared%20Documents/Meridian_Invoice_Batch_Aug2026.pdf.pdf
```

The attacker used Marcus Webb's compromised account to send a malicious SharePoint link to David Chen — likely a phishing lure to pivot to Chen's account.

---

### Q6 — OS used in the suspicious sign-in to David Chen's account

**Answer: `Linux`**

David Chen's legitimate sessions all came from MacOS at `41.128.55.10` (same IP as Marcus Webb's legitimate device — likely a corporate proxy or VPN). At 13:27, a Linux device appeared from `91.219.237.88`:

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

---

### Q7 — IP address used in the suspicious sign-in to David Chen's account

**Answer: `91.219.237.88`**

Same query as Q6. The Linux device at `91.219.237.88` first appeared at 13:27:01 and continued through 14:47.

---

### Q8 — Time between the Teams message and the suspicious David Chen sign-in

**Answer: `23 minutes 26 seconds`**

The Teams message was sent at 13:03:38. The first successful Linux sign-in to David Chen's account (`ErrorNumber: 0`) was at 13:27:04 — the 13:27:01 event carried `ErrorNumber: 50140` (KMSI interrupt), same pattern as the Marcus Webb compromise.

Message sent: 13:03:38  
Successful login: 13:27:04  
Elapsed: **23 minutes 26 seconds**

---

### Q9 — Time the downloaded file was legitimately modified earlier that day

**Answer: `2026-08-27 08:27:03`**

The attacker navigated directly to the Leadership SharePoint site after logging in as David Chen and downloaded `Q4_Board_Financial_Summary.xlsx` at 13:28:31. To find the legitimate modification time:

```spl
index=* sourcetype="o365:management:activity" 
Operation="FileModified"
SourceFileName="Q4_Board_Financial_Summary.xlsx"
| where _time < strptime("2026-08-27 13:27:04", "%Y-%m-%d %H:%M:%S")
| table _time, UserId, SourceFileName
```

David Chen had modified the file himself at **08:27:03** — over five hours before the attacker downloaded it.

---

### Q10 — File on the Leadership site with a sensitivity label applied prior to the incident

**Answer: `Q4_Board_Financial_Summary.xlsx`**

```spl
index=* sourcetype="o365:management:activity" 
Operation IN ("FileSensitivityLabelApplied", "SensitivityLabelApplied", "SensitivityLabelUpdated")
| table _time, UserId, SourceFileName, ObjectId
```

David Chen applied a sensitivity label to `Q4_Board_Financial_Summary.xlsx` at 08:27:41 — 38 seconds after modifying it. The attacker specifically targeted this labeled file, suggesting prior knowledge of its contents.

---

### Q11 — File the attacker created an external sharing link for

**Answer: `Vendor_Onboarding_Notes.docx`**

After downloading the financial summary, the attacker used David Chen's account to create an external sharing invitation for a second file:

```spl
index=* sourcetype="o365:management:activity"
Operation IN ("SharingInvitationCreated", "SharingSet", "AnonymousLinkUpdated", "SharingLinkUpdated")
| where _time > strptime("2026-08-27 12:28:31", "%Y-%m-%d %H:%M:%S")
| table _time, UserId, Operation, SourceFileName, TargetUserOrGroupName
```

At 14:52, `Vendor_Onboarding_Notes.docx` was shared externally with a Guest account. Note the file appears in logs as `Vendor_Onboarding_Notes.docx.docx` — a double extension artifact in the environment.

---

### Q12 — External email address granted access to the file

**Answer: `d.reynolds88@protonmail.com`**

From the same query as Q11. The `TargetUserOrGroupName` field showed:

```
d.reynolds88_protonmail.com#ext#@vantagedynamics.onmicrosoft.com
```

This is the O365 external guest representation of `d.reynolds88@protonmail.com` — a ProtonMail address consistent with an attacker-controlled exfiltration destination.

---

### Q13 — Subject line of the sharing notification sent to the external address

**Answer: `David Chen shared "Vendor_Onboarding_Notes.docx" with you`**

```spl
index=* sourcetype="o365:reporting:messagetrace"
| search RecipientAddress="*reynolds*" OR RecipientAddress="*protonmail*"
| table _time, Subject, SenderAddress, RecipientAddress
```

SharePoint's `no-reply@sharepointonline.com` sent the notification at 14:52:44 — the same second the sharing invitation was created.

---

## Attack Timeline

```
08:23 – 09:24   David Chen logs in normally (MacOS, 41.128.55.10)
08:27:03        David Chen modifies Q4_Board_Financial_Summary.xlsx
08:27:41        David Chen applies sensitivity label to the file
08:19 – 09:23   Marcus Webb logs in normally (MacOS, 41.128.55.10)

12:28:17        Attacker hits Marcus Webb's account (Windows10, 185.220.101.47) — KMSI interrupt
12:28:31        Attacker successfully authenticates as Marcus Webb
12:28:40–53     Attacker reads 22 emails across Marcus Webb's inbox
12:30:10        Attacker creates inbox rule: delete emails containing "invoice"
12:41:09        Reply "RE: Meridian invoice batch - please confirm" arrives and is auto-deleted
13:03:38        Attacker sends Teams message to David Chen with malicious SharePoint link
13:27:04        Attacker successfully authenticates as David Chen (Linux, 91.219.237.88)
13:27:41–28:31  Attacker browses Leadership site, downloads Q4_Board_Financial_Summary.xlsx
14:52:35–44     Attacker creates external sharing link for Vendor_Onboarding_Notes.docx
14:52:44        SharePoint notifies d.reynolds88@protonmail.com
```

---

## Key Splunk Techniques

**Extracting nested JSON arrays** — O365 logs store device properties, folder items, and parameters as JSON arrays within the `_raw` field. The `spath` + `mvexpand` pattern is essential:

```spl
| spath input=_raw path=DeviceProperties{} output=DeviceProperties
| mvexpand DeviceProperties
| spath input=DeviceProperties path=Name output=PropName
| spath input=DeviceProperties path=Value output=PropValue
```

**Distinguishing failed from successful logins** — `ErrorNumber: 0` indicates success; `ErrorNumber: 50140` is the "Keep Me Signed In" prompt and should not be counted as a completed authentication.

**OperationCount vs unique items** — `MailItemsAccessed` events contain an `OperationCount` field that is more reliable than counting unique `ImmutableId` values, which can appear across multiple events for the same email.

**Message trace for email delivery** — `o365:management:activity` records mail access but not always delivery. `o365:reporting:messagetrace` confirms whether an email was actually delivered, which is essential for timing questions involving inbox rules.
