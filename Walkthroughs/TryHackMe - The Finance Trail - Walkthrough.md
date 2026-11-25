# TryHackMe: The Finance Trail — Walkthrough

2026-10-17

A forensic investigation into a phishing-to-exfiltration attack chain against a finance workstation. Ten questions answered entirely through Splunk SPL across five log sources: endpoint (Sysmon XML), mail (RFC 822), network (Suricata JSON), web (Nginx JSON), and file events.

## Setup & Access

The machine runs Splunk at `http://10.144.130.14:8000` (or via THM reverse proxy). Connect to the THM network first with `sudo openvpn ~/us-west-2-<username>-premium.ovpn`, then RDP in with `xfreerdp /v:10.144.130.14 /u:analyst /p:analyst /dynamic-resolution`. If the machine returns a 502, restart it from the THM room page — the reverse proxy URL changes with the new IP.

Once inside, open Splunk in the browser. All five indexes are pre-loaded:

| Index | Sourcetype | Contents |
| --- | --- | --- |
| finance\_endpoint | finance:windows:xml | Sysmon XML (EventID 1, 11, 5156) |
| finance\_mail | finance:mail:rfc822 | Raw RFC 822 email messages |
| finance\_network | finance:network:suricata:json | Suricata alerts (HTTP, DNS, SMB) |
| finance\_web | finance:web:nginx:json | Nginx access logs |
| finance\_files | finance:windows:xml | File system events |

All timestamps in the evidence are UTC. The attack occurred on 2026-10-09 starting around 02:29.

## Q1 — Identifying the Phishing Campaign

**Answer:** `lawson-rowe-review.com`

The question asked for the sender domain of the phishing email that kicked off the attack. I started in the mail index, searching for external senders around the attack window:

```
index=finance_mail sourcetype="finance:mail:rfc822"
| search sender_address!="*vantara*"
| table _time, sender_address, mail_subject, message_id
| sort _time
```

This returned an email from `disclosures@lawson-rowe-review.com` with subject `Disclosure Schedule Update — Action Required`, arriving at 02:29:02. The domain `lawson-rowe-review.com` was clearly anomalous — all other external mail in the logs came from known counterparties.

To confirm it was actually acted on, I pivoted to the Nginx web logs and searched for ZIP downloads on 2026-10-09:

```
index=finance_web sourcetype="finance:web:nginx:json" status=200
| search uri="*.zip*"
| eval t=strftime(_time,"%H:%M:%S")
| where t > "02:25" AND t < "02:40"
| table _time, uri, client_ip
```

At 02:33:16 — four minutes after the email — a GET for `/downloads/Disclosure_Schedule_Update.zip` came back 200. Every other ZIP in the logs lived under structured paths like `/accounts/downloads/` or `/trade/downloads/`. This bare `/downloads/` path was unique to the attacker’s staging server, confirming the domain.

## Q2 — Tracing the Initial Execution

**Answer:** `VantaraFinancePortal.exe`

The question asked which process launched Chrome to open the phishing URL. I searched Sysmon EventID=1 (process creation) for any Chrome invocation that carried the attacker’s domain:

```
index=finance_endpoint sourcetype="finance:windows:xml" EventID=1
| search Image="*chrome*" CommandLine="*lawson-rowe-review*"
| table _time, ParentImage, Image, CommandLine
```

The result showed Chrome spawned at 02:33:13 with command line `"chrome.exe" http://lawson-rowe-review.com/review/disclosure-schedule`. The `ParentImage` field pointed directly to `C:\Program Files\Vantara\Finance Client\VantaraFinancePortal.exe` — the legitimate finance portal had been weaponised to auto-open the phishing URL, likely as a result of the ZIP payload executing.

## Q3 — Recovering the Payload Hash

**Answer:** `98D66005B3F2CFD556EEF503EC1ADA73DE34C24D3800D41D8E30C43AF32DEDEF`

Sysmon EventID=15 (FileCreateStreamHash) fires when a browser writes a file with an Alternate Data Stream — Chrome’s mark-of-the-web mechanism. I searched for it filtering on the ZIP filename:

```
index=finance_endpoint sourcetype="finance:windows:xml" EventID=15
| search TargetFilename="*Disclosure_Schedule_Update*"
| table _time, TargetFilename, SHA256
```

The hash returned was `98D66005B3F2CFD556EEF503EC1ADA73DE34C24D3800D41D8E30C43AF32DEDEF`. EventID=15 is the right event to use here because it captures the hash at the moment Chrome committed the download — before any post-download modification could occur.

## Q4 — Linking the Loader to the Sync Client

**Answer:** `AAD4B231C4AFC7D02A09344545A957086FE36CD6A9CCA8F1F92E1AC3DDFFAC5C`

The question asked for the hash shared by `ledgerdrop.exe` and `VantaraSync.exe`, which would confirm they’re the same binary masquerading under two names. I queried EventID=1 for both:

```
index=finance_endpoint sourcetype="finance:windows:xml" EventID=1
| search Image="*ledgerdrop*" OR Image="*VantaraSync*"
| table _time, Image, SHA256, CommandLine
```

Both processes returned hash `AAD4B231C4AFC7D02A09344545A957086FE36CD6A9CCA8F1F92E1AC3DDFFAC5C`. The loader (`ledgerdrop.exe`) ran first and dropped the sync client (`VantaraSync.exe`) — both being the same file confirms the loader left a copy of itself behind under a more legitimate-looking name.

## Q5 — Malicious Scheduled Task

**Answer:** `VantaraUpdateCheck`

I searched EventID=1 for `schtasks.exe` invocations spawned by the loader, since scheduled task creation via command line shows up as a child process of the creating executable:

```
index=finance_endpoint sourcetype="finance:windows:xml" EventID=1
| search Image="*schtasks*"
| table _time, ParentImage, CommandLine
```

Two tasks appeared. One was created by `ledgerdrop.exe`: `schtasks /create /tn VantaraUpdateCheck /tr "C:\Users\maya.chen\AppData\Roaming\VantaraSync.exe" /sc MINUTE /mo 15`. The other, `FinanceTemplateRefresh`, was created by `VantaraDocumentSync.exe` — a legitimate Vantara process. The malicious one was `VantaraUpdateCheck`, named to blend in with legitimate Vantara tooling.

## Q6 — Time to First Callback

**Answer:** `47` seconds

I needed the exact creation time of `VantaraSync.exe` from Sysmon EventID=1, and the timestamp of its first HTTP callback in the Nginx logs.

For the process creation time I queried:

```
index=finance_endpoint sourcetype="finance:windows:xml" EventID=1
| search Image="*VantaraSync*"
| table UtcTime, Image
```

This returned `2026-10-09 02:33:26.240`.

For the first callback I queried the Nginx logs for requests to the attacker’s domain after that time. The Nginx log timestamps are Unix epoch integers, so I had to convert:

```
index=finance_web sourcetype="finance:web:nginx:json"
| search http_host="*lawsonreview*" OR http_host="*lawson-rowe*"
| eval readable=strftime(time,"%Y-%m-%d %H:%M:%S")
| table time, readable, uri, status
| sort time
| head 1
```

The first callback hit epoch `1791513253`, which converts to `02:34:13 UTC`. The gap was 47.76 seconds — rounded to **47 whole seconds**.

## Q7 — Correlating Network Events

**Answer:** `50611`

The question asked for the TCP source port that appears in both the Suricata HTTP event and the Sysmon WFP (EventID=5156) network connection record for the same callback at 02:34:13.

I first found the Suricata HTTP event at that timestamp and pulled the source port:

```
index=finance_network sourcetype="finance:network:suricata:json" event_type=http
| where timestamp >= "2026-10-09T02:34:13" AND timestamp < "2026-10-09T02:34:14"
| table timestamp, src_ip, src_port, dest_ip, http.hostname
```

Src port was `50611`. I then confirmed the same port in the WFP log:

```
index=finance_endpoint sourcetype="finance:windows:xml" EventID=5156
| search SourcePort=50611
| table UtcTime, SourceIp, SourcePort, DestAddress, DestPort
```

The WFP event at 02:34:13.444 matched exactly — same source port, same destination IP. This cross-source correlation is the reliable way to tie a Suricata packet-level event to its originating process on the host.

## Q8 — Failover Timing

**Answer:** `8.307` ms

At 02:53:21 the implant received a 503 from `cdn-lawsonreview.net` and needed to find the gap between that failure and the last DNS resolution that told it where to go next (`api-lawsoncdn.net`).

I found the 503 event first:

```
index=finance_network sourcetype="finance:network:suricata:json" event_type=http
| search http.http_host="cdn-lawsonreview.net" http.status=503
| table timestamp, src_port, http.http_host, http.status
```

Timestamp: `2026-10-09T02:53:21.531963+0000`.

Then I found the most recent DNS A answer for `api-lawsoncdn.net` before that moment:

```
index=finance_network sourcetype="finance:network:suricata:json" event_type=dns
| search "dns.answers{}.rrname"="api-lawsoncdn.net" dns.type=response
| where timestamp < "2026-10-09T02:53:21.531963"
| table timestamp, "dns.answers{}.rdata"
| sort -timestamp
| head 1
```

Timestamp: `2026-10-09T02:53:21.523656+0000`, rdata `192.0.2.77`.

Gap in microseconds: `531963 − 523656 = 8307 µs = **8.307 ms**`. The implant queried DNS, got an answer, immediately attempted the primary C2, received a 503, and pivoted to the backup — all within 8.3 milliseconds.

## Q9 — PID Reuse

**Answer:** `elevation_service.exe`

Windows reuses process IDs once a process exits. The question asked what executable last ran with the same PID as the PowerShell process that created the archive — a forensic technique for reconstructing PID history.

First I found the PowerShell process that created the archive (EventID=11, FileCreateStreamHash is not the right event here — EventID=11 is FileCreate):

```
index=finance_endpoint sourcetype="finance:windows:xml" EventID=11
| search TargetFilename="*review_notes_2026.zip*"
| table UtcTime, Image, ProcessId
```

PowerShell ran with PID **692**, creating the file at 02:53:29.688. The command confirmed it was `Compress-Archive` archiving `C:\Users\maya.chen\Documents\BoardReview\*`.

Then I queried for any other EventID=1 with ProcessId=692, strictly before PowerShell’s own start time of 02:53:28.528:

```
index=finance_endpoint sourcetype="finance:windows:xml" EventID=1 ProcessId=692
| eval t=strptime(UtcTime, "%Y-%m-%d %H:%M:%S.%3N")
| where t < strptime("2026-10-09 02:53:28.528", "%Y-%m-%d %H:%M:%S.%3N")
| table UtcTime, Image, ProcessId
| sort -UtcTime
| head 1
```

Result: `C:\Program Files\Google\Chrome\Application\155.0.8059.40\elevation_service.exe` at 02:33:14. Chrome’s elevation service spawned with PID 692 early in the session, terminated when Chrome closed, and Windows reassigned that PID to PowerShell nearly 20 minutes later.

## Q10 — Time to Exfiltration

**Answer:** `11` seconds

The question asked how many whole seconds elapsed between Sysmon recording the ZIP file creation and Suricata seeing the first successful SMB2 WRITE to the file share.

I already had the Sysmon file creation time from Q9: `02:53:29.688`.

For the SMB WRITE I searched Suricata after that timestamp. My first attempt with `event_type=smb` and field filters on `smb2.command` returned nothing, so I broadened to keyword search and confirmed SMB negotiation starting at 02:53:40. Then I searched specifically for the WRITE:

```
index=finance_network sourcetype="finance:network:suricata:json" event_type=smb
| where timestamp > "2026-10-09T02:53:29"
| search "SMB2_COMMAND_WRITE" "STATUS_SUCCESS"
| table timestamp, smb.command, smb.status
| sort timestamp
| head 1
```

First successful WRITE at `02:53:40.986626`.

Gap: `40.987 − 29.688 = 11.299` seconds — **11 whole seconds**. The 11-second window covers the SMB handshake (negotiate → session setup → tree connect → create file → write), which is consistent with authenticating via NTLM to the file share before the first write could land.

## Answers Summary

| # | Question | Answer |
| --- | --- | --- |
| Q1 | Sender domain of phishing email | `lawson-rowe-review.com` |
| Q2 | Process that opened the phishing URL | `VantaraFinancePortal.exe` |
| Q3 | SHA-256 of downloaded ZIP | `98D66005B3F2CFD556EEF503EC1ADA73DE34C24D3800D41D8E30C43AF32DEDEF` |
| Q4 | Shared hash of ledgerdrop.exe & VantaraSync.exe | `AAD4B231C4AFC7D02A09344545A957086FE36CD6A9CCA8F1F92E1AC3DDFFAC5C` |
| Q5 | Malicious scheduled task name | `VantaraUpdateCheck` |
| Q6 | Seconds from VantaraSync creation to first callback | `47` |
| Q7 | Source port linking Suricata HTTP to WFP event | `50611` |
| Q8 | ms between DNS answer for next host and 503 | `8.307` |
| Q9 | .exe that last used PowerShell's PID before it | `elevation_service.exe` |
| Q10 | Whole seconds from file creation to SMB2 WRITE | `11` |
