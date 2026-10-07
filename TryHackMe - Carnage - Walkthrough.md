# TryHackMe: Carnage — Walkthrough

**Room type:** DFIR / PCAP Analysis  
**Category:** Network Forensics  
**Tools:** Wireshark  
**Credit:** Brad Duncan / malware-traffic-analysis.net  

---

## Overview

A phishing email with a Word document attachment was delivered to Eric Fischer at Bartell Ltd. Upon opening the document and enabling macros, the workstation (`10.9.23.102`) began making suspicious outbound connections. The network sensor captured a PCAP of the activity, which we analyze here to reconstruct the full infection chain.

The infection follows a classic macro-based malware pattern: document → macro execution → zip/XLS payload download → secondary payload downloads → Qakbot C2 → Cobalt Strike beaconing → SMTP spam relay. The timeline spans roughly 20 minutes from initial compromise to active malspam activity.

---

## Environment and Setup

The PCAP is loaded in Wireshark on the THM split-screen machine. The victim host is `10.9.23.102` on the `goingfortune.com` domain. The internal DNS server is `10.9.23.5`.

Key Wireshark views used throughout:
- `Statistics → HTTP → Requests` for a summary of all HTTP activity
- `Statistics → Endpoints → IPv4` for traffic volume by IP
- `dns.flags.response == 1` for DNS resolution mapping
- `http.request` for plaintext download traffic
- `tls.handshake.extensions_server_name` for HTTPS destinations
- `smtp` for mail relay traffic

---

## Q1 — First HTTP Connection to Malicious IP

**Filter:** `http.request`

Sorting by time, the earliest outbound HTTP GET is frame 1735 at timestamp 56.248 seconds into the capture:

```
GET /incidunt-consequatur/documents.zip HTTP/1.1
Host: attirenepal.com
```

**Answer: `2021-09-24 16:44:38`**

The frame details show:
- Arrival Time: Sep 24, 2021 16:44:38.990412000 UTC
- Destination: `85.187.128.24` (attirenepal.com)
- Source port 62245 → Destination port 80

---

## Q2 — Name of the Downloaded Zip File

Visible directly in the GET request URI of frame 1735.

**Answer: `documents.zip`**

---

## Q3 — Domain Hosting the Malicious Zip

The HTTP Host header in frame 1735 identifies the hosting domain.

**Answer: `attirenepal.com`**

The DNS resolution for attirenepal.com (frame 1649) confirms this resolves to `85.187.128.24`.

---

## Q4 — File Inside the Zip

The HTTP response (frame 2173) contains the zip file data. The zip local file header at offset 0x01f4 in the raw data contains the filename bytes:

`63 68 61 72 74 2d 31 35 33 30 30 37 36 35 39 31 2e 78 6c 73`

Decoding: `chart-1530076591.xls`

**Answer: `chart-1530076591.xls`**

The ZIP central directory structure is visible in the chunked HTTP response data — no extraction needed.

---

## Q5 — Web Server of the Malicious IP

The HTTP response headers in frame 2173 include:

```
server: LiteSpeed
```

**Answer: `LiteSpeed`**

---

## Q6 — Web Server Version

From the same HTTP response headers:

```
x-powered-by: PHP/7.2.34
```

**Answer: `PHP/7.2.34`**

---

## Q7 — Three Domains Involved in Malicious File Downloads

After the XLS macro executed, three HTTPS connections to compromised legitimate websites served secondary payloads. These are visible in the TLS Client Hello SNI fields shortly after the initial zip download, and confirmed via DNS responses in the capture:

- `finejewels.com.au` → `148.72.192.206` (DNS frame 2423, TLS SNI at 16:45:11)
- `thietbiagt.com` → `210.245.90.247` (DNS frame 2998, TLS SNI at 16:45:21)
- `new.americold.com` → `148.72.53.144` (DNS frame 3225, TLS SNI at 16:45:25)

Note: `attirenepal.com` hosted the initial zip but is not counted here — this question specifically targets the secondary payload download domains reached by the macro after the XLS opened.

**Answer: `finejewels.com.au, thietbiagt.com, new.americold.com`**

---

## Q8 — Certificate Authority for the First Domain

The TLS certificate for `finejewels.com.au` is visible in the Server Hello handshake (frame at 16:45:12). Decoding the issuer field from the certificate bytes:

`47 6f 20 44 61 64 64 79 20 53 65 63 75 72 65...` → `Go Daddy Secure Certificate Authority - G2`

The root CA is GoDaddy.

**Answer: `GoDaddy`**

---

## Q9 — Two Cobalt Strike C2 IP Addresses

From the endpoint statistics, the two highest-traffic non-Microsoft IPs that don't resolve to known legitimate services are:

- `185.106.96.158` — resolves to `survmeter.live` (DNS frame 6511)
- `185.125.204.174` — resolves to `securitybusinpuff.com` (DNS frame 4494)

Both IPs are confirmed as Cobalt Strike C2 servers via VirusTotal Community tab tags.

Note: `23.111.114.52` and `136.232.34.70` (the two highest-traffic IPs overall) are Qakbot C2, not Cobalt Strike.

**Answer: `185.106.96.158, 185.125.204.174`**

---

## Q10 — Host Header for the First Cobalt Strike IP

Filtering HTTP traffic to `185.106.96.158` reveals a GET request whose Host header is:

```
GET /spfooh/cacerts.crl HTTP/1.1
Host: ocsp.verisign.com
```

This is a classic Cobalt Strike malleable C2 profile technique — the beacon masquerades as legitimate OCSP certificate validation traffic using a spoofed Host header, while the actual destination IP is the C2 server. The `/spfooh/` path is the tell.

**Answer: `ocsp.verisign.com`**

---

## Q11 — Domain Name for the First Cobalt Strike IP

DNS resolution from frame 6511:

```
survmeter.live → 185.106.96.158
```

**Answer: `survmeter.live`**

---

## Q12 — Domain Name for the Second Cobalt Strike IP

DNS resolution from frame 4494:

```
securitybusinpuff.com → 185.125.204.174
```

**Answer: `securitybusinpuff.com`**

---

## Q13 — Domain of Post-Infection Traffic

From `Statistics → HTTP → Requests`, `maldivehost.net` generated 26 HTTP POST requests with base64-encoded URI paths, all following the same pattern:

```
POST /zLIisQRWZI9/<base64_data>= HTTP/1.1
Host: maldivehost.net
```

The heavily obfuscated POST paths with rotating base64 payloads are the signature of Qakbot's HTTP-based C2 beaconing.

**Answer: `maldivehost.net`**

---

## Q14 — First Eleven Characters Sent to the C2

The first POST request to `maldivehost.net` begins with the URI path `/zLIisQRWZI9/`. The first 11 characters of the path (after the leading slash) are the consistent prefix across all beacons.

**Answer: `zLIisQRWZI9`**

---

## Q15 — Length of the First Packet Sent to the C2

Clicking on the first POST request packet to `208.91.128.6` (maldivehost.net) and checking the frame length in the packet details pane:

**Answer: `281`**

---

## Q16 — Server Header for the Post-Infection Domain

The HTTP response from `208.91.128.6` includes:

```
Server: Apache/2.4.49 (cPanel) OpenSSL/1.1.1l mod_bwlimited/1.4
```

**Answer: `Apache/2.4.49 (cPanel) OpenSSL/1.1.1l mod_bwlimited/1.4`**

---

## Q17 — DNS Query Timestamp for the IP Check Domain

Malware commonly queries an IP-lookup API to determine the victim's public IP before phoning home. Filtering for `api.ipify.org` DNS queries:

```
dns.qry.name == "api.ipify.org" and dns.flags.response == 0
```

The first query is frame 24147:

```
2021-09-24 17:00:04.093354 UTC
```

**Answer: `2021-09-24 17:00:04 UTC`**

---

## Q18 — Domain in the DNS Query

From the same filter above.

**Answer: `api.ipify.org`**

The malware queried `api.ipify.org` multiple times throughout the infection — a standard technique used to discover the victim's external IP for reporting back to the operators.

---

## Q19 — First MAIL FROM Address in SMTP Traffic

Later in the capture, the infected workstation begins sending spam through compromised mail servers — a secondary objective of Qakbot infections. Filtering for SMTP MAIL commands:

```
smtp.req.command == "MAIL"
```

The first MAIL FROM seen is:

**Answer: `farshin@mailfa.com`**

The SMTP traffic shows the host connecting to multiple mail servers (`smtp.outlook.com`, `mail.smtp2go.com`, `smtp.propertyestructuras.com`, and others) and sending spam using spoofed sender addresses.

---

## Q20 — Total SMTP Packet Count

Applying the `smtp` filter and reading the packet count from the bottom of the Wireshark window:

**Answer: `1439`**

---

## Full Kill Chain Summary

| Time (UTC) | Event |
|---|---|
| 16:44:38 | First HTTP GET — `documents.zip` from `attirenepal.com` |
| 16:44:38 | `chart-1530076591.xls` delivered inside zip |
| 16:45:11 | Secondary payload download from `finejewels.com.au` (HTTPS) |
| 16:45:21 | Secondary payload download from `thietbiagt.com` (HTTPS) |
| 16:45:25 | Secondary payload download from `new.americold.com` (HTTPS) |
| 16:45:57 | Qakbot C2 beaconing begins — `maldivehost.net` POST traffic |
| 16:46:28 | Cobalt Strike C2 — `survmeter.live` (`185.106.96.158`) |
| 16:47:05 | Cobalt Strike C2 — `securitybusinpuff.com` (`185.125.204.174`) |
| 17:00:04 | IP check via `api.ipify.org` |
| 17:02:19 | SMTP spam relay begins — 1,439 packets across multiple mail servers |

---

## Key Analyst Notes

**DNS as a mapping tool.** With 18,000+ packets going to unresolved IPs, DNS response analysis was the most efficient way to map suspicious IPs to hostnames. The filter `dns.flags.response == 1` with export to plain text produced the full resolution table needed to identify all malicious domains.

**Cobalt Strike traffic masquerading.** The CS beacon to `185.106.96.158` spoofed a Verisign OCSP Host header (`ocsp.verisign.com`) — a malleable C2 profile designed to blend with legitimate certificate validation traffic. The non-standard URI path (`/spfooh/`) and the mismatch between the Host header and the actual destination IP are the indicators. Always cross-reference Host headers against actual destination IPs in PCAP analysis.

**Qakbot's base64 URI pattern.** The maldivehost.net traffic is immediately recognizable — 26 POST requests to the same IP with rotating base64-encoded URI paths, all using the same 11-character path prefix `zLIisQRWZI9`. This is Qakbot's HTTP C2 channel, using base64-encoded encrypted data as the URI path rather than the request body.

**attirenepal.com is not one of the three payload domains.** Q7 specifically asks for domains involved in file downloads after the initial infection, meaning the domains the macro called out to after the XLS opened. attirenepal.com hosted the initial zip that arrived via email link, not a secondary payload.

**Qakbot vs Cobalt Strike.** The two highest-traffic IPs (`23.111.114.52` and `136.232.34.70`) are Qakbot infrastructure — not Cobalt Strike. VirusTotal Community tab is essential for distinguishing between malware families when the traffic characteristics alone are ambiguous. The CS servers (`survmeter.live` and `securitybusinpuff.com`) were identified by Community tab tags and confirmed by their behavioral patterns (periodic beaconing, spoofed headers).
