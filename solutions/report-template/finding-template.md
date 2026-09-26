# Finding template

> **Instructor / deliverable material.** Not linked from `_sidebar.md`. Copy this block once per
> finding. It implements the deliverable rubric in
> [`curriculum/exercise-standard.md`](../../curriculum/exercise-standard.md) — a finding is only
> "done" when every field below is filled: **what · where · reproduction · evidence · impact ·
> severity rationale · remediation**. Delete the italic guidance when you fill it in. Used by
> M16 (16.2 / 16.3), the assessments, and the capstone.

---

## F-<id> — <specific, descriptive title>

*Name the vulnerability and its location, not the class. "Unauthenticated SQL injection in product
search (`/search?q=`)", not "SQL Injection".*

| | |
|---|---|
| **Finding ID** | F-<id> |
| **Severity** | <Critical / High / Medium / Low / Informational> |
| **Status** | <Open / Remediated / Partially remediated / Not remediated / Risk accepted> |
| **Affected asset(s)** | <host / URL / IP / parameter / file:function — unambiguous> |
| **Category** | <e.g. Injection · Broken access control · Privilege escalation> |
| **CWE / OWASP** | <CWE-89 · OWASP A03:2021 Injection> |

### Severity rationale (CVSS)

- **CVSS v3.1:** `<CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_>` = **<score> (<band>)**
- **CVSS v4.0:** `<CVSS:4.0/AV:_/AC:_/AT:_/PR:_/UI:_/VC:_/VI:_/VA:_/SC:_/SI:_/SA:_>` = **<band>**
- **Environmental adjustment (if any):** `<CR/IR/AR or modified metrics>` — *why this client's
  context moves the score.*
- **Justification:** *one line per non-trivial metric — why AV, why PR, and especially why the
  C/I/A (or VC/VI/VA) values reflect what you **demonstrated**, not what you assume. Note the
  realistic ceiling if fuller exploitation is plausible but was not shown.*

### Description

*What the vulnerability is and, briefly, **why it exists** (the root cause — e.g. "user input is
concatenated into a SQL query instead of being bound as a parameter"). Keep it factual; save the
story for the attack narrative.*

### Affected asset detail

*Exact endpoint(s), parameter(s), file/line or config item, and the environment (prod/staging) and
access level required to reach it.*

### Reproduction steps

*Numbered, exact, and copy-pasteable. Another tester must reproduce this **without you**. Include the
precise request/command and the observable result at each step.*

1. `<exact command or request>`
2. `<next step>`
3. *Observe: `<what confirms the vulnerability>` — including the synthetic marker (`LAB-FLAG-…`) in
   course/lab work, or the equivalent proof artifact in a real engagement.*

### Evidence

*Reference captured artifacts by their deterministic filename (see 16.1 evidence handling); embed
key screenshots/output. Show the proof and the marker; redact real PII.*

- `evidence/<YYYYMMDD-HHMMSS>_<host>_F-<id>_<n>.png` — <what it shows>
- ```text
  <trimmed request/response or command output proving the finding>
  ```
- *(Optional) integrity: `sha256 <hash>` of any large/loose artifact (`.pcap`, export).*

### Impact

*The **business** consequence, not "it's bad" and not a restatement of the CVSS score. What can an
attacker do to this client's data, users, money, availability, or compliance posture? Tie it to the
asset's value.*

### Remediation

*Actionable, root-cause, layered, and verifiable (see 16.2):*

- **Fix (root cause):** *the specific change — e.g. "parameterize the query in
  `app/views.py:search()`."*
- **Defense in depth:** *supporting controls — least privilege, input validation, security headers.*
- **Strategic (if the class recurs):** *the pattern-level fix — standard, lint/SAST rule, CI check.*
- **Verification:** *how the retest will confirm the fix — e.g. "re-run the PoC payload; confirm it
  is treated as a literal value."*
- **Effort estimate:** *quick win / moderate / project — feeds prioritization.*

### References

- *CWE-<id>; OWASP <cheat sheet / Top 10 item>; vendor advisory / docs; CVE if applicable.*

### Retest result *(added at retest)*

- **Date / tester:** <…>
- **Status:** <Remediated / Partially remediated / Not remediated / Risk accepted>
- **Evidence:** <retest artifact reference>
- **Residual risk:** *what, if anything, remains and why it matters — for the client's informed
  accept/fix decision.*
