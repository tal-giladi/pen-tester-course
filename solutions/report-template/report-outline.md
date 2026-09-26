# Penetration-test report — outline & template

> **Instructor / deliverable material.** Not linked from `_sidebar.md`. This is the full report
> skeleton taught in M16 (16.3) and required by the assessments and the capstone. Copy it, fill each
> section, and drop in one [`finding-template.md`](finding-template.md) block per finding. Delete the
> italic guidance as you go. Structure follows **NIST SP 800-115 §7** and **PTES Reporting**; the
> severity blocks follow **CVSS v3.1 / v4.0**.

---

## 0. Cover & document control

- **Client:** <organization>
- **Engagement:** <name> · **Type:** <black / grey / white box> · <external / internal / web / AD / cloud…>
- **Testing window:** <start – end dates>
- **Tester(s):** <name(s), role(s)> · **Report author:** <…>
- **Report version / date:** <v1.0 — YYYY-MM-DD> · **Distribution list:** <named recipients>
- **Confidentiality classification:** *e.g. CONFIDENTIAL — contains exploitable vulnerability detail;
  handle per the engagement data-handling terms (16.1).*

*Include a short revision history table (version · date · author · change).*

---

## 1. Executive summary

*1–2 pages, **non-technical**. A leader who reads only this can fund the right work. No jargon, no
CVSS numbers, no CVE/technique IDs.*

- **What we did:** *one paragraph — what was tested, when, and to what end.*
- **Overall risk posture:** *an honest, non-theatrical verdict (e.g. "below expectations for a system
  holding customer data"), with a rationale.*
- **Key themes / most significant risks:** *the handful of things that matter, in business terms —
  what an attacker could actually do and to what.*
- **Summary of results:** *counts by severity (a small chart/table is fine here — numbers only).*
- **Recommended priorities:** *the top few actions, framed as decisions the client should make now.*

---

## 2. Scope & rules of engagement

*Straight from the pre-engagement documents (16.1) — this is what makes coverage defensible.*

- **In-scope assets:** <enumerated hosts / URLs / ranges / cloud account IDs>
- **Out-of-scope / exclusions:** <explicit — third parties, provider control planes, DoS, etc.>
- **Assumptions:** <what was treated as true without proof>
- **Rules of engagement:** <timing window, allowed/forbidden techniques, rate limits, test type>
- **Authorization:** <reference to the signed authorization; signatory + date>
- **Contacts & escalation:** <who was notified of what, and when critical findings were escalated>

---

## 3. Methodology

*Show the work was systematic, not lucky.*

- **Standards followed:** <PTES · NIST SP 800-115 · OWASP WSTG · OWASP API Top 10 · MITRE ATT&CK mapping>
- **Approach:** <recon → discovery → validation → impact; tooling classes; manual verification>
- **Grading/severity method:** <CVSS v3.1 and v4.0; environmental adjustment approach; how risk is
  derived from severity>
- **Limitations:** <time box, credentials provided, environments not reachable, anything not tested
  and why — a stated limitation is defensible; a silent gap is not.>

---

## 4. Findings summary

*The manager's view — one row per finding, sorted by severity/risk.*

| ID | Finding | Severity | CVSS (v3.1) | Affected asset | Status |
|---|---|---|---|---|---|
| F-1 | <title> | Critical | 9.x | <asset> | Open |
| F-2 | <title> | High | 7.x | <asset> | Open |
| … | | | | | |

*Optionally include a severity-distribution chart and a one-line "top 3 to fix first" call-out.*

---

## 5. Detailed findings

*One [`finding-template.md`](finding-template.md) block per finding, ordered by severity/risk. Each
must satisfy the deliverable rubric: what · where · reproduction · evidence · impact · severity
rationale · remediation.*

- **F-1 — <title>** … *(full template block)*
- **F-2 — <title>** … *(full template block)*
- …

---

## 6. Attack narrative & timeline

*The story the findings table cannot tell: how individually-scored issues **chained** into business
impact, in attacker order, mapped to PTES phases and ATT&CK techniques (00.2).*

- **Narrative:** *prose walkthrough of the compromise path, referencing finding IDs and technique
  IDs (e.g. "…exploited F-1 (T1190) to read the user table, cracked a hash (F-4, T1110.002), reused
  it over SSH (T1078), and escalated via F-2 (T1548.003) to root.").*
- **Timeline:** *built from the timestamped action log (16.1) — the client's blue team replays this
  against their own logs to test detection.*

  | Time | Action | Finding / ATT&CK | Result |
  |---|---|---|---|
  | <HH:MM> | <what you did> | F-<id> / T#### | <outcome> |

---

## 7. Remediation roadmap

*The prioritized plan (16.2) the client acts on — ranked by risk, tie-broken by effort.*

| Priority | Finding(s) | Recommended action | Effort | Type |
|---|---|---|---|---|
| 1 | F-1 | <root-cause fix> | Low | Quick win |
| 2 | F-2, F-5 | <fix> | Medium | Project |
| … | | | | |

- **Quick wins:** *low-effort, high-value fixes to do immediately.*
- **Strategic recommendations:** *pattern-level fixes where a class of issue recurs (standards,
  CI/SAST checks, architecture).*

---

## 8. Retest results

*Added after the client remediates and a retest is performed.*

| Finding | Original severity | Retest status | Residual risk |
|---|---|---|---|
| F-1 | High | Remediated | None |
| F-2 | High | Partially remediated | <what remains> |
| … | | | |

*Attach fresh evidence per retested finding; "Risk accepted" is a legitimate, recorded client
decision.*

---

## 9. Appendices

- **A. Evidence index** — every artifact by deterministic filename, mapped to its finding (16.1).
- **B. Tool output** — full scan/tool logs referenced by findings.
- **C. Proof-of-concept code / payloads** — with the synthetic markers.
- **D. Methodology detail / checklists** — WSTG coverage, ATT&CK technique list.
- **E. Glossary** — plain-language definitions for non-technical readers.
- **F. Document data-handling & retention** — how this report and its evidence are stored and when
  they will be destroyed (16.1).
