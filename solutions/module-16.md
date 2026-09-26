# Instructor / solutions — Module 16 (Professional practice &amp; reporting)

> **Instructor material.** Not linked from `_sidebar.md`. Students should attempt every exercise and
> Check-yourself before reading. Grade for *reasoning and completeness*, not for matching these
> exact words — reporting has many correct forms. The reusable deliverables live in
> `solutions/report-template/`.

---

## 16.1 — The engagement lifecycle (Meridian Health)

**Exercise — a strong submission.**

- **Scope (in):** `portal.meridian.example` and the specific backend API base path(s) the client
  confirms they own; the client's **own** Azure resources (App Service / VMs / storage) *only after*
  confirming subscription/resource IDs and reading Microsoft's Azure penetration-testing rules.
  **Scope (out):** the billing partner and the nightly feed's endpoint (a third party the client
  **cannot** authorize — 00.1); Azure's control plane and shared infrastructure; any host resolving
  to third-party SaaS.
- **RoE:** grey-box, two provided patient test logins. **Timing:** testing that could affect
  availability restricted to outside clinic hours (07:00–19:00) — i.e. evenings/nights or weekends;
  read-only/manual work may run in-hours if agreed. **Techniques:** no DoS/stress, no destructive
  exploitation, authenticated automated scanning rate-limited (≤ agreed req/s). **Stop-conditions:**
  any sign of a prior breach; any instability of a production clinical system; access to patient
  records beyond the minimum to prove a finding → halt and notify. **Contacts:** named 24/7
  technical + business escalation.
- **Assumptions (record *and* ask):** the two test logins are non-privileged patients; the client
  owns every Azure resource in scope; the billing feed is outbound-only and not reachable from the
  portal in a way that lets testing touch the partner. Each is a stated assumption **and** a
  kickoff question.
- **Exclusions:** billing partner + feed endpoint; Azure control plane; any DoS; any bulk export of
  real records.
- **Evidence &amp; data handling (the graded core, given real patient data):** capture the *minimum*
  proving each finding; **redact PII** in every screenshot (block names/IDs, keep the marker that
  proves the vuln); deterministic naming (`YYYYMMDD-HHMMSS_<host>_<finding>_<n>`); store the whole
  engagement folder in an **encrypted** container, full-disk-encrypted machine, isolated from
  personal data; timestamped action log for the timeline/chain-of-custody; deliver the report over
  an encrypted channel (portal or password-protected archive, password out-of-band); **short
  retention** (e.g. 30 days) then secure deletion, confirmed to the client. Reference the regulatory
  regime (HIPAA/GDPR) as the reason handling is strict.
- **Biggest risk:** mishandling **real patient data** — over-collecting it as "evidence" or reaching
  the billing partner. Mitigated by the minimization/redaction rules, the third-party exclusion in
  writing, encryption, and the short destruction window. Accept any answer that names data handling
  *or* the unauthorizable third party as the top risk with a matching mitigation.

**Common wrong turns:** accepting "we host it in Azure" as authorization to test Azure broadly;
treating the billing feed as in-scope because "it's their integration"; collecting real records
"to be thorough"; no retention/destruction clause; reconstructing the timeline after the fact.

**Check-yourself.** (1) It expands scope/authorization; verbal scope creep is how testers end up
outside their authorization (00.1). Get a written scope amendment naming the new asset, confirming
ownership, and (if needed) a revised window — signed by someone with authority. (2) It exposes real
PII you didn't need; the fix is to **redact** the personal fields in the image while keeping the
part that proves the finding (and re-capture if the original can't be redacted) — you keep the proof,
drop the liability. (3) *Assumption:* "the two logins are ordinary patients" (treated as true, not
proven). *Exclusion:* "the billing partner is not tested" (a decision not to act). (4) The contract
sets a retention window after which you securely destroy engagement data; if that date passed, "we
destroyed it on `<date>` per §X" is the correct, professional answer — holding client PII longer
than agreed is itself a risk. (5) Deterministic names bind each artifact to a finding and a
timestamp, so evidence can't be silently swapped or mismatched — that's integrity/chain-of-custody,
plus it makes tampering detectable when paired with a recorded hash.

---

## 16.2 — Severity, CVSS, risk &amp; remediation (three lab findings)

**Reference scoring.** Vectors are the deliverable; the numbers below are from the official FIRST
calculators. Accept a *different* vector only if the student's justification matches what they say
they demonstrated.

**F-1 — Unauthenticated SQLi (`lab-07 /search`), read demonstrated:**
- v3.1: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = **7.5 High**.
- v4.0: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` = **High** (per the v4.0
  calculator).
- Justify: network, unauth, no UI, no special conditions; C:H (read of credential material);
  **I/A:N because writes/DoS were not demonstrated.** Note the ceiling: if the DB account permits
  writes/stacked queries → I:H/A:H → 9.8. **Impact:** unauthenticated internet read of all customer
  records + hashes → account takeover + reportable breach. **Remediation:** parameterized query in
  `app/views.py:search()`; least-privilege DB account; input validation as defense-in-depth; verify
  by re-running the payload. **Environmental:** for a PII/regulated client set CR:H → environmental
  score rises above base — the report should do this and say why.

**F-2 — Local privesc via `sudo` NOPASSWD (`lab-04`):**
- v3.1: `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = **7.8 High**.
- v4.0: `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` = **High**.
- Justify: **AV:L** (needs an existing foothold on the host — not remote); **PR:L** (must already be
  the low-priv `lab` user, not None); UI:N; C/I/A all **H** (full root = read/modify/deny anything);
  S:U (same host authority). **Impact:** any local/foothold user becomes root → full host + data
  compromise. **Remediation:** remove the NOPASSWD rule / scope `sudo` to the exact non-interactive
  command with no shell-escape; audit all `sudoers` entries; verify with `sudo -l` as `lab`.
  References CWE-250/CWE-269.

**F-3 — Missing `Secure` / `HttpOnly` on the session cookie (`lab-07 /login`):**
- v3.1: no demonstrated downstream impact → typically **Low**, e.g.
  `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N` ≈ 3.1 (justify AC:H/UI:R: exploitation needs a
  further condition such as XSS or a MITM position). Accept Low–Medium with a defensible vector, or
  a defensible **N/A base + "enabler" framing.**
- v4.0: correspondingly Low. **Impact:** on its own, little; as an **enabler**, `HttpOnly`-less
  cookies are stealable via XSS and `Secure`-less cookies leak over plaintext — call this out in the
  narrative rather than inflating the score. **Remediation (a quick win):** set
  `Secure; HttpOnly; SameSite` on the session cookie — a one-line config change. References
  CWE-614/CWE-1004.

**Prioritized table (illustrative):**

| Rank | ID | Title | Severity (v3.1) | Rationale |
|---|---|---|---|---|
| 1 | F-1 | Unauth SQLi in `/search` | High (7.5) | Unauthenticated, internet-facing, exposes all customer PII + hashes — highest risk to the business. |
| 2 | F-2 | `sudo` NOPASSWD local privesc | High (7.8) | Full host compromise, but requires an existing foothold, so exposure is lower than F-1 despite the marginally higher base. |
| 3 | F-3 | Missing cookie flags | Low (~3.1) | Low severity, but the **fix is a one-line config change** → flag as a "quick win" to do immediately alongside F-1. |

**The teaching points to grade for:** (a) F-3 scored honestly *low* despite the temptation to call
missing security headers "High"; (b) F-2's base (7.8) is slightly higher than F-1's (7.5) yet F-1
ranks first — because **risk ≠ base score** (unauthenticated internet exposure of PII beats a
foothold-gated privesc); students must articulate this; (c) F-3 called out as a quick win even
though it ranks last — **effort, not just severity, drives the plan**; (d) "score what you
demonstrated" — I/A:N on F-1, with the ceiling noted.

**Check-yourself.** (1) No — you publish what you can defend. You demonstrated read only, so I:N/A:N
and 7.5, with a noted ceiling of 9.8 *if* write/stacked queries are possible; 9.8 asserts impact you
didn't prove. (2) Use environmental metrics: raise the Confidentiality/Integrity Requirement (CR/IR)
for the payroll asset and lower it for the cafeteria page — same base, different environmental score,
and the vector shows why; back it with a one-line business-impact sentence for each. (3) "Sanitize"
is undefined and usually implies blacklisting, which is bypassable; write the root-cause fix —
parameterized queries so `q` is always bound as data — plus least privilege and verification. (4)
v4.0 puts the confidentiality hit on the **subsequent system** (SC:H) while the vulnerable web app's
own impact may be low — it expresses "bug here, damage there" directly, where v3.1 could only wave at
it with S:C. (5) A trivial-to-fix Low that is also a prerequisite/enabler for a serious chain, or a
one-line config change that removes real exposure (e.g. F-3's cookie flags, or a default credential):
low severity, near-zero cost, do it first.

---

## 16.3 — The report &amp; the debrief (finding + executive summary)

**Exercise — grading rubric.** Two altitudes for one finding.

**Detailed finding** — must hit **every** rubric field (exercise-standard): specific title; exact
asset (host/URL/param or file); **both** CVSS vectors with per-metric justification; description
naming the **root cause**; numbered, copy-pasteable reproduction another tester can follow **without
the author**; evidence references showing the `LAB-FLAG-…` marker and named per convention;
**business** impact (not "it's bad"); **actionable, root-cause, verifiable** remediation with
CWE/OWASP references. The "after" finding in the lesson is the minimum bar. Dock for: missing
evidence, reproduction that assumes context, impact that restates severity, "best practices"
remediation.

**Executive summary** — must be jargon-free (**automatic defect** for any of: "SQLi", "IDOR", a CVSS
number, a CVE, a technique name), lead with business consequence, quantify exposure in plain terms,
state posture honestly without FUD, and end with a priority. The lesson's Meridian paragraph is the
model.

**Findings-summary-table entry** — one row, correct severity + asset + status.

**Attack narrative** — 3–5 lines, attacker order, ≥1 ATT&CK technique ID, showing how the finding
sits in a story (even a one-step story is fine if honestly scoped).

**Common wrong turns:** the executive summary reads like the finding with headers removed (jargon
intact); reproduction steps that only work in the author's session; impact = severity restated;
attack narrative that just re-lists the findings table instead of telling a causal story.

**Check-yourself.** (1) e.g. *"The public website lets anyone on the internet, with no password,
download the entire customer database and take over customer accounts; this would likely be a
reportable breach and should be fixed first."* Wrong with the original: acronyms (SQLi, RCE, CVSS)
and technique detail a CEO can't act on, and it asserts RCE via stacked queries that wasn't
demonstrated. (2) "Serious security issue" restates severity and gives the client nothing to weigh;
impact must state the **business consequence** ("an unauthenticated attacker can read all customer
records, enabling account takeover and a reportable breach"). (3) The narrative captures
**causality and chaining** — how individually modest findings combine into full compromise, in
attacker order with a timeline — which a severity-sorted table structurally cannot show; it's also
what the blue team replays against their logs. (4) Escalate immediately via the RoE escalation path
(16.1) — a Critical reaches the client the day it's confirmed, not on delivery day; the RoE's
stop-condition/communication clause governs. (5) Record **Partially remediated**: injection fixed
(re-test evidence), but least-privilege not applied; **residual risk** = "if another injection or
flaw is found, the admin-level DB account still allows full data compromise" — the statement exists
so the client can make an informed accept/fix decision on what remains.

---

## Grading notes (all three lessons)

- Reward **honesty over drama**: scoring only what was demonstrated, low severities called low,
  "risk accepted" treated as a legitimate outcome.
- Reward **audience discipline**: the same finding correctly re-voiced for executive vs. engineer.
- Reward **defensibility**: every severity has a vector + justification; every scope decision has an
  owner; every piece of evidence has a name, a time, and (where it matters) a hash.
- The professional arc to look for across the module: **discover → validate → understand →
  demonstrate impact → document → communicate → remediate → retest.** A student who "got root" but
  can't produce a reproducible, evidenced, prioritized, well-communicated finding has not met the
  bar this module sets.
