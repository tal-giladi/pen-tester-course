# 16.2 — Findings that land: severity (CVSS), risk, impact &amp; remediation

<div class="prereq">

**Prerequisites:** [16.1 The engagement lifecycle](lesson-01.md),
[00.3 Threat modeling](../module-00/lesson-03.md) (risk = threat × likelihood × impact).
Familiarity with at least one finding you produced in an earlier module (e.g. the `lab-07` SQL
injection or the `lab-04` privilege escalation).
**Module:** M16 Professional practice &amp; reporting. **Difficulty:** 🟡 intermediate.
**You will produce:** CVSS v3.1 **and** v4.0 vectors with written justification, a
severity-versus-risk assessment, and actionable remediation for three synthetic findings.

</div>

## Why this matters

The client does not read your report to admire your exploit. They read it to answer one question:
**"What do we fix first, and why?"** Everything in this lesson serves that question. A finding with
a wrong or unjustified severity is worse than no finding: it sends the client's limited remediation
budget to the wrong place. A "Critical" that is really informational cries wolf; a genuinely
critical issue buried under a scanner's "Medium" gets ignored until it becomes a breach.

Severity and risk are also where testers most often sound unprofessional — pasting a scanner's CVSS
number with no justification, confusing "the CVSS base score" with "the risk to this business," or
writing remediation so vague ("apply security best practices") that no developer could act on it.
This lesson is the craft of making a finding *land*: scored honestly, framed as business risk, and
paired with a fix someone can actually implement.

## Learning objectives

By the end you can:

- State the difference between **severity** and **risk**, and why the base CVSS score is neither.
- Build and justify a **CVSS v3.1** vector, metric by metric.
- Build and justify a **CVSS v4.0** vector, and explain what changed and why it often scores more
  faithfully.
- Recognize when the base score **misleads**, and use environmental/temporal (v3.1) or
  environmental/threat/supplemental (v4.0) metrics to correct it.
- Translate a technical finding into **business impact** and write **actionable** remediation.
- **Prioritize** a set of findings for a specific client and defend the order.

## Intuition

Severity asks: *"How bad is this vulnerability, in the abstract?"* Risk asks: *"How bad is it for
**this** client, given what the asset is worth and how exposed it is?"* A default admin password is
severe everywhere. Its *risk* on an internet-facing production database is catastrophic; on an
isolated lab box scheduled for decommission tomorrow, it is minor. CVSS mostly measures severity.
Your job is to carry it the rest of the way to risk — which is what the client actually needs.

## The professional practice: CVSS as a shared language

The **Common Vulnerability Scoring System (CVSS)**, maintained by FIRST, is the industry's shared
vocabulary for severity. Two versions are current in 2026: **v3.1** (2019, still the most widely
required by clients and tooling) and **v4.0** (2023, more expressive and increasingly requested).
You must be fluent in both and know when to present which.

<div class="callout key">

**A CVSS score without its vector string is noise.** The vector — the `AV:N/AC:L/…` string — is the
*argument*; the number is just its arithmetic. Always publish the vector, and always justify each
metric in prose. A reviewer must be able to disagree with your metric, not just your number.

</div>

### CVSS v3.1 — the base metrics

The **base** score (0.0–10.0, mapped to None/Low/Medium/High/Critical) captures the intrinsic
properties of the flaw:

- **Attack Vector (AV):** Network / Adjacent / Local / Physical — how "far" the attacker can be.
- **Attack Complexity (AC):** Low / High — are there conditions beyond the attacker's control?
- **Privileges Required (PR):** None / Low / High — what access must the attacker already have?
- **User Interaction (UI):** None / Required — must a victim do something?
- **Scope (S):** Unchanged / Changed — does the impact cross a security authority boundary (e.g.
  from an app into the host/hypervisor)? This is v3.1's most misused metric.
- **Confidentiality / Integrity / Availability (C/I/A):** None / Low / High impact on each.

Temporal and Environmental metric groups then adjust the base for exploit maturity and for *this*
environment (see "when the base score misleads").

### CVSS v4.0 — what changed and why

v4.0 was designed to fix v3.1's real-world complaints:

- **Attack Requirements (AT)** is added beside AC, separating "the exploit is complex" from "the
  target must be in a particular state."
- **User Interaction** is refined to None / Passive / Active.
- **Scope is gone.** In its place, impact is split into **Vulnerable System** (VC/VI/VA) and
  **Subsequent System** (SC/SI/SA) — a far clearer way to express "the bug is in A but the damage
  lands on B."
- **Threat** metrics (Exploit Maturity) replace v3.1's temporal group, and a **Supplemental** group
  (Safety, Automatable, Recovery, Value Density, etc.) carries context that used to be lost.
- The naming reflects intent: a base-only score is **CVSS-B**; add threat → **CVSS-BT**; add
  environmental → **CVSS-BE**; all → **CVSS-BTE**.

The practical upshot: v4.0 usually describes a finding more faithfully, especially chained and
"blast-radius" issues. Present v3.1 when the client's tooling or compliance regime requires it; lead
with v4.0 when you can.

## Worked example: the `lab-07` unauthenticated SQL injection

Recall the finding: the `/search?q=` endpoint on the Northwind Shop app concatenates the `q`
parameter into a SQL query. Unauthenticated, over the network, you demonstrated a UNION-based read
of the `users` table (synthetic accounts + password hashes, tagged with the `LAB-FLAG-…` marker).

**CVSS v3.1 — the naive score vs. the honest one.**

A careless tester reflexively scores every SQLi at 9.8:
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → **9.8 Critical**. That assumes full read *and*
write *and* denial of the database. What you actually demonstrated was UNION-based **reading** on a
DBMS/driver that did not permit stacked queries — no proven write, no proven availability impact:

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` → **7.5 High**.

<div class="callout method">

**Justification, metric by metric.** AV:N — reachable over the network. AC:L — no special
conditions; the payload works every time. PR:N — no authentication needed. UI:N — no victim action.
S:U — impact stays within the app's own DB authority. **C:H** — full read of a table containing
credential material. **I:N / A:N** — *we did not demonstrate* modification or denial; scoring them
High would be scoring an assumption, not a finding. In the finding we note the realistic ceiling
("if the DB account permits writes or stacked queries, integrity/availability rise to High, taking
the base to 9.8") so the client sees the upside risk without us inflating the proven score.

</div>

**CVSS v4.0** for the same demonstrated capability:

`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` → **High** (compute the exact
value with the official calculator; do not hand-wave it). Here VC:H captures the confidentiality hit
to the vulnerable system, VI/VA:N reflect the un-demonstrated write/DoS, and the subsequent-system
metrics are None because we did not pivot out of the database. If the SQLi were shown to leak
credentials that then unlock *another* system, that pivot is exactly what SC/SI/SA are for.

## Severity vs. risk: carrying the finding to the business

The 7.5/High is a *severity*. Risk is severity contextualized:

- **Environmental metrics** let you formalize context inside CVSS. If this app holds regulated PII,
  raise the Confidentiality Requirement (CR:H in v3.1 / v4.0), pushing the environmental score up.
  If it is a throwaway demo with fake data, CR:L pulls it down. **Same base score, different risk —
  and the vector shows exactly why.**
- **Business impact** is the plain-language version the executive summary needs (16.3): not "C:H"
  but *"an unauthenticated attacker on the internet can read every customer's account, including
  password hashes, enabling account takeover and a reportable data breach."*

<div class="callout key">

**Say the number, then say the sentence.** The CVSS vector is for engineers and trackers; the
business-impact sentence is for the people who decide the budget. A finding needs both. A CVSS score
alone has never motivated a fix.

</div>

## When the base score misleads

- **Environment ignored.** A base "Medium" info-leak on the host holding the crown-jewel database
  may be the client's top risk. Use environmental metrics and say so.
- **Chaining.** Three "Medium" findings that chain into full compromise are, together, "Critical."
  Score them individually *and* report the chain (this is 16.3's attack narrative). CVSS scores
  atoms; you must also score the molecule in prose.
- **Availability blindness.** For a system whose whole value is uptime, an A:H issue the base rates
  High may be the client's Critical — raise AR (Availability Requirement).
- **Scanner defaults.** Automated tools emit a base vector with no environmental context and often
  guess impact high. Never paste a scanner score without re-deriving the vector against what you
  actually observed.

## Actionable remediation

<div class="callout defend">

**Vague (useless):** *"Sanitize user input and follow secure coding best practices."* No developer
can act on this — sanitize how? which input? which practice?

**Actionable:** *"Replace the string-concatenated query in `/search` (`app/views.py`, `search()`)
with a parameterized query / prepared statement so `q` is always bound as data, never SQL.
Additionally: run the DB connection under a least-privilege account with no DDL/DML rights beyond
what the feature needs; add centralized input validation on `q` as defense-in-depth. Verify by
re-running the PoC payload and confirming it is treated as a literal search term."*

Good remediation is **specific** (the exact file/control), **root-cause** (parameterization, not
blacklisting), **layered** (least privilege + validation as backup), and **verifiable** (how the
retest will confirm it). Where possible, cite the authority: OWASP Query Parameterization / SQL
Injection Prevention cheat sheets, CWE-89.

</div>

Also give the client a **strategic** note where a class of bug recurs: "SQLi appeared in three
endpoints — adopt an ORM or a query-builder standard and add a CI check (e.g. a linter/SAST rule)
so new concatenated queries fail the build." Tactical fix for the finding, strategic fix for the
pattern.

## Prioritization for the client

Clients fix in an order. Give them one they can defend to *their* board. Rank by **risk**
(severity × exposure × asset value), then break ties by **remediation cost/effort** — a
one-line config change that kills a High belongs above a High that needs a re-architecture. Present
it as a simple table (Critical → Low), and for the top items add a "quick win vs. project" tag.
The prioritized list, not the raw score, is what a client acts on Monday morning.

## Practical

<div class="lab">

**Environment:** the official FIRST CVSS calculators (v3.1 and v4.0) — paper/browser only, no
targets. **Time:** ~60 min.

</div>

1. Score the `lab-07` SQLi above in both v3.1 and v4.0 using the official calculators; reproduce the
   vectors and confirm you can justify every metric out loud.
2. Now change one assumption (the DB account *can* write) and re-score; watch the vector and number
   move, and write the one sentence you'd add to the finding.
3. Add environmental metrics for a client who is a regulated healthcare provider; note the new score
   and why it differs from the base.

## Exercise

<div class="callout method">

**Situation.** You are writing up an engagement against the course labs. You have three validated,
synthetic findings:

- **F-1 — Unauthenticated SQL injection** in `lab-07`'s `/search?q=`: UNION-based read of the
  `users` table (synthetic credentials + hashes) demonstrated; no write proven. App is
  internet-facing and holds customer PII.
- **F-2 — Local privilege escalation** in `lab-04`: a `sudo` NOPASSWD entry on an interactive
  program lets the low-privileged `lab` user obtain a root shell and read `/root/flag.txt`. Requires
  an existing foothold on the host.
- **F-3 — Missing cookie security flags** in `lab-07`'s `/login`: the session cookie is set without
  `Secure` and `HttpOnly`. No exploitation of a further impact demonstrated.

**Objective.** Produce a defensible severity-and-risk assessment and a prioritized remediation plan
a client would accept.

**Starting information.** The three findings above and the lab READMEs.

**Constraints.** Use the official CVSS calculators. Score what was *demonstrated*, not what you
imagine; state assumptions explicitly. Synthetic/lab data only.

**Expected deliverables.**
1. For each finding: a **CVSS v3.1 vector + score** and a **CVSS v4.0 vector + score**, each with a
   metric-by-metric justification.
2. For each: a one-sentence **business-impact** statement and an **actionable** remediation (root
   cause + verification).
3. A **prioritized table** (all three, ranked) with a short rationale for the order — including at
   least one place where remediation effort, not raw severity, changes the ranking.
4. A note on any finding whose **base score misleads** and how environmental metrics correct it.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Two of these you demonstrated end-to-end; one (F-3) you only observed a weakness with no proven
downstream impact. How should "no demonstrated impact" show up in the C/I/A (or VC/VI/VA) metrics —
and therefore in the score?
</details>

<details><summary>Hint 2 — technique family</summary>
F-1 is network, unauth, no UI (compare the worked example). F-2 is <em>local</em> and needs
existing privileges — think AV:L and PR:L, with C/I/A all High (you became root). F-3's flags are a
weakness enabler; its severity depends on what else is true (is the site HTTPS-only? is there XSS?).
</details>

<details><summary>Hint 3 — where to look</summary>
For F-2, the canonical user→root local privesc vector is
<code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code> = 7.8 High — justify why it is not
Network and why PR is Low not None. For F-3, resist scoring "High" reflexively; without a
demonstrated impact it is typically Low/Medium, and its real value is as an enabler you note in the
narrative.
</details>

<details><summary>Hint 4 — specific direction</summary>
Ranking: F-1 (unauth, internet-facing, PII) almost certainly leads. F-2 outranks F-3 (full host
compromise vs. a config weakness), but note that F-3's <em>fix</em> is trivial (a one-line config
change) — a legitimate "quick win" to call out even though it ranks lowest by severity. That
severity-vs-effort tension is the point of the exercise.
</details>

## Check yourself

<div class="callout key">

1. A scanner reports your SQLi as "9.8 Critical." You demonstrated read-only access. Do you publish
   9.8? Justify your answer in terms of what CVSS metrics you can defend.
2. Two findings both score 6.5 base. One is on the payroll database; one is on the cafeteria-menu
   page. How do you make the report reflect that they are not equally urgent — using CVSS, not just
   words?
3. Explain, to a developer, why "sanitize the input" is not acceptable remediation for F-1 and what
   you'd write instead.
4. Why does CVSS v4.0 splitting impact into "vulnerable system" and "subsequent system" describe an
   SSRF-to-metadata chain better than v3.1's Scope flag?
5. Give one situation where the lowest-CVSS finding should be fixed *first*, and defend it.

</div>

Model answers are in `solutions/module-16.md` (instructor material — try the questions first).

## References

- **CVSS v3.1 Specification Document** — FIRST, first.org/cvss/v3-1/specification-document.
- **CVSS v4.0 Specification Document** and **User Guide** — FIRST,
  first.org/cvss/v4-0/specification-document.
- **CVSS calculators** — first.org/cvss/calculator/3.1 and first.org/cvss/calculator/4.0 (score
  every finding here; publish the vector).
- **NIST SP 800-115** §7 — analysis and reporting of findings.
- **OWASP** — *SQL Injection Prevention* and *Query Parameterization* cheat sheets; **CWE-89**
  (SQLi), **CWE-250/CWE-269** (privilege management), **CWE-614/CWE-1004** (Secure/HttpOnly cookie
  flags).
- **OWASP Risk Rating Methodology** — an alternative/ complement to CVSS for business-risk framing.

## What you should now be able to do

- Build and defend CVSS v3.1 and v4.0 vectors metric by metric, scoring what you demonstrated.
- Distinguish severity from risk and use environmental/threat metrics to bridge them.
- Turn a technical finding into a one-sentence business impact and a root-cause, verifiable fix.
- Prioritize a set of findings for a specific client and defend the order — including when effort
  beats severity.

## Progress checkpoint

```bash
py course.py complete 16.2
```
