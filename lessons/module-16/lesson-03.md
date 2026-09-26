# 16.3 — The report &amp; the debrief: executive summary, technical findings, attack narrative, communication &amp; retesting

<div class="prereq">

**Prerequisites:** [16.1 The engagement lifecycle](lesson-01.md),
[16.2 Severity, CVSS, risk &amp; remediation](lesson-02.md). You should have a finding of your own from
an earlier module to write up (the `lab-07` SQLi or `lab-04` privesc work well).
**Module:** M16 Professional practice &amp; reporting. **Difficulty:** 🟡 intermediate.
**You will produce:** a complete technical finding (using the report template) **and** a
non-technical executive summary for a vulnerability you "found" in a course lab.

Every worked example here is drawn from this course's **isolated lab targets** (LAB TARGET only,
never a real system) — the same authorization boundary from [00.1](../module-00/lesson-01.md)
governs the engagements you report on.

</div>

## Why this matters

The report is the product. Not the shell, not the flag — the report. It is the only artifact that
outlives the engagement, the only thing most stakeholders ever see, and the thing the client
actually paid for. A brilliant compromise described in a confusing, unstructured, or condescending
report is a failed engagement. A modest set of findings written clearly, prioritized honestly, and
communicated with respect is a successful one that gets you hired again.

Reporting is also where the two audiences of security collide. The board wants to know *"are we
okay, and what will it cost?"* in ninety seconds. The engineer wants the exact request, the exact
line of code, and the exact fix. A professional report serves both without patronizing either — and
the debrief that follows turns a document into decisions.

## Learning objectives

By the end you can:

- Lay out a professional report: cover, executive summary, scope/RoE, methodology, findings summary,
  detailed findings, attack narrative/timeline, remediation roadmap, retest, appendices.
- Write an **executive summary** a non-technical leader can act on — risk and business, not jargon.
- Write a **technical finding** to the deliverable rubric (what/where/reproduction/evidence/impact/
  severity-rationale/remediation).
- Write an **attack narrative** and **timeline** that tell the story of the compromise.
- Run a **debrief**, communicate difficult findings well, and manage the **retest** and closeout.

## Intuition

A good report is a **pyramid**. At the top, one page any executive can read: how exposed is the
business, and what are the few things that matter. Below it, a summary table a manager uses to
assign work. Below that, the detailed findings an engineer implements from. Anyone can enter at their
level and drill down exactly as far as their job requires — and never has to wade through the wrong
altitude to find theirs. Writing the report is mostly deciding what belongs at each level.

## The professional practice: report structure

Report formats vary by firm, but a complete report has these parts (the full skeleton is in
`solutions/report-template/report-outline.md`):

<div class="callout method">

1. **Cover &amp; document control** — client, engagement name, dates, tester(s), version, and a
   **confidentiality classification**. This document is an attacker's treasure map (16.1) — mark it.
2. **Executive summary** — 1–2 pages, non-technical: what was tested, the overall risk posture, the
   handful of themes that matter, and the recommended priorities.
3. **Scope &amp; rules of engagement** — exactly what was in/out, the test type, the window, and the
   assumptions/exclusions (straight from 16.1). This is what makes coverage defensible.
4. **Methodology** — the standards you followed (PTES, OWASP WSTG, ATT&CK mapping) so the client
   sees the work was systematic, not lucky.
5. **Findings summary** — a table: ID, title, severity, CVSS, affected asset, status. The manager's
   view.
6. **Detailed findings** — one per finding, to the template (below). The engineer's view.
7. **Attack narrative &amp; timeline** — the story: how the pieces chained, with a timestamped
   timeline from your action log (16.1).
8. **Remediation roadmap** — the prioritized plan (16.2), grouped into quick wins vs. projects.
9. **Retest results** — added after the retest: what was fixed, what wasn't, residual risk.
10. **Appendices** — full tool output, PoC code, evidence index, methodology detail, glossary.

</div>

### The executive summary — writing for a non-technical audience

<div class="callout key">

Rules for the executive summary: **no jargon** (no "SQLi", "CVSS 7.5", "IDOR" — say what an attacker
could *do*); **lead with risk and business consequence**, not technique; **quantify exposure**
("an unauthenticated attacker on the internet could read all customer records"); **be honest but not
theatrical** — no FUD, no "you will be hacked tomorrow"; and **end with priorities**, not a list of
every bug. If a busy executive reads only this page, they should be able to fund the right work.

</div>

**Example — a strong executive-summary paragraph (for the `lab-07` SQLi engagement):**

> *"Meridian Shop's public website contains a flaw that lets anyone on the internet — with no login —
> retrieve the entire customer database, including the scrambled passwords that protect customer
> accounts. In practical terms, an attacker could download your customer list and use it to break
> into individual accounts, and the incident would likely be a reportable data breach. This is the
> single most urgent issue we found and can be fixed in a small, well-understood code change; we
> recommend it be prioritized this week. Overall, the application's security is below what we would
> expect for a system holding customer data, driven mainly by missing input handling and access
> controls — themes we detail below with concrete fixes."*

Notice: no CVSS, no "UNION-based injection," a clear business consequence, an honest posture
statement, and a priority. That is what lands with leadership.

### The detailed finding — writing for engineers

Every detailed finding meets the course's deliverable rubric (exercise-standard) and uses
`solutions/report-template/finding-template.md`. It must contain:

- **Title** — specific: "Unauthenticated SQL injection in product search (`/search?q=`)", not "SQL
  Injection".
- **Affected asset** — host/URL/parameter/file, unambiguous.
- **Severity** — CVSS v3.1 and v4.0 vectors + scores (16.2), with the rationale.
- **Description** — what the vulnerability is and *why it exists* (root cause), briefly.
- **Reproduction steps** — numbered, exact, copy-pasteable; another tester reproduces it without
  you.
- **Evidence** — the request/response or command output and a captured screenshot showing the
  synthetic `LAB-FLAG-…` marker, named per your convention (16.1).
- **Impact** — the business consequence, not "it's bad".
- **Remediation** — root-cause, specific, verifiable (16.2), with references (OWASP/CWE).
- **References** — CWE, OWASP, vendor docs.

### A finding, before and after

<div class="callout warn">

**Before (a poor finding):**
> *SQL Injection — High. The search is vulnerable to SQL injection. This is dangerous and should be
> fixed. Sanitize inputs.*

No asset, no reproduction, no evidence, no real impact, un-actionable fix. A developer cannot act on
it and a manager cannot judge it. It is an opinion, not a finding.

</div>

<div class="callout defend">

**After (a finding that lands):**
> **F-1 — Unauthenticated SQL injection in product search (`/search?q=`)**
> **Asset:** `http://web:5000/search` — parameter `q` (lab-07 Northwind Shop).
> **Severity:** High — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5);
> `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`.
> **Description:** `q` is concatenated directly into a SQL query, so input is parsed as SQL. Root
> cause: string-built query instead of a parameterized statement.
> **Reproduction:** (1) `curl "http://web:5000/search?q=x' UNION SELECT username,password,3 FROM users-- -"`
> (2) observe the response lists synthetic user rows and hashes; the seeded row shows the
> `LAB-FLAG-…` marker (see `evidence/20260926-141203_web_F-1_1.png`).
> **Impact:** an unauthenticated internet attacker can read the full `users` table, including
> credential hashes, enabling account takeover and a reportable breach of customer data.
> **Remediation:** replace the concatenated query in `app/views.py:search()` with a parameterized
> query; run the DB account at least privilege; add input validation as defense-in-depth. Verify by
> re-running the payload and confirming it is treated as a literal search term.
> **References:** CWE-89; OWASP SQL Injection Prevention Cheat Sheet.

</div>

### The attack narrative &amp; timeline

The findings table lists atoms; the **narrative** tells the story of how they combined into
business impact — the molecule. It is prose, in attacker order, mapped to PTES phases and ATT&CK
techniques (00.2), and it is where "three Mediums that chain to Critical" (16.2) is made vivid.

**Example — one narrative paragraph:**

> *"Starting unauthenticated from the internet, we exploited the product-search SQL injection (F-1,
> T1190) to read the application's user table, recovering password hashes. One synthetic account's
> hash cracked offline (F-4, T1110.002), and the credential was reused on the host's SSH service,
> giving an interactive foothold as the `lab` user (T1078). From there, a permissive `sudo` rule
> (F-2, T1548.003) yielded a root shell in a single command. In under an hour, a single
> unauthenticated web flaw led to full compromise of the host and its data — none of the individual
> steps required advanced tooling."*

Pair it with a **timeline** built straight from your action log (16.1): `14:02 — F-1 confirmed;
14:19 — users table dumped; 14:37 — hash cracked; 14:41 — SSH foothold; 14:44 — root.` The timeline
is also what the client's blue team compares against their own logs to test their detection.

## Communication &amp; the debrief

The report is delivered *and* discussed. The **debrief** (a meeting, often with both technical and
leadership stakeholders) is where you walk the pyramid: posture for the leaders, priorities for the
managers, details for the engineers.

<div class="callout method">

**Debrief craft.** Lead with the honest headline. Frame findings as help, not gotchas — you are on
the client's side against the same adversary. Never blame individuals ("the developer was
careless"); describe the system ("input handling isn't standardized, so this recurs"). Be ready to
defend every severity with its vector. Answer "how bad is it, really?" without exaggeration or
minimization. And **communicate critical findings immediately during the engagement** — a Critical
should reach the client the day you confirm it, via the RoE escalation path (16.1), not as a
surprise on page 12 weeks later.

</div>

## Retesting &amp; closeout

After the client remediates, a **retest** verifies the fixes. For each finding you record a status —
**Remediated / Partially remediated / Not remediated / Risk accepted** — with fresh evidence and,
where a fix is incomplete, the **residual risk**. The retest section is appended to the report (or
issued as a short retest letter), the fixed items are marked, and then the engagement closes: you
follow the data-retention/destruction schedule from 16.1 and confirm it to the client. "Risk
accepted" is a legitimate outcome — the client's informed decision, recorded — not a failure on your
part.

## Practical

<div class="lab">

**Environment:** the report templates in `solutions/report-template/` and one finding of your own
from an earlier lab (`lab-07` or `lab-04`). **Time:** ~75 min. No new targets.

</div>

1. Take a vulnerability you validated earlier in the course and fill in
   `finding-template.md` completely — every rubric field, real reproduction steps, real (synthetic)
   evidence references.
2. Write the one-page executive summary that would sit above it, using the rules above.
3. Draft the two-sentence entry it would get in the findings summary table.

## Exercise

<div class="callout method">

**Situation.** You have completed testing of a course lab and confirmed a vulnerability (choose the
`lab-07` SQL injection, the `lab-04` `sudo` privilege escalation, or another you validated). The
client is a fictional company with a non-technical CEO and a small engineering team.

**Objective.** Produce two deliverables at two altitudes for the *same* finding: a complete
technical finding an engineer can fix from, and an executive summary a CEO can fund from.

**Starting information.** Your own notes/evidence from the lab and the report templates.

**Constraints.** Synthetic/lab data only; evidence must show the `LAB-FLAG-…` marker. The finding
must meet the full deliverable rubric. The executive summary must contain **no jargon and no CVSS
number** — business language only.

**Expected deliverables.**
1. A complete **detailed finding** using `finding-template.md`: title, affected asset, CVSS v3.1 +
   v4.0 vectors with rationale, description (with root cause), numbered reproduction steps, evidence
   references, business impact, actionable remediation, references.
2. A one-page **executive summary** covering what was tested, the overall risk posture, this
   finding's business consequence in plain language, and the recommended priority.
3. The single-row **findings-summary-table** entry for this finding.
4. A three-to-five-line **attack-narrative** paragraph placing the finding in a story (even a short
   one), mapped to at least one ATT&CK technique.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Write the finding first (concrete), then the executive summary (abstract). It is far easier to
generalize up to business language than to invent details down from a vague summary.
</details>

<details><summary>Hint 2 — technique family</summary>
Executive summary = risk + business consequence + priority. Detailed finding = the rubric, in order.
The same vulnerability appears in both, described in two completely different vocabularies for two
different readers.
</details>

<details><summary>Hint 3 — where to look</summary>
Re-read the "before/after finding" pair above and the executive-summary example. Your finding should
be at least as complete as the "after"; your summary should read like the example — a leader could
act on it without knowing what SQL is.
</details>

<details><summary>Hint 4 — specific direction</summary>
Check your executive summary against the rules callout: any acronym, CVE, CVSS number, or technique
name is a defect there. Check your finding against the rubric: if a teammate could not reproduce it
from your steps alone, it is not done.
</details>

## Check yourself

<div class="callout key">

1. Your executive summary contains the sentence "We found a critical SQLi (CVSS 9.8) enabling RCE
   via stacked queries." Rewrite it for a non-technical CEO, and say what was wrong with the
   original.
2. A finding has perfect reproduction steps but its "Impact" says "this is a serious security
   issue." Why does that fail the rubric, and what would you write instead?
3. Why publish an attack narrative *in addition* to the findings table — what does the story capture
   that the table cannot?
4. During the engagement you confirm a Critical on day 2. The report is due day 14. What do you do,
   and which document/clause governs it?
5. At retest, a finding is "Partially remediated" — the injection is fixed but the DB still runs as
   admin. How do you record it, and what is the residual risk statement for?

</div>

Model answers are in `solutions/module-16.md` (instructor material — try the questions first).

## References

- **NIST SP 800-115** §7 — *Reporting* (structure and content of assessment reports).
- **PTES** — *Reporting* section (executive summary vs. technical report structure),
  penetration-testing-execution-standard.org.
- **OWASP Web Security Testing Guide** — *Reporting* guidance; **OWASP** report-writing resources.
- **CVSS v3.1 / v4.0** specifications — FIRST (for the severity block of each finding).
- **MITRE ATT&CK** — attack.mitre.org (technique IDs for the attack narrative).
- Public sample reports for structure/tone (read several): e.g. **PTES** examples and reputable
  firms' published redacted reports.

## What you should now be able to do

- Assemble a full penetration-test report at the right altitude for each reader.
- Write an executive summary that a non-technical leader can act on, and a technical finding an
  engineer can fix from.
- Tell the story of a compromise as an attack narrative with a defensible timeline.
- Run a debrief, communicate critical findings responsibly, and manage retest and closeout.

## Progress checkpoint

```bash
py course.py complete 16.3
```
