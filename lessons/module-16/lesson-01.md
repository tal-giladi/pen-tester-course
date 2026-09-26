# 16.1 — The engagement lifecycle: scope, rules of engagement, planning &amp; evidence handling

<div class="prereq">

**Prerequisites:** [00.1 Ethics, authorization &amp; RoE](../module-00/lesson-01.md),
[00.2 Methodology &amp; note-taking](../module-00/lesson-02.md),
[00.3 Threat modeling](../module-00/lesson-03.md). M16 assumes every prior module — you have found
real bugs; now you learn to run the engagement around them professionally.
**Module:** M16 Professional practice &amp; reporting. **Difficulty:** 🟡 intermediate.
**You will produce:** a scope statement, a rules-of-engagement (RoE) document, and an
evidence-handling &amp; chain-of-custody plan for a realistic client scenario.

</div>

## Why this matters

You can already discover, validate, and exploit vulnerabilities. That skill is worthless — worse,
dangerous — without the professional wrapper around it. The wrapper is the **engagement
lifecycle**: the sequence that turns "I can hack this" into "I ran a controlled, authorized,
documented assessment that a client can act on and a court would recognize as legitimate."

Ninety percent of the harm a tester can cause happens *outside* the exploit: testing the wrong
asset, storing a client's stolen credentials on a personal laptop, losing the one screenshot that
proved a finding, or being unable to answer "what exactly did you touch, and when?" during an
incident review. This lesson is where the craft of *running an engagement* lives. It is the least
glamorous module and the one that most separates a professional from a hobbyist with a Kali VM.

## Learning objectives

By the end you can:

- Walk an engagement from first contact to closeout, and name what each phase produces.
- Write a scope statement and an RoE that are unambiguous enough to defend under pressure.
- Distinguish **assumptions** from **exclusions**, and record both so nobody is surprised later.
- Design an **evidence-handling** and **chain-of-custody** plan: how findings are captured, named,
  timestamped, stored securely, and destroyed on schedule.
- Keep engagement notes that survive interruption and become the raw material for the report.

## Intuition

Think of a penetration test as a **flight**, not a stunt. A skilled pilot is not someone who can
pull a barrel roll; it is someone who files a flight plan, runs the pre-flight checklist, stays in
the assigned airspace, logs everything, and lands where they said they would. The exciting part —
the actual flying — is bracketed by discipline on both ends. Your exploit is the barrel roll. The
lifecycle is the flight plan, the checklist, the black box, and the tower you stay in contact with.

Everything in this lesson exists to answer three questions a client, a lawyer, or a future you will
eventually ask: *Were you allowed to do that? Can you prove what you did? Can someone else
reproduce it?*

## The professional practice: the engagement lifecycle

A real engagement moves through phases. This is the PTES/NIST spine from 00.2, now seen from the
*business* side rather than the technical loop:

<div class="callout method">

1. **Pre-engagement** — scoping, RoE, authorization, logistics, contacts. *Produces:* the signed
   documents you operate under and a test plan.
2. **Kickoff** — confirm scope is still accurate, credentials/accounts work, contacts are reachable,
   test window is agreed. *Produces:* a "go" and a shared understanding.
3. **Execution** — the technical work (recon → discovery → validation → impact), governed by the
   RoE, logged continuously. *Produces:* validated findings with evidence.
4. **Live communication** — status updates, and immediate escalation of critical findings and
   stop-conditions. *Produces:* no surprises for the client.
5. **Reporting** — findings, evidence, impact, remediation, narrative (16.2, 16.3). *Produces:* the
   deliverable the client pays for.
6. **Debrief** — walk the client through the report; agree priorities (16.3). *Produces:* a client
   who understands and can act.
7. **Retest &amp; closeout** — verify fixes, issue a retest letter, then **securely destroy** engagement
   data per the agreed schedule. *Produces:* closure and a clean data footprint.

</div>

The two properties from 00.2 still hold: the *execution* phase loops internally, and **notes are
not optional**. But notice how much of the lifecycle is not hacking at all. Pre-engagement and
reporting are where engagements are won or lost.

### Scope — the "where"

Scope is the exact set of assets you are authorized to test (00.1). At the professional level, a
scope statement is precise enough that a third party could tell, for any given packet, whether it
was in bounds. That means:

- **In-scope**, enumerated as CIDR ranges, resolved hostnames, specific URLs/apps, cloud
  account/subscription IDs, API base paths — with the *owner* of each confirmed.
- **Out-of-scope**, stated explicitly: third-party SaaS, shared-hosting neighbours, provider
  control planes, and any asset the client cannot legally authorize.
- **Wildcards resolved**: `*.example.com` is not a scope; it is a promise to argue about scope
  later. Enumerate what the wildcard covers *today* and agree how new hosts are handled.

### Rules of engagement — the "how"

The RoE fixes *how* you may test: timing windows, allowed and forbidden techniques (DoS? social
engineering? destructive exploitation? password cracking of real hashes?), rate limits, the test
type (black/grey/white box), data-handling rules, stop-conditions, and 24/7 escalation contacts.
The RoE is what protects the *business* while you attack it.

### Assumptions and exclusions — the "everything else"

<div class="callout key">

An **assumption** is something you are treating as true without proving it ("staging mirrors
production"; "the provided test accounts are non-privileged"; "the client owns every IP in the
range they gave"). An **exclusion** is something you are deliberately *not* doing ("no testing of
`payments.example.com`"; "no DoS"; "no exploitation against live customer data").

Every assumption that turns out false, and every exclusion you forget, is a future dispute. Write
them down in the RoE. When an assumption matters to a finding's severity, restate it in the finding
(16.2). "Assumed vs. excluded" is the vocabulary that keeps engagements out of court.

</div>

### Test planning

From scope + RoE + your threat model (00.3), build a **test plan**: which asset classes you'll
cover, in what order, against which standard (OWASP WSTG for web, ATT&CK-mapped tactics for infra),
and a rough time budget per area. The plan is not a straitjacket — the execution loop will change
it — but it makes coverage *defensible*. "We didn't test the API" is a very different sentence when
the plan shows the API was out of scope versus when it shows you simply ran out of time and never
said so.

## Evidence handling &amp; chain of custody

A finding you cannot prove is an opinion. Evidence is what makes it a finding, and mishandled
evidence is both useless and a liability.

<div class="callout method">

**What to capture, per finding:** the exact request/response or command and its full output; a
timestamped screenshot showing the synthetic marker (`LAB-FLAG-…` in this course; the real
equivalent in a real engagement); the affected URL/host/parameter; and enough context that another
tester can reproduce it without you. Capture the *minimum* that proves the issue — never bulk-copy
customer data to "be thorough" (00.1).

</div>

**Chain of custody** is the record of who handled a piece of evidence, when, and how it was stored —
so its integrity can be trusted later (this matters enormously when a finding feeds a legal case or
an incident). A workable, proportionate scheme:

- **Name deterministically:** `YYYYMMDD-HHMMSS_<host>_<finding-id>_<n>.png`. The timestamp and
  finding ID make evidence self-describing and sortable.
- **Log actions with time:** keep the timestamped action log from 00.2 (`time — command — target —
  result`). This log *is* the technical timeline you'll publish in 16.3, and it answers "what did
  you touch and when?" during any dispute.
- **Preserve integrity:** for significant artifacts, record a hash (`sha256sum evidence.pcap`) in
  your notes so you can later prove the file is unaltered.
- **Attribute handling:** in a team, note who collected and who accessed each artifact.

### Secure data handling

Engagement data — credentials you cracked, PII you glimpsed, screenshots of internal systems, the
report itself — is some of the most sensitive data a company holds, and *you* are now holding a
copy. Treat it accordingly:

- **Encrypt at rest** (full-disk plus an encrypted container/vault for the engagement folder) and
  **in transit** (deliver reports over an encrypted channel — a client portal, PGP, or a
  password-protected archive with the password sent out-of-band; **never** a plaintext email
  attachment).
- **Minimize:** don't collect real secrets you don't need; redact PII in evidence to the least that
  proves the point.
- **Retain and destroy on a schedule:** the contract states how long you keep engagement data
  (often 30–90 days post-delivery) and then you **securely delete** it. "We deleted the data on
  the agreed date" is part of the professional closeout, not an afterthought.

<div class="callout warn">

The compromise of a pentest firm is a supply-chain catastrophe: the attacker inherits a curated
list of exactly how to break into every client. Your handling of engagement data is a security
control with real blast radius. Isolated, encrypted, minimized, time-limited — always.

</div>

## Why it matters (the payoff)

Do this well and: you never test something you weren't allowed to; every finding survives challenge
because the evidence and timeline are intact; a stopped session resumes without loss; the client is
never surprised; and if anything goes wrong, your log and authorization letter make you the calm
professional rather than the suspect. Do it poorly and one missing screenshot or one out-of-scope
scan can erase the value of a week of skilled work.

## How to do it well

- **Turn every vague phrase into a field or a question.** "Everything related to the shop" is not a
  scope; it's the question "please enumerate the assets you own and authorize." (This is exactly the
  00.1 Northwind reflex, now habitual.)
- **Write exclusions you think are obvious anyway.** The obvious ones are the ones that cause
  disputes.
- **Log as you go, not after.** Reconstructed timelines are wrong and unconvincing. A terminal
  logger (`script`, `tmux` logging, or a tool like `pwncat`/Burp's history) plus your note file is
  the baseline.
- **Name evidence at capture time.** Renaming 200 screenshots the night before delivery is how
  evidence gets mismatched to findings.
- **Rehearse the stop-condition.** Know, before you start, exactly what you do the moment you find a
  prior breach or knock something over: who you call, what you stop touching, what you preserve.

## Concrete example: a scope/RoE mistake, and its fix

<div class="callout warn">

**Before (a real class of incident).** RoE says: *"In scope: `*.acme-shop.com`. Test type:
black-box. Techniques: standard web testing."* During execution the tester finds
`status.acme-shop.com` and load-tests it. It turns out to be a hosted status-page SaaS (a third
party), and the "standard web testing" wording never excluded automated high-rate scanning. The
tester has now hit a third party's infrastructure, arguably conducted a mini-DoS, and has no
written cover for either.

</div>

<div class="callout defend">

**After.** In-scope is enumerated as concrete hosts the client confirms they own, with a clause:
*"Hosts resolving to third-party providers (e.g. status-page, email, payment SaaS) are out of scope
regardless of subdomain; new in-scope hosts must be added in writing."* Techniques are itemized:
*"Manual and authenticated automated web testing at ≤ N requests/second; no load/stress testing; no
DoS."* A stop-condition covers "if an asset appears to be third-party hosted, halt and confirm
ownership before proceeding." The same finding — "a customer subdomain points to an unmanaged third
party" — is now reported as a *scope/asset-inventory observation*, which is more valuable to the
client than the reckless test would have been.

</div>

## Practical

<div class="lab">

**Environment:** paper/notes only — no targets. **Time:** ~60 min. This lesson's "lab" is producing
the governing documents for a mock engagement, the same way 00.1 did, but now at professional
depth and paired with an evidence plan.

</div>

1. Take the 00.1 RoE skeleton and extend it with explicit **Assumptions** and **Exclusions**
   sections and a **Data-handling &amp; retention** clause.
2. Draft an **evidence-handling plan**: naming convention, where evidence is stored and how it's
   encrypted, how the action log is kept, and the destruction schedule.
3. Sketch a one-page **test plan** mapping scope to asset classes, standards, and a time budget.

## Exercise

<div class="callout method">

**Situation.** **Meridian Health**, a mid-size clinic network, hires you for a two-week grey-box
test. In the kickoff they say: *"Test our patient portal at `portal.meridian.example` and its
backend API. We host it in Azure. There's a nightly data feed to our billing partner. We'll give
you two test patient logins. It's production — we can't have downtime during clinic hours (07:00–19:00).
Some records are real patient data; we're mid-migration so staging isn't ready."*

**Objective.** Turn this into a defensible engagement package: scope, RoE, assumptions/exclusions,
and an evidence &amp; data-handling plan appropriate to the sensitivity (this is regulated health data).

**Starting information.** Only the paragraph above.

**Constraints.** Paper only — you are not testing anything. Assume nothing the client didn't say;
where you would assume, that becomes an assumption you record *and* a question you ask.

**Expected deliverables.**
1. A **scope statement** (in/out) that resolves the Azure mention, the billing-partner feed, and the
   "real patient data" problem.
2. A **rules-of-engagement** document including timing (note the clinic-hours constraint), allowed
   and forbidden techniques, rate limits, stop-conditions, and 24/7 contacts.
3. An explicit **Assumptions** list and **Exclusions** list.
4. An **evidence-handling &amp; chain-of-custody plan** and a **data-handling/retention** clause suited
   to real patient data — capture, naming, storage/encryption, PII minimization/redaction, and
   destruction schedule.
5. A one-paragraph note on the single biggest legal/ethical risk here and how your package mitigates
   it.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Every constraint the client stated maps to an RoE field. Which stated facts are actually
<em>assumptions you must not silently accept</em> (Azure ownership, what the billing feed touches,
what "test logins" can reach)?
</details>

<details><summary>Hint 2 — technique family</summary>
"Production, no downtime during clinic hours" → timing window + no-DoS + rate-limit clauses. "Real
patient data" → data-handling clause + PII minimization + a hard stop-condition on accessing
records beyond what proves a finding.
</details>

<details><summary>Hint 3 — where to look</summary>
The billing partner is a third party the client cannot authorize (00.1). Azure has a published
testing policy and a shared-responsibility line — the client's resources are testable, the control
plane is not. Real patient data implicates a regulatory regime (e.g. HIPAA/GDPR) — your evidence
plan must minimize and protect it.
</details>

<details><summary>Hint 4 — specific direction</summary>
Your riskiest exposure is handling real patient records: over-collecting as "evidence," or reaching
the billing partner via the feed. Exclude the partner in writing, cap evidence to the minimum that
proves each finding, redact PII, encrypt everything, and set a short retention/destruction window.
</details>

## Check yourself

<div class="callout key">

1. A client says "just add the new marketing site to the test, you're already in there." Why is
   this a stop-and-get-it-in-writing moment even though it sounds trivial, and what specifically do
   you get?
2. You captured a finding with one screenshot that happens to show a real customer's full name and
   record. What is wrong with that evidence and how do you fix it *without* losing the proof?
3. Distinguish, with one example each from the Meridian scenario, an **assumption** from an
   **exclusion**.
4. Six weeks after delivery a client emails asking you to "re-send the raw data you collected."
   Walk through why your answer may be "we securely destroyed it on `<date>` per the contract," and
   why that is the professional outcome.
5. Why is a deterministic evidence-naming convention a *security and integrity* control, not just
   tidiness?

</div>

Model answers are in `solutions/module-16.md` (instructor material — try the questions first).

## References

- **NIST SP 800-115** — *Technical Guide to Information Security Testing and Assessment*, §3
  (planning), §7 (reporting, RoE, data handling). csrc.nist.gov.
- **PTES** — *Pre-engagement Interactions* and *Reporting* sections,
  penetration-testing-execution-standard.org.
- **OWASP Web Security Testing Guide (WSTG)** — Introduction: "Testing Methodology" and reporting
  guidance. owasp.org/www-project-web-security-testing-guide.
- **OWASP Penetration Testing Methodologies** / *Firm engagement* guidance.
- Cloud provider testing policies: **Microsoft (Azure) Penetration Testing Rules of Engagement**,
  **AWS Penetration Testing** policy, **Google Cloud** security-testing guidance (read the current
  versions).
- Chain-of-custody / digital evidence handling: **NIST SP 800-86** (*Guide to Integrating Forensic
  Techniques into Incident Response*) and **ISO/IEC 27037** for evidence-integrity principles.

## What you should now be able to do

- Run an engagement as a governed lifecycle and name what each phase produces.
- Write a scope and RoE precise enough to defend, with explicit assumptions and exclusions.
- Design a proportionate evidence-handling, chain-of-custody, and data-retention plan.
- Keep an action log that doubles as your technical timeline and your legal cover.

## Progress checkpoint

```bash
py course.py complete 16.1
```
