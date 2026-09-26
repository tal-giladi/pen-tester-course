# 00.1 — Ethics, authorization &amp; the law; rules of engagement

<div class="prereq">

**Prerequisites:** none — this is the first lesson and the most important one.
**Module:** M00 Foundations. **Difficulty:** 🟢 foundational.
**You will produce:** a filled-in rules-of-engagement (RoE) template for a mock engagement and a
personal "authorization checklist" you run before touching any target.

</div>

## Why this matters

Everything else in this course — every scan, every exploit, every clever chain — is a **crime**
when done against a system you neither own nor are explicitly authorized to test. The single
difference between a penetration tester and a criminal is not skill; it is **authorization**. A
professional who forgets this ends a career and sometimes starts a prison sentence. So we begin
here, and every offensive page in this course restates the boundary.

This lesson is also where you learn that the deliverable of our work is *trust*. A client lets you
attack their business because they believe you will stay in scope, not cause damage, protect what
you find, and tell them the truth. The paperwork you'll learn to read and write — scope, rules of
engagement, authorization — is how that trust is made concrete and legally sound.

## Learning objectives

By the end you can:

- State, precisely, what makes a security test lawful, and name the boundary you must never cross.
- Read and write a **rules-of-engagement** document and a **scope** definition.
- Recognize the situations where an engagement can go wrong (scope creep, third-party assets,
  accidental data exposure) and the professional response to each.
- Explain why this course's lab is built the way it is (isolation), and run an authorization
  checklist before any hands-on work.

## Intuition

Think of a penetration test as a **contract to break in, on purpose, with permission**. A
locksmith you hire to test your locks is doing something that would be burglary if a stranger did
it. What separates the two is: *who asked, what exactly they authorized, for how long, and what
happens to what's found.* Get those four things in writing and you have a profession. Skip them
and you have a case number.

## The underlying reality: the law

<div class="callout legal">

This is orientation, **not legal advice**. Laws differ by country and change. When it matters,
consult a lawyer. But you must know these exist.

</div>

Unauthorized access to a computer system is illegal under statutes such as:

- **United States** — the *Computer Fraud and Abuse Act* (CFAA, 18 U.S.C. § 1030): accessing a
  computer "without authorization" or "exceeding authorized access." Penalties scale with intent
  and damage. Related: the *Digital Millennium Copyright Act* (DMCA) for circumvention.
- **United Kingdom** — the *Computer Misuse Act 1990*: unauthorized access, unauthorized access
  with intent, and unauthorized acts impairing operation.
- **European Union** — the *Directive 2013/40/EU on attacks against information systems*,
  implemented in member-state law; plus **GDPR** the moment personal data is involved.
- **Israel** — the *Computer Law, 5755-1995* (חוק המחשבים) criminalizes unlawful access and
  interference.

Two themes recur in all of them and matter to you daily:

1. **"Authorization" is defined by the system owner, not by you.** Your belief that testing was
   "obviously fine" is not a defense. The authorization must be real, specific, and from someone
   with the authority to grant it.
2. **Scope is legal, not just polite.** Testing a host *adjacent* to your target — a shared
   hosting neighbor, a third-party API, a cloud provider's infrastructure — can be a separate
   offense even if your actual target is in scope. Cloud providers (AWS, Azure, GCP) publish their
   own testing policies; some assets are never yours to test regardless of who your client is.

<div class="callout warn">

**Bug-bounty programs** are authorization too — but only within the program's published scope and
rules. "I found it on the Internet" is never authorization. Even responsible-disclosure of an
unsolicited finding can expose you to liability if you accessed data to prove it.

</div>

## Why the paperwork exists — and what's in it

A real engagement rests on a chain of documents. You must be able to read and (for scope/RoE)
write them.

### Scope

**Scope** is the exact set of assets you are authorized to test, expressed unambiguously:

- IP ranges / CIDR blocks, hostnames, domains and subdomains, specific URLs or applications.
- Cloud accounts/subscriptions, API endpoints, mobile apps (with store/build identifiers).
- Explicit **exclusions** ("do not test `payments.example.com`; do not touch the `HR-*` VLAN").
- **Assumptions** ("the staging environment mirrors production"; "test accounts are provided").

Ambiguity in scope is the number-one way an engagement goes wrong. A wildcard like `*.example.com`
sounds generous until a subdomain turns out to be a third party's SaaS you're now attacking.

### Rules of Engagement (RoE)

The **RoE** is *how* you're allowed to test. It typically fixes:

- **Timing windows** — when testing may run (e.g. off-hours to limit business impact).
- **Allowed and forbidden techniques** — e.g. "no denial-of-service," "no social engineering,"
  "no destructive exploitation," "no exploitation of production data."
- **Data handling** — what you may access, how you store evidence, when you must stop and report
  (e.g. on finding real customer PII or evidence of a *prior* breach).
- **Escalation & contacts** — who to call, and *stop conditions* ("if a production system becomes
  unstable, halt and notify immediately").
- **Testing type** — black-box (no info), grey-box (some credentials/info), white-box (full
  access/source). This course teaches you to operate across all three.
- **Evidence & reporting** — format, timeline, and secure delivery of the report.

### Authorization ("get out of jail") letter

A signed document from someone with authority stating that the named tester is authorized to test
the named scope during the named window. You carry it. If a defender or law enforcement notices
your activity, it is what stops a very bad day. It does **not** authorize anything beyond scope.

<div class="callout method">

**Professional reflex:** *no signed authorization + defined scope + RoE → no testing.* Not "I'll
just do a little recon." Passive recon can be fine, but the moment you interact with a target, the
paperwork must already exist. This reflex is the habit this lesson is really teaching.

</div>

## How a tester recognizes trouble (and what to do)

Real engagements produce ethical decisions in real time. The professional responses:

- **You find a way out of scope.** (e.g. an in-scope web app SSRFs into an out-of-scope internal
  service.) → Stop at the boundary, **document the reachability as a finding**, and ask the client
  before crossing. The *finding* — "this app can reach internal systems" — is often more valuable
  than the exploit.
- **You discover real sensitive data** (customer PII, credentials, medical records). → Access the
  **minimum** needed to prove the issue, do not exfiltrate or copy beyond evidence, and follow the
  RoE's data-handling clause. Note it and often stop to notify.
- **You find signs of a *prior*, real breach.** → This is a "stop and call" event in most RoEs.
  You may be looking at an active incident or a crime scene.
- **Something breaks.** → Halt, notify per the escalation path, don't try to quietly fix it.
  Honesty protects you and the client.
- **Scope creep** ("while you're in there, can you also check…"). → Get it in writing first.
  Verbal expansions are how people end up outside their authorization.

## The lab, and why it's built the way it is

Because unauthorized testing is illegal and mistakes happen, **this course never asks you to
practice on anything but the intentionally vulnerable systems we ship**, on isolated networks.
The lab (see [`labs/README.md`](../../labs/README.md)) uses:

- **Private Docker networks with no route to the Internet** and host-only VM networks, so a
  mistyped target hits a lab host, not a stranger's server.
- **Synthetic credentials** (`lab / Lab-Passw0rd!`) and **benign flags** (`LAB-FLAG-{uuid}`) so
  nothing you "steal" is real.
- A **local sink** for anything resembling exfiltration, so data never leaves your machine.

This is the safety architecture that lets you practice offense without ever endangering a real
system — the same principle as the RoE, enforced by the network itself.

## Practical lab

<div class="lab">

**Environment:** none yet (paper exercise + your notes). **Time:** ~45 min. **Targets:** none.
This lesson's "lab" is producing the documents you'll rely on for the rest of the course.

</div>

1. Copy the RoE skeleton below into `exercises/my-roe.md` (git-ignored is fine) and complete it
   for the mock client in the exercise. Fill *every* field; where you'd need to ask the client,
   write the question you'd ask.
2. Write your personal **authorization checklist** — the short list you will run in your head
   before touching any target for the rest of your life. (A starter is in the Check-yourself.)

```text
RULES OF ENGAGEMENT — <client> / <engagement name>
1. Parties & authority: tester(s), client signatory (name/role), date
2. Scope (in):   <IPs/CIDRs, domains, apps, cloud accounts>
3. Scope (out):  <explicit exclusions, third-party assets>
4. Assumptions:  <environment, provided accounts>
5. Test type:    <black/grey/white box>
6. Techniques allowed / forbidden: <DoS? social eng? destructive exploit?>
7. Timing window(s) & rate limits:
8. Data handling: <what may be accessed, evidence storage, PII rule>
9. Stop conditions & escalation contacts (24/7):
10. Prior-breach / real-incident clause:
11. Deliverables & secure delivery:
12. Authorization statement + signatures
```

## Exercise

<div class="callout method">

**Situation.** A fictional company, **Northwind Retail**, hires you for a two-week external
penetration test. In a kickoff call they say: *"Test our website `shop.northwind.lab` and anything
you find related to it. We're on AWS. Try not to break anything — it's production. Oh, and our
payment page is handled by a third-party processor."*

**Objective.** Turn that vague, realistic conversation into a defensible engagement: a scope, an
RoE, and a list of clarifying questions you must resolve **before** testing.

**Starting information.** Only the paragraph above.

**Constraints.** Lab/paper only — you are not testing anything. Assume nothing the client didn't
say; where you'd assume, that's a question, not a fact.

**Expected deliverables.**
1. A completed RoE using the skeleton, with unknowns turned into explicit questions.
2. A scope statement with clear in/out lists — decide how you handle "anything related to it," the
   AWS mention, and the third-party payment processor.
3. A one-paragraph note on the *biggest* legal/ethical risk in this engagement as stated, and how
   your RoE mitigates it.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Every vague phrase the client used maps to a field in the RoE/scope. Which phrases hide a
third-party or provider whose systems are <em>not the client's to authorize</em>?
</details>

<details><summary>Hint 2 — technique family</summary>
Think about "authorization is defined by the owner." Who owns <code>shop.northwind.lab</code>'s
underlying infrastructure? Who owns the payment processor? Who owns AWS's control plane?
</details>

<details><summary>Hint 3 — where to look</summary>
Cloud providers publish penetration-testing policies. "Anything related to it" and a wildcard are
scope traps. "Production" plus "don't break anything" is a RoE clause about techniques and timing.
</details>

<details><summary>Hint 4 — specific direction</summary>
Your riskiest exposure is testing something the client cannot legally authorize (the payment
processor, or AWS infrastructure vs. the client's own resources). Your RoE should exclude it in
writing and record that you raised it.
</details>

## Check yourself

<div class="callout key">

1. A client says "you're authorized to test everything on `10.0.0.0/8`." You scan and find a live
   host that turns out to be a *different company* co-located in that range. Were you authorized to
   test it? What should you have done, and what do you do now?
2. During an authorized web test you find you can read other customers' invoices by changing an ID.
   The RoE says "access only the minimum needed to demonstrate a finding." What exactly do you
   capture as evidence, and what do you *not* do?
3. Why is a signed authorization letter valuable *even though* it doesn't change what's technically
   possible?
4. A friend asks you to "just check if my ex's Instagram is hackable." Walk through why this is not
   an engagement, in one sentence.

</div>

_A starter authorization checklist (extend it): (1) Do I have written authorization from someone
with authority? (2) Is this specific asset in the defined scope? (3) Am I inside the allowed timing
window and techniques? (4) If I find sensitive data or a prior breach, do I know my stop/notify
rule? If any answer is "no/unsure," I do not proceed._

Model answers and discussion are in `solutions/module-00/` (instructor material — try the
questions before looking).

## References

- **CFAA** — 18 U.S.C. § 1030 (US DOJ *Prosecuting Computer Crimes* manual is a readable primer).
- **UK Computer Misuse Act 1990** — legislation.gov.uk.
- **EU Directive 2013/40/EU** on attacks against information systems; **GDPR** (Regulation 2016/679).
- **PTES** — Pre-engagement Interactions (penetration-testing-execution-standard.org).
- **NIST SP 800-115** — Technical Guide to Information Security Testing and Assessment, §3
  (planning) and §7 (RoE, disclosure).
- Cloud testing policies: **AWS Penetration Testing** policy; **Microsoft Cloud Penetration
  Testing Rules of Engagement**; **Google Cloud** support/security testing guidance. (Read the
  current versions — these change.)

## What you should now be able to do

- Explain, in one sentence, the only thing separating a pentester from a criminal, and why the
  paperwork is legal rather than bureaucratic.
- Turn a vague client conversation into a defensible scope + RoE with explicit exclusions and
  clarifying questions.
- Recognize the common in-engagement ethical events and give the professional response to each.
- Run an authorization checklist reflexively before any hands-on work — including in this course's
  lab.

## Progress checkpoint

```bash
py course.py complete 00.1
```
