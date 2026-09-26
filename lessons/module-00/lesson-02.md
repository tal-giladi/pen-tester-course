# 00.2 — Penetration-testing methodology: PTES, the kill chain &amp; MITRE ATT&amp;CK

<div class="prereq">

**Prerequisites:** [00.1 Ethics &amp; authorization](lesson-01.md).
**Module:** M00 Foundations. **Difficulty:** 🟢 foundational.
**You will produce:** a one-page personal methodology checklist and an ATT&amp;CK-tagged narrative
of a simple intrusion.

</div>

## Why this matters

The difference between someone who "knows some hacking tools" and a penetration tester is a
**repeatable process**. Under time pressure, on an unfamiliar network, the amateur pokes at
whatever looks interesting and forgets what they've checked; the professional follows a method,
takes disciplined notes, and can always answer "what have I covered, what's left, and why am I
doing this next?" This lesson gives you that method and the two vocabularies —the **kill chain**
and **MITRE ATT&CK** — that the whole industry uses to describe attacks. You'll use ATT&CK tags in
every later module, so we introduce them now.

## Learning objectives

- Describe the phases of a penetration test (PTES / NIST) and what each produces.
- Explain the Cyber Kill Chain and, more importantly, **its limits** versus ATT&CK.
- Read and write a MITRE ATT&CK reference (tactic vs technique, IDs) and use it to structure an
  attack narrative and connect offense to detection.
- Keep engagement notes that survive a stopped session and become report material.

## Intuition

A pentest is an **investigation with a goal**, run as a loop, not a straight line. You gather
information, form a hypothesis ("this service looks outdated and exposed"), test it cheaply,
and let the result feed the next round. Every phase feeds the next: recon shapes enumeration,
enumeration shapes exploitation, a foothold restarts recon *from the inside*. The named phases
below are just a checklist so the loop stays organized and nothing is forgotten.

## The methodology (PTES / NIST SP 800-115)

The **Penetration Testing Execution Standard** and **NIST SP 800-115** describe essentially the
same process. We use this seven-phase spine throughout the course:

<div class="callout method">

1. **Pre-engagement** — scope, RoE, authorization (00.1). *Produces:* the contract you operate under.
2. **Intelligence gathering (recon)** — passive then active discovery of the attack surface (M02).
   *Produces:* an inventory of hosts, services, domains, identities.
3. **Threat modeling** — what's valuable, where the trust boundaries are, likely attack paths (00.3).
   *Produces:* prioritized targets and hypotheses.
4. **Vulnerability analysis** — enumeration and discovery: which weaknesses plausibly exist (M03+).
   *Produces:* candidate findings, ranked.
5. **Exploitation** — validating a vulnerability by safely triggering it in the lab (M07, M09…).
   *Produces:* proof, a foothold, evidence.
6. **Post-exploitation** — privilege escalation, lateral movement, pivoting, impact assessment
   (M04–M06, M10–M14). *Produces:* the demonstrated business impact — the real deliverable.
7. **Reporting** — findings, evidence, impact, remediation, communication (M16). *Produces:* the
   thing the client actually pays for.

</div>

Two properties matter more than the list itself:

- **It loops.** Reaching a foothold in phase 5 sends you back to phase 2 *inside* the perimeter.
  A real engagement spirals through these phases many times at different vantage points.
- **Notes are not optional.** From phase 2 onward you keep a timestamped log: what you ran,
  against what, what you saw, what you concluded. It's how you avoid re-scanning, how you write the
  report, and — per the goal of this course — how a stopped session resumes without loss.

## The Cyber Kill Chain — and why it's not enough

Lockheed Martin's **Cyber Kill Chain** models an intrusion as a linear sequence: *Reconnaissance →
Weaponization → Delivery → Exploitation → Installation → Command & Control → Actions on
Objectives.* It's a useful teaching mental model — break any link and you disrupt the attack — and
you'll hear it constantly.

<div class="callout warn">

**Its limits.** Real intrusions aren't linear, and the kill chain is very "malware-delivery"
shaped — it fits a phishing-to-ransomware story better than, say, an attacker who logs in with
valid stolen credentials (no "weaponization," no "delivery") and lives off the land. It also says
little about *lateral* movement and internal escalation, which is where most of the interesting
work in this course happens. That's why the industry largely reaches for ATT&CK to describe *what
attackers actually do*.

</div>

## MITRE ATT&amp;CK — the shared vocabulary

**ATT&CK** is a curated knowledge base of real adversary behavior, organized as a matrix:

- **Tactics** = the adversary's *goal* at a step (the "why"). Columns of the matrix, e.g.
  *Initial Access, Execution, Persistence, Privilege Escalation, Credential Access, Discovery,
  Lateral Movement, Collection, Command and Control, Exfiltration, Impact.*
- **Techniques** = *how* they achieve it (the "what"), each with an ID. Example: **T1190 — Exploit
  Public-Facing Application** (tactic: Initial Access). Sub-techniques refine it, e.g. **T1558.003
  — Kerberoasting** under *Steal or Forge Kerberos Tickets*.

Why you care as a *tester*:

1. **It structures your thinking and your report.** "I gained initial access via T1190, escalated
   with T1548, moved laterally with T1021.002" is precise, mappable, and immediately understood by
   any blue team.
2. **It connects offense to detection.** Every ATT&CK technique page lists *data sources* and
   *detection* guidance. When you write remediation, you use it to tell the client not just "fix
   this bug" but "here's how you'd have caught this." That habit — thinking about how your action
   looks to a defender — is what M15 is built on, and it starts now.
3. **It's the common language across tools** (BloodHound, Caldera, SIEM rules, threat-intel
   reports all speak ATT&CK).

<div class="callout key">

**Tactic vs technique, quickly:** *Tactic* answers "what was the attacker trying to do?"
*Technique* answers "how?" One tactic (e.g. Privilege Escalation) has many techniques; one
technique can serve several tactics. This course tags techniques as they appear — collect them and
you'll have your own ATT&CK map by the capstone.

</div>

## How a tester uses all three together

- **PTES** is your *process* — the order you work in.
- **ATT&CK** is your *vocabulary* — how you describe each action and connect it to detection.
- **The kill chain** is a *communication aid* — a simple story for a non-technical audience, used
  with awareness of its limits.

## Manual practice: note-taking that becomes a report

Adopt a simple, durable structure now (you'll thank yourself in M16). Per target/host:

```text
## <host/target>  <IP>  <date>
- surface:   <open ports/services, versions>            [recon]
- hypotheses: <ranked: why each service is interesting>  [threat model]
- actions:   <timestamp — command — result>             [vuln analysis / exploitation]
- findings:  <what — where — evidence path — impact>     [→ report]
- ATT&CK:    <techniques used, with IDs>
- next:      <what I'd do with more time>
```

Tools help (CherryTree, Obsidian, Joplin, plain Markdown), but the discipline matters more than
the tool. Evidence (screenshots, command output, PoC files) is filed alongside, named so it's
obvious later.

## Practical lab

<div class="lab">

**Environment:** none (paper + reading). **Time:** ~40 min. **Targets:** none. Uses the live
MITRE ATT&CK site as a reference.

</div>

1. Open the ATT&CK Enterprise matrix (attack.mitre.org). Find the tactics *Initial Access*,
   *Privilege Escalation*, *Lateral Movement*, and *Exfiltration*, and read one technique under
   each. Note the technique IDs and skim the *Detection* section of one.
2. Create `lessons/module-00/my-methodology.md` (or in your notes) with the seven PTES phases and,
   for each, one line on *what you produce*.
3. Set up your note-taking tool of choice with the per-host template above.

## Exercise

<div class="callout method">

**Situation.** Read this short, deliberately informal intrusion story:

> *"An attacker found the company's web app on the Internet, exploited an unpatched flaw in it to
> run commands on the web server, found database credentials in a config file, used them to dump
> the user table, cracked a reused password, logged into an internal admin panel over the VPN, and
> copied an export of customer records to an external server."*

**Objective.** Convert this prose into a professional attack narrative.

**Starting information.** Only the paragraph.

**Constraints.** No tools; this is analysis. Use the live ATT&CK matrix as your reference.

**Expected deliverables.**
1. Map each step to a **PTES phase** and a **MITRE ATT&CK tactic + technique (with ID)**.
2. Identify the **one link** whose removal would have most disrupted the chain, and justify it
   (this is kill-chain thinking).
3. For the *initial access* step, write one sentence of remediation **and** one sentence on how a
   defender could have detected it (use the ATT&CK technique's Detection guidance).

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Walk the story clause by clause. Each clause is roughly one technique. Some map to the same tactic
(e.g. "found creds in a config" and "cracked a reused password" are both Credential Access).
</details>

<details><summary>Hint 2 — technique family</summary>
"Exploited an unpatched flaw in the web app" → Initial Access. "Ran commands" → Execution. "Creds
in a config file" and "dump the user table" → Credential Access / Collection. "Logged into admin
over VPN with a cracked password" → Lateral Movement (valid accounts). "Copied to external server"
→ Exfiltration.
</details>

<details><summary>Hint 3 — where to look</summary>
Search ATT&CK for: Exploit Public-Facing Application (T1190), Valid Accounts (T1078), Unsecured
Credentials (T1552), Exfiltration Over Web Service / C2 (T1567/T1041). Match, don't memorize.
</details>

## Check yourself

<div class="callout key">

1. You've spent an hour and have a foothold on a web server. Which PTES phase are you *re-entering*,
   and what changes about your recon now that you're inside?
2. Give one concrete intrusion the Cyber Kill Chain describes poorly, and say why.
3. A client asks, "why do you keep citing these T-numbers?" Answer in two sentences a non-technical
   manager would accept.
4. Your notes show you scanned a host but not what you concluded. Why is that a problem beyond
   tidiness?

</div>

Model answers in `solutions/module-00/`.

## References

- **PTES** — penetration-testing-execution-standard.org (the seven areas).
- **NIST SP 800-115** — Technical Guide to Information Security Testing and Assessment.
- **MITRE ATT&CK** — attack.mitre.org (Enterprise matrix; read "Getting Started" and one technique
  page fully, including Detection and Data Sources).
- **Lockheed Martin Cyber Kill Chain** — the original whitepaper (and read a critique of its
  linearity to understand the limits).
- **MITRE D3FEND** — d3fend.mitre.org (the defensive counterpart you'll pair with ATT&CK).

## What you should now be able to do

- Run a penetration test as a disciplined, looping process and always know where you are in it.
- Describe any attack in PTES phases and ATT&CK tactics/techniques, and use the kill chain
  appropriately (and know when not to).
- Keep notes that resume after interruption and become the skeleton of your report.
- Connect every offensive action to how a defender would detect it.

## Progress checkpoint

```bash
py course.py complete 00.2
```
