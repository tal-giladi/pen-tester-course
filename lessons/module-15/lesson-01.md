# 15.1 — Adversary simulation vs penetration testing: ATT&amp;CK, the intrusion lifecycle &amp; attack chains

<div class="prereq">

**Prerequisites:** [M00 Foundations](../module-00/lesson-01.md) — ethics/RoE (00.1) and the
PTES/kill-chain/ATT&amp;CK framing (00.2); [M06 Active Directory](../module-06/lesson-01.md);
[M11 Lateral movement](../module-11/lesson-01.md).
**Module:** M15 Adversary simulation concepts. **Difficulty:** 🔴⚫ advanced.
**You will produce:** an ATT&amp;CK-mapped attack-chain plan for a stated objective, with a detection
data source named for every step. A *plan*, not an execution.

</div>

<div class="callout warn">

**What this module is, and is not.** M15 teaches the **concepts and the detection** of adversary
simulation. It does **not** teach malware development, weaponization, or product-specific evasion.
There is no implant, no obfuscator, no evasion recipe on these pages — those would be a different
(and, in this course, deliberately excluded) craft. Everything here is designed to make you a
better tester *and* to make the defender better, which is the entire point of the discipline.

</div>

## Why this matters

By this point you can find and exploit vulnerabilities across Linux, Windows, Active Directory,
web, and cloud. That makes you a good penetration tester. It does **not** yet make you a red-team
operator, and the two jobs answer different questions. A penetration test asks *"how many ways in
are there, and how bad is each?"* An adversary simulation asks *"if a specific threat actor came
for our crown jewels, would we **see** it, and could we **stop** it in time?"* The first is a
breadth-and-coverage exercise; the second is a stealth-and-objective exercise measured against a
defensive team.

The professional shift M15 asks for is this: stop thinking only about *whether an action works* and
start thinking about *what it looks like to a defender*. That habit — planted in 00.2, exercised in
every "Detection / blue-team view" section since — becomes the whole job here. An operator who can
get domain admin but leaves a trail the SOC ignores has taught the client nothing about their
detection. An operator who maps every action to how it would be caught has delivered the real
product: a measured, improvable defense.

## Learning objectives

By the end you can:

- Distinguish **penetration testing**, **red teaming**, and **purple teaming** by goal, scope,
  stealth posture, and deliverable — and pick the right one for a client's actual question.
- Walk the **intrusion lifecycle** as a sequence of MITRE ATT&amp;CK **tactics**, and place the
  techniques you already learned into it.
- Explain **threat-intelligence-driven emulation** — building an engagement around a *named*
  adversary's TTPs rather than an arbitrary attack path.
- Assemble an **attack chain** from techniques (with IDs) and, for each link, name the **detection
  data source** a defender would use to catch it.
- Describe, as detection-testing tools, what **Atomic Red Team**, **CALDERA**, and **adversary
  emulation plans** do and where their limits lie.

## Intuition

Think of the three disciplines as three questions a client's security program asks as it matures.

A young program asks *"what's broken?"* — that's a **penetration test**: go wide, find as many real
vulnerabilities as you can, rank them, hand back a prioritized list. Stealth barely matters; the
defender usually knows you're testing.

A more mature program has already fixed the obvious holes and bought detection tooling. It now asks
*"does our detection actually work against a real attacker?"* — that's a **red team**: pick one
realistic threat actor, one concrete objective (the "crown jewels"), and try to reach it the way
that actor would, **quietly**, while the defenders operate as if it were a real intrusion. You are
not trying to find every bug; you are trying to test the *defensive response* against a plausible
adversary.

The most mature version drops the adversarial secrecy and asks *"let's find the detection gaps
together, fast."* — that's a **purple team** (15.2): red and blue in the same room, emulate a
technique, check whether it fired an alert, tune, re-test. Same techniques, collaborative loop.

## The underlying concepts

### Penetration test vs red team vs purple team

<div class="callout method">

| | **Penetration test** | **Red team** | **Purple team** |
|---|---|---|---|
| **Question** | What vulnerabilities exist? | Would we detect/stop a real adversary? | Where exactly are our detection gaps? |
| **Goal** | Breadth of findings | A specific objective (crown jewels) | Measured detection coverage |
| **Scope** | Broad (many assets) | Narrow, objective-focused | Technique-by-technique |
| **Stealth** | Usually not required | Central — emulate real OPSEC | Not required — loud on purpose |
| **Blue team knows?** | Often yes | No (or only a small "trusted agent") | Yes — collaborating |
| **Success looks like** | Long ranked findings list | Objective reached *or* caught | Alerts tuned, coverage raised |
| **Deliverable** | Findings + remediation | Attack narrative + detection gaps | Updated detections + coverage map |

</div>

These are points on a spectrum, not rival religions. The same person runs all three in a career;
the skill is knowing which one answers the client's question. A client with no SOC does not need a
covert red team — they need a pentest and, honestly, a SOC. A client with a mature SOC learns
nothing new from another vulnerability scan.

### The intrusion lifecycle, as ATT&amp;CK tactics

The kill chain (00.2) told a linear story; ATT&amp;CK tells a truer one — a set of **tactics** (the
adversary's goals) that an intrusion moves through, loops back into, and revisits. Walk the
lifecycle and notice that **you already know a technique for almost every tactic** from earlier
modules:

<div class="callout attack">

**The lifecycle as tactics (concept map — technique IDs are examples).**

- **Initial Access** (TA0001) — get a foothold. *T1190 Exploit Public-Facing Application* (M07),
  *T1566 Phishing* (concept), *T1078 Valid Accounts* (M10).
- **Execution** (TA0002) — run attacker code. *T1059 Command and Scripting Interpreter* (incl.
  .001 PowerShell, M05), *T1047 WMI* (M11).
- **Persistence** (TA0003) — survive a reboot/logout. *T1053 Scheduled Task/Job*, *T1543.003
  Windows Service*, *T1547 Boot/Logon Autostart* (M05).
- **Privilege Escalation** (TA0004) — gain higher rights. *T1548 Abuse Elevation Control*,
  *T1068 Exploitation for Priv Esc* (M04/M05).
- **Defense Evasion** (TA0005) — avoid detection. *T1218 System Binary Proxy Execution* (LOLBins),
  *T1027 Obfuscated Files* — **concepts covered in 15.2**.
- **Credential Access** (TA0006) — steal secrets. *T1558.003 Kerberoasting* (M06), *T1003 OS
  Credential Dumping* (M10), *T1110.003 Password Spraying* (M10).
- **Discovery** (TA0007) — learn the environment. *T1087 Account Discovery*, *T1482 Domain Trust
  Discovery*, *T1018 Remote System Discovery* (M06).
- **Lateral Movement** (TA0008) — move host to host. *T1021 Remote Services* (.002 SMB, .006 WinRM,
  .001 RDP), *T1550 Use Alternate Authentication Material* (PtH/PtT) (M11).
- **Collection** (TA0009) — gather target data. *T1074 Data Staged*, *T1560 Archive Collected Data*.
- **Command and Control** (TA0011) — remote control the foothold. *T1071 Application Layer
  Protocol*, *T1573 Encrypted Channel* — **concepts in 15.2**.
- **Exfiltration** (TA0010) — take the data out. *T1041 Exfil Over C2*, *T1567 Exfil Over Web
  Service*.
- **Impact** (TA0040) — the mission effect. *T1486 Data Encrypted for Impact*, *T1490 Inhibit
  System Recovery*.

(Two "pre-intrusion" tactics — *Reconnaissance* TA0043 and *Resource Development* TA0042 — precede
Initial Access; in a simulation these are largely modeled or provided rather than performed live.)

</div>

The lifecycle **loops**: reaching a foothold sends you back to Discovery *from the inside*; new
credentials reopen Lateral Movement. This is the same PTES spiral from 00.2, now named in the
vocabulary the whole industry shares with defenders.

### Threat-intelligence-driven emulation

A penetration test's attack path is opportunistic — you take whatever works. An **adversary
simulation** is *scripted from threat intelligence*: you pick a threat actor the client plausibly
faces (based on their sector, geography, and crown jewels), read the public reporting on how that
actor operates, and **emulate their specific TTPs** — their initial-access style, their tooling
choices, their persistence habits, their exfiltration channels.

Why bother constraining yourself this way? Because it makes the test **relevant** and the result
**actionable**. "We simulated *FIN7*'s known techniques and your EDR missed their persistence
method" tells a retail client something concrete about a threat they actually face. It also lets
the blue team pre-load the corresponding detections and measure precisely.

<div class="callout key">

**Emulation vs imitation.** You emulate an adversary's *techniques* (the ATT&amp;CK IDs and the
tradecraft pattern), not their literal malware. You do **not** need — and this course does not use —
the actor's real implant to test whether the defender detects the *technique*. A safe atomic test
of *T1053.005 Scheduled Task* exercises the same detection surface as the real actor's scheduled
task, without any weaponized payload. Detection lives at the technique level, which is exactly why
concepts-and-detection is a complete and legitimate way to teach this.

</div>

## Why this framing matters

Mapping an engagement to ATT&amp;CK is not decoration; it converts your work into something the
defender can measure. Because every technique page carries **Detection** guidance and **Data
Sources**, an ATT&amp;CK-mapped attack chain is *automatically* a detection test plan: each link
names both what you did and where they should have seen it. The client's output is a **coverage
map** — which of your techniques fired an alert, which were merely logged, and which were invisible.
That map, not a shell, is the deliverable of a mature engagement.

## How the two sides think

The operator thinks in **tactics and objectives**: "I need Credential Access to enable Lateral
Movement toward the objective; which technique is both effective *and* consistent with the adversary
I'm emulating, and how noisy is it?" The defender thinks in **data sources and detections**: "which
telemetry would this technique touch — process creation, authentication logs, named pipes, network
flow — and do I have a detection watching that source?"

Adversary simulation is the deliberate collision of those two mindsets. The operator's job is to
generate realistic activity across many data sources; the defender's job is to have coverage on
each; the engagement measures the gap. The **D3FEND** knowledge base (MITRE's defensive counterpart
to ATT&amp;CK) gives the countermeasure vocabulary — *Process Spawn Analysis*, *Network Traffic
Analysis*, *Authentication Event Thresholding* — so both sides can name not just the attack but the
specific defensive technique that should have caught it.

## Analysis: assembling an attack chain

An attack chain is an ordered list of techniques that moves from Initial Access to Impact/objective.
Building one on paper is a core M15 skill. The method:

1. **State the objective in the client's terms** — "read the finance share," "prove domain
   compromise," "reach the cardholder-data environment." The objective anchors everything.
2. **Work backward and forward to the tactics you must traverse.** To read a domain file share you
   likely need Initial Access → Execution → Credential Access → Discovery → Lateral Movement →
   Collection. Not every tactic every time.
3. **Pick one technique per link** — ideally one you already know (M06/M10/M11) and one consistent
   with the adversary you're emulating. Record the **technique ID**.
4. **For every link, name the detection data source** and, ideally, the specific event or telemetry.
   If you cannot name how a step would be seen, you do not yet understand the step.

<div class="callout defend">

**Worked micro-example (concept — no commands).** Objective: prove access to a domain file share.

| # | Tactic | Technique (ID) | Detection data source → concrete signal |
|---|---|---|---|
| 1 | Initial Access | Valid Accounts (T1078) | Authentication logs → anomalous logon (new host/geo), Windows **4624** |
| 2 | Discovery | Account/Trust Discovery (T1087/T1482) | Process + command-line → LDAP/`net`/`nltest` enumeration bursts |
| 3 | Credential Access | Kerberoasting (T1558.003) | Authentication logs → Windows **4769** RC4 ticket requests, spike per account |
| 4 | Lateral Movement | Remote Services: SMB (T1021.002) | Authentication + named pipe → **4624** type 3 + service/pipe creation on target |
| 5 | Collection | Data from Network Shares (T1039) | File access auditing → **5145** share-object access, unusual volume |

Every row pairs an offensive step with the telemetry that catches it. That pairing *is* the
engagement's value.

</div>

## Tooling as concept: emulation frameworks

These frameworks exist to **exercise detections**, not to weaponize. Understand what each does and
where it stops.

- **Atomic Red Team** (Red Canary) — a library of small, self-contained **atomic tests**, each
  mapped to a single ATT&amp;CK technique, designed to be run in seconds and cleaned up. Its purpose is
  *"fire technique T1XXX so the blue team can check whether their detection triggers."* Strength:
  granular, per-technique, safe-by-design, ideal for the purple-team loop (15.2). Limit: atomics are
  isolated actions, not a coherent adversary walking a chain — they test detection *breadth*, not a
  realistic *end-to-end* intrusion.
- **CALDERA** (MITRE) — an automated adversary-emulation platform: an operator server drives agents
  through **abilities** (technique implementations) assembled into **adversary profiles**, chaining
  Discovery → Credential Access → Lateral Movement autonomously. Strength: runs a *chain*
  automatically and repeatably, good for scaling emulation across many hosts. Limit: automation is
  more detectable and less adaptive than a human operator, and it must be run **only in the
  authorized lab/engagement** — its plugins include real technique implementations.
- **Adversary emulation plans** (MITRE Engenuity Center for Threat-Informed Defense) — free,
  published, step-by-step plans that reproduce a *named* actor's TTPs in ATT&amp;CK order (e.g. the
  APT3, APT29, FIN6, and menuPass plans). Strength: they turn threat intel into a runnable,
  intel-driven scenario — exactly the "emulate a named adversary" concept above. Limit: a plan is a
  scenario template, not authorization; you still scope, deconflict, and adapt it to the target.

<div class="callout warn">

**The reality of these tools.** CALDERA agents and Atomic tests contain working technique code. In
this course they are studied as **concepts** and, where run at all, only inside the isolated lab
against lab targets, per the safety boundary (00.1). None of them is a substitute for the
authorization, scoping, and deconfliction M15 keeps insisting on.

</div>

## Practical (tabletop)

<div class="lab">

**Environment:** paper/whiteboard + the live ATT&amp;CK site (attack.mitre.org) and D3FEND
(d3fend.mitre.org). **Time:** ~50 min. **Targets:** none — this is planning and analysis, done
*before* any authorized execution.

</div>

1. On the ATT&amp;CK Enterprise matrix, locate the twelve tactics of the intrusion lifecycle in order.
   For four of them (Initial Access, Credential Access, Lateral Movement, Exfiltration) open one
   technique and read its **Detection** and **Data Sources** sections.
2. Take the informal intrusion story you mapped in 00.2 and re-map it as a **tactic-ordered attack
   chain** with technique IDs — the same story, now in adversary-simulation form.
3. For each link, write the single data source a defender would watch. Where you can't name one,
   that's a gap in *your* understanding to close before you'd ever run the step.
4. Pick one published **adversary emulation plan** (e.g. APT29) and skim its first three steps;
   note which ATT&amp;CK techniques it uses for Initial Access and Persistence.

## Exercise

<div class="callout method">

**Situation.** **Meridian Health**, a mid-size hospital group, has a functioning SOC with an EDR and
a SIEM. They believe they would detect a ransomware crew. They engage you for an **adversary
simulation** (not a broad pentest). Their stated crown jewel: the patient-records database on an
internal segment reachable only after domain authentication. Threat intel suggests a financially
motivated, ransomware-affiliated actor that favors valid-account initial access, LOLBin execution,
and Kerberos-based lateral movement.

**Objective.** Design — on paper — an **ATT&amp;CK-mapped attack chain** from initial access to a
demonstrable impact on the crown jewel, emulating the described actor. This is a *plan*, not an
execution, and it must be detection-forward.

**Starting information.** Only the paragraph above, plus the ATT&amp;CK and D3FEND sites.

**Constraints.** Concepts and detection only — no payloads, no evasion recipes, no product-specific
techniques. Assume a properly scoped, signed engagement (00.1) and that you will deconflict with a
trusted agent. Respect that this is a hospital: your plan must *avoid* any step that risks patient
safety or availability, and say so.

**Expected deliverables.**
1. An ordered attack chain: for each link, the **tactic**, one **technique with ID**, and one
   sentence on *why this actor would use it*.
2. For **every** link, the **detection data source** and one concrete signal (event ID, log type,
   or telemetry) a defender should have.
3. A short "emulation vs the real thing" note: for two links, state how you would exercise the
   *technique* safely without the actor's real malware, and argue that the detection surface is the
   same.
4. One paragraph on **do-no-harm** choices specific to a hospital (which techniques you would *not*
   perform live, and the safer proof you would substitute).

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Start from the crown jewel and walk backward: to reach a DB behind domain auth you need valid
credentials and a route. That dictates Credential Access and Lateral Movement tactics; the actor's
"valid-account + Kerberos" profile chooses the techniques for you.
</details>

<details><summary>Hint 2 — technique family</summary>
Valid Accounts (T1078) for entry, PowerShell/LOLBin execution (T1059.001 / T1218), Kerberoasting
(T1558.003) or spraying (T1110.003) for creds, Remote Services / PtT (T1021 / T1550.003) for
movement, and — for a hospital — prove impact *without* detonating anything (stop at "I can reach
and read the DB," not "I encrypted it").
</details>

<details><summary>Hint 3 — where to look</summary>
Each technique page's Detection/Data Sources section hands you deliverable #2 directly. For
Kerberoasting that's authentication logs / event 4769; for SMB lateral movement, logon type 3 +
named-pipe/service creation; for LOLBins, process creation with command-line arguments.
</details>

<details><summary>Hint 4 — specific direction</summary>
The "do-no-harm" paragraph is where you show maturity: Impact techniques (T1486 encryption, T1490
recovery inhibition) are demonstrated by <em>capability</em>, not detonation, in a live hospital.
Name the substitute proof (a benign canary write, a read of a synthetic record) and the stop
condition.
</details>

## Check yourself

<div class="callout key">

1. A client with no SOC and no EDR asks you for a "red-team engagement." Why is that probably the
   wrong service for them, and what would you propose instead?
2. Give one intrusion that a *penetration test* would handle well but a *red team* would deliberately
   *not* pursue, and explain the difference in terms of goal and stealth.
3. You emulate *T1558.003 Kerberoasting* with a benign lab test instead of the named actor's real
   tooling. Argue why the blue team's detection result is still valid.
4. Why does mapping your attack chain to ATT&amp;CK make the engagement more useful to a *defender*
   than an equally successful but unmapped chain?
5. Your emulation of a chosen adversary reaches the objective and the SOC never alerts. Is that a
   "win"? For whom, and what does the report actually say?

</div>

Model answers and discussion are in `solutions/module-15.md` (instructor material — try the
questions before looking).

## References

- **MITRE ATT&amp;CK** — attack.mitre.org: the Enterprise matrix, the tactic and technique pages
  (read Detection and Data Sources), and the *Groups* pages for named-adversary TTPs.
- **MITRE D3FEND** — d3fend.mitre.org: the defensive countermeasure knowledge base that pairs with
  ATT&amp;CK.
- **MITRE Engenuity Center for Threat-Informed Defense — Adversary Emulation Library** — published,
  ATT&amp;CK-mapped emulation plans (APT3, APT29, FIN6, menuPass, and others).
- **MITRE Engenuity ATT&amp;CK Evaluations** — how EDR products are tested against emulated adversary
  scenarios; useful for understanding what "detection coverage" means in practice.
- **Atomic Red Company (Red Canary) — Atomic Red Team** — the per-technique atomic-test library.
- **MITRE CALDERA** — caldera.mitre.org: the automated adversary-emulation platform (studied here as
  a concept).
- **Scott Roberts &amp; Rebekah Brown, *Intelligence-Driven Incident Response*** — the threat-intel
  discipline behind intel-driven emulation.
- **Joe Vest &amp; James Tubberville, *Red Team Development and Operations*** — the professional
  framing of red-team objectives and engagement structure.

## What you should now be able to do

- Choose correctly between a penetration test, a red team, and a purple team for a client's real
  question, and justify the choice by goal, stealth, and deliverable.
- Walk the intrusion lifecycle as ATT&amp;CK tactics and place your existing techniques into it.
- Explain intelligence-driven emulation and the difference between emulating a technique and
  imitating malware.
- Build an ATT&amp;CK-mapped attack chain in which every link names both a technique ID and the
  detection data source that would catch it.
- Describe Atomic Red Team, CALDERA, and adversary emulation plans as detection-testing tools, with
  their limits.

## Progress checkpoint

```bash
py course.py complete 15.1
```
