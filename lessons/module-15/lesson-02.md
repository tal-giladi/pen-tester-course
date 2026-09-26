# 15.2 — Defense-evasion, C2 &amp; OPSEC concepts: detection-aware testing and the purple-team loop

<div class="prereq">

**Prerequisites:** [15.1 Adversary simulation vs pentesting](lesson-01.md);
[M00 Foundations](../module-00/lesson-01.md) (00.1 ethics/RoE, 00.2 ATT&amp;CK);
[M06 Active Directory](../module-06/lesson-01.md); [M11 Lateral movement](../module-11/lesson-01.md).
**Module:** M15 Adversary simulation concepts. **Difficulty:** 🔴⚫ advanced.
**You will produce:** a purple-team test plan for one technique you already know — how to emulate it
safely in the lab, what telemetry proves detection, and how to close a missed detection.

</div>

<div class="callout warn">

**Concepts and detection only — read this before anything else.** This lesson explains what
defense-evasion and C2 tactics *are*, *why* they work at a conceptual level, and — at length — *how
defenders detect them*. It contains **no** working evasion code, **no** obfuscation or
logging-tamper recipe, **no** implant, and **no** step-by-step technique tuned against a named
security product. That material is out of scope for this course by design (see the curriculum's
deliberate exclusions). If you want to *practice* detection, the safe path is the purple-team loop
below, run against lab targets with authorized, benign atomic tests.

</div>

## Why this matters

A red-team operator's effectiveness is measured against a defender, so the operator must understand
*why* real adversaries stay hidden and *exactly how* those hiding tactics are caught. That
understanding is what lets you design a test that teaches the SOC something. But the value flows the
other way too: the same knowledge, pointed at detection, is **detection engineering** — the craft of
building and tuning the alerts that catch these tactics. M15 sits on that seam. You learn the
offensive concept only far enough to build the defense, and the deliverable is always a better
detection, not a stealthier attack.

The professional posture here is **detection-aware testing**: knowing that most of what you do
generates telemetry, choosing actions with an understanding of their footprint, and — in an
authorized engagement — using that awareness to *measure* the defender rather than to defeat them
for its own sake.

## Learning objectives

By the end you can:

- Explain, conceptually, the major **defense-evasion** ideas — living-off-the-land/LOLBins,
  obfuscation, and logging/telemetry tampering — and, for each, **how a defender detects it**.
- Explain **C2** concepts — beaconing, jitter, channels, redirectors — and the network/host
  telemetry that reveals them, without building any of it.
- Apply **OPSEC** in its professional sense: deconfliction, avoiding business impact, evidence
  discipline, and clean-up.
- Run the **purple-team loop** — emulate → did the SOC detect? → tune → re-test — and express results
  as a coverage improvement.
- Reason honestly about **EDR reality** without producing an evasion recipe.

## Intuition

Every action an attacker takes touches something a computer can record: a process starts, a command
line is parsed, a registry key changes, a network connection opens, an authentication happens.
**Defense evasion is the art of making those recordings look normal** — reusing trusted programs,
hiding intent inside legitimate-looking data, or reducing what gets recorded at all. **C2 is the art
of a control channel hiding inside ordinary traffic.** In both, the adversary is not becoming
invisible; they are trying to **blend into the baseline**.

That reframes the defender's job precisely: detection is *anomaly against a known-good baseline*.
The more an operator blends in, the more the defense depends on rich telemetry, good baselines, and
behavioral (not signature) detection. Purple teaming is simply the two sides sitting together to
find where the blending currently succeeds — and fixing it.

## The underlying concepts — defense evasion

Each concept below is paired immediately with its detection. That pairing is the lesson.

### Living-off-the-land (LOLBins/LOLBAS)

<div class="callout attack">

**Concept (T1218 System Binary Proxy Execution, T1059 Command &amp; Scripting Interpreter).**
Instead of dropping a new tool, the adversary uses programs **already trusted and present** on the
system — signed OS binaries, admin utilities, scripting engines. On Windows these "living-off-the-
land binaries and scripts" are catalogued by the community **LOLBAS** project; on Unix, **GTFOBins**.
*Why it evades:* signature/reputation and allow-listing tuned to block *unknown* binaries see a
trusted, signed, expected program — so file-based and reputation-based detection has nothing to bite.

</div>

<div class="callout defend">

**Detection.** LOLBins defeat *file* detection, so you detect the **behavior**, not the file. The
data source is **process creation with full command-line** (Windows event **4688** with command-line
auditing enabled, or **Sysmon Event ID 1**) plus **parent-child process relationships**. A trusted
binary is suspicious *in context*: a document reader spawning a script host; a signed utility making
outbound network connections; an admin tool invoked with argument patterns typical of abuse rather
than administration. D3FEND names the countermeasures — *Process Spawn Analysis*, *Process Lineage
Analysis*, *Script Execution Analysis*. **Sigma** rules encode exactly these "trusted binary,
untrusted context" patterns; this is where detection engineering earns its keep, because the answer
is never "block the binary."

</div>

### Obfuscation and encoding

<div class="callout attack">

**Concept (T1027 Obfuscated Files or Information; related T1140 Deobfuscate/Decode).** The adversary
transforms scripts, commands, or payloads — encoding, packing, string-splitting — so that
signature-based detection matching known-bad strings fails to match. *Why it evades:* a static
signature is looking for a specific byte pattern; change the representation and the pattern is gone,
even though the *behavior* on execution is unchanged.

</div>

<div class="callout defend">

**Detection.** Obfuscation defeats static string-matching, so defenders move **later in the
lifecycle** and to **statistical** signals. Command-line and script **entropy/length anomalies**,
telemetry of the *decoded* content at runtime (script-block logging captures what actually
executed), and the behavior *after* deobfuscation are the tells. On Windows, **PowerShell
Script-Block Logging (event 4104)** records the de-obfuscated script the engine ran, and the
**Antimalware Scan Interface (AMSI)** lets security products inspect script content *at execution
time*, after any encoding is undone. The concept to hold: heavy obfuscation is itself an anomaly —
legitimate admin scripts are rarely base64-wrapped and string-reversed — so "the presence of
obfuscation" becomes a detection signal in its own right.

</div>

### Telemetry and logging tampering

<div class="callout attack">

**Concept (T1562 Impair Defenses; T1070 Indicator Removal).** Rather than hide within logs, an
adversary may try to reduce or remove the recording: stopping or blinding a security agent, disabling
a logging channel, or clearing logs after the fact. *Why it's attempted:* if the telemetry never
exists, behavioral detection has nothing to analyze. This is described here **as a concept only** —
no method, no commands.

</div>

<div class="callout defend">

**Detection — and why tampering is loud.** The key insight: **turning off telemetry is itself a
high-fidelity signal.** The act of disabling logging, stopping a security service, or clearing an
event log *generates* events — Windows **1102** (audit log cleared), Sysmon **service-state** and
config-change events, security-agent tamper-protection alerts. Mature defenders therefore forward
logs **off-box in real time** (to a SIEM the attacker can't reach), enable **tamper protection** on
the EDR, and alert specifically on gaps — a host that suddenly stops sending logs is *more*
suspicious, not less. D3FEND frames this as *Platform Monitoring* and *System Daemon Monitoring*.
The design principle for the blue team: assume the endpoint is contested and put the source of truth
where the attacker isn't.

</div>

## The underlying concepts — command and control (C2)

C2 is how an operator remotely controls a foothold. All the concepts below are network/behavior
patterns; none require you to build a channel.

- **Beaconing** (T1071 Application Layer Protocol) — the implant periodically "checks in" to the
  operator for tasking rather than holding an open connection. *Why it blends:* short, periodic
  callbacks resemble ordinary polling (software update checks, telemetry).
- **Jitter** — randomizing the beacon interval so callbacks aren't perfectly periodic. *Why:* to
  defeat detection that keys on the *regularity* of the interval.
- **Channels** (T1071 .001 Web/HTTPS, .004 DNS; T1573 Encrypted Channel) — the protocol the beacon
  rides: HTTPS to look like web traffic, DNS to abuse a protocol that's almost never blocked,
  encryption to hide content.
- **Redirectors / proxies** (T1090 Proxy; T1584 Compromised Infrastructure as a concept) — an
  intermediary that stands between the victim and the operator's real server, so defenders and
  responders see only the redirector. Domain-fronting-style techniques and CDN abuse are the
  higher-end version.

<div class="callout defend">

**Detection of C2.** Content hiding (encryption) pushes defenders to **metadata and behavior**, which
is where beacons are caught:

- **Beacon periodicity** — even with jitter, repeated callbacks to the same destination form a
  statistical pattern; **network flow analysis** (NetFlow/Zeek) detects regular low-volume outbound
  connections. D3FEND: *Network Traffic Analysis*, *Outbound Traffic Filtering*.
- **Destination reputation and novelty** — first-seen domains, young domains, and non-business
  destinations stand out; **DNS analytics** catch high-volume or high-entropy DNS queries typical of
  DNS tunneling (T1071.004) and domain-generation algorithms (T1568.002).
- **TLS/JA3-style fingerprinting** — the *shape* of the encrypted handshake can distinguish tooling
  from a normal browser without decrypting anything.
- **Egress control** — a network that only permits outbound through an authenticated proxy, blocks
  unusual protocols/ports, and inspects DNS gives beacons far fewer places to hide. Prevention is a
  form of detection surface.

The concept to internalize: **you cannot hide the fact that something is talking out on a schedule;
you can only try to make it look normal.** Detection is baseline-relative, so a good baseline is the
defender's strongest asset.

</div>

## OPSEC — in the professional, ethical sense

In red teaming, **OPSEC** does not mean "avoid getting caught for its own sake." It means operating
so that your *authorized* activity is realistic, controlled, safe, and attributable to you when it
must be. The pillars:

<div class="callout method">

- **Deconfliction.** A named **trusted agent** on the client side knows an engagement is live so
  that if your activity is spotted, a real incident response isn't launched against a phantom — and
  conversely, so a *real* concurrent attacker isn't mistaken for you. You maintain an **activity log**
  (timestamped: what, where, from which source IP) so any observed event can be confirmed as "that
  was the red team" within minutes.
- **Avoiding business impact.** You choose techniques that don't threaten availability or safety. No
  destructive Impact techniques against production; no denial of service; extreme care with anything
  touching production data. On sensitive targets (hospitals, OT/ICS, finance) you prove *capability*
  rather than detonating effect (15.1's do-no-harm principle).
- **Evidence discipline.** Access the minimum needed to prove a finding, handle any sensitive data
  per the RoE (00.1), and keep clean evidence for the report (M16) rather than hoarding data.
- **Clean-up.** Everything you create — accounts, scheduled tasks, services, dropped files,
  persistence — is inventoried and **removed** at the end, exactly as you'd clean a dropped SUID
  binary in M04. Leaving live persistence behind is a real risk you created for the client.

</div>

<div class="callout legal">

Every concept in this lesson is exercised **only** within a signed, scoped engagement (00.1) or the
course's isolated lab against lab targets with synthetic markers. Evasion and C2 concepts have no
legitimate use against systems you are not explicitly authorized to test, and "I was practicing" is
not authorization. The deconfliction and clean-up discipline above is not optional politeness — it
is what keeps an authorized simulation from becoming an incident.

</div>

## The purple-team loop

This is the heart of M15's detection focus and the safest, most productive way to apply everything
above. The loop:

<div class="callout method">

1. **Select a technique** to test, by ATT&amp;CK ID, chosen from a real threat model or a coverage gap
   (e.g. *T1558.003 Kerberoasting*).
2. **Emulate it safely** — the smallest benign action that produces the same telemetry as the real
   technique. An **Atomic Red Team** test, or a hand-run lab action, against a **lab target**. No
   weaponized payload is needed because detection lives at the technique level (15.1).
3. **Observe the defense.** Did the SOC's SIEM/EDR **alert**? Was the activity merely **logged** but
   not alerted? Or was it **invisible** (no telemetry at all)? Record which of the three.
4. **Diagnose the gap.** Invisible = missing **data source** (turn on the logging: command-line
   auditing, 4769, script-block logging). Logged-but-no-alert = missing/weak **detection rule**.
   Alerted-but-slow/noisy = **tuning** problem.
5. **Tune** — write or fix the detection (often a **Sigma** rule mapped to the technique), enable the
   telemetry, adjust the threshold.
6. **Re-test** — run the same emulation again and confirm the alert now fires cleanly. Record the
   before/after as a **coverage improvement**.

</div>

The output is a **detection coverage matrix** — techniques down the side, "detected / logged /
blind" across — that grows greener each cycle. Tools like **VECTR** track this over time; the
**Purple Team Exercise Framework (PTEF)** gives the whole exercise a repeatable structure (planning,
execution, lessons-learned, retest). This is a genuinely collaborative, non-adversarial exercise:
red teaches blue what the activity looks like, blue teaches red what they can and can't see, and the
organization's detection measurably improves.

## Tooling as concept

- **Sysmon** (Sysinternals) — a Windows telemetry engine that logs rich process, network, and file
  events (Event ID 1 process create with command line and hashes, 3 network connect, 7 image load,
  11 file create, and more). It is the **detection data source** many rules depend on; a well-tuned
  Sysmon config (e.g. the SwiftOnSecurity or Olaf Hartong baselines) is often step one of closing a
  blind spot.
- **Sigma** — a vendor-neutral detection-rule format ("the YAML of detections"). You write the logic
  once, mapped to an ATT&amp;CK technique, and convert it to your SIEM's query language. Sigma is how a
  purple-team finding becomes a durable, shareable detection.
- **Atomic Red Team** — (15.1) the per-technique emulation library that drives step 2 of the loop.
- **CALDERA** — (15.1) automates multi-step emulation; useful for regression-testing a whole chain's
  coverage after tuning.
- **VECTR / PTEF** — tracking and framework for running the loop as a repeatable program, not a
  one-off.

## EDR reality, honestly

Modern **Endpoint Detection and Response** watches process trees, command lines, memory,
API/syscall behavior, and network activity, correlating them into behavioral detections — far beyond
the signature antivirus of a decade ago. Real adversaries invest heavily in evading it, and it is
professionally dishonest to pretend EDR is either trivial to bypass or impossible to bypass.

<div class="callout warn">

**What this course will and won't say.** It is *true* that determined operators evade EDR; the
**MITRE Engenuity ATT&amp;CK Evaluations** publish exactly how well products detect emulated
adversaries, and the results show real gaps as well as real strength. What this course will **not**
do is hand you a working bypass for a named product — that is weaponization, it dates instantly, and
it teaches nothing durable. The durable lesson is the opposite one: **evasion is an arms race that
the defender wins with telemetry breadth, off-box log integrity, behavioral detection, and the
purple-team loop.** Your job as the offensive half of that loop is to generate realistic activity
and *measure* the gaps honestly — not to collect bypasses.

</div>

## Practical (analysis)

<div class="lab">

**Environment:** paper + the live ATT&amp;CK/D3FEND sites and the Sigma and Atomic Red Team public
repositories (reading only). **Time:** ~50 min. **Targets:** none — analysis and planning. Any
actual emulation happens later, only against lab targets under the safety boundary (00.1).

</div>

1. Pick one technique from a module you've done (Kerberoasting M06, or PsExec-style SMB execution
   M11). On its ATT&amp;CK page, list its **Data Sources**.
2. Find (don't write) a public **Sigma** rule for that technique and read its logic: which log
   source, which fields, which condition. Note what would make it *miss* (blind spot) and what would
   make it *noisy* (false positives).
3. Sketch the purple-team loop for that technique on paper: emulation step (which Atomic test or lab
   action), expected telemetry, the three possible outcomes, and the tuning move for each.
4. For one C2 concept (beaconing with jitter, or DNS as a channel), write the one network signal you
   would build a detection on and why encryption doesn't defeat it.

## Exercise

<div class="callout method">

**Situation.** You're running a **purple-team exercise** with **Meridian Health**'s SOC (the client
from 15.1). They want to know whether they detect the lateral-movement and credential-access
techniques your simulated actor favors. Pick **one** technique you already know well —
**Kerberoasting (T1558.003)** from M06, **or** **PsExec-style SMB service execution (T1021.002 /
T1569.002)** from M11.

**Objective.** Produce a complete, detection-forward **purple-team test plan** for that one
technique — the full loop, on paper.

**Starting information.** The technique's ATT&amp;CK page, D3FEND, and the public Sigma/Atomic
repositories (reading only).

**Constraints.** Concepts and detection only. All emulation is **against lab targets** with synthetic
credentials/markers under the safety boundary (00.1); state the deconfliction and clean-up steps.
No evasion code, no product-specific bypass.

**Expected deliverables.**
1. **Safe emulation:** the smallest benign action (an Atomic test or a described lab step) that
   produces the *same telemetry* as the real technique, and one sentence on why the detection surface
   is identical to the real thing.
2. **Proof-of-detection telemetry:** the exact data source(s) and concrete signal(s) that would prove
   the SOC detected it — for Kerberoasting, name the event and the anomaly (e.g. **4769** RC4 ticket
   requests, volume/encryption-type anomaly); for PsExec, the logon type, **service creation (7045)**,
   and named-pipe telemetry.
3. **Missed-detection remediation:** if the technique came back *logged-but-not-alerted* or *blind*,
   state precisely how you'd close it — which telemetry to enable and/or the logic of the Sigma rule
   you'd write (fields + condition, not necessarily final syntax) — and how you'd **re-test** to
   confirm.
4. **OPSEC/safety note:** the deconfliction (trusted agent, activity log entry) and clean-up
   (remove any created service/task/account) you'd perform, framed for a live hospital environment.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
The whole exercise is the loop: emulate → observe (detected/logged/blind) → diagnose → tune →
re-test. Structure your answer as those steps. The technique you pick only changes the specific
telemetry, not the shape of the plan.
</details>

<details><summary>Hint 2 — technique family</summary>
Kerberoasting's fingerprint is a burst of Kerberos <em>service-ticket requests</em> (event 4769),
classically for RC4 (encryption type 0x17) against many SPNs from one account — that volume +
encryption-type combination is the detection. PsExec's fingerprint is a type-3 logon plus a
<em>service install</em> (7045) and the classic named pipe on the target.
</details>

<details><summary>Hint 3 — where to look</summary>
Deliverable #3 is detection engineering: "blind" means the data source is off (enable Kerberos
logging / command-line + service auditing / Sysmon); "logged but no alert" means write the Sigma
rule (source = Security/Sysmon log, fields = event ID + encryption type or service image, condition
= threshold or known-bad context). Re-test = run the same Atomic again and confirm the alert fires.
</details>

<details><summary>Hint 4 — specific direction</summary>
The maturity marker is deliverable #4: in a hospital you emulate against a <em>lab</em> replica or a
non-clinical test host, you log the activity with the trusted agent <em>before</em> you run it so the
4769 spike isn't chased as a real incident, and you remove any service/account you created. Say the
stop condition explicitly.
</details>

## Check yourself

<div class="callout key">

1. LOLBins defeat file-based and reputation-based detection. What data source do you pivot to
   instead, and what makes a *trusted* binary suspicious?
2. Why is **disabling logging** often easier to detect than the quiet technique it was meant to hide,
   and what defensive design makes that true?
3. An operator adds heavy **jitter** to a beacon to break interval-based detection. Name two other
   C2 signals a defender still has, given they can't read the encrypted content.
4. In the purple-team loop, you get "logged but no alert." Which specific step failed, and what's the
   fix — versus the fix when you get "blind (no telemetry)"?
5. Explain, to a client executive, why this course teaches evasion *concepts and their detection*
   rather than working evasion techniques — and why that's the more valuable deliverable for their
   security program.
6. Why is **deconfliction** (a trusted agent + activity log) both an OPSEC control *and* a safety
   control, especially in a hospital engagement?

</div>

Model answers and discussion are in `solutions/module-15.md` (instructor material — try the
questions before looking).

## References

- **MITRE ATT&amp;CK** — Defense Evasion (TA0005) and Command and Control (TA0011) tactic pages, and
  techniques T1218, T1027, T1562, T1070, T1071, T1573, T1090; read each page's Detection/Data
  Sources.
- **MITRE D3FEND** — d3fend.mitre.org: *Process Spawn/Lineage Analysis*, *Script Execution
  Analysis*, *Network Traffic Analysis*, *Platform Monitoring* countermeasures.
- **LOLBAS** (lolbas-project.github.io) and **GTFOBins** (gtfobins.github.io) — catalogues of
  living-off-the-land binaries, studied here to understand *detection context*, not for abuse.
- **Sysmon** — Microsoft Sysinternals documentation; community configs (SwiftOnSecurity,
  Olaf Hartong's `sysmon-modular`).
- **Sigma** — github.com/SigmaHQ/sigma: the generic detection-rule format and rule library.
- **Atomic Red Team** — atomicredteam.io / github.com/redcanaryco/atomic-red-team.
- **Purple Team Exercise Framework (PTEF)** — SCYTHE's published framework; **VECTR** for tracking
  coverage.
- **MITRE Engenuity ATT&amp;CK Evaluations** — attackevals.mitre-engenuity.org: EDR detection results
  against emulated adversaries.
- **Microsoft AMSI** and **PowerShell Script-Block Logging (event 4104)** documentation — runtime
  script inspection and logging, on the detection side.

## What you should now be able to do

- Explain LOLBins, obfuscation, and logging tampering as concepts and, for each, name the data
  source and signal that detects them.
- Explain beaconing, jitter, channels, and redirectors, and the network/host telemetry that reveals
  C2 despite encryption.
- Apply professional OPSEC — deconfliction, do-no-harm, evidence discipline, clean-up — to an
  authorized engagement.
- Run the purple-team loop end to end and express the result as a measurable coverage improvement.
- Reason honestly about EDR without reaching for (or needing) a working evasion recipe.

## Progress checkpoint

```bash
py course.py complete 15.2
```
