# Instructor / solutions — Module 15 (Adversary simulation concepts)

> Instructor material. Not linked from `_sidebar.md`. Do the exercises before reading.

M15 is a **concepts-and-detection** module: there is no lab target to compromise and no payload to
run. Grade on **reasoning, correct ATT&amp;CK mapping, and — above all — whether every offensive
concept is paired with a concrete detection** (data source + signal). The universal bar: any
submission that supplies working evasion/obfuscation/C2 code, a product-specific bypass, or proposes
running these techniques outside the isolated lab / a signed-and-scoped engagement fails the
professionalism bar (00.1, and the M15 safety boxes) regardless of technical cleverness. Reward the
student who *declines* to weaponize and instead deepens the detection.

Technique IDs below are the expected/most-common answers; ATT&amp;CK evolves, so accept a correct
adjacent technique with sound justification. The point is the *mapping discipline*, not memorizing
numbers.

---

## 15.1 — Adversary simulation vs penetration testing

**Exercise (ATT&amp;CK-mapped attack chain for Meridian Health).** Full credit is a tactic-ordered
chain that reaches a *demonstrable* impact on the patient-records DB while emulating the described
actor (valid-account entry, LOLBin execution, Kerberos lateral movement), with **a detection data
source on every link**, a safe-emulation note for two links, and a hospital-specific do-no-harm
paragraph. A strong model chain:

| # | Tactic | Technique (ID) | Why this actor | Detection data source → signal |
|---|---|---|---|---|
| 1 | Initial Access | Valid Accounts (T1078) | actor favors valid-account entry (bought/sprayed creds) | Authentication logs → **4624** anomalous logon (new host/geo/time) |
| 2 | Execution | Command &amp; Scripting: PowerShell (T1059.001) / LOLBin (T1218) | actor lives off the land | Process creation + command line → **4688**/Sysmon **1**, parent-child anomaly |
| 3 | Discovery | Account / Domain Trust Discovery (T1087/T1482) | map the domain to find the DB path | Process + command-line → LDAP/`net`/`nltest` bursts |
| 4 | Credential Access | Kerberoasting (T1558.003) or Password Spraying (T1110.003) | Kerberos-centric TTPs | Authentication logs → **4769** RC4 ticket spike / **4625** spray pattern |
| 5 | Lateral Movement | Remote Services SMB (T1021.002) / Pass-the-Ticket (T1550.003) | Kerberos-based movement | Auth + named pipe/service → **4624** type 3, **7045**, pipe creation |
| 6 | Collection | Data from Information Repositories / Network Shares (T1213/T1039) | reach the DB | DB audit logs / file-access **5145** → unusual query/volume |
| 7 | Impact (proof only) | *demonstrate* Data Encrypted for Impact (T1486) capability — **do not detonate** | show ransomware relevance | n/a — proof is capability, not effect |

Grading emphasis:

- **Objective-anchored, not opportunistic.** The chain must aim at the stated crown jewel and reflect
  the *named actor's* style; a generic "find everything" pentest plan misses the point of 15.1
  (breadth vs objective/stealth). Dock for a chain that ignores the intel profile.
- **Detection on every link is mandatory** — a link without a data source is an incomplete answer,
  exactly as remediation-or-detection-missing is docked throughout the course.
- **Emulation vs the real thing (deliverable 3).** Full credit for two links argues detection lives at
  the *technique* level: e.g. a benign Kerberoasting request produces the same **4769** telemetry as
  the actor's tool; a benign scheduled-task creation produces the same **4698**/Sysmon signal — so no
  weaponized payload is needed to test the detection. Reward this explicitly; it is the module's
  central idea.
- **Do-no-harm (deliverable 4) is the maturity marker.** Correct answer: in a live hospital you do
  **not** perform destructive Impact (T1486 encryption, T1490 recovery inhibition) or anything
  risking availability/patient safety; you prove *capability* (a benign canary write, a read of a
  synthetic record, "I demonstrably had write access to the share") and state a stop condition +
  deconfliction. A student who plans to "encrypt a test folder to prove ransomware" on production has
  failed the safety judgment even if technically scoped.

Docking: opportunistic breadth instead of objective/stealth; any link missing detection; treating
"got to the DB" as the deliverable rather than the measured detection gaps; a plan that would detonate
impact in a hospital; requesting the actor's real malware "for realism."

**Check-yourself.**
1. A red team tests *detection and response*; a client with no SOC/EDR has nothing to detect *with*,
   so a covert red team would quietly succeed and teach them almost nothing — an expensive way to
   learn "we have no visibility." Propose instead a **penetration test** (find and rank the
   vulnerabilities they should fix first) and, candidly, building detection capability; a red team is
   the right service *after* they have a SOC to exercise. Right service for the maturity level.
2. Example: a low-severity but *broad* finding like reflected XSS on a marketing page, or enumerating
   every missing patch across 500 hosts. A pentest wants that breadth on the findings list; a red team
   deliberately ignores it because it doesn't advance the *objective* and generates noise that risks
   detection — the red team takes the *one quiet path* to the crown jewel, not the *many* paths. Goal
   (breadth vs objective) and stealth (irrelevant vs central) drive the difference.
3. Detection fires on the **technique's telemetry**, not on the specific binary. Kerberoasting is
   detected by the **4769** service-ticket request pattern (volume + RC4/encryption-type anomaly);
   that telemetry is produced identically whether the requests come from the actor's tool or a benign
   lab emulation. So a missed detection in the benign test means the detection would also miss the
   real actor — the result is valid. (This is precisely why concepts-and-detection is a complete way
   to teach the discipline.)
4. An ATT&amp;CK-mapped chain hands the defender a **coverage map**: each technique page carries
   Detection/Data Sources, so they can check, per technique, whether they alerted, merely logged, or
   were blind — and prioritize fixes. An unmapped "we got in" narrative tells them the *outcome* but
   not *which detections to build*; it isn't actionable at the technique level. Mapping converts an
   attack into a measurable, improvable defensive to-do list.
5. Reaching the objective undetected is a **win for the report, not for the client's security** — it
   means the simulation found real, unmonitored gaps, which is the *purpose*. The report says: which
   techniques were blind vs logged vs alerted, the specific telemetry/detections missing at each step,
   and a prioritized remediation + detection-engineering plan (feeding the 15.2 purple-team loop). "We
   succeeded" is worthless without "here is exactly where you couldn't see us and how to fix it."

---

## 15.2 — Defense-evasion, C2 &amp; OPSEC concepts and the purple-team loop

**Exercise (purple-team test plan for one technique).** Full credit is the *entire loop on paper* for
the chosen technique, detection-forward, with a safe emulation, concrete proof-of-detection telemetry,
a real remediation for a missed detection (distinguishing "blind" from "logged-but-no-alert"), and an
OPSEC/safety note fit for a hospital. Model answers for the two offered techniques:

### If they chose Kerberoasting (T1558.003)

- **Safe emulation:** request a service ticket (TGS) for one or more SPNs from a normal domain user —
  an **Atomic Red Team** T1558.003 test or the M06 lab action against the **lab DC**, not production.
  One-sentence justification: the request produces the same **event 4769** telemetry as a real
  Kerberoasting tool, so the detection surface is identical without cracking anything or using a
  weaponized payload.
- **Proof-of-detection telemetry:** Domain-Controller **Security log event 4769** (Kerberos
  service-ticket requested), and the *anomaly* that distinguishes attack from noise — a **burst** of
  4769s for many distinct SPNs from **one** account, and **RC4 (encryption type 0x17)** requested
  where the environment normally uses AES. The detection is the volume + encryption-type combination,
  not any single 4769 (those are normal).
- **Missed-detection remediation:**
  - *Blind* (no 4769 at all): Kerberos service-ticket-operations auditing isn't enabled on the DCs —
    enable it (audit policy), confirm 4769 now flows to the SIEM, re-test.
  - *Logged but no alert:* write a **Sigma** rule — source = DC Security log, selection = EventID 4769
    + TicketEncryptionType 0x17, condition = count of distinct ServiceName by the same
    TargetUserName over a short window exceeds a threshold; tune the threshold against a baseline to
    control false positives. Convert to the SIEM query language.
  - **Re-test:** run the same atomic again, confirm the alert fires cleanly and quickly.
- **Defensive note (bonus):** the durable fix is also **gMSA/AES-only** service accounts so RC4
  roasting is far less useful (ties back to M06/M10 remediation), but that's hardening — the exercise
  is about *detecting* it.

### If they chose PsExec-style SMB execution (T1021.002 / T1569.002)

- **Safe emulation:** perform an authenticated SMB service-execution against a **lab target** (M11
  action or an Atomic test for T1021.002/T1569.002) with synthetic creds. Justification: it creates
  the same host/network artifacts as the real tool — a type-3 logon, a **service install (7045)**, and
  the classic named pipe — so detection is exercised identically.
- **Proof-of-detection telemetry:** on the target, **4624 logon type 3** (network) from the source
  host, **event 7045** (a new service installed) and/or Sysmon **service-creation**, plus **named-pipe
  creation** telemetry (Sysmon Event ID 17/18) matching the PsExec pipe pattern; correlate source →
  destination.
- **Missed-detection remediation:**
  - *Blind:* enable command-line process auditing (**4688** + command line) / deploy **Sysmon** with a
    config that logs process, service, and pipe events; confirm telemetry, re-test.
  - *Logged but no alert:* Sigma rule — source = Security/System/Sysmon, selection = 7045 with a
    randomly-named or single-char service image in a temp/writable path, or pipe-name pattern + a
    preceding type-3 logon; condition = that correlation from a non-admin-management source. Tune to
    exclude legitimate deployment tooling.
  - **Re-test** the atomic, confirm the alert.
- **Defensive note (bonus):** restrict who can remotely create services / reach admin shares; ties to
  M11 remediation.

Grading emphasis (both):

- **The loop shape must be present** — emulate → observe (detected/logged/blind) → diagnose → tune →
  re-test. A plan that stops at "run it and see" without the tuning/re-test half is incomplete.
- **Distinguish blind from logged-but-no-alert** (deliverable 3). This is the core detection-
  engineering insight: *blind = enable the data source; logged-but-no-alert = write/fix the rule*.
  Conflating them is the most common miss — dock for it.
- **Safe emulation reasoning** — the student must argue the benign test hits the *same telemetry* as
  the real technique. If they think they need the real malware, they've missed 15.1's central idea.
- **OPSEC/safety (deliverable 4) is required, doubly so for a hospital.** Correct: log the activity
  with the **trusted agent before** running it so the 4769/7045 spike isn't chased as a real incident;
  emulate against a lab/non-clinical host, not clinical production; **remove** any service/account/task
  created (clean-up, as with a dropped SUID binary in M04); state the stop condition. Missing
  deconfliction or clean-up is a professionalism dock.

Docking: any working evasion/obfuscation/C2 code or product-specific bypass (hard fail — the exercise
explicitly forbids it); loop missing the tune/re-test half; blind vs no-alert conflated; no safe-
emulation justification; missing deconfliction/clean-up; proposing to run against production hospital
systems.

**Check-yourself.**
1. Pivot from *file* detection to **behavior**: **process creation with full command line** (4688 /
   Sysmon 1) and **parent-child/lineage** analysis. A trusted, signed binary is suspicious **in
   context** — invoked by an unusual parent (a document reader spawning a script host), with
   abuse-pattern arguments, from an unusual path, or making unexpected network connections. You detect
   the *use*, never the file (you can't block the OS's own binaries). D3FEND: Process Spawn/Lineage
   Analysis.
2. Disabling logging, stopping a security service, or clearing a log **generates its own events** —
   Windows **1102** (log cleared), Sysmon service-state/config-change, EDR tamper-protection alerts —
   and it's a rare, high-fidelity anomaly (normal operations don't clear the Security log). The design
   that makes it detectable: **forward logs off-box in real time** to a SIEM the attacker can't reach,
   enable **tamper protection**, and **alert on the gap** (a host that goes silent is *more*
   suspicious). The source of truth lives where the attacker isn't.
3. With content encrypted, defenders still have: **beacon periodicity** — even jittered, repeated
   callbacks to one destination form a statistical pattern in **network flow** analysis; **destination
   reputation/novelty** — first-seen/young/non-business domains, or high-entropy/high-volume **DNS**
   (tunneling/DGA); and **TLS/JA3-style handshake fingerprinting** — the *shape* of the encrypted
   session distinguishes tooling from a browser without decryption. (Any two.) Jitter breaks only the
   *interval-regularity* signal, not these.
4. "Logged but no alert" = the **data source exists but the detection rule is missing or too weak** —
   fix by **writing/tuning the rule** (e.g. a Sigma rule with the right fields + threshold) and
   re-testing. "Blind (no telemetry)" = the **data source itself is off** — fix by **enabling the
   logging/telemetry** (command-line auditing, 4769, script-block logging, deploy Sysmon) *first*,
   then you can even build a rule. Different failures, different fixes: turn on the sensor vs. write
   the detection.
5. For the executive: working evasion techniques are **product-specific and perishable** — they break
   with the next EDR update, teach nothing durable, and are the weaponization half of the craft the
   course deliberately excludes. Teaching the **concepts and their detection** produces something that
   *lasts and improves the security program*: analysts who understand why an attacker blends in and
   therefore how to build telemetry and detections that catch the *class* of technique, plus a
   repeatable purple-team loop that raises measurable coverage. The deliverable is a stronger,
   self-improving defense — not a bag of tricks that expires.
6. **Deconfliction** is an **OPSEC** control because it keeps the *authorized* activity attributable —
   a trusted agent + timestamped activity log lets any spotted event be confirmed as "the red team"
   within minutes, and stops a *real* concurrent attacker from being mistaken for you (or vice-versa).
   It's a **safety** control because it prevents the client from launching a costly, disruptive **real
   incident response** against your phantom — in a hospital, an IR fire-drill (isolating hosts,
   pulling systems) could itself threaten patient care. So the same log that makes you attributable
   also prevents your test from causing the very business impact you're sworn to avoid.

---

## Grading notes (both lessons)

- **Detection is not optional — it's the deliverable.** Every offensive concept must be paired with a
  data source + concrete signal. This mirrors the course-wide "remediation AND detection on every
  finding" rule, intensified: in M15 the detection *is* the point. A brilliant attack chain with no
  detection mapping is a failing answer.
- **Concepts, never weaponization.** Zero credit — a hard fail — for supplying working evasion,
  obfuscation, C2, or a named-product bypass, or for asking for one. Reward students who explicitly
  keep to concepts-and-detection; that judgment is a graded outcome, not a limitation to apologize
  for.
- **ATT&amp;CK mapping discipline.** Correct tactic/technique/ID and correct use of Data Sources
  matters more than exact numbers; accept sound adjacent mappings. D3FEND countermeasure naming is a
  bonus that shows they can speak to both sides.
- **Objective + stealth thinking (15.1).** Reward answers that show the pentest→red→purple distinction
  operationally (breadth vs objective vs collaboration), not just as definitions.
- **The loop, whole (15.2).** The tune-and-re-test half separates a real purple-team plan from "run a
  test." Insist on it, and on the blind-vs-no-alert diagnosis.
- **Safety and OPSEC are doubled here.** Lab-only/authorized-engagement scope, deconfliction (trusted
  agent + activity log), do-no-harm (no destructive impact, prove capability), evidence discipline,
  and clean-up are all graded — especially in the hospital scenario. A technically strong answer that
  would detonate impact in production, skip deconfliction, or leave persistence behind fails the
  professionalism bar, exactly as it would on a real engagement.
