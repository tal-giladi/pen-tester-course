# 03.3 — Vulnerability discovery &amp; prioritization: from findings to a plan

<div class="prereq">

**Prerequisites:** [00.1 Ethics &amp; authorization](../module-00/lesson-01.md),
[00.3 Threat modeling &amp; attack surface](../module-00/lesson-03.md),
[01.1 Networking](../module-01/lesson-01.md),
[02.1 Reconnaissance](../module-02/lesson-01.md),
[03.1 Port scanning](lesson-01.md), [03.2 Service enumeration](lesson-02.md).
**Module:** M03 Scanning &amp; enumeration. **Difficulty:** 🟡 intermediate.
**You will produce:** a ranked, justified testing plan — a prioritized hypothesis list built from a
set of enumerated services, scored by impact × likelihood, not an exhaustive dump.

</div>

<div class="callout legal">

This lesson turns enumeration into a *plan*; it does not exploit anything. Running a vulnerability
scanner is still **active** and needs authorization ([00.1](../module-00/lesson-01.md)), and some
scanner checks are intrusive. All targets are **LAB TARGETS** on the isolated network; `TARGET` is
always a lab host. Validation of any hypothesis happens only in the lab, per RoE.

</div>

## Why this matters

By now you have a pile of facts: open ports, versions, shares, banners. A junior tester turns that
into a 40-item to-do list and works top to bottom until time runs out — usually finishing the easy,
low-impact half and missing the one issue the client actually needed found. This lesson is the
bridge from [00.3 threat modeling](../module-00/lesson-03.md) to real testing: how to convert
enumeration into a **ranked hypothesis list** where the top items are the ones most likely to be
both *exploitable* and *impactful*. The deliverable of scanning was never "a list of vulnerabilities"
— it's a defensible plan for where to spend your limited hours, and the evidence to justify that
order to a client. Getting the *order* right is what separates a tester from a tool-runner.

## Learning objectives

- Map enumerated services/versions to likely weakness classes and known vulnerabilities using
  `searchsploit`, CVE, and CWE.
- Read a **CVSS v3.1 and v4.0** vector and explain what base score does and does **not** tell you.
- Use **EPSS** and the **CISA KEV** catalogue as *prioritization signals* alongside CVSS.
- State the limits of vulnerability scanners (false positives/negatives) and why manual validation
  is mandatory.
- Build a ranked testing plan scored by impact × likelihood — and defend the ranking.

## Intuition

You're a detective with a board of leads and one week. CVSS is the *severity of the crime if it
happened* — useful, but it doesn't tell you which lead to chase first. A brutal crime with no viable
suspect ranks below a lesser one you can actually solve this week. Prioritization is combining
**how bad it would be** (impact) with **how likely you are to actually pull it off here, now, in this
environment** (likelihood). A "critical" CVE for a component you can't reach, or that's patched
behind a banner, is a cold lead. A "medium" IDOR you can trivially reach with your test account is
hot. The board isn't ranked by severity; it's ranked by *expected value of your time*.

## The underlying technology: from a version to a vulnerability

### CVE and CWE — two different questions

- **CVE** (Common Vulnerabilities and Exposures, run by MITRE) — a unique ID for *one specific
  vulnerability in one specific product*, e.g. `CVE-2021-44228` (Log4Shell). It answers "*which*
  known flaw."
- **CWE** (Common Weakness Enumeration) — the *class* of mistake, e.g. `CWE-89` SQL Injection,
  `CWE-79` XSS, `CWE-918` SSRF. It answers "*what kind* of flaw." A CVE is usually an *instance* of
  a CWE.

You use both: CWE to reason about a service where no CVE applies ("this custom app concatenates
input into SQL → CWE-89 hypothesis"), CVE to check whether a *known* flaw matches your enumerated
version.

### Matching versions to known exploits

`searchsploit` (the offline Exploit-DB mirror) is the fast first pass:

```text
$ searchsploit vsftpd 2.3.4
------------------------------------------------- ---------------------------------
 Exploit Title                                    |  Path
------------------------------------------------- ---------------------------------
 vsftpd 2.3.4 - Backdoor Command Execution        | unix/remote/49757.rb
------------------------------------------------- ---------------------------------
```

Corroborate against the **NVD** (nvd.nist.gov) for the CVE, affected-version range, and the CVSS
vector — the banner version must actually fall in the vulnerable range, and you must confirm the
component isn't back-patched (see [03.2](lesson-02.md)). `searchsploit` finding an exploit is a
*lead*; a version match is a *hypothesis*; a lab-validated PoC is a *finding*.

## CVSS — reading the vector, not just the number

**CVSS** (the FIRST standard) produces a 0–10 severity score from a *vector*. Read the vector; the
number alone hides everything that matters.

**v3.1** base metrics:

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H   →  9.8 Critical
        │    │    │    │    │   └── Impact: Confidentiality/Integrity/Availability all High
        │    │    │    │    └── Scope unchanged
        │    │    │    └── User Interaction: None
        │    │    └── Privileges Required: None
        │    └── Attack Complexity: Low
        └── Attack Vector: Network
```

`AV:N/PR:N/UI:N` (network-reachable, no auth, no user interaction) is what makes a flaw a `9.8` —
and it's exactly the "likelihood" information you care about. A `C:H/I:H/A:H` bug that needs
`AV:L` (local access) and `PR:H` (admin already) is far less urgent from the outside.

**v4.0** (current, published 2023; adoption growing through 2025–26) refines this: it splits the old
Scope into explicit **Vulnerable System** vs **Subsequent System** impact (`VC/VI/VA` and
`SC/SI/SA`), adds **Attack Requirements** (`AT`) alongside complexity, and formalizes
**Threat** (exploit maturity, `E:`) and **Environmental** metrics so defenders can rescore for their
own context. Base score naming can be `CVSS-B`, `CVSS-BT` (with threat), `CVSS-BTE` (with
environmental).

<div class="callout warn">

**CVSS base score is not risk.** It deliberately excludes *your* environment and *current* exploit
activity — it's a context-free severity, "the worst this could be." A base `9.8` on an
unreachable internal host may be lower *risk* to this client than a `6.5` on their Internet-facing
login. This is why CVSS is a starting input, not the ranking itself.

</div>

## EPSS and CISA KEV — the "is it actually being exploited?" signals

CVSS says how *bad*; these two say how *likely to be used*:

- **EPSS** (Exploit Prediction Scoring System, FIRST) — a data-driven probability (0–1) that a CVE
  will be **exploited in the wild within 30 days**. It's updated daily from real exploitation
  telemetry. A `9.8` with EPSS `0.02` (2%) is theoretically dire but not currently weaponized; a
  `7.5` with EPSS `0.90` is a fire. EPSS reflects *activity*, CVSS reflects *severity*.
- **CISA KEV** (Known Exploited Vulnerabilities catalogue) — a curated list of CVEs with
  **confirmed, observed** active exploitation. Binary and high-confidence: if a CVE matching your
  target is on KEV, it goes to the top, because attackers demonstrably use it. KEV is the strongest
  single "prioritize this" signal you get.

<div class="callout method">

**Combine the signals.** CVSS (how bad) × reachability/PR/UI from the vector (can I get there) ×
EPSS/KEV (is it live) × *your* enumeration (does the finding even apply here). No single number
ranks the board. A KEV-listed, network-reachable, no-auth CVE that matches your confirmed version is
the definition of "test this first."

</div>

## The limits of vulnerability scanners

Automated scanners (Nessus, OpenVAS/Greenbone, Nuclei, Nmap `vuln` scripts) are force multipliers
for *coverage*, not oracles of *truth*:

- **False positives.** Most checks are **version-based**: the scanner reads a banner and flags every
  CVE for that version — ignoring back-ported patches, non-default configs, or compensating controls.
  It will confidently report a "critical" that isn't exploitable here. Reporting it unvalidated
  destroys your credibility with the client's engineers.
- **False negatives.** Scanners miss what they have no signature for: **business-logic** flaws,
  **IDOR/BOLA**, chained issues, custom-code bugs, and anything requiring auth context or multi-step
  interaction. The highest-impact findings on many engagements are *invisible* to scanners — which
  is exactly why you're paid instead of a subscription.
- **Context blindness.** A scanner can't know that the "medium" info leak hands you the token that
  unlocks the "critical" path. Chaining is human work.

<div class="callout warn">

**LIMITS &amp; the rule.** A scanner result is an *unverified hypothesis*. Every finding you report
must be **manually validated** in the lab (reproduced, with evidence and the synthetic marker) or
explicitly labelled "reported by scanner, not validated." Never paste a scanner's severity into a
report as your own conclusion. Scanners also generate load and can be intrusive — keep them in-scope
and RoE-approved.

</div>

## How a tester builds the ranked hypothesis list

This is [00.3](../module-00/lesson-03.md) prioritization applied to concrete enumeration output:

1. **Inventory** each enumerated service → candidate weakness classes (CWE) and matching CVEs.
2. **Estimate impact** — against *assets* (crown jewels), using CVSS impact metrics as an input,
   translated to business terms ("full read of customer PII", "domain admin").
3. **Estimate likelihood** — reachability (from the CVSS vector: `AV`, `PR`, `UI`), current
   exploitation (EPSS/KEV), and *your* confirmation that the finding applies (version in range,
   config present). A brilliant exploit for a version you don't actually have is likelihood ~0.
4. **Rank by impact × likelihood**, note the *cheapest confirming test* for each, and cut the tail —
   a plan the client accepts is short and defended, not exhaustive.

```text
Rank  Service/finding hypothesis          Impact  Likelihood  Signals              Cheap first test
1     SMB null session → domain users     High    High        KEV n/a; trivial     smbclient -N -L (done in 03.2)
2     Web: outdated Apache CVE (AV:N)      High    Med         EPSS 0.4; ver match  curl banner → confirm ver in range
3     SNMP 'public' → config/creds         High    High        default string      snmpwalk system+interfaces
4     SSH password auth exposed            Med     Med         spray candidate(M10) note; no brute now
5     FTP anonymous read                   Med     Med         ftp-anon confirmed   list root, assess sensitivity
```

That's the deliverable: ranked, justified, with a next action per line — not a wall of CVEs.

## Practical lab

<div class="lab">

**Environment:** [`labs/lab-02-recon`](../../labs/lab-02-recon/README.md) — the enumerated hosts
from [03.2](lesson-02.md). **Time:** ~60 min. **Targets:** lab hosts only, no Internet route. Use
an **offline** `searchsploit` and a local NVD/CVE reference; the lab has no external egress.

</div>

1. Take your 03.2 enumeration output. For three services, list candidate CWEs and any CVEs a version
   match suggests (`searchsploit` + your offline CVE reference).
2. For one CVE, read the CVSS v3.1 vector aloud: what makes it reachable, what's the impact, what
   would change the score in *this* environment? Sketch the v4.0 differences.
3. Look up (from your offline notes) whether it's KEV-listed and its EPSS band; decide how those move
   its rank.
4. Produce a ranked top-5 with a cheap first test per line. Justify why #1 beats #5 in one sentence
   each.

## Exercise

<div class="callout method">

**Situation.** Enumeration of lab host `10.10.10.50` (authorized, black-box) produced:

```text
80/tcp   open  http     Apache 2.4.49
139/445  open  smb      Samba 4.15 — null session lists shares: 'backups' (anon read), 'IPC$'
22/tcp   open  ssh      OpenSSH 9.6 — password auth enabled
3306/tcp open  mysql    MySQL 8.0 — remote login as 'root' with no password succeeds
161/udp  open  snmp     community 'public' works; MIB walk returns interface + process list
```

The client's crown jewel is the customer database; `/admin` on the web app is their stated concern.
You have **two days** and cannot test everything.

**Objective.** Produce a **ranked, justified testing plan** (impact × likelihood), not an exhaustive
list — the top few hypotheses you'll pursue, in order, with the reasoning a client would accept.

**Starting information.** The enumeration above. You may reference CVSS/CWE/EPSS/KEV *concepts*; note
where you'd look values up (the lab is offline).

**Constraints.** LAB TARGET only. This is a *plan* — no exploitation in this exercise. Rank by
expected impact on the client's assets × your realistic likelihood of demonstrating it, not by raw
CVSS. Justify every rank.

**Expected deliverables.**
1. A ranked hypothesis table: rank, service, weakness class (CWE) and any candidate CVE, impact
   (in asset terms), likelihood (with the vector/signal reasoning), and the cheapest confirming test.
2. A short paragraph defending your **#1** — why it beats a higher-CVSS alternative if it does.
3. One hypothesis you explicitly **deprioritized or excluded**, and why (reachability, RoE, low
   asset impact, or unverifiable).

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Rank by impact-on-the-crown-jewel × likelihood-here, not by which CVE has the scariest number. Which
of these findings most directly reaches the customer database — and how sure are you it's real?
</details>

<details><summary>Hint 2 — technique family</summary>
An unauthenticated `root`-with-no-password MySQL that's network-reachable is direct access to the
crown jewel — near-certain likelihood, maximal impact. Compare that to a version-based Apache CVE
that may be back-patched. Apache 2.4.49 specifically suggests a well-known path-traversal/RCE class —
worth a CVE lookup, but confirm the version is really in range.
</details>

<details><summary>Hint 3 — where to look</summary>
Reachability comes off the CVSS vector (`AV:N/PR:N/UI:N`). EPSS/KEV tell you if the Apache CVE is
live. The SMB `backups` share and SNMP walk are information-disclosure that could *chain* — a
credential in a backup or MIB might unlock something scored lower on its own.
</details>

<details><summary>Hint 4 — specific direction</summary>
A defensible order often starts with the no-auth MySQL root (crown jewel, certain), then the anon
`backups` share (may contain the very creds that reach `/admin`), then the Apache CVE *if* the version
confirms and it's KEV/EPSS-hot, then SNMP as chaining fuel, with SSH password-auth noted for M10.
Show the chaining reasoning, not just isolated scores.
</details>

## Check yourself

<div class="callout key">

1. A scanner reports `CVSS 9.8 Critical` on an internal host, and `CVSS 6.5 Medium` on the
   Internet-facing login. Why might you test the 6.5 first? Which extra signals would settle it?
2. Two CVEs both score `7.5`. One is on CISA KEV with EPSS `0.85`; the other has EPSS `0.01`. How
   does that change your plan, and why doesn't the identical CVSS make them equal?
3. Explain, to a developer, why "the scanner said critical" is not the same as "you have a critical
   vulnerability." Give one false-positive and one false-negative example.
4. Your enumerated banner matches a vulnerable version exactly, but exploitation fails in the lab.
   Give two innocent reasons, and what you now write in the report.

</div>

Model answers are in `solutions/module-03.md`.

## References

- **CVSS v3.1 &amp; v4.0 specifications** — FIRST: [first.org/cvss](https://www.first.org/cvss/).
- **EPSS** — FIRST: [first.org/epss](https://www.first.org/epss/) (model &amp; data docs).
- **CISA KEV catalogue** — [cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- **NVD** (CVE + CVSS data) — [nvd.nist.gov](https://nvd.nist.gov/); **MITRE CVE** &amp; **CWE** —
  [cve.org](https://www.cve.org/), [cwe.mitre.org](https://cwe.mitre.org/).
- **Exploit-DB / searchsploit** — [exploit-db.com](https://www.exploit-db.com/).
- **MITRE ATT&CK T1595** Active Scanning, **T1190** Exploit Public-Facing Application (the phase this
  plan feeds); **NIST SP 800-115** §4 (vulnerability analysis) and **SSVC** (CISA's stakeholder-
  specific vulnerability categorization) as an alternative to score-only ranking.

## What you should now be able to do

- Map enumerated services to CWEs and candidate CVEs, and treat a version match as a hypothesis.
- Read a CVSS v3.1/v4.0 vector and explain why the base score is an input, not the risk.
- Use EPSS and CISA KEV to weight what's *actually* exploited.
- Explain scanner false positives/negatives and validate every finding by hand.
- Deliver a short, ranked, defended testing plan scored by impact × likelihood.

## Progress checkpoint

```bash
py course.py complete 03.3
```
