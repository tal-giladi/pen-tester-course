# Assessment 5 — Active Directory attack path

<div class="prereq">

**Modules tested:** [M06 Active Directory](../lessons/module-06/lesson-01.md),
[M10 Credential attacks](../lessons/module-10/lesson-01.md),
[M11 Lateral movement](../lessons/module-11/lesson-01.md).
**Lab:** [`lab-06-ad`](../labs/vm/README.md) (the Windows/AD **VM** forest — build it first).
**Difficulty:** 🔴 advanced. **Time:** 3–5 h. **Scaffolding:** *advanced* — you are given the
engagement; you supply the methodology (`exercise-standard`, `plan.md` §28).
**You will produce:** an enumeration record, the attack-path graph you discovered, one finding per
misconfiguration you abused (to the deliverable rubric), and the evidence proving domain compromise.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Everything below targets **only** the `lab-06-ad` VMs, on a
**host-only / internal** virtual network with **no Internet route** (see
[`labs/vm/README.md`](../labs/vm/README.md)). The domain `lab.local`, its accounts, and its flags
are **synthetic**. Kerberoasting, ACL abuse, delegation abuse, and credential replay are crimes
against a domain you are not authorized to test — on a **REAL SYSTEM** you do none of this without a
signed authorization and a defined scope (00.1). Verify isolation from **inside a VM** (an external
ping/curl must fail) and run `./labs/lab check` before you start. If either fails, stop.

</div>

## Situation

You are three days into an internal engagement for a mid-sized firm. Phishing (out of scope for
this assessment — assume it succeeded) has already given you what a real intruder usually gets
first: a single set of **ordinary domain-user** credentials on a domain-joined workstation. Nothing
about that account is privileged. The client's security lead is skeptical that "one helpdesk-tier
account" can matter, and has asked you to demonstrate — with evidence — exactly how far that account
can be walked, and to stop only when you either reach full domain control or run out of path.

## Objective

Starting from an unprivileged domain account, **discover and traverse an attack path to full domain
compromise** (Domain Admins, or an equivalent primitive — DC replication / DCSync rights, control of
a Domain Admin, or SYSTEM on a domain controller). Prove it by reading the Domain Admin–only flag
and by demonstrating a domain-wide credential-access primitive. The path is **not given to you** —
finding it is the assessment.

## Starting information

Only what the "phish" yielded:

- One low-privileged account: `lab\r.olsen` / `Lab-Passw0rd!` — a member of **Domain Users** only,
  no local admin anywhere you have been told about.
- The domain is `lab.local`; you are on the `192.168.56.0/24` host-only network with your attacker
  VM at `192.168.56.100`. Three domain hosts exist (a DC and two others) — their roles are for you
  to determine.
- Nothing else. No map of groups, no list of service accounts, no "the answer is Kerberoasting."

## Constraints

- **In scope:** the three `lab-06-ad` VMs and the `lab.local` domain only.
- **Out of scope / forbidden:** anything not on `192.168.56.0/24`; any real host; denial of service;
  destructive changes (do not delete accounts, do not disable the DC, do not change passwords you
  cannot restore). Reset from the clean snapshot between attempts rather than hand-repairing.
- **Safety boundary:** LAB TARGETS ONLY. Confirm no VM can reach the Internet, and run
  `./labs/lab check`, before any offensive action. Credentials and flags are synthetic; treat the
  `LAB-FLAG-…` markers as your proof artifacts.
- **Methodology:** enumerate → hypothesize → verify, before you exploit. An exploit you cannot
  explain the mechanism of does not count.

## Expected deliverables

1. **Enumeration record** — what you collected, how, and the reasoning that turned raw objects
   (users, groups, ACLs, SPNs, delegation, sessions) into candidate paths. Include the tool output
   and note where you verified a finding by hand rather than trusting a collector.
2. **Attack-path graph** — the chain from `r.olsen` to domain compromise, as a short node→edge
   diagram (principal → right/technique → principal), with each hop justified by the specific
   misconfiguration that enabled it. This is the graph a defender must break.
3. **A finding per abused misconfiguration**, each to the deliverable rubric
   ([`finding-template.md`](../solutions/report-template/finding-template.md)): what · where ·
   reproduction · evidence · impact · CVSS rationale · remediation. At minimum: the initial
   escalation primitive, any credential-access step, and the final domain-compromise primitive.
4. **Evidence** — commands/output and screenshots named by the deterministic convention
   (`evidence/<YYYYMMDD-HHMMSS>_<host>_F-<id>_<n>.png`, 16.1), each showing the relevant
   `LAB-FLAG-…` marker: the Domain Admin–only flag and proof of the domain-wide primitive.
5. **Root cause & remediation** per hop — not "patch it," but *why the domain permitted this edge*
   and the specific configuration change (and detection) that removes it.
6. **A findings-summary table** (report §4 format) — the manager's-eye view of the chain.

*(A5 does not require the full executive report — that arrives at A7. It requires findings, the
chain, evidence, and remediation.)*

<details><summary>Hint 1 — conceptual direction</summary>
Stop thinking of AD as a list of machines to exploit and start thinking of it as a <em>graph of
who-can-act-on-whom</em>. Compromise in a modern domain is rarely a software vulnerability; it is a
<em>path through relationships</em> the administrators did not realize they had created. Your whole
job is to find the shortest such path from where you stand to where you want to be.
</details>

<details><summary>Hint 2 — technique family</summary>
An unprivileged user can already <em>read</em> most of the directory. The paths that don't need an
exploit are: recovering credential material that the protocol will hand you for asking (accounts
whose secrets are exposed by how Kerberos issues tickets), and object permissions that let one
principal modify or authenticate as another. Enumerate credentials and rights before you reach for
anything noisy.
</details>

<details><summary>Hint 3 — relevant tools / what to look at</summary>
Graph-based collectors (BloodHound-style) exist precisely to answer "shortest path to Domain
Admins." Collect the domain as your low-priv user, then read the graph: outbound control edges from
principals you can become, service accounts with a set SPN, accounts flagged for delegation, and
group memberships that are more transitive than they look. Verify each promising edge manually
against the live directory — collectors go stale and lie.
</details>

<details><summary>Hint 4 — specific investigation direction</summary>
Chain, don't leap. Look first for a way to obtain <em>a second, better</em> credential (a crackable
service ticket, or a secret readable/resettable because of an ACL your user is inside). Then re-run
the graph <em>as that identity</em> — the path usually opens one hop at a time, and the final hop to
the DC is typically a rights primitive (replication/DCSync, control of a privileged group, or a
delegation abuse), not a memory-corruption exploit. Do not brute-force; find the edge.
</details>

## Check yourself

<div class="callout key">

1. Your collector shows a path `r.olsen → (GenericAll) → svc_backup → (MemberOf) → Domain Admins`.
   Before you touch anything, what two things must you verify against the live directory, and why
   would acting on the graph alone be a mistake?
2. You recover a service account's plaintext by cracking a ticket offline. Why did the domain hand
   you that ticket for a low-priv request at all, and what property of the account made the crack
   feasible? What single configuration change would have made this path dead?
3. You reach a primitive that lets you replicate directory secrets. Explain, in defender's terms,
   why that is equivalent to full domain compromise even though you are "not in Domain Admins."
4. You could take the shortest path (one noisy step to DA) or a longer, quieter one. On a
   detection-aware engagement, how would the RoE and the client's goals decide which you choose, and
   what would you record either way?
5. A teammate says "I got Domain Admin" and shows a screenshot of a shell. What is missing before
   that is a *finding* a client can act on?

</div>

## Grading rubric

<div class="callout method">

| Band | Criteria |
|---|---|
| **Pass — domain compromised** | Reached a domain-compromise primitive from the unprivileged account; read the DA-only flag; demonstrated the domain-wide credential primitive; every hop justified by a specific, verified misconfiguration. |
| **Findings quality** | Each abused misconfiguration is a complete finding (rubric-complete: what/where/repro/evidence/impact/CVSS-rationale/remediation). Reproduction steps let another tester walk the same path without you. |
| **Methodology** | Enumeration precedes exploitation; collector output is verified by hand; the attack-path graph is explicit and correct; no destructive actions; isolation confirmed. |
| **Impact & remediation** | Impact is stated in business terms, not "it's bad"; each hop's remediation addresses *why the edge existed*, with a detection note. |
| **Distinction** | Found more than one independent path to compromise, or the shortest path *and* a quieter alternative, and reasoned about detection trade-offs; remediation is pattern-level (tiering, ACL hygiene, service-account policy), not per-object. |
| **Fail** | Path not reached; or reached by guessing/undocumented steps; or no evidence with the marker; or destructive/ out-of-scope actions; or isolation not verified. |

</div>

_Grading key, the intended path(s), and common wrong turns are instructor material in
[`solutions/assessments/A5.md`](../solutions/assessments/A5.md) — not linked from the sidebar. Try
the assessment before looking._
