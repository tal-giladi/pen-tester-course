# 06.4 — Domain privilege escalation & attack-path analysis

<div class="prereq">

**Prerequisites:** [06.1](lesson-01.md) (the graph, HVTs, DCs and `NTDS.dit`), [06.2](lesson-02.md)
(Kerberoasting/AS-REP), [06.3](lesson-03.md) (ACL/delegation/GPO edges), and
[05.2](../module-05/lesson-02.md) (NT hashes, TGT, `krbtgt`, pass-the-hash/ticket). Credential
extraction and cracking mechanics are M10; lateral movement is M11 — both are referenced here.
**Module:** M06. **Difficulty:** 🔴 advanced.
**M06 assumes** a low-privileged domain account on the lab forest. This lesson is where the
individual techniques become a **single chain to Domain Admin**.
**You will produce:** a report-ready attack narrative that walks from your low-priv foothold to a
high-privilege account on the lab forest, evidence-backed, with the path discovered — not given.

</div>

## Why this matters

The previous three lessons taught individual primitives: read the graph, roast a ticket, abuse an
edge. **This lesson is the synthesis** — turning the graph into a *plan* and executing a chain that
composes those primitives into full domain compromise. That synthesis is the actual job. A client
does not pay for "we Kerberoasted an account"; they pay for "**a normal employee can become Domain
Admin in four steps; here is each step, the evidence, and how to break the chain.**" You will also
meet the techniques that define "game over" once you reach replication rights or the `krbtgt` key —
**DCSync**, and the golden/silver-ticket concepts — taught here as **mechanism and detection**, not
as weaponized tooling.

## Learning objectives

By the end you can:

- **Chain** primitives from 06.1–06.3 with credential reuse into a path from low-priv to Domain
  Admin, and explain each hop's mechanism.
- Explain **credential harvesting and reuse** across hosts (NT hashes/tickets from a compromised
  machine → authenticate elsewhere) and where it fits a path — the bridge to M10/M11.
- Explain **DCSync**: how *replication rights* (`DS-Replication-Get-Changes` + `-All`) let a
  principal ask a DC to hand over any account's secrets (including `krbtgt`) over **DRSUAPI**,
  without touching disk or running code on the DC.
- Explain the **Golden** and **Silver ticket** *concepts* (forging TGTs with the `krbtgt` key /
  service tickets with a service key) and why they are persistence, not just access.
- Perform **attack-path analysis**: convert the graph into a ranked, justified plan and then a
  written narrative — the professional deliverable.

## Intuition

You have a map (06.1) covered in one-way roads (06.2/06.3 edges). Domain escalation is **route
planning**: find the shortest, most reliable road from where you stand to the town-hall keys, then
drive it, using each intersection you reach to unlock the next road. Two things make AD routes
uniquely powerful. First, **credentials are reusable material** (05.2): the moment you own a machine,
you inherit every credential cached on it, and those often open the *next* door. Second, once you
reach **replication rights or the `krbtgt` key**, the game changes qualitatively — you can ask the DC
for *everyone's* secret (DCSync) or forge tickets for *anyone* (Golden Ticket). The art is
recognizing the shortest path to one of those two states and proving each step.

## The underlying technology

### Credential reuse and harvesting — the connective tissue

Most real paths are not one clever edge; they are **compromise a host → harvest its cached
credentials → those credentials own the next host** (or account), repeated. When you gain SYSTEM/local
admin on a machine (via a 06.3 edge, a service-account password from 06.2, or 05.3 local privesc),
LSASS holds NT hashes and Kerberos tickets for everyone logged on there (05.2). Extraction is the
subject of M10; *using* them — **pass-the-hash**, **pass-the-ticket**, **overpass-the-hash** — is
M11. In an attack path they are the edges labelled `HasSession`/`AdminTo`: a Domain Admin's session
on a workstation you can reach means their credential material is *there*, and harvesting it
(post-SYSTEM) makes you them. This is why the 06.1 graph marks sessions, and why *tiering* (keeping
Tier-0 creds off Tier-2 machines) is the structural defense.

### DCSync — replicating the domain's secrets

Domain controllers keep each other in sync by **replicating** directory data over the **Directory
Replication Service (DRSUAPI)** protocol (`IDL_DRSGetNCChanges`). A principal granted the
replication extended rights on the **domain object** —
**`DS-Replication-Get-Changes`** *and* **`DS-Replication-Get-Changes-All`** (and, for some data,
`-In-Filtered-Set`) — can **pretend to be a DC** and ask a real DC to send account secrets: NT
hashes, Kerberos keys, and crucially the **`krbtgt`** account's hash.

<div class="callout key">

**Why DCSync is so dangerous and so quiet.** It is not an exploit — it is the replication protocol
working as designed for a principal that *has the rights*. It requires **no code execution on the
DC**, **no touching `NTDS.dit` on disk**, and no service restart — just an authenticated DRSUAPI
request from anywhere in the domain. Those replication rights are held by DCs and Domain/Enterprise
Admins by default, but they are exactly the kind of right a 06.3 `WriteDACL`/`AllExtendedRights`
edge on the domain object can *grant you* — which is why an ACL edge to the domain root is
equivalent to domain compromise. Once you have `krbtgt`'s hash, you can forge tickets forever.

</div>

```text
# CONCEPT (mechanism, not a drop-in): with replication rights, request a specific account's secrets.
secretsdump.py -just-dc-user krbtgt lab.local/pwned_admin@192.168.56.10
#            └─ speaks DRSUAPI to DC01, asks for krbtgt's keys — the DC replicates them back.
```

`secretsdump.py` also has a `-just-dc` mode that pulls the whole domain, and offline modes that parse
a stolen `NTDS.dit` + `SYSTEM` hive (the "grab the DB" alternative, M10). We show the invocation to
make the **mechanism and its telemetry** concrete, not as tradecraft — the detection below is the
point.

### Golden and Silver tickets — forging, once you hold a key

- **Golden Ticket** — with the **`krbtgt`** account's key (from DCSync or an `NTDS.dit` dump), you
  can **forge a TGT** for any user, including a fabricated Domain Admin, because the TGT is encrypted
  and signed with `krbtgt`'s key and the KDC trusts anything that key produced. This is **domain
  persistence**: valid until `krbtgt` is rotated **twice** (its history keeps one old key).
- **Silver Ticket** — with a *service account's* key (e.g. a Kerboasted `svc_sql`, or a machine
  account's hash), you can **forge a service ticket** for that one service, bypassing the KDC
  entirely (the service validates the ticket with its own key). Narrower, stealthier (no 4769 on the
  DC), and a form of targeted persistence.

Both are taught here as **concepts**: what key enables them, what they forge, why they are
persistence rather than mere access, and — below — how defenders detect and defeat them (`krbtgt`
double-rotation, ticket-lifetime and PAC-validation anomalies). This course does not provide
forging recipes.

### Attack-path analysis — the actual skill

Turning the graph into a plan is a repeatable method:

1. **Anchor both ends.** Start = nodes you control (mark them Owned). Goal = the HVTs from 06.1
   (Domain Admins, DCs, `krbtgt`).
2. **Enumerate candidate paths** (BloodHound shortest-path, plus your own reading of the edges).
3. **Score each edge** by *reliability × noise × reversibility × effort* — a deterministic
   `GenericAll` beats a "wait for a session"; a targeted Kerberoast beats a destructive reset.
4. **Verify each edge over LDAP** before committing (06.1's discipline) — sessions may be stale,
   ACEs may be misread.
5. **Execute hop by hop, harvesting as you go**, re-collecting the graph after each compromise (new
   access reveals new edges).
6. **Record evidence per hop** so the path is a *narrative*, not a claim.

## How a tester recognizes the finish line

You are near domain compromise when a path reaches any of: **membership in a Tier-0 group** (Domain
Admins/Administrators/Enterprise Admins), **local admin/SYSTEM on a DC**, a **`WriteDACL`/
`AllExtendedRights` edge on the domain object** (→ grant yourself DCSync), **control of an account
with replication rights**, or the **`krbtgt` hash**. Any one is effectively "won"; the rest is
demonstrating and documenting impact.

## Manual investigation

```text
# Who already holds replication (DCSync) rights on the domain? Read the domain object's DACL:
PS> Get-DomainObjectAcl -Identity 'DC=lab,DC=local' -ResolveGUIDs |
      ? { $_.ObjectAceType -match 'Replication-Get-Changes' } |
      select SecurityIdentifier, ObjectAceType
# Anyone here who ISN'T a DC/Domain Admin is an escalation edge to domain compromise.

# Where are privileged sessions? (credential-reuse targets — verify, sessions go stale)
#   BloodHound 'HasSession' + re-check with a live session enumeration at execution time.
```

## Tooling — what it does, key options, limits, verify

<div class="callout method">

- **BloodHound** — path planning: "Shortest Path from Owned Principals to Domain Admins", plus
  per-edge help text. *Limit:* proposes, doesn't prove; re-verify and re-collect after each hop.
- **netexec (`nxc`)** — spray a harvested hash/password across hosts to find where it is admin
  (`--local-auth`, hash via `-H`), map `AdminTo` in practice. *Limit:* noisy; authentications are
  logged.
- **Impacket `secretsdump.py`** — DCSync (`-just-dc`, `-just-dc-user`) and offline `NTDS.dit`
  parsing; the reference for demonstrating replication impact. *Limit/《verify》:* the DRSUAPI request
  is visible on the DC (4662 with the replication GUIDs) — expect and document it.
- **Rubeus / mimikatz** — ticket and credential operations (pass-the-ticket, forging). Taught here
  as **concept**; not provided as weaponized invocations.

</div>

**Verify by hand at each hop:** confirm the credential works where you think (`nxc` a single host,
or an LDAP bind), confirm a claimed admin right by actually reading `\\host\C$` or the group
membership, and confirm replication rights by reading the domain DACL — don't take the graph's word.

## Exploitation / demonstration (LAB ONLY): an illustrative chain

<div class="callout attack">

**Technique — composing a path (one illustrative route; your lab path may differ, and the exercise
path is deliberately not this one).**

```text
lowpriv ─MemberOf→ [IT Support] ─GenericAll→ (svc_backup) ─?→ ... ─→ Domain Admin
```

1. **Foothold → edge (06.3).** `IT Support` (contains `lowpriv`) has `GenericAll` on `svc_backup`.
   Targeted-Kerberoast `svc_backup` (write SPN → roast → crack offline → remove SPN). *Verify:* log
   in as `svc_backup`.
2. **Credential reuse (M11 preview).** `svc_backup` is a member of a backup group that is
   **`AdminTo` `SRV01`**. `nxc smb SRV01 -u svc_backup -p <cracked>` → admin. Gain SYSTEM on SRV01.
3. **Harvest (M10 preview).** On SRV01 (now SYSTEM), a **Domain Admin session** was present; its
   credential material is in LSASS. Harvest the DA's ticket/hash (extraction = M10).
4. **DCSync.** As the DA, request the domain's secrets over DRSUAPI:
   `secretsdump.py -just-dc-user krbtgt lab.local/da@DC01` → `krbtgt` hash. **Domain compromise.**
5. **(Concept) persistence.** The `krbtgt` key would allow a Golden Ticket — *stated as impact, not
   performed.*

Each arrow is a mechanism you can defend: sever the ACL edge (1), tier so `svc_backup` isn't AdminTo
(2), keep DA sessions off SRV01 (3), and DCSync never gets its foothold.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** The entire chain runs against the isolated `lab-06-ad` forest
(`DC01`/`SRV01`/`WS01`, host-only, no egress), synthetic accounts, benign `LAB-FLAG-{uuid}`. DCSync,
credential harvesting, and ticket forging against any domain you are not explicitly authorized to
test are serious crimes (M00) and, for DCSync/forging, among the most damaging actions possible in a
network. In lab you reset via snapshot; in a real engagement these steps require explicit written
approval, careful evidence handling, and disclosure. **`krbtgt` and Golden/Silver tickets are taught
as mechanism + detection only — no forging recipes are provided.** Restate scope and authorization
first.

</div>

## Verification

The path is verified when **every hop has evidence**: the cracked service-account login, the `nxc`
admin confirmation on SRV01, the harvested DA context, and the DCSync output showing `krbtgt`'s hash
returned by the DC. "I reached Domain Admin" is a claim; a hop-by-hop chain with the command, its
output, and the DC event it generated at each step is a *finding*. Screenshot/record each hop as you
go (M16) — reconstructing evidence after the fact is how details get lost.

## Impact

Domain compromise is the maximum-impact internal finding: with `krbtgt` or DCSync, the attacker owns
**every** identity and can persist through password resets (Golden Ticket) until `krbtgt` is rotated
twice. Every host, every file share, every application that trusts the domain is reachable. In
business terms this is total loss of confidentiality, integrity, and availability of everything the
directory governs — and the recovery (forest recovery, `krbtgt` double-reset, rebuilding trust) is
expensive and disruptive. Frame it that way, and lead the remediation with the *cheapest edge that
breaks the chain*, not just "rebuild AD."

## Remediation

<div class="callout defend">

- **Break the chain at its cheapest edge.** The value of path analysis is that you can tell the
  client *"remove this one `GenericAll` and the path to DA disappears."* Prioritize the edges that
  the most paths traverse (BloodHound's "choke points").
- **Tiered administration / Enterprise Access Model:** Tier-0 credentials (DA/EA/DC) never log on to
  Tier-1/2 machines — this deletes the `HasSession`/harvest edges that most chains rely on. Use
  **PAWs** for admin work and **Protected Users** for sensitive accounts.
- **Protect replication rights:** audit who holds `DS-Replication-Get-Changes-All` on the domain;
  it should be DCs and a *very* short list. Any other principal is a DCSync waiting to happen.
- **Protect `krbtgt`:** rotate it (twice, with the required interval) on a schedule and after any
  suspected compromise; this invalidates Golden Tickets.
- **Least privilege on service accounts and gMSA** (06.2), pruned DACLs and delegation (06.3), and
  **credential hygiene** (LAPS for local admin passwords, Credential Guard/RunAsPPL to protect
  LSASS) — each removes a class of edge.

</div>

## Detection / blue-team view

<div class="callout defend">

- **DCSync → Event ID 4662** on the domain object with the replication access GUIDs
  (`1131f6aa-…` `DS-Replication-Get-Changes`, `1131f6ad-…` `-All`) from a principal that is **not a
  DC**. This is the canonical, high-fidelity DCSync alert; **Defender for Identity** ships
  "**Suspected DCSync attack (replication of directory services)**". Baseline your DCs' own
  replication (machine accounts) so non-DC requests stand out.
- **Credential reuse / lateral movement → 4624** LogonType 3 with NTLM for accounts that should use
  Kerberos, or one account authenticating to many hosts quickly; **4776**; overpass-the-hash shows
  as RC4 TGT requests (**4768**) after a hash-based logon (M11 detail).
- **Golden Ticket → 4769** service-ticket requests with **no preceding 4768** (the TGT wasn't issued
  by this DC — it was forged), anomalous ticket lifetimes, or a username that doesn't exist / mismatched
  RID; **Silver Ticket → 4624/4634 on the service host with no corresponding 4769 on the DC** (the
  KDC was bypassed).
- **`krbtgt` and DC changes:** alert on `krbtgt` password changes, DC group modifications, and any
  add to Tier-0 groups (**4728/4756**).
- **Honeypots:** a decoy DA-looking account or an object with a tempting DCSync-granting DACL; any
  use is high-signal.
- Map to **MITRE ATT&CK T1003.006** (DCSync / OS Credential Dumping), **T1207** (Rogue Domain
  Controller), **T1558.001/.002** (Golden/Silver Ticket), **T1550.002/.003** (PtH/PtT), **T1078.002**
  (Valid Domain Accounts).

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-06-ad` — the `lab.local` VM forest (`DC01`/`SRV01`/`WS01`) on the
host-only, no-Internet network (see [`labs/vm/README.md`](../../labs/vm/README.md)). **Access:**
`lab.local\lowpriv : Lab-Passw0rd!`. The forest is provisioned so that **at least one full path**
from `lowpriv` to a high-privilege account exists, composed of edges from 06.1–06.3 plus a
credential-reuse hop; the path is **not disclosed**. **Time:** ~120 min. **Isolation:** verify egress
fails; **reset via snapshot** between attempts (harvesting/DCSync/RBCD leave persistent changes).
Watch `DC01`'s Security log to see the telemetry your chain produces.

</div>

Do the full method: mark `lowpriv` Owned, plan candidate paths, verify edges, execute hop by hop
harvesting as you go, re-collect after each compromise, and reach a high-priv account. Capture
evidence at every hop and note the DC event each step generated — the detection story is part of the
deliverable.

## Exercise

<div class="callout method">

**Situation** *(Scenario C — AD compromise).* Authorized internal engagement. You start with the
low-privileged domain account `lab.local\lowpriv : Lab-Passw0rd!` on the `lab.local` forest and
nothing else.

**Objective.** Discover and demonstrate an attack path from your low-priv foothold to a
**high-privilege account** (a Domain Admin or equivalent), and deliver it as a **report-ready attack
narrative**. The intended path is **not** provided — discovering it is the assessment.

**Starting information.** The low-priv credentials and network access. No path, no list of the
"right" edges.

**Constraints.** Lab forest only. Verify every edge before using it; prefer reversible primitives;
record before/after for any persistent change and reset via snapshot afterward. Every hop must be
evidence-backed. Treat DCSync/forging strictly as lab mechanism — do not generalize them off the
lab.

**Expected deliverables.**
1. An **attack narrative**: each hop as *starting state → edge/mechanism → action → verification →
   new state*, from `lowpriv` to the high-priv account, with the command and its output (or a
   screenshot) per hop.
2. The **graph justification**: why you chose this path over alternatives (reliability/noise/
   reversibility), and the re-collected graph showing edges revealed after each compromise.
3. A **remediation section** that names the *single cheapest edge* whose removal breaks the path,
   plus the structural fixes (tiering, replication-rights audit, `krbtgt` rotation, gMSA), and a
   **detection** section mapping each hop to its event ID(s) and ATT&CK technique.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Anchor both ends first: mark yourself Owned, mark the HVTs from 06.1 as the goal, and let the graph
propose routes. Then think like a planner — score edges by reliability and noise, not novelty, and
verify before committing.
</details>

<details><summary>Hint 2 — technique family</summary>
Real paths usually alternate <em>edge abuse</em> (06.2/06.3) with <em>credential reuse</em>: crack or
seize a credential, find where it is admin, harvest what's cached there, repeat. Re-collect the graph
after every new access — new sessions and rights appear.
</details>

<details><summary>Hint 3 — where to look</summary>
The finish line is any of: a Tier-0 group membership, admin/SYSTEM on the DC, a
replication-rights (DCSync) edge on the domain object, or the <code>krbtgt</code> key. Watch for a
privileged <em>session</em> on a host you can reach — that's often the harvest hop that unlocks the
rest.
</details>

<details><summary>Hint 4 — the reporting deliverable</summary>
The narrative <em>is</em> the finding. Capture each hop's evidence live, and for remediation identify
the choke-point edge — clients act on "remove this one grant," not on "rebuild the forest."
</details>

## Check yourself

<div class="callout key">

1. Why is a `WriteDACL` (or `AllExtendedRights`) edge on the **domain object** effectively equal to
   domain compromise? What right would you grant yourself, and what does it then let you do?
2. Explain **DCSync** mechanically: which two replication rights, over which protocol, and why it
   needs no code execution on the DC. What single event ID gives a defender a high-fidelity alert?
3. Distinguish a **Golden** from a **Silver** ticket: which key forges each, what each forges, and
   why the Silver ticket produces *no* DC ticket-request event.
4. Your path relies on a `HasSession` edge (a Domain Admin logged onto a server you can admin). Why
   does **tiered administration** delete this edge, and why is that often the cheapest fix for the
   whole path?
5. You've reached Domain Admin through four hops. For the report, how do you decide which **single**
   remediation to lead with, and why is "rotate `krbtgt` and rebuild" usually *not* the lead?

</div>

Model answers are in `solutions/module-06.md`.

## References

- **Microsoft** — **[MS-DRSR]** Directory Replication Service Remote Protocol (DRSUAPI); replication
  extended rights (`DS-Replication-Get-Changes`, `-All`); *AD forest recovery* and *`krbtgt`
  account maintenance / reset* guidance; *Enterprise Access Model* and *tiered administration*;
  **LAPS**.
- **SpecterOps / BloodHound** — attack-path and choke-point analysis; **Sean Metcalf
  (adsecurity.org)** — DCSync, Golden/Silver ticket internals and detection.
- **Impacket** — `secretsdump.py`; **Benjamin Delpy — mimikatz** (DCSync/ticket concepts, studied
  for mechanism and detection, not weaponization).
- **MITRE ATT&CK** — **T1003.006** DCSync, **T1207** Rogue Domain Controller, **T1558.001** Golden
  Ticket, **T1558.002** Silver Ticket, **T1550.002/.003** PtH/PtT, **T1078.002** Valid Domain
  Accounts, **T1484** Domain Policy Modification.
- **CWE-266/CWE-269** privilege assignment/management; **CWE-522** Insufficiently Protected
  Credentials.

## What you should now be able to do

- Chain enumeration, Kerberos, ACL/delegation abuse, and credential reuse into a verified path to
  Domain Admin.
- Explain credential harvesting/reuse, DCSync (mechanism + telemetry), and the Golden/Silver-ticket
  concepts — and why they are persistence.
- Perform attack-path analysis: score edges, verify, execute hop by hop, and re-collect the graph.
- Deliver a report-ready attack narrative with per-hop evidence, a choke-point remediation, and an
  event-ID-level detection story.

## Progress checkpoint

```bash
py course.py complete 06.4
```
