# 06.1 — Active Directory as a graph: architecture, objects, and enumeration

<div class="prereq">

**Prerequisites:** [05.1 Windows for testers](../module-05/lesson-01.md) (SIDs, tokens, SCM),
[05.2 Windows authentication](../module-05/lesson-02.md) (NTLM, Kerberos, SMB/LDAP/WinRM — this
module builds directly on it), [M03 Scanning & enumeration](../module-03/lesson-01.md), and
[00.3 threat modeling](../module-00/lesson-03.md) (trust boundaries, the confused deputy).
**Module:** M06 Active Directory. **Difficulty:** 🔴 advanced.
**M06 assumes** you already hold a **low-privileged domain account** on the lab forest
(`lab.local\lowpriv : Lab-Passw0rd!`) — a normal user, no special rights. That single foothold is
the standard starting point for the whole module.
**You will produce:** a graph model of the lab domain (nodes, edges, trusts) and a ranked
high-value-target list, built entirely by enumeration — *without* being told the attack path.

</div>

## Why this matters

Active Directory (AD) runs identity for the overwhelming majority of enterprises: it decides who
you are, what you can touch, and which machines trust which. On an internal engagement, "domain
compromise" is usually the finding that matters most, because a Domain Admin can read every file,
reset every password, and own every host. Yet you almost never *break* AD — you **abuse it as
designed**. The permissions, group memberships, delegations, and cached credentials that let a
25,000-person company function are the same edges an attacker walks from one intern's laptop to the
domain controller.

The single skill that separates an AD tester from a tool-runner is **thinking about the domain as a
graph**. Every principal (user, computer, group) is a node; every "X can control Y" or "X's
credentials live on Z" is a directed edge. Compromise is a *path* through that graph. This lesson
builds the map. The next three lessons walk specific edges (Kerberos, ACLs/delegation, and the
chain to Domain Admin). Get the graph model right here and every later attack becomes "of course."

## Learning objectives

By the end you can:

- Describe AD's structure — domains, trees, forests, trusts, domain controllers, the global
  catalog, and the LDAP directory — and what each means for an attacker.
- Name the core object classes (users, groups, computers, OUs, GPOs) and the attributes that
  matter offensively (`memberOf`, `servicePrincipalName`, `userAccountControl`, `adminCount`,
  `nTSecurityDescriptor`).
- Explain the **graph model**: what the standard node types and edges (`MemberOf`, `AdminTo`,
  `HasSession`, `GenericAll`, `WriteDACL`, `CanRDP`) represent.
- Enumerate a domain by hand over **LDAP**, understand **RID cycling**, and collect graph data with
  BloodHound-style tooling — then verify what the tool claims against raw LDAP.
- Produce a high-value-target list and reason about attack surface without being handed a path.

## Intuition

Picture the domain as a city map where the roads are *permissions*. You are dropped in as a
low-privilege resident. Somewhere is the town hall (the domain controller) holding the master keys.
You will not tunnel through a wall; you will find that your building superintendent can enter the
mayor's aide's apartment, the aide is in a group that administers the town-hall annex, and the
annex shares a maintenance key with the hall. Each hop is a legitimate relationship someone
configured for a real reason. Your job is to **draw every road, then find the shortest one to the
keys.** AD's power — that identities and permissions compose transitively — is exactly what makes
that path exist.

## The underlying technology

### Domains, trees, forests, and trusts

A **domain** (`lab.local`) is an administrative and replication boundary: a database of principals
plus the policies that govern them. Domains that share a contiguous DNS namespace form a **tree**;
one or more trees form a **forest**, which is the **true security boundary** in AD — everything
inside a forest implicitly trusts the forest's schema and configuration. This distinction matters:
a common misconception is that the *domain* is the security boundary. It is not; a compromise of
one domain in a forest can often be leveraged forest-wide (via the schema, the Enterprise Admins
group, or trust keys).

**Trusts** are relationships that let principals in one domain authenticate to resources in
another. They are directional (A trusts B), can be transitive or not, and carry a shared trust key.
For a tester, a trust is just another set of edges into a neighboring graph. The lab forest is a
single domain, so trusts are covered conceptually here and revisited when they become an escalation
path in later study.

### Domain controllers, the KDC, and the global catalog

A **domain controller (DC)** hosts a writable replica of the domain database (`NTDS.dit`), runs
the **Key Distribution Center (KDC)** that issues Kerberos tickets (05.2), and answers LDAP,
DNS, SMB, and RPC. Every DC is a crown-jewel target: the `NTDS.dit` contains **every account's NT
hash**, including `krbtgt` (the key behind every ticket). The **global catalog (GC)** is a
DC role that holds a partial, forest-wide replica reachable on **TCP 3268/3269** — useful to you
because it answers cross-domain queries from a single port.

### LDAP: the directory as a queryable database

AD exposes its directory over **LDAP** (TCP 389, or LDAPS 636). LDAP is a hierarchical database of
**objects**, each with a **distinguished name** (DN) like
`CN=lowpriv,CN=Users,DC=lab,DC=local` and a set of **attributes**. Any authenticated domain user
can *read* enormous amounts of it — this is by design, because member computers and users must be
able to resolve group memberships, find services, and apply policy. That readability is your
primary enumeration surface: **you don't need admin to map the domain, you need a valid account.**

### The objects that matter

<div class="callout key">

- **Users** — human and service accounts. Offensively interesting attributes: `memberOf` (group
  links), `servicePrincipalName` (SPNs → Kerberoastable, 06.2), `userAccountControl` (flags like
  *no pre-auth required* → AS-REP roastable, or *trusted for delegation* → 06.3), `adminCount=1`
  (currently or historically in a protected admin group), `pwdLastSet`, `description` (people put
  passwords here more often than you'd believe).
- **Groups** — the primary way privilege is granted. **Nested** membership is transitive: if
  `HelpDesk` is a member of `Server Operators`, every `HelpDesk` member inherits it. Key built-ins:
  **Domain Admins**, **Enterprise Admins**, **Administrators**, **Account Operators**, **Server
  Operators**, **Backup Operators**, **DnsAdmins** — each is a well-known escalation target.
- **Computers** — every domain-joined machine is an account too (`WS01$`, `SRV01$`). Computer
  accounts have SPNs and can be delegated; a machine account's hash = the machine's identity.
- **Organizational Units (OUs)** — containers for delegation and for **linking GPOs**.
- **GPOs (Group Policy Objects)** — policy applied to OUs/domains/sites; control over a GPO means
  control over every object it applies to (06.3).
- **The schema** — defines object classes and attributes forest-wide; modifiable only by Schema
  Admins, and a forest-level lever.

</div>

Every object carries a **security descriptor** (`nTSecurityDescriptor`) with a **DACL** — the list
of who may do what to it (read, write specific properties, reset the password, take ownership).
DACLs are where a huge fraction of AD attack paths live, and they are the subject of 06.3.

### The graph model — nodes and edges

The breakthrough that reshaped AD testing (SpecterOps's **BloodHound**, 2016) was to stop treating
AD as a list of objects and start treating it as a **directed graph**:

```text
NODES:  User, Computer, Group, OU, GPO, Domain, (Container, Cert Template…)
EDGES (a directed "X can act on / reach Y"):
  MemberOf        user/group → group        (transitive privilege)
  AdminTo         principal → computer       (local admin on that host)
  HasSession      computer → user            (that user's creds are cached there — reuse target)
  CanRDP/CanPSRemote  principal → computer    (remote logon)
  GenericAll / GenericWrite / WriteDACL / WriteOwner / ForceChangePassword
                  principal → object          (control-of-object edges — 06.3)
  AllowedToDelegate / AllowedToAct            (delegation edges — 06.3)
  DCSync          principal → domain          (can replicate secrets — 06.4)
```

An **attack path** is a chain of edges from a node you control to a node you want:

```text
lowpriv ─MemberOf→ [IT Support] ─GenericAll→ (svc_backup) ─MemberOf→ [Backup Operators] ─(rights)→ DC01
```

You control `lowpriv`; three edges later you reach the DC. Nobody *intended* that path — it
emerged from three independently reasonable grants. Finding it is graph search, and that is what
BloodHound automates. But the tool only shows edges it *collected*; the skill is knowing what each
edge means, spotting ones the tool missed, and verifying them.

## Why the weakness exists

AD's readable directory and composable permissions are **features**: they make a huge organization
manageable and let single-sign-on work. The weakness is **emergent complexity plus permission
sprawl**. Over years, admins add group nests, delegate OU rights to a help-desk team, grant a
service account "just enough" access that turns out to be `GenericAll`, and leave `adminCount`
accounts scattered. No single grant is a bug; their *composition* is a path. This is
**CWE-266 (incorrect privilege assignment)** and **CWE-284 (improper access control)** at
organizational scale, and it is why the graph — not any one object — is the vulnerability.

## How a tester recognizes it

You are looking, from your low-priv foothold, for:

- **Over-permissioned principals** — users/groups with control edges over accounts more privileged
  than themselves, or local-admin rights on many hosts.
- **Sessions of privileged users** on reachable machines (credential-reuse targets — 06.4).
- **Service accounts with SPNs** and accounts with weak `userAccountControl` flags (06.2).
- **Nested group membership** that quietly grants a built-in admin group.
- **Stale/forgotten objects** — `adminCount=1` on a decommissioned account, passwords in
  `description`, old computer accounts.

## Manual investigation — LDAP by hand

Before any graph tool, prove you can read the directory yourself. From the attacker box, an
authenticated LDAP query with `ldapsearch`:

```text
$ ldapsearch -x -H ldap://192.168.56.10 -D 'lowpriv@lab.local' -w 'Lab-Passw0rd!' \
    -b 'DC=lab,DC=local' '(objectClass=user)' sAMAccountName memberOf servicePrincipalName

dn: CN=svc_sql,CN=Users,DC=lab,DC=local
sAMAccountName: svc_sql
servicePrincipalName: MSSQLSvc/db01.lab.local:1433
memberOf: CN=IT Support,OU=Groups,DC=lab,DC=local

dn: CN=jdoe,CN=Users,DC=lab,DC=local
sAMAccountName: jdoe
userAccountControl: 4194304          # 0x400000 = DONT_REQ_PREAUTH → AS-REP roastable (06.2)
```

Targeted filters map straight to attack surface — this is the manual equivalent of what the tools
run for you:

```text
# Accounts with an SPN (Kerberoast candidates, 06.2):
'(&(objectClass=user)(servicePrincipalName=*))'
# Accounts not requiring Kerberos pre-auth (AS-REP roast, 06.2):
'(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
# Members of Domain Admins:
'(memberOf=CN=Domain Admins,CN=Users,DC=lab,DC=local)'
```

That `1.2.840.113556.1.4.803` is the LDAP **bitwise-AND matching rule** — it lets you test a single
flag inside `userAccountControl`. Knowing it means you can find no-pre-auth accounts without any
tool.

### RID cycling

Even with minimal rights you can often enumerate accounts by **RID** (the relative identifier at
the tail of a SID). The domain SID is fixed; RIDs count up (500 = built-in Administrator, 512 =
Domain Admins). Asking the DC to resolve `S-1-5-21-<domain>-500`, `-501`, `-1000`, `-1001` … maps
RIDs back to names over MS-RPC (`lsarpc`/`samr`), even where an anonymous LDAP bind is refused:

```text
$ nxc smb 192.168.56.10 -u lowpriv -p 'Lab-Passw0rd!' --rid-brute
500: LAB\Administrator (SidTypeUser)
512: LAB\Domain Admins (SidTypeGroup)
1103: LAB\svc_sql (SidTypeUser)
1108: LAB\jdoe (SidTypeUser)
```

## Tooling — what it does, key options, limits, verify

<div class="callout method">

- **`ldapsearch` / Windows `Get-ADUser`,`Get-ADGroup`** — raw directory reads. *What:* exact
  attribute values straight from the DC. *Verify:* this **is** the ground truth other tools
  summarize; use it to confirm any edge you plan to exploit.
- **netexec (`nxc`, successor to CrackMapExec)** — swiss-army enumeration over SMB/LDAP/WinRM.
  *Key options:* `--users`, `--groups`, `--rid-brute`, `--shares`, `-M` modules. *Limit:* breadth,
  not depth; confirm findings by hand.
- **BloodHound + a collector (SharpHound on Windows, `bloodhound-python` remote)** — collects
  nodes and edges over LDAP/SMB and renders the **graph**; the "Shortest Path to Domain Admins"
  query is the flagship. *Key options:* collection methods (`Default`, `All`, `Session`,
  `LoggedOn`, `DCOnly`). *Limits:* it shows only what it collected — **`Session`/`LoggedOn` data is
  a point-in-time snapshot** (a privileged session may have logged off), and it can miss edges from
  custom ACLs or newer abuse primitives; `DCOnly` is quieter but sees no sessions. Every edge you
  intend to abuse must be **re-verified against LDAP** before you rely on it.
- **ADExplorer (Sysinternals)** — a GUI LDAP browser and *snapshot* tool; the snapshot can be
  ingested offline, which is excellent OPSEC (one read, analyze later).

</div>

## Demonstration (LAB ONLY): collecting and reading the graph

<div class="callout attack">

**Technique — graph collection + shortest-path reasoning.** From the low-priv account, run a
remote collector and load the result:

```text
# LAB ONLY — remote collection with a valid low-priv account
bloodhound-python -u lowpriv -p 'Lab-Passw0rd!' -d lab.local -ns 192.168.56.10 -c All
# → JSON files (users, groups, computers, sessions, acls) → import into BloodHound
```

In the UI, mark `lowpriv` as **Owned**, then run **Shortest Path from Owned Principals to Domain
Admins**. Read the returned path *as edges* and translate each to a mechanism you already know or
will learn: a `MemberOf` is a group you're in; a `GenericAll` is 06.3; a `HasSession` is
credential-reuse (06.4). The graph is a hypothesis generator — it proposes paths; **you** confirm
each edge over LDAP and decide which is cleanest.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Every query and collection above targets the isolated `lab-06-ad`
forest (`DC01`/`SRV01`/`WS01` on the host-only `192.168.56.0/24`, no Internet route) using the
synthetic `lab.local\lowpriv` account and benign `LAB-FLAG-{uuid}` markers. Enumerating a real
Active Directory you are not explicitly authorized to test is unauthorized access and a crime
(M00). BloodHound collection is *noisy and logged*; on a real engagement it happens only inside a
signed scope and RoE. Restate authorization before you touch anything.

</div>

## Verification

Enumeration is verified when your graph matches reality: pick three edges the tool asserts and
confirm each with a raw LDAP read (the `memberOf` value, the SPN, the DACL ACE). Confirm your list
of privileged principals by resolving Domain Admins/Enterprise Admins membership directly. If
BloodHound shows a `HasSession` edge, treat it as *possibly stale* until re-checked. "The tool drew
an arrow" is not a finding; "the DC's own directory shows this grant, here is the query" is.

## Impact

A complete, verified graph is the map for the entire domain compromise. Even before exploiting
anything, the deliverable — *"a low-priv user can reach Domain Admin in three hops; here is each
edge"* — is often the highest-value single output of an internal test, because it tells the client
exactly which grants to sever. Mis-scoped permissions discovered here are the root cause behind the
attacks in 06.2–06.4.

## Remediation

<div class="callout defend">

- **Tier the administration model** (Microsoft's tiered/PAW model, now *Enterprise Access Model*):
  Tier-0 (DCs, domain admins) credentials never touch Tier-1/2 machines, so `HasSession` edges to
  workstations disappear.
- **Prune group nesting and privileged membership**; review `adminCount=1` accounts; enforce
  least privilege on OUs and objects (removes control edges — 06.3).
- **Restrict directory reads where feasible** and remove secrets from readable attributes
  (`description`, `info`).
- **Run BloodHound yourself** as a defender: the same graph shows *your* riskiest paths to fix
  first. This is the intended blue-team use.

</div>

## Detection / blue-team view

<div class="callout defend">

- **Enumeration is detectable.** Large or unusual LDAP queries (especially for `servicePrincipalName`
  or `nTSecurityDescriptor` across the whole directory) show in DC LDAP diagnostics and in
  **Microsoft Defender for Identity (MDI)**, which specifically alerts on "**Security principal
  reconnaissance (LDAP)**" and "**Account enumeration reconnaissance**."
- **RID cycling / SAMR enumeration** appears as bursts of SAMR/LSARPC calls; MDI flags
  "**User and group membership reconnaissance (SAMR)**."
- **Session enumeration** (BloodHound's `HasSession`) uses SMB/`SrvSvc` `NetSessionEnum`/`NetWkstaUserEnum`;
  restricting these (the *Net Cease* hardening / **`RestrictRemoteSAM`**) both reduces the edge and
  makes attempts stand out.
- Baseline: normal member workstations do not enumerate the whole directory. Map to
  **MITRE ATT&CK T1087** (Account Discovery), **T1069** (Permission Groups Discovery),
  **T1482** (Domain Trust Discovery), **T1018** (Remote System Discovery).

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-06-ad` — the VM forest `lab.local` (`DC01` 192.168.56.10, `SRV01`
192.168.56.20, `WS01` 192.168.56.30) on the **host-only 192.168.56.0/24 network with no Internet
route**; attacker box at .100. Built from documented eval media (see
[`labs/vm/README.md`](../../labs/vm/README.md)); provisioned with deliberate misconfigurations.
**Access:** `lab.local\lowpriv : Lab-Passw0rd!` (a plain domain user). **Time:** ~90 min.
**Isolation:** confirm external egress fails from inside a VM first; restore the "clean" snapshot to
reset. This lesson is **enumeration only** — no exploitation.

</div>

Enumerate the forest three ways and reconcile them: (1) raw `ldapsearch` for users, groups, SPNs,
and no-pre-auth accounts; (2) `nxc` for `--users --groups --rid-brute --shares`; (3) a BloodHound
collection. Draw the graph by hand from the LDAP data *first*, then compare to BloodHound's — note
anything the tool added or missed.

## Exercise

<div class="callout method">

**Situation.** Authorized internal engagement. You have a foothold: the domain account
`lab.local\lowpriv : Lab-Passw0rd!` and network access to the `lab.local` forest. Nothing else.

**Objective.** Produce a **graph model of the domain** and a **ranked high-value-target (HVT)
list** — the map you (or a teammate) would use to plan an attack. You are **not** told the intended
path and you must not be handed it; discovering structure is the exercise.

**Starting information.** The low-priv credentials and the lab network. No hints about which
accounts matter.

**Constraints.** Lab forest only; enumeration only in this lesson (no password resets, no
Kerberoasting yet — those are 06.2/06.3). Every claimed edge must be backed by a raw LDAP/RPC query,
not just a BloodHound screenshot.

**Expected deliverables.**
1. A node/edge graph (users, groups, computers, OUs, GPOs, and the edges among them), built from
   your own LDAP data and cross-checked against a BloodHound collection — with any discrepancies
   noted.
2. A ranked HVT list (which principals, if compromised, yield the most control) with a
   one-line justification each, tied to a concrete edge or membership.
3. Three edges you would investigate first as *possible* attack paths, each with the exact query
   that evidences it — **without** asserting a full path to Domain Admin.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Start from the crown jewels and work outward: who is in Domain Admins / Enterprise Admins /
Administrators, and what has control over <em>them</em> or over accounts that can reach a DC? Rank by
"blast radius," not by how easy the account looks.
</details>

<details><summary>Hint 2 — technique family</summary>
The offensively interesting attributes are <code>memberOf</code> (nesting),
<code>servicePrincipalName</code>, <code>userAccountControl</code> flags, <code>adminCount</code>,
and the object DACLs. Which principals sit on control edges pointing "uphill" toward more privilege?
</details>

<details><summary>Hint 3 — where to look</summary>
Mark <code>lowpriv</code> as Owned in BloodHound and read the shortest-path <em>edges</em>, but
confirm each with <code>ldapsearch</code>. Sessions are point-in-time — treat a <code>HasSession</code>
edge as a lead, not a fact, until re-checked.
</details>

## Check yourself

<div class="callout key">

1. Why is the **forest**, not the domain, the real security boundary — and what does that imply if
   you compromise one domain in a multi-domain forest?
2. Any authenticated user can read most of the directory. Name three attributes that read access
   alone hands an attacker, and the attack each one enables.
3. BloodHound shows a `HasSession` edge from `WS01` to a Domain Admin. Why might that edge be
   *false* by the time you act on it, and how do you confirm it?
4. Explain, in graph terms, what an "attack path" is and why three individually reasonable
   permission grants can compose into a domain compromise.
5. You need to find AS-REP-roastable accounts but have no tools installed — only `ldapsearch`. What
   filter do you use, and what does the odd numeric OID in it do?

</div>

Model answers are in `solutions/module-06.md` (instructor material — reason through them first).

## References

- **Microsoft** — *Active Directory Domain Services* overview; *How the Global Catalog works*;
  *Trusts* and *forest as a security boundary* guidance; *Enterprise Access Model / tiered
  administration*.
- **RFC 4511** — Lightweight Directory Access Protocol (LDAP): the protocol; **[MS-ADTS]** —
  Active Directory Technical Specification (schema, DNs, `userAccountControl`, matching rules).
- **SpecterOps — BloodHound** documentation (nodes, edges, collection methods) and the original
  "Six Degrees of Domain Admin" research.
- **netexec (nxc)** and **Impacket** project documentation.
- **MITRE ATT&CK** — **T1087** Account Discovery, **T1069** Permission Groups Discovery,
  **T1482** Domain Trust Discovery, **T1018** Remote System Discovery.
- **CWE-266** Incorrect Privilege Assignment; **CWE-284** Improper Access Control.

## What you should now be able to do

- Explain AD's architecture — domains/forests/trusts, DCs, GC, LDAP — and why the forest is the
  security boundary.
- Identify the objects and attributes that matter offensively and read them straight from the DC
  with `ldapsearch`.
- Model a domain as a graph of nodes and edges and explain what an attack path is.
- Enumerate a domain manually (LDAP, RID cycling) and with tooling (nxc, BloodHound), and verify
  every edge before trusting it.
- Produce a graph and a ranked HVT list from a low-priv foothold — the foundation for 06.2–06.4.

## Progress checkpoint

```bash
py course.py complete 06.1
```
