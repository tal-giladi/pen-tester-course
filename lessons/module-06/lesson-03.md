# 06.3 — Abusing ACLs, delegation & GPOs

<div class="prereq">

**Prerequisites:** [06.1](lesson-01.md) (the graph, object DACLs/`nTSecurityDescriptor`, computer
accounts), [06.2](lesson-02.md) (Kerberos, SPNs, service tickets — targeted Kerberoasting reuses
it), [05.2](../module-05/lesson-02.md) (Kerberos delegation, impersonation), and
[00.3](../module-00/lesson-03.md) (the confused deputy — delegation *is* the confused deputy).
**Module:** M06. **Difficulty:** 🔴 advanced.
**M06 assumes** a low-privileged domain account on the lab forest; this lesson assumes you have
found — via 06.1 — at least one **control edge** or **delegation** you may abuse.
**You will produce:** one abused control edge (a principal you gain control of), documented with the
exact ACE that enabled it, its remediation, and its detection.

</div>

## Why this matters

Groups are the *obvious* way privilege flows in AD. **ACLs, delegation, and GPOs are the hidden
way** — and they are where the most interesting attack paths live, because almost nobody audits
them. An administrator delegates "reset passwords in the Sales OU" to the help desk, grants a
backup tool `GenericAll` on a service account, links a GPO to an OU that happens to contain
sensitive servers, or configures a web server to delegate to a database. Each is a legitimate,
often necessary configuration. Each is also a directed edge in the graph that lets a principal
**take control of another principal or machine.** These are the edges BloodHound draws in red, and
the ones that turn 06.1's map into a real path to Domain Admin (06.4).

This lesson teaches the mechanism behind each edge so you can recognize, abuse (in lab), and — every
time — *remediate and detect* it.

## Learning objectives

By the end you can:

- Read an object's **DACL** and interpret the abusable rights: **GenericAll, GenericWrite,
  WriteDACL, WriteOwner, WriteProperty, ForceChangePassword, AddMember, Self**.
- Turn each right into control of the target principal (password reset, targeted Kerberoasting,
  group addition, DACL rewrite, ownership takeover).
- Explain Kerberos **delegation** — **unconstrained**, **constrained**, and **resource-based
  constrained (RBCD)** — and why each is a confused-deputy escalation.
- Explain **GPO abuse**: how control over a GPO becomes code execution on every object it applies
  to.
- State the remediation **and** the detection for every one of these — AD ACL/delegation changes
  have specific event IDs and audit signals.

## Intuition

Every AD object is a little safe with a list on the door saying who may open it, change its
combination, or change the *list itself*. Most attacks here are about finding a safe whose door
list names **you** (or a group you're in) with a powerful right. If the list says you can *reset the
password* of the account inside, you become that account. If it says you can *rewrite the list*
(`WriteDACL`), you grant yourself every right and then do anything. Delegation is a different
confused deputy: a service is told "you may act *as* users toward this other service" — so if you
control that service, you can make it act as **anyone**, including an admin, toward the target. GPOs
are the safe that controls *thousands* of other safes at once: own the policy and you own everything
it touches.

## The underlying technology

### DACLs and the rights that matter

An object's `nTSecurityDescriptor` holds a **DACL**: an ordered list of **ACEs** (access-control
entries), each granting or denying a **right** to a **principal** on this object. The rights that
create attack edges:

<div class="callout key">

| Right (ACE) | What it lets the holder do to the target | Abuse |
|---|---|---|
| **GenericAll** | Full control | anything below — reset password, add to group, etc. |
| **GenericWrite** | Write any non-protected property | set an SPN (→ targeted Kerberoast), set `logonScript`, alter `msDS-AllowedToActOnBehalfOfOtherIdentity` (→ RBCD) |
| **WriteProperty** (specific) | Write one attribute | e.g. write `member` (add to a group) or `servicePrincipalName` |
| **WriteDACL** | Modify the object's own DACL | grant yourself GenericAll, then proceed |
| **WriteOwner** | Take ownership | owner can rewrite the DACL → GenericAll |
| **ForceChangePassword** (an extended right) | Reset the target's password **without knowing the old one** | become the target |
| **Self / AddMember** (extended right on a group) | Add a member | add yourself to a privileged group |
| **AllExtendedRights** | All extended rights, incl. password reset & **DS-Replication-Get-Changes** on the domain | ForceChangePassword; on the *domain* object → **DCSync** (06.4) |

</div>

These are **directed edges**: `PrincipalA ─GenericAll→ PrincipalB` means A can become or control B.
Chains of them (A→B→C) are exactly what shortest-path search walks.

### How each right becomes control

- **ForceChangePassword / GenericAll → password reset.** You set the target's password to one you
  know, then authenticate as it. Loud (the user's password now broken) but decisive; on a service
  account it can break the service, so note the operational impact.
- **GenericWrite / WriteProperty(servicePrincipalName) → targeted Kerberoasting.** If you can write
  the target's `servicePrincipalName`, you *give* it an SPN, then Kerberoast it (06.2) to crack its
  password offline — **and remove the SPN afterward**. This is stealthier than a password reset
  because you don't change the account's password; you just borrow its Kerberoastability.
- **WriteProperty(member) / Self → add to group.** Add yourself (or a controlled principal) to a
  privileged group, inheriting its rights transitively.
- **WriteDACL → grant yourself GenericAll.** Rewrite the target's DACL to add an ACE giving you full
  control, then use it. **WriteOwner → become owner → rewrite DACL** is the same, one step longer.

Each is a *general primitive at the target's privilege level* — the same reasoning as GTFOBins in
04.2, now expressed in directory permissions.

### Kerberos delegation — the confused deputy across machines

Delegation lets a service use a **client's identity** to reach a *third* service (the web app talks
to the database *as the user*). Three kinds, in ascending subtlety:

- **Unconstrained delegation** <span class="badge deprecated">DANGEROUS, legacy</span> — a computer
  flagged for unconstrained delegation caches the **TGT of every user who authenticates to it**. If
  you compromise that host (or coerce a privileged account — even a DC's machine account — to
  authenticate to it), you harvest their TGTs and become them. This is why unconstrained delegation
  on anything but a DC is a critical finding.
- **Constrained delegation (`msDS-AllowedToDelegateTo`)** — a service may impersonate users, but
  only toward a **listed set of SPNs**. The abuse: if you control an account configured for
  constrained delegation (especially with **protocol transition**, "any authentication"), you can
  request a ticket *as an arbitrary user* (including an admin) to those target services via the
  **S4U2Self/S4U2Proxy** extensions.
- **Resource-Based Constrained Delegation (RBCD)** — the modern form: the *resource* (target
  computer) names who may delegate to it, in its attribute
  **`msDS-AllowedToActOnBehalfOfOtherIdentity`**. The abuse is a favorite because it needs only
  **write access to that attribute** (e.g. via `GenericWrite`/`GenericAll` on the computer, or the
  `ms-DS-MachineAccountQuota` letting you add a computer you control): set the computer to trust
  *your* controlled account, then S4U to get a service ticket **as any user** (e.g. a Domain Admin)
  to the target — often local `cifs`/`host` access → SYSTEM.

All three are the **confused deputy**: a privileged service is authorized to act as clients, and you
arrange for it to act as a *client it shouldn't* — an admin — on your behalf.

### GPO abuse — one edge, thousands of targets

A **GPO** applies settings to every object in the OUs/domain/sites it is **linked** to. If you have
write access to a GPO (a `GenericWrite`/`GenericAll`/`WriteDACL` edge to the GPO object, or edit
rights via `gPCFileSysPath` in SYSVOL), you can add, for example, an **immediate scheduled task** or
a startup script that runs as SYSTEM on every computer, or add a user to the local Administrators
group of every machine in scope. The blast radius is whatever the GPO is linked to — potentially the
whole domain. This is why GPO edit rights are Tier-0-sensitive.

## Why the weakness exists

None of these is a bug; each is delegation of authority that a graph makes *transitive and
composable*. Admins grant object rights to solve day-to-day problems (help desk resets passwords,
backup software needs access, a service needs to reach a DB), rarely realizing that "reset passwords
in this OU" or `GenericWrite` on a computer is a path to Domain Admin. It is **CWE-266/CWE-269
(privilege assignment/management)** and **CWE-441 (confused deputy)** for delegation, expressed in
AD's rich permission model. The kernel and KDC are doing exactly what the ACEs and delegation flags
tell them.

## How a tester recognizes it

From 06.1's collection: BloodHound draws these as edges (`GenericAll`, `WriteDACL`, `WriteOwner`,
`ForceChangePassword`, `AddSelf`, `AllowedToDelegate`, `AllowedToAct`). By hand, read the target's
`nTSecurityDescriptor` and look for ACEs naming your principal (or a group you're in) with any right
in the table above; read `userAccountControl` for `TRUSTED_FOR_DELEGATION` (unconstrained) and
`msDS-AllowedToDelegateTo` / `msDS-AllowedToActOnBehalfOfOtherIdentity` for constrained/RBCD;
enumerate GPO objects and their DACLs and links.

## Manual investigation

```text
# Read a target's DACL (PowerView-style, on a Windows foothold) and find abusable ACEs:
PS> Get-DomainObjectAcl -Identity svc_backup -ResolveGUIDs |
      ? { $_.SecurityIdentifier -match $mySid } |
      select ActiveDirectoryRights, ObjectAceType, SecurityIdentifier
  ActiveDirectoryRights : GenericAll
  SecurityIdentifier    : S-1-5-21-...-1105   (IT Support — a group lowpriv is in)

# Unconstrained delegation computers (UAC bit 0x80000 = TRUSTED_FOR_DELEGATION):
'(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))'
# Constrained delegation (has a delegation target list):
'(msDS-AllowedToDelegateTo=*)'
```

The DACL read is the ground truth: an ACE granting `GenericAll` to a group you belong to **is** the
edge — the tool just visualized it.

## Tooling — what it does, key options, limits, verify

<div class="callout method">

- **BloodHound** — surfaces every ACL/delegation edge and lets you query "shortest path" through
  them. *Limit:* it names the edge, not the *safest* way to use it; you choose the primitive.
- **PowerView / SharpView** (Windows) — `Get-DomainObjectAcl`, `Add-DomainObjectAcl`,
  `Set-DomainObject` (write SPN), `Add-DomainGroupMember`. Read-and-verify DACLs by hand.
- **Impacket** — `dacledit.py` (view/modify DACLs), `rbcd.py` (read/write
  `msDS-AllowedToActOnBehalfOfOtherIdentity`), `addcomputer.py` (add a machine account for RBCD),
  `getST.py` (S4U to obtain the impersonation ticket). *Limit:* remote; each write is logged.
- **Rubeus / `getST.py`** — perform the **S4U2Self/S4U2Proxy** exchange for constrained/RBCD abuse.

</div>

**Verify before you act:** re-read the DACL/delegation attribute over LDAP so you know the exact
ACE, and — for anything destructive like a password reset — confirm the operational blast radius
(will resetting `svc_backup` break a running service?). Prefer the **reversible** primitive
(targeted Kerberoast, add-then-remove SPN, then remove yourself from the group) over the
irreversible one when both reach the goal.

## Exploitation / demonstration (LAB ONLY)

<div class="callout attack">

**Technique — GenericAll → targeted Kerberoast (the reversible choice).** 06.1 showed `IT Support`
(a group `lowpriv` is in) has **GenericAll** on `svc_backup`. Rather than reset its password
(destructive), give it an SPN, Kerberoast it, then clean up:

```text
# LAB ONLY. 1) write an SPN onto svc_backup (uses the GenericAll/GenericWrite edge)
PS> Set-DomainObject -Identity svc_backup -Set @{serviceprincipalname='fake/svc_backup'}
# 2) Kerberoast it (06.2), crack offline on the attacker box (mode 13100)
PS> Get-DomainSPNTicket -SPN 'fake/svc_backup'      # → $krb5tgs$23$... → hashcat
# 3) CLEAN UP: remove the SPN you added
PS> Set-DomainObject -Identity svc_backup -Clear serviceprincipalname
```

**Technique — RBCD via GenericWrite on a computer.** 06.1 showed `GenericWrite` on `SRV01$`:

```text
# LAB ONLY. Point SRV01 at a computer account we control, then impersonate an admin to it.
$ addcomputer.py lab.local/lowpriv:'Lab-Passw0rd!' -computer-name 'ATK$' -computer-pass 'Atk-Passw0rd!'
$ rbcd.py lab.local/lowpriv:'Lab-Passw0rd!' -delegate-from 'ATK$' -delegate-to 'SRV01$' -action write
$ getST.py -spn cifs/SRV01.lab.local -impersonate Administrator lab.local/ATK$:'Atk-Passw0rd!'
# → a service ticket AS 'Administrator' to cifs/SRV01 → admin file access / SYSTEM on SRV01
```

Both are the confused deputy: you never learned an admin's password; you made a service the KDC
trusts issue you a ticket *as* the admin. Mechanism first — do not treat these as blind recipes.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Every command targets the isolated `lab-06-ad` forest, synthetic
accounts, benign flags. Writing SPNs, DACLs, `msDS-AllowedToActOnBehalfOfOtherIdentity`, or adding
computer accounts in a domain you are not explicitly authorized to test is unauthorized modification
(M00) — and several of these actions are **destructive or persistent** (a password reset breaks a
service; an added computer account and RBCD change persist). In lab you reset via snapshot; in a
real engagement you get written approval for any change and you *clean up* and document every
modification. Restate scope and authorization first.

</div>

## Verification

Verified control means you can *act as* the target: after a targeted Kerberoast, the cracked
password authenticates as `svc_backup`; after RBCD, `klist` shows a service ticket for
`cifs/SRV01.lab.local` impersonating `Administrator` and you can list `\\SRV01\C$`. For a group
addition, `whoami /groups` (or a fresh logon) shows the new membership. Capture the *before* state
too — the DACL/attribute you changed — so your report proves the edge existed and shows what you
altered.

## Impact

A single control edge can be the whole ballgame: `WriteDACL` on the domain object or
`AllExtendedRights` enabling DCSync (06.4) is domain compromise from one ACE; RBCD or constrained
delegation to a DC or a Tier-0 host is SYSTEM on a critical machine; GPO write is code execution
across everything the GPO is linked to. Even a "small" edge (reset one service account) is often the
first link of the chain in 06.4. In the report, state the edge, the principals it connects, and the
*reachable* impact through the graph.

## Remediation

<div class="callout defend">

- **Audit and prune DACLs.** Remove standing `GenericAll`/`GenericWrite`/`WriteDACL`/`WriteOwner`
  and broad `ForceChangePassword` grants to non-Tier-0 principals; delegate the *narrowest* right
  (a specific `WriteProperty`) instead of full control. Watch for ACEs on Tier-0 objects.
- **Delegation:** eliminate **unconstrained delegation** (use constrained/RBCD; put sensitive
  accounts in **Protected Users** and mark them *"Account is sensitive and cannot be delegated"*,
  which blocks delegation of that identity). Restrict who can write
  `msDS-AllowedToActOnBehalfOfOtherIdentity`; set **`ms-DS-MachineAccountQuota` to 0** so users
  can't add attacker-controlled computer accounts for RBCD.
- **GPOs:** restrict GPO **edit** and **link** rights to Tier-0 admins; monitor SYSVOL for changes.
- Model with **least privilege and tiering** so no low-priv principal sits on a control edge toward
  a high-priv one — the structural fix that erases these edges from the graph.

</div>

## Detection / blue-team view

<div class="callout defend">

- **DACL changes → Event ID 4662** ("An operation was performed on an object") with the specific
  access mask/GUID, and **5136** ("A directory service object was modified") when SACL auditing is
  on — alert on writes to `nTSecurityDescriptor`, `member` of privileged groups, `servicePrincipalName`
  (targeted Kerberoast tell), and `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD tell).
- **Password reset → Event ID 4724** ("An attempt was made to reset an account's password") by an
  unexpected principal; **4728/4732/4756** for additions to privileged groups.
- **Computer account added → Event ID 4741** (a common RBCD precursor when `MachineAccountQuota`>0).
- **Delegation abuse → Event ID 4769** service-ticket requests showing S4U (the
  *Transited Services* field populated) or tickets requested *for* an admin by a service — anomalous
  impersonation. Unconstrained-delegation TGT harvesting often pairs with **coercion** (auth-forcing)
  traffic on the delegation host.
- **Honeypots:** a decoy privileged object with a tempting DACL, or a decoy account marked sensitive;
  any modification/impersonation attempt is high-fidelity.
- **Defender for Identity** flags several of these ("suspicious additions to sensitive groups",
  delegation anomalies). Map to **MITRE ATT&CK T1484** (Domain Policy Modification — GPO),
  **T1098** (Account Manipulation — ACL/attribute writes), **T1550/T1558** (delegation → ticket
  abuse), **T1207** context for the DC-side effects.

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-06-ad` — the `lab.local` VM forest on the host-only, no-Internet network
(see [`labs/vm/README.md`](../../labs/vm/README.md)). **Access:** `lab.local\lowpriv : Lab-Passw0rd!`.
The forest is provisioned with at least one **control edge** (e.g. a group `lowpriv` is in with
`GenericAll`/`GenericWrite` over another principal) and at least one **delegation** misconfiguration
(constrained or RBCD-abusable). **Time:** ~90 min. **Isolation:** verify egress fails; **reset via
snapshot** after any destructive/persistent change. Prefer reversible primitives; clean up what you
add.

</div>

From your 06.1 graph, pick **one** control edge and abuse it to gain control of another principal —
preferring the reversible primitive (targeted Kerberoast, add-then-remove SPN) over a password reset
where possible. Verify you can act as the target. Then document the exact ACE, the remediation, and
the detection. If time permits, abuse the delegation edge (RBCD or constrained) to reach a host, and
compare its detection signature to the ACL abuse.

## Exercise

<div class="callout method">

**Situation.** Authorized internal test. Your 06.1 graph shows at least one control edge from a
group you're in toward a more privileged principal, and a delegation misconfiguration somewhere in
the forest.

**Objective.** Abuse **one** edge to gain control of another principal (or a machine, via
delegation), verify the control, and write the finding — including the exact enabling ACE/attribute,
remediation, and detection.

**Starting information.** Your low-priv account and the 06.1 graph. You choose the edge and the
primitive; the intended full path to Domain Admin is **not** given.

**Constraints.** Lab forest only. Prefer reversible primitives; if you must do something destructive
or persistent (password reset, RBCD write, added computer account), record the before-state and the
cleanup, and reset via snapshot afterward. Every abused right must be evidenced by the raw ACE, not
just a BloodHound edge.

**Expected deliverables.**
1. The chosen edge, the **exact ACE/attribute** that enables it (from a raw DACL/LDAP read), and the
   primitive you used (and *why* that primitive over the alternatives).
2. **Verification** that you now control the target (authenticate as it / hold an impersonation
   ticket / show new group membership), with before/after evidence.
3. **Remediation** (narrow the right / tier / block delegation / MachineAccountQuota=0) **and**
   **detection** (the specific event IDs — 4662/5136/4724/4728/4741/4769 as applicable — and any
   honeypot) — both required, mapped to ATT&CK.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Ask what right you hold on the target and what that right's <em>general primitive</em> is: reset
password? write a property (SPN, member, RBCD attribute)? rewrite the DACL? Choose the one that
reaches control with the least breakage and best cleanup.
</details>

<details><summary>Hint 2 — technique family</summary>
GenericAll/GenericWrite over a user → targeted Kerberoast (write SPN, roast, remove SPN) or password
reset. GenericWrite over a <em>computer</em> → RBCD (write
<code>msDS-AllowedToActOnBehalfOfOtherIdentity</code>, then S4U). WriteDACL → grant yourself
GenericAll first. Write on a group's <code>member</code> → add yourself.
</details>

<details><summary>Hint 3 — where to look</summary>
Read the target's raw DACL (<code>Get-DomainObjectAcl -ResolveGUIDs</code> or
<code>dacledit.py</code>) and match ACEs to your SID / group SIDs. For delegation, check
<code>userAccountControl</code> (unconstrained), <code>msDS-AllowedToDelegateTo</code> (constrained),
and <code>msDS-AllowedToActOnBehalfOfOtherIdentity</code> (RBCD).
</details>

## Check yourself

<div class="callout key">

1. You have `GenericAll` on a service account. Give **two** ways to gain control of it and explain
   why the **targeted-Kerberoast** route is stealthier and more reversible than a password reset.
2. Explain why **RBCD** often needs only `GenericWrite` on the *target computer* — what single
   attribute do you write, and what does the S4U exchange then let you request?
3. Why is **unconstrained delegation** on a non-DC server a critical finding? What does the server
   cache, and how would an attacker make a privileged account authenticate to it?
4. Control over a GPO can be worse than compromising one admin. Why? Tie your answer to what a GPO is
   *linked* to.
5. A defender wants to catch ACL abuse. Which event ID fires when someone writes an object's DACL,
   and which specific attribute-writes would you alert on as high-signal (name two)?

</div>

Model answers are in `solutions/module-06.md`.

## References

- **Microsoft** — Active Directory *security descriptors / DACLs / ACEs*; *Kerberos constrained
  delegation*, *resource-based constrained delegation*, **S4U2Self/S4U2Proxy** ([MS-SFU]);
  *Protected Users* and *"sensitive and cannot be delegated"*; *ms-DS-MachineAccountQuota*.
- **SpecterOps** — "An ACE Up the Sleeve" (Robbins/Schroeder), BloodHound ACL/delegation edge docs;
  **Elad Shamir** — "Wagging the Dog" (RBCD abuse); **Will Schroeder** — constrained-delegation
  research.
- **Impacket** — `dacledit.py`, `rbcd.py`, `addcomputer.py`, `getST.py`; **PowerView** function
  reference.
- **MITRE ATT&CK** — **T1484** Domain Policy Modification (GPO), **T1098** Account Manipulation,
  **T1550** Use Alternate Authentication Material, **T1558** Steal or Forge Kerberos Tickets.
- **CWE-266/CWE-269** privilege assignment/management; **CWE-441** Unintended Proxy/Confused Deputy.

## What you should now be able to do

- Read a DACL and identify the abusable right, and convert each right into control of the target.
- Explain unconstrained/constrained/RBCD delegation as confused-deputy escalations and abuse one in
  lab.
- Explain GPO abuse and its blast radius.
- Choose the safest reversible primitive, verify control, and clean up.
- Write the specific remediation **and** the event-ID-level detection for every ACL/delegation/GPO
  edge.

## Progress checkpoint

```bash
py course.py complete 06.3
```
