# 05.2 — Windows authentication primer: NTLM, Kerberos, SMB/LDAP/WinRM & access tokens

<div class="prereq">

**Prerequisites:** [05.1 Windows for testers](lesson-01.md) — you must understand SIDs, access
tokens, privileges, and the SCM. Also [M01 Networking](../module-01/lesson-01.md) (protocols,
challenge/response, sessions) and [M00's confused deputy](../module-00/lesson-03.md).
**Module:** M05. **Difficulty:** 🟡 intermediate.
**M05 assumes** a low-privileged shell on a lab Windows host. This lesson is mostly **conceptual** —
it builds the authentication model that 05.3 (token abuse) and, above all, **M06 (Active Directory)**
depend on. There is no exploitation here; you are learning where credential material lives and why it
is reusable.
**You will produce:** an annotated authentication-flow analysis for a described logon, marking every
point where credential material is exposed, cached, or reusable.

</div>

## Why this matters

Active Directory (M06), credential attacks (M10), and lateral movement (M11) are, at bottom,
attacks on **Windows authentication**. You cannot Kerberoast, pass-the-hash, or reason about a
BloodHound path if you don't first understand what a Windows credential *is*, how NTLM and Kerberos
prove identity, and why the material that proves identity is so often **reusable without knowing the
password**. That last property — *reusable credential material* — is the single most consequential
fact in Windows offense, and it falls straight out of how the protocols are designed.

This lesson is a **primer**, not an attack chapter. It gives you the mechanism cleanly, marks the
exposure points, and forward-references where each becomes an attack: pass-the-hash (M10/M11),
Kerberoasting and delegation abuse (M06), token impersonation (05.3). Learn the flows now and every
later attack becomes "of course" rather than a memorized recipe.

## Learning objectives

By the end you can:

- Explain what a Windows credential is at each layer: plaintext, NT hash, NTLM challenge/response,
  Kerberos ticket — and which are reusable.
- Walk through **NTLM** challenge/response and say precisely why the NT hash is a
  "password-equivalent" that enables **pass-the-hash**.
- Walk through the **Kerberos** AS/TGS exchange conceptually — TGT, service tickets, SPNs, the KDC —
  and locate where offline-crackable and replayable material appears.
- Describe the roles of **SMB, LDAP, and WinRM** in authenticated Windows access.
- Explain **access tokens, impersonation, and delegation**, and why `SeImpersonate`/`SeDebug` matter
  for both privesc (05.3) and credential theft.
- Point at any logon flow and identify where credential material is exposed, cached, or reusable.

## Intuition

Proving "I am Alice" to a computer can be done three ways: send the secret (a password — simple but
exposes it), prove you know the secret without sending it (a **challenge/response**, as NTLM does), or
present a **ticket** a trusted third party already issued you (as Kerberos does). Windows uses all
three across its history. The attacker's insight is that in defending the password, these protocols
create *other* artifacts — hashes, responses, tickets — that are **themselves sufficient to
authenticate**. If the artifact is enough to log in, then stealing the artifact is as good as
stealing the password, and you never needed to crack anything. Almost all of Windows credential
offense is a variation on "the thing that proves identity got reused by someone who shouldn't have
it" — the confused deputy again, this time at the authentication layer.

## The underlying technology

### What a Windows credential actually is

- **Plaintext password** — what the user types. Rarely available to an attacker directly (though it
  can leak via `unattend.xml`, autologon, memory, or phishing).
- **NT hash** — `MD4(UTF-16LE(password))`. Unsalted, no iteration. Windows stores this (not the
  plaintext) in the local **SAM** and in AD's **NTDS.dit**, and LSASS keeps it in memory for
  single-sign-on. **Crucially, the NT hash is what NTLM authentication consumes** — so possessing the
  hash is equivalent to possessing the password for NTLM. That is the whole basis of pass-the-hash.
- **NTLMv1/v2 response** — the per-authentication challenge/response value derived from the NT hash
  (below). Not directly reusable like the hash, but **crackable offline** or, in some
  configurations, **relayable**.
- **Kerberos tickets** — TGT and service tickets (below). Time-limited, but **replayable while
  valid** (pass-the-ticket) and, for service tickets, **crackable offline** (Kerberoasting).

<div class="callout key">

**The reuse ladder.** Plaintext → NT hash → challenge/response → ticket. Windows spends enormous
effort protecting the plaintext, but each *derived* form is, by design, enough to authenticate in
some context. A tester's job is to notice which form they can obtain and what it unlocks. "I don't
have the password" is rarely the end of the road.

</div>

### NTLM — challenge/response, and why the hash is enough

<span class="badge deprecated">LEGACY, still everywhere</span> NTLM is the older protocol, still
enabled in most environments for compatibility. It authenticates in three messages:

```text
Client                                             Server (or DC via netlogon)
  | ---- NEGOTIATE (capabilities) ------------------>|
  | <--- CHALLENGE (random 8-byte server nonce) -----|
  | ---- AUTHENTICATE ------------------------------>|
  |        response = f( NT hash, challenge, ... )    |
  |        (username, domain, and the computed        |
  |         response — NOT the password, NOT the hash) |
```

The server (or the domain controller, for domain accounts) knows the user's NT hash, computes the
same function over the challenge it sent, and compares. The design goal was to **never send the
password or the hash on the wire** — and it succeeds at that. But look at what the client needs to
compute the response: **only the NT hash.** The plaintext is never required. Therefore anyone holding
the NT hash can complete this exchange as the user, **without ever knowing or cracking the password.**

<div class="callout attack">

**Pass-the-Hash — preview only (full technique in M10/M11).** Because the NTLM response is derived
purely from the NT hash, an attacker who extracts a user's NT hash from LSASS or the SAM (05.1 noted
where these live; extraction is M10) can authenticate to any service that accepts NTLM **as that
user**, feeding the hash to the protocol instead of a password. No cracking is involved — the hash
*is* the credential. This is why an NT hash is called "password-equivalent," and why dumping hashes is
a top objective after gaining SYSTEM. **We do not perform PtH here; we are establishing why it is
possible.** Detection and remediation are below and expanded in M11.

</div>

**NTLMv1 vs NTLMv2.** NTLMv1 uses a weak DES-based construction and is trivially crackable / relayable
— it should be disabled. NTLMv2 adds the client challenge, timestamps, and a target-server binding
(HMAC-MD5), which resists some relay and precomputation but is still **offline-crackable** if you
capture a response (a fast dictionary/mask target), and NTLM broadly is vulnerable to **relay** when
signing is not enforced. Those capture/relay attacks live in M10/M11; here, note the exposure.

### Kerberos — tickets, SPNs, and the KDC

<span class="badge current">CURRENT default in AD</span> Kerberos is the default in an Active
Directory domain. Instead of proving yourself to each server, you prove yourself **once** to a trusted
third party — the **Key Distribution Center (KDC)**, a role of every domain controller — and then
present **tickets** it issues. Conceptually, two exchanges:

```text
1) AS-REQ / AS-REP  (authentication — once per logon)
   Client --AS-REQ--> KDC       "I'm alice; here's a timestamp encrypted with my key (NT hash-derived)"
   Client <--AS-REP-- KDC       TGT (encrypted with the KRBTGT account's key) + session key
                                 -> the TGT proves "the KDC vouched for alice"

2) TGS-REQ / TGS-REP  (authorization for a specific service — per service)
   Client --TGS-REQ--> KDC      "here's my TGT; give me a ticket for SPN MSSQLSvc/db01"
   Client <--TGS-REP-- KDC      Service Ticket (TGS) encrypted with the SERVICE ACCOUNT's key
   Client --AP-REQ---> Service  presents the service ticket; service decrypts with its own key
```

Key ideas to carry into M06:

- **TGT (Ticket-Granting Ticket)** — proves the KDC authenticated you; encrypted with the domain's
  `krbtgt` key. Stealing a valid TGT lets you request service tickets as that user
  (**pass-the-ticket**); forging one with the `krbtgt` key is the **Golden Ticket** (M06).
- **SPN (Service Principal Name)** — a string like `MSSQLSvc/db01.lab.local:1433` that names a service
  and maps to the **account that runs it**. To get a ticket for an SPN you need only a valid TGT — any
  authenticated domain user can request one.
- **The service ticket is encrypted with the service account's key** (derived from that account's
  password). This is the crack that makes **Kerberoasting** work.

<div class="callout attack">

**Kerberoasting — forward reference to M06 (conceptual here).** Any domain user can ask the KDC for a
service ticket for any SPN. That ticket is encrypted with the **service account's password-derived
key** — so an attacker requests tickets for service accounts, takes them **offline**, and cracks the
account's password at their leisure (M10 cracking). No elevated access and no touching the target
service is required — the KDC hands out the crackable material to any authenticated user. Service
accounts with weak passwords and human-set SPNs are the classic target. **AS-REP roasting** is the
sibling: accounts with "Kerberos pre-authentication not required" leak an AS-REP an attacker can crack
similarly. Both are M06 attacks; here, note *why the material is obtainable and crackable.*

</div>

### The plumbing: SMB, LDAP, WinRM

Authentication is a means to an end — reaching a service. The three you meet constantly:

- **SMB (TCP 445)** — file sharing, but also named pipes for remote administration (the transport
  behind PsExec-style execution, M11) and the `IPC$`/`ADMIN$`/`C$` shares. Authenticates via NTLM or
  Kerberos. **SMB signing** is the control that prevents NTLM relay; when it is off, relay attacks work
  (M11). SMB enumeration reveals shares, users, and (via RPC/`lsarpc`, `samr`) domain information.
- **LDAP (TCP 389; LDAPS 636)** — the query protocol for Active Directory's directory database. This
  is how you enumerate users, groups, computers, SPNs, and ACLs in M06 (BloodHound speaks LDAP). Binds
  with NTLM/Kerberos or simple bind; **LDAP signing/channel binding** is the relay control here.
- **WinRM (TCP 5985 HTTP / 5986 HTTPS)** — Windows Remote Management, the transport for PowerShell
  Remoting and remote admin. Authenticates with NTLM/Kerberos/CredSSP; a common lateral-movement
  channel (M11) for accounts in `Remote Management Users` or local admins.

You don't attack these here; you learn that each one **accepts NTLM or Kerberos**, which means each is
a place your reusable credential material can be *spent* — and a place signing/channel-binding controls
decide whether relay is possible.

### Access tokens, impersonation, and delegation

05.1 introduced the **access token** LSASS builds at logon. Two token behaviors are central to both
privesc and credential theft:

- **Impersonation.** A privileged service often needs to act *as the client that connected to it* —
  e.g. a file server accessing files with the caller's rights, not its own. Windows lets a thread
  **impersonate** a client's token for this. The privilege that permits it is **`SeImpersonatePrivilege`**.
  Service accounts (`LocalService`, `NetworkService`, IIS/SQL app-pool identities) hold it by design.
- **Delegation.** Across machines, a service may need to use the client's identity to reach a *third*
  service ("I'm the web server; let me talk to the database *as* the user"). Kerberos **delegation**
  (unconstrained, constrained, resource-based) enables this — and its misconfiguration is a major AD
  escalation class in M06.

<div class="callout key">

**Why `SeImpersonate` is a privesc primitive (bridge to 05.3).** If you run as a service account that
holds `SeImpersonatePrivilege`, and you can trick a **SYSTEM** process into authenticating to *you*
(over a local named pipe/RPC), you can **impersonate the SYSTEM token** it presents and spawn a
process with it. That is the entire "potato" family (05.3) — it is not a bug, it is impersonation
working exactly as designed, pointed the wrong way. `SeDebugPrivilege` is the sibling: it lets you open
*any* process (including LSASS) and read or inject — enabling both token theft and credential dumping.

</div>

## Why the weakness exists

Nothing here is a protocol bug in the "implementation error" sense — these are **design consequences**
of backward compatibility and single-sign-on convenience. NTLM had to authenticate without sending the
password, so it made the hash sufficient — and never having to re-type a password on the network means
the hash must live in memory, reusable. Kerberos hands crackable service tickets to any user because
SPN-to-account mapping and per-service tickets are how the protocol scales. Impersonation exists so
services can act for clients. The "weaknesses" are **CWE-522 (Insufficiently Protected Credentials)**
and **CWE-294 (Authentication Bypass by Capture-Replay)** as *emergent* properties, plus the specific
misconfigurations (NTLMv1 enabled, no SMB signing, weak service-account passwords) that turn a design
trade-off into an exploitable one.

## How a tester recognizes it (conceptually)

You are mapping **where reusable material appears**: any host where you can reach LSASS (SYSTEM/`SeDebug`
→ NT hashes, tickets, TGTs in memory); any service account with an SPN (Kerberoastable); any account
with pre-auth disabled (AS-REP roastable); any SMB/LDAP service without signing (relay-able); any place
a plaintext or hash is stored (SAM, `unattend.xml`, autologon, DPAPI-protected blobs). In this lesson
you *identify* these; the attacks are M06/M10/M11.

## Tooling — what it does, key options, limits (survey only)

You will not run these until later modules, but know the map so the flows above have names:

- **Impacket** (`secretsdump.py`, `GetUserSPNs.py`, `getTGT.py`) — Python implementations of SMB/LDAP/
  Kerberos that dump secrets, request roastable tickets, and manipulate tickets. The reference toolkit
  for M10/M11.
- **Rubeus / mimikatz** — Windows tools for ticket and credential operations. **mimikatz is taught in
  this course as a *concept*** (next callout): what it extracts and why, not weaponized use.
- **BloodHound** (M06) — collects LDAP data and graphs attack paths (who can Kerberoast, who has
  delegation, who is admin where).

<div class="callout warn">

**mimikatz — concept, not weaponized code.** <span class="badge current">CURRENT, heavily
detected</span> mimikatz is the well-known tool that reads credential material out of **LSASS memory**:
NT hashes, Kerberos tickets and keys, and (on legacy/misconfigured systems) even plaintext via the old
**WDigest** provider. *Why it can:* LSASS caches this material to provide single-sign-on, and a process
with `SeDebugPrivilege` (i.e. SYSTEM or a local admin who elevates) can open LSASS and read its memory.
That is the mechanism — **the credential material is in memory because the OS put it there for SSO,
and sufficient privilege can read any process's memory.** This course does **not** provide mimikatz
invocations or offensive tradecraft; you learn *what class of material is exposed and why*, and how
defenders stop it (below). Extraction in a lab, using standard tooling under authorization, is covered
where it belongs (M10) — always against the lab targets only.

</div>

### Current defenses you must cite honestly

<span class="badge current">CURRENT</span>

- **Credential Guard** — uses virtualization-based security to isolate LSASS secrets (NT hashes, TGTs)
  in a separate VTL, so even SYSTEM cannot read them from normal memory. Where enabled, it defeats the
  classic LSASS dump — but it does not stop everything (fresh interactive logons, machine account,
  service tickets already in use, or accounts not covered).
- **LSASS protection (RunAsPPL / PPL)** — runs LSASS as a Protected Process Light, blocking casual
  memory reads; bypassable with a driver but a real speed bump and a loud one.
- **WDigest disabled by default** (since Windows 8.1/Server 2012 R2) — removes the plaintext-in-memory
  path unless an admin re-enables it.
- **Signing everywhere** — SMB signing and LDAP signing/channel binding defeat NTLM relay; enforcing
  them is the primary relay remediation.
- **NTLM restriction / Kerberos-only** — Group Policy can audit and block NTLM; disabling NTLMv1 and
  restricting NTLM shrinks the reusable-hash and relay surface.

State these accurately in reports: "the classic dump is blocked by Credential Guard" is a very
different finding from "LSASS is wide open."

## Demonstration (LAB ONLY): tracing a logon, not attacking it

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** This lesson performs **no exploitation**. Any observation (e.g.
watching a logon's event IDs, listing your own tickets with `klist`) is done on the
`lab-05-win-privesc` VM on the isolated host-only network, as `lab\lowpriv`. Capturing or reusing
another party's credential material is an attack reserved for M06/M10/M11 against lab targets under
explicit authorization. Never do it on a real system (M00).

</div>

On the lab host you can *observe* the model without attacking. `klist` lists the Kerberos tickets your
own session holds (you will see your TGT and any service tickets you've used). `whoami /priv` shows
whether your context holds `SeImpersonate`/`SeDebug`. `nltest`/event logs show whether a logon used
NTLM or Kerberos. The exercise below asks you to *reason about* a flow, not to run an attack — the flow
analysis is the deliverable, exactly as 00.3's threat model was.

## Verification (of understanding)

You understand the model when you can answer, for a given logon: which protocol authenticated it
(NTLM vs Kerberos), what reusable artifact it produced and where that artifact lives, and what an
attacker who obtained that artifact could do *without the password*. "The service ticket for
`MSSQLSvc/db01` is encrypted with the SQL service account's key, so it's offline-crackable → weak
password = compromise of that account" is a verified understanding. "Kerberos is used" is not.

## Impact

Reusable credential material is what turns a single-host compromise into a domain compromise. A hash
or ticket harvested on one machine (after 05.3 gets you SYSTEM) authenticates to others (M11); a
Kerberoasted service-account password may be a domain admin's; a stolen TGT is that user for its
lifetime. This is *why* the AD module (M06) is the course's center of gravity, and why this primer sits
directly before it. In report terms, you frame these as **credential-exposure and reuse** findings with
concrete blast radius.

## Remediation

<div class="callout defend">

- **Kill the reusable-plaintext paths:** ensure **WDigest** stays disabled; enable **Credential
  Guard** and **LSASS protection (RunAsPPL)** on supported hosts to isolate/guard LSASS secrets.
- **Shrink NTLM:** disable **NTLMv1**, audit and restrict NTLM use, move to Kerberos-only where
  possible; this directly reduces hash-reuse and relay surface.
- **Enforce signing:** **SMB signing** and **LDAP signing + channel binding** defeat NTLM relay.
- **Harden service accounts:** use **(group) Managed Service Accounts (gMSA)** with long random
  machine-managed passwords so Kerberoasting yields nothing crackable; avoid human-set SPN passwords;
  apply least privilege so a roasted account isn't also over-privileged.
- **Protect stored secrets:** no passwords in `unattend.xml`/autologon/scripts; restrict SAM/`SECURITY`;
  understand DPAPI is only as strong as the user/machine keys protecting it.

These map to **CWE-522** and **CWE-294**; the AD-specific hardening is expanded in M06.

</div>

## Detection / blue-team view

<div class="callout defend">

- **NTLM / PtH:** logon events (**Event ID 4624**) with **LogonType 3** and NTLM auth package,
  especially for accounts that should use Kerberos, or the *same* account authenticating to many hosts
  in quick succession; **4776** (NTLM credential validation) spikes; NTLMv1 usage at all.
- **Kerberoasting:** **Event ID 4769** (service ticket requested) at high volume from one account, or
  requests using weak encryption (**RC4/`0x17`**) — a strong signal. **AS-REP roasting:** 4768 with
  pre-auth-not-required accounts.
- **LSASS access (mimikatz-class):** **Sysmon Event ID 10** (ProcessAccess) showing a non-system
  process opening `lsass.exe` with read/`PROCESS_VM_READ` rights; EDR flags LSASS handle opens.
- **Ticket anomalies:** tickets with excessive lifetimes, or TGTs used from unexpected hosts
  (pass-the-ticket / golden-ticket indicators, expanded in M06).

Mapped to **MITRE ATT&CK**: **T1550** Use Alternate Authentication Material (.002 Pass-the-Hash,
.003 Pass-the-Ticket), **T1558** Steal or Forge Kerberos Tickets (.003 Kerberoasting), **T1003**
OS Credential Dumping (.001 LSASS Memory), **T1557** Adversary-in-the-Middle (NTLM relay).

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-05-win-privesc` — the Windows VM on the isolated **host-only network with
no Internet route** (built separately; see [`labs/vm/README.md`](../../labs/vm/README.md)).
**Access:** `lab\lowpriv : Lab-Passw0rd!`. **Goal here:** *observe and reason*, not attack — inspect
your own tickets (`klist`) and privileges (`whoami /priv`), and confirm which logon types appear in the
Security log. **Time:** ~45 min. **Isolation:** verify external egress fails from inside the VM first.
No credential capture or reuse in this lesson — that is M06/M10/M11 territory, lab targets only.

</div>

Trace the two authentication flows on paper against the lab host's configuration: when your shell
reached a share via SMB, was it NTLM or Kerberos? When you requested a resource by SPN, what ticket
appeared in `klist`? Mark, on your diagram, every point where reusable material exists.

## Exercise

<div class="callout method">

**Situation.** During an authorized engagement you're given a description of a Windows logon and
service-access flow (below) — no shell yet, this is analysis. A domain user `alice` logs on to
workstation `WS01`, opens a file share on `SRV01` over SMB, and the share's app connects to
`MSSQLSvc/db01.lab.local` running as the domain account `svc_sql`. WDigest is disabled; Credential
Guard is **not** enabled; SMB signing is **not** enforced; `svc_sql` has a human-set password and an
SPN.

**Objective.** Produce an **authentication-flow analysis**: identify every place credential material is
created, cached, or transmitted, mark whether each is reusable/crackable/relayable, and name the
later-module attack that would target it — **conceptually, with no exploitation.**

**Starting information.** The description above and the flows from this lesson. This is a reasoning
exercise like 00.3's threat model — no tools, no attacks.

**Constraints.** Conceptual only. You are not capturing, cracking, or replaying anything. For each
exposure you must state the *mechanism* (why the material is reusable/crackable), not just its name.

**Expected deliverables.**
1. A flow diagram of the logon + SMB + SQL access, annotated with the protocol at each hop
   (NTLM vs Kerberos) and the credential artifact produced.
2. An exposure table: each artifact (NT hash in LSASS on WS01, NTLM response on the wire to SRV01,
   TGT, service ticket for `MSSQLSvc/db01`, `svc_sql` key), its location, whether it is
   reusable/crackable/relayable, and the mechanism.
3. For each exposure, the forward-referenced attack (PtH, relay, Kerberoasting, pass-the-ticket) **and**
   one remediation that would neutralize it — with a note on what Credential Guard / SMB signing would
   change here.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Walk the credential "reuse ladder": plaintext → NT hash → challenge/response → ticket. At each hop,
ask "if I stole exactly this artifact, could I authenticate somewhere without the password?"
</details>

<details><summary>Hint 2 — technique family</summary>
SMB with signing off → NTLM <em>relay</em>. NT hash in LSASS → <em>pass-the-hash</em>. A service
account with an SPN → <em>Kerberoasting</em> (the service ticket is encrypted with svc_sql's key). A
stolen TGT → <em>pass-the-ticket</em>.
</details>

<details><summary>Hint 3 — where to look</summary>
The SQL service ticket is the standout: any authenticated user can request it and it's encrypted with
<code>svc_sql</code>'s password-derived key. Why does "human-set password" make that dangerous, and
why doesn't Credential Guard help against it?
</details>

<details><summary>Hint 4 — specific reasoning direction</summary>
Credential Guard protects <em>LSASS-resident</em> secrets (blunts PtH from memory) but does nothing
about a service ticket the KDC hands out for Kerberoasting, nor about relay when signing is off. Map
each defense to exactly the exposure it does — and does not — cover.
</details>

## Check yourself

<div class="callout key">

1. NTLM is designed never to send the password or the hash over the network. Given that, explain in
   one sentence why **possessing the NT hash is still enough to authenticate** — and what that attack
   is called.
2. Any authenticated domain user can request a service ticket for any SPN. Why does that let an
   attacker crack a *service account's* password offline, without touching the service or having any
   privilege? Which key encrypts the ticket?
3. Distinguish a **TGT** from a **service ticket**: what does each prove, which key encrypts each, and
   what does stealing each let you do?
4. Why does `SeImpersonatePrivilege` on a service account matter for *both* local privilege escalation
   (05.3) and credential access?
5. A finding says "LSASS credentials are exposed." The host has **Credential Guard enabled** and
   **WDigest disabled**. How does that change the finding, and what material might *still* be
   obtainable?

</div>

Model answers are in `solutions/module-05.md` (instructor material — reason through them first).

## References

- **Microsoft — NTLM** (MS-NLMP): challenge/response, NTLMv1 vs NTLMv2, and the security guidance to
  restrict NTLM.
- **Microsoft — Kerberos authentication** overview and **[MS-KILE]**: AS/TGS exchanges, TGT, service
  tickets, SPNs, delegation.
- **RFC 4120** — The Kerberos Network Authentication Service (V5) — the protocol reference.
- **Microsoft — Access Tokens, Impersonation, `SeImpersonatePrivilege`, `SeDebugPrivilege`**; and
  **Credential Guard**, **Protecting LSA (RunAsPPL)**, **WDigest** deprecation.
- **Microsoft — SMB signing**, **LDAP signing and channel binding** (relay mitigations).
- **MITRE ATT&CK** — **T1550** Use Alternate Auth Material, **T1558** Steal/Forge Kerberos Tickets,
  **T1003.001** LSASS Memory, **T1557.001** LLMNR/NBT-NS & NTLM relay.
- **CWE-522** Insufficiently Protected Credentials; **CWE-294** Authentication Bypass by
  Capture-Replay.
- **Benjamin Delpy — mimikatz** (concept and defensive research; studied here for mechanism and
  detection, not weaponization).

## What you should now be able to do

- Explain what a Windows credential is at each layer and which forms are reusable, crackable, or
  relayable.
- Walk through NTLM challenge/response and Kerberos AS/TGS, and locate the exposed material in each.
- Say precisely why pass-the-hash and Kerberoasting are *possible* (mechanism, not recipe), and where
  they're covered (M10/M11, M06).
- Describe SMB/LDAP/WinRM as the services that spend credential material, and the signing controls that
  gate relay.
- Explain access tokens, impersonation, and delegation, and why `SeImpersonate`/`SeDebug` bridge to
  05.3's token abuse.
- Analyze any logon flow for where credential material is exposed, cached, or reusable — the skill M06
  is built on.

## Progress checkpoint

```bash
py course.py complete 05.2
```
