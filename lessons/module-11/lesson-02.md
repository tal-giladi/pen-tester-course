# 11.2 — Credential-based movement: pass-the-hash, pass-the-ticket &amp; overpass-the-hash

<div class="prereq">

**Prerequisites:** [11.1](lesson-01.md) (the remote-admin channels you spend a credential on),
[05.2](../module-05/lesson-02.md) (**the core**: NT hash, NTLM challenge/response, Kerberos
TGT/TGS/SPN, and why *derived* credential material is reusable), [06.4](../module-06/lesson-04.md)
(credential harvesting as an attack-path hop), and [M10](../module-10/lesson-01.md) (where the hash
or ticket you reuse is extracted). [M00](../module-00/lesson-01.md) authorization applies throughout.
**Module:** M11 Lateral movement. **Difficulty:** 🔴 advanced.
**M11 assumes** you hold credential *material* — an NT hash or a Kerberos ticket — for an account,
without its plaintext password. This lesson is why that material alone is enough to move.
**You will produce:** using a synthetic hash/ticket captured in the lab, authentication to a second
host **without the plaintext**, written up with the protocol mechanism and the detection it produces.

</div>

## Why this matters

[11.1](lesson-01.md) assumed you had a password. Real engagements rarely do. What you actually lift
from a compromised host ([M10](../module-10/lesson-01.md), [06.4](../module-06/lesson-04.md)) is
**credential material** — an NT hash out of the SAM or LSASS, a Kerberos ticket out of memory — and
almost never a plaintext password. The pivotal fact from [05.2](../module-05/lesson-02.md) is that
**this material is itself sufficient to authenticate.** NTLM consumes the *hash*, not the password;
Kerberos accepts a *ticket*, not the password. So an attacker who holds the derived artefact can log
in as the user *without ever knowing or cracking the password* — the plaintext is simply not part of
the transaction.

This is the single most consequential idea in Windows offense, and it is why "we didn't crack any
passwords" is not a reassurance to a client. Understanding *why* pass-the-hash, pass-the-ticket, and
overpass-the-hash work mechanically — rather than memorizing tool flags — lets you recognize the
exposure, explain the blast radius, and, above all, tell the defender which of these leaves a
Kerberos-shaped footprint and which leaves an NTLM-shaped one.

## Learning objectives

By the end you can:

- Explain **pass-the-hash**: why the NTLM response is computed from the NT hash alone, so the hash is
  "password-equivalent" and can be fed to any NTLM-accepting service ([05.2](../module-05/lesson-02.md)).
- Explain **pass-the-ticket**: injecting a stolen TGT or service ticket into a logon session so
  Kerberos treats you as the ticket's owner for the ticket's lifetime.
- Explain **overpass-the-hash** ("pass-the-key"): using an NT hash (or AES key) to request a *real
  Kerberos TGT*, converting NTLM material into Kerberos access.
- Trace where the material comes from — LSASS/SAM concept from [05.2](../module-05/lesson-02.md),
  `secretsdump.py`, ticket export — and reuse it to reach a second host in the lab.
- State the **modern mitigations** (Credential Guard, Protected Users, LAPS, tiering, disabling
  NTLM) and exactly which exposure each does and does not cover.
- Give the **detection** for each technique with concrete event IDs, including the NTLM-vs-Kerberos
  and RC4-encryption tells.

## Intuition

Proving "I am Alice" to Windows never requires Alice's password directly — it requires *something
derived from it* ([05.2](../module-05/lesson-02.md)). NTLM needs the **NT hash** to compute its
response. Kerberos needs either Alice's **key** (also derived from the password, to get a TGT) or an
already-issued **ticket**. Each of these is a distinct artefact, and each is enough on its own. So if
you can obtain the artefact, you can skip the password entirely:

- Have the **NT hash**? Feed it to NTLM → **pass-the-hash**.
- Have a **ticket** (TGT or TGS)? Inject it and let Kerberos honour it → **pass-the-ticket**.
- Have the **NT hash** but want *Kerberos* access (quieter, or NTLM is blocked)? Use the hash as the
  key to ask the KDC for a real TGT → **overpass-the-hash**.

It is the confused deputy at the authentication layer once more: the artefact that was meant to
*prove* identity has become sufficient *to assume* it. The three techniques are just three artefacts
fed into the two protocols.

## The underlying technology

### Where the material comes from (recap, mechanism from M10)

You do not start with a hash or ticket; you *harvest* it after gaining SYSTEM/admin on a host:

- **NT hashes** live in the local **SAM** (local accounts) and in **LSASS memory** for every
  principal with a session on the host (domain and local), because LSASS caches them for single
  sign-on ([05.2](../module-05/lesson-02.md)). On a DC they live in **`NTDS.dit`**, extractable via
  DCSync ([06.4](../module-06/lesson-04.md)).
- **Kerberos tickets** (TGTs and service tickets) also sit in **LSASS** for logged-on users.
- **Extraction** is [M10](../module-10/lesson-01.md)'s subject. The reference tool is Impacket's
  `secretsdump.py`, which pulls SAM/LSA/`NTDS.dit` secrets; ticket export from memory is the
  Rubeus/mimikatz territory studied there as **concept**. In this lesson the material is *given* to
  you (synthetically, in the lab); the focus is what you do with it.

An NT hash is written as a 32-hex-character value; you often see it in the impacket `LM:NT` form
where LM is the empty/blank half, e.g. `aad3b435...:<32-hex-NT>`.

### Pass-the-hash (PtH) — NTLM consumes the hash <span class="badge current">CURRENT</span>

Recall the NTLM exchange from [05.2](../module-05/lesson-02.md): the server sends a challenge, and the
client returns a response computed as a function of the **NT hash** and that challenge. **The
plaintext password never enters the computation and never crosses the wire.** The unavoidable
consequence: anyone holding the NT hash can compute a valid response and complete the exchange **as
that user**. No cracking, no plaintext — the hash *is* the credential for NTLM.

Operationally, PtH means supplying the NT hash where a password would go, to any service that accepts
NTLM (SMB, WMI, WinRM, LDAP…). In the lab, NetExec and the Impacket exec scripts take the hash with
`-H`/`-hashes` instead of `-p`:

```text
# LAB ONLY — authenticate to host B with the NT hash, no plaintext:
nxc smb 10.11.0.20 -u Administrator -H <32-hex-NT-hash> --local-auth
#   -> (Pwn3d!) means the hash authenticated as a local admin of B. No password was used.
```

Requirement: NTLM must be accepted by the target service and the account must be valid/admin there.
Detection tell: an **NTLM** network logon (below) for an account, produced by a *hash*, not a
keyboard.

### Pass-the-ticket (PtT) — inject a Kerberos ticket <span class="badge current">CURRENT</span>

Kerberos does not re-verify the password on every use; it trusts **tickets** it (or a service)
previously issued ([05.2](../module-05/lesson-02.md)). A **TGT** proves the KDC authenticated you and
lets you request service tickets; a **service ticket (TGS)** is accepted by one service. So a stolen,
still-valid ticket, **injected into your current logon session**, makes Kerberos treat you as the
ticket's owner — for the ticket's lifetime, without any password or hash.

- Steal a **TGT** → request service tickets as that user for anything, until the TGT expires
  (typically ~10 hours, renewable). This is the powerful case.
- Steal a **service ticket** → use that one service as that user.

Impacket tools consume tickets from a saved **credential cache** via the `KRB5CCNAME` environment
variable (and `-k`/`-no-pass` to force Kerberos):

```text
# LAB ONLY — use an exported ticket cache instead of any secret:
export KRB5CCNAME=/tmp/svc_ops.ccache
nxc smb hostB.lab.local -u svc_ops -k --use-kcache
#   -> Kerberos authentication succeeds using the injected ticket; no password, no hash.
```

Requirement: the ticket must be valid (not expired; for a TGS, the right service) and Kerberos must
be usable (name-based, so you target the host's SPN/FQDN, not a bare IP). Detection tell: a Kerberos
logon with **no preceding AS-REQ from this host** for a forged TGT, or ticket use from an unexpected
source; for a stolen-but-legitimate ticket, the anomaly is the *source*, not the protocol.

### Overpass-the-hash (pass-the-key) — hash → Kerberos TGT <span class="badge current">CURRENT</span>

Pass-the-hash produces *NTLM* logons, which stand out in a Kerberos-first domain and are exactly what
NTLM-restriction controls flag. **Overpass-the-hash** converts the NT hash into **Kerberos** access:
because the key that encrypts the Kerberos **AS-REQ** pre-authentication is *derived from the
password* — and the NT hash (or the AES key) *is* that derived key — you can present the hash to the
**KDC** and receive a **real, legitimate TGT** for the user. From then on you are indistinguishable
from a normal Kerberos client: you hold a genuine TGT and request service tickets normally.

```text
# LAB ONLY — turn an NT hash into a real TGT, then use Kerberos:
getTGT.py -hashes :<32-hex-NT-hash> lab.local/svc_ops
#   -> writes svc_ops.ccache containing a KDC-issued TGT
export KRB5CCNAME=svc_ops.ccache
#   -> now authenticate anywhere with Kerberos (as in PtT), leaving Kerberos-shaped telemetry
```

Why it works: the NT hash is the RC4 Kerberos key (and modern accounts also have AES keys derived
from the password). Presenting the correct key to the KDC is *how Kerberos authentication is meant to
work* — you simply obtained the key without the password. The tell: an **RC4-encrypted (`0x17`) TGT
request (4768)** appearing without a corresponding interactive logon — a hash was used as a key. Using
the AES key instead avoids even the RC4 tell, which is why "downgrade to RC4" detections are only part
of the picture.

<div class="callout key">

**Three artefacts, two protocols.** PtH feeds the **hash** to **NTLM**. Overpass-the-hash feeds the
**hash** to **Kerberos** (via the KDC) to get a TGT. PtT feeds an **existing ticket** to **Kerberos**.
Choosing among them is choosing your telemetry: NTLM logons vs Kerberos ticket activity. None of them
involves the plaintext — that is the whole point, and the reason cracking is optional.

</div>

## Why the weakness exists

This is not an implementation bug; it is a **design consequence** of single sign-on and backward
compatibility ([05.2](../module-05/lesson-02.md)). NTLM had to authenticate without sending the
password, so it made the *hash* sufficient — and SSO means the hash and tickets must live in memory,
reusable. Kerberos trusts previously issued tickets so users need not re-authenticate per service —
so a stolen ticket is honoured. The weaknesses are **CWE-522** (insufficiently protected, reusable
credentials) and **CWE-294** (authentication bypass by capture-replay) as *emergent* properties, made
exploitable by the specific conditions: LSASS readable by admin/SYSTEM, NTLM still enabled, shared
local-admin hashes, over-privileged accounts with sessions everywhere.

## How a tester recognizes it

You are looking for **reusable material plus somewhere to spend it**:

- **A host where you have SYSTEM/admin** → LSASS/SAM hold hashes and tickets for everyone logged on
  there ([05.2](../module-05/lesson-02.md)).
- **A shared local-admin hash** imaged across machines → PtH opens all of them (the LAPS-shaped hole).
- **A privileged user's session** on a host you control → their ticket/hash is *there* to harvest,
  and reusing it makes you them ([06.4](../module-06/lesson-04.md)).
- **NTLM still accepted** (PtH works) vs **Kerberos-only** (you need PtT/overpass). Which controls are
  present decides which technique is viable.

## Manual investigation

```text
# Given harvested material, reason before spending it:
#  - Is the artefact a HASH (feed NTLM=PtH, or KDC=overpass) or a TICKET (feed Kerberos=PtT)?
#  - Is the ticket still valid?  klist  -> check End time / Renew time on the TGT/TGS
#  - Does the target accept NTLM, or is NTLM restricted (then PtH fails, overpass/PtT needed)?
#  - Kerberos is NAME-based: target the host's FQDN/SPN, never a bare IP, or you fall back to NTLM.
```

`klist` (Windows) or `klist`/`describe` on a ccache (Linux) shows a ticket's lifetime and encryption
type — verify validity by hand rather than discovering expiry mid-move.

## Tooling — what it does, key options, limits, verify by hand

<div class="callout method">

- **Impacket `secretsdump.py`** — the source of the material: dumps SAM/LSA secrets and (with
  replication rights) `NTDS.dit`. Output is the `LM:NT` hashes you then pass. *Limit:* requires admin
  locally or replication rights on the DC ([06.4](../module-06/lesson-04.md)); its DCSync path is
  loud (4662). *This lesson uses synthetic material; extraction is [M10](../module-10/lesson-01.md).*
- **NetExec (`nxc`)** — spends a hash or ticket across hosts/protocols: `-H <NT>` for PtH,
  `-k`/`--use-kcache` for a ticket. Confirms *where* the material is admin (`(Pwn3d!)`). *Limit:*
  every attempt is logged; scope it.
- **Impacket exec scripts** (`psexec.py`, `wmiexec.py`, `smbexec.py`) — all accept `-hashes LM:NT`
  (PtH) and `-k -no-pass` with `KRB5CCNAME` (PtT), so any [11.1](lesson-01.md) channel can be driven
  by material instead of a password. `getTGT.py` performs overpass-the-hash (hash → TGT ccache).
- **evil-winrm** — accepts `-H <NT>` to pass-the-hash into WinRM/PS-Remoting.
- **Rubeus / mimikatz** — Windows-side ticket request, export, and injection (PtT/overpass). Taught
  in this course as **concept and detection**, not as weaponized invocations
  ([05.2](../module-05/lesson-02.md)'s mimikatz callout).

</div>

**Verify by hand** at the target: after spending material, prove access with a benign result from the
target itself (its `hostname`/`whoami`, or the lab flag), and record whether the logon was NTLM or
Kerberos — that classification *is* half the finding.

## Exploitation / demonstration (LAB ONLY)

<div class="callout attack">

**Technique — reach host B with material only, no plaintext.** Given a synthetic NT hash for an
account valid on B:

```text
# Path 1 — pass-the-hash (NTLM), simplest where NTLM is accepted:
nxc smb 10.11.0.20 -u Administrator -H <32-hex-NT> --local-auth -x "hostname & whoami"
#   -> executes on B as Administrator; the logon on B is NTLM (LogonType 3). No password used.

# Path 2 — overpass-the-hash, when you prefer Kerberos telemetry (or NTLM is restricted):
getTGT.py -hashes :<32-hex-NT> lab.local/svc_ops   # hash -> real TGT
export KRB5CCNAME=svc_ops.ccache
nxc smb hostB.lab.local -u svc_ops -k --use-kcache  # Kerberos logon using the KDC-issued TGT
```

Why each works: Path 1 relies on NTLM computing its response from the hash alone — the hash is the
credential. Path 2 relies on the hash *being* the Kerberos key, so the KDC issues a genuine TGT and
everything after looks like normal Kerberos. Same starting material, deliberately different footprint
on B — Path 1 shows an NTLM logon, Path 2 shows an RC4 TGT request then Kerberos service tickets.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** The hash and ticket used here are **synthetic**, issued inside the
isolated `lab-11-lateral` scenario (and the `lab-06-ad` forest for the Kerberos paths), on a private
network with no Internet route, against the benign `LAB-FLAG-{uuid}`. Capturing or reusing anyone's
real credential material — even a hash that "still works" on an in-network host — against a system you
are not explicitly authorized to test is a serious crime ([M00](../module-00/lesson-01.md)) and a
scope violation. Reusing credential material is among the highest-impact actions in an engagement;
confirm authorization and scope for **each destination host** before you spend material on it.

</div>

## Verification

Confirm the move by evidence from the target: the command returned B's `hostname` and the expected
account from `whoami`, or produced B's flag — obtained **without any plaintext password having been
entered**. The finding must state *which artefact* you used (NT hash / TGT / TGS), *which technique*
(PtH / overpass / PtT), and *which protocol* the target logged (NTLM vs Kerberos), because those
determine both impact and detection. "We authenticated without the password" plus the target's own
output is the proof.

## Impact

Credential-material reuse is what makes a single SYSTEM compromise metastasize. A local-admin hash
shared across a fleet turns one host into all of them via PtH. A harvested TGT *is* that user for its
lifetime, anywhere in the domain (PtT). Overpass-the-hash launders a hash into first-class Kerberos
access that evades NTLM-focused controls. Because none of this needs the plaintext, password
complexity and cracking difficulty are irrelevant — the classic reason strong-password policies do
not stop lateral movement. Combined with harvesting a privileged session ([06.4](../module-06/lesson-04.md)),
this is the mechanism that reaches Domain Admin. Frame the finding as **reusable-credential blast
radius**, and note explicitly that no passwords were cracked — that is the alarming part.

## Remediation

<div class="callout defend">

- **Protect the material at rest in memory:** **Credential Guard** (VBS-isolated LSASS secrets) and
  **LSASS protection (RunAsPPL)** stop the classic harvest of hashes/TGTs from LSASS — no material,
  no reuse. *Limit honestly:* Credential Guard does not protect local SAM accounts, cannot help once
  a ticket is already exported, and does not cover every logon type.
- **Protected Users group:** members cannot use NTLM, cannot use RC4/DES Kerberos, and get no
  long-lived cached credentials — directly blunting PtH and RC4 overpass for sensitive accounts.
- **Windows LAPS:** unique, rotated local-admin password (and therefore a unique *hash*) per machine
  — a hash lifted from A no longer opens B. The single most effective control against local-admin
  PtH.
- **Tiering / Enterprise Access Model** ([06.4](../module-06/lesson-04.md)): keep privileged
  credentials off lower-tier hosts so their material is never harvestable there; this deletes the
  harvest-then-reuse hop most paths rely on.
- **Disable/restrict NTLM** and disable NTLMv1: shrinks or removes the PtH surface and forces
  attackers toward noisier Kerberos techniques; audit NTLM use first, then restrict.
- **Kerberos hygiene:** enforce **AES** (deprecate RC4) so overpass/forged-RC4 tickets stand out;
  keep TGT lifetimes sane; rotate **`krbtgt`** on schedule (limits forged-ticket persistence,
  [06.4](../module-06/lesson-04.md)).

Map to **CWE-522** and **CWE-294**; note that these controls *layer* — none is complete alone, and a
report should say which exposure each one leaves standing.

</div>

## Detection / blue-team view

<div class="callout defend">

- **Pass-the-hash (NTLM):** **Event ID 4624 LogonType 3** with authentication package **NTLM** for an
  account — especially one that normally uses Kerberos, or the *same* account authenticating to many
  hosts rapidly; **4776** (NTLM credential validation, logged on the DC/authenticating host) spikes.
  A local account (e.g. `Administrator`) doing network logons across many machines is the shared-hash
  signature.
- **Overpass-the-hash:** **4768** (TGT requested) using **RC4 / `0x17`** encryption with **no
  preceding interactive logon (4624 type 2)** for that account — a hash was used as a key rather than
  a keyboard password. AES-key overpass avoids the RC4 tell, so also baseline *which hosts* request
  TGTs for which accounts.
- **Pass-the-ticket:** ticket use from an **unexpected source host**; for forged/injected TGTs,
  **4769** (service ticket requested) with **no matching 4768** on any DC (the TGT wasn't issued
  here); anomalous ticket lifetimes. For a stolen-but-legitimate ticket the protocol looks normal —
  the anomaly is the source and timing.
- **Harvest precursor:** **Sysmon Event ID 10 (ProcessAccess)** showing a non-system process opening
  `lsass.exe` with read rights; EDR LSASS-handle alerts ([05.2](../module-05/lesson-02.md)).
- **Correlation is the real detector:** one identity, many hosts, short window; NTLM where Kerberos is
  expected; a TGT request with no logon behind it. **Microsoft Defender for Identity** ships
  built-in "Suspected identity theft (pass-the-hash / pass-the-ticket)" and "Suspected
  overpass-the-hash" detections built on exactly these signals.

Map to **MITRE ATT&CK T1550** Use Alternate Authentication Material — **.002 Pass-the-Hash**,
**.003 Pass-the-Ticket** (overpass-the-hash is covered under .002/.003 and T1558) — with **T1558**
Steal or Forge Kerberos Tickets and **T1003** OS Credential Dumping for the harvest step. The
recurring idea: *you cannot easily stop a valid credential from being valid, so you detect its
reuse pattern and protect the material so it is never harvested.*

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-11-lateral` (built separately) — the **two-host credential-reuse
scenario** on an **isolated private network with no Internet route**; the **`lab-06-ad`** VM forest is
used for the Kerberos (PtT/overpass) paths. **Access:** a foothold on host A from which a **synthetic**
NT hash and/or Kerberos ticket for an account valid on host B is available (provided by the scenario —
extraction mechanics are [M10](../module-10/lesson-01.md)). **Targets:** host B / a forest host only;
the `LAB-FLAG-{uuid}` is retrievable after you authenticate there **without the plaintext**. **Time:**
~90 min. **Isolation:** verify egress fails first; reset per the lab README between attempts. The
scenario provides both a hash and a ticket so you can practise PtH, overpass, and PtT and contrast
their telemetry.

</div>

Take the provided synthetic material, decide whether it is a hash or a ticket, spend it to reach host
B **without the password** by the fitting technique, verify with the flag, and record whether the
logon on B was NTLM or Kerberos and the event IDs it produced. For practice, obtain a TGT via
overpass-the-hash from the same NT hash and repeat over Kerberos, comparing the footprints.

## Exercise

<div class="callout method">

**Situation.** Authorized internal engagement. You have SYSTEM on host A and, from it, a **synthetic**
credential artefact for an account that is also valid on host B (the objective, holding the flag). You
do **not** have the plaintext password and are not permitted to spend time cracking it.

**Objective.** Authenticate to host B and retrieve the flag **without the plaintext**, using the
technique that matches your artefact, and explain the protocol and detection.

**Starting information.** The artefact (a hash or a ticket — determine which) and network access to B.
No password.

**Constraints.** Lab targets only; confirm B is in scope before authenticating. You must reach B
without the plaintext. State the mechanism (why the artefact alone authenticates), not just the
command. Note any validity limit (ticket lifetime) and any artefact left behind.

**Expected deliverables.**
1. **Artefact identification** (hash vs TGT vs TGS) and the **technique** chosen (PtH / overpass / PtT)
   with a one-line justification tied to what the target accepts (NTLM vs Kerberos).
2. The **mechanism**: *why* the artefact authenticates without the password — reference NTLM
   consuming the hash, or the hash being the Kerberos key, or Kerberos honouring an issued ticket.
3. **Verification** from B itself (hostname/whoami/flag), plus the **protocol the logon used** on B.
4. **Remediation** (Credential Guard / Protected Users / LAPS / NTLM restriction / tiering as they
   apply) **and** **detection** (the exact event IDs — 4624/4776 for PtH, 4768 RC4 for overpass,
   4769-without-4768 for a forged ticket — mapped to ATT&CK T1550). Both required.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
The password is not part of the transaction. Ask which <em>artefact</em> you hold and which protocol
it feeds: a hash feeds NTLM (PtH) or, via the KDC, Kerberos (overpass); a ticket feeds Kerberos (PtT).
</details>

<details><summary>Hint 2 — technique family</summary>
If NTLM is accepted, PtH (<code>-H</code>) is the shortest route. If you want Kerberos telemetry or
NTLM is restricted, convert the hash to a TGT (overpass, <code>getTGT.py</code>) or inject a ticket
(PtT, <code>KRB5CCNAME</code> + <code>-k</code>). Kerberos is name-based — use B's FQDN, not its IP.
</details>

<details><summary>Hint 3 — where to look</summary>
Check the artefact first: 32 hex chars = an NT hash; a <code>.ccache</code>/<code>klist</code> entry =
a ticket (check its expiry). Then match to a [11.1](lesson-01.md) channel B exposes, and confirm with
a benign command rather than a payload.
</details>

<details><summary>Hint 4 — the deliverable</summary>
The finding is "authenticated as X on B with no password, via &lt;technique&gt;, logged as
&lt;NTLM|Kerberos&gt;." Lead remediation with the control that stops the <em>harvest</em> (Credential
Guard/LAPS/tiering), since you cannot stop a valid credential from being valid — you detect its reuse.
</details>

## Check yourself

<div class="callout key">

1. NTLM is designed never to send the password or the hash on the wire. Given that, why is possessing
   the NT hash still enough to authenticate, and what is that attack called?
2. Distinguish **pass-the-hash** from **overpass-the-hash**: same starting artefact — what is different
   about what you feed it to, and how does the resulting *telemetry* differ?
3. Why does **pass-the-ticket** need no password *and* no hash? What must be true of the ticket for it
   to work, and why must you target a name rather than a bare IP?
4. **Credential Guard is enabled** on the host you compromised. Which of PtH / overpass / PtT does that
   most affect, and what material might *still* be reusable?
5. A defender sees **4768 with RC4 encryption and no preceding interactive logon** for a service
   account. Which technique does this most likely indicate, and how could an attacker have avoided the
   RC4 tell?

</div>

Model answers are in `solutions/module-11.md` (reason through them first).

## References

- **Microsoft** — *NTLM* (**[MS-NLMP]**): the challenge/response is computed from the NT hash;
  *Kerberos* (**[MS-KILE]**, **RFC 4120**): TGT/TGS, pre-authentication keys, ticket lifetimes;
  **Credential Guard**; **Protected Users** security group; *Protecting LSA (RunAsPPL)*; **Windows
  LAPS**; *Restrict NTLM* Group Policy; **[MS-DRSR]** (DCSync source of hashes).
- **Impacket** — `secretsdump.py`, `getTGT.py`/`getST.py`, and the `-hashes`/`-k` options across
  `psexec.py`/`wmiexec.py`/`smbexec.py`.
- **NetExec (`nxc`)** — `-H` (pass-the-hash), `-k`/`--use-kcache` (pass-the-ticket) usage.
- **Benjamin Delpy — mimikatz** and **Rubeus** (pass-the-hash/ticket and overpass concepts and
  *defensive* research — studied here for mechanism and detection, not weaponization).
- **MITRE ATT&CK** — **T1550.002** Pass-the-Hash, **T1550.003** Pass-the-Ticket, **T1558** Steal or
  Forge Kerberos Tickets, **T1003.001** LSASS Memory, **T1078.002** Valid Domain Accounts.
- **CWE-522** Insufficiently Protected Credentials; **CWE-294** Authentication Bypass by
  Capture-Replay.

## What you should now be able to do

- Explain why credential *material* — NT hash or Kerberos ticket — authenticates without the plaintext,
  and where it comes from.
- Perform pass-the-hash, overpass-the-hash, and pass-the-ticket in the lab, and choose among them by
  the protocol and telemetry each produces.
- State which modern control (Credential Guard, Protected Users, LAPS, tiering, NTLM restriction)
  covers which exposure, and which gaps remain.
- Write the ATT&CK-mapped detection for each technique, including the NTLM-vs-Kerberos and RC4 tells.

## Progress checkpoint

```bash
py course.py complete 11.2
```
