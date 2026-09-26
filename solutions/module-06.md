# Instructor / solutions — Module 06 (Active Directory)

> Instructor material. Not linked from `_sidebar.md.` Do the exercises before reading.

Module 06 assumes a low-privileged domain account (`lab.local\lowpriv : Lab-Passw0rd!`) on the
`lab-06-ad` VM forest (`DC01` .10 / `SRV01` .20 / `WS01` .30 on the isolated host-only
`192.168.56.0/24`, no Internet route; see `labs/vm/README.md`). All work is against that lab forest
only. Offensive DCSync/ticket-forging content is taught as **mechanism + detection**; there are no
weaponized recipes to hand out, and graders should reward *mechanistic understanding and detection*,
not tool fluency.

**Scenario C rule (06.4).** The intended path from low-priv to Domain Admin is **never** given to
the student, and the concrete lab path depends on the provisioning scripts in
`labs/lab-06-ad/provision/`. Grade the *method and evidence*, not whether the student found the one
route the instructor had in mind. The illustrative chain in 06.4 is one possibility, not "the
answer."

---

## 06.1 — AD as a graph (enumeration → graph + HVT list)

**Exercise grading.** A strong submission (a) builds the graph from *its own* LDAP/RID data first,
(b) cross-checks against a BloodHound collection and notes discrepancies (edges the tool added or
missed, stale sessions), and (c) ranks HVTs by *blast radius* with each claim tied to a concrete
query. Look for: Domain Admins/Enterprise Admins/Administrators membership resolved directly; nested
groups expanded; SPN accounts and `DONT_REQ_PREAUTH` accounts noted as future targets; at least one
control edge spotted from a raw DACL read. Reject "BloodHound said so" without a backing query.

Illustrative HVT reasoning table:

| Principal | Why high value | Evidence (query) |
|---|---|---|
| `Domain Admins` members | full domain control | `(memberOf=CN=Domain Admins,CN=Users,DC=lab,DC=local)` |
| `svc_sql` (SPN) | Kerberoastable; check its group edges | `(&(objectClass=user)(servicePrincipalName=*))` |
| a group `lowpriv` is in with `GenericAll` over another user | control edge "uphill" | raw `nTSecurityDescriptor` ACE naming the group SID |
| `DC01$` / any unconstrained-delegation host | TGT harvest → identity theft | `userAccountControl:...:=524288` |

**Check-yourself.** (1) The **forest** is the security boundary because all domains in it trust the
shared schema/config and Enterprise Admins/trust keys span it; compromising one domain (esp. via the
schema, EA, or a trust key) can be leveraged forest-wide, so "we only own one child domain" is not
containment. (2) Any three of: `memberOf` → group/privilege mapping and nesting; `servicePrincipalName`
→ Kerberoasting; `userAccountControl` flags → AS-REP roast (no-preauth) or delegation abuse
(trusted-for-delegation); `adminCount=1` → find protected/admin accounts; `description`/`info` →
plaintext secrets; `nTSecurityDescriptor` → control edges. (3) `HasSession` is **point-in-time** —
the DA may have logged off since collection; confirm at execution time with a fresh session
enumeration (and remember collection itself is noisy), and treat it as a lead until re-checked.
(4) An attack path is a chain of directed edges from an Owned node to a target node; three individually
reasonable grants (`MemberOf` → `GenericAll` → `MemberOf`) compose transitively into a route nobody
designed. (5) `(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))` — the OID
`1.2.840.113556.1.4.803` is the **LDAP bitwise-AND matching rule**, testing whether the
`DONT_REQ_PREAUTH` bit (`0x400000` = 4194304) is set inside `userAccountControl`.

---

## 06.2 — Kerberoasting & AS-REP roasting

**Exercise grading.** The attack is easy; the deliverable's value is the **impact assessment**. Grade
for: correct target enumeration by hand (the two LDAP filters), correct Hashcat mode per artifact
(**13100** TGS-REP, **18200** AS-REP), the etype read from the hash prefix (`$23$` = RC4, fast),
authentication as each cracked account (proof, not just a plaintext), and — critically — **mapping
each cracked account back to the 06.1 graph** to state what it unlocks. Full marks require per-account
remediation (gMSA / AES-only / length / clear pre-auth) *and* detection (4769 RC4-downgrade / honeypot
SPN / 4768).

**Check-yourself.** (1) Any user can Kerberoast because requesting a TGS is *authentication, not
authorization* — the KDC issues a ticket for any SPN to any TGT holder; the service is never touched
because the loot is the **service-ticket blob encrypted with the service account's key**, obtained
from the **KDC (DC)**, not the service. (2) `$23$` (RC4-HMAC) uses the plain **NT hash** (single MD4)
as the key — billions of guesses/sec on GPU; `$18$` (AES256) derives the key via **PBKDF2, 4096
iterations + salt**, orders of magnitude slower, so a strong password under AES is effectively safe.
(3) Kerberoasting: **service account**, needs a **TGT**, targets **SPNs**, loot is **TGS-REP**, mode
**13100**. AS-REP roasting: **user with `DONT_REQ_PREAUTH`**, needs **no TGT**, loot is **AS-REP**,
mode **18200**. (4) A gMSA has a machine-managed **~120-char random** password; cracking is infeasible,
so the SPN is a non-target — and this *is* the fix (move human service accounts to gMSA). (5) Create a
**honeypot account with an SPN**, a strong password, and no real service using it; enable 4769
auditing — **any** 4769 for that SPN is a near-zero-false-positive Kerberoast alert (an RC4 request
for it is even stronger).

---

## 06.3 — ACL, delegation & GPO abuse

**Exercise grading.** A strong finding names the **exact ACE/attribute** from a raw DACL/LDAP read
(not a BloodHound screenshot), justifies the *choice of primitive* (reversible/targeted-Kerberoast or
member-add preferred over a destructive password reset), verifies control (auth as target /
impersonation ticket / new membership) with before/after evidence, and gives both remediation and
event-ID-level detection. For a delegation edge, expect the single written attribute
(`msDS-AllowedToActOnBehalfOfOtherIdentity` for RBCD) and the S4U step, plus `MachineAccountQuota`
context.

**Check-yourself.** (1) With `GenericAll` you can (a) **ForceChangePassword** — reset it, become it
(destructive: may break the service; visible via 4724) — or (b) **write an SPN → targeted Kerberoast
→ crack offline → remove the SPN** (reversible; doesn't change the account's password; only 4662/5136
on the SPN write plus a 4769). The Kerberoast route is stealthier and reversible. (2) RBCD needs write
to one attribute on the **target computer**: **`msDS-AllowedToActOnBehalfOfOtherIdentity`**, set to a
principal you control; the **S4U2Self/S4U2Proxy** exchange then lets you request a service ticket to
that computer **as any user** (e.g. Administrator) → e.g. `cifs`/`host` → SYSTEM. (3) An
unconstrained-delegation server caches the **TGT of every account that authenticates to it**; compromise
the server (or coerce a privileged account/DC machine account to authenticate to it, e.g. via an
auth-forcing/coercion technique) and you harvest their TGTs → become them. (4) A GPO applies to
**every object in the OUs/domain/sites it is linked to**; GPO write = code execution (scheduled task /
startup script as SYSTEM) or local-admin addition across all linked machines — potentially the whole
domain, vs. one admin. (5) **Event ID 5136** (object modified; DACL write) — with 4662 for the access;
high-signal attribute-writes to alert on: **`member`** of privileged groups (4728/4732/4756),
**`servicePrincipalName`** (targeted-Kerberoast tell), and **`msDS-AllowedToActOnBehalfOfOtherIdentity`**
(RBCD tell).

---

## 06.4 — Domain privesc & attack-path analysis (Scenario C)

**Do not disclose the intended path to students.** Grade the **method and evidence**, per the
Scenario C rule above.

**Exercise grading.** A full-mark submission is an **attack narrative** where every hop is
*starting state → edge/mechanism → action → verification → new state*, with the command and its
output/screenshot per hop; it justifies the chosen path over alternatives (reliability × noise ×
reversibility), shows the **re-collected graph** after each compromise (new edges revealed), and its
remediation identifies the **single cheapest choke-point edge** whose removal breaks the path — not
just "rebuild AD." The detection section must map each hop to its event ID(s) and ATT&CK technique.
Common shortfalls to mark down: claiming DA without per-hop evidence; taking BloodHound edges without
verification; treating stale `HasSession` as fact; leading remediation with "rotate krbtgt/rebuild"
instead of the choke point; performing (rather than describing) Golden/Silver forging.

The illustrative chain in the lesson (`lowpriv → IT Support → GenericAll svc_backup → AdminTo SRV01
→ harvest DA session → DCSync krbtgt`) is **one** shape. Accept any verified, evidence-backed route
to a Tier-0 principal / DC SYSTEM / domain-object replication rights / `krbtgt`.

**Check-yourself.** (1) `WriteDACL`/`AllExtendedRights` on the **domain object** lets you add an ACE
granting yourself the replication rights **`DS-Replication-Get-Changes` + `-All`**, i.e. **DCSync** —
you then pull `krbtgt` and every hash: domain compromise from a single ACE. (2) DCSync uses the two
replication extended rights over the **DRSUAPI** (`IDL_DRSGetNCChanges`) protocol; a rights-holder
*impersonates a DC* and the real DC **replicates** the secrets back — **no code runs on the DC and
`NTDS.dit` is never touched on disk**. High-fidelity alert: **Event ID 4662** on the domain object
with the replication GUIDs from a **non-DC** principal. (3) **Golden** = forged **TGT** using the
**`krbtgt` key**, valid for any user until `krbtgt` is rotated twice (persistence). **Silver** =
forged **service ticket** using a **service/computer account key**, for that one service; it produces
**no 4769** because it **bypasses the KDC** — the service validates the ticket with its own key.
(4) `HasSession` exists because a privileged account's credential material is cached on a lower-tier
host; **tiered administration** forbids Tier-0 logons on Tier-1/2 machines, so the material is never
there — deleting the edge. It's often the cheapest fix because many chains route through that single
harvest hop. (5) Lead with the **choke-point edge** most paths traverse and whose removal is cheap and
low-risk (e.g. remove one `GenericAll`, or stop a DA logging onto SRV01) — clients can *act* on
"remove this grant." `krbtgt` rotation/forest recovery is remediation-of-last-resort and is disruptive;
it treats the symptom (a stolen key) rather than the structural cause (the path).

---

## Notes for instructors

- Reinforce the graph-reasoning mindset over tool output at every step: the deliverable is a
  *verified, defended path*, not a BloodHound screenshot.
- Every technique in M06 pairs an attack with **remediation and a specific detection** (event IDs
  4662/4724/4728/4741/4768/4769/5136, honeypots, Defender for Identity). A finding lacking the
  blue-team half is incomplete — mark accordingly.
- Modern defenses to credit when students cite them: **gMSA/AES-only** (kills Kerberoasting yield),
  **Protected Users / "cannot be delegated"** and `MachineAccountQuota=0` (delegation), **tiering/PAW
  and Credential Guard/RunAsPPL/LAPS** (credential reuse), **`krbtgt` double-rotation** (Golden
  Ticket), and **replication-rights auditing** (DCSync).
- Reset the forest via the clean snapshot between attempts — harvesting, RBCD writes, added computer
  accounts, and DCSync leave persistent state.
