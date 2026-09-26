# 06.2 — Kerberos attacks: Kerberoasting & AS-REP roasting

<div class="prereq">

**Prerequisites:** [05.2 Windows authentication](../module-05/lesson-02.md) — you must already
understand the Kerberos **AS/TGS** exchange, the **TGT**, **service tickets**, **SPNs**, and the
KDC (this lesson turns that primer into two attacks). Also [06.1](lesson-01.md) (the graph,
enumeration, SPNs and `userAccountControl`) and [M10 preview](../module-10/lesson-01.md) for offline
cracking (referenced, not required).
**Module:** M06. **Difficulty:** 🔴 advanced.
**M06 assumes** a low-privileged domain account (`lab.local\lowpriv : Lab-Passw0rd!`) on the lab
forest — which is *all* these two attacks need.
**You will produce:** a list of roastable accounts, the extracted ticket material (in lab), a
conceptual crack plan with the correct Hashcat modes, and an assessment of what each cracked account
would unlock.

</div>

## Why this matters

Kerberoasting and AS-REP roasting are the two highest-yield, lowest-privilege attacks in the entire
AD arsenal. They require **no elevation, no exploit, and no interaction with the target service** —
only a single valid domain account, exactly the foothold M06 assumes. The KDC will hand *any*
authenticated user cryptographic material that is encrypted with a **service account's password-
derived key**, which the attacker then cracks **offline**, at their own pace, invisibly to the
target. On real engagements a service account cracked this way is very often over-privileged — a
member of Domain Admins, or local admin on dozens of hosts — turning a five-minute request into
domain compromise.

You met *why* this is possible in 05.2. This lesson makes it concrete: how to find the targets, how
the material is extracted, why offline cracking works, which encryption type matters, and — because
these attacks have unusually rich telemetry — exactly how a defender catches them.

## Learning objectives

By the end you can:

- Explain **Kerberoasting** mechanically: how requesting a TGS for an SPN yields a **TGS-REP** whose
  encrypted portion is crackable, and why any user can request it.
- Explain **AS-REP roasting**: why accounts with *pre-authentication disabled* leak a crackable
  **AS-REP**, and how it differs from Kerberoasting.
- Identify roastable accounts by hand (LDAP) and with tooling (Impacket `GetUserSPNs`, Rubeus).
- State the correct **Hashcat modes** — **13100** (TGS-REP / Kerberoast) and **18200** (AS-REP) —
  and why RC4 (`etype 23`, `0x17`) tickets crack far faster than AES.
- Assess the *impact* of a cracked account by mapping it back to the 06.1 graph.
- Write the detection story: **Event ID 4769/4768** anomalies, encryption-downgrade signals, and
  **honeypot SPN** accounts.

## Intuition

Kerberos was built so you prove yourself *once* to the KDC and then collect tickets for services.
The catch: to let a service verify your ticket without calling home, the KDC encrypts the ticket
with **that service's own key** — and that key is just the service account's password run through a
hash. So when you ask for a ticket to `MSSQLSvc/db01`, the KDC hands you a blob encrypted under
`svc_sql`'s password. You can't read it — but you don't need to. You take it away and **guess the
password offline**: for each candidate, derive the key, try to decrypt, check for a valid structure.
No lockout, no logs on the SQL server, no rate limit. The protocol's scaling trick (per-service
tickets so servers stay stateless) is exactly the crack. AS-REP roasting is the same idea one step
earlier: for accounts that skip pre-authentication, the KDC's *first* reply is already encrypted
with the user's key, so you don't even need a TGT to start.

## The underlying technology

### Kerberoasting — the TGS-REP is the loot

Recall the TGS exchange (05.2). You present your TGT and ask for a service ticket by SPN; the KDC
returns a **TGS-REP** containing the service ticket. The ticket has two encryption layers:

```text
TGS-REP for SPN MSSQLSvc/db01.lab.local:
  ├─ (outer) session key material, encrypted with YOUR TGT session key   ← you can read this
  └─ the SERVICE TICKET itself, encrypted with the SERVICE ACCOUNT'S key  ← the crack target
         key = kerberos_hash( svc_sql's password )
```

The inner service ticket is normally decrypted only by the service (which knows its own key). But
**you were given the whole blob**, and the KDC did not check whether you have any right to that
service — issuing the ticket is authentication, not authorization. So you extract the encrypted
service-ticket portion, format it as a crackable hash, and attack it offline. Because the account's
password is the only secret, a weak or human-set service-account password falls quickly.

Three facts make this devastating:

1. **Any authenticated user can request a ticket for any SPN.** No privilege needed.
2. **The target service is never touched.** You talk only to the KDC (the DC). No auth failures or
   lockouts appear on the SQL box.
3. **Service accounts are frequently over-privileged and have old, human-chosen passwords** — set
   once, years ago, never rotated, sometimes reused as a description or documented in a wiki.

### AS-REP roasting — the sibling one step earlier

Kerberos normally requires **pre-authentication**: in the AS-REQ you send a timestamp encrypted
with your key, proving you know your password *before* the KDC replies. This stops an attacker from
requesting AS-REP material for arbitrary users. But an account can have the flag
**`DONT_REQ_PREAUTH`** set (`userAccountControl` bit `0x400000`), usually for legacy compatibility.
For such an account, the KDC will return an **AS-REP** to *anyone* who asks — and part of that
AS-REP is encrypted with the **user's own password-derived key**:

```text
AS-REP for jdoe (DONT_REQ_PREAUTH set):
  └─ encrypted timestamp / session-key blob, encrypted with jdoe's key ← crack target (mode 18200)
```

So you don't even need a domain account to *start* an AS-REP roast against a named user (you need
one to *enumerate* which users have the flag). The difference from Kerberoasting: Kerberoasting
attacks **service accounts** (needs a TGT, targets SPNs, TGS-REP, mode 13100); AS-REP roasting
attacks **users with pre-auth disabled** (AS-REP, mode 18200).

### Why offline cracking works — and the encryption type that decides speed

Offline cracking works because the material's only secret is the password, and verifying a guess is
cheap and local: derive the key from the candidate password, attempt the decryption, and check for a
known plaintext structure. The **encryption type (etype)** the KDC used sets the cost:

- **RC4-HMAC (`etype 23`, shown as `0x17`)** — key is the plain **NT hash** (`MD4` of the password),
  fast to compute; billions of guesses/second on a GPU. This is the roaster's dream, and attackers
  will *request* RC4 tickets when the account supports it.
- **AES128/256 (`etype 17`/`18`)** — uses PBKDF2 with 4096 iterations and a salt; **orders of
  magnitude slower** to crack. A strong password under AES-only is effectively safe.

This is why "**force RC4**" is part of the tradecraft and, conversely, why "**AES-only + long random
password (gMSA)**" is the fix that makes the attack yield nothing.

## How a tester recognizes it

From the 06.1 enumeration: **any user object with a `servicePrincipalName`** is Kerberoastable;
**any user with `DONT_REQ_PREAUTH`** in `userAccountControl` is AS-REP-roastable. Prioritize service
accounts that the graph shows are privileged (local admin somewhere, in a sensitive group), and any
account whose SPN or `description` hints at age or manual setup.

## Manual investigation — find the targets over LDAP

```text
# Kerberoastable — user accounts that have an SPN (exclude machine accounts):
$ ldapsearch -x -H ldap://192.168.56.10 -D 'lowpriv@lab.local' -w 'Lab-Passw0rd!' \
   -b 'DC=lab,DC=local' \
   '(&(objectClass=user)(!(objectClass=computer))(servicePrincipalName=*))' \
   sAMAccountName servicePrincipalName
dn: CN=svc_sql,CN=Users,DC=lab,DC=local
sAMAccountName: svc_sql
servicePrincipalName: MSSQLSvc/db01.lab.local:1433

# AS-REP roastable — DONT_REQ_PREAUTH (0x400000) set:
$ ldapsearch ... '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' \
   sAMAccountName
dn: CN=jdoe,CN=Users,DC=lab,DC=local
sAMAccountName: jdoe
```

## Tooling — what it does, key options, limits, verify

<div class="callout method">

- **Impacket `GetUserSPNs.py`** — enumerates SPN accounts over LDAP and, with `-request`, fetches
  the TGS-REP and prints the **mode-13100 hash**. *Options:* `-request` (get tickets),
  `-request-user <name>` (one target), `-outputfile`. *Limit:* remote, needs a valid account;
  the request itself is logged (4769).
- **Impacket `GetNPUsers.py`** — the AS-REP-roast equivalent: enumerates no-pre-auth accounts and
  emits the **mode-18200 hash**. Can target a **user list** with no credentials at all.
- **Rubeus** (Windows, C#) — `kerberoast` and `asreproast` from inside a session; `/rc4opsec` and
  encryption controls; `/tgtdeleg`. *Limit:* runs on the host (AMSI/EDR surface); use only in lab.
- **Hashcat / John** — the offline cracker. **Mode 13100 = Kerberoast (TGS-REP)**, **mode 18200 =
  AS-REP**. *Verify by hand:* the hash string itself tells you the type — `$krb5tgs$23$...`
  (Kerberoast, RC4) vs `$krb5asrep$23$...` (AS-REP). The `$23$` is the etype; `$18$` would be AES.

</div>

Always **verify the target set by hand** first (the LDAP filters above): a tool listing an SPN on a
`gMSA` or a machine account is not a useful crack target, and you should not waste an engagement's
clock (or a client's logs) roasting accounts that can't yield a usable password.

## Exploitation / demonstration (LAB ONLY)

<div class="callout attack">

**Technique 1 — Kerberoasting.** With the low-priv account, request the service ticket and extract
the crackable hash:

```text
# LAB ONLY — request TGS-REP for every SPN account and print mode-13100 hashes
$ GetUserSPNs.py lab.local/lowpriv:'Lab-Passw0rd!' -dc-ip 192.168.56.10 -request
ServicePrincipalName            Name     MemberOf
------------------------------  -------  --------------------------------
MSSQLSvc/db01.lab.local:1433    svc_sql  CN=IT Support,OU=Groups,DC=lab,DC=local

$krb5tgs$23$*svc_sql$LAB.LOCAL$MSSQLSvc/db01.lab.local~1433*$a1b2c3...   (truncated)
```

The `$krb5tgs$23$` prefix confirms an **RC4 (etype 23)** ticket — the fast case. Crack it offline
(concept — full cracking workflow is M10):

```text
# LAB ONLY — offline, on the attacker box; mode 13100 = Kerberoast
$ hashcat -m 13100 svc_sql.tgs /usr/share/wordlists/rockyou.txt
$krb5tgs$23$*svc_sql$...:Lab-Passw0rd!            # recovered (lab password)
```

**Technique 2 — AS-REP roasting.** For the no-pre-auth account, no TGT is even required:

```text
# LAB ONLY — mode 18200
$ GetNPUsers.py lab.local/ -dc-ip 192.168.56.10 -usersfile users.txt -no-pass -format hashcat
$krb5asrep$23$jdoe@LAB.LOCAL:9f8e...            (truncated)
$ hashcat -m 18200 jdoe.asrep /usr/share/wordlists/rockyou.txt
```

Neither attack ever contacts `db01` or logs onto `jdoe`'s workstation — all traffic is to the KDC.
That is the whole point, and the reason the *detection* below lives on the DC.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Both techniques run against the isolated `lab-06-ad` forest, as
`lab.local\lowpriv`, cracking synthetic passwords (`Lab-Passw0rd!`) — benign by design. Requesting
Kerberos tickets for accounts in a domain you are not authorized to test, or cracking any real
credential, is unauthorized access (M00). Cracking happens offline on *your* lab box; never against
a production KDC's rate or a real user's account. Restate scope and authorization first.

</div>

## Verification

You have verified a Kerberoast when: the emitted hash begins `$krb5tgs$`, Hashcat/John returns a
plaintext for it, and that plaintext authenticates as the service account (e.g. an LDAP bind or SMB
logon as `svc_sql` succeeds). For AS-REP, the `$krb5asrep$` hash cracks and the password logs in as
the user. "I extracted a ticket" is not the finding; "I recovered `svc_sql`'s password and
authenticated as it" is. Then immediately assess *what that account can do* — the impact step.

## Impact

The impact is **whatever the cracked account is authorized for** — which is why you map it back to
the 06.1 graph. A Kerberoasted `svc_sql` that is merely a SQL service is a moderate finding; the
same account that BloodHound shows as `AdminTo` a dozen servers, or a member of Domain Admins, is a
critical, domain-wide finding. Historically, over-privileged service accounts are the norm, so
Kerberoasting frequently *is* the path to Domain Admin (06.4). AS-REP-roasted user accounts are
often forgotten legacy/service identities with the same over-privilege problem. Frame the finding by
blast radius, not by the mere fact of a cracked hash.

## Remediation

<div class="callout defend">

- **Use (group) Managed Service Accounts (gMSA/dMSA)** — the machine manages a **120-character
  random password**, rotated automatically. A gMSA ticket is uncrackable in practice; this is the
  primary fix for Kerberoasting.
- **Enforce long, random passwords** on any remaining human-managed service account (25+ chars) and
  **rotate** them; length beats everything against offline cracking.
- **Require AES, disable RC4** for accounts where possible (`msDS-SupportedEncryptionTypes`), and
  audit for RC4 usage — removes the fast-crack path.
- **Remove pre-auth exemptions:** clear `DONT_REQ_PREAUTH` wherever it's set (kills AS-REP roasting)
  and find out why it was ever enabled.
- **Least privilege on service accounts** so that even a cracked one isn't a domain compromise;
  and adopt **Protected Users** / tiering for sensitive accounts.

</div>

## Detection / blue-team view

<div class="callout defend">

These attacks are quiet on the *target* but loud on the *DC*, which sees every ticket request:

- **Kerberoasting → Event ID 4769** ("A Kerberos service ticket was requested"). Signals: a single
  account requesting tickets for **many distinct SPNs** in a short window; requests with
  **`Ticket Encryption Type 0x17` (RC4)** where the environment is otherwise AES — an
  *encryption-downgrade* red flag; requests for service accounts a user has no business using.
- **AS-REP roasting → Event ID 4768** ("A Kerberos authentication ticket (TGT) was requested")
  for accounts with pre-auth disabled, and enumeration of those accounts.
- **Honeypot SPN (a canary).** Create a decoy account with an SPN and a strong password that no
  legitimate service ever uses. **Any** 4769 for that SPN is high-fidelity evidence of Kerberoasting
  — nobody should ever request it. The same idea works for AS-REP with a decoy no-pre-auth account.
- **Defender for Identity** ships built-in detections ("**Suspected Kerberoasting**",
  "**Suspected AS-REP roasting**") keyed on these anomalies.
- Baseline first: some legitimate apps request many tickets. The high-confidence signals are
  **RC4 downgrade**, **honeypot hits**, and **volume from a single non-service principal**.

Map to **MITRE ATT&CK T1558.003** (Kerberoasting) and **T1558.004** (AS-REP Roasting).

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-06-ad` — the `lab.local` VM forest (`DC01`/`SRV01`/`WS01`) on the
host-only, no-Internet network (see [`labs/vm/README.md`](../../labs/vm/README.md)). **Access:**
`lab.local\lowpriv : Lab-Passw0rd!`. The forest is provisioned with at least one SPN service account
and one no-pre-auth account, with **synthetic** passwords present in the lab wordlist so cracking
succeeds quickly. **Time:** ~75 min. **Isolation:** verify egress fails; reset by restoring the
clean snapshot. All cracking runs offline on the attacker box.

</div>

Enumerate roastable and no-pre-auth accounts by hand, extract the material with Impacket, crack it
against the lab wordlist, and then — the real deliverable — **map each cracked account to the graph**
to state precisely what it unlocks. Watch the DC's Security log (4769/4768) as you go to see your own
footprints.

## Exercise

<div class="callout method">

**Situation.** Authorized internal test. You hold `lab.local\lowpriv` and your 06.1 graph. The
client wants to know which service and legacy accounts expose crackable credentials and what those
accounts would give an attacker.

**Objective.** Find every roastable and AS-REP-roastable account, extract the material, crack what
you can (lab wordlist), and **assess the access each cracked account grants** — a report-ready
finding per account.

**Starting information.** Your low-priv account and the 06.1 graph. No list of which accounts are
vulnerable — you enumerate them.

**Constraints.** Lab forest only; cracking offline only, against the provided lab wordlist (do not
treat this as license to crack anything real). Verify each recovered password by authenticating as
the account. Note the DC events your activity generated.

**Expected deliverables.**
1. The enumerated target set (Kerberoastable vs AS-REP-roastable), each backed by the LDAP filter
   that found it and the hash prefix (`$krb5tgs$`/`$krb5asrep$`) and etype.
2. For each cracked account: the correct Hashcat mode used, proof of authentication as that account,
   and — mapped to the graph — **what it unlocks** (groups, `AdminTo`, path relevance).
3. Per-account **remediation** (gMSA / AES-only / password length / clear pre-auth flag) and the
   **detection** a defender should have (4769 RC4-downgrade / honeypot SPN / 4768).

</div>

<details><summary>Hint 1 — conceptual direction</summary>
The attack is trivial; the <em>value</em> is in the impact assessment. A cracked account is only as
important as what it's authorized to do — return to the 06.1 graph for every hit and ask "what edges
now start from this node?"
</details>

<details><summary>Hint 2 — technique family</summary>
SPN on a user object → Kerberoast (TGS-REP, mode 13100). <code>DONT_REQ_PREAUTH</code> →
AS-REP roast (mode 18200). The <code>$..$23$..</code> in the hash tells you it's RC4 — the fast case.
</details>

<details><summary>Hint 3 — where to look</summary>
Prioritize by privilege, not by ease: a service account BloodHound shows as <code>AdminTo</code> a
server, or nested into a sensitive group, is worth cracking first. Check <code>description</code>
fields while you're in the directory.
</details>

## Check yourself

<div class="callout key">

1. Any domain user can Kerberoast, and the target service (e.g. the SQL server) never sees the
   attack. Explain *mechanically* why both are true — what key encrypts the loot, and who does the
   attacker actually talk to?
2. Why does a `$krb5tgs$23$…` ticket crack far faster than a `$krb5tgs$18$…` one? Tie your answer to
   the key-derivation difference.
3. Distinguish Kerberoasting from AS-REP roasting: which account type, which message, which
   `userAccountControl`/SPN condition, and which Hashcat mode for each?
4. A gMSA has an SPN and shows up in your Kerberoast target list. Why is cracking it a waste of time,
   and what does that tell you about the fix?
5. You want a *high-confidence* Kerberoast alert with almost no false positives. Design it — what
   object do you create, and what single event proves an attack?

</div>

Model answers are in `solutions/module-06.md`.

## References

- **Microsoft — [MS-KILE]** Kerberos Protocol Extensions; **RFC 4120** (Kerberos V5); Microsoft
  guidance on **service accounts**, **gMSA**, and **`msDS-SupportedEncryptionTypes`**.
- **Tim Medin** — "Attacking Kerberos: Kerberoasting" (the original 2014 research).
- **SpecterOps / Will Schroeder** — Kerberoasting and AS-REP roasting write-ups; **Rubeus** docs.
- **Impacket** — `GetUserSPNs.py`, `GetNPUsers.py`; **Hashcat** modes **13100** and **18200**.
- **MITRE ATT&CK** — **T1558.003** Kerberoasting, **T1558.004** AS-REP Roasting;
  **T1550** Use Alternate Authentication Material (context).
- **CWE-522** Insufficiently Protected Credentials; **CWE-916** Use of Password Hash With
  Insufficient Computational Effort (RC4/NT-hash weakness).

## What you should now be able to do

- Explain Kerberoasting and AS-REP roasting mechanically, tying each to the 05.2 Kerberos flows.
- Find roastable and no-pre-auth accounts by hand over LDAP and with Impacket/Rubeus.
- Extract the material, name the correct Hashcat mode, and explain why RC4 vs AES decides crack cost.
- Assess a cracked account's true impact by mapping it to the domain graph.
- Write the gMSA/AES/length remediation and the 4769/4768/honeypot-SPN detection for each attack.

## Progress checkpoint

```bash
py course.py complete 06.2
```
