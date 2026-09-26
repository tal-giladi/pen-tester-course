# 10.1 — Password attacks done responsibly: spraying vs brute force vs stuffing, and online vs offline

<div class="prereq">

**Prerequisites:** [M00](../module-00/lesson-01.md) (authorization, RoE, the stop/notify reflex) and
[00.3](../module-00/lesson-03.md) (trust boundaries — authentication is one). [M03](../module-03/lesson-01.md)
(enumeration — where usernames and services come from). [M05](../module-05/lesson-02.md) (NTLM/Kerberos
primer — what a Windows credential *is*) and [M06](../module-06/lesson-01.md) (AD, the directory that
holds the users you'll spray).
**Module:** M10 Credential attacks. **Difficulty:** 🟡 intermediate.
**M10 assumes** you can enumerate an environment (M03) and understand Windows/AD authentication
(M05/M06). This first lesson is about **choosing the right attack and not doing harm**; 10.2 is the
offline-cracking craft.
**You will produce:** a written, defensible **password-spray plan** for a described lab environment
that respects a stated lockout policy, justifies every choice, and predicts its own detection footprint.

</div>

## Why this matters

Guessing passwords is the most **operationally dangerous** thing a tester does that isn't an exploit.
A single careless script can lock out hundreds of real employees, page an on-call team at 3 a.m., and
turn a quiet engagement into an incident — all without gaining a single credential. The difference
between a professional and a liability here is not tooling; it is knowing **which** of three very
different attacks fits the situation, whether it belongs **online** (touching a live auth system) or
**offline** (against captured material), and how to run it without collateral damage. This lesson
teaches that judgment. It is the ethics-and-methodology half of M10; 10.2 is the mechanics of cracking
what you capture.

Password attacks also sit on the highest-value trust boundary there is — *authentication* (00.3). A
weak password is not an exotic bug; it is, year after year, one of the most common root causes of real
breaches. Your job is to demonstrate that exposure to the client **without becoming the incident**.

## Learning objectives

By the end you can:

- Distinguish **password spraying**, **brute force**, and **credential stuffing** by mechanism, and
  say when each is appropriate, ethical, or forbidden.
- Explain the **online vs offline** split and why offline is preferred whenever it's available.
- Compute a **lockout-safe spray schedule** from a stated account-lockout policy, with margin for real
  users.
- Explain where a **valid username list** legitimately comes from in an authorized engagement.
- Run a responsible spray against a lab target and **verify** a hit without escalating harm.
- Describe the detection signal each attack leaves (4625/4771 spikes, impossible travel, lockout
  storms) and design a test that a defender *should* catch.

## Intuition

Every password attack answers one question — *"is this the right secret?"* — by asking an authority
that knows the answer. The three attacks differ only in **what you vary and against whom**, and that
difference decides whether you cause harm:

- **Brute force:** *many passwords, one account.* You hammer one user with guess after guess. This is
  exactly what account lockout was invented to stop, so against a modern system it mostly just **locks
  the victim out** and screams in the logs. Rarely the right online choice.
- **Spraying:** *one password, many accounts.* You try a single plausible password (say `Autumn2026!`)
  across the whole user population, then wait, then try a second. Each account sees only **one** bad
  attempt per round, so you stay under the lockout threshold — and organisations are big enough that
  *someone* almost always used the seasonal password. This is the responsible online default.
- **Credential stuffing:** *known username+password pairs, from someone else's breach.* You replay
  leaked credentials hoping a user reused them. It's cheap and effective because people reuse passwords
  — but it drags real third-party breach data into your work and raises sharp legal and privacy
  questions.

Hold that table in your head: **what varies, against whom, and what it costs the target.** Everything
else in this lesson elaborates it.

## The underlying technology

### Online vs offline — the split that governs everything

An **online** attack sends each guess to a **live authentication service** — an SMB/LDAP/Kerberos
endpoint, an RDP or SSH daemon, a web login form, an API token endpoint. The service is the oracle. This
means:

- Every guess is **rate-limited, logged, and lockout-gated** by that service. You are loud and slow.
- You touch a **production dependency**. Lock out a service account and you may break an application,
  not just a person.

An **offline** attack takes **captured hashed material** — an NTLM hash from the SAM/NTDS.dit, an
NTLMv2 response sniffed on the wire, a Kerberos service ticket (Kerberoasting, M06), a `/etc/shadow`
entry, a leaked database dump *from the client's own systems* — and guesses against **your own copy**
at the speed of your hardware, with **no lockout, no logging on the target, and no rate limit**. That
is why offline is almost always preferable *when the material is obtainable*:

<div class="callout method">

**Prefer offline whenever you already hold, or can lawfully obtain, the hashed material.** Online
guessing risks lockouts and alerts for a few guesses per minute; offline cracking risks nothing on the
target and runs at millions to billions of guesses per second (10.2). The online attack's real job is
often just to **obtain one credential or one hash** — after which the work moves offline. Online is a
means, not the destination.

</div>

The catch: offline needs the material first. You usually get online → foothold → dump hashes → offline.
So both matter, and knowing which phase you're in tells you which risk profile applies.

### The three online attacks in detail

**Brute force** (T1110.001 / .002) varies the password against a fixed account. Online, it is the
lockout trigger by design and should be reserved for services **with no lockout** (some SSH configs,
some APIs) or where the RoE explicitly permits it against a designated test account. Offline it's fine —
"brute force" against a captured hash is just 10.2's masks.

**Password spraying** (T1110.003) varies the *account* while holding the password fixed for a round.
Because each account receives only one attempt per round, spraying is the online attack that a
competent tester actually runs against a real directory. Its effectiveness comes from population size
and predictable human passwords: in a 500-person company, the odds that *nobody* used the company name,
a season, or `Welcome1` are slim.

**Credential stuffing** (T1110.004) uses real `email:password` pairs harvested from unrelated breaches,
betting on reuse. It powers a huge share of real-world account takeover. In an engagement it is
sometimes in scope — e.g. testing whether employees reused corporate passwords on breached third-party
sites — but it comes with heavy conditions (below), because you are now handling **real people's
breached credentials**.

## Why the weakness exists

The attackable surface is created by two enduring facts. First, **humans choose predictable secrets**:
a password that must be "8+ characters with a capital, a number and a symbol, changed every 90 days"
reliably produces `Summer2026!` → `Autumn2026!`. Modern guidance (**NIST SP 800-63B**) actually
*recommends against* forced periodic rotation and complexity theatre precisely because they push users
toward guessable patterns — but most environments you'll test still enforce the old rules. Second,
**people reuse passwords** across sites, which is what makes stuffing work. The underlying weaknesses
are **CWE-521 (weak password requirements)** and **CWE-262/263-style** rotation mistakes, with
**CWE-307 (improper restriction of excessive authentication attempts)** on the defender's side deciding
whether your online guessing is even possible. None of this is a software bug; it is the human layer of
the trust boundary.

## How a tester recognizes it — and where usernames come from

You can only spray a **valid username list**, and building one in an authorized engagement is itself a
skill. Legitimate sources, all inside scope:

- **Provided by the client** — grey-box engagements often hand you an employee list or a test OU.
- **Directory enumeration** (M06) — authenticated or, in weak configs, unauthenticated LDAP; RID
  cycling over SMB; `enum4linux-ng`; NetExec `--users`. This is the richest source in an AD engagement.
- **Kerberos user enumeration** — the KDC responds differently to a request for a *valid* vs *invalid*
  principal (AS-REQ pre-auth), so a tool like **kerbrute** can validate usernames **without a single
  login attempt** and therefore **without incrementing any lockout counter** — a key OPSEC and safety
  property you'll use below.
- **OSINT** (M02) — email/username conventions from the corporate site, LinkedIn, breach-notification
  metadata, and certificate/whois data, mapped to the org's format (`first.last`, `flast`, `f.last`).

<div class="callout warn">

**Username enumeration is still touching their systems.** Even "just" validating usernames via Kerberos
or a login form's error-message difference is interaction with a live service, in scope, logged.
Kerbrute-style validation avoids *lockout* (no bad password is submitted) but is not invisible — 4768
events still appear. Confirm it's permitted, and prefer it precisely *because* it doesn't lock anyone
out.

</div>

## Manual investigation — before you spray anything

Do this reasoning **on paper** first; it is the difference between a plan and a lockout storm:

1. **Find the lockout policy.** In AD: the Default Domain Policy / fine-grained password policies give
   *lockout threshold*, *observation (reset) window*, and *lockout duration*. Read them with
   `net accounts`, `Get-ADDefaultDomainPasswordPolicy`, or NetExec's `--pass-pol`. On a web app, infer
   it from behaviour (does the 6th attempt lock you?) **carefully**, using a throwaway test account you
   own, never a real user.
2. **Do the lockout math** (next section). Decide attempts-per-account-per-window and the inter-round
   delay.
3. **Choose passwords by relevance, not size.** A spray is 3–5 *well-chosen* guesses (season+year,
   company name, `Welcome1`, `Password1`), not a dictionary. A dictionary belongs offline.
4. **Leave headroom for real users.** Employees generate their own failed logins. If the threshold is
   5, do not consume 4 — a user's two morning typos would then lock them because of you.

### The lockout math

Given a policy of **threshold T** bad attempts within an **observation window W**, after which an
account locks:

- Spraying puts **1** bad attempt on each account per round.
- To be safe, keep bad attempts per account **strictly below T within any window W**, and leave a
  margin M for the real user: `attempts_per_account_per_W ≤ T − 1 − M`. With `M = 1` you use at most
  `T − 2`.
- Because a spray round adds exactly 1, you can run at most `T − 2` rounds inside one window, then must
  **wait out the window** before the counter resets.

**Worked example.** Policy: `T = 5`, `W = 30 min`, lockout duration 30 min. Then `T − 2 = 3` rounds are
safe per 30-minute window, but the conservative professional default is **1 attempt per account per
window** — try one password, wait `W + a small buffer` (say **35 min**), try the next. Five candidate
passwords → ~5 rounds → about **2h55m** end to end. Slower, yes; but you will not lock out a single
real user, and *that* is the deliverable. If the policy is `T = 3` (aggressive), the only safe online
choice may be **one** carefully chosen password total, or Kerberos pre-auth validation with no password
at all.

<div class="callout key">

**The spray rule of thumb:** one password, wait longer than the observation window, next password. Never
let your attempts plus a real user's normal typos reach the lockout threshold. When in doubt, one guess
per account per window, and confirm the policy first.

</div>

## Tooling — what it does, key options, limits, verify by hand

- **NetExec (`nxc`)** <span class="badge current">CURRENT</span> — the CrackMapExec successor for
  SMB/LDAP/WinRM/RDP. `nxc smb <dc> -u users.txt -p 'Autumn2026!' --continue-on-success` sprays one
  password across a user file; `--pass-pol` reads the lockout policy first. **Limit:** it will happily
  lock everyone out if you feed it a *password* list per user — you must drive the schedule yourself; it
  is not lockout-aware. Verify a hit by authenticating once, manually, with the found pair.
- **kerbrute** — `kerbrute userenum` validates usernames via Kerberos pre-auth **without submitting
  passwords** (no lockout impact); `kerbrute passwordspray` sprays a single password over a user list.
  **Limit:** AD/Kerberos only; still generates 4768 events. Its value is username validation that
  doesn't touch the lockout counter.
- **hydra** <span class="badge current">CURRENT</span> — generic online login tester for many protocols
  (SSH, FTP, HTTP forms, RDP). Powerful and **dangerous**: `-t` threads and password lists make it a
  brute-forcer by default. Use `-p` (single password) not `-P` (list) for spraying, and low `-t`.
  **Limit:** protocol modules vary in reliability; a wrong `http-post-form` failure string yields false
  positives — always confirm a claimed hit by logging in yourself.
- **Impacket `GetNPUsers` / `GetUserSPNs`** — obtain **offline-crackable** AS-REP/TGS material (M06);
  strictly speaking a collection step, but a reminder that the best "password attack" often skips online
  guessing entirely and hands 10.2 a hash.

<div class="callout method">

**Verify by hand, always.** Online tools report success from a heuristic (a status code, an error
string, an SMB response). Before you write "valid credential `svc_backup:Autumn2026!`" in a report,
authenticate **once** with it yourself through the normal client. A false positive that turns out to be
a lockout artefact is an embarrassing and damaging mistake.

</div>

## Demonstration (LAB ONLY): a responsible spray

<div class="callout attack">

**Technique — lockout-safe password spray against the lab AD.** Suppose `--pass-pol` reported
`T = 5, W = 30 min`. You validated 40 usernames with kerbrute (no lockout impact) and chose the season
password.

```bash
# LAB ONLY — one password, one attempt per account, then WAIT past the observation window.
# Round 1:
nxc smb 10.10.10.10 -u users.txt -p 'Autumn2026!' --continue-on-success
#   → 1 bad attempt per account; well under T=5, leaves headroom for real typos.
# ...wait 35 minutes (W=30 + buffer) so lockout counters reset...
# Round 2:
nxc smb 10.10.10.10 -u users.txt -p 'Company2026!' --continue-on-success
```

A hit prints `[+] lab.local\jdoe:Autumn2026! ` (a valid pair). One password per round, spaced past the
window, is the entire safety mechanism — the tool does not enforce it, **you** do.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Every command here targets the `lab-06-ad` forest on the isolated
host-only network (built from licensed evaluation media; see [`labs/vm/README.md`](../../labs/vm/README.md)),
with synthetic users and the season-password planted deliberately. Spraying, brute-forcing, or stuffing
credentials against any system you do not own and are not explicitly authorized to test is a crime
(M00), and can lock real people out of their livelihoods. Confirm authorization, scope, **and** the
lockout policy before a single guess. Credential stuffing with real breach data against a live service
is out of scope for this course entirely.

</div>

## Verification

A responsible online attack has two verifications. **Did I get a credential?** — authenticate once,
manually, with the found pair (`nxc smb <dc> -u jdoe -p 'Autumn2026!'` alone, or an interactive logon)
and capture the success as evidence. **Did I stay safe?** — check that **no account locked out** as a
result: `Get-ADUser -Filter {LockedOut -eq $true}` on the lab DC, or the lab's reset/verify script,
should show zero lockouts attributable to your window. A finding of "weak password `Autumn2026!` in use
by 3 accounts, zero lockouts caused" is the professional result; "I sprayed and locked out 60 users" is
a reportable *mistake*.

## Impact

One valid low-privilege credential is a foothold: authenticated LDAP enumeration and BloodHound (M06),
a shell over WinRM/SSH (M11), or SMB access to shares full of secrets (10.2). If the sprayed hit is a
**service account** with an SPN, you may pivot straight to Kerberoasting and offline cracking. Framed for
the client: *"a single seasonal password we guessed in three attempts, without triggering lockout, gave
authenticated domain access"* — which is both a technical finding and a policy finding (weak passwords
plus a lockout threshold that permits low-and-slow spraying).

## Remediation

<div class="callout defend">

- **Kill guessable passwords at the source.** Adopt **NIST SP 800-63B**: screen new passwords against
  breach/common-password lists (blocklists), require length over complexity theatre, and **stop forced
  periodic rotation** (it manufactures `Season+Year`).
- **Multi-factor authentication** everywhere reachable — it defeats spraying and stuffing even when the
  password is guessed, because the password alone is no longer sufficient.
- **Tune lockout thoughtfully.** A threshold plus a *short* observation window still permits low-and-slow
  spraying; smart lockout / risk-based throttling that counts distinct-account failures from one source
  catches the spray pattern without locking legitimate users. Balance against DoS-by-lockout.
- **Kill reuse.** Deploy breached-credential monitoring; enforce unique passwords; move service accounts
  to **gMSA** (M05/M06) so there's no human password to spray or reuse.

Maps to **CWE-521**, **CWE-307**, and **CWE-522** on the storage side (10.2).

</div>

## Detection / blue-team view

<div class="callout defend">

- **Spraying signature:** **many distinct accounts, one failure each, from one source, in a short
  burst** — then a pause. On Windows: **Event ID 4625** (failed logon) fanning across many usernames;
  **4771** (Kerberos pre-auth failed) or **4768** with failure codes; a spike with a *low per-account*
  count is the tell (brute force is the opposite: many failures on *one* account, and lockout **4740**).
- **Stuffing signature:** high-volume logins from many source IPs, high failure rate, occasional
  success — classic bot traffic; WAF/identity-provider risk scoring flags it.
- **Impossible travel / anomalous source:** a success from a new ASN/geo right after a failure burst;
  identity providers (Entra ID Protection and equivalents) score this.
- **Design your test to be catchable.** Part of the value you deliver is telling the client whether their
  detection *fired*. Note the timestamps and source of your spray so blue team can confirm (or discover
  they missed) the 4625 fan-out.

Mapped to **MITRE ATT&CK T1110** — Brute Force: **.001** Password Guessing, **.002** Password Cracking
(offline, 10.2), **.003** Password Spraying, **.004** Credential Stuffing.

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-06-ad` — the small AD forest (DC + hosts) on the isolated **host-only network
with no Internet route** (VM-based; see [`labs/vm/README.md`](../../labs/vm/README.md)). **Access:**
network reachability to the DC from the attacker box; a synthetic user list is derivable via
enumeration (M06). **Targets:** the lab DC only; synthetic accounts, one of which uses the planted
season password. **Time:** ~60 min (much of it *waiting out the observation window* — that's the point).
**Isolation:** verify no external egress first. **Resettable:** the lab's reset script clears any lockouts
between attempts. No GPU needed here — this lesson is online-only; the heavy compute is in 10.2.

</div>

Read the lockout policy (`--pass-pol`), validate usernames with kerbrute (note: no lockout impact),
compute a safe schedule on paper, then run a single-password spray round, wait past the window, and run a
second — confirming after each that **zero accounts locked out**.

## Exercise

<div class="callout method">

**Situation.** Authorized internal engagement against the lab AD. You've enumerated the directory and
have ~120 usernames. NetExec `--pass-pol` reports **lockout threshold 5, observation window 30 minutes,
lockout duration 30 minutes**. The RoE says: *"no denial of service; do not lock out production users;
demonstrate weak-password exposure."* You have a four-hour testing window today.

**Objective.** Produce a **written, defensible password-spray plan** you could hand to a reviewer — not
a running of a tool, a *plan* — that gets you a credential if a weak one exists while guaranteeing you
cannot lock out a real user, and that predicts its own detection footprint.

**Starting information.** The policy above, your username list, and this lesson.

**Constraints.** Lab target only. Online spraying only (offline cracking is 10.2). You must not exceed
the lockout policy for any account including a hypothetical real user's own typos. Justify every number.

**Expected deliverables.**
1. **Attack choice + justification:** why spraying (not brute force, not stuffing) is correct here, in
   two sentences tied to the policy and the RoE.
2. **The schedule:** attempts per account per window, inter-round delay (show the math against T=5/W=30
   with a margin for real users), password candidates ranked by *relevance* with a one-line rationale
   each, and total wall-clock time within the 4-hour window.
3. **Username sourcing note:** how you'd validate the list without touching the lockout counter, and why
   that matters.
4. **Detection prediction:** exactly which events (IDs) your plan generates, what the spray signature
   looks like to blue team, and one thing that *would* catch you — so the client learns whether their
   detection works.
5. **Verification + safety check:** how you confirm a real hit (not a false positive) and how you prove
   you locked out zero accounts.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Start from the mechanism table: what varies, against whom, at what cost. The RoE's "no lockout" clause
eliminates one of the three attacks outright and makes a second one's *scheduling* the whole exercise.
</details>

<details><summary>Hint 2 — technique family</summary>
Spraying = one password, many users, one attempt per account per round. The only hard part is the
timing: relate your attempts-per-window to <code>T</code> and <code>W</code>, and leave room for a real
user's failures.
</details>

<details><summary>Hint 3 — where to look</summary>
Do the lockout math: with T=5, how many attempts per account per 30-minute window keep you safely below
the threshold <em>with</em> a margin? What inter-round delay guarantees the counter resets? Prefer one
attempt per window when unsure.
</details>

<details><summary>Hint 4 — specific direction</summary>
Pick 3–5 <em>relevant</em> passwords (season+year, company name, <code>Welcome1</code>) — not a
dictionary; a dictionary is an offline job. Validate usernames with Kerberos pre-auth (kerbrute) so you
add zero to the lockout counter, then map your rounds to 4625/4771/4768 events for the detection section.
</details>

## Check yourself

<div class="callout key">

1. You have a captured NTLMv2 response and also network access to the login form of the same account.
   Which do you attack, and why is one of these choices almost always better?
2. A junior colleague sets hydra to try a 10,000-word list against the domain admin account "to save
   time." Name every professional problem with this, and what they should have done instead.
3. The lockout policy is threshold 3, window 15 minutes. How many passwords can you *safely* spray in a
   one-hour window, and what number do you actually use? Show the reasoning.
4. Why does spraying evade account lockout while brute force triggers it, expressed in one sentence about
   *what is held constant*?
5. Credential stuffing is offered to you as in-scope. What must be true — legally, ethically, and
   about the data itself — before you'd agree, and what would make you refuse?
6. Your spray got a hit but three accounts also locked out. Is this a successful finding? What do you
   report, and what does the lockout tell you about your schedule?

</div>

Model answers are in `solutions/module-10.md` (instructor material — reason through them first).

## References

- **MITRE ATT&CK — T1110 Brute Force**: **.001** Password Guessing, **.002** Password Cracking,
  **.003** Password Spraying, **.004** Credential Stuffing.
- **NIST SP 800-63B** — Digital Identity Guidelines, Authentication & Lifecycle Management: password
  screening/blocklists, length-over-complexity, and the guidance *against* forced periodic rotation.
- **CWE-521** Weak Password Requirements; **CWE-307** Improper Restriction of Excessive Authentication
  Attempts; **CWE-522** Insufficiently Protected Credentials.
- **OWASP** — Credential Stuffing Prevention and Blocking Brute-Force Attacks cheat sheets.
- **Microsoft** — Account Lockout Policy (threshold / observation window / duration) and Kerberos/NTLM
  logon auditing (Event IDs 4625, 4740, 4768, 4771, 4776).
- **NetExec**, **kerbrute**, and **hydra** documentation (tool behaviour and options; see `TOOLS.md`
  for pinned versions).

## What you should now be able to do

- Choose correctly among spraying, brute force, and credential stuffing for a given situation, and
  justify it on mechanism and ethics.
- Explain the online/offline split and why offline is preferred whenever the material is obtainable.
- Compute a lockout-safe spray schedule from a stated policy, with margin for real users.
- Source a valid username list legitimately, including validation that doesn't touch the lockout counter.
- Run and **verify** a responsible spray in the lab, confirming zero lockouts.
- Predict the detection footprint of each attack and design a test the blue team should catch.

## Progress checkpoint

```bash
py course.py complete 10.1
```
