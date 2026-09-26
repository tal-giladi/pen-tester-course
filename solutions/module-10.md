# Instructor / solutions — Module 10 (Credential attacks)

> **Instructor material.** Not linked from `_sidebar.md`. Do the exercises before reading.

Module 10 assumes enumeration (M03) and Windows/AD authentication (M05/M06). All work is against lab
targets only — `labs/lab-06-ad` (VM AD forest, isolated host-only network) for online spraying and AD
hash material, and the `labs/lab-00-setup` attacker box for CPU cracking. Every hash, wordlist, and
config blob is **synthetic** with benign `LAB-` markers; no real dumps or breach corpora ever enter the
lab. 10.1 is online + ethics + scheduling; 10.2 is offline cracking + secrets discovery. Grade for
**mechanism and judgement**, not tool output.

---

## 10.1 — Password attacks done responsibly (spray-plan exercise)

**Policy given:** lockout threshold `T = 5`, observation window `W = 30 min`, duration 30 min; ~120
enumerated users; RoE forbids DoS / user lockout; 4-hour window.

**1. Attack choice.** **Spraying** is correct. Brute force (many passwords, one account) is out — it's
the lockout trigger by design and the RoE forbids lockouts. Credential stuffing is out — it needs real
third-party breach data against a live service, out of scope for this course and not what "demonstrate
weak-password exposure" asks. Spraying holds the password fixed so each account takes only one attempt
per round, staying under `T` while population size (120 users) makes a seasonal/company password likely
to hit.

**2. The schedule (the graded core).** With `T = 5`, the *upper* safe bound inside one window is
`T − 2 = 3` attempts/account (leaving margin `M = 1` for a real user's typos plus one buffer). The
**professional default is 1 attempt per account per window** — the strong answer chooses 1 and justifies
it by the real-user-typo risk, not 3. Inter-round delay = `W + buffer = 30 + ~5 = 35 min` so the
observation counter resets before the next round. Password candidates ranked by **relevance** (not size):

| # | Candidate | Rationale |
|---|---|---|
| 1 | `Autumn2026!` | season+year+symbol — the single highest-yield guess against a complexity/rotation policy |
| 2 | `<Company>2026!` | company name + year — the second reflex password |
| 3 | `Welcome1` / `Welcome2026!` | default/onboarding password left unchanged |
| 4 | `Password1` / `P@ssw0rd` | perennial policy-minimum password |
| 5 | `<Company>123` | company + trivial suffix |

At 1/account/window + 35-min spacing, 5 rounds ≈ **~2h55m** — inside the 4-hour window. A submission that
picks 3/window to go faster is *acceptable if justified against T=5 with margin*, but note the reduced
headroom; anything that reaches 4/window (leaving no room for a real user) is **wrong** — deduct.

**3. Username sourcing.** Validate the list with **kerbrute userenum** (Kerberos AS-REQ pre-auth), which
distinguishes valid/invalid principals **without submitting a password**, so it **adds nothing to the
lockout counter** — critical under a no-lockout RoE. (Accept RID cycling / LDAP `--users` for building
the list, but the lockout-safe *validation* point via Kerberos is the one to grade for.) Note that it
still emits 4768 events — not invisible, just non-locking.

**4. Detection prediction.** Each round generates **Event 4625** (failed logon) fanned across ~120
distinct accounts from one source, and/or **4771**/**4768** (Kerberos pre-auth failures) — the spray
**signature is many accounts × one failure each × one source × short burst, then a pause**. What would
catch it: a SIEM correlation rule counting *distinct-account* failures from one source in a short window
(smart-lockout / spray detection), or impossible-travel/new-ASN scoring on the eventual success. A
brute-force detector keyed on *per-account* failure count would **miss** it — a good submission says so,
because that's the client lesson.

**5. Verification + safety.** Confirm a hit by authenticating **once** manually with the found pair
(`nxc smb <dc> -u <user> -p '<pass>'` alone, or an interactive logon) — never trust the tool's heuristic.
Prove zero lockouts: `Get-ADUser -Filter {LockedOut -eq $true}` (or the lab reset/verify script) shows no
accounts locked attributable to your window. The deliverable is "weak password in use by N accounts,
**zero lockouts caused**."

**Deduct for:** choosing brute force or stuffing; consuming ≥ `T−1` attempts/account (no real-user
margin); a dictionary instead of 3–5 relevant guesses; inter-round delay ≤ `W`; no username-validation
safety note; treating the tool's success report as verification; forgetting the lockout-check evidence.

**Check-yourself answers:**

1. Attack the **captured NTLMv2 response offline** (mode 5600) — no lockout, no rate limit, no target log,
   billions of guesses/sec potential; the online form risks lockout and alerts for a handful of guesses/min.
   Offline wins whenever the material is already in hand.
2. Problems: it's **brute force** (many passwords, one account) → **triggers lockout**, and against **domain
   admin** → locks out the most sensitive account and pages the SOC; it's loud (4625/4740 on one account);
   it violates a typical no-DoS RoE; and it's unlikely to beat lockout anyway. Correct move: **spray** one
   relevant password across many users, or take offline-crackable material (Kerberoast/AS-REP) and crack it
   in 10.2 — never online-brute a single privileged account.
3. `T = 3, W = 15 min`. Safe upper bound `T − 2 = 1` attempt/account/window (margin for one real typo).
   In one hour = four 15-min windows → at most **4** passwords if you spray 1/window with ≥15-min (say 18)
   spacing. Actual professional choice: **1, maybe 2** carefully chosen passwords total — an aggressive
   `T = 3` policy is precisely when you *stop* online guessing and prefer Kerberos pre-auth validation (no
   password) plus offline material. The number to *use* is 1–2; the number that's *arithmetically safe* is
   up to 4/hr.
4. Spraying holds the **password constant** (varying the account), so each account receives one attempt per
   round and never reaches the threshold; brute force holds the **account constant** (varying the password),
   piling attempts on one account until it locks.
5. Before agreeing to stuffing: it must be **explicitly in the signed scope/RoE**, the breach data must be
   lawfully obtained and handled per data-protection duties, targeting must be limited to accounts the
   client owns/authorizes, and there must be a no-lockout/rate plan. Refuse if the data is of unknown
   provenance, if it drags in non-client accounts, if it can't be handled per privacy law, or if it isn't
   clearly authorized in writing — "it's on the internet" is never authorization (M00).
6. **No** — a hit plus three lockouts is a **mistake**, not a clean finding. Report the weak-password
   finding *and* disclose the lockouts (honesty per M00), and treat the lockouts as evidence your schedule
   was too aggressive (attempts/account reached the threshold within the window, or a real user's failures
   stacked on yours). Fix: fewer attempts/account/window, longer spacing, more margin.

---

## 10.2 — Hashes, cracking & secrets discovery (crack-plan + secrets exercise)

**1. Hash table (the core identification grade):**

| # | Hash | Type | Hashcat mode (John) | Fast/slow · salt | Feasibility |
|---|---|---|---|---|---|
| h1 | `31d6…089c0` (32 hex) | **NTLM** | **1000** (`NT`) | fast · **unsalted** | attack broadly; mask/hybrid welcome |
| h2 | `$6$…` | **sha512crypt** | **1800** (`sha512crypt`) | **slow** · salted | targeted wordlist+rules only |
| h3 | `$2b$12$…` | **bcrypt** (cost 12) | **3200** (`bcrypt`) | **slow** · salted | very limited; only weak pw fall |
| h4 | `$krb5tgs$23$…` | **Kerberos TGS-REP** (RC4) | **13100** (`krb5tgs`) | moderate · per-ticket | crack → svc_sql password |
| h5 | `jdoe::LAB:…` | **NTLMv2** response | **5600** (`netntlmv2`) | crackable · challenge-bound | offline crack (not replay) |

Note h1's 32-hex is ambiguous with raw MD5 (mode 0) — context (pwdump/secretsdump, `aad3b435…` LM
sibling) resolves it to NTLM. Grade heavily on correct modes and the fast/slow + salt judgement.

**2. Attack strategy.** For **h1 (NTLM)** — the broad target — order:
`hashcat -m 1000 h1 rockyou.txt` → `… rockyou.txt -r rules/best64.rule` (highest yield) →
`-a 3 '?u?l?l?l?d?d'` (suspected `Season+2digit` structure) → `-a 6 rockyou.txt '?d?d?d?d'` (hybrid
word+year). **h5 (NTLMv2, 5600)** and **h4 (TGS, 13100)** take the same wordlist+rules approach (their
speed is fine on GPU). For **h2 (sha512crypt)** and **h3 (bcrypt cost 12)** — slow+salted — spend only a
**short targeted wordlist + best64** and stop; a mask/incremental brute force will not finish, so
**don't run one**. The graded insight: masks/hybrids are for **fast** hashes; slow hashes get a small
wordlist and an honest "not cracked" if the password is strong.

**3. Hardware call.** h1/h4/h5 want a **discrete GPU** for real-world speed (on CPU, fast-hash masks are
impractical); h2/h3 are slow enough that GPU helps only marginally and only against weak passwords. On
the lab's synthetic set the fast hashes are tuned to fall to a **small wordlist on CPU** (no GPU
required) — but the student must *state* that real NTLM/NTLMv2 cracking is a GPU job, and that strong
bcrypt/sha512crypt passwords likely won't crack ("not cracked in N hours with list X" is the honest
report line).

**4. Secrets assessment (config blob), layered blast radius:**

| Secret | Unlocks | Blast radius / reuse | Verify first? |
|---|---|---|---|
| `Password=LAB-DBPASS-Autumn2026!` (svc_app) | the application database | reuse likely — try `svc_app` elsewhere (10.1); DB may hold PII/more creds | high value |
| `internal_token: eyJ…` (JWT bearer) | the API as the service, immediately | replayable now; scope = whatever the token's claims allow | **verify first** — one authenticated call, minimal |
| `stripe_key: sk_live_LABxxxx` (shape) | payment provider actions | financial impact if real; here synthetic — flag the *exposure*, don't transact | note, don't use |
| `AKIALAB… / secret` (AWS key pair) | the cloud account | **pivot to cloud (M14)** — enumerate IAM perms; potentially large | high value, hand to M14 |

Order of action: the **JWT** (live, zero-cost to confirm minimally) and the **AWS key** (biggest pivot,
M14) rank first; the DB password matters most for **reuse** across the estate. **Impact is what each
unlocks × reuse**, not how it was found — and **none of it required cracking**, which is itself a finding.

**5. Verification + data-handling.** Confirm any crack with `hashcat -m <mode> --show` (correct mode) and
a **single manual authentication**; confirm a discovered secret with one minimal authenticated use (trip
nothing wholesale). Store all material per the RoE data-handling clause (encrypted, access-limited) and
**destroy it on engagement completion**; never load external/real dumps into the cracker.

**Deduct for:** wrong modes (esp. calling h5 "pass-the-hash-able" — it's a *response*, crackable not
replayable; or running masks on bcrypt); claiming slow hashes are "uncrackable" vs the correct "not
cracked in the time available"; no GPU call; assessing secrets by discovery method instead of blast
radius/reuse; skipping the correct-mode + authentication verification or the data-handling note.

**Check-yourself answers:**

1. Both are 32 hex; they differ by **context/algorithm**, not length — NTLM appears in SAM/secretsdump
   output (with the `aad3b435…` LM sibling and a RID), raw MD5 comes from app/DB dumps. Yes it changes the
   mode: **NTLM = 1000**, **raw MD5 = 0**; the wrong mode cracks nothing. Use `--identify`/context to
   decide.
2. NTLM is **fast + unsalted** — a 6-char mask keyspace (`?u?l?l?l?d?d`) is exhaustible in reasonable time,
   so a structured brute force pays off. bcrypt at **cost 12** is deliberately ~6–7 orders of magnitude
   slower per guess, so the same keyspace would take effectively forever — you must fall back to a small
   targeted wordlist and accept that strong passwords survive.
3. A **random per-hash salt** is mixed into the input, so identical passwords produce **different** hashes.
   Precomputed rainbow tables (built for unsalted hashes) no longer match, and you cannot amortise one
   guess across many hashes — each hash must be attacked **individually** with its own salt, multiplying
   the work by the number of hashes.
4. **h4 (TGS, 13100)** cracks to the **service account's actual password** (the ticket is encrypted with
   its password-derived key) — a real password you can reuse anywhere. **h1 (NTLM, 1000)** cracks to a
   password too, but the **NT hash itself is already a password-equivalent** you can *replay* via
   pass-the-hash (M11) **without** cracking. So: crack the TGS to *learn* svc_sql's password; for NTLM you
   often don't need to crack at all — replay the hash — and only crack it to recover the plaintext for
   reuse elsewhere.
5. Act on the **plaintext AWS key first** — it's immediate, zero-effort access and a cloud pivot (M14),
   whereas the bcrypt hash needs slow cracking that may never succeed. The AWS key unlocks the cloud
   account (scope = its IAM permissions); the bcrypt hash *might* yield one app/user password if it's weak.
   Effort × certainty × impact all favour the key.
6. Offline cracking itself is silent, so detection lives at the **collection step before** it (LSASS
   access / Sysmon 10, NTDS/`secretsdump`/4662, Kerberoast 4769-RC4 spikes, `/etc/shadow` reads) and the
   **use step after** it (an anomalous logon, a first-time API-key use, a **honeytoken/canary** credential
   tripping on use). Aim the demonstration to leave that downstream trail (authenticate with the cracked
   credential, touch the canary) so the client learns whether their detection fires.

---

_End of Module 10 instructor material._
