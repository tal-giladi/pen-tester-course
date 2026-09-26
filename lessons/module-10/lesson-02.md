# 10.2 — Hashes, cracking & secrets discovery: Hashcat/John, wordlists/rules/masks, and where credentials hide

<div class="prereq">

**Prerequisites:** [10.1](lesson-01.md) — the online/offline split and why offline is preferred. [M00](../module-00/lesson-01.md)
(authorization; data-handling for anything you crack). [M03](../module-03/lesson-01.md) (enumeration —
where hashes and secrets surface). [M05](../module-05/lesson-02.md) (NTLM/Kerberos primer — what the
hashes and tickets *are*) and [M06](../module-06/lesson-01.md) (Kerberoasting/AS-REP produce the
crackable material).
**Module:** M10 Credential attacks. **Difficulty:** 🟡 intermediate.
**M10 assumes** you can obtain hashed material (via M05/M06 or a file you're authorized to read). This
lesson is the **offline craft**: turning captured hashes and hidden secrets into plaintext and impact.
**You will produce:** a written **cracking plan** for a set of synthetic hashes (correct mode, ordered
attack strategy, hardware call) plus a **secrets-discovery + impact assessment** for a provided config
blob.

</div>

## Why this matters

Online guessing (10.1) is slow, loud, and lockout-gated. The moment you hold **hashed material**, the
game changes: offline, on your own hardware, you guess millions to billions of times per second, the
target never knows, and nothing locks out. This is where a dumped SAM, a Kerberoasted ticket, a leaked
`/etc/shadow`, or a database export *from the client's own systems* becomes a live domain admin
password. Equally important — and more often the fast win — **secrets that were never hashed at all**:
plaintext credentials, API keys, and tokens sitting in config files, source code, and CI logs. A
professional knows how to recognise a hash type on sight, choose an attack strategy that fits it, call
for the right hardware, and *also* knows that the cheapest credential is usually the one someone
committed to a repo.

## Learning objectives

By the end you can:

- Identify common hash types on sight (NTLM, NTLMv2, Kerberos TGS/AS-REP, `sha512crypt`, `bcrypt`) and
  give the correct **Hashcat mode** / **John format**.
- Explain **fast vs slow hashes** and **salting**, and why hash type dictates whether cracking is even
  feasible.
- Choose and order an offline attack strategy: **wordlist → rules → mask → hybrid**, and say why.
- Extract crackable material with the **`*2john`** family and the M05/M06 collection tools.
- State when a **GPU** is required vs when CPU suffices, and flag it in a plan.
- Find secrets where they hide — config files, source, CI/CD, browser stores (concept), API keys, tokens,
  cloud credentials — and assess the impact and blast radius (with the link to cloud, M14).

## Intuition

A password hash is a **one-way turnstile**: easy to go password → hash, infeasible to reverse
hash → password directly. So cracking doesn't reverse anything — it **guesses forward**: hash each
candidate the same way and compare. Two properties of the turnstile decide your fate. **Speed** — if the
hash is cheap to compute (NTLM, raw MD5), you can try billions per second; if it's deliberately
expensive (bcrypt, sha512crypt with thousands of rounds), you try thousands or millions, and only weak
passwords fall. **Salt** — a random per-hash value mixed in means identical passwords produce different
hashes, killing precomputation (rainbow tables) and forcing you to attack each hash individually.
Everything about offline cracking is a consequence of those two knobs, and reading a hash tells you
where both are set.

## The underlying technology

### Fast vs slow hashes, and salting

Authentication hashes come in two families:

- **Fast, general-purpose hashes** — NTLM (`MD4`), raw MD5/SHA-1/SHA-256. Designed for *speed*, which is
  a disaster for password storage: a commodity GPU computes **billions of NTLM guesses per second**.
  NTLM is also **unsalted**, so identical passwords hash identically and precomputation is possible.
  These are the crackable jackpot.
- **Slow, purpose-built password hashes (KDFs)** — `bcrypt`, `sha512crypt` (`$6$`), PBKDF2, `scrypt`,
  `Argon2`. These are **deliberately expensive** (a tunable *work factor* / iteration count) and
  **salted**. bcrypt at cost 12 might allow only tens of thousands of guesses per second on the same GPU
  — six or seven orders of magnitude slower than NTLM. Against these, only genuinely weak passwords are
  crackable in any reasonable time; strong ones are effectively safe. That is the whole point of a KDF.

<div class="callout key">

**Hash type dictates feasibility — read it first.** Before choosing a wordlist, identify the hash.
NTLM/MD5 → you can throw huge attacks at it and expect results. bcrypt/sha512crypt/Argon2 → only a
short, targeted wordlist+rules has any chance; a full mask brute force is hopeless. Misjudging this
wastes days of GPU time. The salt (present in `$6$…$…`, `$2b$…`, absent in NTLM) tells you whether
precomputation and cross-hash sharing are possible.

</div>

### Recognising the artifacts (all values below are **synthetic LAB samples**, truncated with `…`)

**NTLM** — Hashcat **mode 1000**. A 32-hex NT hash, usually seen in `pwdump`/secretsdump format
`user:RID:LMhash:NThash:::`:

```text
svc_backup:1108:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
#           RID   (empty LM hash — ignore)        NT hash (mode 1000)
```

**NTLMv2** (captured challenge/response, e.g. via a poisoning capture in M11) — Hashcat **mode 5600**:

```text
jdoe::LAB:1122334455667788:1F2E…9A:0101000000000000C0653150DE09D201B0…0000000000000000
# user::DOMAIN:server-challenge:HMAC-MD5:blob   (the response, NOT the NT hash — crackable, not PtH-able)
```

**Kerberos TGS-REP** (Kerberoasting, M06) — Hashcat **mode 13100** (RC4 `$23$`):

```text
$krb5tgs$23$*svc_sql$LAB.LOCAL$MSSQLSvc/db01.lab.local:1433*$3f8b…$a91c…(long edata)…
# encrypted with svc_sql's password-derived key → crack it → svc_sql's password
```

(AS-REP roasting yields `$krb5asrep$23$…`, Hashcat **mode 18200**.)

**Linux `sha512crypt`** — Hashcat **mode 1800**, from `/etc/shadow`. Slow + salted:

```text
labuser:$6$Xy9pQ2rT$Kf3…(86 chars)…/:19700:0:99999:7:::
#        $6$ = sha512crypt   $salt$    hash        (slow, salted — only weak passwords fall)
```

**bcrypt** — Hashcat **mode 3200**. Slow + salted; the cost factor is *in the hash*:

```text
$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW
# $2b$  cost=12  22-char salt + 31-char hash   (cost 12 ≈ very slow → wordlist+rules only)
```

Use **`hashid`** or Hashcat's `--identify` / John's detection to confirm — but learn the shapes; the
`$2b$`, `$6$`, `$krb5…`, and bare 32-hex tells are worth memorising.

### Extracting crackable material — the `*2john` family

Hashes rarely arrive in crack-ready form; you extract them. John the Ripper ships a large family of
`*2john` converters that turn a file into a hash line Hashcat/John can eat:

```bash
# LAB ONLY — turn protected files into crackable hash lines:
zip2john secret.zip           > zip.hash      # password-protected ZIP
ssh2john  id_rsa              > key.hash       # passphrase on an SSH private key
office2john  budget.xlsx      > office.hash    # Office document password
keepass2john vault.kdbx       > kp.hash        # KeePass database master password
pdf2john.pl  report.pdf       > pdf.hash       # PDF owner/user password
```

Each reads the file's KDF parameters and emits the hash + salt + iteration data. On Windows/AD the
collection tools from M05/M06 produce the material directly: **secretsdump.py** (SAM/LSA/NTDS →
mode 1000), **GetUserSPNs.py** (Kerberoast → 13100), **GetNPUsers.py** (AS-REP → 18200). The reasoning is
always the same: *get the salted, KDF-formatted representation, then attack it offline.*

## Why the weakness exists

Two design choices, one human one. **Using a fast hash (or none) for password storage** — NTLM's
unsalted MD4 exists for backward compatibility and speed, not security; storing web passwords as raw
MD5/SHA-256 is a developer error that persists. This is **CWE-916 (use of a password hash with
insufficient computational effort)** and **CWE-759/760 (missing/predictable salt)**. **Handing out
crackable material** — Kerberos gives any user a TGS encrypted with a service account's key by design
(M05), so a weak service-account password is offline-crackable regardless of how it's stored. And the
human one: **secrets left in the clear** — plaintext passwords, keys, and tokens in config, code, and
logs — **CWE-522 (insufficiently protected credentials)** and **CWE-798 (hard-coded credentials)**. The
strongest KDF in the world is irrelevant if the password is also sitting in `appsettings.json`.

## How a tester recognizes it

- **A hash you can name** — the `$`-prefix or the 32-hex shape tells you the algorithm and therefore the
  feasibility. NTLM/MD5 = attackable at scale; bcrypt/`$6$`/Argon2 = targeted only.
- **A service account with an SPN** (M06) — free offline-crackable TGS material.
- **Any protected file** (ZIP, SSH key, Office doc, KeePass, PDF) → a `*2john` target.
- **Secrets in plaintext** — the highest-value, lowest-effort find: config files with connection
  strings, `.env` files, hard-coded keys in source, tokens in CI logs, cloud credentials in
  `~/.aws/credentials`. Often no cracking required at all.

## Manual investigation — before you spin up the GPU

1. **Identify every hash's type and mode** and split them into files by type — Hashcat cracks one mode
   per run.
2. **Triage by feasibility:** attack the **fast, unsalted** hashes (NTLM) first and broadly; give the
   **slow** hashes (bcrypt/`$6$`) only a small, targeted wordlist+rules budget.
3. **Grep for secrets in parallel** — a plaintext credential in a config file beats any crack. This
   often finishes the engagement before the GPU warms up.
4. **Scope the crack to the target.** Build a **targeted wordlist** from the client's own vocabulary
   (company name, products, locations) plus known leaks — far more effective per guess than a generic
   list.

## Tooling — what it does, key options, limits, verify by hand

- **Hashcat 6.2.6** <span class="badge current">CURRENT</span> — the GPU cracker. `-m <mode>` (hash
  type), `-a <attack>` (0 = wordlist, 3 = mask, 6/7 = hybrid), `-r <rules>` (mutation rules), `-w`
  (workload). `--identify` guesses the mode. **Limit:** wants a real GPU for fast hashes (CPU is orders
  of magnitude slower); one mode per run; a wrong mode silently cracks nothing.
- **John the Ripper (jumbo) 1.9.0** <span class="badge current">CURRENT</span> — CPU-first, superb
  **format autodetection** and the `*2john` extractors. `--format=`, `--wordlist=`, `--rules=`,
  `--incremental` (its Markov brute force), `--show` to print cracked results. **Limit:** slower than
  Hashcat on GPU-friendly hashes; the value is detection, extraction, and CPU convenience.
- **Wordlists** — `rockyou.txt` (the standard teaching list; ~14M leaked passwords), SecLists, and a
  **custom** list you build for the target. **Limit:** a generic list misses org-specific passwords —
  build a targeted one.
- **Rules** — `best64.rule` (Hashcat's compact, high-yield default), `dive.rule`, `OneRuleToRuleThemAll`.
  A rule mutates each word (append digits, capitalise, leetspeak) so `password` also tries
  `Password1`, `p@ssw0rd`, `password2026`. **Limit:** more rules = more candidates = more time;
  best64 is the efficient default.
- **hashid / name-that-hash** — identify unknown hashes. **Limit:** ambiguous for same-length hashes
  (raw MD5 vs NTLM are both 32 hex) — confirm with context.

<div class="callout method">

**Verify by hand.** When Hashcat reports a crack, confirm it: `hashcat -m 1000 hashes.txt --show`
prints `hash:plaintext`. Then prove the plaintext actually authenticates (a single manual logon, per
10.1's verify rule) before it goes in a report. A "cracked" value against the wrong mode is nonsense;
the mode and the authentication are your two checks.

</div>

### Attack-mode strategy — wordlist → rules → mask → hybrid

Order attacks cheapest-and-likeliest first:

```bash
# LAB ONLY. mode 1000 = NTLM (fast, unsalted) — attack broadly.
# 1) Straight wordlist (-a 0): try known passwords as-is.
hashcat -m 1000 hashes.txt rockyou.txt
# 2) Wordlist + rules (-a 0 -r): mutate each word — the highest-yield step.
hashcat -m 1000 hashes.txt rockyou.txt -r rules/best64.rule
# 3) Mask brute force (-a 3): exhaust a *pattern* you suspect. ?u?l?l?l?d?d = Upper+3lower+2digit
#    (e.g. "Autumn26"-shaped) — a 6-char keyspace, feasible on NTLM, hopeless on bcrypt.
hashcat -m 1000 hashes.txt -a 3 '?u?l?l?l?d?d'
# 4) Hybrid (-a 6): wordlist + appended mask — "word"+"2026" style.
hashcat -m 1000 hashes.txt -a 6 rockyou.txt '?d?d?d?d'
```

The mask charsets: `?l` a–z, `?u` A–Z, `?d` 0–9, `?s` symbols, `?a` all. A mask is a *targeted* brute
force — you use it when you suspect a **structure** (a policy that forces `Uppercase+letters+digits`
produces exactly `?u?l?l?l?l?d?d`-shaped passwords). Against a **slow** hash you skip masks entirely and
run only a short wordlist+rules — anything larger will not finish.

<div class="callout warn">

**GPU flag.** Fast-hash cracking (NTLM, MD5, NTLMv2) at useful speed **needs a discrete GPU**; on a
laptop CPU it is orders of magnitude slower and a full mask may take years. The lab's synthetic hashes
are chosen to fall to a **small wordlist on CPU** so no GPU is required — but on a real engagement,
plan hardware explicitly and say so in the report. Slow hashes (bcrypt/`$6$`) are GPU-resistant *by
design*: even with a GPU you crack only weak passwords, so the honest report line is "strong bcrypt
passwords were not cracked in the time available," not "uncrackable."

</div>

## Secrets discovery — the credentials that were never hashed

Cracking is only half of M10. The other half — often the faster win — is finding secrets stored in the
clear. Where they hide:

- **Config files:** `web.config`/`appsettings.json` connection strings, `.env`, `settings.py`,
  `application.properties`, `wp-config.php`, `docker-compose.yml` environment blocks, unattended-install
  files (`unattend.xml`, M05).
- **Source & version control:** hard-coded keys/passwords in code, and **git history** — a secret
  removed in a later commit still lives in the history (`git log -p`, tools like `trufflehog`/`gitleaks`).
- **CI/CD & logs:** pipeline variables echoed into build logs, tokens in Jenkins/GitLab job output.
- **API keys & tokens:** cloud provider keys (AWS `AKIA…`), OAuth/JWT bearer tokens, Slack/GitHub PATs,
  Stripe keys — recognisable by prefix and shape.
- **Cloud credentials:** `~/.aws/credentials`, `~/.azure/`, `~/.config/gcloud/`, kube configs, and
  **instance metadata** reachable via SSRF (IMDS) — the direct bridge to **M14 (cloud)**.
- **Browser credential stores (concept only):** browsers store saved logins encrypted with an OS-bound
  key (Windows DPAPI, macOS Keychain), so a local attacker *at that user's context* can often decrypt
  them. This course treats it **conceptually** — you must know it's an exposure and how it's protected;
  we do not run credential-store extractors against real profiles.

A worked recognition example (synthetic LAB config blob):

```yaml
# LAB ONLY — synthetic config. Every secret here is a benign LAB marker.
database:
  connection: "Server=db01;User Id=svc_app;Password=LAB-DBPASS-Autumn2026!;"   # plaintext DB cred
api:
  stripe_key: "sk_live_LABxxxxEXAMPLExxxx"          # (synthetic) live-key SHAPE → payment impact
  internal_token: "eyJhbGciOiJIUzI1NiJ9.eyJ...LAB"  # JWT bearer → API auth as the service
aws:
  access_key_id: "AKIALAB0EXAMPLE00000"             # AWS key SHAPE → pivot to cloud (M14)
  secret_access_key: "LABsecretEXAMPLEdoNotUseReal0000000000000"
```

Reading that blob, a tester immediately sees a **layered blast radius**: the DB password grants the
application database (and the `svc_app` account may be reused elsewhere — try it, per 10.1); the JWT is
a ready-to-replay bearer token; the AWS key pair is a pivot into the cloud account (enumerate its IAM
permissions in M14). None of it required cracking. **Impact is assessed by what each secret unlocks and
whether it's reused**, not by how it was found.

## Demonstration (LAB ONLY): crack a synthetic hash, then find the secret

<div class="callout attack">

**Technique — offline crack + secrets sweep.** Given a synthetic NTLM hash file and the lab's config
drop:

```bash
# LAB ONLY. 1) Identify + crack (small wordlist, CPU-friendly synthetic hash):
hashcat -m 1000 lab_hashes.txt lab_wordlist.txt -r rules/best64.rule
hashcat -m 1000 lab_hashes.txt --show        # → svc_backup NT hash : Autumn2026!  (verify the crack)

# 2) Secrets sweep across the provided config tree (grep the obvious patterns):
grep -RniE 'password|passwd|secret|api[_-]?key|token|AKIA|BEGIN (RSA|OPENSSH) PRIVATE KEY' ./config/
```

The crack yields a plaintext password; the sweep yields plaintext secrets. Together they show the
client that both their *hashed* and *stored-plaintext* credentials are exposed — two findings, two
remediations.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Every hash, wordlist, and config blob in this lesson is **synthetic**,
uses **benign LAB markers** (`LAB-…`, `AKIALAB…`, `sk_live_LABxxxx`), and lives only in the isolated lab
(`labs/lab-06-ad` for AD material; the attacker box for CPU cracking). **Never** load a real credential
dump, a third party's breach corpus, or another organisation's hashes into your cracker — cracking
material you are not authorized to hold is itself an offence, and handling real breach data raises legal
and privacy duties (M00's data-handling clause). Crack only what an authorized engagement lawfully put
in your hands, store it under the RoE's data-handling rules, and destroy it on completion.

</div>

## Verification

A cracked credential is verified in two steps: **the crack itself** (`--show` prints `hash:plaintext`
against the *correct mode* — a crack under the wrong mode is meaningless) and **authentication** (the
plaintext logs in once, manually, per 10.1). A discovered secret is verified by using it *minimally* to
confirm it's live — one authenticated call, not wholesale access — and by noting where it was found
(file, line, git commit) as evidence. For slow hashes, "not cracked in N GPU-hours with wordlist X" is
itself a reportable, honest result — record the effort so the finding is defensible.

## Impact

Offline cracking converts captured material into **working credentials without ever alerting the
target** — a Kerberoasted `svc_sql` password may be a domain admin (M06); a cracked `/etc/shadow` entry
is a login; an NTLM hash cracked to plaintext lets you authenticate anywhere the password is reused
(10.1). Discovered secrets are often worse and faster: a plaintext DB password, an AWS key, or a JWT is
immediate access with no cracking at all, and reuse multiplies the blast radius across systems. In
report terms you frame it as **credential exposure with a measured blast radius**: what each cracked or
found secret unlocks, how far reuse carries it, and whether it reached crown-jewel assets — and you tie
the cloud keys forward to M14.

## Remediation

<div class="callout defend">

- **Store passwords with a strong, salted KDF** — bcrypt, `scrypt`, or **Argon2id** with a tuned work
  factor; never raw MD5/SHA-256, and unique per-hash salts (CWE-916, CWE-759).
- **Eliminate weak passwords upstream** — the 10.1 remediation (blocklists, length, MFA) is what makes
  even fast/leaked hashes uncrackable in practice.
- **Harden Kerberoastable accounts** — **gMSA** with long random machine-managed passwords so a
  captured TGS is not crackable (M05/M06); AES encryption types over RC4.
- **Get secrets out of the clear** — use a **secrets manager / vault** (not config files, not source);
  short-lived tokens; scan repos and CI with `gitleaks`/`trufflehog`; rotate anything ever exposed;
  never commit keys (CWE-798, CWE-522). For cloud keys, prefer instance roles and IMDSv2 (M14).

</div>

## Detection / blue-team view

<div class="callout defend">

- **Offline cracking is invisible to the target** — this is the core teaching point. There is **no**
  authentication log for a guess made against your own copy. Detection must therefore focus on the
  **collection** step that preceded it: LSASS access (Sysmon **Event 10**), NTDS.dit / `ntdsutil` /
  `secretsdump` activity (**4662** on the DС, volume-shadow-copy creation), Kerberoasting's **4769**
  spikes with RC4 (M05/M06), and abnormal reads of `/etc/shadow`.
- **Secrets exposure** is caught by scanning, not by an attacker's action: repo secret-scanning in CI,
  DLP on config artefacts, and honeytoken/canary credentials (a fake AWS key that alerts on use) — using
  the *found* secret trips the canary even though the discovery didn't.
- **Downstream use is the detectable moment:** the cracked/found credential eventually **authenticates**,
  and *that* event (an unusual logon, a first-time API-key use from a new source, a canary-token hit) is
  what blue team sees. Design your demonstration to leave that trail so the client learns whether they'd
  notice.

Mapped to **MITRE ATT&CK**: **T1110.002** Password Cracking; **T1003** OS Credential Dumping
(collection); **T1558.003** Kerberoasting; **T1552** Unsecured Credentials (**.001** in files, **.004**
private keys, **.005** cloud instance metadata, **.007** container/cloud creds); **T1555** Credentials
from Password Stores (**.003** browsers).

</div>

## Practical lab

<div class="lab">

**Environment:** the attacker workstation from `labs/lab-00-setup` for CPU cracking, plus `labs/lab-06-ad`
for AD hash material (VM; see [`labs/vm/README.md`](../../labs/vm/README.md)); both on the isolated
network with no Internet route. **Targets:** a **synthetic** hash set and a **synthetic** config blob
shipped with the lab — no real dumps, benign `LAB-` markers. **Time:** ~75 min. **Hardware:** the
synthetic fast hashes are tuned to fall to a **small wordlist on CPU** — **no GPU required**; the lesson
*explains* where a GPU would be mandatory on real work. **Isolation:** verify no external egress; never
load external breach corpora. **Resettable:** delete cracked output and re-copy the synthetic set per the
lab README.

</div>

Identify each synthetic hash's mode, crack the fast ones with wordlist+rules (note the slow ones resist),
extract a protected file with a `*2john` tool, then sweep the config blob for plaintext secrets and write
the two-part impact.

## Exercise

<div class="callout method">

**Situation.** Authorized engagement. You've been handed (lawfully, under the RoE) a **synthetic** set
of five hashes and a **synthetic** application config blob from a compromised host:

```text
h1  31d6cfe0d16ae931b73c59d7e0c089c0                                  (32 hex)
h2  $6$Xy9pQ2rT$Kf3…(sha512crypt)…/
h3  $2b$12$R9h/cIPz0gi.URNNX3kh2OP…(bcrypt)
h4  $krb5tgs$23$*svc_sql$LAB.LOCAL$MSSQLSvc/db01*$3f8b…$a91c…
h5  jdoe::LAB:1122334455667788:1F2E…9A:0101…0000     (challenge/response)
```
plus the config blob from the "Secrets discovery" section above.

**Objective.** Produce (a) a **cracking plan** — correct mode per hash, an ordered attack strategy, a
feasibility judgement, and a hardware call — and (b) a **secrets-discovery + impact assessment** of the
config blob. This is a written plan and assessment; you may *concept-execute* the crack on the lab's
synthetic set.

**Starting information.** The hashes and blob above, and this lesson.

**Constraints.** Lab/synthetic only. No real dumps, no external breach data. Justify every mode and
every ordering decision; be honest about what won't crack.

**Expected deliverables.**
1. **Hash table:** each hash → its type, Hashcat mode (and John format), fast/slow + salted/unsalted, and
   a one-line feasibility verdict.
2. **Attack strategy:** for the *feasible* hashes, the ordered plan (wordlist → rules → mask → hybrid)
   with a concrete example command and a suspected mask; for the slow ones, what limited budget you'd
   spend and why a mask is pointless.
3. **Hardware call:** which hashes need a GPU and which are CPU-fine, stated explicitly.
4. **Secrets assessment:** every secret in the blob, what it unlocks, its blast radius, whether reuse is
   likely, and which one you'd verify first (minimally) — including the cloud-key hand-off to M14.
5. **Verification + data-handling:** how you confirm a crack (correct mode + authentication) and how you
   store/destroy the material under the RoE.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Read each hash's prefix/shape <em>before</em> planning any attack. The <code>$</code>-prefix (or its
absence) tells you the algorithm, and the algorithm tells you whether cracking is feasible at all. Sort
into "attack broadly" vs "targeted only."
</details>

<details><summary>Hint 2 — technique family</summary>
h1 = NTLM (mode 1000, fast, unsalted). h2 = sha512crypt (1800, slow, salted). h3 = bcrypt (3200, slow,
salted). h4 = Kerberos TGS (13100). h5 = NTLMv2 (5600). Fast+unsalted → mask/hybrid welcome; slow+salted
→ short wordlist+rules only.
</details>

<details><summary>Hint 3 — where to look</summary>
For the feasible hashes, order wordlist → rules(best64) → mask → hybrid, cheapest first. A mask like
<code>?u?l?l?l?d?d</code> targets a suspected structure; use it on NTLM, never on bcrypt. For the config
blob, grep the obvious patterns and ask "what does each secret authenticate to, and is it reused?"
</details>

<details><summary>Hint 4 — specific direction</summary>
State plainly which hashes need a GPU (the fast ones, for real-world speed) and which are CPU-fine, and
that strong bcrypt/sha512crypt passwords likely won't crack — say so honestly. For impact, layer the
blast radius: DB password → app DB (+ reuse); JWT → API as the service; AWS key → cloud pivot (M14).
Verify a crack with <code>--show</code> and a single manual logon.
</details>

## Check yourself

<div class="callout key">

1. You have two 32-hex hashes: one is NTLM, one is raw MD5. How do you tell them apart, and does it
   change your Hashcat mode?
2. Why is a mask brute force (`-a 3 '?u?l?l?l?d?d'`) a sensible move against an NTLM hash but a waste of
   time against a bcrypt hash at cost 12?
3. Explain, mechanically, why salting defeats rainbow tables and forces you to attack each hash
   individually.
4. A Kerberoasted TGS (mode 13100) and an NTLM hash (mode 1000) are both "crackable." Which gives you
   the *account's password* and which gives you a *password-equivalent you can also just replay* — and
   what's the difference in how you'd use each?
5. You find a plaintext AWS key and a bcrypt password hash in the same config file. Which do you act on
   first and why, and what does each unlock?
6. Offline cracking leaves no log on the target. So how would a blue team ever detect that it happened,
   and where do you aim your demonstration to give them a chance?

</div>

Model answers are in `solutions/module-10.md` (instructor material — reason through them first).

## References

- **Hashcat** — documentation and wiki: hash modes (`-m`), attack modes (`-a`), mask charsets, rule
  syntax; `best64.rule`. Pinned version in `TOOLS.md` (6.2.6).
- **John the Ripper (jumbo)** — documentation: format autodetection, `--rules`, `--incremental`, and the
  **`*2john`** extractor family (`zip2john`, `ssh2john`, `office2john`, `keepass2john`, `pdf2john`).
- **MITRE ATT&CK** — **T1110.002** Password Cracking; **T1552** Unsecured Credentials (.001/.004/.005/.007);
  **T1555** Credentials from Password Stores (.003 Browsers); **T1003** OS Credential Dumping;
  **T1558.003** Kerberoasting.
- **NIST SP 800-63B** — password storage guidance (memorized-secret verifiers, salting, KDFs).
- **CWE-916** Insufficient Computational Effort (weak password hash); **CWE-759/760** Missing/Predictable
  Salt; **CWE-522** Insufficiently Protected Credentials; **CWE-798** Use of Hard-coded Credentials.
- **OWASP** — Password Storage and Secrets Management cheat sheets.

## What you should now be able to do

- Identify common hashes on sight and give the correct Hashcat mode / John format.
- Explain fast vs slow hashes and salting, and judge crack feasibility from the hash type.
- Order an offline attack (wordlist → rules → mask → hybrid) and call the hardware honestly.
- Extract crackable material with the `*2john` family and M05/M06 collection tools.
- Find secrets across config, code, CI, tokens, and cloud credentials (browser stores conceptually), and
  assess layered impact — with the bridge to M14.
- Verify cracks and discovered secrets, handle the data under the RoE, and explain why offline cracking
  is invisible on the target and where detection actually lives.

## Progress checkpoint

```bash
py course.py complete 10.2
```
