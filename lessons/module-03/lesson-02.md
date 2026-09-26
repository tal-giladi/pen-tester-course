# 03.2 — Service &amp; version fingerprinting and enumerating common services

<div class="prereq">

**Prerequisites:** [00.1 Ethics &amp; authorization](../module-00/lesson-01.md),
[00.3 Threat modeling](../module-00/lesson-03.md),
[01.1 TCP/IP &amp; protocols](../module-01/lesson-01.md),
[02.1 Reconnaissance](../module-02/lesson-01.md),
[03.1 Host discovery &amp; port scanning](lesson-01.md).
**Module:** M03 Scanning &amp; enumeration. **Difficulty:** 🟡 intermediate.
**You will produce:** a methodical enumeration plan for a lab host, and evidence-backed findings
for two of its services — every claim tied to output you captured, not to a scanner's guess.

</div>

<div class="callout legal">

Fingerprinting and enumeration are **active** — you connect to services and read what they tell you,
which is logged. Authorization is required ([00.1](../module-00/lesson-01.md)). Every host here is a
**LAB TARGET** on the isolated network ([`labs/lab-02-recon`](../../labs/lab-02-recon/README.md));
`TARGET` always means a lab host. Do not enumerate real systems.

</div>

## Why this matters

An open port is a door with no label. `445/tcp open` could be a hardened, patched Samba or a
five-year-old Windows box with null sessions enabled — the port number is identical; the *risk* is
worlds apart. Fingerprinting reads the label (what software, what version); enumeration opens the
door a crack to inventory what's inside (shares, users, methods, config) **without exploiting
anything**. This is where most of a test's real findings actually come from. Exploits are dramatic
but rare; the finding that "this SMB server allows a null session that lists every domain user" or
"this SNMP agent answers `public` and dumps the routing table" is enumeration, and it wins
engagements. Skipping straight to exploits past thin enumeration is the most common way testers miss
the easy, high-impact issue.

## Learning objectives

- Explain what `-sV` and `-sC` actually do on the wire (probe/response matching, not magic) and
  where they get it wrong.
- State the caveats of OS detection and why you never report it as fact.
- Enumerate each common service — HTTP(S), SMB, SSH, FTP, DNS, SMTP, SNMP, databases, LDAP —
  methodically: what to extract, how, and why it matters.
- Drive and read NSE scripts, and confirm any interesting result by hand.

## Intuition

Fingerprinting is **listening to an accent**. You don't ask a service "what are you?" — it would lie
or refuse. Instead you say something innocuous and listen to *how* it answers: the exact wording of a
greeting, the header order, which error it throws for a malformed request. Every implementation has
tells, and a good database of tells (Nmap's) maps the accent to a name and version. Enumeration is
the next step: once you know you're talking to, say, SMB, you ask it the *legitimate* questions the
protocol allows anonymous callers to ask — "what shares do you have? who are your users?" — and write
down what it volunteers. You are not breaking in; you are cataloguing what it hands out for free.

## The underlying technology: how `-sV` fingerprints

`nmap -sV` opens a real connection and runs the **service-probe database** (`nmap-service-probes`):
a set of payloads, each with regexes that match known responses.

1. **Listen first.** Many services greet you unprompted (SMTP `220`, SSH `SSH-2.0-...`, FTP `220`).
   Nmap reads that banner and tries to match it before sending anything.
2. **Probe if needed.** No banner, or ambiguous? Nmap sends protocol-specific probes (an HTTP
   `GET`, a TLS hello, a MySQL greeting read) and matches the reply against its regexes.
3. **Rank by rarity.** Probes are tried in an order tuned so common services resolve fast.

The output is a *best match*, with a confidence Nmap doesn't always surface. `-sV --version-all`
tries every probe (slower, more thorough); `--version-intensity 0` only reads banners (fast, less
certain).

`nmap -sC` runs the **default set of NSE scripts** (those tagged `default`: safe, useful, non-
intrusive). `-A` bundles `-sV -sC -O --traceroute`. Neither `-sC` nor `-sV` "exploits" — but some
NSE scripts do more than read, so know your categories (below).

<div class="callout warn">

**What `-sV` gets wrong.** It reports what the banner/probe *says*, which can be (a) stripped or
faked by the admin, (b) a back-ported patch level Linux distros keep the old version string on a
fixed binary — so "vulnerable version" from a banner is a **hypothesis**, never a confirmed
vuln, and (c) a proxy/load-balancer's banner, not the real backend. Always corroborate a version
before you build a finding on it.

</div>

## OS detection caveats

`nmap -O` fingerprints the TCP/IP stack (initial window size, TTL, options ordering, ISN
generation) against a database. It is **inference from stack quirks** and is easily wrong:

- It needs at least one open and one closed port to be reliable; behind a firewall it degrades to
  guesses with low confidence.
- NAT, load balancers, and network appliances present *their* stack, not the host's.
- A raw TTL of ~64 (Linux/BSD), ~128 (Windows), ~255 (network gear) is a useful *hint* you can read
  straight off a `ping` or scan reply — but it's a hint, not an OS. Report OS as "probably Linux
  (TTL 64, OpenSSH banner)," never as fact.

## Enumerating common services — methodically

For each service: **identify → ask the legitimate questions → record what it volunteers → note the
weakness class.** Below, `TARGET` is a lab host.

### HTTP(S) — the biggest surface

Extract: server/framework and version (headers), virtual hosts, methods, TLS config, hidden paths,
default/verbose errors. Start by hand:

```text
$ curl -sI http://TARGET/
HTTP/1.1 200 OK
Server: Apache/2.4.58 (Ubuntu)
X-Powered-By: PHP/8.2.7
Set-Cookie: PHPSESSID=...; path=/          # session cookie, no HttpOnly → note it
```

Then `curl` the allowed methods (`-X OPTIONS`), fetch `/robots.txt` and `/.well-known/`, and inspect
TLS (`openssl s_client -connect TARGET:443` for cert names → more vhosts/subdomains). NSE:
`http-title`, `http-headers`, `http-methods`, `http-enum` (finds common paths). Directory
brute-forcing (feroxbuster/ffuf) belongs here but is [M07](../module-07/lesson-01.md) depth — for
enumeration, inventory the stack and obvious misconfigs. Weakness classes: outdated components,
missing security headers, exposed admin/backup paths, verbose errors leaking versions/paths. See
**OWASP WSTG** for the full checklist.

### SMB (139/445) — shares, sessions, users

The highest-yield internal service. Extract: OS/domain, SMB dialect and **signing** status, share
list, and — if a **null/guest session** is allowed — users and policies.

```text
$ nmap -p445 --script smb-protocols,smb2-security-mode,smb-os-discovery TARGET
| smb2-security-mode: message signing enabled but not required   # relay risk (M11)
| smb-os-discovery: Windows Server 2019; Domain: LAB
$ smbclient -N -L //TARGET/                # -N = no password (null session)
        Sharename       Type      Comment
        backup          Disk      (accessible anonymously!)
        IPC$            IPC
```

`enum4linux-ng TARGET` or `nmap --script smb-enum-shares,smb-enum-users` pulls shares/users where
allowed. Weakness classes: null-session information disclosure, anonymous-readable shares, signing
"not required" (NTLM relay), legacy SMBv1. A **null session that lists domain users** is a finding on
its own — it feeds credential attacks in [M10](../module-10/lesson-01.md).

### SSH (22)

Extract: version banner (implementation + OS hint), offered algorithms, and **auth methods**.

```text
$ nc TARGET 22
SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13         # banner, free of charge
$ nmap -p22 --script ssh2-enum-algos,ssh-auth-methods TARGET
| ssh-auth-methods: password, publickey       # password auth on → spray candidate (M10)
```

Weakness classes: outdated OpenSSH, weak KEX/cipher offerings, password auth exposed to the network.
You do **not** brute-force here — you note that password auth is available.

### FTP (21)

Extract: banner/version, and whether **anonymous login** works.

```text
$ ftp -inv TARGET  →  USER anonymous / PASS anything
230 Login successful.                          # anonymous allowed → enumerate files
```

NSE `ftp-anon` confirms it and lists the root. Weakness classes: anonymous read/write, cleartext
credentials on the wire, world-writable upload dirs, vulnerable server versions (e.g. vsftpd).

### DNS (53)

Extract: version (`version.bind` CHAOS query), and — the prize — a **zone transfer** (AXFR) if
misconfigured, which dumps every record.

```text
$ dig axfr lab.internal @TARGET               # succeeds only if AXFR is misconfigured
$ dig CH TXT version.bind @TARGET
```

Weakness classes: open AXFR (full internal namespace disclosure), open recursion (cache poisoning /
amplification). This overlaps M02 recon but here you're confirming it against a specific host.

### SMTP (25/587)

Extract: banner, supported verbs (`EHLO`), and **user-enumeration** via `VRFY`/`EXPN`/`RCPT`.

```text
$ nc TARGET 25
220 mail.lab ESMTP Postfix
VRFY root
252 2.0.0 root                                 # user enumeration possible
```

NSE `smtp-commands`, `smtp-enum-users`. Weakness classes: user enumeration, open relay (`nmap
--script smtp-open-relay`), version disclosure.

### SNMP (161/udp) — quietly enormous

Extract: whether a **community string** (`public`/`private`) works, then walk the MIB — interfaces,
routes, processes, installed software, sometimes credentials.

```text
$ snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.1     # system MIB
SNMPv2-MIB::sysDescr.0 = STRING: Linux TARGET 6.x ... 
$ onesixtyone -c community-list.txt TARGET         # find valid community strings fast
```

Weakness classes: default/guessable community strings (huge internal-recon win), SNMP over v1/v2c
(cleartext), writable `private` (config change). Remember it's **UDP** — apply the 03.1 UDP caveats.

### Databases (MySQL 3306, MSSQL 1433, PostgreSQL 5432, Redis 6379, Mongo 27017)

Extract: version banner, and whether **unauthenticated/default** access is allowed. Redis and Mongo
historically bind open with no auth — connect and run `INFO` / `db.stats()`. MSSQL: `nmap --script
ms-sql-info,ms-sql-ntlm-info`. Weakness classes: no-auth exposure, default creds, version-specific
RCE. Never run destructive queries.

### LDAP (389/636)

Extract: naming contexts and, if **anonymous bind** is allowed, the directory tree — users, groups,
computers, descriptions (which sometimes contain passwords).

```text
$ nmap -p389 --script ldap-rootdse,ldap-search TARGET
$ ldapsearch -x -H ldap://TARGET -s base namingContexts     # anonymous
```

Weakness classes: anonymous bind information disclosure, credentials in `description`/`info`
attributes. This is the doorway to Active Directory ([M06](../module-06/lesson-01.md)).

<div class="callout method">

**The enumeration reflex.** For every open port: (1) grab the banner by hand (`nc`/`curl`), (2) ask
what the protocol lets an anonymous caller ask, (3) record exactly what came back with the command
that produced it, (4) tag the weakness *class* — don't chase the exploit yet. Enumeration is
inventory; prioritization ([03.3](lesson-03.md)) decides what to chase.

</div>

## Tooling: NSE, and its limits

The **Nmap Scripting Engine** runs Lua scripts by category: `default`, `safe`, `discovery`,
`version`, `auth`, `brute`, `vuln`, `intrusive`, `dos`, `exploit`. `-sC` = the `default` set.

```text
$ nmap -sV -sC -p- TARGET               # version + default scripts, all ports
$ nmap --script "smb-* and not brute" -p445 TARGET   # targeted, excluding noisy brute scripts
```

<div class="callout warn">

**LIMITS.** Category names are promises, not guarantees — `brute`, `dos`, and `exploit` scripts
send real attacks and can lock accounts or crash services; never run `--script vuln`/`exploit`
outside the lab or without RoE sign-off. NSE `vuln` scripts have **false positives** (version-only
checks) and **false negatives** (back-ported patches, non-default configs). A script result is a
lead: reproduce it by hand before it becomes a finding.

</div>

**Verify by hand.** Anything NSE claims, you can re-derive: `smbclient -N -L //TARGET/` for shares,
`curl -I` for headers, `snmpwalk` for SNMP, `ldapsearch -x` for LDAP, `openssl s_client` for TLS.
When the script and the hand-check disagree, trust the hand-check and note the discrepancy.

## Practical lab

<div class="lab">

**Environment:** [`labs/lab-02-recon`](../../labs/lab-02-recon/README.md) — isolated Docker range
with a web host, an SMB host, and an SNMP-enabled host. **Time:** ~70 min. **Targets:** lab hosts
only. **Isolation:** no Internet route; reset via the `lab` helper.

</div>

1. `nmap -sV -sC -p-` one host with `--reason`. For three services, re-grab the banner by hand and
   compare to Nmap's version string. Where do they differ, and why might they?
2. On the SMB host, attempt a null session (`smbclient -N -L`); if shares list, catalogue them and
   note which are anonymously readable — with the exact command as evidence.
3. On the SNMP host, find a working community string with `onesixtyone`, then `snmpwalk` the system
   and interfaces MIBs. Record one piece of information a defender would not want exposed.
4. Pick one NSE `vuln`-adjacent result and either confirm or refute it by hand; write which and how.

## Exercise

<div class="callout method">

**Situation.** You've been authorized to enumerate a single lab host, `10.10.10.40`. Your port scan
from [03.1](lesson-01.md) returned:

```text
22/tcp   open  ssh
80/tcp   open  http
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
161/udp  open  snmp
```

No credentials were provided (black-box). The client wants to know, before any exploitation phase,
*what is actually exposed here and where the real risk sits.*

**Objective.** Produce (1) a **methodical enumeration plan** covering all five services in a sane
order, and (2) **evidence-backed findings for two** of them — your choice, but justify why those two.

**Starting information.** The port list above and the fact that it's a single host on the lab
network. Everything else you must obtain by enumerating.

**Constraints.** LAB TARGET only; enumeration, **not exploitation** — no brute force, no `--script
exploit`, no destructive queries. Every finding must carry the command that produced its evidence.

**Expected deliverables.**
1. An ordered enumeration plan: per service, what you'll extract, the exact commands, and why that
   order (what informs what).
2. For two services, a finding written to the rubric: **what / where / evidence (command + output) /
   weakness class / why it matters** — impact in business terms, not "it's bad."
3. One sentence on a result you would **not** trust from a scanner alone, and how you'd confirm it.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Order matters: which service most cheaply tells you about the *others* (OS, domain, users)? Cataloguing
identity/OS early makes every later step sharper.
</details>

<details><summary>Hint 2 — technique family</summary>
SMB null session and SNMP community strings are both "ask the legitimate anonymous questions"
techniques — high yield, no exploitation. HTTP header/stack inventory is nearly free. SSH gives you a
banner and auth methods for almost nothing.
</details>

<details><summary>Hint 3 — where to look</summary>
`smbclient -N -L`, `enum4linux-ng`, `onesixtyone` + `snmpwalk`, `curl -I` + `http-enum`, `nc :22`.
Which of these could hand you *users* or *credentials* — the things that unlock later modules?
</details>

<details><summary>Hint 4 — specific direction</summary>
Your two strongest findings are most likely the SMB null session (if it lists shares/users) and the
SNMP community string (if `public` walks the MIB) — both are information-disclosure findings that
directly enable credential attacks. Tie each to its business impact.
</details>

## Check yourself

<div class="callout key">

1. `-sV` reports `vsftpd 2.3.4`. Name three reasons that string might be misleading, and what you'd
   do before writing "vulnerable FTP" in the report.
2. Why is an SMB null session that only lists share *names* still a finding, even if you can't read
   any share?
3. You get `open|filtered` on 161/udp but a valid SNMP walk succeeds. Reconcile those two facts
   using what you learned in [03.1](lesson-01.md).
4. `-O` says "Windows" but the SSH banner says `OpenSSH ... Ubuntu`. Which do you trust, and what
   are two innocent explanations for the contradiction?

</div>

Model answers are in `solutions/module-03.md`.

## References

- **Nmap: Service &amp; Version Detection; NSE** — [nmap.org/book/vscan.html](https://nmap.org/book/vscan.html),
  [nmap.org/book/nse.html](https://nmap.org/book/nse.html).
- **OWASP Web Security Testing Guide (WSTG)** — information-gathering &amp; configuration testing.
- **RFC 3912** (WHOIS), **RFC 5321** (SMTP), **RFC 1035** (DNS), **RFC 3416** (SNMPv2 PDUs),
  **RFC 4511** (LDAP) — the protocols you enumerate.
- **MITRE ATT&CK T1046** Network Service Discovery; **T1592/T1590** gathering host/network info.
- **CIS Benchmarks** — the hardened baselines your findings are measured against.

## What you should now be able to do

- Explain what `-sV`/`-sC` do on the wire and treat their output as a hypothesis to confirm.
- Report OS detection honestly, with its caveats.
- Enumerate each common service methodically, extracting the right information and naming the
  weakness class.
- Drive NSE safely and re-derive any interesting result by hand.

## Progress checkpoint

```bash
py course.py complete 03.2
```
