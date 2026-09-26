# 02.1 — Passive reconnaissance &amp; OSINT

<div class="prereq">

**Prerequisites:** [00.1 Ethics &amp; authorization](../module-00/lesson-01.md),
[00.2 Methodology](../module-00/lesson-02.md), [00.3 Threat modeling](../module-00/lesson-03.md),
and [M01 Networking &amp; protocols](../module-01/lesson-01.md) (DNS, HTTP/HTTPS &amp; TLS — you
must understand what a DNS record and a TLS certificate *are* before you hunt for them).
**Module:** M02 Reconnaissance. **Difficulty:** 🟡 intermediate.
**You will produce:** a passive attack-surface inventory for a target organization and a written
justification of which items deserve *active* follow-up (02.2) and why.

</div>

## Why this matters

Recon is where the engagement stops being paperwork and becomes investigation — and where the most
common rookie mistake happens: firing a scanner at the target before you know what the target *is*.
Passive reconnaissance is the discipline of learning as much as possible about an organization's
attack surface **without sending a single packet the target can attribute to you**. Done well, it
means that by the time you touch anything (02.2), you already have a map: domains, subdomains,
IP ranges, technologies, people, and the forgotten assets nobody remembers deploying.

It matters for two reasons beyond efficiency. First, **the passive/active line is a legal and
OPSEC line**, not just a technical one — passive work stays within information that is already
public, while active work touches infrastructure you must be authorized to touch. Second, **the
finding is often in the passive phase**: a leaked API key in a public repo, an S3 bucket named
after the company, or a certificate for `vpn-old.corp` that reveals an asset the client forgot they
owned. Attackers start here; so do you.

## Learning objectives

By the end you can:

- Define passive reconnaissance precisely and draw the line between passive, "grey," and active.
- Enumerate an organization's public footprint from **DNS, WHOIS/RDAP, certificate transparency,
  search engines, public code, and job posts** — and know the ethical limits of each.
- Use OSINT tooling (`theHarvester`, passive `amass`/`subfinder`, Shodan/Censys) *and verify every
  result by hand*, understanding what each tool queries and where it can lie.
- Reason about OPSEC: what leaks about *you* while you recon, and how to stay quiet.
- Assemble the results into a structured attack-surface inventory that feeds threat modeling (00.3)
  and active recon (02.2).

## Intuition

Imagine casing a building before a (contracted, authorized) physical security test. You don't rattle
the doors on day one — you read the company's website, note the delivery entrance from public photos,
watch which badge readers people use, read the job posting that says "must know Cisco ASA." None of
that touches the building; all of it shapes where you'll look when you do. Passive recon is exactly
this: you assemble a picture from what the organization has *already published to the world*, so that
your later, noisier work is precise instead of a fishing expedition.

The mental model: **every organization leaks a shadow of its internal structure into public data.**
DNS records mirror their services. Certificates mirror their hostnames. Job posts mirror their tech
stack. Developers' public repos mirror their code — and sometimes their secrets. Your job is to
collect that shadow and reconstruct the shape casting it.

## The underlying technology: what "public" data exposes

Passive recon draws on sources that exist independently of the target's servers, so querying them
tells the target nothing:

- **DNS** (RFC 1035) — the public directory of the Internet. Passive DNS databases (built by
  resolvers logging what they've seen) let you look up historical and current records *without
  querying the target's own nameservers*. You'll do live DNS in 02.2; here you mine what's already
  recorded.
- **WHOIS / RDAP** — registration data for domains and IP blocks. WHOIS is the legacy text protocol;
  **RDAP** (RFC 9082/9083) is its structured, JSON, access-controlled successor and is what you
  should prefer in 2026. <span class="badge current">CURRENT</span> Registrant details are often
  redacted for privacy now, but **IP-block ownership, ASN, registration dates, and nameservers**
  remain gold.
- **Certificate Transparency (CT)** — every TLS certificate issued by a public CA is logged to
  append-only public logs (RFC 6962). Because certificates carry hostnames (including
  Subject Alternative Names), CT logs are the single richest passive source of **subdomains** —
  including internal-sounding ones that were never meant to be found. `crt.sh` is the common
  front-end.
- **Search engines &amp; "dorking"** — indexed pages, exposed directories, and file types, queried
  with precise operators.
- **Public code** — GitHub/GitLab and package registries, where source, config, and sometimes
  **secrets** leak.
- **Job posts, LinkedIn, conference talks** — an organization advertises its tech stack and its
  people when it hires and speaks.
- **Breach-data awareness** — the *knowledge* that credentials for a domain have appeared in public
  breach corpora is a legitimate risk signal; handling that data has hard ethical limits (below).

## The passive / active line — and why it is legal, not just polite

<div class="callout legal">

**Passive = you touch only third parties' public records; the target cannot see you.** The moment a
packet reaches infrastructure the target owns — a DNS query to *their* nameserver, an HTTP request
to *their* web server, a port scan — you are doing **active** recon, which **requires authorization**
(00.1). Some sources are genuinely grey: querying a public passive-DNS API is passive; running `dig`
against the target's authoritative nameserver is active. When in doubt, treat it as active and check
your scope.

Two firm ethical limits, regardless of scope:
- **Never enumerate real third parties.** Everything in this course targets the course's
  `*.lab` domains and lab hosts (e.g. `northwind.lab`) resolved by the lab resolver `10.13.0.53`.
  Do not point these techniques at a real organization you have not been authorized to test — OSINT
  against a real company is still recon *of that company*, and running it "just to practice" can
  breach a provider's terms and your local law.
- **Breach data and PII.** Knowing a domain appears in a breach corpus is a risk signal you may
  report. **Downloading, storing, or logging into anything with** breach-sourced credentials is not
  passive recon — it is unauthorized access and mishandling of personal data. Stay on the right side
  of this line even when it is technically easy to cross.

</div>

<div class="callout method">

**Passive-first is the professional reflex.** You gather the free, silent intelligence *before* you
generate a single log line on the target. It makes your active phase faster, quieter, and more
defensible — and occasionally hands you the finding before you ever "attack."

</div>

## How a tester uses passive recon

You are answering four questions and writing the answers down (00.2 note discipline):

1. **What domains and IP ranges does this organization own?** (Roots for everything else.)
2. **What subdomains and hosts exist?** (CT logs and passive DNS, before you brute-force in 02.2.)
3. **What technologies and versions are in play?** (Headers seen by third parties, job posts, repos.)
4. **Who are the people and what do they leak?** (Emails, usernames, secrets in code.)

Every answer is a candidate node on the attack-surface map — and every one gets a note on whether
it warrants *active* follow-up.

## Manual investigation — do it by hand first

### WHOIS / RDAP: who owns what

Registration data anchors the whole picture. RDAP output for an IP block tells you the owning
organization and the CIDR range — which lets you expand from one host to a whole netblock:

```text
$ whois 203.0.113.10          # (illustrative fields — RDAP gives the same, as JSON)
NetRange:       203.0.113.0 - 203.0.113.255
CIDR:           203.0.113.0/24
NetName:        NORTHWIND-CORP
OrgName:        Northwind Retail Ltd
OrgId:          NWND
NameServer:     NS1.NORTHWIND.LAB
NameServer:     NS2.NORTHWIND.LAB
```

The netblock (`203.0.113.0/24`) and the nameservers (`ns1/ns2.northwind.lab`) are both leads: one
bounds an IP range worth mapping, the other names DNS infrastructure to enumerate actively later.
Domain WHOIS registrant fields are frequently privacy-redacted in 2026 — don't rely on them; the
**structural** fields (registrar, nameservers, creation date, ASN) survive redaction.

### Certificate transparency: the subdomain goldmine

CT logs record every publicly-trusted certificate. Query `crt.sh` for a domain and you get every
hostname a CA ever put in a certificate for it — often revealing hosts that resolve internally and
were never linked anywhere:

```bash
# Passive: this hits crt.sh, NOT the target. Pull unique names as JSON.
curl -s 'https://crt.sh/?q=%25.northwind.lab&output=json' \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```

```text
api.northwind.lab
autodiscover.northwind.lab
dev.northwind.lab
mail.northwind.lab
shop.northwind.lab
vpn.northwind.lab
vpn-old.northwind.lab        ← a decommissioned-sounding host worth a hard look
```

`vpn-old.northwind.lab` is exactly the kind of forgotten asset that becomes a finding. Note it as a
**high-priority active follow-up** — but you have not yet confirmed it resolves or responds; that's
02.2's job.

### Search-engine dorking (framed for authorized use)

Search operators narrow the index to what matters. Framed for a scope you are authorized against:

```text
site:northwind.lab -www              # indexed hosts other than the main site
site:northwind.lab ext:pdf | ext:xls # documents that may carry metadata / internal data
site:northwind.lab inurl:admin       # admin-ish paths the crawler already found
intitle:"index of" site:northwind.lab   # exposed directory listings
```

These read a *third party's* (the search engine's) index, so they're passive. The results are
leads, not confirmations — the search engine's cache can be stale, and a hit is only real once you
verify it (in 02.2, within scope).

### Public code and leaked secrets

Developers publish more than they intend. A GitHub search across an org's public repos for strings
like `northwind.lab`, `AWS_SECRET`, `apikey`, or `BEGIN RSA PRIVATE KEY` surfaces hardcoded
credentials and internal hostnames. This is legitimate passive recon *when the repos are public and
in scope*.

<div class="callout warn">

If you find a live secret (a key, a token, a password), that is a **finding**, not a toy. Record its
location and the fact that it is exposed; do **not** use it to authenticate unless your RoE
explicitly authorizes it and the target system is in scope. Using a leaked credential is active,
authenticated access — the exact thing 00.1 says needs authorization.

</div>

## Tooling — what each does, its limits, and how to verify by hand

Tools *aggregate* the sources above quickly. They never replace the manual check, because they cache,
rate-limit, and silently drop sources.

- **`theHarvester`** — aggregates emails, subdomains, hosts, and names from many public sources
  (search engines, CT, passive DNS). Key options: `-d <domain>`, `-b <sources>` (e.g.
  `crtsh,bing,duckduckgo`). *Limits:* depends entirely on which source APIs are reachable and keyed;
  results vary run-to-run. *Verify:* re-query the underlying source (crt.sh, the search engine)
  yourself for anything you'll act on.
- **`amass enum -passive`** and **`subfinder`** — subdomain aggregation from dozens of passive
  sources (CT, passive DNS, APIs). `subfinder -d northwind.lab -silent`; `amass enum -passive -d
  northwind.lab`. *Limits:* passive mode does **not** confirm a host is live — it lists names other
  people have seen. *Verify:* resolution and liveness are an *active* step (02.2 with `dnsx`/`httpx`).
- **Shodan / Censys** — Internet-wide scan databases. You query *their* stored scan results, so a
  lookup is passive from the target's view. Great for "what services and banners are exposed on this
  netblock," `ssl.cert.subject.cn:` pivots, and finding hosts by favicon hash. *Limits &amp; ethics:*
  the data can be stale, and these are powerful enough that you must stay within scope — a Censys
  query is passive, but acting on what it shows is not. *Verify:* confirm the service is actually
  live and in scope before you rely on it.
- **`whois` / RDAP clients** — as above; prefer RDAP (`rdap.org`, or a client like `whois` with
  RDAP support) for structured, current data. *Verify:* cross-check ASN/netblock ownership via a
  routing looking-glass or `bgp.tools`.

<div class="callout recon">

**Aggregators disagree, and that's useful.** Run two subdomain sources and diff them: names only one
finds are worth extra attention (a fresh CT entry the other's cache missed, or a stale name that no
longer resolves). The union is your candidate list; resolution in 02.2 turns candidates into
confirmed surface.

</div>

## OPSEC — what leaks about *you*

Passive recon is quiet by definition, but "passive" is not "invisible":

- **Third-party queries can be logged and correlated.** A burst of `crt.sh`, Shodan, and GitHub
  searches for one domain, from one IP, in one minute, is a pattern. For most authorized engagements
  this is fine; for red-team work where stealth is in the RoE, pace yourself and consider from where
  you query.
- **Never let a "passive" tool go active without you noticing.** Many subdomain tools have a
  resolve/brute step one flag away. Read the flags; know exactly when you cross the line onto the
  target's infrastructure.
- **Your own attribution.** Logging into the target's own portals, or fetching its pages, ties your
  IP/browser to the recon. Keep truly passive work off the target entirely.

## Building the inventory

The deliverable of passive recon is a structured inventory that flows straight into threat modeling
(00.3) and active recon (02.2). A workable shape:

```text
ORG: Northwind Retail   scope: *.northwind.lab + owned netblocks
- domains:    northwind.lab (registrar X, NS ns1/ns2.northwind.lab, created 2019)
- netblocks:  203.0.113.0/24 (RDAP: NORTHWIND-CORP)   [confirm ownership]
- subdomains (passive, UNVERIFIED):
    shop, api, mail, vpn, vpn-old, dev, autodiscover   [source: crt.sh, subfinder]
- tech signals: "Cisco ASA" (job post); nginx (Shodan banner on .10)   [unconfirmed]
- people/emails: a.smith@, it-help@ (theHarvester)     [for later, ethically]
- exposures:  possible API key in gh:northwind/config  [FINDING — do not use]
- follow-up (active, 02.2): resolve all subdomains; vpn-old = priority; map .0/24
```

Every row carries its **source** and whether it is **verified**. Unverified passive data is a
hypothesis, not a fact — that distinction is what keeps your later report honest.

## Practical lab

<div class="lab">

**Environment:** the course recon lab (`lab-02-recon`), which serves DNS, web, and hidden services
on a private range with the lab resolver at `10.13.0.53`. **Time:** ~50 min. **Targets:** the lab's
`northwind.lab` estate only — LAB TARGETS, isolated, no Internet route. Run `./labs/lab check`
first. **This lesson's passive sources (crt.sh, WHOIS) are simulated inside the lab** so nothing
leaves your machine.

</div>

1. From the lab's provided public artifacts (a captured `crt.sh` JSON export, a WHOIS record, and a
   search-index dump under the lab's `osint/` directory), build the inventory above **without
   querying any `northwind.lab` host directly**.
2. For every subdomain, record the *source* and mark it UNVERIFIED.
3. Write, for three of the subdomains, one sentence each on whether it warrants active follow-up and
   why (impact × likelihood, per 00.3). Do not resolve them yet — that's 02.2.

## Exercise

<div class="callout method">

**Situation.** You have a signed authorization to test **Northwind Retail**, scope `*.northwind.lab`
plus any netblocks Northwind owns. It is day one. You may **not** touch any Northwind-owned
infrastructure yet — active testing is authorized only from tomorrow. Today is passive-only.

**Objective.** Produce a **passive attack-surface inventory** and a **prioritized active-recon
plan** for tomorrow — decide, with justification, what is worth actively investigating first and
what is noise.

**Starting information.** The domain `northwind.lab`; the lab's `osint/` artifacts (a `crt.sh` JSON
export, a WHOIS/RDAP record for the domain and one IP, a search-index dump, and one public repo
listing). Nothing else — you must not query Northwind hosts today.

**Constraints.** Passive only: no packet may reach a Northwind-owned host or nameserver. LAB TARGETS
only. If you find a secret, treat it as a finding — do not use it. Assume nothing you can't source.

**Expected deliverables.**
1. An inventory grouped as *domains / netblocks / subdomains (with source + UNVERIFIED) / tech
   signals / people / exposures*.
2. A ranked list of the top items to actively investigate tomorrow, each with a one-line
   impact × likelihood rationale referencing 00.3, and the *cheapest* active check you'd run first.
3. A short note identifying the single **most interesting passive finding** and the ethical
   constraint that governs how you handle it.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Which sources here are truly passive (touch only third parties) and which would cross onto Northwind
infrastructure? Everything you do today must stay in the first group. Rank by the threat-modeling
lens from 00.3, not by what looks fun.
</details>

<details><summary>Hint 2 — technique family</summary>
CT logs and passive DNS give you names; WHOIS/RDAP gives you netblocks and nameservers; the repo and
search dump give you tech and possibly secrets. A name in a CT log is a <em>hypothesis</em> until
tomorrow's resolution confirms it.
</details>

<details><summary>Hint 3 — where to look</summary>
Look for the odd one out in the subdomain list — names with <code>old</code>, <code>dev</code>,
<code>test</code>, <code>staging</code>, or <code>vpn</code> in them. Forgotten and non-production
assets are where impact and likelihood are both high.
</details>

<details><summary>Hint 4 — specific direction</summary>
Your most interesting finding is probably the exposed secret or the decommissioned-sounding host.
The secret is a finding you record but must not <em>use</em> (that's authenticated, active access);
the old host is a top active-recon target for tomorrow. Say which is which and why.
</details>

## Check yourself

<div class="callout key">

1. You run `subfinder` and it returns `payments.northwind.lab`. Is that host confirmed to exist?
   What exactly have you learned, and what have you *not*?
2. A `crt.sh` query for `northwind.lab` returns `internal-crm.northwind.lab`. Why does a certificate
   for an "internal" host end up in a public log, and what does that tell you about CT as a source?
3. You find a valid-looking AWS key in a public Northwind repo. Your RoE authorizes testing
   `*.northwind.lab`. May you use the key? Explain using the passive/active line.
4. Why is querying Shodan for a target's netblock passive, while running `nmap` against the same
   netblock is not — even though both tell you about open ports?
5. A teammate says "WHOIS is dead, registrants are all redacted now." What structural value does
   WHOIS/RDAP still give you?

</div>

Model answers and discussion are in `solutions/module-02.md` (instructor material — try them first).

## References

- **RFC 1035** — Domain Names: Implementation and Specification (the DNS data you're mining).
- **RFC 9082 / RFC 9083** — RDAP query format and JSON responses (the modern WHOIS successor).
- **RFC 6962** — Certificate Transparency (why every public cert's hostnames are logged).
- **OWASP WSTG** — WSTG-INFO-01/02 (Conduct Search Engine Discovery Reconnaissance; Fingerprint Web
  Server) — the information-gathering methodology.
- **NIST SP 800-115** §4 — Review Techniques (passive information gathering).
- **OSINT Framework** (osintframework.com) and **theHarvester** / **crt.sh** documentation.
- Provider terms you must respect: search-engine and Shodan/Censys acceptable-use policies.

## What you should now be able to do

- State exactly where the passive/active line is and why it is a legal and OPSEC line.
- Enumerate an organization's public footprint from DNS, WHOIS/RDAP, CT logs, search engines,
  public code, and job posts — ethically and within scope.
- Use OSINT aggregators and *verify every actionable result at its source*.
- Assemble a sourced, verification-flagged attack-surface inventory that feeds threat modeling and
  hands active recon a prioritized plan.

## Progress checkpoint

```bash
py course.py complete 02.1
```
