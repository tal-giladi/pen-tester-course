# 02.2 — Active reconnaissance: DNS enumeration, subdomain discovery &amp; attack-surface inventory

<div class="prereq">

**Prerequisites:** [00.1 Ethics &amp; authorization](../module-00/lesson-01.md),
[00.3 Threat modeling](../module-00/lesson-03.md),
[M01 Networking &amp; protocols](../module-01/lesson-01.md) (DNS, HTTP/HTTPS &amp; TLS), and
[02.1 Passive reconnaissance &amp; OSINT](lesson-01.md) — you should arrive here with a passive
inventory of *candidate* names and netblocks to confirm.
**Module:** M02 Reconnaissance. **Difficulty:** 🟡 intermediate.
**You will produce:** a verified, evidence-backed, **prioritized** external attack-surface map for
the lab's `northwind.lab` estate.

</div>

## Why this matters

Passive recon (02.1) gave you a pile of *hypotheses* — names in CT logs, netblocks from RDAP, tech
signals from job posts. Active reconnaissance is where you **confirm** them: you send packets to the
target's own infrastructure to learn what actually resolves, what actually responds, and what it
actually runs. That confirmation is the difference between "crt.sh mentioned `vpn-old.northwind.lab`"
and "`vpn-old.northwind.lab` resolves to 203.0.113.7 and serves a login page on 443."

The catch is in the first sentence: **you are now touching the target.** Active recon generates logs
on the client's systems and is unambiguously in the "requires authorization" category (00.1). Done
carelessly it's noisy, it can knock over fragile services, and it can stray out of scope one wildcard
at a time. Done well, it turns your candidate list into a confirmed, prioritized attack-surface map —
the direct input to scanning and enumeration (M03) and the rest of the engagement.

## Learning objectives

By the end you can:

- Enumerate DNS actively: the record types that matter, forward and reverse lookups, **zone-transfer
  attempts**, and controlled brute-forcing.
- Discover subdomains three ways — passive ingestion, active resolution/brute-force, and
  **permutation** — and pivot from certificates you retrieve live.
- Discover **virtual hosts** behind a shared IP and fingerprint the technology stack from live HTTP.
- Verify every tool's output by hand and turn confirmed surface into a **prioritized** attack-surface
  map, ranked with the threat-modeling lens from 00.3.

## Intuition

You have a list of maybe-doors from 02.1. Active recon is walking up and checking which are real
doors, where each one is, and what kind of door it is — quietly, and only on the property you're
authorized to be on. DNS is the building directory: ask it what names exist and where they point.
Certificates and HTTP responses are the nameplates on the doors: they tell you what's behind them.
Your goal is not to open anything yet (that's exploitation) — it's to produce an accurate, ranked
map so that when you *do* start knocking (M03), you knock on the right doors first.

## The underlying technology: DNS, and where it leaks

DNS (RFC 1035) resolves names to data through **resource records**. The types a tester cares about:

| Record | Carries | Why a tester wants it |
|---|---|---|
| **A / AAAA** | IPv4 / IPv6 address | The host actually exists and is *here* — confirms a candidate. |
| **CNAME** | Alias to another name | Reveals third-party SaaS (dangling CNAME = subdomain-takeover risk). |
| **NS** | Authoritative nameservers | The DNS infrastructure to query and possibly transfer from. |
| **MX** | Mail servers | Mail infrastructure; often points at the provider (tech signal). |
| **TXT** | Arbitrary text (SPF, DKIM, verification) | SPF/DKIM leak sending hosts; verification tokens leak SaaS in use. |
| **SOA** | Zone authority &amp; serial | Confirms who's authoritative; serial hints at change cadence. |
| **PTR** | IP → name (reverse) | Reverse-maps a netblock to names — expands surface from an IP. |

### Zone transfers (AXFR) — the classic misconfiguration

A **zone transfer** (`AXFR`) is the mechanism a secondary nameserver uses to copy an entire zone
from a primary. It is meant to be restricted to authorized secondaries. When a nameserver is
misconfigured to answer AXFR for *anyone*, it hands you **every record in the zone at once** — the
complete internal name map, no brute-forcing needed. It is increasingly rare on well-run
infrastructure <span class="badge deprecated">DEPRECATED misconfig</span> but still turns up, and
costs one command to check, so you always check.

<div class="callout recon">

**Why the weakness exists.** AXFR predates the modern threat model — it was designed when the
concern was replication reliability, not confidentiality of names. Default-open or copy-pasted
configs, and forgotten legacy secondaries, leave it exposed. It's the DNS equivalent of leaving the
building directory in the lobby: not an exploit, but a gift of the entire map.

</div>

## How a tester recognizes high-value surface

While enumerating, flag the patterns that 00.3 taught you to value:

- **Non-production names** — `dev`, `test`, `staging`, `uat`, `old`, `legacy`, `beta`. Weaker
  controls, older code, real data. High likelihood × often high impact.
- **Access and identity infrastructure** — `vpn`, `sso`, `adfs`, `citrix`, `remote`, `owa`. The
  front doors to the internal network.
- **Dangling CNAMEs** — a subdomain aliased to a deprovisioned cloud resource = subdomain-takeover
  candidate.
- **Wildcard DNS** — `*.northwind.lab` resolving everything to one IP will make naive brute-forcing
  return garbage; recognize it so you don't chase ghosts.

## Manual investigation — DNS by hand

Always start with `dig`; it shows you exactly what the resolver returned, unembellished. In the lab,
`@10.13.0.53` is the lab resolver.

```bash
# Records for a known name (confirm a passive candidate resolves)
$ dig +noall +answer shop.northwind.lab @10.13.0.53
shop.northwind.lab.     300  IN  A     203.0.113.10

# The zone's nameservers and mail/text records (each a lead)
$ dig +noall +answer northwind.lab NS  @10.13.0.53
northwind.lab.          3600 IN  NS    ns1.northwind.lab.
northwind.lab.          3600 IN  NS    ns2.northwind.lab.
$ dig +short northwind.lab MX  @10.13.0.53
10 mail.northwind.lab.
$ dig +short northwind.lab TXT @10.13.0.53
"v=spf1 include:_spf.northwind.lab ip4:203.0.113.0/24 -all"   ← SPF leaks a sending netblock
```

### The zone-transfer attempt

Try AXFR against each authoritative nameserver. On a well-configured server you get a refusal; on a
misconfigured one, the entire zone:

```bash
$ dig axfr northwind.lab @ns1.northwind.lab
; <<>> DiG <<>> axfr northwind.lab @ns1.northwind.lab
northwind.lab.          3600 IN  SOA   ns1.northwind.lab. admin.northwind.lab. 2026091501 ...
northwind.lab.          3600 IN  NS    ns1.northwind.lab.
shop.northwind.lab.     300  IN  A     203.0.113.10
api.northwind.lab.      300  IN  A     203.0.113.11
dev.northwind.lab.      300  IN  A     203.0.113.20
vpn-old.northwind.lab.  300  IN  A     203.0.113.7
internal-crm.northwind.lab. 300 IN A   10.20.0.15          ← an internal-only address, leaked
northwind.lab.          3600 IN  SOA   ns1.northwind.lab. admin.northwind.lab. 2026091501 ...
```

```bash
# The refusal you'll usually get from a well-run server:
$ dig axfr northwind.lab @ns2.northwind.lab
; Transfer failed.
```

If AXFR succeeds you are done enumerating names for that zone — you have all of them, authoritatively.
Note that `internal-crm` points at RFC 1918 space (`10.20.0.15`): a name that only matters once you
have internal access, but a valuable map of what's *there*.

### Reverse DNS across a netblock

With a netblock from RDAP (02.1), reverse-resolve it to expand names:

```bash
$ for ip in 203.0.113.{1..20}; do
    dig +short -x "$ip" @10.13.0.53 | sed "s/$/  <- $ip/"
  done
mail.northwind.lab.   <- 203.0.113.5
vpn-old.northwind.lab.  <- 203.0.113.7
shop.northwind.lab.   <- 203.0.113.10
```

## Manual investigation — HTTP and virtual hosts by hand

One IP frequently serves **many** sites via the HTTP `Host` header (name-based virtual hosting).
Certificates and default pages leak which. `curl` is the ground truth:

```bash
# What does the IP serve by default, and what does it admit about itself?
$ curl -sI https://203.0.113.10 --resolve 203.0.113.10:443:203.0.113.10 -k
HTTP/1.1 200 OK
Server: nginx/1.27.1
X-Powered-By: PHP/8.3.6
Set-Cookie: PHPSESSID=...; path=/
X-Frame-Options: SAMEORIGIN

# Same IP, different Host header — a vhost that isn't the default site:
$ curl -sI https://203.0.113.10 -H 'Host: dev.northwind.lab' -k
HTTP/1.1 200 OK
Server: nginx/1.27.1
X-Debug-Mode: on               ← a dev vhost with debugging left enabled
```

The `Server` and `X-Powered-By` headers, cookie names (`PHPSESSID`, `JSESSIONID`, `.AspNetCore`),
and security headers are all **fingerprint** signals — they tell you the stack without a scanner.
Fetching `robots.txt` and `sitemap.xml` (now that you're authorized and active) reveals paths the
site itself advertises:

```text
$ curl -s https://shop.northwind.lab/robots.txt
User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /api/internal/
Sitemap: https://shop.northwind.lab/sitemap.xml
```

`robots.txt` is not a security control — it's a list of paths the operator *wanted hidden*, which
makes `/admin/` and `/backup/` immediate leads.

## Tooling — what each does, key options, limits, verify by hand

- **`dnsx`** — fast bulk DNS resolver/toolkit. Feed it candidate names to confirm which resolve:
  `dnsx -l names.txt -a -resp -r 10.13.0.53`. *Limits:* answers only what DNS says, not liveness of
  the service. *Verify:* `dig` any name you'll act on.
- **`dnsrecon` / `dnsenum`** — all-in-one DNS enumeration: record types, AXFR attempt, brute-force,
  reverse ranges. `dnsrecon -d northwind.lab -n 10.13.0.53 -t axfr,brt`. *Limits:* the brute-force
  is only as good as its wordlist; wildcard zones fool it. *Verify:* confirm the AXFR result with a
  raw `dig axfr`.
- **`subfinder`** (active resolve) / **`amass enum -active`** — take aggregated names and *resolve*
  them, and (amass) can brute-force and do reverse sweeps. *Limits:* active mode touches the target —
  authorization required; can be noisy. *Verify:* diff against your passive list; investigate names
  only one source found.
- **Permutation tools — `gotator`, `altdns`, `puredns`** — generate variations
  (`dev-api`, `api-staging`, `shop2`) from known names and mass-resolve them with `puredns` (which
  also filters wildcards). *Limits:* huge candidate lists → volume; needs wildcard filtering or every
  answer looks live. *Verify:* resolve with `dnsx`; spot-check with `dig`.
- **vhost discovery — `ffuf` / `gobuster vhost`** — brute the `Host:` header against one IP to find
  name-based vhosts that DNS didn't reveal:
  `ffuf -w vhosts.txt -u https://203.0.113.10 -H 'Host: FUZZ.northwind.lab' -fs <baseline-size>`.
  *Limits:* you must filter the default-response size (`-fs`) or everything looks like a hit.
  *Verify:* re-request the interesting vhost with `curl -H 'Host: ...'`.
- **`httpx`** — probe a list of hosts for live HTTP(S), titles, status, tech, and TLS SANs:
  `httpx -l hosts.txt -title -tech-detect -status-code -tls-grab`. *Limits:* fingerprints are
  heuristics; version guesses can be wrong. *Verify:* `curl -sI` the host and read the headers.
- **`Wappalyzer`** (and httpx tech-detect) — technology fingerprinting from response
  fingerprints. *Limits:* infers from patterns; a stripped/masked server defeats it. *Verify:*
  headers, cookies, and specific file paths by hand.

<div class="callout method">

**Certificate-transparency pivoting, live.** In 02.1 you read CT logs passively. Now, actively,
retrieve the live certificate and read its Subject Alternative Names — they often list *sibling*
hostnames sharing the cert:

```bash
$ echo | openssl s_client -connect 203.0.113.10:443 -servername shop.northwind.lab 2>/dev/null \
    | openssl x509 -noout -text | grep -A1 'Subject Alternative Name'
    X509v3 Subject Alternative Name:
        DNS:shop.northwind.lab, DNS:www.northwind.lab, DNS:checkout.northwind.lab
```

`checkout.northwind.lab` may not have appeared in your passive list — a new lead, confirmed live.

</div>

## Turning discovery into a prioritized attack-surface map

Enumeration produces a list; the *deliverable* is a **ranked** map. Apply 00.3 directly: score each
confirmed asset by **impact × likelihood**, note the trust boundary it sits on, and record the
evidence that it exists. A workable form:

```text
CONFIRMED EXTERNAL SURFACE — northwind.lab   (evidence: dig/curl output filed per row)
| host                     | IP          | service        | signal                | priority | why (00.3)                        |
|--------------------------|-------------|----------------|-----------------------|----------|-----------------------------------|
| vpn-old.northwind.lab    | 203.0.113.7 | 443 (login)    | old VPN, self-signed  | HIGH     | identity edge + "old" = weak/CVE  |
| dev.northwind.lab        | 203.0.113.20| 443 (vhost)    | X-Debug-Mode: on      | HIGH     | non-prod, debug leaks, real data  |
| api.northwind.lab        | 203.0.113.11| 443 (JSON)     | PHP 8.3               | MED      | app logic, authz surface (→M08)   |
| shop.northwind.lab       | 203.0.113.10| 443 (web)      | nginx/PHP, /admin,/backup | MED  | main app; robots leaks paths      |
| internal-crm.northwind.lab | 10.20.0.15| — (internal)   | AXFR leak             | LATER    | not reachable externally yet      |
```

Each row is a hypothesis for M03 to enumerate and, later, test. The ranking is the point: it tells
you and the client *where the limited time goes first*, and it's defensible because every row cites
evidence and an impact/likelihood rationale.

<div class="callout legal">

**Active recon touches the target — authorization is mandatory.** Everything on this page sends
packets to the target's DNS and web infrastructure. That is authorized here only because the target
is the isolated lab estate (`northwind.lab`, resolver `10.13.0.53`) shipped in `labs/lab-02-recon` —
LAB TARGETS on a private network with no Internet route. Never run AXFR attempts, subdomain
brute-forcing, vhost fuzzing, or reverse sweeps against a real organization without written scope and
RoE covering exactly those hosts. Watch scope creep in DNS: a CNAME can point out of scope, and
reverse DNS on a shared netblock can enumerate a *neighbor's* hosts — stop at the boundary and treat
anything outside it as a finding to report, not to probe (00.1).

</div>

## Practical lab

<div class="lab">

**Environment:** `lab-02-recon` — DNS (authoritative NS with a deliberately AXFR-open secondary),
web with several vhosts, and hidden services, on a private range; lab resolver `10.13.0.53`.
**Time:** ~75 min. **Targets:** the `northwind.lab` estate only — LAB TARGETS, isolated, no Internet
route. Run `./labs/lab up lab-02-recon` then **`./labs/lab check`** before you touch anything.

</div>

1. Confirm your 02.1 candidate names with `dig`/`dnsx` against `10.13.0.53`; mark each resolved/not.
2. Attempt AXFR against **each** nameserver; capture the one that succeeds and diff its names against
   your candidate list — what did the transfer reveal that CT logs didn't?
3. Find at least one virtual host that DNS alone didn't show (vhost fuzz + `curl -H 'Host:'`), and
   fingerprint the stack of three hosts from their live headers.
4. Pivot on a live certificate's SANs for one more name.
5. Assemble the confirmed, evidence-backed, prioritized map (table above). File the `dig`/`curl`
   output as evidence per row.

## Exercise

<div class="callout method">

**Situation.** Same engagement as 02.1, now day two: active testing of `*.northwind.lab` and
Northwind-owned netblocks is authorized. You bring yesterday's passive inventory of candidate names
and netblocks.

**Objective.** Produce a **verified, prioritized external attack-surface map** — every entry backed
by evidence you captured, every priority justified with the 00.3 impact × likelihood lens, ready to
hand to M03 (scanning &amp; enumeration).

**Starting information.** Your 02.1 inventory; the lab estate `northwind.lab`; resolver `10.13.0.53`;
the netblock from RDAP. Nothing is confirmed until *you* confirm it.

**Constraints.** LAB TARGETS only; `./labs/lab check` must pass first. Stay in scope — if a CNAME or
a reverse lookup points outside `northwind.lab`/the owned netblock, stop and record it as a scope
note, don't probe it. No exploitation — this is recon; you map, you don't open.

**Expected deliverables.**
1. A confirmed subdomain/host list, each with the **evidence** (the `dig`/`curl`/`httpx` output) and
   the discovery method (passive-confirmed / AXFR / brute / permutation / vhost / cert-SAN).
2. The result of the zone-transfer attempt on each nameserver, with the captured output.
3. A **prioritized** attack-surface map (the table form above): host, IP, service, fingerprint,
   priority, and a one-line impact × likelihood rationale citing the trust boundary each sits on.
4. One paragraph: which two hosts you'd hand M03 to enumerate first, and why.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
You're converting hypotheses (passive names) into facts (resolved + responding) and then ranking the
facts. Confirmation is cheap; ranking is where the skill is. Lead with the 00.3 question: which asset,
if weak, hurts the crown-jewel data most?
</details>

<details><summary>Hint 2 — technique family</summary>
Three subdomain paths — resolve the passive list (<code>dnsx</code>), brute + permute new names
(<code>puredns</code>/<code>gotator</code> with wildcard filtering), and pivot on live cert SANs.
Then vhost-fuzz the busy IPs for names DNS never advertised. Try AXFR first — it can make the rest
unnecessary.
</details>

<details><summary>Hint 3 — where to look</summary>
Attempt <code>dig axfr</code> against <em>every</em> NS, not just the first — misconfigurations
often live on a forgotten secondary. Watch for wildcard DNS (every random name resolves): if you see
it, your brute-force needs wildcard filtering or every result is a false positive.
</details>

<details><summary>Hint 4 — specific direction</summary>
Rank the non-production and identity-edge hosts (<code>dev</code>, <code>vpn-old</code>) above the
hardened main site: weaker controls, older software, and often the same data. A host that only
resolves to RFC 1918 space (from AXFR) isn't externally reachable yet — note it for post-foothold,
don't prioritize it for external testing.
</details>

## Check yourself

<div class="callout key">

1. Your AXFR attempt against `ns1` is refused but succeeds against `ns2`. What does that tell you
   about the organization's DNS, and why do you always try every nameserver?
2. A subdomain brute-force returns 4,000 "live" hosts for a domain you expected to have a dozen.
   What's the most likely explanation, and how do you confirm it in one `dig` command?
3. You find `promo.northwind.lab` is a CNAME to `northwind-promo.s3.amazonaws.com`, which returns
   *NoSuchBucket*. Why is that potentially serious, and is chasing it still within scope?
4. Two hosts resolve to the same IP but return different pages depending on the `Host` header. What
   is happening, and how did you (or would you) discover the second one?
5. You have `dev.northwind.lab` (debug on, non-prod) and `shop.northwind.lab` (hardened, production,
   the money-maker). M03 time is limited. Which do you enumerate first, and what's the argument you'd
   give the client?

</div>

Model answers in `solutions/module-02.md` (instructor material — attempt them first).

## References

- **RFC 1035** — Domain Names: Implementation and Specification (record types; AXFR in the STD 13
  set with RFC 5936 for the modern AXFR protocol).
- **RFC 6962** — Certificate Transparency (the source you pivot on, passively and live via SANs).
- **OWASP WSTG** — WSTG-INFO-04 (Enumerate Applications on Webserver — incl. vhosts &amp;
  non-standard ports), WSTG-INFO-02 (Fingerprint Web Server), WSTG-INFO-10 (Map Application
  Architecture).
- **NIST SP 800-115** §4 — active information gathering and network mapping.
- **MITRE ATT&CK** — T1590 (Gather Victim Network Information), T1595 (Active Scanning), T1596
  (Search Open Technical Databases) — how this phase maps to adversary behavior.
- Tool docs: ProjectDiscovery **subfinder / dnsx / httpx**, **amass**, **dnsrecon**, **puredns**.

## What you should now be able to do

- Enumerate DNS actively — the record types that matter, reverse sweeps, and a zone-transfer attempt
  against every nameserver — and read the results by hand.
- Discover subdomains by passive confirmation, active brute-force, and permutation, filtering
  wildcards so you don't chase ghosts.
- Discover virtual hosts and fingerprint the stack from live HTTP, verifying every tool with `curl`.
- Turn confirmed surface into a prioritized, evidence-backed attack-surface map that hands M03 a
  ranked plan — all strictly within authorized scope.

## Progress checkpoint

```bash
py course.py complete 02.2
```
