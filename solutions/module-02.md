# Instructor / solutions — Module 02 (Reconnaissance)

> **Instructor material.** Not linked from `_sidebar.md`. Have students do the exercises before
> reading. All work targets the isolated `lab-02-recon` `northwind.lab` estate (resolver
> `10.13.0.53`); never a real organization.

## 02.1 — Passive reconnaissance &amp; OSINT

**Exercise (Northwind, passive-only day one).** A strong submission:

- **Inventory, grouped and sourced.**
  - *Domains:* `northwind.lab` — registrar, NS `ns1/ns2.northwind.lab`, creation date (from WHOIS/RDAP).
  - *Netblocks:* `203.0.113.0/24` owned by NORTHWIND-CORP (RDAP) — marked `[confirm ownership]`
    because RDAP org names can be shared/stale; ASN cross-check is the confirmation.
  - *Subdomains (UNVERIFIED, with source):* `shop, api, mail, vpn, vpn-old, dev, autodiscover`
    from crt.sh; any extras from the search dump. Every one flagged UNVERIFIED — a CT entry proves a
    cert was issued, not that the host resolves or responds today.
  - *Tech signals:* "Cisco ASA" (job post → VPN/firewall brand), any `Server`/framework hint from
    the search dump — all `[unconfirmed]`.
  - *People/emails:* addresses from the repo/search dump, recorded for later and handled ethically.
  - *Exposures:* the secret in the public repo — recorded as a **FINDING, do not use**.
- **Ranked active-recon plan for tomorrow (impact × likelihood, per 00.3):**
  1. `vpn-old.northwind.lab` — identity edge + "old" ⇒ likely unpatched/weak; highest impact ×
     likelihood. Cheapest first check: `dig +short vpn-old.northwind.lab @10.13.0.53` (does it even
     resolve?), then `curl -sI`.
  2. `dev.northwind.lab` — non-production ⇒ weaker controls, possible debug/real data. Cheap check:
     resolve + `curl -sI` for debug headers.
  3. `api.northwind.lab` — application/authz surface (feeds M08). Cheap check: resolve + `curl -sI`.
  4. Everything else = confirm-resolution pass.
- **Most interesting passive finding + its ethical constraint.** Two defensible answers: (a) the
  **exposed secret** — a finding you *record but must not use*; using it is authenticated, active
  access needing explicit RoE authorization (the passive/active line). (b) **`vpn-old`** — a
  forgotten identity-edge asset that's tomorrow's top active target. Accept either if the ethical
  constraint is stated correctly.

**Common wrong turns.** Treating CT/subfinder names as confirmed hosts (they're hypotheses);
resolving `northwind.lab` names "just to check" on the passive-only day (that's active — a scope
violation in the exercise's framing); proposing to *use* the leaked key; ranking by "coolness"
instead of impact × likelihood.

**Check-yourself.**
1. **No.** `subfinder` reports a name some source has *seen* (CT, passive DNS). You've learned the
   name is a candidate worth resolving; you have **not** learned that it resolves, is live, is in
   scope, or still exists. Confirmation is an active step (02.2).
2. CT logs record **every** publicly-trusted certificate, and orgs routinely obtain public certs for
   internal hosts (wildcard issuance, automated ACME, convenience). So "internal" names leak into a
   public, append-only log. Lesson: CT is a rich, *unsolicited* subdomain source you can't opt out
   of, and it surfaces names never linked anywhere.
3. **No — not without explicit authorization for that action.** Scope authorizes *testing
   `*.northwind.lab`*; it does not authorize *using* a discovered credential to authenticate.
   Finding the key is passive (reading a public repo); using it is active, authenticated access to a
   system — the thing 00.1 says needs authorization. Record it as a finding; ask the client before
   using it, if ever.
4. Shodan returns results from **its own** prior Internet-wide scans — you query a third party's
   stored data, so the target sees nothing (passive). `nmap` sends **your** packets to the target's
   hosts now, generating logs on the target and requiring authorization (active). Same information
   class, opposite side of the line.
5. Registrant PII is often redacted, but the **structural** data isn't: registrar, **nameservers**
   (DNS infra to enumerate), creation/expiry dates, and — for IP RDAP — **netblock/ASN ownership**,
   which lets you expand from one host to a whole owned range.

## 02.2 — Active reconnaissance

**Exercise (Northwind, day two, active authorized).** A strong submission:

- **Confirmed hosts, each with evidence + method.** Resolved passive candidates via `dig`/`dnsx`
  (method: passive-confirmed); names only AXFR revealed (method: AXFR — e.g. `internal-crm`, and any
  host not in CT); names from permutation/brute that resolved (method: brute/permutation, wildcard
  filtered); vhost-only names (method: vhost fuzz + `curl -H 'Host:'`); a cert-SAN pivot name
  (e.g. `checkout.northwind.lab`, method: cert-SAN). Each row files the actual `dig`/`curl`/`httpx`
  output as evidence.
- **Zone-transfer result per NS.** `ns1` refuses (`Transfer failed`); the deliberately
  misconfigured secondary (`ns2`) returns the full zone. The captured AXFR is the evidence, and it
  should reveal at least one name CT logs didn't (the internal `10.20.0.15` host) — the teaching
  point that AXFR, when open, beats brute-forcing outright.
- **Prioritized map** (the table form from the lesson): `vpn-old` and `dev` HIGH (identity edge /
  non-prod, weak controls, likely real data — crosses the untrusted-Internet ↔ app boundary onto the
  weakest components); `api`/`shop` MED (core app + authz surface; `shop` hardened but `robots.txt`
  leaks `/admin`,`/backup`); `internal-crm` LATER (RFC 1918, not externally reachable — post-foothold
  target, not external priority). Each row: host, IP, service, fingerprint, priority, one-line
  impact × likelihood + trust boundary.
- **First two for M03:** `vpn-old` and `dev`. Argument to the client: limited time goes where impact
  × likelihood is highest — a legacy VPN at the identity edge and a debug-enabled non-prod host are
  more likely weak and, if weak, give the most (network access / real data) than the hardened
  production storefront. That's defensible prioritization, not guesswork.

**Common wrong turns.** Trying AXFR only against `ns1` and concluding DNS is locked down (always try
every NS — the misconfig is on the secondary); reporting brute-force wildcard noise as real hosts
(no wildcard filtering); probing the out-of-scope `promo` CNAME target or reverse-sweeping a
neighbor's hosts (scope violation — record, don't probe); prioritizing the internal-only host for
*external* testing; ranking the hardened storefront first because it's the "main" app.

**Check-yourself.**
1. DNS config is **inconsistent** across servers — one secondary is misconfigured to allow AXFR to
   anyone. You always try every nameserver because misconfigurations commonly live on a forgotten or
   legacy secondary while the primary is locked down; checking only `ns1` would have missed the
   entire-zone leak. One command each; always worth it.
2. **Wildcard DNS** — `*.northwind.lab` resolves everything to one IP, so every random name "exists."
   Confirm in one command: `dig +short definitely-not-real-$RANDOM.northwind.lab @10.13.0.53` — if a
   nonsense name returns an address, it's a wildcard, and your brute-force needs wildcard filtering
   (e.g. `puredns`) or every result is a false positive.
3. It's a **dangling CNAME → subdomain-takeover** candidate: the S3 bucket the alias points to no
   longer exists, so an attacker who *registers that bucket name* now serves content from
   `promo.northwind.lab`. Serious (phishing, cookie theft, cert issuance under the subdomain).
   **Scope:** the S3 bucket is third-party infrastructure the client cannot authorize you to test —
   record the dangling CNAME as a **finding** and the takeover as a risk; do **not** register the
   bucket or interact with AWS. The *finding* (a takeover-able subdomain) is the deliverable, not the
   exploit.
4. **Name-based virtual hosting** — one IP serves multiple sites selected by the HTTP `Host` header.
   You discover the second by vhost fuzzing the `Host:` header against the IP (`ffuf`/`gobuster
   vhost`, filtering the default-response size) and/or reading the live certificate's SANs, then
   confirming with `curl -H 'Host: dev.northwind.lab' https://<ip>`.
5. **`dev` first.** Argument: production `shop` is hardened and, if broken, the business impact is
   high but the *likelihood* of a quick finding is lower; a debug-enabled non-production host is more
   likely weak, often shares data/credentials with production, and debug output shortcuts discovery.
   Rank by impact × likelihood, not by which host is "important." (A defensible counter-argument that
   puts `shop` first because it holds the crown-jewel payment/customer data and is the actual money
   path is acceptable *if* the student argues impact explicitly and notes they'd still circle back to
   `dev` — the point is the reasoning, not a fixed answer.)
