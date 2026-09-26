# 01.2 — DNS, HTTP/HTTPS &amp; TLS for testers

<div class="prereq">

**Prerequisites:** [01.1 TCP/IP &amp; the packet's journey](lesson-01.md), [00.3 Threat modeling](../module-00/lesson-03.md).
**Module:** M01 Networking &amp; protocols for testers. **Difficulty:** 🟢 foundational.
**You will produce:** a written technology-stack and attack-surface inference for a domain, built
from its DNS records, one captured HTTP request/response, and its TLS certificate.

</div>

## Why this matters

Above the transport layer live the three protocols you will spend most of your career reading: DNS
turns a name into an address and, along the way, leaks a map of an organization's infrastructure;
HTTP carries almost every application you will test; TLS wraps them and, through its certificates,
publicly advertises names the target may not have meant to reveal. A tester who reads these fluently
extracts an organization's **attack surface** from public data before sending a single intrusive
request — subdomains, mail providers, a WAF, the web-server software, session mechanics. This lesson
turns each protocol into a recon and analysis instrument you will use constantly in M02 (recon) and
M07 (web).

## Learning objectives

- Trace a DNS resolution end to end and read the record types (A/AAAA/CNAME/MX/TXT/NS/PTR) as a
  tester reads them.
- Explain zone transfers and why a misconfigured one is a jackpot for recon.
- Dissect an HTTP/1.1 and HTTP/2 request and response: methods, status codes, and the headers that
  matter to a tester.
- Walk the TLS 1.3 handshake, read a certificate, and explain SNI, virtual hosts, and Certificate
  Transparency as recon sources.
- Verify all of the above by hand with `dig`, `curl`, and `openssl`.

## Intuition

Names are for humans; the network runs on numbers and streams of bytes. **DNS** is the phone book
that maps `shop.example.com` to an IP — and, because organizations describe themselves in it (mail
servers, verification records, subdomains), the phone book doubles as a floor plan. **HTTP** is a
stunningly simple request/response conversation: you ask for a resource by method and path, the
server answers with a status and a body. **TLS** is the sealed envelope around that conversation —
but the envelope has your name printed on the outside (the certificate), which is why it leaks
information even though the contents are encrypted. Read all three and you know a target's shape
before you touch it.

## DNS — resolution flow and record types

When your machine resolves a name it usually asks a **recursive resolver**, which walks the
hierarchy on your behalf:

```text
stub (your OS) ──▶ recursive resolver ──▶ root (.)            "ask the .com servers"
                                     ──▶ TLD (.com)           "ask example.com's NS"
                                     ──▶ authoritative (example.com)  "A record = 93.184.x.x"
                   ◀── answer (cached with a TTL) ◀───────────
```

Each answer carries a **TTL** telling the resolver how long to cache it. The record **types** a
tester reads:

<div class="callout recon">

- **A / AAAA** — name → IPv4 / IPv6 address. The actual reachable host.
- **CNAME** — an alias pointing one name at another. A CNAME to `*.cloudfront.net`,
  `*.azurewebsites.net`, or `*.github.io` instantly reveals the hosting provider — and dangling
  CNAMEs (pointing to a deprovisioned resource) are the root of **subdomain takeover**.
- **MX** — mail exchangers. Points to Google, Microsoft 365, Proofpoint, etc. — reveals the mail
  stack and a phishing-relevant surface.
- **TXT** — free text. Holds SPF (`v=spf1 …`), DKIM, DMARC, and countless domain-verification
  strings (`google-site-verification`, `atlassian-`, `MS=`) that enumerate the SaaS a company uses.
- **NS** — the authoritative name servers for the zone (who to interrogate, and the DNS provider).
- **PTR** — reverse mapping IP → name; useful when sweeping a range to name what you found.

</div>

### Zone transfers (AXFR)

A **zone transfer** is the mechanism secondary name servers use to copy the full zone from a primary.
It is meant to be restricted to known secondaries. When a server answers an AXFR to *anyone*, it
hands over **every record in the zone at once** — a complete map of hosts and subdomains you would
otherwise have to guess. It is a classic, still-found misconfiguration:

```bash
# LAB TARGET ONLY. Ask the zone's own name server for the whole zone.
dig AXFR example.lab @ns1.example.lab
```

If it succeeds you get the entire zone; if it's configured correctly you get `Transfer failed`. This
is enumeration, not exploitation — but on the right target it collapses hours of subdomain
brute-forcing into one query.

## HTTP — the request/response you will read a thousand times

HTTP/1.1 is human-readable text. A request is a method, a path, a version, headers, a blank line, and
an optional body:

```http
GET /account?id=42 HTTP/1.1
Host: shop.example.lab
User-Agent: curl/8.5.0
Accept: */*
Cookie: session=eyJ1c2VyIjo0Mn0; theme=dark

```

The response mirrors it — status line, headers, blank line, body:

```http
HTTP/1.1 200 OK
Server: nginx/1.24.0
Content-Type: text/html; charset=utf-8
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax
X-Powered-By: Express
Strict-Transport-Security: max-age=31536000
Content-Length: 512

<!doctype html>…
```

**Methods** you must know: `GET` (retrieve), `POST` (submit), `PUT`/`PATCH` (create/update),
`DELETE`, `HEAD` (headers only — cheap recon), `OPTIONS` (which methods/CORS are allowed — often
reveals more than intended). **Status classes:** `2xx` success, `3xx` redirect (watch `Location`),
`4xx` client error (`401` needs auth, `403` forbidden, `404` not found, `429` rate-limited), `5xx`
server error (a `500` on odd input is a promising signal).

<div class="callout recon">

**Headers a tester reads first:**
- `Server`, `X-Powered-By`, `X-AspNet-Version` — software and framework fingerprints.
- `Set-Cookie` and its flags (`HttpOnly`, `Secure`, `SameSite`) — session security, covered in 01.3.
- `Location` — redirect targets; sometimes leak internal hostnames.
- `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options` — presence *and absence*
  are both findings.
- `Access-Control-Allow-Origin` — CORS posture (M07).
- `Via`, `X-Cache`, `CF-RAY`, `X-Amz-Cf-Id` — a proxy, CDN, or WAF sits in front (01.3).

</div>

### HTTP/2 (and a word on HTTP/3)

HTTP/2 (RFC 9113) keeps the same **semantics** — methods, status codes, headers, the same meaning of
a request (RFC 9110 defines semantics independently of version) — but changes the **wire format**:
it is binary, multiplexes many concurrent streams over one TCP connection, and compresses headers
with HPACK. Header names are lowercased and the request line is split into pseudo-headers
(`:method`, `:path`, `:authority`, `:scheme`). For a tester this matters in two ways: your tools must
speak h2 to test an h2-only endpoint, and the mismatch between how front-end and back-end servers
parse framing is the basis of **request smuggling** (M07). HTTP/3 moves the same semantics onto QUIC
over UDP — know it exists; the semantics you learn here still apply.

## HTTPS and the TLS 1.3 handshake

HTTPS is just HTTP carried inside a **TLS** session. TLS gives you three things: **confidentiality**
(encryption), **integrity** (tamper detection), and **authentication** (the certificate proves you
reached the server you named). TLS 1.3 (RFC 8446) streamlined the handshake to one round trip:

```text
Client ── ClientHello ─────────────▶  supported ciphers, key share, and SNI (server name)
Client ◀── ServerHello ─────────────  chosen cipher, key share
       ◀── {Certificate, CertVerify, Finished}   (encrypted from here on)
Client ── {Finished} ──────────────▶  handshake done — application data flows
```

Compared with TLS 1.2, version 1.3 removed a round trip, encrypted more of the handshake, and
dropped legacy ciphers (RSA key exchange, RC4, static DH). Seeing a target still negotiate TLS 1.0/1.1
or weak ciphers is itself a finding.

### The certificate — a recon goldmine

The server presents an **X.509 certificate** binding a public key to names, signed by a Certificate
Authority. The fields you read:

```text
Subject:            CN = shop.example.lab
Subject Alt Names:  DNS:shop.example.lab, DNS:api.example.lab, DNS:staging.example.lab
Issuer:             Let's Encrypt R3
Validity:           Not Before / Not After  (expired = finding; short-lived = ACME automation)
Public Key:         RSA 2048 / ECDSA P-256
```

The **Subject Alternative Names (SAN)** list is the prize: certificates routinely name every host
they cover, so one cert can hand you `api.` and `staging.` subdomains you had not discovered.

### SNI and virtual hosts

One IP often serves many sites. **Server Name Indication (SNI)** is the hostname the client sends *in
the clear* in the ClientHello so the server knows which certificate and virtual host to serve. Two
consequences for testers: (1) you must send the right SNI/`Host` to reach a specific vhost — hitting
the IP alone may return a default site and hide the real target; (2) because SNI is unencrypted, the
names you request are observable on the wire (Encrypted Client Hello is emerging to fix this).

### Certificate Transparency

Every publicly trusted certificate is logged to append-only **Certificate Transparency (CT)** logs
(RFC 6962). Anyone can search them (e.g. `crt.sh`) to enumerate certificates issued for a domain —
which means **subdomains a company created appear in public logs**, often including internal-sounding
names (`vpn.`, `jenkins.`, `dev.`) that were never meant to be advertised. CT is passive recon: you
learn names without ever touching the target. You will use it heavily in M02.

## Manual investigation and tooling

<div class="callout method">

**`dig`** — one DNS question, honestly. `dig A shop.example.lab`, `dig MX example.lab`,
`dig TXT example.lab`, `dig NS example.lab`, `dig +trace name` (walk root→TLD→authoritative
yourself), `dig AXFR zone @ns` (attempt a transfer). *Limit:* answers may be cached or geo-split;
`+trace` and querying the authoritative NS directly bypass the resolver's cache. *Verify:* compare
answers from two resolvers.

**`curl`** — one HTTP request, fully visible. `curl -v` (show request+response headers and TLS),
`-I` (HEAD only), `-X` (method), `-H` (custom headers, e.g. a specific `Host` to hit a vhost),
`--http2`, `-k` (skip cert validation — for a self-signed lab host), `--resolve host:443:IP` (force
which IP a name maps to, to test one backend). *Limit:* it is a client — it shows you the exchange,
not the server's internal logic. *Verify:* read the raw bytes rather than a rendered page.

**`openssl s_client`** — inspect TLS by hand. `openssl s_client -connect TARGET:443 -servername shop.example.lab`
completes a handshake and prints the negotiated version, cipher, and full certificate chain; add
`| openssl x509 -noout -text` to read the SANs and validity. *Limit:* it tests what *you* can
negotiate, not every client's experience. *Verify:* cross-check the SANs against DNS and CT logs.

</div>

<div class="callout legal">

**LAB TARGETS ONLY.** `dig`, `curl`, and `openssl` against a target are active requests to that
server. Run them only against the isolated lab hosts (`*.example.lab`, `TARGET`) or against public
CT logs and your own DNS resolver. Passive sources (CT, public DNS) are the safest recon, but
querying a specific organization's name servers still touches their infrastructure — stay in scope
(00.1).

</div>

## Practical

<div class="lab">

**Environment:** the attacker box on the lab network; a lab web host serving `*.example.lab` over
HTTPS with a lab CA. **Time:** ~45 min. **Targets:** lab hosts only.

</div>

1. Enumerate the zone: `dig NS example.lab`, then `dig A/MX/TXT example.lab`. Attempt
   `dig AXFR example.lab @<ns>` and note whether it is (mis)configured to allow the transfer.
2. Fingerprint the web server: `curl -vI https://shop.example.lab` (note `Server`, `X-Powered-By`,
   `Set-Cookie` flags, security headers present/absent).
3. Read the certificate: `openssl s_client -connect shop.example.lab:443 -servername shop.example.lab </dev/null | openssl x509 -noout -text` and list the SANs.
4. Cross-reference: does any SAN name a host that DNS didn't obviously reveal? Try to reach it.

## Exercise

<div class="callout method">

**Situation.** An authorized test of the lab domain `example.lab`. You are given three public-ish
artifacts and must infer the technology stack and hidden attack surface before any intrusive testing.

**Objective.** Produce a stack-and-surface inference — what software is running, which provider(s)
are in play, and which additional hosts you now know to investigate — each claim tied to its
evidence.

**Starting information.** Lab data:

```text
; DNS
example.lab.        IN NS   ns1.example.lab.
shop.example.lab.   IN A    10.10.0.20
www.example.lab.    IN CNAME shop.example.lab.
example.lab.        IN MX   10 aspmx.l.google.com.
example.lab.        IN TXT  "v=spf1 include:_spf.google.com ~all"
example.lab.        IN TXT  "atlassian-domain-verification=9f3a…"
```

```http
GET / HTTP/1.1
Host: shop.example.lab

HTTP/1.1 200 OK
Server: nginx
X-Powered-By: Express
Set-Cookie: connect.sid=s%3A…; Path=/; HttpOnly
Via: 1.1 vegur
```

```text
; TLS certificate (openssl x509 -text, trimmed)
Issuer:  C=US, O=Let's Encrypt, CN=R3
Subject: CN = shop.example.lab
X509v3 Subject Alternative Name:
    DNS:shop.example.lab, DNS:api.example.lab, DNS:staging-admin.example.lab
Validity: Not After : (30 days out)
```

**Constraints.** Reason from the artifacts. Lab data — you are not sending requests now.

**Expected deliverables.**
1. A stack inference: web server, application framework/runtime, mail provider, and any SaaS the
   domain uses — each with the specific record/header that proves it.
2. A list of hosts to investigate that you did **not** start with, and where each came from.
3. One sentence naming the single most interesting host in the SANs and why a tester's eye jumps to
   it.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Each artifact answers a different question. DNS says "who provides my services and what do I use";
headers say "what software am I"; the cert says "what names do I secretly cover." Read them as three
lenses on the same organization.
</details>

<details><summary>Hint 2 — the fingerprints</summary>
`X-Powered-By: Express` and a `connect.sid` cookie point at one specific runtime and framework. `Via:
… vegur` names a specific hosting platform. An `MX` to Google and an `atlassian-` TXT record name two
external services outright.
</details>

<details><summary>Hint 3 — the hidden surface</summary>
You began knowing `shop` and `www`. The certificate's SAN list contains two names DNS didn't
advertise to you. Which one sounds like it was never meant to face the Internet?
</details>

## Check yourself

<div class="callout key">

1. You found `staging-admin.example.lab` in a certificate's SAN list, and it resolves to a lab IP.
   You never queried it directly. Why is discovering it through the certificate both effective and
   low-noise compared with brute-forcing subdomain names?
2. A single lab IP serves two different sites depending on the `Host`/SNI you send. Explain, in
   handshake terms, why hitting the raw IP with `curl https://10.10.0.20/` might show you the "wrong"
   site, and how you'd reach the intended one.
3. TLS encrypts the HTTP payload, yet it still leaks information useful to a tester. Name two things
   an observer or a tester learns from TLS despite the encryption.
4. A response has no `Strict-Transport-Security`, no `Content-Security-Policy`, and a `Set-Cookie`
   without `Secure`. None of these is an exploit by itself. Why do you still record them, and what do
   they collectively suggest about the app's security maturity?

</div>

Model answers are in `solutions/module-01.md`.

## References

- **RFC 1034 / 1035** — Domain Names (concepts and specification); **RFC 5936** — DNS Zone Transfer (AXFR).
- **RFC 9110** — HTTP Semantics; **RFC 9111** — HTTP Caching; **RFC 9112** — HTTP/1.1; **RFC 9113** — HTTP/2.
- **RFC 8446** — TLS 1.3; **RFC 6066** — TLS Extensions (SNI).
- **RFC 5280** — X.509 Public Key Infrastructure certificates; **RFC 6962** — Certificate Transparency.
- **OWASP Web Security Testing Guide** — Information Gathering (fingerprinting, TLS testing).
- **Mozilla Server Side TLS** — current recommended TLS configurations (a baseline for "is this weak?").

## What you should now be able to do

- Trace a DNS lookup and read A/AAAA/CNAME/MX/TXT/NS/PTR records as infrastructure intelligence.
- Recognize a misconfigured zone transfer and what it hands you.
- Dissect HTTP/1.1 and HTTP/2 requests and responses and read the security-relevant headers.
- Walk the TLS 1.3 handshake, read a certificate's SANs, and use SNI and CT logs as recon.
- Verify every inference by hand with `dig`, `curl`, and `openssl`.

## Progress checkpoint

```bash
py course.py complete 01.2
```
