# Instructor / solutions — Module 01

> **Instructor material.** Not linked from `_sidebar.md`. Do the exercises before reading.

## 01.1 — TCP/IP &amp; the packet's journey

**Exercise (interpret the scan + capture).** A strong submission reasons purely from responses:

| Port | State | Proof (the packet, or its absence) |
|---|---|---|
| 22 | open | target answered **SYN/ACK** (`Flags [S.]`); we tore down with RST |
| 80 | open | scanner reports `syn-ack`; same SYN/ACK pattern as 22 |
| 139 | closed | target answered **RST/ACK** (`Flags [R.]`) — host reachable, no listener |
| 445 | filtered | our SYN sent, **retransmitted, no reply** — silence |
| 3389 | filtered | same: SYN + retransmit, **no reply** |

- **Firewall argument.** A firewall is present and **selective**. Proof: 139 returned a RST, so the
  host itself is up and willing to answer on at least one port; yet 445 and 3389 produced *total
  silence* (including on retransmit). A host that RSTs on 139 would also RST on 445/3389 if the
  packets reached it and no service listened — the difference in behavior isn't the host, it's a
  device in the path **dropping** (not rejecting) 445 and 3389. So the rule is roughly: *permit
  22/80/139 to this host, silently drop 445 and 3389.* Drop (not reject) is what yields `filtered`
  rather than `closed`. Accept the alternative that 445/3389 are host-firewalled locally — the
  evidence (silence vs. RST) is the same; the point is the student names *drop vs. reject* and cites
  the silence.
- **TTL.** Arriving TTL 63 → started at 64 (Linux/Unix family), crossed **1 hop** (64 − 63). One-hop
  distance is consistent with a directly-adjacent lab host.

**Check-yourself.** (1) `filtered` = no useful reply: either a firewall **dropped** the probe/reply,
or the packet was lost / rate-limited. Tell them apart by re-probing (transient loss won't persist),
scanning from another vantage point, or looking for an ICMP admin-prohibited message (explicit
reject) vs. pure silence (drop). (2) A connect scan calls `connect()` and completes the full
three-way handshake, so the listening application accepts a real connection and typically **logs**
it; a SYN scan sends only SYN and sends RST on the SYN/ACK, so the handshake never completes and many
apps never see/log a connection. Quieter because the connection never fully forms. (3) UDP has no
handshake: an open port that simply doesn't reply to that input is **indistinguishable** from a
dropped probe — both are silence — so the honest verdict is `open|filtered`. The ambiguity is in the
protocol (no acknowledgement of receipt), not the scanner. (4) A firewall (or host-discovery being
blocked) is dropping your scan probes while the web path is permitted — or nmap decided the host was
"down" from a failed ping and skipped it. Use **`-Pn`** to skip host discovery, and note that
`filtered`-everywhere with a working website means a device is dropping your probes, not that the
host is dead.

## 01.2 — DNS, HTTP &amp; TLS

**Exercise (stack &amp; surface inference).**
- **Stack:** web server **nginx** (`Server: nginx`); application runtime **Node.js / Express**
  (`X-Powered-By: Express` + the `connect.sid` session cookie is Express's default); hosting platform
  **Heroku** (`Via: 1.1 vegur` — vegur is Heroku's router); mail via **Google Workspace**
  (`MX aspmx.l.google.com`, SPF `include:_spf.google.com`); the org uses **Atlassian** (the
  `atlassian-domain-verification` TXT record).
- **New hosts to investigate:** `api.example.lab` and `staging-admin.example.lab` — both from the
  **certificate SAN list**, not from the DNS you were given. (`www` was already known via the CNAME.)
- **Most interesting host:** `staging-admin.example.lab` — "staging" often means weaker controls and
  fresher/unfinished code, and "admin" means high privilege; a staging admin surface is a classic
  high-impact, low-scrutiny target. It also appeared only in the cert, suggesting it wasn't meant to
  be advertised.

**Check-yourself.** (1) The name was published by the org itself into a public CT log / its own cert,
so reading it is **passive** — you never sent a probe to the host to learn it exists, so there's
nothing to detect or block, and no guesswork/noise like a brute-force wordlist that hammers the DNS
server with thousands of failed lookups. (2) One IP serves multiple vhosts; the server picks the site
by the **SNI** in the ClientHello (and the HTTP `Host` header). `curl https://10.10.0.20/` sends SNI
= the IP (or none), so the server falls back to its **default** vhost. Reach the intended site with
`curl --resolve shop.example.lab:443:10.10.0.20 https://shop.example.lab/` (or `-H "Host: …"` +
`--connect-to`) so the right SNI/Host is sent. (3) Any two of: the **SNI** (server name requested,
sent in the clear); the **certificate** (subject + all SANs → other hostnames); the negotiated **TLS
version and cipher** (weak = finding); traffic **timing and volume**; and the destination **IP/port**.
(4) They are individually low-severity but you record them because (a) they're real hardening gaps
that compound with other bugs (no HttpOnly + an XSS = session theft; no Secure = cookie leak over
HTTP; no CSP = easier XSS impact), and (b) collectively the absence of standard security headers
signals **low security maturity**, which shapes where you look next and what the report recommends.

## 01.3 — Routing, NAT, firewalls, proxies, VPNs &amp; auth

**Exercise (two vantage points + cookie + JWT).**
- **Why 8443 differs by vantage point.** A **stateful firewall** (or the perimeter/segmentation
  policy) permits `8443/admin` only from **internal/VPN source addresses** and **drops** it from
  external sources, while `443` is permitted from anywhere. Being on the office VPN gives the teammate
  an internal source address, so their SYN to 8443 is allowed and completes (port observed **open**);
  from the external attacker box the SYN to 8443 is silently dropped, so it **times out** (observed
  **filtered**), while 443 answers from both. Confirming evidence: from the VPN, 8443 returns
  SYN/ACK; from outside, 8443 gives no reply (retransmit → silence) whereas 443 gives SYN/ACK — i.e.
  the `open` vs `filtered` split follows the *source*, which is the signature of a source-based
  firewall rule, not a dead host. (NAT/routing is an acceptable secondary answer if the admin service
  is on a private-only interface, but the "443 works from both" detail points at a **firewall rule
  keyed on source**, not pure unroutability.)
- **Cookie analysis.** Present: `HttpOnly` (good — XSS can't read it via `document.cookie`). **Missing
  `Secure`** → the cookie can be sent over plaintext HTTP and captured on the wire / via an HTTP
  downgrade. **Missing `SameSite`** → depending on browser default it may ride cross-site requests,
  reopening **CSRF** (the browser as confused deputy). Also worth flagging conceptually: no visible
  `Max-Age`/`Expires` (session lifetime), and you'd want to confirm the ID is random and rotated on
  login.
- **JWT analysis.** At least two of: (a) **No `exp` claim** — the token never expires, so a captured
  token is valid forever; a serious lifetime flaw. (b) The **`role` claim** is what the app trusts to
  decide privilege — if the signature can be **stripped (`alg:none`)**, **forged via a weak HS256
  secret**, or bypassed by **algorithm confusion**, an attacker flips `"role":"user"` →
  `"role":"admin"` and the server, trusting the claim, becomes a **confused deputy** acting with admin
  authority on a forged assertion. (c) HS256 with a guessable/shared secret is brute-forceable
  offline (the token is signed, not encrypted, so the claims are readable and the secret is the only
  protection). The app trusts the token to assert *identity and role*; that trust is only as strong as
  the signature verification, which must happen — correctly, with a pinned algorithm — on **every
  request**.

**Check-yourself.** (1) `10.0.0.50` is an **RFC 1918 private** address; no Internet router has a route
to it and NAT only maps *outbound*-initiated connections, so an external attacker has no path in and
no existing mapping to reuse. An attacker on another `10.0.0.x` host is **inside** the same routable
private network, so it can address `10.0.0.50` directly — which is exactly why pivoting through a
foothold works (M12). (2) The stateful firewall adds an entry to its **state table** when the user's
outbound SYN leaves; the returning SYN/ACK/data is permitted *because it matches existing state*, with
no inbound rule needed. An **unsolicited** inbound SYN matches **no** state entry and no permit rule,
so it's dropped. One state-tracking mechanism, two outcomes. (3) **Authorization** failure —
authentication succeeded (the app knew who the user was), but it failed to check whether that user was
permitted to access *this* record. Confused deputy: the app used *its own* data-access privilege on
the user's supplied ID without verifying the user's right to that object; the missing check is a
**per-request object-level authorization** check (does *this* user own/‑may‑access *this* ID). (4) A
signature only proves the token wasn't altered *and was issued by a holder of the key* — it says
nothing about whether the claim is true unless the server **verifies the signature with the correct
key and a pinned algorithm on every request** and then makes its **own** authorization decision. "It's
signed" is worthless if the server doesn't actually verify it (or accepts `alg:none`, or the secret is
weak). The server must verify then authorize per request. (5) A **load balancer / reverse proxy** (the
changing `Server` and the stickiness cookie give it away). "The host" is really **several back ends**,
so a single scan may hit different servers with different states/software; you must account for the
front end (and possible WAF) and test each back end, not assume one consistent target.
