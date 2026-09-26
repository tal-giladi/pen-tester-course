# 01.3 — Routing, NAT, firewalls, proxies, VPNs &amp; authentication concepts

<div class="prereq">

**Prerequisites:** [01.1 TCP/IP &amp; the packet's journey](lesson-01.md), [01.2 DNS, HTTP &amp; TLS](lesson-02.md), [00.3 Threat modeling](../module-00/lesson-03.md).
**Module:** M01 Networking &amp; protocols for testers. **Difficulty:** 🟢 foundational.
**You will produce:** an explanation of why one service behaves differently from two network
vantage points, plus a conceptual security analysis of a session cookie and a JWT.

</div>

## Why this matters

By now you can read packets and protocols. But the *same* packet gets a different fate depending on
**where you send it from** and **what sits in the path** — a router that has no route to a private
host, a NAT that hides a whole network behind one address, a stateful firewall that permits replies
but drops fresh probes, a reverse proxy that answers on the real server's behalf. Testers are
constantly surprised that a service is reachable from inside but not outside, or that a scan result
flips when they move. This lesson explains the machinery that shapes reachability — the same
machinery that makes **pivoting** a whole discipline later (M12) — and then turns to the other half
of a modern engagement: **authentication and authorization**, the mechanisms (sessions, cookies,
tokens, JWTs) whose flaws are the most common serious findings in the course.

## Learning objectives

- Explain routing and NAT well enough to know why internal hosts are unreachable from outside and
  why pivoting exists.
- Distinguish stateful from stateless firewalls and predict how each shapes your scan results.
- Tell forward proxies, reverse proxies, and load balancers apart, and read them from responses.
- State precisely what a VPN changes about your vantage point.
- Define **authentication vs authorization** exactly, and analyze sessions, cookies (HttpOnly /
  Secure / SameSite), and JWTs (structure, claims, `alg`) for conceptual weaknesses.
- Connect broken authorization to the **confused-deputy** pattern from 00.3.

## Intuition

Two ideas carry this lesson. First, **reachability is a property of a path, not of a host**: whether
your packet arrives depends on every router, NAT, and firewall between you and the target, so
"where you stand" changes what you can see — which is exactly why attackers pivot to a better vantage
point. Second, **authentication answers "who are you?" and authorization answers "are you allowed to
do this?"** — two separate questions that systems constantly conflate, and that conflation is where
a huge share of real vulnerabilities live.

## Routing and NAT — why internal hosts hide

A **router** forwards a packet toward its destination using a routing table; if it has no route to a
destination, the packet is dropped. **Private address ranges** (RFC 1918: `10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`) are, by agreement, **not routable on the public Internet** — no
Internet router will forward them. So an internal host at `10.0.0.50` is unreachable from outside not
because a firewall blocks it, but because the Internet has no path to it at all.

**Network Address Translation (NAT)** is what lets those private hosts still reach out. A NAT gateway
rewrites the source address (and port) of outbound packets to its own public address, remembers the
mapping, and reverses it on the replies:

```text
inside 10.0.0.50:51000 ─▶ [NAT] rewrites src ─▶ 203.0.113.9:40000 ─▶ Internet server
inside 10.0.0.50:51000 ◀─ [NAT] reverses map ◀─ 203.0.113.9:40000 ◀─ reply
```

The consequence for a tester is fundamental: **NAT is directional.** Internal hosts can initiate
connections out, but the outside cannot initiate connections *in* to a specific internal host —
there is no mapping until the inside creates one. This is *why* attackers, once they have a foothold
on one internal host, use it as a relay to reach the hosts they could never touch directly. That is
**pivoting**, and it gets a full module (M12); recognize here that NAT and private addressing are the
reason it is necessary.

## Firewalls — stateful vs stateless, and how they shape scans

A **firewall** enforces a policy on which traffic may pass. The distinction that changes your scan
results:

<div class="callout key">

- **Stateless (packet filter)** — decides on each packet in isolation, using header fields
  (addresses, ports, flags). It has no memory of connections, so its rules must explicitly allow both
  directions. Cheaper, but crude.
- **Stateful** — tracks connections in a state table. It allows a reply *because it remembers the
  request that started the connection*, without a separate inbound rule. Almost all modern firewalls
  are stateful. This is why an internal host can browse the web (its outbound SYN creates state; the
  SYN/ACK is allowed back) while unsolicited inbound SYNs to it are dropped.

</div>

How this shows up in a scan (tying back to 01.1's port states): a firewall that **drops** your probe
produces `filtered` (silence); one that **rejects** with a RST or ICMP can make a port look `closed`
even though a service is behind it. A host that returns `closed` on some ports and `filtered` on
others reveals a *selective* firewall — the pattern of silence is itself a map of the rule set. This
is why you scan from more than one vantage point when you can: the firewall between you and the
target is part of what you're measuring.

## Proxies and load balancers — someone answers on the server's behalf

<div class="callout recon">

- **Forward proxy** — sits in front of *clients*, making requests on their behalf (corporate egress
  proxy, or your own `proxychains`/SOCKS setup). It changes the apparent source of your traffic.
- **Reverse proxy** — sits in front of *servers*, receiving client requests and forwarding them to a
  back end (nginx, HAProxy, a CDN, a WAF). To you it *is* the server; the real origin is hidden
  behind it. Headers often betray it: `Via`, `X-Cache`, `X-Forwarded-For`, `Server: cloudflare`,
  `CF-RAY`, `X-Amz-Cf-Id`.
- **Load balancer** — a reverse proxy that spreads requests across several back ends. Symptoms: a
  changing `Server`/`Set-Cookie` between requests, inconsistent behavior, or a balancer-set stickiness
  cookie. It means "the host you're testing is really several hosts."

</div>

Two tester consequences. First, **the front end and the back end may parse requests differently** —
the seam between a reverse proxy and its origin is where request smuggling and cache poisoning live
(M07). Second, a WAF (a reverse proxy that inspects traffic) will alter your results: a payload
blocked at the edge tells you a WAF exists, not that the app is safe — you learn to fingerprint and
account for it rather than conclude "not vulnerable."

## VPNs — changing your vantage point

A **VPN** builds an encrypted tunnel between your machine and a remote network and gives you an
address *inside* that network. Its security relevance is precisely the vantage-point shift from the
intuition: a service unreachable from the Internet (private, NATed, firewalled) becomes reachable
once you are "inside" via VPN — you are now past the perimeter. Engagements are frequently scoped as
"we'll drop you on the internal network via VPN" exactly to test the internal posture without you
having to breach the perimeter first. The lesson to carry: **being on the VPN changes what packets
can reach, and therefore changes every scan result** — always record which vantage point produced a
finding.

## Authentication vs authorization — get this exactly right

<div class="callout key">

- **Authentication (authn)** — *proving who you are.* Login, a session cookie, a token, a
  certificate. Answers **"who are you?"**
- **Authorization (authz)** — *deciding what you're allowed to do.* Answers **"are you permitted to
  perform this action on this resource?"**

</div>

They are separate steps and separate failures. Being authenticated does **not** mean being
authorized. The most common serious web finding — reading another user's data by changing an ID
(IDOR/BOLA, 00.3) — is an **authorization** failure by a perfectly **authenticated** user: the system
knew *who* you were and failed to check *whether you were allowed*. Keep the two words apart in your
head and your reports, because the fix differs: authn problems are about proving identity; authz
problems are about enforcing per-request permission checks.

## Sessions and cookies

HTTP is stateless — each request stands alone — so after you authenticate, the server needs a way to
recognize you on the next request. The classic mechanism is a **session**: the server stores your
state and hands you an opaque **session identifier** in a cookie; you send it back on every request.

```http
Set-Cookie: session=8f14e45fceea167a; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=3600
```

The **flags** are the security-relevant part:

<div class="callout defend">

- **`HttpOnly`** — JavaScript cannot read the cookie (`document.cookie`), which blunts session theft
  via XSS. Its absence means an XSS bug can steal the session.
- **`Secure`** — the cookie is only sent over HTTPS, so it can't leak over plaintext HTTP.
- **`SameSite`** — controls whether the cookie rides along on cross-site requests. `Strict`/`Lax`
  mitigate CSRF; `None` (which requires `Secure`) sends it cross-site and reopens CSRF exposure.

</div>

A tester reads these flags on every `Set-Cookie`. Also relevant conceptually: is the identifier
**random and long** (unguessable), is it **rotated on privilege change** (login/logout), and does it
**expire**? A predictable or immortal session ID is a finding regardless of flags.

## Tokens and JWT

Instead of server-side session storage, many systems issue a **token** the client presents on each
request (often `Authorization: Bearer <token>`). The dominant format is the **JSON Web Token (JWT,
RFC 7519)** — three Base64url parts joined by dots: `header.payload.signature`.

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9   .  eyJzdWIiOiI0MiIsInJvbGUiOiJ1c2VyIiwiZXhwIjoxNzM1Njg5NjAwfQ  .  <signature>
        header (alg, typ)                              payload (claims)                                    signature
```

Decoded, the header names the signing algorithm and the payload holds **claims**:

```json
// header
{ "alg": "HS256", "typ": "JWT" }
// payload
{ "sub": "42", "role": "user", "iss": "shop.example.lab", "iat": 1735686000, "exp": 1735689600 }
```

Standard claims: `sub` (subject/identity), `iss` (issuer), `aud` (audience), `exp` (expiry — a
missing or far-future `exp` is a finding), `iat`, `nbf`. The **signature** is what makes the token
trustworthy: the server verifies it to confirm the token was issued by *it* and not altered.

<div class="callout warn">

**Conceptual JWT weaknesses to recognize** (you'll test these safely in the lab in M07/M08, never on
real systems): the token is **signed, not encrypted** — anyone can read the claims, so secrets must
never live in the payload; the historic **`alg: none`** flaw, where a server accepts an unsigned
token; **weak HS256 secrets** that can be brute-forced offline; and **algorithm-confusion** tricks.
The single most important habit: **decode every JWT you see and read its claims** — the `role`,
`sub`, and `exp` fields tell you what the app trusts the token to assert, which is exactly what an
attacker would try to forge.

</div>

## The connection to the confused deputy

Recall the **confused-deputy** pattern from [00.3](../module-00/lesson-03.md): a privileged component
tricked into misusing its authority on behalf of a less-privileged party. Session cookies are the
textbook enabler. In **CSRF**, the browser is the confused deputy — it automatically attaches the
victim's session cookie to a request the attacker triggered, so the server acts with the victim's
authority on the attacker's instruction (which is why `SameSite` matters). In **SSRF**, the server is
the confused deputy — its network position, not a cookie, is the borrowed authority. Whenever you see
one component acting on another's input **with its own credentials or reach** — a cookie sent
automatically, a token forwarded downstream, a server fetching a user-supplied URL — ask 00.3's
question: *can the less-privileged party make the deputy do something they couldn't do directly?*
Authn/authz flaws and confused deputies are two views of the same underlying mistake: **trusting the
request instead of verifying the requester's right to this specific action.**

## Manual investigation and tooling

<div class="callout method">

- **`traceroute` / `tracert`** — reveals the routers (hops) between you and a target using expiring
  TTLs (01.1); shows where a path dies and hints at perimeter devices. *Verify:* compare from two
  vantage points.
- **`ip route` / `ip addr`, `netstat -rn`** — read your own routing table and interfaces to know
  which networks you can reach and via which gateway. Essential before and after gaining a foothold.
- **`curl -v`** — reveals proxies and balancers from response headers (`Via`, `X-Cache`,
  `Set-Cookie` churn) and lets you read cookie flags directly.
- **JWT inspection** — decode the three parts by hand (Base64url) or with a decoder to read the
  header and claims. *Do not paste real production tokens into online decoders* — they are
  credentials; decode locally.

*Limit of all of these:* they describe the path and the artifacts from **your** vantage point only.
The same commands from inside the perimeter tell a different story — which is the whole point.

</div>

<div class="callout legal">

**LAB TARGETS ONLY.** Any cookie, token, or credential in this course is synthetic and belongs to a
lab host (`lab / Lab-Passw0rd!`, lab-issued JWTs). Never analyze, replay, or tamper with a real
user's session or token, and never test authorization by accessing another *real* person's data —
that is exactly the line 00.1 draws. Vantage-point techniques (VPN, pivoting) are only ever used
inside the authorized, isolated lab network.

</div>

## Practical

<div class="lab">

**Environment:** the attacker box; a lab web app behind a lab reverse proxy, reachable on the lab
network. **Time:** ~45 min. **Targets:** lab hosts only.

</div>

1. `traceroute TARGET` and `ip route` — sketch the path and note any device that ends the trace.
2. `curl -v https://shop.example.lab/login` then log in with the lab credentials; capture the
   `Set-Cookie` and list which of `HttpOnly`/`Secure`/`SameSite` are present or missing.
3. If the app issues a JWT, decode its three parts and write out the header `alg` and the payload
   claims (`sub`, `role`, `exp`). Note what the app is trusting the token to assert.
4. In your notes, name one confused-deputy scenario this app enables (CSRF via the cookie, or SSRF if
   it fetches URLs) and explain the borrowed authority in one sentence.

## Exercise

<div class="callout method">

**Situation.** An authorized test of a lab service. A teammate reports: *"From my laptop on the
office VPN I can reach the admin panel at `https://TARGET:8443/admin` and it works. From the external
attacker box, the same URL just times out — but the public site on 443 loads fine from both."* You
are also handed the app's session cookie and a JWT it issued (lab data below).

**Objective.** Explain the two-vantage-point behavior from the network machinery, and give a
conceptual security read of the cookie and token.

**Starting information.** Lab data:

```http
Set-Cookie: SESSION=b7e2…; Path=/; HttpOnly
```

```json
// decoded JWT the app issued to a normal user
// header
{ "alg": "HS256", "typ": "JWT" }
// payload
{ "sub": "1001", "user": "alice", "role": "user", "iat": 1735686000 }
```

**Constraints.** Reason conceptually — you are not attacking anything. Explain mechanisms, not
exploit steps.

**Expected deliverables.**
1. A crisp explanation of why 8443 is reachable from the VPN vantage point but not the external one,
   while 443 is reachable from both — naming the specific machinery (routing/NAT/firewall/proxy)
   responsible and what evidence would confirm it.
2. A conceptual weakness analysis of the session cookie: which protective flags are present, which
   are missing, and what class of attack each missing flag reopens.
3. A conceptual weakness analysis of the JWT: at least two issues you'd flag from the header and
   claims alone, and why each matters. State explicitly what the app trusts the token to assert and
   why that is dangerous if the signature can be forged or stripped.

</div>

<details><summary>Hint 1 — the two vantage points</summary>
The public site is reachable from everywhere; the admin port only from inside. What kind of device
permits a port to internal sources and drops it from external ones — and how does that relate to the
VPN putting you "inside"? Which port state (01.1) would each vantage point observe on 8443?
</details>

<details><summary>Hint 2 — the cookie flags</summary>
Compare the flags present against the full set from this lesson. Which one, if missing, lets an XSS
bug read the cookie? Which lets it ride cross-site requests (CSRF)? Which lets it leak over plaintext
HTTP?
</details>

<details><summary>Hint 3 — the token claims</summary>
Look at what the payload asserts and what it *lacks*. What claim decides privilege? What claim that
governs the token's lifetime is missing entirely? What could a less-privileged holder try to change
if the signature weren't properly verified — and how does that make the server a confused deputy?
</details>

## Check yourself

<div class="callout key">

1. An internal host at `10.0.0.50` runs a web server. Explain, using routing and NAT, why an
   Internet attacker cannot connect to it directly even with no firewall in the path — and why an
   attacker who already controls another `10.0.0.x` host can.
2. A stateful firewall lets an internal user browse the web but drops all unsolicited inbound
   connections to that same user's machine. Explain, in terms of the state table, how one mechanism
   produces both behaviors.
3. A user is fully authenticated and can still read another user's records by changing an ID in the
   URL. Is this an authentication or an authorization failure? Tie it to the confused-deputy pattern
   and say what check was missing.
4. A JWT's claims include `"role":"admin"` and the token is *signed*. Why is "it's signed" not by
   itself a reason to trust the `role` claim? What must the server actually do on every request?
5. You get different `Server` headers and a stickiness cookie on repeated requests to one hostname.
   What is almost certainly in the path, and how does that change how you interpret a single scan of
   "the host"?

</div>

Model answers are in `solutions/module-01.md`.

## References

- **RFC 1918** — Address Allocation for Private Internets; **RFC 2663 / 3022** — NAT terminology and
  traditional NAT.
- **RFC 4301** — Security Architecture for IP (IPsec/VPN concepts); **RFC 8446** — TLS 1.3 (for VPNs
  built on TLS).
- **RFC 6265** — HTTP State Management (cookies); **draft/RFC updates** for the `SameSite` attribute.
- **RFC 7519** — JSON Web Token; **RFC 7515** — JSON Web Signature; **RFC 6749** — OAuth 2.0
  Authorization Framework; **RFC 6750** — OAuth Bearer Token usage.
- **OWASP** — Session Management, CSRF, and JWT cheat sheets; **OWASP Top 10** A01 Broken Access
  Control, A07 Identification &amp; Authentication Failures.
- **NIST SP 800-63B** — Digital Identity Guidelines (authentication and session management).
- **CWE-441** — Unintended Proxy or Intermediary (Confused Deputy); **CWE-284/285/287** — access
  control, authorization, authentication.

## What you should now be able to do

- Explain why internal hosts hide behind NAT and why that makes pivoting necessary.
- Predict how stateful and stateless firewalls shape scan results, and read a firewall from the
  pattern of port states.
- Identify forward proxies, reverse proxies, and load balancers from responses, and state what a VPN
  changes about your vantage point.
- Define authentication vs authorization precisely and analyze cookies (HttpOnly/Secure/SameSite) and
  JWTs (structure, claims, `alg`) for conceptual weaknesses.
- Recognize the confused-deputy pattern behind CSRF, SSRF, and broken authorization.

## Progress checkpoint

```bash
py course.py complete 01.3
```
