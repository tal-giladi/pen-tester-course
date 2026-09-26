# 07.1 — The web attack model: HTTP in depth, cookies, sessions &amp; the intercepting proxy

<div class="prereq">

**Prerequisites:** [00.1 Ethics &amp; authorization](../module-00/lesson-01.md),
[00.3 Threat modeling &amp; the confused deputy](../module-00/lesson-03.md),
[01.2 DNS, HTTP/HTTPS &amp; TLS](../module-01/lesson-02.md) (you must already read a raw HTTP
request/response and a `Set-Cookie` line), and [03](../module-03/lesson-01.md) enumeration.
**Module:** M07 Web application penetration testing (major). **Difficulty:** 🔴 advanced.
**You will produce:** a mapped attack surface for the lab app — its routes, its session mechanism,
and its authentication surface — reconstructed entirely from intercepted traffic.

</div>

## Why this matters

Every later lesson in this module — injection, access control, SSRF, XXE, request smuggling — is a
specific way of abusing the **request/response conversation** you learn to control here. A tester who
cannot read a raw HTTP exchange, spot where the session lives, and replay a modified request by hand
is stuck running a scanner and reading its guesses. A tester who *can* do those things sees the
application the way it actually behaves on the wire, forms hypotheses from that behavior, and proves
them one request at a time. 01.2 taught you to read HTTP as recon; this lesson turns it into a
manipulation instrument and sets up the trust-boundary lens ([00.3](../module-00/lesson-03.md)) you
will apply to every web bug for the rest of the course.

## Learning objectives

- Describe the **web attack model**: client, server, and the trust boundary between them, and why the
  client is always attacker-controlled.
- Weaponize HTTP methods, status codes, and headers — read them for what they *reveal* and manipulate
  them for what they *permit*.
- Explain cookie-based and token-based **session management** and read `HttpOnly`/`Secure`/`SameSite`
  as security controls with concrete failure modes.
- Drive an **intercepting proxy** (Burp Suite / OWASP ZAP): proxy, target/site map, Repeater, and the
  concept behind Intruder — and know what each does and does not prove.
- **Map an application** methodically into a route + parameter + session + auth-surface inventory.

## Intuition

A web application is a program whose input arrives over the network from a party you do not trust —
the browser. The developer *wishes* the browser were part of their program (they wrote the
JavaScript, after all), but it runs on the attacker's machine, and **every byte it sends can be
changed**. Hidden fields, disabled buttons, client-side validation, the price in a cart, the user ID
in a cookie — all of it is a suggestion the client is free to ignore. The entire discipline of web
testing is: find each place where the server *trusts* something the client controls, and see what
happens when that trust is misplaced. The intercepting proxy is simply the tool that lets you sit on
the wire and edit that "something" before it arrives.

## The underlying technology — the web attack model

<div class="callout key">

**The trust boundary.** Draw the line between browser and server (00.3). Everything left of the line
is **untrusted and attacker-controlled**: URL, path, query string, every header (including `Host`,
`Cookie`, `Referer`, `X-Forwarded-For`), the body, the method, cookies, and any client-side check.
Everything right of the line is what the server *decides* to do with that input. A vulnerability is
any place the server treats a left-of-line value as if it were trustworthy — a filename, an identity,
an authorization decision, a query fragment, a URL to fetch. This one picture generates the whole
module.

</div>

The browser is a **confused deputy** waiting to happen (00.3): it holds the victim's session and will
faithfully attach it to any request, including one an attacker tricked it into sending (CSRF). The
server is a confused deputy too: it has network reach and privileges the user does not (SSRF, access
control). Keep both deputies in mind.

### HTTP methods a tester weaponizes

You met the methods in 01.2 as semantics; here they are levers:

- **`GET` / `POST`** — the workhorses. The key insight: the server often does not care *which* it
  received. A state-changing action reachable by `GET` is CSRF-friendly and shows up in logs and
  browser history (secrets in the query string leak). Try swapping the method.
- **`HEAD`** — same routing as `GET`, no body: cheap existence checks during mapping.
- **`OPTIONS`** — advertises allowed methods (`Allow:` header) and drives CORS preflight; often
  reveals methods the UI never uses.
- **`PUT` / `DELETE`** — if enabled and unauthenticated, direct file write / resource deletion.
- **`PATCH`** — partial update; a frequent home for **mass assignment** (M08).
- **`TRACE`** — reflects the request; historically enabled Cross-Site Tracing. Its presence is a
  finding.
- **Arbitrary/unknown verbs** — some frameworks route `FOO /admin` as `GET` while an access-control
  filter only matched `GET`/`POST`. **HTTP method override** headers (`X-HTTP-Method-Override`,
  `_method` form field) can smuggle a `DELETE` past a filter that only inspects the real verb. This is
  the seed of many auth bypasses (07.2).

### Status codes as an oracle

The server's status code is information it *cannot help but give you*. `200` vs `302` vs `401` vs
`403` vs `404` vs `500` on the same request with different inputs is a side channel: a login that
returns `200` for a valid username and `302` for an invalid one is a **username-enumeration** oracle;
a `500` on a single quote hints at injection (07.3); a `403`→`200` when you change one path segment
hints at broken access control (07.2). You will learn to read *differences* in responses far more
than absolute values.

### Headers, both directions

Request headers you control and abuse:

- **`Host`** — the server may trust it to build absolute URLs (password-reset links → **host-header
  injection**, 07.2), pick a virtual host, or route. It is attacker-controlled.
- **`X-Forwarded-For` / `X-Forwarded-Host` / `X-Original-URL`** — proxies add these; apps sometimes
  trust them for access decisions or IP allow-lists. Spoofable.
- **`Referer` / `Origin`** — used for weak CSRF checks and analytics; both are client-set.
- **`Content-Type`** — switching `application/x-www-form-urlencoded` ↔ `application/json` ↔
  `multipart/form-data` can change how the body is parsed and slip past filters (07.3 NoSQL/JSON).
- **`Cookie`** — the session; see below.

Response headers you read as findings (presence *and absence*, 01.2): `Set-Cookie` flags, `Location`,
`Content-Security-Policy`, `Strict-Transport-Security`, `Access-Control-Allow-Origin`, `Server`/
`X-Powered-By`, and framework leaks like `X-Debug`/stack traces in the body.

## Cookies &amp; session management — where identity lives

HTTP is **stateless**: each request stands alone. To know "this is the same logged-in user," the
server issues a **session identifier** the client returns on every request. Two dominant designs:

1. **Server-side session (opaque cookie).** The cookie holds a random ID (`connect.sid`,
   `JSESSIONID`, `PHPSESSID`, `ASP.NET_SessionId`); the real state lives server-side keyed by that ID.
   The ID must be **unpredictable** and long — a guessable or sequential ID is session hijacking by
   counting.
2. **Client-side / stateless token.** The cookie (or `Authorization: Bearer`) carries the state
   itself — a signed **JWT** or a signed/encrypted blob. Now the *integrity* of that token is
   everything; forge or tamper it and you are whoever it says (07.2 covers JWT attacks in depth).

### The cookie security flags — what each actually defends

<div class="callout key">

- **`HttpOnly`** — JavaScript cannot read the cookie (`document.cookie`). Blunts **XSS-to-session-
  theft**; it does *not* stop the cookie being sent, so it does nothing against CSRF.
- **`Secure`** — the cookie is sent only over HTTPS, so it can't leak over a downgraded/plaintext
  request.
- **`SameSite`** — controls whether the cookie rides along on **cross-site** requests. `Strict` = never
  cross-site; `Lax` (the modern default) = only on top-level `GET` navigations; `None` = always (must
  be paired with `Secure`). This is the primary modern **CSRF** control — `SameSite=Lax/Strict`
  neuters most classic CSRF, which is why CSRF has faded relative to a decade ago, but `None`, GET-based
  state changes, and method/subdomain quirks keep it alive.
- **`Path` / `Domain`** — scope. A cookie scoped to a parent domain is shared with every subdomain — a
  vulnerable subdomain can then read or set it (session fixation, cookie tossing).
- **Expiry** — a session cookie (no `Expires`/`Max-Age`) dies with the browser; a persistent one
  lingers on disk.

</div>

### Session lifecycle bugs a tester probes

- **Predictable IDs** — capture several session IDs; are they random or a counter/timestamp? (Verify
  by collecting a sample, not by eyeballing one.)
- **Session fixation** — does the app issue you a session *before* login and keep the **same** ID
  *after* login? If so an attacker who plants a known ID can ride the victim's authenticated session.
  The fix is to rotate the ID on privilege change.
- **No/weak logout &amp; timeout** — does the server actually invalidate the session, or just delete the
  client cookie? Replay the old cookie after logout; if it still works, logout is cosmetic.
- **Tokens in the URL** — a session/reset token in the query string leaks via `Referer`, logs, and
  history.

## Manual investigation — raw HTTP with curl

Before any proxy, prove you can drive the conversation by hand (01.2's `curl -v`), because the proxy
only automates what you already understand.

```bash
# LAB TARGET ONLY (see the legal box). Log in and capture the session cookie.
curl -i -s -c jar.txt \
  -d 'user=lab&password=Lab-Passw0rd!' \
  http://webapp.lab/login
# -c writes cookies to jar.txt; -i shows response headers including Set-Cookie.

# Reuse the captured session on an authenticated route:
curl -i -s -b jar.txt http://webapp.lab/account
# -b sends the jar. Now change ONE thing (a path id, a header) and compare responses.

# Probe the method: does a GET reach a state-changing endpoint the UI only POSTs to?
curl -i -s -b jar.txt -X GET 'http://webapp.lab/account/delete?id=self'
```

The discipline is **one variable at a time**: baseline request → change exactly one thing (method,
one parameter, one header, the cookie) → diff the response (status, length, timing, body). That diff
is your signal. This is the same "recognize it from behavior" habit you will apply to every bug.

## Tooling — the intercepting proxy

<div class="callout method">

**What it is.** An intercepting proxy (Burp Suite Community/Professional, or OWASP ZAP) sits between
your browser and the target. Your browser trusts the proxy's CA certificate, so the proxy can read
and rewrite HTTPS. Everything the app does becomes visible and editable.

**The core workflow:**

- **Proxy / Intercept** — pause each request, edit it in flight, forward it. Use it to see exactly
  what the browser sends (including the requests JavaScript makes that you never see in the URL bar).
- **Target / Site map** (Burp) or **Sites tree** (ZAP) — the proxy records every request into a tree
  of hosts → paths, building your map as you browse. This *is* your application map.
- **Repeater** (Burp) / **Requester** (ZAP) — send one request, edit it, resend, repeat. This is your
  primary manual-testing surface: the GUI version of the `curl` loop above. Almost all careful web
  testing happens here.
- **Intruder** (Burp) / **Fuzzer** (ZAP) — take one request, mark insertion points, and iterate a
  payload list across them (fuzzing, enumeration, brute-forcing IDs). Powerful, but noisy and easy to
  misuse — respect the RoE's rate limits, and remember Community-edition Intruder is throttled.
- **Decoder / Inspector** — encode/decode Base64, URL, hex; decode JWTs. Essential for reading
  tokens and cookies.
- **Passive scan / spider** — ZAP and Burp Pro can crawl and flag issues automatically. Treat output
  as *leads*, never proof — the same rule as LinPEAS in [04.2](../module-04/lesson-02.md).

**Limits.** A proxy shows and replays traffic; it does not understand your target's business logic,
and its automated scanner misses authorization and logic bugs entirely (the highest-value findings).
It is an accelerator for manual reasoning, not a substitute. Always confirm a scanner hit by hand in
Repeater.

</div>

Configure it once: point the browser at `127.0.0.1:8080`, install the proxy CA in the browser's trust
store, and scope the target so you never proxy or attack anything outside the lab.

## Mapping an application (LAB ONLY)

<div class="callout attack">

**Technique — build the map, don't just browse it.** Systematically walk the app so the proxy records
everything, then read the site map as an inventory:

1. **Crawl by hand** — exercise every feature while logged out, then as `lab`, then (if you have one)
   as an admin. Each role reveals different routes; the *difference* between what roles can reach is
   your access-control surface (07.2).
2. **Enumerate hidden content** — `robots.txt`, `sitemap.xml`, JS source (endpoints and API paths are
   often hard-coded in front-end bundles), `OPTIONS` responses, comments, and error pages. Directory
   brute-forcing (`ffuf`, `feroxbuster`) fills gaps — with a wordlist, respecting rate limits.
3. **Inventory parameters** — for every route, list its parameters (query, body, JSON keys, headers,
   cookies) and their apparent type/purpose. Parameters are where injection and IDOR live.
4. **Find the session mechanism** — which cookie/header carries identity? Is it opaque or a JWT? What
   flags are set? Rotate on login?
5. **Map the auth surface** — every login, logout, registration, password-reset, and privilege
   boundary (`/admin`, role-gated actions, per-object ownership).

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Every request in this module targets `labs/lab-07-web` on the isolated
network, authenticating with the synthetic `lab / Lab-Passw0rd!` and reading benign
`LAB-FLAG-{uuid}` markers and synthetic data only. Pointing a proxy, spider, Intruder, or `ffuf` at a
site you do not own and are not explicitly authorized to test is a crime ([00.1](../module-00/lesson-01.md)) — and spidering/fuzzing generate real load. Confirm scope, authorization,
and rate limits before every session.

</div>

## Verification

A finding at this stage is a *fact about behavior*, verified by reproduction in Repeater: "sending
`GET` to `/account/delete` returns `200` and removes the record" — shown by the request, the response,
and the state change. "The session cookie lacks `HttpOnly`/`SameSite`" — shown by the raw
`Set-Cookie`. "Logout does not invalidate the session" — shown by replaying the post-logout cookie and
getting `200`. Capture request + response, not a screenshot of the rendered page.

## Impact

Mapping itself is not an exploit, but it *scopes* every exploit that follows and produces real
findings on its own: missing cookie flags (session theft amplifier), state changes over `GET` (CSRF),
weak/predictable session IDs (hijacking), session fixation, cosmetic logout, tokens in URLs, verbose
`Server`/error headers. In the report (M16) these are the low/medium findings that frame the
high-severity ones you find later.

## Remediation

<div class="callout defend">

- Set `HttpOnly`, `Secure`, and `SameSite=Lax` (or `Strict`) on session cookies; scope `Path`/`Domain`
  as narrowly as possible.
- Use long, cryptographically random session IDs; **rotate the ID on login and any privilege change**
  (kills fixation); invalidate server-side on logout and after an idle/absolute timeout.
- Enforce the intended method per route; don't let `GET` perform state changes; ignore untrusted
  method-override headers.
- Never trust `Host`, `X-Forwarded-*`, `Referer`, or `Origin` for security decisions without
  validating against an allow-list.
- Add `Strict-Transport-Security`, a restrictive `Content-Security-Policy`, and suppress
  `Server`/`X-Powered-By`/stack traces. (CWE-614, CWE-1004, CWE-384, CWE-352.)

</div>

## Detection / blue-team view

<div class="callout defend">

- **Proxy-driven testing** looks like a single client hitting many endpoints fast, with edited
  headers and unusual method/verb combinations — visible in WAF and access logs.
- **Spidering/Intruder** shows bursts of `404`s, sequential ID access, and high request rates from one
  source — classic enumeration signatures.
- Alert on **method anomalies** (`PUT`/`DELETE`/`TRACE`, override headers), spoofed `X-Forwarded-*`,
  and post-logout use of an invalidated session. These map to **MITRE ATT&CK T1595** (Active Scanning)
  and **T1590/T1592** (gathering victim info); the recurring idea is *one source exercising the app
  far more thoroughly and faster than a human would.*

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-07-web` (built separately) — an intentionally vulnerable web-app suite in
Docker on a private, no-Internet network. **Access:** attacker box with Burp/ZAP configured; the
synthetic account `lab / Lab-Passw0rd!` and (for later lessons) an admin account. **Targets:** the
lab app only; proof markers are benign `LAB-FLAG-{uuid}` values and synthetic records. **Time:**
~75 min. **Isolation:** private Docker network; reset per the lab README between attempts. **Scope
your proxy to the lab host so nothing else is ever touched.**

</div>

Configure the proxy, trust its CA, and scope it to the lab. Browse the whole app logged out and as
`lab`, letting the site map fill. Then, from the site map alone, write the application map described
in the exercise.

## Exercise

<div class="callout method">

**Situation.** Authorized grey-box test of the lab app. You have the `lab` account and a configured
intercepting proxy. No source code.

**Objective.** Reconstruct the app's **session mechanism and authentication surface** from intercepted
traffic — the map every later 07 lesson builds on.

**Starting information.** The running lab app and your `lab` credentials.

**Constraints.** Lab target only; stay within the proxy scope and the RoE rate limit. Do **not**
exploit anything yet — this is mapping and characterization. One variable at a time when you probe.

**Expected deliverables.**
1. A **route + parameter inventory** grouped by trust boundary (unauthenticated / authenticated-user /
   admin), noting each parameter's apparent purpose.
2. A **session characterization**: which cookie/header carries identity; opaque vs JWT; the exact
   `Set-Cookie` flags; whether the ID **rotates on login**; whether **logout** truly invalidates it
   (show the replay test); and a first read on whether IDs look random or predictable.
3. An **auth-surface map**: every login/register/reset/logout endpoint and every privilege boundary,
   with the method(s) each accepts (did you find a state change reachable by an unexpected method?).
4. Two prioritized hypotheses for later lessons, each tied to the behavior that suggests it.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Everything left of the browser↔server line is yours to change. Your map is really a list of every
place the server reads a client-controlled value and the decision it makes from it.
</details>

<details><summary>Hint 2 — technique family</summary>
Watch the traffic during login and logout in the proxy, not the rendered page. Compare the
<code>Set-Cookie</code> before and after login (rotation?), and replay the old cookie after logout
(invalidation?). Diff responses across roles for the same route (access-control surface).
</details>

<details><summary>Hint 3 — where to look</summary>
Front-end JS bundles and <code>OPTIONS</code> responses list endpoints the UI never shows. Try
sending a UI-only <code>POST</code> action as <code>GET</code> in Repeater. Collect several session
IDs into the proxy and eyeball them for structure before claiming "random."
</details>

## Check yourself

<div class="callout key">

1. Why is *every* value the browser sends — including the `Host` and `Cookie` headers — considered
   attacker-controlled, even the parts your own JavaScript set?
2. A session cookie has `HttpOnly` and `Secure` but no `SameSite`. Which attack class does this
   *fail* to defend against, and why do the other two flags not help there?
3. The app issues `SESSION=abc` before you log in and, after a successful login, keeps sending
   `SESSION=abc`. Name the vulnerability and the one-line fix.
4. You send `GET /transfer?to=lab2&amt=100` (the UI uses `POST`) and get `200` plus a completed
   transfer. What two distinct problems does this reveal, and which later lesson does each feed?
5. Why is a proxy's automated scanner good at reflected XSS and missing headers but blind to the
   IDOR/access-control bugs that are usually the most serious finding?

</div>

Model answers are in `solutions/module-07-part1.md` (instructor material — try them first).

## References

- **OWASP Web Security Testing Guide (WSTG) v4.2** — WSTG-INFO (mapping/fingerprinting),
  WSTG-SESS (session management testing), WSTG-CONF (HTTP methods).
- **OWASP Cheat Sheets** — Session Management; HTTP Headers; CSRF Prevention.
- **RFC 9110** HTTP Semantics (methods, status, headers); **RFC 6265bis** Cookies (`SameSite`,
  `HttpOnly`, `Secure`).
- **PortSwigger Web Security Academy** — "Your first request" / Repeater / Intruder; and the OWASP ZAP
  "Getting Started" guide.
- **CWE-384** Session Fixation; **CWE-614** Sensitive Cookie without `Secure`; **CWE-1004** Sensitive
  Cookie without `HttpOnly`; **CWE-352** CSRF.
- **MITRE ATT&CK** — T1595 Active Scanning; T1590/T1592 Gather Victim Information.

## What you should now be able to do

- Draw the web trust boundary and explain why the client is always attacker-controlled.
- Read and manipulate HTTP methods, status codes, and headers as levers and oracles.
- Characterize a session mechanism (opaque vs token), read cookie flags as controls, and test for
  fixation, weak invalidation, and predictability.
- Drive an intercepting proxy's Proxy/Site map/Repeater/Intruder workflow, and know its limits.
- Map an application into a route/parameter/session/auth-surface inventory that scopes the rest of M07.

## Progress checkpoint

```bash
py course.py complete 07.1
```
