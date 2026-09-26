# 07.4 — Client-side &amp; cross-origin: XSS, CSRF, CORS, and the SSRF/XXE server-side request family

<div class="prereq">

**Prerequisites:** [00.1 Authorization](../module-00/lesson-01.md), [00.3 Threat modeling &amp; the
confused deputy](../module-00/lesson-03.md), [01.2 DNS/HTTP/TLS](../module-01/lesson-02.md),
[03 Enumeration](../module-03/lesson-01.md), and Module 07's first three lessons —
[07.1 HTTP/cookies/sessions](lesson-01.md), [07.2 Authn/authz &amp; access control](lesson-02.md),
[07.3 The injection family](lesson-03.md). You must already read a request/response fluently and
know how cookies and the same-origin model work.
**Module:** M07 Web application penetration testing. **Difficulty:** 🔴 advanced.
**You will produce:** one demonstrated client-side-or-SSRF finding on the lab app, chained to a
concrete impact, with mechanism, verification evidence, remediation, and detection.

</div>

## Why this matters

07.3 taught injection into an *interpreter the server runs* (SQL, a shell, a template). This lesson
covers the other half of web attack surface: bugs that abuse **trust between origins and between a
privileged actor and its input**. XSS runs your code in another user's browser session; CSRF makes
that browser act with the victim's authority; CORS misconfiguration hands your JavaScript another
origin's authenticated data; SSRF turns the server into your proxy into the internal network; XXE
turns an XML parser into a file-reader and a second SSRF primitive. Every one is a **confused
deputy** (00.3) — a component acting on attacker-controlled input using privileges the attacker does
not have. These are among the highest-frequency serious findings in real web engagements, and none
is reliably caught by a scanner, because each depends on *context* the scanner cannot see.

## Learning objectives

- Distinguish reflected, stored, and DOM-based XSS, and explain why the **output context**
  (HTML body, attribute, JS, URL) — not the input — dictates the payload and the defense.
- Recognize CSRF from the shape of a state-changing request, and explain what `SameSite` and
  anti-CSRF tokens actually stop.
- Read a CORS request/response pair and identify the reflected-origin-plus-credentials misconfig.
- Recognize classic and blind SSRF, reason about filter bypasses, and demonstrate reaching an
  **internal lab service** and a **local metadata simulation** (never real cloud metadata).
- Recognize XXE and use it for file read and as an SSRF vector; explain billion-laughs at the
  concept level.
- For each: recognize from behavior → prove safely with an inert marker → state impact →
  remediate → detect.

## Intuition

Two trust relationships are being abused here. **The browser trusts the origin.** The same-origin
policy is meant to stop `evil.com`'s script from reading `bank.com`'s data — but if `bank.com`
*reflects your script back into its own page* (XSS), the script now runs *as* `bank.com` and the
policy protects the attacker. **The server trusts itself.** A server sits behind the firewall, holds
credentials, and can reach internal hosts the Internet cannot; if you can make it fetch a URL or
parse an XML document you supply (SSRF, XXE), you borrow all of that reach. Say the confused-deputy
sentence out loud for each bug: *"component A acts on input from B, using A's privileges — can B make
A do what B couldn't?"* If yes, you have the shape of the finding before you write a payload.

## The underlying technology

### Same-origin policy and the browser as an execution environment

An **origin** is `scheme://host:port`. The same-origin policy (SOP) lets a page freely *send*
cross-origin requests but restricts *reading* cross-origin responses, and it isolates the DOM,
cookies, and storage of one origin from another. Two facts drive this whole lesson: (1) the browser
executes whatever HTML/JS an origin sends it, with that origin's privileges (its cookies, its DOM,
its stored tokens); (2) cookies are attached to requests **by destination**, regardless of who
triggered the request — the seed of CSRF.

### Where the parser lives

XSS is injection into the **browser's HTML/JS parser**; SQLi (07.3) was injection into the database
parser. XXE is injection into the **server's XML parser**. SSRF isn't injection at all — it is
*supplying a URL to a function that fetches it*. Knowing which parser or fetch you are feeding tells
you the payload grammar and the defense.

### XSS — three delivery paths, many output contexts

XSS is running attacker script in a victim's browser in the target's origin. The three **delivery
paths** differ only in where the payload lives:

- **Reflected** — the payload is in the request (a query parameter, a header) and echoed straight
  into the response. One victim per crafted link; needs delivery (phishing, a link).
- **Stored** — the payload is saved server-side (a comment, a profile field, a support ticket) and
  served to every viewer. Higher impact: it fires for anyone who loads the page, including admins.
- **DOM-based** — the vulnerable data flow is entirely in client-side JS: a *source* (e.g.
  `location.hash`, `document.referrer`) reaches a dangerous *sink* (`innerHTML`, `eval`,
  `document.write`, `element.setAttribute`) without the payload ever reaching the server. You find
  it by reading JavaScript, not by watching responses.

What actually decides the payload is the **output context** — where in the response your input
lands:

| Context | Example sink | A marker that fires |
|---|---|---|
| HTML body | `<div>INPUT</div>` | `<img src=x onerror=alert(document.domain)>` |
| HTML attribute | `<input value="INPUT">` | `"><svg onload=alert(document.domain)>` (break out of the attribute) |
| JavaScript string | `var q = "INPUT";` | `";alert(document.domain)//` (break out of the string) |
| URL / `href` | `<a href="INPUT">` | `javascript:alert(document.domain)` |

The same input string is harmless in one context and executes in another. This is why "recognize the
context" is the entire skill, and why a blocklist that strips `<script>` misses the `onerror`
attribute payload.

### CSRF — the browser is the deputy

A **cross-site request forgery** abuses the fact that the browser attaches the victim's cookies to a
request *no matter which site initiated it*. If a state-changing action (`POST /account/email`,
`GET /transfer?to=...`) relies **only** on the session cookie for authorization, an attacker page
can submit that request from the victim's browser, and the server — seeing a valid session cookie —
performs it as the victim. The two defenses:

- **Anti-CSRF token** — an unpredictable per-session/per-request value the server issues and
  requires back in the request body/header. The attacker's cross-site page cannot read it (SOP), so
  it cannot forge a valid request.
- **`SameSite` cookies** — `SameSite=Lax` (the modern browser default) stops the cookie from being
  sent on most cross-site *sub-requests* (e.g. a form auto-POST from another origin), which
  neutralizes the classic CSRF vector for top-level state changes; `Strict` is stronger but breaks
  cross-site navigation. `SameSite` is defense-in-depth, not a replacement for tokens — GET-based
  state changes, `Lax`'s top-level-navigation exemption, and same-site subdomains still leave gaps.

### CORS — relaxing the SOP, sometimes too far

**Cross-Origin Resource Sharing** lets a server opt in to letting *specific* other origins read its
responses, via `Access-Control-Allow-Origin` (ACAO) and, for authenticated reads,
`Access-Control-Allow-Credentials: true` (ACAC). The dangerous misconfiguration is a server that
**reflects the request's `Origin` header into ACAO and sets ACAC true** — meaning *any* origin,
including the attacker's, can make the victim's browser fetch the endpoint with credentials and read
the response. `Access-Control-Allow-Origin: *` cannot be combined with credentials by spec, so the
reflected-origin variant is the one that leaks authenticated data.

### SSRF — the server is the deputy

**Server-side request forgery** is making the server issue a request to a URL you control. Servers
routinely fetch URLs: webhook testers, URL-preview/thumbnail generators, PDF renderers, "import from
URL," SSO metadata fetchers, XML/SVG processors. Because the server sits inside the network, your
request reaches things you can't: `http://localhost:8080/admin`, an internal-only inventory service,
a database admin port, and — the classic escalation — a **cloud metadata endpoint** at
`169.254.169.254` that hands out temporary credentials.

- **Classic (in-band) SSRF** — the fetched response comes back to you; you read internal pages
  directly.
- **Blind SSRF** — no response is returned, but the request *happens*; you confirm it out-of-band
  (a request lands on a listener you control) and exploit it against endpoints whose *side effects*
  matter (e.g. an internal action that needs no response).

<div class="callout warn" data-badge="current">

**CURRENT.** Cloud metadata is the highest-impact SSRF target in real engagements. In this course
you attack a **local metadata SIMULATION** on the lab network only — never `169.254.169.254` on a
real host or in a real cloud account. The real IMDSv1/IMDSv2 mechanics and defenses are covered in
[M14 Cloud](../module-14/lesson-01.md); this lesson teaches the *reachability* mechanism against a
lab stand-in.

</div>

### XXE — the XML parser as file-reader and fetcher

XML documents can declare a **DTD** with **external entities**. A parser that resolves external
entities will read a local file or fetch a URL when the entity is referenced:

```xml
<!-- LAB ONLY. Mechanism illustration with an inert marker path. -->
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY x SYSTEM "file:///lab/marker.txt"> ]>
<order><note>&x;</note></order>
```

If the app echoes the parsed `note` back, `&x;` is replaced by the file's contents — **XXE file
read**. Point the entity at `http://internal-lab-service/` instead and XXE becomes an **SSRF**
vector. A **parameter entity + external DTD** enables **out-of-band (OOB) XXE** when the value isn't
reflected — the parser exfiltrates the read data to a listener you control. **Billion laughs** is a
separate DTD abuse: nested entities that expand exponentially to exhaust memory (a DoS — normally
out of RoE; you recognize the pattern and do **not** fire it).

## Why the weakness exists

Every bug here is misplaced trust across a boundary. XSS: the app treats user input as *code* when
it renders it, mixing data and instructions in the browser's parser (CWE-79) — the same class as
SQLi, different interpreter. CSRF: the app authenticates the *cookie* but not the *intent*, so it
cannot tell a genuine click from a forged one (CWE-352). CORS: a developer needed cross-origin access
and reflected the origin to "make it work," trusting the client-supplied `Origin` (CWE-942). SSRF:
code fetches a URL supplied by the user, trusting that the URL is external and benign (CWE-918) — the
canonical confused deputy. XXE: the XML parser resolves external entities by default (historically
true of many libraries), trusting the document to be inert data (CWE-611). In each, a component
acts on untrusted input with more authority than the input's source deserves.

## How a tester recognizes it

- **XSS:** your input reflected verbatim in a response (view-source, not the rendered page — the
  browser may have decoded it); a stored field re-displayed to others; JS that reads
  `location.*`/`document.referrer`/`postMessage` and writes to `innerHTML`/`eval`. A benign marker
  string echoed unencoded is the tell.
- **CSRF:** a state-changing request whose only auth is the cookie, with **no unpredictable token**
  in body/header and a cookie that isn't `SameSite=Strict/Lax`-protected for that flow.
- **CORS:** send `Origin: https://evil.example` and watch whether ACAO reflects it back with
  `Access-Control-Allow-Credentials: true`.
- **SSRF:** any parameter that is a URL, hostname, or file path the server fetches — `url=`,
  `image=`, `callback=`, `webhook=`, `next=`, an XML/SVG upload, a PDF-from-HTML feature. Differing
  response times/errors for internal vs external hosts is a blind-SSRF tell.
- **XXE:** any endpoint that accepts XML (`Content-Type: application/xml`, SOAP, SVG, `.docx`/`.xlsx`
  uploads, RSS). Try a benign external entity and watch for reflection or an OOB hit.

## Manual investigation

<div class="callout method">

**Recognize context, then prove minimally.** For XSS, inject a unique, harmless marker
(`zqx7HTMLtest"><'`) and find *exactly* where each character lands in the raw response — that tells
you the context and which characters you must break out of, before you ever try to execute. For CSRF,
capture the target request and ask: is there a token? Is the cookie `SameSite`? Would a cross-site
form reproduce it? For CORS, add an `Origin` header and diff the response headers. For SSRF, start
with a URL you control (an internal lab listener) to confirm the fetch *happens*, then enumerate
internal targets. For XXE, confirm the parser resolves entities with a harmless internal/file marker
before anything else. Never jump to a weaponized payload — confirm the primitive first.

</div>

## Tooling — what it does, key options, limits, verify by hand

- **Burp Suite (Repeater)** — replay and mutate a single request; the core tool for confirming
  context and testing filter bypasses one variable at a time. *Limit:* it shows the exchange, not
  the browser's rendering — always confirm XSS execution in a real browser.
- **Burp Intruder** — fuzz an injection point across a payload set (context-breakers, SSRF host
  lists, encodings). *Limit:* rate-limited in the community edition; noisy — mind the RoE.
- **Burp Collaborator (or a self-hosted OOB listener)** — a server you control that records DNS/HTTP
  hits, used to confirm **blind SSRF** and **OOB XXE**. In this course the equivalent is a listener
  **on the lab network** (e.g. a lab HTTP catcher) — never a public Collaborator against a real
  target. *Limit:* proves the request happened, not always what it achieved.
- **Browser DevTools** — the authority for DOM XSS (source→sink tracing in the debugger) and for
  observing CORS behavior in the Network tab. *Limit:* your reasoning, not the tool, finds the sink.
- **Automated scanners (DAST)** — flag reflected XSS and some SSRF/CORS patterns. *Limit:* miss
  stored/DOM XSS, context nuances, and logic-dependent SSRF; treat every hit as a lead to verify
  by hand.

## Exploitation / demonstration (LAB ONLY)

<div class="callout attack">

**Reflected XSS — context-driven.** The lab search page reflects `q` into an HTML attribute:
`<input value="INPUT">`. A body-context `<script>` payload would be inert here; you must break the
attribute first:

```text
?q="><svg onload=alert(document.domain)>
```

The `">` closes the `value` attribute and the `<input>` tag; the `<svg onload>` then executes. The
marker `alert(document.domain)` **proves the origin** in which your script runs — inert, non-
destructive, and unambiguous evidence. Same input in a JS-string context needs `";alert(...)//`
instead. *Recognize the context, then pick the breakout.*

</div>

<div class="callout attack">

**CSRF PoC.** The lab's "change email" endpoint takes `POST /account/email` with only the session
cookie for auth and no token. An attacker-hosted page auto-submits it from the victim's browser:

```html
<!-- LAB ONLY — hosted on the attacker origin; victim is logged in to the lab app. -->
<form action="http://app.lab/account/email" method="POST">
  <input name="email" value="attacker@lab.invalid">
</form>
<script>document.forms[0].submit()</script>
```

It works only because the cookie rides along and no token gates the request. Setting the session
cookie `SameSite=Lax` stops this auto-POST; a per-request token the attacker can't read stops it
regardless.

</div>

<div class="callout attack">

**CORS misconfig.** Probe the authenticated `/api/profile` endpoint:

```http
GET /api/profile HTTP/1.1
Host: app.lab
Origin: https://evil.lab
Cookie: session=<victim>

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.lab      ← reflected our Origin
Access-Control-Allow-Credentials: true             ← with credentials
```

Because ACAO reflects the attacker origin *and* credentials are allowed, a script on `evil.lab` can
`fetch('http://app.lab/api/profile', {credentials:'include'})` and **read** the victim's profile
JSON. Verify by reading the actual JSON in the response, not just the headers.

</div>

<div class="callout attack">

**SSRF to an internal lab service and metadata simulation.** The "import from URL" feature fetches
`url=`. Point it inward:

```text
url=http://localhost:8080/admin           → reaches an internal-only admin page
url=http://inventory.lab:9000/health      → reaches an internal service the Internet can't
url=http://169.254.169.254.lab/latest/... → the LAB metadata SIMULATION (never a real cloud IP)
```

Filter bypasses to reason about (test only against the lab): decimal/octal/hex IP encodings of
`127.0.0.1`, `http://127.1`, a DNS name that resolves to an internal IP, adding a userinfo prefix
(`http://expected@internal`), or an open redirect on an allowed host that bounces to the internal
target. The lab metadata simulation returns a **synthetic** `LAB-FLAG-{uuid}` credential — proving
the reachability mechanism without any real secret. This ties directly to the confused deputy (00.3)
and to M14.

</div>

<div class="callout attack">

**XXE file read and SSRF.** The lab order API accepts XML. A benign external entity reads a lab
marker file, and a second points at an internal service:

```xml
<!DOCTYPE r [ <!ENTITY x SYSTEM "file:///lab/marker.txt"> ]>
<order><note>&x;</note></order>          <!-- reflected note = file contents (file read) -->
```

Swap the entity to `SYSTEM "http://inventory.lab:9000/"` and the parser fetches it — XXE-as-SSRF.
If the value isn't reflected, an external-DTD parameter-entity chain exfiltrates it OOB to the lab
listener (concept; you build it against the lab only). Do **not** fire a billion-laughs payload —
recognize it, describe the DoS, move on.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Every payload above targets `labs/lab-07-web` on the isolated
network, uses inert markers (`alert(document.domain)`, `LAB-FLAG-{uuid}`, `attacker@lab.invalid`),
and reaches only lab-internal services and the **local metadata simulation**. Running any of this
against a system you do not own and are not explicitly authorized to test — and in particular
touching real cloud metadata at `169.254.169.254` — is a crime (00.1). Restate scope and
authorization before you touch anything outside the lab.

</div>

## Verification

Proof is behavioral and specific. **XSS:** the marker executes *in the target origin* — a real
browser shows `app.lab` in the `alert(document.domain)` dialog (or a benign DOM change you scripted);
a reflection in view-source that does not execute is a lead, not a confirmed finding. **CSRF:** the
victim's state actually changed (the email is now `attacker@lab.invalid`) driven solely from the
attacker page. **CORS:** you captured the cross-origin `fetch` returning the victim's private JSON.
**SSRF:** you retrieved internal-only content or the synthetic metadata `LAB-FLAG-{uuid}`, or the
lab OOB listener logged the server's request (blind). **XXE:** the reflected node contains the lab
marker file's contents, or the listener recorded the entity fetch. Capture the request, the
response, and the origin/host reached — a screenshot of an alert box without the request is weak
evidence.

## Impact

<div class="callout key">

- **XSS** → session/token theft, action-as-victim, credential capture via injected forms, and — for
  stored XSS hitting an admin — effective account takeover of the application. It runs with the
  victim's full authority in the origin.
- **CSRF** → any state change the victim can make (change email/password → account takeover, transfer
  funds, change settings), performed without the victim's intent.
- **CORS misconfig** → cross-origin theft of authenticated data (profiles, tokens, API keys),
  sometimes enabling full account compromise if secrets are exposed.
- **SSRF** → internal network reconnaissance and reaching internal-only services; **cloud metadata
  SSRF** commonly yields temporary cloud credentials → cloud account compromise (M14). The classic
  confused-deputy escalation.
- **XXE** → arbitrary local file read (config, secrets, source), SSRF into the internal network, and
  DoS (billion laughs). File read of a credentials config often chains into deeper compromise.

</div>

## Remediation

<div class="callout defend">

- **XSS:** **context-aware output encoding** at every sink (HTML, attribute, JS, URL each need a
  different encoding) — the primary defense. Prefer frameworks that auto-escape and safe sinks
  (`textContent` over `innerHTML`). Add a strong **Content-Security-Policy** as defense-in-depth
  (e.g. nonce-based `script-src`, no `unsafe-inline`) — knowing CSP can be *bypassed* (unsafe-inline,
  overly broad allowlists, JSONP endpoints) means it is a mitigation, not a fix. Set `HttpOnly` on
  session cookies so stolen script can't read them.
- **CSRF:** unpredictable **anti-CSRF tokens** (synchronizer or double-submit) validated server-side,
  plus `SameSite=Lax`/`Strict` cookies, plus rejecting state changes on `GET`. Check `Origin`/
  `Referer` for sensitive actions.
- **CORS:** never reflect `Origin`; use a strict allowlist; **never** combine a wildcard/permissive
  origin with `Allow-Credentials: true`; keep sensitive data out of CORS-reachable GET endpoints.
- **SSRF:** validate URLs against an **allowlist** of permitted hosts/schemes (not a blocklist);
  resolve the hostname and block private/link-local ranges *after* resolution (defeats DNS
  rebinding); disable unneeded schemes/redirects; on cloud, enforce **IMDSv2** (M14). Isolate the
  fetcher on a network segment with no access to internal services.
- **XXE:** **disable external entities and DTD processing** in the XML parser (the definitive fix) —
  e.g. `disallow-doctype-decl` / disable external general+parameter entities. Prefer less complex
  formats (JSON) where possible.

</div>

## Detection / blue-team view

<div class="callout defend">

- **XSS:** WAF signatures catch obvious payloads but miss context/DOM cases; better signal is CSP
  `report-uri`/`report-to` violation reports and anomalous parameters containing markup. Stored XSS
  shows as script-like content in persisted fields.
- **CSRF:** hard to see server-side by design; missing-token rejections and `Origin`/`Referer`
  mismatches on state-changing endpoints are the telemetry.
- **CORS:** monitor for reflected-origin responses in egress; it's mostly a code-review/finding, not
  a runtime alert.
- **SSRF:** the strongest signal — **outbound requests from the app server to internal/link-local
  addresses** (especially `169.254.169.254`), and DNS lookups for internal names from a web tier.
  Egress filtering both mitigates and alerts.
- **XXE:** the app server making outbound requests during XML parsing, or reading unexpected local
  files; parser logs for external-entity resolution.

Mapped to **MITRE ATT&CK**: SSRF/XXE reachability aligns with discovery/collection of internal
services; metadata-credential theft is **T1552.005 (Cloud Instance Metadata API)**. XSS/CSRF are
application-layer and tracked via OWASP more than ATT&CK.

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-07-web` (built separately) — an intentionally vulnerable web application
suite on the isolated Docker network, with a companion **internal-only service**, a **local metadata
simulation**, and a **lab OOB listener** for blind confirmation. **Access:** a test account
(`lab / Lab-Passw0rd!`) and an attacker-hosted origin. **Targets:** lab hosts only; benign markers
and synthetic `LAB-FLAG-{uuid}` values throughout. **Time:** ~120 min. **Isolation:** private
network, no Internet route, no real cloud reachable; reset per the lab README between attempts.

</div>

Work each family once: find a reflected/stored/DOM XSS and identify its context; write a CSRF PoC
against a token-less state change; confirm the reflected-origin CORS misconfig by reading private
JSON cross-origin; drive the "import from URL" SSRF to the internal service and the metadata
simulation; and use the XML endpoint for a file-read XXE. Verify each with the evidence above, then
reset.

## Exercise

<div class="callout method">

**Situation.** Authorized web test of the lab app. You hold the `lab` test account and an attacker
origin on the lab network. The client's crown-jewel concern is "could an outsider reach our internal
systems or take over an account through the website?"

**Objective.** Find **one** client-side-or-cross-origin flaw *or* one SSRF/XXE flaw, and **chain it
to a demonstrable impact** — not just "reflection observed," but a concrete result (script executing
as the origin and stealing a session marker, an account state changed via CSRF, private data read
cross-origin, an internal service or metadata marker retrieved, or a lab file read via XXE).

**Starting information.** The `lab` account, the attacker origin, and the lab OOB listener address.
No pre-built exploit.

**Constraints.** Lab target only. Inert markers only — never a destructive or real-exfiltration
payload; never touch real cloud metadata. You must be able to explain the **mechanism** (which
parser/fetch, which trust boundary, why the deputy is confused), not just paste a working string.

**Expected deliverables.**
1. The chosen flaw, its **class and mechanism** (delivery path + output context for XSS; token/
   `SameSite` analysis for CSRF; the reflected-origin+credentials pair for CORS; the fetch primitive
   and target for SSRF; the entity/parser for XXE).
2. Reproduction steps and **verification evidence** (request + response + the origin/host reached or
   the executing marker).
3. The **chained impact** stated in client terms.
4. **Remediation** and **detection** for the specific finding — both required.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Two servers to distrust: the browser's parser (client-side) and the app's own network reach
(server-side). Which class most directly answers the client's "reach internal systems / take over an
account" question? SSRF answers the first; stored XSS or CSRF answers the second.
</details>

<details><summary>Hint 2 — technique family</summary>
For XSS, first map <em>where</em> your marker lands in the raw response and break out of that context
only. For SSRF, confirm the fetch happens against the OOB listener before enumerating internal hosts.
For CORS, one added <code>Origin</code> header tells you everything.
</details>

<details><summary>Hint 3 — where to look</summary>
Hunt URL-shaped parameters and file/XML uploads for SSRF/XXE; hunt reflected and stored inputs and
client-side <code>innerHTML</code>/<code>eval</code> sinks for XSS; hunt token-less
<code>POST</code>s for CSRF; add an <code>Origin</code> header to authenticated JSON endpoints for
CORS.
</details>

<details><summary>Hint 4 — chaining to impact</summary>
Reflection alone is not the finding. For XSS, script the theft of a benign session marker to prove
account-context access. For SSRF, retrieve the synthetic metadata <code>LAB-FLAG-{uuid}</code> — that
is the confused-deputy escalation the client fears, and the bridge to M14.
</details>

## Check yourself

<div class="callout key">

1. The same input string is harmless inside `<div>INPUT</div>` but executes inside
   `<input value="INPUT">`. Why? What does that tell you about where the defense must live?
2. An app sets `SameSite=Lax` on its session cookie but has no anti-CSRF token. Name a state-changing
   flow that could still be CSRF-able, and one that `Lax` now protects.
3. `Access-Control-Allow-Origin: *` is present on an endpoint. Why is that *less* dangerous than a
   reflected specific origin when the endpoint serves authenticated data?
4. You supply `url=http://169.254.169.254.lab/…` and get a synthetic credential back. Explain, in
   confused-deputy terms, exactly whose privilege you borrowed and why the server let you.
5. An XML endpoint reflects nothing back, yet you suspect XXE. How do you confirm the parser resolves
   external entities, and why is an OOB listener the right tool?

</div>

Model answers are in `solutions/module-07-part2.md` (try them before looking).

## References

- **OWASP WSTG** — Testing for Reflected/Stored/DOM XSS (4.7), CSRF (4.6.5), CORS (4.11.1), SSRF
  (4.7.19 / dedicated guide), XXE (4.7.3).
- **OWASP Cheat Sheets** — Cross Site Scripting Prevention, DOM-based XSS Prevention, CSRF
  Prevention, XML External Entity Prevention, SSRF Prevention.
- **CWE** — CWE-79 (XSS), CWE-352 (CSRF), CWE-942 (permissive CORS), CWE-918 (SSRF), CWE-611 (XXE),
  CWE-441 (confused deputy).
- **PortSwigger Web Security Academy / Research** — Cross-origin resource sharing, SSRF (incl. cloud
  metadata and filter bypasses), XXE, DOM-based vulnerabilities.
- **RFC 6454** (Web Origin Concept); **Fetch Standard** (CORS); **W3C CSP Level 3**;
  **RFC 6265bis** (`SameSite` cookies).
- **MITRE ATT&CK** — **T1552.005** Unsecured Credentials: Cloud Instance Metadata API.

## What you should now be able to do

- Classify XSS by delivery path and, crucially, by output context, and pick a context-appropriate
  inert marker.
- Recognize CSRF and explain precisely what tokens and `SameSite` each stop.
- Spot the reflected-origin-plus-credentials CORS misconfiguration and prove it by reading data.
- Recognize classic and blind SSRF, reason about filter bypasses, and reach internal lab services
  and the metadata simulation as a confused deputy.
- Recognize XXE and use it for file read and SSRF, and describe billion-laughs without firing it.
- Remediate and detect each class, and chain any of them to a client-meaningful impact.

## Progress checkpoint

```bash
py course.py complete 07.4
```
