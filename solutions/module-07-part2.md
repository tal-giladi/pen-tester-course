# Instructor / solutions — Module 07, part 2 (07.4–07.5)

> Instructor material. Not linked from `_sidebar.md`. Do the exercises before reading.

These answers cover the client-side/cross-origin and advanced-web lessons ([07.4](../lessons/module-07/lesson-04.md),
[07.5](../lessons/module-07/lesson-05.md)). They assume the `labs/lab-07-web` suite as specified: a
vulnerable app behind a front-end proxy, with a companion **internal-only service**, a **local
metadata simulation** (a stand-in at a lab address, not `169.254.169.254`), a **lab OOB listener**, an
upload store, a `?file=` download endpoint, a Node JSON deep-merge API, a deserialization sink, and a
limited-resource (coupon/balance) endpoint. Markers are inert: `alert(document.domain)`,
`LAB-EXEC-OK`, `LAB-PP-OK`, `LAB-FLAG-{uuid}`, synthetic balances. Exact paths/params vary with the
built lab; **grade on reasoning and mechanism, not on matching a specific string.** Above all, dock
hard for anything weaponized, destructive, real-exfiltrating, or aimed outside the lab — the safety
boundary is the point.

---

## 07.4 — Client-side & cross-origin (XSS/CSRF/CORS/SSRF/XXE)

### Exercise — find & chain a client-side or SSRF flaw to impact

A strong submission picks **one** flaw, proves the **mechanism**, and drives it to a **concrete
result** — not "reflection observed." Full-marks patterns by class:

| Class chosen | What earns full marks |
|---|---|
| Reflected/stored XSS | Identifies delivery path **and output context**; picks a context-appropriate breakout; proves execution *in the app origin* in a real browser; chains to stealing a benign session/CSRF marker (account-context access) |
| DOM XSS | Traces source→sink in DevTools (e.g. `location.hash` → `innerHTML`); proves execution without the payload touching the server |
| CSRF | Shows the target request has **no token** and the cookie isn't `SameSite`-protected for that flow; the attacker page actually changes victim state (email → `attacker@lab.invalid`) |
| CORS | One `Origin: https://evil.lab` header shows reflected ACAO **+** `Allow-Credentials: true`; cross-origin `fetch(...,{credentials:'include'})` returns the victim's private JSON |
| SSRF | Confirms the fetch happens (OOB listener) before enumerating; reaches an internal-only service **and** retrieves the synthetic metadata `LAB-FLAG-{uuid}`; names the confused deputy explicitly and links forward to M14 |
| XXE | Confirms external-entity resolution with a benign file/internal marker; reads a lab marker file and/or fetches an internal service (XXE-as-SSRF); describes billion-laughs without firing it |

Grading: (a) mechanism stated in confused-deputy / trust-boundary terms (which parser or fetch, whose
privilege borrowed); (b) evidence includes the **request + response + origin/host reached or executing
marker**, not just a screenshot of an alert; (c) impact in client terms; (d) remediation **and**
detection both present and specific; (e) strictly inert, lab-only, no real cloud metadata. Docking:
"I saw my input reflected" with no execution proof; firing a destructive/real payload; touching
`169.254.169.254` on a real host; recommending "add a WAF" as the primary XSS fix instead of
context-aware output encoding.

### Check-yourself

1. **Context decides execution.** In `<div>INPUT</div>` the browser parses INPUT as text/markup, so a
   payload must *introduce* an executing element (`<img onerror>`); the naive `<script>` may be
   stripped or not re-parsed. In `<input value="INPUT">` your bytes sit inside an attribute, so you
   must first **break out** of the attribute/tag (`">…`) before anything executes. Lesson: the defense
   must live **at the output sink**, encoded for *that* context — input filtering can't know where the
   value will land.
2. `SameSite=Lax` sends the cookie on **top-level navigations** (a full-page GET) but not on
   cross-site sub-requests like a background form auto-POST. So a classic auto-POST CSRF to
   `POST /account/email` is blocked; but a **GET-based state change** (`/transfer?to=...`) reached by
   a top-level navigation (a link the victim clicks / a redirect) can still fire under `Lax`. `Lax`
   also doesn't help across same-site subdomains. Tokens are still required.
3. Per the Fetch spec a browser will **not** expose a credentialed cross-origin response when ACAO is
   the wildcard `*` — `*` and `Allow-Credentials: true` are mutually exclusive. So `*` on an
   authenticated endpoint typically can't be read *with the victim's cookies*. A **reflected specific
   origin** + `Allow-Credentials: true` *does* let the attacker origin read the credentialed response —
   which is why the reflected-origin variant is the dangerous one.
4. You borrowed the **web server's** network position and identity. The server is a confused deputy:
   it holds a privilege you lack (a route to the link-local metadata address / internal network), and
   the "import from URL" code trusted that the URL you supplied was an external, benign resource
   (CWE-918). It fetched an internal address *on your behalf* and returned the (synthetic) credential.
   In real cloud this is the temporary-credential theft covered in M14; here it's a lab simulation.
5. Send a **benign external entity** pointing at a lab file or an internal marker
   (`<!ENTITY x SYSTEM "http://<lab-oob-listener>/probe">`). If the value isn't reflected, you can't
   see the result in-band, so you confirm the parser resolved the entity by the **out-of-band hit**
   landing on your lab listener — that proves external-entity processing is enabled (the primitive)
   even with zero reflection, and is the basis for OOB exfiltration via a parameter-entity/external-DTD
   chain.

---

## 07.5 — Advanced web (upload/traversal/deserialization/PP/smuggling/cache/race)

### Exercise — chain two independent weaknesses (Scenario E)

The deliverable is a **report-ready finding** built from **two independent** weaknesses. Independence
matters: grade down if the "two" are really one bug and its step (e.g. "traversal, and reading a file
with traversal"). Strong chains and what makes them full marks:

| Chain | Why it earns full marks |
|---|---|
| Upload to non-executing store **+** path traversal / LFI | Upload alone isn't RCE (non-executing store); the traversal/LFI *consumes* the dropped file's path to execute it. Proves each independently, then shows the uploaded `LAB-EXEC-OK` reached via the traversal → execution |
| Server-side prototype pollution **+** template/option gadget | PP sets a polluted default; a separate template/render path reads it → XSS/SSTI or config change. Two distinct code paths, one composed impact |
| Cache deception **+** an endpoint reflecting a session marker | Deception caches a "private" response under a public key; the second flaw is what makes that response *sensitive*. Composed = theft of another (lab) context's data |
| Logic bug **+** race condition | The race multiplies a single-use/limited effect; the logic bug is what's worth multiplying (coupon/balance). Independent, and the combination is the real severity |
| SSRF (07.4) **+** an internal service weakness | SSRF reaches an internal-only endpoint; a second flaw *on that endpoint* is what yields impact. Cross-lesson chain is acceptable and encouraged |

Grading: (a) both weaknesses named with **class + mechanism (parser/trust assumption/boundary)**;
(b) each proven **independently** with its inert marker; (c) an explicit "A produces capability X;
B consumes X" narrative and the **combined** impact in client terms; (d) verification evidence per
step (requests/responses/markers, `X-Cache` MISS→HIT, desync timing, invariant broken then holding
sequentially); (e) remediation **and** detection for both, plus **which single fix breaks the chain
most cheaply** (a good answer reasons about the *cheapest cut*, e.g. "store uploads off the web root
and disable execution kills the chain regardless of the traversal"). Docking: weaponized gadget
chains, real exfiltration, hijacking a real user's request in smuggling, destructive race effects,
or any test aimed outside the lab; also a "chain" whose two halves aren't independent.

### Check-yourself

1. **Not worthless.** A non-executing upload can still be **stored XSS via SVG/HTML** (served inline),
   a **client-side chain input**, a **path/name-injection** vector, or a **deserialization/parser**
   input if the app later processes it. The second weakness that turns it into RCE is a **path
   traversal / LFI that includes or reaches the uploaded file**, or a misconfigured handler that
   executes the store — i.e. a way to get the file *executed* despite where it landed.
2. `....//` defeats a **single-pass** `../` strip because removing the inner `../` from `....//`
   leaves `../` behind (`....//` → remove `../` → `../`). Lesson: filtering by substring-removal is
   fragile; **canonicalize first** (resolve to an absolute real path) and then confine to the base
   directory — canonicalization must happen *before* the confinement check, not as a blocklist on the
   raw input.
3. Server-side pollution is often **invisible immediately** — you've mutated `Object.prototype`, but
   nothing has *read* the polluted property yet (no visible gadget). Confirm it with a **benign marker
   property**: inject `{"__proto__":{"labPolluted":"LAB-PP-OK"}}`, then trigger any code path that
   reads a **default from a fresh object** and observe `LAB-PP-OK` come back — proving pollution
   succeeded even though no security-relevant gadget fired.
4. In **CL.TE**, the **front-end honours `Content-Length`** and the **back-end honours
   `Transfer-Encoding: chunked`**. The front-end reads exactly CL bytes and forwards them as one
   request; the back-end, using chunked, ends the request at the zero-length chunk **earlier** (or
   later) than the front-end intended, so the **remaining bytes sit in the back-end's buffer** and get
   prepended to the *next* connection/request — the smuggled prefix. The disagreement about *which
   header sets the boundary* is exactly what creates the leftover bytes.
5. **Poisoning:** the **attacker's** harmful response is stored in the cache under a key that
   *victims* match, so every subsequent user is served the attacker's content — victim = anyone who
   requests the poisoned resource. **Deception:** the **victim's own private** response is stored under
   a public-looking key the **attacker** then requests — victim = the specific user whose data got
   cached. The difference (whose data lands under whose key) determines whether it's mass-delivery of
   attacker content or targeted theft of a victim's content.
6. The check ("balance ≥ amount") and the debit are **not atomic**; 20 concurrent requests all read
   the same pre-debit balance and all pass the check *before* any writes its decrement, so each
   proceeds — over-withdrawal (TOCTOU / limit overrun, CWE-367). The most direct fix is to make
   check-and-debit **atomic**: a DB transaction with a row lock / conditional atomic decrement
   (`UPDATE ... SET bal = bal - :amt WHERE bal >= :amt`) or a unique/idempotency constraint — not a
   re-check, which just narrows the window.

---

## Instructor notes

- **The unifying question.** For every finding in both lessons, make students answer the
  confused-deputy / trust-boundary sentence: *component A acts on input from B using A's privilege —
  what can B make A do?* If they can't, they've memorised a payload, not learned the class.
- **Recognition before payload.** The most common weak submission jumps to a working string. Insist on
  the recognition-and-context step (where does the marker land? which server honours which header? what
  is keyed vs unkeyed?) — it's what transfers to unseen targets.
- **Safety is graded.** Touching real cloud metadata, shipping a real gadget chain, hijacking a real
  user's request, or firing billion-laughs/DoS is an automatic fail regardless of technical quality.
  The professional habit — prove the mechanism with an inert marker, then report — is the outcome.
- **Forward links.** SSRF-to-metadata → M14 (cloud, IMDSv2). Deserialization/upload RCE and the
  reporting of these findings → M09 (exploitation mindset) and M16 (severity, evidence, narrative).
