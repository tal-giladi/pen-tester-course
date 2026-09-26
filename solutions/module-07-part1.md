# Instructor / solutions — Module 07, Part 1 (07.1–07.3)

> Instructor material. Not linked from `_sidebar.md`. Do the exercises before reading.

These answers assume the `lab-07-web` suite as specified: an intentionally vulnerable web app in
Docker on a private, no-Internet network, with synthetic accounts (`lab / Lab-Passw0rd!` plus a second
user and an admin), benign `LAB-FLAG-{uuid}` markers in synthetic tables/records, and a lab-internal
OOB collector container for blind cases. Exact routes, parameter names, cookie names, and token formats
vary with the built lab; **grade on reasoning, behavioral recognition, and mechanism**, not on matching
a specific payload or path. The recurring non-negotiables carry over from M04: *mechanism is mandatory,
every finding needs remediation AND detection, verification evidence is part of the finding, and any
out-of-lab or destructive action fails the professionalism bar (00.1).*

---

## 07.1 — The web attack model, cookies, sessions &amp; the proxy

**Exercise (map the session mechanism &amp; auth surface).** Full credit is a *characterization built from
intercepted traffic*, not a feature list. Expected:

- **Route/parameter inventory grouped by trust boundary** — unauthenticated (login, register, reset,
  static, public API), authenticated-user (account, orders, profile, per-object routes with IDs), and
  admin (`/admin*`, role-gated actions). Each parameter tagged with apparent purpose and source (query
  / body / JSON / header / cookie). Reward finding routes from JS bundles and `OPTIONS` that the UI
  never links.
- **Session characterization** — names the identity carrier (opaque cookie e.g. `session`/`connect.sid`
  **or** a JWT in cookie/`Authorization`); the exact `Set-Cookie` flags; and three *tested* facts:
  (a) **rotation on login** — compare the pre-login and post-login cookie; full credit shows the two
  values and states whether they differ; (b) **logout invalidation** — replays the pre-logout cookie
  after logout and reports the status (still `200` = cosmetic logout = finding); (c) **predictability** —
  collects several IDs and comments on structure, without over-claiming "random" from one sample.
- **Auth surface** — every login/register/reset/logout endpoint and every privilege boundary, with the
  methods each accepts; bonus for finding a state change reachable by an unexpected method (GET where UI
  POSTs, or an override header).
- **Two prioritized hypotheses** tied to observed behavior (e.g. "sequential invoice IDs + user session
  → probable IDOR (07.2)"; "`role` claim visible in a decodable JWT → token tampering (07.2)"; "single
  quote in search returned 500 → probable SQLi (07.3)").

Docking: a rendered-page description instead of traffic analysis; claiming "random session IDs" from one
value; asserting logout works without the replay test; **exploiting** anything (the task is mapping);
proxying/scanning outside the lab scope.

**Check-yourself.**
1. Everything the browser sends executes on a machine the attacker controls and travels as plain bytes
   the user (or a proxy) can rewrite before they leave. Your JavaScript's values, hidden fields, and the
   `Host`/`Cookie` headers are all just text in the outgoing request — the server has no way to know the
   real browser, not an attacker, produced them. Trust must be re-established server-side, never assumed
   from client origin.
2. It fails against **CSRF**. `HttpOnly` only stops JavaScript *reading* the cookie (XSS→theft); `Secure`
   only stops it traveling over plaintext. Neither stops the browser *attaching* the cookie to a
   cross-site request it was tricked into sending — that's precisely what `SameSite` governs, and it's
   absent.
3. **Session fixation.** The app keeps the same session ID across the authentication boundary, so an
   attacker who fixes a known ID in the victim's browser rides the resulting authenticated session. Fix:
   **rotate (regenerate) the session ID on login and any privilege change.**
4. Two problems: (a) a **state-changing action is reachable by `GET`** — it shows up in logs/history and
   is trivially CSRF-able (feeds 07.1/CSRF); and (b) the endpoint likely **doesn't verify authorization
   on the target object** — you moved money to/for an account without an ownership check (feeds 07.2
   IDOR/BOLA). Method-agnostic state change + missing authz is a common dangerous pair.
5. Reflected XSS and missing headers are *pattern matches* — a payload reflects, or a header is
   absent — which a scanner detects mechanically. IDOR/access-control requires knowing **whose** object
   `id=1006` is and whether *this* user should reach it — application- and identity-specific semantics
   the scanner has no model of. A human reasons about ownership and roles and supplies a negative
   control; the tool can't.

---

## 07.2 — Authn/authz, access control, JWT, OAuth/OIDC

**Exercise (find &amp; chain an access-control flaw).** Full credit: the class(es) recognized **from
behavior**, request/response pairs **including a negative control**, an explicit **chain** with
blast-radius framing, and remediation + detection per link. Illustrative model chains for the likely lab:

- **Horizontal IDOR → data exposure.** `GET /api/invoice/{id}` under `lab`'s session returns another
  user's invoice (`owner != lab`) with a `200` where `403` was expected. Negative control: the same call
  a real app would deny, or the same object correctly served to its owner. Impact: iterate IDs → *every*
  user's invoices (state the count reachable), not one record. Fix: server-side per-object ownership
  check against the session; random UUIDs as defense-in-depth only. Detect: one session touching many
  object IDs / sequential sweep. CWE-639, A01, ATT&CK T1078.
- **JWT `alg:none` / weak-secret → vertical privesc.** Decode the session JWT; `role:user` is present
  and decodable. Either (a) forge `{"alg":"none"}` with `role:admin` and an empty signature, or (b)
  crack a weak `HS256` secret (`hashcat -m 16500`) and re-sign with `role:admin`. Send to an admin route;
  `200` + `LAB-FLAG` where `lab`'s real token gets `403`. Negative control = the unmodified token's
  `403`/`user` behavior. Fix: pin algorithm, reject `none`, long random secret, validate `exp`/`aud`.
  Detect: `alg:none`/unexpected `alg`, verification failures, `role` change with no login. CWE-347/287,
  A01/A07, T1548.
- **Chain: IDOR → reset-token leak → account takeover.** A horizontal IDOR (or a reset endpoint that
  echoes/derives the token, or `Host`-header link poisoning) yields the victim's reset token; use it to
  set a new password and take over. Impact: takeover of arbitrary accounts (blast radius = all users).
  Fix: random single-use user-bound short-lived tokens, server-configured link base URL (never `Host`),
  never echo the token. Detect: many resets across users from one source, anomalous `Host`. CWE-640/287.
- **Forced browsing / BFLA.** `/admin/...` returns `200` directly (or via unexpected method / trailing
  slash / `X-Original-URL`) though unlinked; or `POST /admin/promote` succeeds as `lab`. Fix: default-deny
  function-level authz on every route. Detect: `403` bursts then `200`, method anomalies. CWE-862, A01.

Grading: (a) recognition shown from a **response diff / decoded token / token structure**, not a
definition; (b) **negative control present** so the wrong decision is unambiguous; (c) a genuine
**chain** (one flaw's output enables the next) with **blast-radius** impact, not a single example; (d)
remediation AND detection per link with CWE/OWASP/ATT&CK; (e) **no access to data beyond what proves the
finding**, only benign markers. Docking: "changed the ID and got data" with no negative control; forging
a token but never confirming the *server accepted* it; claiming account takeover without demonstrating
the reset actually set a password (in-lab); treating a random-UUID endpoint as automatically safe.

**Check-yourself.**
1. Example: `GET /account` correctly requires a valid session (**authn** right) but `GET
   /account/{id}` serves any id to any logged-in user (**authz** wrong) — logged-in but not
   *authorized* for that object. Authn = are you a valid user; authz = may this user do this to this
   object.
2. BOLA is about the **missing ownership check**, not ID guessability. UUIDs stop *guessing*, but if the
   attacker *obtains* a victim's UUID (referrer, logs, a shared link, another endpoint, enumeration
   elsewhere) the server still serves it because it never checks ownership. The fix is the server-side
   "does the caller own this object?" check; unpredictable IDs are only defense-in-depth.
3. Algorithm confusion (`RS256`→`HS256`): the server holds an RSA key pair and *publishes the public
   key*; it validates with the public key. The attacker changes the header `alg` from `RS256` to
   `HS256`. A naive verifier calls `verify(token, publicKey)` and, seeing `HS256`, treats the **public
   key bytes as the HMAC shared secret**. Since the public key is known, the attacker computes a valid
   HMAC over their forged header/payload. Fix: pin the expected algorithm; never let the token choose it;
   separate keys per algorithm.
4. Attacker requests a password reset **for the victim** while setting `Host: attacker.lab`; the app
   builds the reset email link from that header → `https://attacker.lab/reset?token=…`. If the victim
   clicks (or the token/host is otherwise used to route it), the token reaches the attacker, who resets
   the victim's password. Fix: build links from a **server-configured base URL**, never the request
   `Host` header (and don't email links to attacker-chosen hosts).
5. Access control is cross-cutting and per-object: frameworks make global *authentication* easy but the
   per-object *authorization* check must be written at every endpoint and is easy to forget — especially
   since developers test with their own account where every visible ID is theirs. A human supplies a
   **second identity and a negative control** and reasons about ownership/roles; the scanner has no model
   of "whose object is this" and can't tell a legitimate `200` from an unauthorized one.
6. Missing `state`: no CSRF protection on the redirect — an attacker can graft their own authorization
   `code` into the victim's session (or splice the victim's into theirs), causing login CSRF / account
   confusion. Prefix-matched `redirect_uri`: an attacker registers/uses
   `https://legit.example.com.attacker.lab` or appends a path/subdomain that still "matches," so the
   `code`/token is delivered to an attacker-controlled URL → account takeover. Both require exact-match
   `redirect_uri` and a verified `state`.

---

## 07.3 — Injection: SQL, NoSQL, command, SSTI

**Exercise (identify an injection from behavior, prove with an inert marker).** Full credit: the class
identified from a **behavioral signal shown first**, the technique with a **mechanism** explanation, a
request/response proving a **benign marker**, reach-based impact, a real remediation (parameterization /
argument vector / data-only template), and detection — with **no destructive payload**. Model answers:

- **UNION SQLi.** Signal: `'` → DB error / `AND 1=1` vs `AND 1=2` result diff. Column count via
  `ORDER BY n`; marker placement finds the reflected/typed column; swap in `flag` from `lab_secrets` →
  `LAB-FLAG`. Mechanism: input concatenated into the `WHERE`; `UNION SELECT` appends an attacker-chosen
  result set of matching arity. Fix: parameterized query. Detect: `UNION SELECT`/`ORDER BY` signatures,
  DB error spike. CWE-89, A03, T1190.
- **Boolean/time-blind SQLi.** Signal: no data/error, but content differs (`AND 1=1`/`1=2`) or only
  timing differs (`SLEEP`/`pg_sleep`). Extract the marker one character per request with
  `SUBSTRING(...) = 'x'`, reading the bit from the response/delay. Mechanism: the differential *is* the
  channel. Fix: parameterization; also non-verbose errors. Detect: near-identical requests differing by
  one char; long-running queries. CWE-89.
- **NoSQL operator injection.** Signal: swapping a JSON string value for `{"$ne":"x"}` (with
  `Content-Type: application/json`) changes the auth result. Mechanism: user input placed into the query
  object as *structure*, so `$ne`/`$gt`/`$regex`/`$where` are parsed as operators. Fix: type-validate
  (password must be a string), reject `$`-keys, no `$where`. Detect: `$`-operator keys where scalars
  expected. CWE-943.
- **OS command injection.** Signal: a field feeding ping/lookup/convert reacts to `;`/`|`/`$()` with
  extra output, or to `; sleep 5` / a lab-collector callback (blind). Mechanism: input concatenated into
  a shell command string (`sh -c`), so metacharacters start new commands. Proof: `id`/`hostname` output
  or reliable delay/collector hit. Fix: execute a program with an **argument array**, no shell. Detect:
  web worker spawning `sh`/`bash`; shell metacharacters; unexpected outbound DNS/HTTP. CWE-78, T1190→T1059.
- **SSTI.** Signal: `{{7*7}}`/`${7*7}` renders as `49` (evaluated), not literal. Marker identifies the
  engine; prove the mechanism by reading a benign `LAB-FLAG` through the engine — **do not** run
  destructive/persistent code. Mechanism: user input placed into template *source* and evaluated as an
  expression; the conceptual jump to RCE is expression eval → reach a code-running built-in. Fix: pass
  user data as template **variables**, sandbox/logic-less templates. Detect: `{{`/`${`/`<%` in input,
  template errors, app spawning a shell. CWE-94/1336, A03.

Grading: (a) **recognition shown before exploitation** — the error/differential/timing/operator/`49`
signal must appear first; (b) mechanism ("data crossed into the code channel"), not a pasted payload;
(c) an **inert marker** proves it (synthetic flag, `id` output, computed `49`) with the request/response;
(d) impact by **reach** (what data/host, what it pivots to); (e) remediation names the *real* fix
(parameterization / argument vector / data-only template), **not** "sanitize input"; (f) detection with
CWE/OWASP/ATT&CK; (g) **no destructive payload** and any OOB to the lab collector only. Docking:
`OR 1=1` with no negative control; claiming SQLi from a generic `500` without confirming a parser
reaction; using `sqlmap --risk=3`/`--os-shell` unprompted; "sanitize input" as the sole remediation;
mis-classifying reflected `{{7*7}}` (literal) as SSTI when it's XSS territory.

**Check-yourself.**
1. Class: **untrusted input is concatenated into a string an interpreter then parses, so the input's
   content becomes instructions.** SQLi (SQL engine), command injection (shell), and SSTI (template
   engine) are the same failure — data mixed into the code channel — differing only in *which*
   interpreter is downstream; the recognition (inject syntax, watch the parser react) and the fix
   (separate data from code) are identical.
2. **Boolean-blind**, **one bit per request**. Read a secret by asking yes/no questions —
   `... AND SUBSTRING((SELECT flag...),1,1)='L'` → "found" means the first char is `L`; walk each
   position and each candidate character, reconstructing the value from the true/false responses.
3. A prepared statement sends the **query structure to the DB first** (with `?`/named placeholders) and
   the user value **separately as a bound parameter**; the parser has already fixed the statement's
   structure before the data arrives, so the value can never be re-interpreted as SQL syntax — quotes
   and keywords in it are just data. Escaping/filtering tries to enumerate dangerous characters in a
   still-concatenated string and always misses an encoding, a context, or a quoting edge case; it treats
   the symptom, not the data/code mixing.
4. Field A (`49`) is **SSTI** — the template engine *evaluated* your expression server-side (path to
   RCE). Field B (literal `{{7*7}}`) is a candidate for **XSS** — the input is *reflected* into the
   page, not evaluated by a server template. The distinction is crucial: SSTI is typically critical
   (server code execution) while reflected XSS executes in the *victim's browser*; they have different
   impact, remediation, and severity in the report.
5. Mongo builds a query object; if the app inserts the request field as structure, `{"$ne":"x"}` becomes
   the operator "password **not equal** to `x`" — true for the real password — so the credential check
   passes without knowing the password (with a known/guessable username). Fix: **validate the type** —
   the password field must be a string, never an object; reject query-operator keys.
6. `--risk=3` enables potentially **destructive** payloads (stacked queries, `OR`-based tests that can
   update rows), risking data damage on a system you don't own — a DoS/integrity violation and RoE
   breach. Professional use: **manually confirm the injection first**, save the exact request from the
   proxy (`-r`), target the parameter (`-p`), constrain to the confirmed technique (`--technique=`) at
   **low `--level`/`--risk`**, `--batch`, and treat sqlmap as an *accelerator* whose findings you
   re-verify by hand — never as the first probe or with heavy modules unprompted.

---

## Grading notes (all three lessons)

- **Recognition from behavior is the point.** M07's thesis (plan.md) is that students identify vulns
  from how the app *behaves*, not from definitions. A submission that jumps to a payload without first
  naming the behavioral signal (response diff, error, timing, decoded token, `49`) misses the core skill,
  however correct the payload.
- **Negative controls and mechanism are mandatory.** For access control, the "should be denied" request
  must accompany the positive result. For injection, the *why it works* (data into the code channel) must
  be explicit. "It worked" is a partial answer.
- **Remediation AND detection, every finding.** Same non-negotiable as M04; remediation must name the
  real fix (parameterization / server-side ownership check / pinned JWT alg / server-configured reset
  URL), not "sanitize" / "validate" hand-waving.
- **Impact as blast radius.** Reward framing by reach — every record via one IDOR, all accounts via one
  reset flaw, the host and its pivots via RCE — over a single illustrative example (sets up M16).
- **Safety.** Benign markers and synthetic data only; no destructive payloads (no `DROP`/updates/file
  writes/real commands), OOB to the lab collector only, everything scoped to `lab-07-web`. Any
  description of running these outside the lab, or omitting the LAB-vs-REAL boundary, fails the
  professionalism bar (00.1).
