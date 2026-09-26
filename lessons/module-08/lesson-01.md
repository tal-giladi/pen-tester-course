# 08.1 — REST API testing: discovery, BOLA/BFLA, mass assignment, excessive data exposure &amp; rate-limiting

<div class="prereq">

**Prerequisites:** [M00](../module-00/lesson-01.md) (authorization) and [00.3](../module-00/lesson-03.md)
(trust boundaries, the confused deputy); [01.2 DNS, HTTP &amp; TLS](../module-01/lesson-02.md) — you
must read an HTTP request/response fluently and know methods, status codes, and headers; **M07
Web application testing** — this module *assumes* it. Access control, sessions, JWT/OAuth, IDOR,
and SSRF are introduced there; here we apply that lens to APIs and do not re-derive it.
**Module:** M08 API security. **Difficulty:** 🟡🔴 intermediate→advanced.
**You will produce:** a discovered API surface (endpoints, versions, parameters) and one
*verified, evidence-backed* object-level authorization finding on the lab API, with impact and fix.

</div>

## Why this matters

An API has no forgiving HTML front-end to hide behind. A web page might do a server-side check
before rendering a button; the API *is* the check, or it isn't. Modern applications are mostly
APIs — an SPA, a mobile client, and partner integrations all talk to the same JSON endpoints — so
the API is where the real authorization decisions live, and where they are most often missing. The
**OWASP API Security Top 10 (2023)** exists because the failure modes differ from the classic web
list: the number-one API risk is not injection but **Broken Object Level Authorization** (API1) —
an authenticated user reading another user's data by changing an ID. These bugs are trivial to
trigger, devastating in impact, and invisible to most scanners because every request looks
perfectly well-formed. This lesson makes you fluent in finding them by hand.

## Learning objectives

By the end you can:

- Discover an API's surface without documentation: OpenAPI/Swagger specs, JavaScript bundles,
  versioned paths (`/v1` vs `/v2`), and undocumented endpoints (API9 — Improper Inventory Management).
- Test **object-level authorization** (BOLA, API1) systematically by manipulating resource
  identifiers, and explain *why* the check is missing.
- Test **function-level authorization** (BFLA, API5) by invoking privileged operations as an
  ordinary user.
- Recognize and exploit **mass assignment** and **excessive data exposure** — the two halves of
  Broken Object Property Level Authorization (API3).
- Probe **rate limiting / resource consumption** (API4) without running a destructive test.
- For every finding, produce verification evidence, business impact, remediation, and detection.

## Intuition

A REST API is a set of **nouns** (resources — `users`, `orders`, `invoices`) addressed by URL, and
a small set of **verbs** (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`) that act on them. Almost every
serious API flaw is one question the server forgot to ask about a noun or a property:

- *"Is this token allowed to touch **this** object?"* — forgotten → **BOLA** (API1).
- *"Is this token allowed to call **this** function at all?"* — forgotten → **BFLA** (API5).
- *"Is this token allowed to **set** this property?"* — forgotten → **mass assignment** (API3).
- *"Should this token even **see** this property?"* — forgotten → **excessive data exposure** (API3).
- *"How **often** may this token do this?"* — forgotten → **resource consumption** (API4).

The API authenticates you (it knows *who* you are, from a token) and then trusts the identifier
*you supplied* to decide *what* you may touch. That gap between authentication ("who") and
authorization ("what you may do to this specific thing") is the entire subject. It is the
confused-deputy pattern from 00.3, wearing a JSON hat.

## The underlying technology

**REST** (Representational State Transfer) is a style, not a protocol: resources have URLs, HTTP
verbs express intent, responses are usually JSON, and requests are meant to be **stateless** —
each carries its own credential. That credential is typically a **Bearer token** in the
`Authorization` header:

```http
GET /api/v1/users/1001/orders HTTP/1.1
Host: api.shop.lab
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEwMDEsInJvbGUiOiJ1c2VyIn0.<sig>
Accept: application/json
```

The token proves *identity* (this is user 1001). The path segment `1001` names the *object*. The
server must independently verify that the identity in the token is allowed to act on the object in
the path — and this is exactly the step that is skipped.

**OpenAPI / Swagger** is the machine-readable contract for an API: a JSON or YAML document
(`openapi.json`, `swagger.json`, or a live `/swagger-ui`, `/api-docs`, `/v3/api-docs` page) listing
every path, method, parameter, and schema. For a defender it is documentation; for a tester it is a
**map of the entire attack surface**, including endpoints no UI ever calls.

**Versioning** (`/api/v1/…`, `/api/v2/…`) exists so old clients keep working while the API evolves.
The security consequence: the old version is often still live, less monitored, and missing fixes
that were only applied to the current one — the heart of API9 (Improper Inventory Management).

## Why the weakness exists

Developers implement authentication once (a middleware validates the token) and then feel
"protected." But authentication is a property of the *request*; authorization is a property of the
*(identity, object, action)* triple, and must be checked in **every handler**, against the
**object actually being accessed** — not the object the UI intended. Frameworks make the easy
thing insecure: `Order.find(params[:id])` fetches *any* order (the developer must remember
`.where(user_id: current_user.id)`); `user.update(params)` binds the whole body and writes a
`role` the client was never meant to control (**mass assignment**); and `return user` ships the
whole row — `password_hash`, `is_admin` — because the UI was trusted to render only some fields
(**excessive data exposure**). The root causes are CWE-639 (authorization bypass through
user-controlled key), CWE-285 (improper authorization), CWE-915 (mass assignment), and CWE-213
(sensitive information exposure). None is exotic; each is a missing line of code.

## How a tester recognizes it

- **Sequential or guessable identifiers** in URLs or bodies (`/orders/1002`, `"userId": 42`) — every
  one is a BOLA candidate.
- **Responses richer than the UI** — the app shows a name and email, but the JSON also carries
  `ssn`, `internalCreditScore`, `isAdmin`. Read the *raw* response, never the rendered page.
- **Admin/privileged verbs reachable at all** — a `DELETE /users/{id}` or `POST /admin/...` that
  returns `401/403` for you *sometimes* but `200` on a sibling path or an older version.
- **A body that echoes more fields than the form sent** — a hint that the model is bound wholesale
  and may accept extra properties.
- **No `429`, no `Retry-After`, no throttling** under repeated requests — a resource-consumption
  and brute-force risk.

## Manual investigation

Manual first, always: you must see the raw request and response to reason about the missing check.

### 1. Discover the surface

Look for the spec before guessing. Common locations:

```bash
# LAB TARGET ONLY (api.shop.lab). Probe well-known spec/doc locations.
for p in openapi.json swagger.json v3/api-docs api-docs swagger/v1/swagger.json \
         .well-known/openapi swagger-ui/index.html; do
  curl -s -o /dev/null -w "%{http_code}  /$p\n" "https://api.shop.lab/$p"
done
```

A `200` on any of these usually hands you every path and parameter. If there is no spec, the
**JavaScript bundle** of the single-page app is the next map — it contains every URL the front-end
calls:

```bash
# Pull endpoint strings out of a JS bundle you already loaded in-scope.
curl -s https://shop.lab/assets/app.[hash].js | grep -oE '"/api/v[0-9]+/[a-zA-Z0-9/_{}.:-]+"' | sort -u
```

Then probe **versioning**: if the app calls `/api/v2/...`, try `/api/v1/...` for the same resource.
Old versions are the classic undocumented, under-protected surface (API9).

### 2. Baseline an authenticated request

Log in as a low-privilege lab user, capture your token, and make a legitimate call so you know what
"normal" looks like:

```bash
TOKEN_A="eyJ...userA..."   # user A's Bearer token, obtained by logging in as user A
curl -s https://api.shop.lab/api/v1/users/1001/orders \
     -H "Authorization: Bearer $TOKEN_A" | jq .
```

### 3. Test object-level authorization (BOLA, API1)

Change *only the object identifier* and keep *your own* token. If you receive another user's data,
the server authenticated you but never authorized you against object `1002`:

```bash
# Same token (user A), different object id. This is the whole test.
curl -s https://api.shop.lab/api/v1/users/1002/orders \
     -H "Authorization: Bearer $TOKEN_A" | jq .
```

The identifier need not be in the path — it is just as often a query parameter (`?account=1002`),
a JSON body field, or a header. UUIDs slow enumeration but do not fix BOLA: if any endpoint leaks
another user's UUID (a shared link, a search result), the authorization gap is still there.

### 4. Test function-level authorization (BFLA, API5)

Take an operation the UI only shows to admins and call it with your *ordinary* token. BFLA is about
the **function**, not the object — can a normal user invoke an admin verb at all?

```bash
# Normal user calling an admin-only listing/management function.
curl -s -X GET  https://api.shop.lab/api/v1/admin/users -H "Authorization: Bearer $TOKEN_A"
curl -s -X DELETE https://api.shop.lab/api/v1/users/1002 -H "Authorization: Bearer $TOKEN_A" -i
```

Also try **HTTP-method swaps** (the app only uses `GET`, but `PUT`/`DELETE` on the same path is
unguarded) and admin paths from the spec or JS.

### 5. Mass assignment (API3)

Send properties the form never offered — the giveaway is a body the framework binds wholesale.
The inert lab marker is a self-promotion attempt:

```bash
# LAB ONLY. Registration/profile-update that also sets a privileged property.
curl -s -X PATCH https://api.shop.lab/api/v1/users/1001 \
     -H "Authorization: Bearer $TOKEN_A" -H 'Content-Type: application/json' \
     -d '{"displayName":"tester","role":"admin"}'      # <-- "role" was never a form field
```

If the response (or a follow-up `GET`) shows `"role":"admin"`, the model accepted a property the
client should never control (CWE-915). Common privileged fields to probe: `role`, `isAdmin`,
`is_verified`, `account_balance`, `user_id`, `email_verified`, `permissions`.

### 6. Excessive data exposure (API3)

Compare the raw JSON with what the UI renders. The API "filters" on the client, so the server ships
everything:

```bash
curl -s https://api.shop.lab/api/v1/users/1001 -H "Authorization: Bearer $TOKEN_A" | jq 'keys'
# UI shows: name, email.  Response also has: password_hash, is_admin, internal_notes, ssn_last4
```

### 7. Rate limiting / resource consumption (API4)

Establish whether the endpoint throttles at all — a *measurement*, not a flood. A small, bounded
burst against a lab target answers the question:

```bash
# LAB ONLY, bounded to 20 requests. Look for 429 / Retry-After appearing.
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code} " https://api.shop.lab/api/v1/login \
       -H 'Content-Type: application/json' -d '{"user":"a","pass":"x"}'
done; echo
```

All `200/401` and no `429` means the login (or OTP, or password-reset) endpoint has no
brute-force/credential-stuffing brake (API4, and API2 by extension).

## Tooling — what it does, key options, limits, verify by hand

- **Postman / Insomnia** — import the OpenAPI spec to get every endpoint as a ready request;
  environments hold your token. *Limit:* it will not decide authorization for you — you still design
  the BOLA/BFLA test. *Verify:* the raw request/response is right there; read it.
- **Burp Suite** — proxy the mobile/SPA client to capture real traffic, then **Repeater** to change
  one ID at a time and **Intruder** (bounded) to sweep an ID range or field set. The **Autorize**
  extension automates access-control testing: it replays each request with a low-priv token and
  flags where the response is identical to the high-priv one — a BOLA/BFLA detector. *Limit:*
  Autorize reports *candidates*; a `200` with an empty body is not access. *Verify:* confirm the
  low-priv response actually contains the other user's data.
- **`kiterunner`** — content discovery tuned for APIs (route+method wordlists), better than a plain
  dir-buster because it sends realistic API requests. *Limit:* noisy; wordlist-bound. *Verify:* a
  discovered route needs a manual auth test.
- **`ffuf` / `arjun`** — fuzz paths, versions, and *hidden parameters* (arjun finds body/query params
  the docs omit — useful for mass-assignment discovery). *Limit:* false positives on generic
  responses; tune by size/status. *Verify:* by hand.
- **`nuclei`** — templates for exposed swagger, common misconfig (API8), default creds. *Limit:*
  signature-based; misses logic flaws entirely. *Verify:* it never finds BOLA for you.

<div class="callout method">

**Methodology, not tools.** Every finding in this lesson is provable with `curl` and your eyes:
change one identifier, add one property, compare two responses. Tools scale the sweep; they do not
replace the reasoning about *which check is missing*. Design the test, then let the tool run it.

</div>

## Exploitation / demonstration (LAB ONLY)

<div class="callout attack">

**Technique — BOLA (API1) on a numeric object reference.** As lab user A (token `TOKEN_A`, `sub:1001`):

```bash
# Legitimate: your own invoice — 200 with your data.
curl -s https://api.shop.lab/api/v1/invoices/5001 -H "Authorization: Bearer $TOKEN_A" | jq .amount
# BOLA: someone else's invoice, same token, only the id changed — still 200.
curl -s https://api.shop.lab/api/v1/invoices/5002 -H "Authorization: Bearer $TOKEN_A" | jq .
# → {"id":5002,"owner":1002,"amount":812.40,"marker":"LAB-FLAG-{uuid}"}
```

**Why it works:** the handler runs `Invoice.find(id)` and returns it after only checking that the
token is *valid*, never that `token.sub == invoice.owner`. Authentication passed; authorization was
never performed (CWE-639). The `LAB-FLAG-{uuid}` in another owner's record is your proof.

</div>

<div class="callout attack">

**Technique — BFLA (API5) + mass assignment (API3) chained.** As the same ordinary user, invoke an
admin function and self-promote:

```bash
# BFLA: admin listing reachable by a normal token (should be 403).
curl -s https://api.shop.lab/api/v1/admin/users -H "Authorization: Bearer $TOKEN_A" | jq length
# Mass assignment: promote self via an unfiltered property.
curl -s -X PATCH https://api.shop.lab/api/v1/users/1001 -H "Authorization: Bearer $TOKEN_A" \
     -H 'Content-Type: application/json' -d '{"role":"admin"}' | jq .role   # → "admin"
```

**Why it works:** the admin route has no role gate (BFLA — the function itself is unprotected), and
the update binds the whole body to the user model, so a client-supplied `role` overwrites a field
the server should own (mass assignment). Either bug alone is serious; together they are full
privilege escalation inside the API.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Every request above targets `labs/lab-08-api` (`api.shop.lab`) on the
isolated lab network, with **synthetic** accounts and **benign** `LAB-FLAG-{uuid}` markers. Changing
an ID to read "another user's" data, calling an admin endpoint, or adding `"role":"admin"` on a
system you do not own and are not explicitly authorized to test is unlawful access (M00) — and on a
real system, changing IDs *reads real people's private data*, which the RoE's data-handling clause
governs. Access the minimum to prove the finding; never enumerate real records for volume. Restate
scope and authorization before every action.

</div>

## Verification

A finding is only real with evidence a client can reproduce:

- **BOLA:** two requests, *identical except the object ID*, both `200`, the second returning data
  owned by a different account (the `LAB-FLAG-{uuid}` or another user's PII field). Capture both full
  requests and responses.
- **BFLA:** the privileged response returned to a token whose decoded claims show a non-admin role;
  include the decoded JWT payload (`role":"user"`) alongside the `200`.
- **Mass assignment:** the pre-state (`role":"user"`), the mutating request, and a *fresh* `GET`
  showing `role":"admin"` — prove the change persisted, not just that the write was echoed.
- **Excessive data exposure:** the raw JSON keys vs. the fields the UI renders, side by side.
- **Rate limiting:** the status-code sequence showing no `429` across the bounded burst.

"I think it's vulnerable" is not a finding; the paired requests are.

## Impact

BOLA and BFLA are, in business terms, **any user can read or modify any other user's data, and any
user can become an administrator**. That is mass PII disclosure (breach-notification and GDPR
consequences), integrity loss (altering orders, balances, permissions), and full account takeover.
Excessive data exposure leaks credentials and internal fields that fuel further attacks. Missing
rate limits enable credential stuffing and OTP/password-reset brute force (API4/API2). You frame all
of this against *assets* (00.3) — customer data, funds, trust — in the report (M16), not as "changed
a number."

## Remediation

<div class="callout defend">

- **BOLA (API1):** enforce object ownership in every handler — scope the query to the caller
  (`WHERE owner_id = :current_user`), or check ownership before returning. Prefer unpredictable IDs
  (UUIDv4) as defense-in-depth, but **never** rely on them as the control. Centralize with a policy
  layer so no handler can forget.
- **BFLA (API5):** deny by default; require an explicit role/permission on every privileged route,
  checked server-side, for every HTTP method. Do not rely on hiding the endpoint from the UI.
- **Mass assignment (API3):** allow-list bindable properties (DTOs / `permit(:name, :email)`); never
  bind the raw request body to the model. Server-owned fields (`role`, `id`, `balance`) are never
  client-writable.
- **Excessive data exposure (API3):** serialize explicitly — return only the fields the consumer
  needs; never `return user` (the whole row). Filter on the *server*, not the client.
- **Resource consumption (API4):** rate-limit per identity and per IP, add `429`/`Retry-After`,
  cap page sizes and query depth, and put stricter limits on auth-sensitive flows.
- **Misconfiguration (API8):** disable interactive Swagger UI in production, remove default creds,
  set security headers, and return generic errors.

All of it is one principle repeated per object, per function, per property: **authorize the action,
not just the identity.**

</div>

## Detection / blue-team view

<div class="callout defend">

- **BOLA/BFLA signatures:** a single token requesting many distinct object IDs in sequence; a token
  whose role claim is `user` receiving `200` from admin routes; a spike in `403`→`200` transitions
  across sibling paths. Log the *(token subject, object id, decision)* triple and alert on
  cross-user access.
- **Mass assignment:** application logs showing writes to privileged columns from a
  non-admin principal; alert on any change to `role`/`is_admin`.
- **Enumeration/consumption:** high request rates per token/IP, large or unbounded page sizes,
  many `404`s from spec/version probing (API discovery). A WAF or API gateway with per-route quotas
  catches the volume; the authorization telemetry catches the logic.
- **Discovery:** requests to `swagger.json`/`/v1` paths from outside expected clients.

This maps to **MITRE ATT&CK** as valid-account abuse and data-from-application (**T1078** Valid
Accounts, **T1213** Data from Information Repositories) rather than exploitation of a memory bug —
the traffic is well-formed, so *behavioral* authorization logging is the only reliable detector.

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-08-api` (built separately) — a deliberately vulnerable REST + GraphQL API
on the isolated lab network, with synthetic users (user A `1001` / `lab`, user B `1002`), an admin
account you do **not** hold, and `LAB-FLAG-{uuid}` markers seeded in other users' objects. This
lesson uses the REST surface; GraphQL is 08.2. **Access:** log in as user A to obtain a Bearer token.
**Targets:** the lab API only (`api.shop.lab`). **Time:** ~90 min. **Isolation:** private Docker
network, no Internet route; reset per the lab README between attempts. The API deliberately mixes
missing object checks, an open admin route, wholesale body binding, verbose serializers, and an
unthrottled login.

</div>

Work the methodology in order: discover the surface (spec/JS/versions), baseline an authenticated
call, then test one flaw class at a time (BOLA → BFLA → mass assignment → excessive data → rate
limit), capturing paired-request evidence for each. Then reset and confirm your remediation reasoning
by predicting which request *should* now fail.

## Exercise

<div class="callout method">

**Situation.** Authorized grey-box test of the lab API. You are given credentials for **one**
ordinary user (user A, `1001`) and nothing else — no documentation, no admin access. The client
believes "the API is safe because you need to log in."

**Objective.** (1) Map the API surface — endpoints, versions, and any undocumented/older paths — from
discovery alone. (2) Find and **prove** one object-level authorization flaw (BOLA) with paired-request
evidence, then state its impact and fix.

**Starting information.** User A's login. The base host `api.shop.lab`. The SPA at `shop.lab`.

**Constraints.** Lab target only. Reason before you fuzz; keep any burst bounded and non-destructive.
Access only the minimum data needed to prove the finding — capturing one other-user record with its
`LAB-FLAG-{uuid}` is proof; enumerating all of them is not (and models a real data-handling
violation). You must explain the **mechanism** — which check is missing and why — not just show a
`200`.

**Expected deliverables.**
1. An API surface map: base paths, versions found (and how — spec, JS, or version probing), and at
   least one endpoint not discoverable from the UI.
2. One BOLA finding with: the two requests (identical but for the object reference), both responses,
   the decoded token showing your identity, and the mechanism (why authorization was skipped).
3. Business **impact** tied to assets, a specific **remediation**, and a **detection** idea.
4. A note on what you deliberately did **not** do (records you didn't read, bursts you didn't run)
   and why — the professional restraint the RoE requires.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Authentication answers "who are you"; the bug you want is where the server never asks "may
<em>you</em> touch <em>this</em>." Where in a request does the <em>object</em> get named — path,
query, body, or a header — and does changing it, with your own token, change what you get back?
</details>

<details><summary>Hint 2 — discovery</summary>
Before guessing endpoints, look for <code>swagger.json</code>/<code>openapi.json</code>/<code>/v3/api-docs</code>,
then read the SPA's JS bundle for <code>/api/v…/</code> strings. If the app calls <code>/api/v2/…</code>,
ask what happened to <code>/api/v1/…</code>.
</details>

<details><summary>Hint 3 — where to look</summary>
Any endpoint that returns something belonging to <em>you</em> and takes an id (<code>/users/1001</code>,
<code>/invoices/5001</code>, <code>/orders?id=…</code>) is the candidate. Change the id to a
neighbouring value and keep everything else — especially your token — identical.
</details>

<details><summary>Hint 4 — specific direction</summary>
Sequential numeric ids make enumeration obvious; if the id is a UUID, look for an endpoint that
<em>leaks</em> another user's id (a list, a search, a shared link) and feed that id back in. The
authorization gap is the same regardless of id format — the UUID was never the control.
</details>

## Check yourself

<div class="callout key">

1. An endpoint requires a valid Bearer token and *still* returns another user's record when you
   change the ID. Exactly which security property failed — authentication or authorization — and why
   does "you must log in" not fix it?
2. A colleague says "we switched all IDs to UUIDs, so BOLA is solved." Give one concrete scenario
   where BOLA still works, and state the actual fix.
3. Distinguish BOLA from BFLA in one sentence each, using the words *object* and *function*.
4. You add `"role":"admin"` to a profile-update body and the response echoes `"role":"admin"`. Why is
   that echo **not** yet proof of mass assignment, and what single request confirms it?
5. The API returns `password_hash` and `is_admin` in every user object, but the mobile app never
   displays them. Name the OWASP API risk, the root cause, and the fix in one line.

</div>

Model answers are in `solutions/module-08.md` (try them before looking).

## References

- **OWASP API Security Top 10 (2023)** — **API1** Broken Object Level Authorization; **API3** Broken
  Object Property Level Authorization (mass assignment + excessive data exposure); **API4**
  Unrestricted Resource Consumption; **API5** Broken Function Level Authorization; **API8** Security
  Misconfiguration; **API9** Improper Inventory Management. (owasp.org/API-Security)
- **OWASP Web Security Testing Guide** — API testing and access-control testing sections.
- **RFC 9110** — HTTP Semantics (methods, status codes); **RFC 6750** — OAuth 2.0 Bearer Token Usage.
- **OpenAPI Specification 3.1** — spec.openapis.org (the contract you mine for surface).
- **CWE-639** Authorization Bypass Through User-Controlled Key; **CWE-285** Improper Authorization;
  **CWE-915** Improperly Controlled Modification of Dynamically-Determined Object Attributes (mass
  assignment); **CWE-213** Exposure of Sensitive Information Due to Incompatible Policies;
  **CWE-770** Allocation of Resources Without Limits or Throttling.
- **MITRE ATT&CK** — **T1078** Valid Accounts; **T1213** Data from Information Repositories.

## What you should now be able to do

- Discover an API's surface from specs, JS bundles, and version probing when handed no docs.
- Test object- and function-level authorization by manipulating identifiers and invoking privileged
  verbs, and explain the missing check each time.
- Recognize and prove mass assignment and excessive data exposure.
- Measure rate limiting without a destructive test.
- Produce paired-request evidence, asset-based impact, remediation, and detection for each finding.

## Progress checkpoint

```bash
py course.py complete 08.1
```
