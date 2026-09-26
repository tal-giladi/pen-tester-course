# Instructor / solutions — Module 08 (API security)

> Instructor material. Not linked from `_sidebar.md`. Do the exercises before reading.

These answers assume the `lab-08-api` target as specified in the lessons: a deliberately vulnerable
REST + GraphQL API on the isolated network with synthetic users A (`1001`) and B (`1002`), an admin
account the student does **not** hold, `LAB-FLAG-{uuid}` markers seeded in other users' objects/fields,
lab-only JWT signing behavior (signature not properly verified), an open admin route, wholesale body
binding, verbose serializers, an unthrottled login, introspection enabled, and no GraphQL query-cost
limits. Exact paths/field names vary with the built lab; **grade on reasoning and mechanism**, not on
matching a specific endpoint. Every full-credit finding pairs evidence with the *missing check*,
asset-based impact, a specific fix, and a detection idea.

---

## 08.1 — REST: discovery + a verified object-level authorization flaw

**Exercise.** A full-credit submission has four parts.

**(1) Surface map.** Strong students find the spec first (`swagger.json`/`openapi.json`/`/v3/api-docs`
or a `/swagger-ui` page), fall back to grepping the SPA JS bundle for `/api/v…/` strings, and then
**probe versioning** — discovering that `/api/v1/*` is still live alongside `/api/v2/*` (API9). Award
the "endpoint not discoverable from the UI" credit for any of: an admin route present in the spec but
never called by the app, a `v1` path retired from the current client, or a parameter `arjun`/spec
reveals that no form sends. Docking: a flat list of guessed URLs with no spec/JS/version reasoning;
treating a `200` on a doc page as the finding rather than as the map.

**(2) The BOLA finding.** The model answer is two requests identical except for the object reference,
same token:

```bash
curl -s https://api.shop.lab/api/v1/invoices/5001 -H "Authorization: Bearer $TOKEN_A"   # own → 200
curl -s https://api.shop.lab/api/v1/invoices/5002 -H "Authorization: Bearer $TOKEN_A"   # other → 200 + LAB-FLAG
```

Mechanism (required for full marks): the token authenticated the caller as `1001`, but the handler
fetched the invoice **by id alone** (`Invoice.find(id)`) and never checked `invoice.owner == token.sub`
— authentication passed, authorization was never performed (CWE-639/CWE-285). Accept the object
reference being in a query string, body, or header instead of the path — the reasoning is identical.
If the lab uses UUIDs, full credit requires the student to find a *leak* of another user's id (list
endpoint, search, shared link) and feed it back — demonstrating that the UUID was never the control.

**(3) Impact / remediation / detection.** Impact: any authenticated user reads any other user's
invoices → mass PII/financial disclosure, breach-notification/GDPR exposure — tied to the *asset*, not
"changed a number." Remediation: scope every query to the caller (`WHERE owner_id = current_user`) or
check ownership before returning; centralize in a policy layer; UUIDs only as defense-in-depth.
Detection: log the `(token subject, object id, decision)` triple; alert on one token touching many
distinct owners' objects.

**(4) Restraint note.** Credit the student for capturing *one* other-user record as proof and
explicitly *not* enumerating the range — the RoE data-handling behavior. A student who dumps every
invoice "to be thorough" loses marks: that models a real data-handling violation.

**Common strong extension:** chaining BFLA (`/admin/users` reachable) with mass assignment
(`{"role":"admin"}` persists) for full in-API privilege escalation — accept as an excellent bonus but
require the persistence proof (a fresh `GET` showing `role":"admin"`), not just the echoed write.

**Check-yourself (08.1).**
1. **Authorization** failed, not authentication — the server correctly identified you and then failed
   to check whether *that identity* may access *that object*. "You must log in" only adds
   authentication; it does nothing about the per-object check, so it can't fix BOLA.
2. UUIDs make ids unguessable but are not an access control. BOLA still works whenever another user's
   id is *disclosed* — a shared invoice URL, a search result, a `seller` field, an error message —
   after which you supply it and the missing ownership check still lets you in. Fix: enforce ownership
   server-side; treat the id as untrusted regardless of format.
3. **BOLA** = the server fails to check whether you may access *this specific object* (object-level).
   **BFLA** = the server fails to check whether you may invoke *this function/operation* at all
   (function-level).
4. The write may have been **echoed** by the response serializer without being **persisted** (or
   while being silently ignored). Confirm with a fresh independent `GET /users/1001` (or re-login and
   read the token/role) showing `role":"admin"` — proving the property actually changed in storage.
5. **Excessive data exposure** (API3). Root cause: the server serializes the whole object
   (`return user`) and trusts the client to display only some fields. Fix: explicit server-side
   serialization returning only needed fields; never ship `password_hash`/`is_admin`.

---

## 08.2 — GraphQL + tokens

**Exercise.** Four parts; the student picks *one* flaw class to prove but must do the map and the token
review.

**(1) Endpoint + schema map.** Full credit: locate the endpoint (`{ __typename }` against `/graphql`,
`/api/graphql`, `/query`, `/v1/graphql`), then dump the schema with an `__schema` introspection query
and enumerate `Query`/`Mutation` fields, flagging sensitive ones (`allUsers`, `admin*`, `internal*`,
`ssnLast4`, `role`, `setRole`, `deleteUser`). If the lab has introspection off, credit
suggestion-based recovery (`clairvoyance`, "Did you mean…" errors) or JS-bundle query extraction, and
confirmation that guessed fields resolve.

**(2a) Authorization flaw (one acceptable path).**

```graphql
query { user(id: 1002) { email ssnLast4 marker } }   # with user A's token → returns B's data + LAB-FLAG
mutation { setRole(userId: 1001, role: "admin") { id role } }   # normal user promotes self
```

Mechanism: the resolver returns/mutates by id without checking the caller's identity or role —
BOLA/BFLA at the field level (CWE-863/CWE-639). Require the decoded low-priv token (`role":"user"`)
alongside the returned `data`, and reading the `errors` block to show which fields resolved.

**(2b) Resource abuse (the other acceptable path).** Accept depth (circular `user→orders→seller→orders`),
aliasing (many aliases of one field in one request), or batching (JSON array of operations). Full
credit requires **bounded** evidence — latency/size at N=1 vs a *small* N showing growth, plus the
observation that no `429`/depth/cost/batch limit fired (API4, CWE-770). Dock any student who scaled the
probe toward an actual DoS: that is out of RoE and the lesson said to bound it.

**(3) Token review.** Decode both base64url segments **locally** (not `jwt.io`), report `alg` and the
`role`/`scope`/`aud` claims, and test *one* validation assumption:

```bash
FORGED='eyJhbGciOiJub25lIn0.eyJzdWIiOjEwMDEsInJvbGUiOiJhZG1pbiJ9.'   # alg:none, role=admin, empty sig
# re-send on a privileged action; acceptance == signature/claim not verified (CWE-347)
```

Full credit: the student shows a *privileged action succeeding* with the tampered/`none` token — the
acceptance is the proof. A decode with no acceptance test is partial credit. Also acceptable: flipping
a claim and re-sending with the original signature, or (if the lab uses a weak HMAC secret) cracking it
with `jwt_tool` and forging — but the secret-crack must be reported as *dependent on a weak secret*,
not a general break.

**(4) Impact / remediation / detection / restraint.** Impact tied to assets: field-level authz gap →
mass graph-wide data exposure/escalation; resource abuse → DoS; JWT flaw → full authentication bypass
/ account takeover. Remediation per the lesson's defend box (per-field authz, disable introspection in
prod, depth/cost/alias/batch limits or persisted queries, verify signature + **pin `alg` server-side**
+ validate `exp`/`aud`/`iss`, JWKS via trusted `kid`). Detection: log operation depth/complexity/alias/
batch and the `(subject, field, decision)` triple; alert on introspection from prod clients, `alg:none`/
unexpected `alg`, and role/scope mismatch vs. the issuer. Restraint note required: bounded probes,
minimal data read, local token decoding.

**Check-yourself (08.2).**
1. GraphQL has a single endpoint and the client chooses the query shape, so there is no per-URL route
   to guard — "protect the endpoint" protects nothing granular. The check must live in **each resolver
   / on each field** (or a policy layer the resolvers call), enforced per `(identity, object, field)`.
2. Not blind. (a) **Field-suggestion recovery** — error messages ("Did you mean `email`?") leak names,
   which tools like `clairvoyance` walk into a schema; (b) the **SPA/mobile JS bundle** contains the
   exact queries/mutations the client sends; also engine fingerprinting (`graphw00f`) and probing known
   default fields.
3. **API4 Unrestricted Resource Consumption** (the aliasing also enables brute force hidden in one HTTP
   request). Stops it: an **alias/complexity (cost) limit** and **rate limiting per identity** (plus,
   ideally, persisted-query allow-listing so arbitrary aliased queries can't be sent at all).
4. The **signature verification** step was skipped — the server trusted the token's own `alg:none`
   header and never verified a signature over the payload (CWE-347). Correct rule: the server pins the
   accepted algorithm(s) **server-side** and never trusts the token's `alg`; `none` is always rejected.
5. If the server verifies `RS256` with the RSA **public** key but also accepts `HS256`, an attacker
   forges a token signed `HS256` using that public key *as the HMAC secret* — the server, told
   `HS256`, verifies with the same public key it publishes, so the forgery validates. Fix: pin the
   algorithm to the expected asymmetric type and never allow the verifier to fall back to HMAC with an
   asymmetric key.
6. A Bearer token is a live credential; `jwt.io` (and similar) transmit the pasted token off your
   machine to a third party, disclosing a valid session/identity to an out-of-scope service — a data
   handling / disclosure incident. Decode locally instead.

---

## Grading rubric (both lessons)

| Dimension | Full credit | Partial | No credit |
|---|---|---|---|
| Discovery | spec + JS + version reasoning; finds non-UI surface | one method only | guessed URLs, no method |
| Finding | paired evidence + **mechanism** (missing check named, CWE) | evidence but "it returned 200" with no mechanism | claim without reproducible evidence |
| Token review (08.2) | privileged action succeeds with tampered/`none` token | decode only, no acceptance test | — |
| Impact | tied to assets (PII/funds/availability/identity) | generic "bad" | absent |
| Remediation + detection | specific, both present, mapped to CWE/ATT&CK | one present or vague | absent |
| Restraint / RoE | minimal data read; bounded probes; local decode; noted | implied | enumerated all records / unbounded DoS-style probe |

A submission that gets a `200`/`data` but cannot say *which check was missing and why* is capped at
partial — the whole module is about the missing authorization/validation step, not the command.
