# 07.2 — Authentication, authorization &amp; access control: IDOR/BOLA, auth bypass, password reset, JWT/OAuth/OIDC

<div class="prereq">

**Prerequisites:** [07.1 The web attack model](lesson-01.md) (you must be able to intercept, replay in
Repeater, and characterize a session), [00.3 Threat modeling &amp; the confused deputy](../module-00/lesson-03.md), [01.2 HTTP/TLS](../module-01/lesson-02.md), and
[00.1 authorization](../module-00/lesson-01.md).
**Module:** M07 (major). **Difficulty:** 🔴 advanced.
**You will produce:** one *chained* access-control finding on the lab app — recognized from behavior,
proven with an inert marker, with impact, remediation, and detection.

</div>

## Why this matters

**Broken access control is #1 on the OWASP Top 10 (2021)** — the most common serious web finding, and
the one scanners are worst at. It is rarely a memory bug or a clever payload; it is the application
simply *forgetting to check whether you're allowed*. These flaws are found by reasoning about identity
and behavior, which is exactly what a human tester does and a tool cannot. This lesson also covers the
token systems modern apps use to carry identity — JWT, OAuth2, OIDC — because when the token layer is
weak, authentication collapses entirely: you become any user without ever knowing a password. If M07
has a single highest-value lesson for a working tester, this is it.

## Learning objectives

- Distinguish **authentication** (who you are) from **authorization** (what you may do), and locate
  each on the trust boundary.
- Recognize and exploit **broken access control**: IDOR/BOLA, horizontal vs vertical privilege
  escalation, forced browsing, and function-level authorization gaps.
- Recognize **authentication bypasses** and insecure **password-reset** flows (token predictability,
  host-header poisoning, reset-token leakage).
- Analyze **JWTs** for `alg:none`, algorithm confusion, weak HMAC secrets, and `kid` abuse.
- Explain **OAuth2/OIDC** flows and their common flaws (`redirect_uri` validation, missing `state`,
  token leakage) well enough to recognize them.

## Intuition

Authentication is the front door; authorization is every interior door. Most apps build a strong front
door (login, MFA) and then leave the interior doors unlocked — they check *that* you're logged in but
not *whether this particular record is yours*. The mental model from 00.3: the server is a deputy that
performs actions on objects. **Authentication** asks "which deputy instruction did the real user
send?"; **authorization** asks "is this deputy allowed to act on *this* object for *this* caller?"
Broken access control is the deputy acting on an object because you *named* it, not because you *own*
it. You recognize it by changing an identifier and watching someone else's data come back.

## The underlying technology

### Authn vs authz, and where each lives

- **Authentication** happens at login and is then *carried* on every subsequent request by the session
  mechanism from 07.1 (opaque cookie or token). Attacks: credential stuffing/spraying (M10), bypass,
  weak reset, and — if identity is a token — forging that token.
- **Authorization** must be enforced **server-side, on every request, per object and per function.**
  The recurring failure is enforcing it *once* (at the UI, or only on the first page) and trusting the
  client thereafter — an impossible trust across the 07.1 boundary.

### Broken access control, decomposed (OWASP A01)

- **IDOR / BOLA** (Insecure Direct Object Reference / Broken Object-Level Authorization — the same bug,
  BOLA being the API-era name, OWASP **API #1**): the app exposes an object identifier (`?id=42`,
  `/invoice/1007`, a UUID in the body) and serves the object based on the ID *without checking the
  caller owns it*. Change the ID → get someone else's object. **Horizontal** privesc: same privilege
  level, another user's data. **Vertical** privesc: reaching higher-privileged functions/data
  (user → admin).
- **Function-level (BFLA)** — the *action* isn't authorized: a non-admin can call
  `POST /admin/promote` because the check only hides the button, not the endpoint.
- **Forced browsing / missing function-level access control** — admin pages, backups, API routes
  reachable directly by URL though "not linked." The UI hides them; the server doesn't gate them.
- **Metadata/parameter tampering** — a `role=user` cookie/JWT/hidden field the server trusts; change it
  to `admin`. (This is access control failing *and* trusting client data.)

### Insecure password reset

Password reset is a **second authentication path**, and often the weakest one:

- **Predictable token** — reset token is sequential, a timestamp, a short number, or an MD5 of the
  email/user id. Generate the victim's token yourself.
- **Host-header poisoning** — the app builds the reset link from the request's `Host` header
  (07.1: attacker-controlled). Request a reset for the victim with
  `Host: attacker.lab`; the victim gets a link to `attacker.lab/reset?token=…`, and if they click, the
  token comes to you. On the lab, the "attacker" host is another lab container and the token is a
  benign marker.
- **Token leakage** — token in the URL leaks via `Referer` to third-party resources on the reset page;
  or the response body/`Location` returns the token directly.
- **No invalidation / user binding** — token not tied to the user, reusable, or never expires.

### JWT — structure and attacks

A **JWT** is three Base64url parts: `header.payload.signature`. The header names the algorithm; the
payload holds claims (`sub`, `role`, `exp`); the signature is over `header.payload` with either an
**HMAC** (symmetric secret, `HS256`) or an **RSA/EC** signature (asymmetric, `RS256`). The client can
*read* everything (it is not encrypted — only signed), and therein lie the attacks:

- **`alg:none`** — set the header to `{"alg":"none"}` and drop the signature. A library that honors
  `none` accepts an unsigned, attacker-authored token. Change `role` to `admin`, send it, become admin.
- **Algorithm confusion (`RS256`→`HS256`)** — the server verifies with the RSA **public** key. If it
  naively calls `verify(token, key)` and the attacker changes `alg` to `HS256`, the library uses that
  same public key as the **HMAC secret** — which the attacker *knows* (it's public) — and forges a
  valid signature.
- **Weak HMAC secret** — `HS256` with a guessable secret (`secret`, `password`, a short string) can be
  **cracked offline** (`hashcat -m 16500`) from a single captured token, then you sign anything.
- **`kid` injection** — the `kid` (key ID) header selects the verification key; if the server uses it
  to read a file or a DB row without sanitizing, it enables path traversal or SQLi to point at a key
  you control.

<div class="callout warn">

A JWT is **signed, not secret**. Never put anything sensitive in the payload, and never trust a claim
you haven't cryptographically verified with a **pinned algorithm** and the correct key.

</div>

### OAuth2 / OIDC — delegated auth and its traps

**OAuth2** delegates *authorization* (get a token to call an API on a user's behalf); **OIDC** layers
*authentication* on top (an `id_token`, itself a JWT, proving who logged in). The common
authorization-code flow: the app redirects the user to the provider, the user consents, the provider
redirects back to the app's **`redirect_uri`** with a `code`, and the app swaps the `code` for tokens
server-side. The classic flaws are all in that dance:

- **`redirect_uri` validation** — if the provider/app accepts an attacker-controlled or loosely-matched
  redirect (open redirect, subdomain/suffix match, path append), the authorization `code` or token is
  delivered to the attacker → account takeover.
- **Missing/ignored `state`** — `state` is the CSRF token of OAuth. Without it, an attacker can splice
  their own `code` into the victim's session (login CSRF) or the reverse.
- **Token leakage** — tokens in the URL fragment leak via `Referer`/history; implicit flow (deprecated)
  is especially exposed. Prefer authorization code + PKCE.
- **Scope/consent and `nonce`** — over-broad scopes, and a missing `nonce` in OIDC allowing `id_token`
  replay.

## Why the weakness exists

Access control is **cross-cutting** — it must be re-checked at every endpoint, but frameworks make it
easy to check *authentication* globally and forget *authorization* per object. Developers test with
their own account, where every ID they see is theirs, so the missing "is it yours?" check never
surfaces. Tokens fail because signing/verification is subtle and libraries historically had unsafe
defaults (honoring `alg:none`, key-type confusion). OAuth fails because it is a multi-party redirect
protocol and any loose link in the chain (`redirect_uri`, `state`) breaks it. Underlying CWEs:
**CWE-639** (IDOR), **CWE-285/862** (missing authorization), **CWE-287** (improper authentication),
**CWE-347** (improper signature verification), **CWE-640** (weak password recovery).

## How a tester recognizes it (from behavior)

<div class="callout method">

- **IDOR/BOLA:** an identifier in the URL/body/header (`id`, `uuid`, `account`, `file`) → change it to
  a value you *shouldn't* own and watch for someone else's data (`200` + different content) instead of
  `403`. Compare responses between two accounts.
- **Vertical privesc / forced browsing:** a `403`/redirect for an admin route as `lab`, but a `200`
  when you request it with a *different method*, a trailing slash, `%2e`, an override header, or the
  admin's session — or when the endpoint simply isn't gated at all.
- **Parameter tampering:** a `role`/`isAdmin`/`user_id` you can see in a cookie/JWT/hidden field/JSON —
  flip it and watch the privilege change.
- **Password reset:** request a reset and *read the token* — is it short/sequential/derived? Does the
  link's host follow your `Host` header? Does the response echo the token?
- **JWT:** decode it (it's Base64url, not encryption). Is `alg` weak/`none`-able? Is the secret
  guessable? Does the server re-verify or just decode?
- **OAuth:** watch the redirect chain — is `state` present and checked? Can you bend `redirect_uri`?

The unifying signal: **change something that identifies you or an object, and the app's decision
changes when it shouldn't.**

</div>

## Manual investigation

Work in Repeater with two authenticated sessions side by side (`lab` and a second user), plus an
unauthenticated one:

```http
GET /api/invoice/1007 HTTP/1.1
Host: webapp.lab
Cookie: session=<LAB's session>

HTTP/1.1 200 OK
Content-Type: application/json

{"id":1007,"owner":"lab","total":42.00,"note":"LAB-FLAG-a1b2..."}
```

Now change only the object ID and keep `lab`'s session:

```http
GET /api/invoice/1006 HTTP/1.1
Host: webapp.lab
Cookie: session=<LAB's session>

HTTP/1.1 200 OK          ← should be 403; it returned ANOTHER user's invoice = IDOR/BOLA
{"id":1006,"owner":"victim","total":99.00,"note":"..."}
```

For JWT, decode and inspect before touching anything:

```bash
# LAB ONLY: split header.payload.signature and base64url-decode the first two parts.
echo '<jwt>' | cut -d. -f1 | base64 -d 2>/dev/null   # {"alg":"HS256","typ":"JWT"}
echo '<jwt>' | cut -d. -f2 | base64 -d 2>/dev/null   # {"sub":"lab","role":"user","exp":...}
# Crack a weak HS256 secret offline from the captured token:
hashcat -m 16500 token.jwt /usr/share/wordlists/rockyou.txt
```

## Tooling — what it does, key options, limits, verify by hand

<div class="callout method">

- **Burp Repeater + Comparer / "Autorize" or "AuthMatrix" extensions** — replay a request under a
  different (or no) session and *diff* the response to spot missing authorization at scale. Limit: it
  finds *candidates*; you confirm the object truly isn't yours.
- **jwt_tool / PyJWT** — decode, tamper, and test `alg:none`, algorithm confusion, `kid`, and weak
  secrets. Limit: it produces a forged token; you must verify the *server accepts* it (behavior), not
  just that the tool built it.
- **hashcat `-m 16500`** — offline crack of an `HS256` secret from one token. Limit: only weak secrets
  fall; a strong random secret won't — and cracking is offline, so it's silent but bounded by your
  wordlist/rules (M10).
- **ffuf / feroxbuster** — forced browsing for unlinked admin/API routes. Limit: wordlist-bound and
  noisy; respect rate limits.

Everything here is a *candidate generator*. The proof is always a replayed request in Repeater showing
the app made the wrong decision.

</div>

## Exploitation / demonstration (LAB ONLY)

<div class="callout attack">

**Chain: JWT `alg:none` → vertical privilege escalation.** Given a session token
`{"alg":"HS256"} . {"sub":"lab","role":"user"} . <sig>`:

1. Rebuild the header as `{"alg":"none","typ":"JWT"}` (Base64url).
2. Rebuild the payload as `{"sub":"lab","role":"admin","exp":<future>}`.
3. Concatenate `header.payload.` with an **empty** signature (trailing dot, nothing after).
4. Send it to an admin-only route in Repeater.

```http
GET /admin/flag HTTP/1.1
Host: webapp.lab
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJsYWIiLCJyb2xlIjoiYWRtaW4ifQ.

HTTP/1.1 200 OK
{"flag":"LAB-FLAG-9f3c...","note":"admin panel"}
```

It works because the JWT library was configured (or defaulted) to accept `alg:none`, so it never
verified a signature — the token is whatever you wrote. **Recognition without the tool:** you noticed
the identity was a client-held JWT (07.1) and a decodable `role` claim; the attack is just editing a
value the server trusts.

**IDOR variant (no token needed):** the invoice example above — keep your own session, change the
object ID, read the benign `LAB-FLAG` planted in another user's synthetic record. The proof is the
`200` with someone else's `owner`.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** These forged tokens, tampered IDs, and poisoned reset links target only
`labs/lab-07-web` on the isolated network, with synthetic users and benign `LAB-FLAG-{uuid}` markers.
The "attacker" host in the reset demo is another lab container; no real email, host, or user is
involved. Forging a token or accessing another person's record on any system you are not explicitly
authorized to test is a serious crime (00.1) — access-control abuse is *reading real people's data*.
Restate scope and authorization first.

</div>

## Verification

Prove the decision was wrong, not just that a response came back: for IDOR, show the same request under
your session returning an object whose `owner` is another user, and (ideally) that the legitimate owner
sees the same object. For vertical privesc, show a route that is `403` as `lab` returning `200` with
the forged/tampered identity. For JWT, show the *unmodified* token gets `user` behavior and the
*modified* one gets `admin` behavior. For reset, show the generated/leaked token successfully setting a
password. Capture request + response pairs for each.

## Impact

Broken access control is typically **high or critical**: mass data exposure (every record by iterating
IDs), account takeover (reset flaw, token forgery, OAuth redirect), and full administrative compromise
(vertical privesc). A single IDOR on a well-populated endpoint often means *every* user's data —
frame it that way in the report (M16), with the count of records reachable, not a single example.

## Remediation

<div class="callout defend">

- **Enforce authorization server-side on every request, per object and per function** — check
  ownership/role against the *authenticated session*, never a client-supplied identity. Default deny.
- Prefer **unpredictable, non-enumerable identifiers** (random UUIDs) — but treat that as defense in
  depth, **not** a substitute for the ownership check (BOLA still applies to UUIDs).
- **JWT:** pin the algorithm server-side, reject `none`, never use a public key as an HMAC secret, use
  a long random secret, validate `exp`/`aud`/`iss`, and sanitize `kid`. Prefer vetted libraries with
  safe defaults.
- **Password reset:** cryptographically random, single-use, short-lived, user-bound tokens; build links
  from a **server-configured** base URL, never the `Host` header; never return the token in a response;
  invalidate on use.
- **OAuth/OIDC:** exact-match `redirect_uri` allow-listing; mandatory `state` and (OIDC) `nonce`;
  authorization code + **PKCE**; keep tokens out of URLs.
- CWEs: 639, 285/862, 287, 347, 640; OWASP **A01** (Broken Access Control), **A07** (Identification &amp;
  Authentication Failures).

</div>

## Detection / blue-team view

<div class="callout defend">

- **IDOR/BOLA:** one session accessing many object IDs it never accessed before, especially sequential
  sweeps or a spike in objects-per-user — the strongest signal.
- **Vertical privesc / forced browsing:** repeated `403`/`404` on admin routes, then a `200`; requests
  to unlinked paths; unusual methods/override headers on gated endpoints.
- **JWT abuse:** tokens with `alg:none`/unexpected `alg`, signature-verification failures, or a sudden
  `role` change without a corresponding login.
- **Reset abuse:** many resets requested for different users from one source; resets with an anomalous
  `Host` header.
- Maps to **ATT&CK T1078** (Valid Accounts), **T1548** (Abuse Elevation Control Mechanism),
  **T1190** (Exploit Public-Facing Application). Core idea: *identity used to reach objects/functions
  it has no history of, or a privilege change with no matching authentication event.*

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-07-web` (built separately) — Docker, private no-Internet network.
**Access:** attacker box with a configured proxy; **two** synthetic accounts (`lab` and a second user)
plus knowledge that an admin exists; benign `LAB-FLAG-{uuid}` markers in synthetic records.
**Targets:** the lab app only. **Time:** ~90 min. **Isolation:** private Docker network; reset per the
lab README. Keep the proxy scoped to the lab host.

</div>

Using your 07.1 map, pick an access-control surface, recognize the flaw from behavior, prove it with a
benign marker, then chain a second step (e.g. IDOR to leak a reset token, or a tampered/forged token to
reach an admin function) into a higher-impact outcome.

## Exercise

<div class="callout method">

**Situation.** Authorized grey-box test of the lab app. You hold two user accounts, a configured proxy,
and your 07.1 application map. An admin role exists but you have no admin credentials.

**Objective.** **Find and chain** an access-control flaw into a higher-impact result, recognized from
behavior and proven with an inert marker — a report-ready finding.

**Starting information.** The running app, two user sessions, your 07.1 map. No source, no admin creds.

**Constraints.** Lab target only; stay in proxy scope and RoE rate limits. Prove the *mechanism* with
benign `LAB-FLAG` markers — no destructive actions, no accessing data beyond what proves the finding.
One variable at a time.

**Expected deliverables.**
1. The vulnerability class(es) and the **behavioral signal** that revealed each (the response diff, the
   decoded token, the reset token's structure — not a definition).
2. Reproduction as request/response pairs, including the **negative control** (the same request that is
   correctly denied) so the wrong decision is unambiguous.
3. The **chain**: how one flaw's output enabled the next, and the final impact (what a real attacker
   reaches, framed as blast radius / record count).
4. **Remediation and detection** for each link, mapped to CWE/OWASP/ATT&CK.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Authentication is carried, authorization must be re-checked every request. Look for the endpoint that
verified you're logged in but not whether the object/function is yours. Two accounts make the "should
be 403" obvious.
</details>

<details><summary>Hint 2 — technique family</summary>
Is identity an opaque cookie (then IDOR/forced-browsing/tampering) or a JWT (then decode it — weak
<code>alg</code>/secret)? Is there a password-reset flow (token structure, <code>Host</code> header)?
Chain: a horizontal IDOR that leaks a token often becomes a vertical takeover.
</details>

<details><summary>Hint 3 — where to look</summary>
Decode any JWT with the proxy's decoder before assuming it's opaque. Replay an admin route with a
different method / trailing slash / override header. Request a reset and read the token in the proxy —
short or derived? Follow the <code>Host</code> header into the link.
</details>

<details><summary>Hint 4 — specific direction</summary>
If it's a JWT, test <code>alg:none</code> and a weak-secret crack (<code>hashcat -m 16500</code>)
before anything fancier. If it's IDOR, iterate the ID under your own session and diff <code>owner</code>.
Always capture the negative control alongside the positive result.
</details>

## Check yourself

<div class="callout key">

1. Explain the difference between authentication and authorization using a single endpoint that gets
   one right and the other wrong.
2. An endpoint uses random UUIDs instead of sequential IDs, and the developer calls it "not IDOR-able."
   Why can BOLA still be present, and what check actually fixes it?
3. A JWT uses `RS256`. Explain the algorithm-confusion attack: what does the attacker change, and why
   does the server's *public* key end up validating a token the attacker forged?
4. A password-reset link is built as `https://<Host header>/reset?token=…`. Walk through how an
   attacker turns that into account takeover, and the one-line server-side fix.
5. Why are broken-access-control bugs the ones automated scanners miss most, and what does a human do
   that the scanner cannot?
6. In an OAuth authorization-code flow, what breaks if `state` is missing, and what breaks if
   `redirect_uri` is matched by prefix instead of exact string?

</div>

Model answers are in `solutions/module-07-part1.md` (try them first).

## References

- **OWASP Top 10 (2021)** — A01 Broken Access Control, A07 Identification &amp; Authentication Failures.
- **OWASP API Security Top 10 (2023)** — API1 BOLA, API5 BFLA.
- **OWASP WSTG v4.2** — WSTG-ATHZ (authorization, IDOR, privilege escalation), WSTG-ATHN
  (authentication, weak reset), WSTG-SESS.
- **OWASP Cheat Sheets** — Authorization; Forgot Password; JSON Web Token for Java (principles apply
  broadly); OAuth 2.0 Security.
- **RFC 7519** JWT; **RFC 8725** JWT Best Current Practices; **RFC 6749** OAuth 2.0; **RFC 6819**
  OAuth 2.0 Threat Model; **RFC 7636** PKCE; **OpenID Connect Core 1.0**.
- **CWE-639** IDOR; **CWE-862/285** Missing/Improper Authorization; **CWE-287** Improper
  Authentication; **CWE-347** Improper Verification of Cryptographic Signature; **CWE-640** Weak
  Password Recovery.
- **MITRE ATT&CK** — T1078 Valid Accounts; T1190 Exploit Public-Facing Application; T1548.

## What you should now be able to do

- Separate authn from authz and locate each on the request path.
- Recognize IDOR/BOLA, vertical/horizontal privesc, forced browsing, and function-level gaps from
  response behavior, and prove them with a negative control.
- Analyze a JWT and test `alg:none`, algorithm confusion, weak secrets, and `kid` abuse.
- Recognize insecure password-reset and OAuth/OIDC flaws from the request/redirect flow.
- Chain access-control flaws into a higher-impact result and write remediation + detection for each.

## Progress checkpoint

```bash
py course.py complete 07.2
```
