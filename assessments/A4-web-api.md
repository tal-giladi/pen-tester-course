# Assessment 4 — Web &amp; API penetration test

_Tests **M07** (web application testing — injection, access control, XSS, SSRF, traversal, upload,
SSTI) and **M08** (API testing — BOLA/BFLA, broken auth/JWT, mass assignment, excessive data
exposure, improper inventory, GraphQL). ~4–6 h. Difficulty: 🟡→🔴. This is an engagement: you get
the scope and the environment; the whole assessment is yours to design._

<div class="lab">

**Environment:** `labs/lab-07-web` (the "Northwind Shop" Flask app + internal service &amp;
metadata simulation) and `labs/lab-08-api` (the REST + GraphQL API). Both run on internal,
no-egress networks; you attack from the `workstation` container
(`docker exec -it ptlab07_ws sh` / `ptlab08_ws sh`) — the app is `http://web:5000`, the API is
`http://api:5000`. **Run `./labs/lab up lab-07-web` and `./labs/lab up lab-08-api`, then
`./labs/lab check` FIRST** and confirm isolation. Burp/Kali may attach to the Docker network (see
the lab README); everything is doable with `curl`. **Reset re-seeds** stored-XSS/profile/upload
state — reset between runs so results stay deterministic.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** All work targets the deliberately vulnerable `web` and `api`
services on their isolated networks, with synthetic users and benign `LAB-FLAG-*` markers. The
networks have **no Internet route** — deliberately, so the app's SSRF can never reach the real
Internet or real cloud metadata (verify with `./labs/lab check`). Every technique here (injection,
authentication bypass, IDOR/BOLA, SSRF, traversal, upload, SSTI) is a crime against any system you
do not own and are not explicitly authorized to test ([M00](../lessons/module-00/lesson-01.md)).
These two labs only; do not point any of it outward.

</div>

## Situation

**Northwind Retail** is preparing to launch a customer storefront and its supporting API, and has
engaged you for a **grey-box web &amp; API penetration test** before go-live. You are given the two
in-scope base URLs and a set of low-privilege test accounts — the access a real customer would
have. The client's brief: *"Two of our engineers built this fast. We need to know what a malicious
customer — or someone who signs up and pokes around — can actually do: read other people's data,
get admin, reach anything they shouldn't. Give us findings we can hand to the developers, with
severities, so we know what blocks launch."* No source code, no architecture diagram, no list of
vulnerabilities.

## Objective

Plan and execute a methodical assessment of the web app and the API, **identify and prove the
significant vulnerabilities across the OWASP Web and API Top 10 classes**, chain them where a chain
raises impact, and deliver **at least three report-ready findings** (spanning at least one web-only
and one API-only issue) — each with mechanism, reproduction, evidence, root cause, business impact,
justified severity, and remediation. You choose the methodology, the order, and which findings are
worth the client's attention.

## Starting information

- Web base URL: `http://web:5000` (from the `ptlab07_ws` workstation).
- API base URL: `http://api:5000` (from the `ptlab08_ws` workstation).
- Synthetic low-privilege accounts: `alice` / `bob` / `admin` exist; the standard test password is
  `password`. Treat the account(s) you are meant to use as a customer would — you are testing what
  such a user can reach and escalate to, not assuming admin.
- Discovery aids the app itself exposes (a documented API surface, robots/sitemap, GraphQL
  introspection) are fair game — finding and using them is part of the test.
- No source, no vuln list, no diagram. You map the surface and choose the targets.

## Constraints

- **Lab targets only.** Confirm isolation with `./labs/lab check` before starting; reset each lab
  between runs to clear seeded state.
- **Grey-box, authenticated-as-a-customer.** Use the provided low-privilege access to find what a
  malicious user can do; do not assume privileges you have not demonstrated you can obtain.
- **No destructive action beyond what a finding requires.** The app has state (profiles, uploads,
  orders) — access the *minimum* needed to prove each issue; do not wipe or corrupt data. For any
  data-exposure finding, capture the proof marker, not bulk real-looking PII.
- **Prove impact with the mechanism, not a weaponized effect.** SSRF is proven by reaching the
  internal-only endpoint and its marker; injection by the observable result; access-control flaws
  by retrieving another principal's data with the marker — not by damage.
- Every finding must be **reproducible without you**, with the exact request(s) and observable
  result at each step.

## Expected deliverables

1. **Attack-surface map** — the endpoints and parameters you enumerated across both services, the
   authentication model (how a session/token is issued and carried), and which surfaces you
   prioritized for testing and why. Note the discovery aids you used.
2. **Methodology &amp; recon notes** — your test plan and how you executed it, mapped to the OWASP
   Web/API Top 10 classes you covered, so the client sees the assessment was systematic (coverage),
   not just a list of lucky hits.
3. **Vulnerability identification** — each significant issue named precisely (the vulnerability and
   its location, not the class), mapped to CWE and the OWASP Web/API Top 10 item.
4. **Exploit chains &amp; evidence** — for each finding, the reproduction steps, the exact
   request/response, and the observable proof (the `LAB-FLAG-*` marker, the cross-account data, the
   internal-only response). Where two issues chain to raise impact (e.g. an auth weakness that turns
   a data-read into an account takeover, or an SSRF that reaches an internal secret), show the
   chain.
5. **Root cause, impact, severity, remediation** — for each finding: why it exists (the code-level
   root cause you can infer), the business consequence tied to this client's data/users/money, a
   justified severity (CVSS), and an actionable, layered, verifiable fix.
6. **At least three written findings** using
   [`solutions/report-template/finding-template.md`](../solutions/report-template/finding-template.md)
   — spanning **at least one web-specific and one API-specific** vulnerability — every field filled.
   Prioritize them so the client knows what blocks launch.

## Grading rubric

Student-visible. Depth and correctness beat breadth — three well-proven, well-explained findings
outscore a long list of shallow ones.

| Dimension | Points | What "good" looks like |
|---|---|---|
| **Method &amp; coverage** | 20 | A systematic plan mapped to the OWASP Web/API Top 10; the auth model understood; surface enumerated (incl. discovery aids); prioritization argued. |
| **Evidence** | 15 | Every finding reproducible without you; exact requests/responses and the proof marker captured. |
| **Exploitation &amp; chaining** | 25 | Findings proven, not asserted; mechanisms correct; at least one chain that raises impact demonstrated and explained. |
| **Impact &amp; severity** | 15 | Business impact tied to this client's assets; CVSS justified per metric and reflecting what was *demonstrated*, with a noted ceiling where fuller exploitation is plausible. |
| **Remediation** | 15 | Root-cause, layered, verifiable fixes (e.g. parameterize/bind, server-side authorization, verify the token, allowlist, escape on output) — not "add a WAF." |
| **Reporting** | 10 | ≥3 findings using the template, ≥1 web + ≥1 API, every field filled, prioritized, client-ready. |

## Progressive hints

<details><summary>Hint 1 — conceptual direction</summary>
Two questions drive almost every web/API finding: <em>whose data or function is this, and does the
server actually check that I am allowed to have it?</em> and <em>where does my input cross into an
interpreter — SQL, a shell, a template, a URL fetch, HTML — without being treated as data?</em> Map
the surface, model the authentication, then test both questions against every endpoint.
</details>

<details><summary>Hint 2 — technique family</summary>
Access control: try to read or act on <em>another</em> principal's object by changing an
identifier, and try an admin-only function as a non-admin. Authentication: examine how the session
token is built and whether the server verifies it. Injection: any parameter reaching a datastore,
shell, template engine, file path, or outbound request is a candidate. The API often re-exposes the
web app's data with weaker checks — and may have forgotten a version or a whole query language.
</details>

<details><summary>Hint 3 — tool category &amp; what to look at</summary>
Use the surfaces the app hands you: a documented API description, an introspectable query endpoint,
robots/sitemap. Intercept and replay requests (curl or an intercepting proxy). For a token, decode
it and test whether the server trusts a client-set claim or a weak/absent signature. For
server-side request forgery, find the parameter that makes the server fetch a URL and point it at
something only the server can reach. Fingerprint error messages — they tell you which interpreter
you are talking to.
</details>

<details><summary>Hint 4 — specific investigation direction</summary>
Compare what the API returns for <em>your</em> object versus another id — does it check ownership,
and does it over-return fields you should never see? When creating a resource, try setting a
privilege field the client should not control. Test whether an older API version skipped auth
entirely, and whether the query language's introspection exposes unauthorized fields. A token whose
signature the server does not properly verify turns any read into an account takeover — that is the
chain worth showing. An input-fetch parameter that reaches an internal-only address proves SSRF via
the marker it returns.
</details>

## Check yourself

<div class="callout key">

1. You can read another customer's order by changing the id in the URL, and you can also make the
   server verify a token it should have rejected. Which single finding do these combine into, and
   why is the combination more severe than either alone?
2. The API returns your own user record including a `password_hash` and `ssn`. Even before any
   access-control bypass, why is that a finding on its own, and what is the class?
3. An endpoint fetches a URL you supply. In this lab it can never reach the real Internet, yet SSRF
   is still a serious finding. What do you point it at to prove impact, and why is the no-egress
   design not a mitigation of the underlying bug?
4. A `role` field set by the client is honored by the server on user creation. Name the class,
   explain the root cause in one line, and give the one-line fix.

</div>

_Model answers, the intended findings across both labs, and the grading key are instructor material
in `solutions/assessments/A4.md` — attempt the assessment before looking._
