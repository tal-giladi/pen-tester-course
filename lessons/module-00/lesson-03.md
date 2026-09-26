# 00.3 — Threat modeling &amp; attack surface

<div class="prereq">

**Prerequisites:** [00.1](lesson-01.md), [00.2 Methodology](lesson-02.md).
**Module:** M00 Foundations. **Difficulty:** 🟢 foundational.
**You will produce:** a threat model (data-flow diagram + trust boundaries + STRIDE notes) and a
prioritized attack-surface map for a described application.

</div>

## Why this matters

Recon and scanning produce a *pile of facts* — open ports, endpoints, versions. Threat modeling is
what turns that pile into a **plan**: it tells you which facts are interesting and why. A tester
who threat-models spends their limited time where impact is highest; one who doesn't scans
everything, exploits the first easy thing, and misses the finding that would have actually mattered
to the client. Threat modeling is also the bridge to *remediation*: the same model that finds the
weak trust boundary tells the client where to reinforce it.

## Learning objectives

- Define attack surface, trust boundary, asset, and threat, and tell them apart.
- Draw a data-flow diagram and mark trust boundaries on it.
- Apply **STRIDE** and **attack-tree** thinking to generate and prioritize attack hypotheses.
- Recognize the **confused-deputy** pattern that underlies a huge fraction of real vulnerabilities.

## Intuition

Every system is a set of components that trust each other to varying degrees, connected by flows of
data. An attacker's whole job is to find a place where trust is **misplaced** — where a component
believes a request is safe, authorized, or from who it claims, when it isn't. Threat modeling is
just drawing that trust explicitly so the misplaced bits stand out. If you can point at a line on a
diagram and say "the server trusts that this input is a filename, but the user controls it," you've
found the shape of a vulnerability before you've run a single tool.

## The vocabulary

<div class="callout key">

- **Asset** — something worth protecting: customer data, credentials, funds, availability,
  reputation. Impact is always measured against assets.
- **Attack surface** — the sum of points where an attacker can *interact* with the system:
  network ports, web endpoints and parameters, file uploads, message queues, **identities and
  their permissions**, trust relationships, even employees (social engineering).
- **Trust boundary** — a line across which the level of trust changes: Internet ↔ DMZ, unauthenticated
  ↔ authenticated, user ↔ admin, one microservice ↔ another, browser ↔ server, tenant ↔ tenant.
  **Vulnerabilities cluster on trust boundaries**, because that's where a component decides whether
  to believe something.
- **Threat** — a potential negative event: "an unauthenticated user reads another user's data."
- **Vulnerability** — a weakness that makes a threat achievable.
- **Risk** — threat × likelihood × impact. It's what the report ultimately communicates (M16).

</div>

## The underlying technique: data-flow diagrams &amp; trust boundaries

Threat modeling starts by drawing the system as **data flows between components**, then marking
where trust changes. A minimal example for a web app:

```text
                    ┌─────────── trust boundary (Internet ↔ app) ───────────┐
  [Browser] ──HTTPS──▶ [Web app] ──SQL──▶ [Database]                          │
    (untrusted)          │  ▲                                                 │
                         │  └── reads ── [Config file: DB creds, API keys]    │
                         └── HTTP ──▶ [Internal metadata / other services] ◀──┘
                                     (trust boundary: app ↔ internal network)
```

Marking the boundaries immediately raises questions a tester turns into hypotheses:

- The browser is **untrusted** — does the web app validate/authorize *everything* crossing that
  boundary, or does it trust hidden fields, IDs, or client-side checks? (→ access control, IDOR)
- Data crosses into **SQL** — is user input ever concatenated into a query? (→ SQL injection)
- The app can reach **internal services** — can an attacker make it fetch a URL of their choosing?
  (→ SSRF, the confused deputy)
- **Secrets** sit in a config file — reachable via path traversal, LFI, or a leaked backup?

## STRIDE — a checklist for "what could go wrong here?"

At each component/flow, run **STRIDE** to generate threats systematically:

| Letter | Threat | Violates | Typical example |
|---|---|---|---|
| **S** | Spoofing | Authentication | logging in as someone else; forged tokens |
| **T** | Tampering | Integrity | modifying data in transit or at rest; parameter tampering |
| **R** | Repudiation | Non-repudiation | acting without a trace; missing/forgeable logs |
| **I** | Information disclosure | Confidentiality | reading data you shouldn't (IDOR, verbose errors) |
| **D** | Denial of service | Availability | exhausting a resource *(usually out of RoE!)* |
| **E** | Elevation of privilege | Authorization | user → admin; container → host; domain user → DA |

You won't chase every STRIDE threat on every component, but running the checklist ensures you don't
*forget* a class. The output is a list of concrete hypotheses to prioritize.

## Attack trees — decomposing a goal

Where STRIDE is breadth-first per component, an **attack tree** is depth-first per goal. Put the
attacker's objective at the root and branch into ways to achieve it:

```text
GOAL: read another customer's orders
├── guess/alter the order ID the app trusts          (IDOR / BOLA)
├── log in as that customer
│   ├── credential stuffing / spraying               (weak/reused password)
│   └── password-reset flaw                           (predictable token)
└── read the database directly
    ├── SQL injection in a search field
    └── leaked DB credentials in a config/backup file
```

Each leaf is a testable hypothesis with a rough cost/likelihood — exactly what you need to
prioritize under time pressure. This is how you decide what to do *next* in the PTES loop.

## The pattern to internalize: the confused deputy

A **confused deputy** is a privileged component tricked into misusing its authority on behalf of a
less-privileged attacker. It underlies SSRF (the server has network access the user doesn't; the
user makes it fetch internal resources), CSRF (the browser has the victim's session; the attacker
makes it send a request), many access-control bugs, and much of cloud/AD abuse. Whenever you see
**"component A acts on input from B, using A's privileges,"** ask: *can B make A do something B
couldn't do directly?* If yes, you've found a confused deputy. You'll meet this pattern in almost
every later module — recognizing it now is worth more than any single exploit.

## How a tester recognizes high-value surface

- **Anything crossing a trust boundary with insufficient checks** — the boundary is where to look.
- **Privileged components that take untrusted input** — confused-deputy candidates.
- **Anywhere identity or authorization is decided** — authz bugs are the most common serious
  findings and the least likely to be caught by scanners.
- **Old, forgotten, or "internal-only" assets** exposed by accident — often the weakest link.

## Practical lab

<div class="lab">

**Environment:** paper/diagram (a drawing tool or ASCII). **Time:** ~50 min. **Targets:** none —
this is modeling, done *before* you'd touch a target.

</div>

Model this described system (you'll actually test something like it in M07's `lab-07-web`):

> *A retail web app. Customers register, log in, browse products, place orders, and download
> invoices. There's an `/admin` panel for staff. The app runs on a server that also hosts a
> product-image uploader and reads its database credentials from a config file. It calls an
> internal inventory microservice by URL, and it runs in AWS.*

1. Draw the data-flow diagram; mark every trust boundary.
2. Run STRIDE on the *invoice download* and *image upload* flows; list the threats.
3. Build an attack tree for the goal **"read another customer's invoice."**
4. Circle the two pieces of attack surface you'd investigate first and write one sentence each on
   why (impact × likelihood).

## Exercise

<div class="callout method">

**Situation.** You're handed the app above with a two-day time box and no credentials beyond a test
customer account. You cannot test everything.

**Objective.** Produce a **prioritized** attack-surface map and testing plan — not an exhaustive
list, a ranked one, with justification a client would accept.

**Starting information.** The description above and your diagram from the lab.

**Constraints.** Model only (no testing yet). DoS is out of scope, as in most engagements — factor
that into what you'd pursue.

**Expected deliverables.**
1. An attack-surface inventory grouped by trust boundary.
2. A ranked top-5 list of hypotheses, each with the STRIDE category, the boundary it crosses, a
   likelihood/impact rationale, and how you'd *cheaply* test it first.
3. One identified confused-deputy candidate in this system, named explicitly.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Rank by <em>impact on assets × likelihood</em>, not by how fun the bug is. What's the crown-jewel
asset here — customer data or admin access? Which boundaries guard it?
</details>

<details><summary>Hint 2 — technique family</summary>
Invoice download by ID → Information disclosure via broken object-level authorization. Image upload
→ Tampering/EoP via malicious file. "Calls an internal service by URL" → the confused deputy.
</details>

<details><summary>Hint 3 — where to look</summary>
The internal-service-by-URL call in an AWS environment is a classic SSRF-to-metadata path (you'll
see IMDS in M14). The config-file credentials are a high-impact secondary target if any file-read
primitive exists.
</details>

## Check yourself

<div class="callout key">

1. Why do vulnerabilities cluster on trust boundaries rather than being spread evenly?
2. You have two candidate bugs: reflected XSS on a public marketing page, and IDOR on the invoice
   endpoint. Same "medium" scanner rating. Which do you test first and why?
3. Explain the confused-deputy pattern to a developer using the "internal service by URL" flow.
4. STRIDE flags a Denial-of-Service threat on the login endpoint. The RoE forbids DoS testing. What
   do you do with that threat — ignore it, or something else?

</div>

Model answers in `solutions/module-00/`.

## References

- **Adam Shostack, *Threat Modeling: Designing for Security*** — the standard text; STRIDE and DFDs.
- **OWASP Threat Modeling** cheat sheet and **pytm** (threat-model-as-code) project.
- **Microsoft STRIDE** — the Security Development Lifecycle threat-modeling material.
- **Bruce Schneier, "Attack Trees"** (1999) — the original.
- **CWE-441** — Unintended Proxy or Intermediary ("Confused Deputy").
- **NIST SP 800-154** — Guide to Data-Centric System Threat Modeling.

## What you should now be able to do

- Turn a system description into a data-flow diagram with explicit trust boundaries.
- Generate threats with STRIDE and decompose a goal with an attack tree.
- Prioritize attack surface by impact and likelihood, and justify it to a client.
- Spot the confused-deputy pattern anywhere it appears in later modules.

## Progress checkpoint

```bash
py course.py complete 00.3
```
