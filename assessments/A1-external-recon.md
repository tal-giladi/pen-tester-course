# Assessment 1 — External reconnaissance &amp; enumeration

_Tests **M01–M03** (methodology, recon, enumeration &amp; fingerprinting). ~2–3 h. Difficulty:
🟢→🟡. This is a graded assessment, not a walkthrough — you choose the methodology and defend it
with evidence._

<div class="lab">

**Environment:** `labs/lab-02-recon` (the fictional `northwind.lab` DNS + web estate on an
internal, no-egress network). **Recon shell:** the `workstation` container
(`docker exec -it ptlab02_ws bash`) — `dig`/`curl`/`openssl`/`nmap` are baked in; resolver is
`10.13.0.53`. **Run `./labs/lab up lab-02-recon` then `./labs/lab check` FIRST** and confirm
isolation before you touch a target. Reset/down per the lab README when finished.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Every name, IP, and service in this assessment belongs to the
isolated `northwind.lab` estate shipped in `labs/lab-02-recon` (no Internet route — verify with
`./labs/lab check`). Active reconnaissance touches the target and, against anything you do not own,
is illegal without written authorization and a defined scope (see
[00.1](../lessons/module-00/lesson-01.md)). The `10.13.0.0/16` lab range and `*.northwind.lab`
are the **only** things you are authorized to enumerate here. If a name resolves to RFC 1918 space
that the lab says is "not externally reachable," that is a scope-and-reachability fact to record —
not an invitation to pivot.

</div>

## Situation

**Northwind Retail** has engaged you for a time-boxed **external** penetration test. The kickoff
was short: *"Here's the apex domain — `northwind.lab`. Assume everything under it is in scope.
Give us a picture of what's exposed on the outside and tell us where you'd go first. We think it's
just the storefront and an API, but honestly nobody's kept the DNS tidy in years."* You have been
authorized for both passive and active recon against `*.northwind.lab` and the lab netblock. No
credentials, no asset list, no network diagram.

## Objective

Produce a **confirmed, evidence-backed, prioritized external attack-surface map** of the
`northwind.lab` estate: every reachable name and service you can justify, its fingerprint, and a
defensible ranking of where a follow-on test should spend its limited time — with your reasoning.
The client's assumption ("just the storefront and an API") is a hypothesis for you to confirm or
break, not a given.

## Starting information

- One apex domain: `northwind.lab`.
- The lab resolver at `10.13.0.53`, reachable from the `workstation` container.
- Authorization for passive and active recon across `*.northwind.lab` and the lab range.
- Nothing else. No subdomain list, no IPs, no tech stack — you build all of it.

## Constraints

- **Lab target only.** Work exclusively against `labs/lab-02-recon`; run `./labs/lab check` and
  confirm no Internet route before starting.
- **In scope:** DNS records for `northwind.lab`, hosts under `*.northwind.lab`, and services on the
  lab network you can reach from the `workstation` container.
- **Out of scope:** anything a name points *to* that the lab flags as internal/RFC 1918 and not
  externally reachable — record its existence and reachability as a finding; do **not** treat it as
  an external target. Any third-party target a record hints at (e.g. an alias to an external
  provider) is likewise off-limits: record it, do not probe it.
- **No destructive actions.** Recon and enumeration only; no exploitation. Keep active recon at a
  reasonable rate (this is a lab, but form the habit).
- Every host you list must be **confirmed** (it resolves and/or responds) with the evidence and the
  method that confirmed it — a name from one source alone is a hypothesis, not a host.

## Expected deliverables

1. **Recon notes** — what you did and why, in order, so another tester could repeat your process.
   Separate *passive* observations from *active* confirmation, and record the method that confirmed
   each host (DNS resolution, zone transfer, vhost fuzzing, certificate SAN, etc.).
2. **Attack-surface map** — a table of confirmed hosts: name, IP, service(s), fingerprint
   (technology/version signals from live headers/banners), how it was discovered, and whether it is
   externally reachable. Call out every host the client did **not** mention.
3. **Evidence** — the actual command output that backs each row (a captured zone transfer, a
   `curl -sI` header block, an `openssl s_client` certificate dump, a vhost-fuzz hit). A claim
   without its artifact is not done.
4. **Prioritization with rationale** — rank the hosts for a follow-on engagement by
   **impact × likelihood** (per [03.x](../lessons/module-03)), not by which host looks "main." For
   your top choices, give a one-line justification and the trust boundary each host sits on.
5. **A written finding** — pick the single most significant *reconnaissance* issue you found (an
   information-exposure or misconfiguration that a defender should fix — e.g. an open zone transfer,
   a leaked non-production host, a name exposed only in a certificate) and write it up using
   [`solutions/report-template/finding-template.md`](../solutions/report-template/finding-template.md).
   Fill every field: what, where, reproduction, evidence (with the observed artifact), impact,
   severity rationale (CVSS), and remediation. Recon findings are real findings.

## Grading rubric

Student-visible. "Good" means the reasoning and evidence are there — the path is yours to find.

| Dimension | Points | What "good" looks like |
|---|---|---|
| **Method** | 25 | Passive-then-active discipline; multiple independent discovery techniques, not one tool's output; each host confirmed by a stated method; process is reproducible. |
| **Evidence** | 20 | Every host and claim backed by the actual captured artifact; enough to reproduce without you. |
| **Enumeration completeness** | 20 | Finds hosts beyond the client's assumption, including at least one not discoverable by naive DNS resolution alone; distinguishes externally reachable from internal-only. |
| **Prioritization &amp; impact** | 15 | Ranking argued by impact × likelihood and trust boundary, not host prominence; internal-only assets correctly deprioritized for *external* testing. |
| **Remediation** | 10 | The written finding's fix is specific, root-cause, and verifiable. |
| **Reporting** | 10 | Finding uses the template, every field filled; severity rationale justified; writing is clear and client-ready. |

## Progressive hints

<details><summary>Hint 1 — conceptual direction</summary>
The client's asset list is a claim to test, not a map to follow. Recon is about the gap between
what an organization <em>thinks</em> it exposes and what it <em>actually</em> exposes. Where do
names come from besides "someone told me"? Enumerate the <em>sources of names</em> first, then
confirm.
</details>

<details><summary>Hint 2 — technique family</summary>
Names live in more places than one A record: the authoritative nameservers themselves (and there
may be more than one), the HTTP layer (the same IP can serve many sites keyed by a header), and the
TLS layer (a certificate names every host it was issued for). A thorough map pulls from all three,
then resolves and probes to confirm.
</details>

<details><summary>Hint 3 — tool category &amp; what to look at</summary>
For DNS: an authoritative-record query to list the nameservers, then a zone-transfer attempt
against <em>each</em> one — configuration often differs between primary and secondary. For HTTP:
fingerprint with header requests and fuzz the host-selection header against the web IP. For TLS:
inspect the live certificate's subject-alternative-name list. Fingerprint every live host from its
own responses.
</details>

<details><summary>Hint 4 — specific investigation direction</summary>
Try the zone transfer against every nameserver you find, not just the first — one may be a
forgotten secondary that answers. A host can be reachable only through the <code>Host:</code>
header (not in DNS at all), and another may appear only in a certificate's SAN list. When a
dumped name points into private address space the lab calls not-externally-reachable, that is a
finding about exposure and a note for post-foothold work — not an external target to rank first.
</details>

## Check yourself

<div class="callout key">

1. You attempted a zone transfer against the first nameserver and it was refused. What is the
   professional next step, and why is "DNS is locked down" the wrong conclusion?
2. A name you enumerated resolves into RFC 1918 space and does not respond from the workstation.
   Is it in scope for *external* testing? What do you do with it, and where does it belong in your
   prioritization?
3. You found a host that appears only in a TLS certificate's SAN list and another reachable only
   via the `Host:` header. Explain, mechanically, why neither shows up in a plain forward-DNS
   sweep.
4. Two hosts are live: a hardened production storefront and a debug-enabled non-production host.
   The client calls the storefront "the important one." Which do you rank first for a follow-on
   test, and how do you defend the choice in impact-×-likelihood terms?

</div>

_Model answers and the intended surface map are instructor material in
`solutions/assessments/A1.md` — attempt the assessment before looking._
