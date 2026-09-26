# Capstone — integrated engagement

<div class="prereq">

**This is the culminating deliverable of the course.** It integrates every phase: recon,
enumeration, web/API, Linux, Windows, **Active Directory**, credentials, lateral movement, pivoting,
and — above all — **professional reporting** (M16). It follows the *final* scaffolding stage
(`plan.md` §28): *here is the scope and the environment; conduct the assessment.*
**Client brief, scope, RoE, and your starting information:**
[`scope-and-roe.md`](scope-and-roe.md) — **read it first.**
**Difficulty:** 🔴🔴 expert-integrative. **Time:** a multi-day engagement.
**You will produce:** a complete, professional penetration-test report of a full external-to-domain
compromise, to the M16 template.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** The capstone runs **only** against the shipped, network-isolated
capstone environment described in [`scope-and-roe.md`](scope-and-roe.md) — synthetic domain,
synthetic accounts, benign `LAB-FLAG-…` markers, **no Internet route**. The complete kill chain you
will build here is serious unauthorized-access crime against anything you neither own nor are
contracted to test. On a **REAL SYSTEM**: signed authorization + defined scope + RoE, escalation
contacts, and stop conditions — exactly the package in `scope-and-roe.md` — must exist *before* you
touch it (00.1, 16.1). Run `./labs/lab check` (and confirm each VM cannot reach the Internet) before
every offensive session. If isolation fails, **stop**.

</div>

## Situation

You have been engaged by **Vireo Logistics Ltd.** for a grey-box external-to-internal penetration
test. The full client brief, the exact scope, the rules of engagement, and the single low-privilege
starting position you are given are in [`scope-and-roe.md`](scope-and-roe.md). In short: Vireo
believes a small external foothold cannot reach their customer data and contracts because "sensitive
systems are segmented off." A recent phishing near-miss shook that confidence. You are to determine —
and prove, with evidence — how far a determined attacker gets from a minimal foothold, whether the
crown-jewel data is reachable, and what Vireo must fix first.

This is a real engagement in every respect except the targets. No one will tell you what to do next.

## Objective

Conduct the **complete engagement** and deliver a **professional report**. Concretely, you must:

1. **Enumerate** the external attack surface from your starting position, and map it.
2. **Discover** the exploitable weaknesses across the tiers (web/API, hosts, domain) — assume
   nothing, verify everything.
3. **Obtain a foothold**, then **escalate** on the host you land on.
4. **Pivot** across the network segmentation into the internal and restricted segments.
5. **Compromise further systems**, including the corporate **Active Directory** domain, to the
   extent the scope allows.
6. **Identify the sensitive assets** (customer PII, contracts, finance references) and **demonstrate
   business impact** — reach and prove access to the crown-jewel data / flags.
7. **Collect evidence** throughout, to the deterministic naming and handling standard (16.1).
8. **Write the report** — the actual deliverable (see below).

The intended attack path is **not published here** (that is the point of the assessment). You
determine the methodology; the environment will reward systematic work and punish guessing.

## Starting information

See [`scope-and-roe.md`](scope-and-roe.md) §8. You get: one low-privilege customer-portal account,
public reachability to `http://portal.vireo.lab` only, and the in-scope ranges. No domain
credentials, no topology past the perimeter, no source, no endpoint list, no path. Everything else
you earn.

## Constraints

All from the RoE ([`scope-and-roe.md`](scope-and-roe.md) §3, §6, §7): in-scope segments only; **no
DoS**; **no destructive exploitation**; minimal-access data handling; no persistent implants/tunnels
left behind; offline/targeted credential techniques over lockout-inducing brute force; and the
**safety boundary** — LAB TARGETS ONLY, isolation verified (`./labs/lab check`) before every
session. Critical findings are escalated the day they are confirmed (16.3), recorded in your log.

## Expected deliverable — the report

The capstone is graded primarily on a **single, complete, professional penetration-test report**,
built from [`solutions/report-template/report-outline.md`](../solutions/report-template/report-outline.md),
classified **CONFIDENTIAL**. It must contain every section of that template:

<div class="callout method">

1. **Cover & document control** — client, engagement, window, tester, version/date, distribution,
   confidentiality classification, revision history.
2. **Executive summary** (1–2 pages) — **no jargon, no CVSS numbers**: what you did, an honest,
   non-theatrical risk posture, the handful of themes that matter to Vireo's *business* (can an
   attacker reach customer data and contracts?), a severity count, and the top priorities framed as
   decisions leadership should make now (16.3).
3. **Scope & rules of engagement** — from the brief; what was in/out, assumptions, test type,
   authorization reference, and who was notified of what.
4. **Methodology** — standards followed (PTES · NIST SP 800-115 · OWASP WSTG / API Top 10 · MITRE
   ATT&CK mapping), your approach, the severity method (CVSS v3.1 **and** v4.0), and honest
   **limitations**.
5. **Findings summary table** — ID · title · severity · CVSS · affected asset · status.
6. **Detailed findings** — one [finding-template](../solutions/report-template/finding-template.md)
   block per finding, each rubric-complete: **what · where · reproduction · evidence (with the
   marker) · impact · CVSS v3.1+v4.0 rationale · remediation · references**. Another tester must
   reproduce each from your steps alone.
7. **Attack narrative & timeline** — the story of the whole chain (external foothold → host privesc →
   pivot across segments → domain compromise → crown-jewel data), in attacker order, mapped to
   ATT&CK technique IDs, with a timestamped timeline from your action log that Vireo's blue team can
   replay against their own logs.
8. **Remediation roadmap** — risk-prioritised, tie-broken by effort; quick wins vs. projects; and at
   least two **strategic** (pattern-level) recommendations — including the segmentation verdict
   (does the "segmented off" claim hold?) and an AD-tiering recommendation if warranted.
9. **Appendices** — evidence index (deterministic filenames mapped to findings), key tool output,
   PoC/payloads with markers, methodology detail / ATT&CK technique list, and a glossary for the
   non-technical reader.

</div>

Alongside the report, retain your **raw evidence** and **action log** (the timeline is built from
it). Findings from the AD, pivoting, and web tiers should carry through the report as one coherent
chain, not as disconnected bugs.

## Progressive hints

*(Methodology only — the capstone never hands you the path. If you need more than a nudge on the
underlying technique, revisit the module and its assessment first.)*

<details><summary>Hint 1 — conceptual direction</summary>
Treat this as one engagement, not a series of lab puzzles. Every phase produces two things: a
finding for the report, and a <em>lead</em> for the next phase. Plan the report structure on day one
and keep the action log from your first packet — the narrative and timeline are impossible to
reconstruct later from memory, and they are where a chain of "mediums" becomes the "critical" that
funds the fix.
</details>

<details><summary>Hint 2 — technique family</summary>
Move through the kill chain in order and let access compound: external surface → foothold →
local escalation → cross-segment movement → domain → data. The perimeter yields <em>information or
access</em>; hosts yield <em>credentials</em>; credentials and the directory graph yield
<em>the domain</em>; the domain yields <em>the data</em>. Segmentation is a claim to test, not a
fact to accept — the question is always "what host do I now control, and what does it touch?"
</details>

<details><summary>Hint 3 — where to look / how to work</summary>
Apply the discipline from each phase's module and assessment: WSTG-style mapping of the whole web/API
surface before exploiting (A4); systematic local-privesc enumeration (A2); credential-reuse and
pivoting tradecraft (A6); and AD-as-a-graph attack-path reasoning (A5). The thing that carries you
between tiers is almost always <em>recovered credential material or a permission relationship</em>,
not a novel exploit. Verify every collector/tool result by hand.
</details>

<details><summary>Hint 4 — specific direction</summary>
When you stall, you are usually missing a lead you already collected — re-read your own notes for a
credential, key, config, share, SPN, or ACL you noted and did not follow. Confirm reachability at
each segment boundary (what fails directly, what succeeds from the host you just took) before
building the next pivot. And stop attacking with enough time left to <em>write</em> — an
under-reported full compromise scores below a well-reported partial one, because the report is the
product (16.3).
</details>

## Grading rubric

<div class="callout method">

| Dimension | What distinguishes a strong submission |
|---|---|
| **Coverage of the chain** | External foothold → host escalation → cross-segment pivot → AD/domain compromise → sensitive-asset access, each stage evidenced with the `LAB-FLAG-…` marker. Partial chains are graded on how far, how cleanly, and how well reported. |
| **Findings quality** | Every finding rubric-complete and reproducible by another tester; correct, defensible severities (CVSS v3.1 **and** v4.0 with rationale); business-terms impact. |
| **Report as product** | All template sections present; **executive summary** genuinely non-technical and decision-oriented; findings genuinely engineer-actionable; both describe the same facts at different altitudes. |
| **Attack narrative & timeline** | The chain reads as one coherent story mapped to ATT&CK; the timeline is timestamped, consistent with the evidence, and useful to a blue team. |
| **Remediation roadmap** | Risk-prioritised, effort-aware; includes the segmentation verdict and pattern-level (strategic) fixes, not just per-bug patches. |
| **Professionalism & safety** | Isolation verified every session; minimal-access data handling; deterministic evidence naming; CONFIDENTIAL classification; critical findings escalated in-engagement and recorded; honest limitations; nothing destructive or out of scope; environment left clean. |
| **Distinction** | The report would survive a real debrief with Vireo's board and its two engineers: honest posture, no FUD, severities defensible by vector, a roadmap that fixes classes of weakness — and a clear, evidenced answer to the CISO's actual question. |

</div>

> **This is a capstone: the report is the deliverable, not the shell.** A brilliant compromise
> described in a confusing report is a failed engagement; a well-reported, honestly-scoped
> compromise is the one that gets the tester hired again (16.3).

_The intended attack path(s), the flags/evidence at each stage, common wrong turns, and the full
grading key are instructor material in
[`solutions/capstone/walkthrough.md`](../solutions/capstone/walkthrough.md) — the **only** place the
path appears, and not linked from the sidebar. Do not open it until you have conducted the
engagement._
