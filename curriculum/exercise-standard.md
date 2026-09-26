# Exercise design standard

_Last reviewed: 2026-09._

Every substantial exercise in this course follows the structure below. The point is to build
**investigation skill**, not to check whether you can copy a command. If an exercise could be
solved by pasting a line from the lesson, it is wrong and should be rewritten.

## The forbidden pattern

> ❌ "Run `nmap` against the target."

That tests nothing. Compare:

> ✅ "You have been given a partially documented corporate network. Several services are
> intentionally exposed, but only some belong to the application environment. Map the externally
> reachable attack surface, identify the technology stack, determine which services deserve
> deeper investigation, and justify your prioritization. Submit evidence supporting your
> conclusions."

The second forces the learner to decide *what* to do and *why*, and to defend it with evidence.

## Required sections

Each exercise page contains, in this order:

1. **Situation** — a realistic scenario (a client, a foothold, a scope).
2. **Objective** — what must be accomplished, in outcome terms.
3. **Starting information** — only what a real tester would receive. Withhold the rest.
4. **Constraints** — what is in and out of scope; time/impact limits; the safety boundary
   restated (LAB TARGET only).
5. **Expected deliverables** — e.g. recon notes, attack-surface map, evidence, vulnerability
   identification, exploit chain, root cause, impact, remediation, and (later) a report section.
6. **Progressive hints** — collapsed, revealed one at a time, never the answer:
   - Hint 1 — conceptual direction ("what class of problem is this?")
   - Hint 2 — technique family
   - Hint 3 — relevant tool/category and what to look at
   - Hint 4 — specific investigation direction
7. **Check yourself** — reasoning questions (interpret this output; what else could explain it?).

**The solution never appears on the student page.** It lives in `solutions/` with the intended
path, common wrong turns, and grading notes, and is not linked from `_sidebar.md`.

## Progressive removal of assistance (`plan.md` §28)

The same topic is scaffolded less as the course advances:

| Stage | The exercise gives you… | You supply… |
|---|---|---|
| Early | The concept and how to investigate it | The execution |
| Middle | The scenario | What to investigate |
| Advanced | The engagement | Your methodology |
| Final | The scope and the environment | The whole assessment |

## Hints in docsify

Use HTML `<details>` so hints stay collapsed:

```html
<details><summary>Hint 1 — conceptual direction</summary>
What trust boundary is being crossed here, and who is being confused into acting for whom?
</details>
```

## Deliverable rubric (used by assessments &amp; capstone)

A finding is only "done" when it has: **what** (the vulnerability, precisely), **where** (asset +
location), **reproduction** (steps another tester can follow), **evidence** (screenshot/log/PoC
with the synthetic marker), **impact** (business consequence, not "it's bad"), **severity
rationale** (CVSS or equivalent, justified), and **remediation** (actionable). This mirrors the
report template in M16 and `solutions/report-template/`.
