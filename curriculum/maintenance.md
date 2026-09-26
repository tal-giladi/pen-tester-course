# Maintenance &amp; currency strategy

_Last reviewed: 2026-09._

Penetration testing changes, but a course that chases every new CVE becomes a news feed and stops
teaching. This is the policy for keeping the course current **without** destabilizing it.

## Principle

> Update a **core lesson** only when a change is significant enough to affect established
> methodology, tooling, or professional practice. Preserve foundational material unless it is
> genuinely obsolete. Everything else goes in a lightweight "frontier" note, not a rewrite.

## What we watch (and roughly how often)

| Area | Signal to watch | Cadence |
|---|---|---|
| Certifications | Objective-set revisions (OSCP/PEN-200, PNPT, eJPT, PenTest+, CRTO/OSEP) | Twice a year |
| Windows / AD | Kerberos/NTLM hardening, LSASS/credential-guard changes, AD CS, new abuse primitives | Quarterly |
| Web / API | OWASP Top 10 & API Top 10 revisions, WSTG updates, browser security-model changes | On release |
| Cloud | IMDS/metadata changes, IAM privilege-escalation research, provider RoE changes | Quarterly |
| Tooling | Successor tools (e.g. CrackMapExec → NetExec), version-breaking changes | As they land |
| Exploitation | Mitigation changes (CET/shadow stacks, kernel hardening) | Yearly |

Primary sources are listed per lesson and in [`references/standards-map.md`](../references/standards-map.md).

## How changes land

1. **Frontier note** (`lessons/frontier/update-NN.md`) — a short, dated note: what changed, why it
   matters, which lesson it touches, and whether a core edit is warranted. Cheap and reversible.
2. **Core edit** — only when the frontier note concludes methodology/tooling actually shifted. The
   edit preserves the foundational explanation, bumps the lesson's last-reviewed date, and is
   recorded in [`CHANGELOG.md`](../CHANGELOG.md).
3. **Curriculum bump** — structural changes (new module, reordering) increment the curriculum
   version in [`course-outline.md`](course-outline.md).

## Currency tags

Every substantial claim is implicitly one of:

- <span class="badge found">FOUNDATIONAL</span> — stable; rarely changes (TCP/IP, HTTP semantics,
  Kerberos basics, memory layout).
- <span class="badge current">CURRENT</span> — accurate for this year's systems and tools.
- <span class="badge emerging">EMERGING</span> — real but fast-moving; expect change.
- <span class="badge deprecated">DEPRECATED</span> — taught for understanding/history, not as
  current best practice (and labeled as such).

Also distinguish **DOCUMENTED** (from a cited source) vs **SPECULATION/experience** when a claim is
operational rather than sourced.

## Automated checks

`scripts/check.py` (added with the tooling batch) runs link checks over the Markdown, verifies
every lesson is linked in `_sidebar.md`, and flags lessons whose last-reviewed date is stale. Run
it before a release; wire it into CI if the repo ever gets Actions.
