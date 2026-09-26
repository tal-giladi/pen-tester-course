# Build guide — Penetration Testing &amp; Ethical Hacking course

This repo is a **docsify static course site** (no build step) plus a **runnable, network-isolated
local lab** (`labs/`). It takes an experienced software engineer (Tal — C#/.NET) to professional
penetration-testing capability: methodology, recon, enumeration, Linux/Windows/AD, web/API,
exploitation, credentials, lateral movement, pivoting, containers, cloud, red-team concepts, and
professional reporting. Source brief: `plan.md`. Sibling course conventions: `../ai-security-course`.

## Layout
- `index.html` — docsify config (search, copy-code, count). No build step. Terminal-green theme.
- `README.md` — docsify home page.
- `_sidebar.md` — full navigation. **Every new lesson/lab/assessment MUST be linked here** (and
  `course.py` reads lessons from it, so a lesson not linked here is invisible to progress tracking).
- `curriculum/` — `course-outline.md` (phase/module map + dependency graph + difficulty +
  certification matrix + gaps), `competency-map.md`, `exercise-standard.md`, `maintenance.md`.
- `lessons/module-XX/lesson-YY.md` — lesson content (`XX` = module 00–16).
- `labs/` — `README.md` (shared lab + `lab` helper), `lab-XX-slug/` self-contained environments
  (README + compose/code + attack + verify + reset), `vm/` (Windows/AD build docs).
- `exercises/`, `assessments/`, `capstone/` — student-facing, **solution-free**.
- `solutions/` — instructor material; keep OUT of `_sidebar.md` and the student flow.
- `references/` — standards maps, `glossary.md`, `command-reference.md`.
- `TOOLS.md` — pinned tool inventory (tested version + purpose + fallback).
- `progress/` — `progress.json` + generated `PROGRESS.md`; `course.py` at repo root.

## Lesson template (every lesson) — from `plan.md` §21, §30
`# NN.M — Title` → **Why this matters** → **Learning objectives** → **Prerequisites** (`.prereq`) →
**Intuition** → **The underlying technology** → **Why the weakness exists** → **How a tester
recognizes it** → **Manual investigation** → **Tooling** (what it does / key options / limits /
verify by hand) → **Exploitation / demonstration** (lab only) → **Verification** → **Impact** →
**Remediation** → **Detection / blue-team view** → **Practical lab** (`.lab` box) → **Exercise**
(situation/objective/starting info/constraints/deliverables/progressive hints — NO solution) →
**Check yourself** (reasoning questions, answers hidden or in `solutions/`) → **References**
(primary; CVE/CWE/OWASP/ATT&CK where apt) → **What you should now be able to do** → **Progress
checkpoint** (`python course.py complete NN.M`).

Teach in this order every time: intuition → technology → why the weakness exists → recognize →
manual → tooling → exploit → verify → impact → remediation. **Never** `run command → get shell`
without the mechanism. Show the real artifacts (packets, HTTP requests, auth flows, permissions,
process/registry state) whenever they clarify.

## Callouts (defined in `index.html`)
`.callout.legal` (law/authorization), `.callout.method` (methodology), `.callout.recon`,
`.callout.attack`, `.callout.defend` (remediation/detection), `.callout.warn`, `.callout.key`.
`.lab` box = hardware/target/runtime + isolation note. `.prereq` box up top. `.hw` for heavy VMs.
Badges: `.badge.found` FOUNDATIONAL · `.badge.current` CURRENT · `.badge.emerging` EMERGING ·
`.badge.deprecated` DEPRECATED. Mark historical-but-taught techniques honestly.

## Non-negotiable rules
- **Safety boundary (`plan.md` §7, §7-safety).** Every offensive action in the course targets
  ONLY the intentionally vulnerable targets shipped in `labs/`, on **private/isolated networks**
  with **synthetic** credentials (e.g. `lab / Lab-Passw0rd!`, canaries `LAB-FLAG-{uuid}`) and
  **benign markers**. No real hosts, no real credentials, no working malware, no live exfil
  endpoints, no detection-evasion tuned for real EDR. Every offensive page repeats LAB TARGET vs
  REAL SYSTEM and the authorization requirement. Labs must be resettable and must not require or
  enable Internet targets. Payloads prove the *mechanism*, not a weaponized effect.
- **Methodology over tools.** Explain what a tool does on the wire and how to verify by hand.
- **Every learning unit has a hands-on exercise** that requires reasoning (not "run nmap").
  Progressive hints; never reveal the solution on the student page.
- **Instructor/solution separation.** Solutions live in `solutions/`, never linked from
  `_sidebar.md`, never inline on the exercise page.
- **Modernity.** Distinguish FOUNDATIONAL / CURRENT / EMERGING / DEPRECATED. Verify tools,
  commands, CVEs, and cert objectives are current; don't preserve outdated technique out of habit.
- **Citations.** Every substantial technical section cites primary sources (RFC, vendor advisory,
  OWASP, NIST, MITRE ATT&CK, CVE/CWE, original research) — to enable further study, not decoration.
- **Reproducibility.** Pin tool versions in `TOOLS.md`; each lab documents CPU/RAM/disk, exact
  commands, and a reset path. Prefer Docker; use VMs only where Docker cannot honestly model the
  target (Windows/AD), and say so.

## Local preview
`python -m http.server 8080` from repo root → <http://localhost:8080>.
Labs: `cd labs/lab-XX-slug && docker compose up` (each lab documents the exact command); the
`labs/lab` (or `labs/lab.ps1`) helper wraps `up/status/reset/down`.

## Progress tracking
`course.py` (stdlib only) reads lessons from `_sidebar.md`, tracks status/quiz/notes in
`progress/progress.json`, regenerates `PROGRESS.md`. Not course content — never edit as lesson work.

## Status / handoff
`TODO_FOR_TAL.md` tracks progress and gaps. **Commit and push after each small batch** so a
stopped session never restarts from scratch. Keep `CHANGELOG.md` current. Attribution lines per
session instructions.
