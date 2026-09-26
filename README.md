# Penetration Testing &amp; Ethical Hacking

**A serious, modern, self-paced penetration-testing curriculum for experienced software engineers — methodology first, tools second, every concept reproduced in a safe local lab.**

This is a full course, meant to be studied **in order**, not a cheat-sheet collection or a pile of
CTF walkthroughs. It takes an engineer who can already read code and use a shell and builds the
reasoning and hands-on skill of a professional penetration tester: map an attack surface, form
hypotheses, enumerate, discover and *validate* vulnerabilities, exploit them in controlled
environments, escalate, move laterally, pivot, and then **document, quantify impact, and report**
like a professional.

> The measure of this course is not "get root." It is:
> **discover → validate → understand → demonstrate impact → document → communicate → remediate → retest.**

---

## Who this is for

An experienced software engineer (comfortable with a terminal, a programming language, HTTP, and
basic networking) who wants real penetration-testing capability — whether to move into offensive
security, to build software that resists attack, or to lead security work. It assumes no prior
security background but does not slow down to re-explain programming or the command line.

## What makes it different

- **Methodology and reasoning over tool memorization.** Every tool is taught only to serve a
  concept: what problem it solves, what it actually does on the wire, its limits, and *how to
  verify its result by hand*. No cargo-cult "run this → get shell."
- **A complete local lab.** A reproducible, resettable, **network-isolated** lab of intentionally
  vulnerable targets (Docker where honest, VMs where Docker cannot faithfully model Windows/AD).
  You cannot accidentally point it at the Internet.
- **Realistic exercises.** Not "scan this host." Instead: *"here is a partially documented
  network — map the external attack surface, justify what deserves deeper investigation, and
  submit supporting evidence."* Assistance is progressively removed as you advance.
- **Professional outcome.** Reporting, severity, risk, evidence handling, and client
  communication are taught as first-class skills, with templates and a capstone report.
- **Modern and cited.** Aligned to current certification objectives (OSCP/PEN-200, PNPT, eJPT,
  PenTest+, and CRTO/OSEP where relevant) and grounded in OWASP, NIST, MITRE ATT&CK, and vendor
  and primary sources — without copying any syllabus.

---

## Safety &amp; the law — read this first

<div class="callout legal">

**All offensive work in this course targets ONLY the intentionally vulnerable systems shipped in
this repo's `labs/`, running on private, isolated networks with synthetic credentials and benign
success markers.** Attacking systems you do not own or lack **explicit written authorization** to
test is illegal in most jurisdictions. This repository teaches skills for authorized testing and
defense. You are responsible for using them lawfully. See
[**00.1 Ethics, authorization &amp; the law**](lessons/module-00/lesson-01.md).

</div>

---

## How to use it

```text
clone → run lab setup → start a module → read the lesson → do the lab → do the exercise → record progress
```

- Start at [**the curriculum map**](curriculum/course-outline.md) to see the whole route,
  dependencies, and what each module assumes.
- Study lessons in sidebar order. Each ends with an exercise and a progress checkpoint.
- Build the lab once ([`labs/README.md`](labs/README.md)), then bring individual scenario
  environments up and down per lesson.
- Track where you are with `course.py` (below).

## Structure

- **Curriculum** — [`curriculum/course-outline.md`](curriculum/course-outline.md): the phase/module
  map, prerequisite graph, difficulty, certification coverage matrix, and known gaps.
- **Lessons** — `lessons/module-NN/lesson-NN.md`, following the template in `CLAUDE.md`.
- **Labs** — `labs/`: the shared lab (`labs/README.md`) plus self-contained per-topic
  environments (`docker compose up`, do the work, `./reset`), and VM build docs for Windows/AD.
- **Exercises / Assessments / Capstone** — `exercises/`, `assessments/`, `capstone/`: realistic,
  multi-step, solution-free on the student side.
- **Solutions / Instructor** — `solutions/`: kept separate and out of the student flow.
- **References** — `references/`: standards maps (OWASP, NIST, MITRE ATT&CK), a glossary, and a
  command/technique reference.
- **Tools** — [`TOOLS.md`](TOOLS.md): pinned tool inventory with tested versions and fallbacks.
- **Progress** — `progress/` + `course.py`.

## Progress tracking

`course.py` (Python standard library only) reads the lesson list from `_sidebar.md`, records
status, quiz scores, struggles and notes in `progress/progress.json`, and regenerates
[`PROGRESS.md`](PROGRESS.md). New lessons appear automatically.

```bash
python course.py status
python course.py next
python course.py complete 02.1
```

## Local preview of the website

```bash
python -m http.server 8080
```

Then open <http://localhost:8080>. The repository is the source of truth; it stays fully usable as
plain Markdown even if GitHub Pages is disabled.

---

*Course under active construction — see [`TODO_FOR_TAL.md`](TODO_FOR_TAL.md) for current status and
[`CHANGELOG.md`](CHANGELOG.md) for version history.*
