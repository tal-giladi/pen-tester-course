# Status & handoff — pen-tester-course

_Build log. Commit + push after each batch so a stopped session resumes here._
_Published: https://github.com/tal-giladi/pen-tester-course · site: https://tal-giladi.github.io/pen-tester-course/_

## Done (pushed)

- **Scaffold + curriculum** — docsify site, course.py tracker, LICENSE/CONTRIBUTING/CHANGELOG,
  curriculum (outline, competency map, exercise standard, maintenance), TOOLS.md, references
  (standards map, glossary, command ref), lab + safety architecture.
- **Lessons — 39 total, all linked & tracked:** M00 Foundations (4), M01 Networking (3),
  M02 Recon (2), M03 Scanning/enum (3), M04 Linux privesc (3), M05 Windows (3),
  M06 Active Directory (4), M07 Web (5), M08 API (2), M09 Exploitation (3),
  M10 Credentials (2), M13 Containers/K8s (2), M14 Cloud (3). Instructor solutions per module.
- **Labs — 8 runnable, all isolated (no egress) + acceptance-tested where runnable:**
  lab-00-setup, lab-02-recon, lab-04-linux-privesc, lab-07-web, lab-08-api, lab-09-exploit,
  lab-13-containers; lab-05-win-privesc (VM docs + provision.ps1). VM lab architecture doc.
- Correctness fix: internal:true Docker networks don't publish ports — attack from an
  on-network workstation (fixed lesson 00.4 + affected lab READMEs).

## Remaining to reach "complete" (per plan.md §30)

- **Lessons:** M11 Lateral movement, M12 Pivoting & segmented networks, M15 Red-team/adversary
  simulation, M16 Professional practice & reporting.
- **Labs still to build:** lab-06-ad (Windows/AD VM forest provisioning — DC01/SRV01/WS01,
  see labs/vm), lab-11-lateral, lab-12-pivot (DMZ→internal→restricted), lab-14-cloud
  (LocalStack-style sim referenced by M14 — lessons pin AWS_ENDPOINT_URL=localhost:4566).
- **Assessments A1–A7** (specs in assessments/, solutions in solutions/) and the **capstone**.
- **Reporting templates** (solutions/report-template/) for M16.
- **scripts/**: install-tools.sh, check.py (link + sidebar + currency checks).
- Optional: papers/reading guides; wire check.py into CI.

## How to resume

- New lessons: write under lessons/module-NN/, add to _sidebar.md, `py course.py render`.
- Solutions go in solutions/ (never linked from _sidebar.md).
- New labs: follow the internal:true + workstation-on-network pattern; add a verify.py; test with
  `bash labs/lab up <dir>` / `check` / `py labs/<dir>/verify.py` / `down`.
- Subagent drafting worked well (point them at CLAUDE.md + exemplars 00.1/00.3/04.2 + strict safety);
  note M13-style container/escape prompts can trip cyber safeguards — author those directly.
