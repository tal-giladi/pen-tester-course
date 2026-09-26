# Status & handoff — pen-tester-course

_Published: https://github.com/tal-giladi/pen-tester-course · site: https://tal-giladi.github.io/pen-tester-course/_

## v1 COMPLETE (all pushed)

- **Curriculum & scaffold** — docsify site, `course.py` tracker, `scripts/check.py` (passing) +
  `install-tools.sh`, LICENSE/CONTRIBUTING/CHANGELOG, curriculum (outline + cert matrix, competency
  map, exercise standard, maintenance), TOOLS.md, references (standards map, glossary, command ref).
- **17 modules / 48 lessons** M00–M16, each with instructor solutions:
  Foundations, Networking, Recon, Scanning, Linux, Windows, Active Directory, Web, API,
  Exploitation, Credentials, Lateral movement, Pivoting, Containers/K8s, Cloud, Adversary
  simulation, Professional practice & reporting (+ reusable finding/report templates).
- **11 runnable labs, all isolated (no egress) + acceptance-tested** where Docker-runnable:
  lab-00 (isolation), lab-02 (recon), lab-04 (Linux privesc), lab-07 (web), lab-08 (API),
  lab-09 (exploit/ret2win), lab-11 (lateral/cred-reuse), lab-12 (pivot DMZ→internal→restricted),
  lab-13 (container escape), lab-14 (cloud/LocalStack), **capstone** (integrated web→pivot→crown
  jewel). Windows & AD are documented VM labs (lab-05, lab-06-ad) with provisioning.
- **7 assessments (A1–A7)** + **capstone** (client brief, scope/RoE, full-report deliverable),
  student-facing & solution-free; all instructor solutions/walkthrough in `solutions/`.

## Optional future work (not required for v1)

- Build & validate the Windows/AD **VM** labs on real eval media (lab-05 `provision.ps1`,
  lab-06-ad `provision-notes.md` / GOAD) — currently documented, not machine-tested here.
- Reconcile capstone/assessment solution object-names (`svc_sql`, etc.) against the AD
  provisioning once the VM forest is built (flagged in `solutions/capstone/walkthrough.md`).
- Optional: `papers/` reading guides; wire `scripts/check.py` into GitHub Actions CI; mobile/
  wireless/physical tracks (deliberately out of v1 scope — see curriculum "Known gaps").

## Maintenance

Follow `curriculum/maintenance.md`: frontier notes for fast-moving changes, core edits only when
methodology/tooling actually shifts; keep `CHANGELOG.md` + last-reviewed dates current. Run
`py scripts/check.py` before a release.

## Working conventions (for resuming)

- New lesson → `lessons/module-NN/`, link in `_sidebar.md`, `py course.py render`.
- Solutions in `solutions/` (never linked from `_sidebar.md`).
- New labs → `internal: true` networks + on-network workstation + a `verify.py`; test with
  `bash labs/lab up <dir>` / `check` / `py labs/<dir>/verify.py` / `down`.
- Container/escape lesson prompts can trip cyber safeguards in subagents — author those directly.
