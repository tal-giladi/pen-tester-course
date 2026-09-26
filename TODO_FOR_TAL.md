# Status &amp; handoff — pen-tester-course

_Build log for the course. Newest first. Commit + push after each batch so a stopped session
resumes here._

## Done

- **Batch 1 — scaffold &amp; curriculum architecture** (2026-09-26)
  - Repo scaffold: `index.html` (docsify, terminal-green theme), `README.md`, `CLAUDE.md`,
    `LICENSE` (MIT + ethical notice), `CONTRIBUTING.md`, `CHANGELOG.md`, `.gitignore`,
    `.gitattributes`, `.nojekyll`, `course.py` (progress tracker, stdlib).
  - Curriculum: `curriculum/course-outline.md` (phases 0–14 → modules M00–M16, dependency graph,
    difficulty, certification coverage matrix, known gaps), `competency-map.md`,
    `exercise-standard.md`, `maintenance.md`.
  - `TOOLS.md` pinned inventory + fallbacks; `references/` standards-map, glossary, command-ref.
  - `labs/README.md` lab + safety architecture; `_sidebar.md`, `progress/`.

## Next up (in order)

- **Batch 2 — M00 Foundations lessons** (ethics/law/RoE, methodology+ATT&CK, threat modeling &
  attack surface, lab/safety) + `lab-00-setup` (isolation check, `lab` helper scripts).
- **Batch 3 — M01 Networking & protocols** lessons.
- **Batch 4 — M02 Recon + M03 Scanning/enum** lessons + `lab-02-recon`.
- **Batch 5 — M04 Linux privesc** lesson(s) + `lab-04-linux-privesc` + Assessment A2.
- Then M05/M06 (Windows/AD, incl. `vm/` build docs), M07/M08 (web/API + labs), M09 exploitation,
  M10 credentials, M11 lateral, M12 pivot, M13 containers, M14 cloud, M15 red-team, M16 reporting.
- Assessments A1–A7 alongside their phases; capstone last.
- Tooling: `scripts/install-tools.sh`, `scripts/check.py` (link + sidebar + currency checks).

## Notes / decisions

- Following sibling `ai-security-course` conventions (docsify, `course.py`, module/lesson layout).
- Windows/AD use VMs, not Docker — documented, not faked.
- Every lesson: link in `_sidebar.md`, then `python course.py render`.
- Solutions go in `solutions/`, never linked from `_sidebar.md`.
