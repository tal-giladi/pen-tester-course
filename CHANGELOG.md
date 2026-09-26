# Changelog

All notable changes to this course. Curriculum versioning is independent of any single lesson;
lessons carry their own last-reviewed date where it matters.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/). Dates are ISO.

## [Unreleased]

### Added
- Repository scaffold: docsify site (`index.html`), `README.md`, `CLAUDE.md`, `LICENSE`,
  `CONTRIBUTING.md`, `.gitignore`/`.gitattributes`, `course.py` progress tracker.
- Curriculum architecture: `curriculum/course-outline.md` (phase/module map, dependency graph,
  difficulty, certification coverage matrix, known gaps), `competency-map.md`,
  `exercise-standard.md`, `maintenance.md`.
- `TOOLS.md` pinned tool inventory; `references/` standards map, glossary, command reference.
- Lab framework overview (`labs/README.md`) and safety architecture.

## [0.1.0] — 2026-09-26
- Project initialized from `plan.md`. Curriculum version 0.1.

## Batch 3 — 2026-09-26
- M01 Networking & protocols (3 lessons), M02 Reconnaissance (2), M03 Scanning &
  enumeration (3), M04 Linux & privilege escalation (3) — 11 lessons + instructor solutions.
- Labs: lab-02-recon (BIND with AXFR-open secondary, multi-vhost nginx, hidden vhost,
  cert-SAN pivot; tested) and lab-04-linux-privesc (5 independent privesc vectors; tested).
  Both isolated (no egress) with acceptance tests.
