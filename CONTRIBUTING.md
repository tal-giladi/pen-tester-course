# Contributing / authoring guide

This is a personal, curated course. These notes keep it consistent and safe if it is extended.

## Ground rules

1. **Safety boundary is absolute.** Every offensive lesson and lab targets ONLY the intentionally
   vulnerable systems shipped here, on isolated/private networks, with **synthetic** credentials
   and **benign** markers. No real hosts, no real credentials, no working malware, no live exfil
   endpoints, no detection-evasion tuned against real products. Every offensive page restates
   LAB TARGET vs REAL SYSTEM and the written-authorization requirement.
2. **Methodology over tools.** A tool is introduced only to serve a concept, and always with: what
   it does on the wire, key options, limits, and how to verify its result by hand.
3. **Every learning unit has a reasoning exercise** — never "run this command." Progressive hints;
   the solution never appears on the student page (it goes in `solutions/`).
4. **Cite primary sources.** RFCs, vendor advisories, OWASP, NIST, MITRE ATT&CK, CVE/CWE, original
   research. Citations must enable further study, not decorate.
5. **Mark currency.** Tag material FOUNDATIONAL / CURRENT / EMERGING / DEPRECATED and keep a
   last-reviewed date on fast-moving content.

## Lesson checklist

- Follows the lesson template in [`CLAUDE.md`](CLAUDE.md).
- Linked in [`_sidebar.md`](_sidebar.md) (or `course.py` and readers can't find it).
- Has a hands-on lab or exercise with deliverables and hints, no inline solution.
- Any command shown is current and tested; any tool version is reflected in [`TOOLS.md`](TOOLS.md).
- Reproducible: lab documents CPU/RAM/disk, exact commands, and a reset path.

## Labs

- Self-contained under `labs/lab-NN-slug/`: `README.md`, compose/code, an attack script, a verify
  step, and a `reset`. Prefer Docker; use VMs only where Docker cannot honestly model the target,
  and document why (Windows/AD).
- Networks are private with no default route to the Internet. Include an isolation check.

## Progress tracker

`course.py` is infrastructure, not content. It reads `_sidebar.md` and writes
`progress/progress.json` + `PROGRESS.md`. Don't hand-edit `PROGRESS.md`.

## Commits

Small, focused commits; push after each batch. Keep [`CHANGELOG.md`](CHANGELOG.md) current.
