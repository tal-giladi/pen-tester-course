# Standards map — OWASP · NIST · MITRE ATT&amp;CK · PTES

_Last reviewed: 2026-09._

The frameworks this course leans on, what each is for, and where it shows up. These are your
authoritative references for further study; individual lessons cite the specific document/section.

## Process &amp; methodology

| Framework | What it is | Where in the course |
|---|---|---|
| **PTES** (Penetration Testing Execution Standard) | A phase model: pre-engagement → intelligence gathering → threat modeling → vuln analysis → exploitation → post-exploitation → reporting | M00 methodology; the spine of the whole course |
| **NIST SP 800-115** — Technical Guide to Information Security Testing | Government-grade testing process, planning, and handling | M00, M16 |
| **NIST SP 800-53 / CSF 2.0** | Control catalog / risk framework — the language of remediation | M16 (remediation & risk) |
| **OSSTMM** | Operational security testing methodology (metrics-oriented) | M00 (contrast with PTES) |

## Adversary behavior

| Framework | What it is | Where in the course |
|---|---|---|
| **MITRE ATT&CK** (Enterprise) | Taxonomy of adversary **tactics** (the *why*) and **techniques** (the *how*), with IDs like `T1558` (Kerberoasting under Steal or Forge Kerberos Tickets) | M00 framing; tagged throughout; central to M15 |
| **Lockheed Martin Cyber Kill Chain** | Linear intrusion phases (recon → weaponization → … → actions on objectives) | M00 (framing, and its limits vs ATT&CK) |
| **MITRE D3FEND** | Defensive countermeasure taxonomy (pairs with ATT&CK) | M15, remediation sections |

## Web &amp; API

| Framework | What it is | Where in the course |
|---|---|---|
| **OWASP Top 10 (2021)** | The awareness list of web risk categories (A01 Broken Access Control … A10 SSRF) | M07 (as an on-ramp, then we go deeper) |
| **OWASP Web Security Testing Guide (WSTG)** | The actual *how-to-test* manual — the real backbone of M07 | M07 (primary reference) |
| **OWASP API Security Top 10 (2023)** | API-specific risks (API1 BOLA, API5 BFLA, API6 mass assignment, …) | M08 (primary reference) |
| **OWASP ASVS** | Verification standard — what "secure" means, testable | M07, M16 (remediation depth) |
| **OWASP Cheat Sheet Series** | Concise remediation guidance per topic | remediation sections |

## Vulnerability identification &amp; scoring

| Framework | What it is | Where in the course |
|---|---|---|
| **CVE** | Identifiers for specific disclosed vulnerabilities | cited per technique |
| **CWE** | Weakness *types* (e.g. CWE-89 SQL Injection, CWE-79 XSS, CWE-22 Path Traversal) | vulnerability classes |
| **CVSS v3.1 / v4.0** | Severity scoring vectors | M16 severity rationale |
| **EPSS / KEV (CISA)** | Exploit-likelihood & known-exploited catalogs — prioritization signals | M03 prioritization, M16 risk |

## AI / emerging (for cross-reference with the sibling course)

| Framework | What it is | Where |
|---|---|---|
| **MITRE ATLAS** | ATT&CK-style matrix for ML systems | noted where AI-backed apps appear |
| **OWASP LLM Top 10** | LLM app risks | pointer to sibling `ai-security-course` |

## How to read an ATT&CK citation in this course

When a lesson tags a technique, it looks like: **T1190 — Exploit Public-Facing Application**
(Tactic: *Initial Access*). Use the ID to pull the ATT&CK page for detection guidance, data
sources, and real-world procedure examples — that's how you connect an offensive technique to how
a blue team would catch it, which is the M15/remediation habit this course builds.
