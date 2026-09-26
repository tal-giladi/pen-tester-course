# Curriculum map, dependency graph, difficulty &amp; certification coverage

_Last reviewed: 2026-09. Curriculum version: 0.1._

This course is **engineered, not assembled**. It moves from stable foundations (networking,
methodology, ethics) through the core testing workflow (recon → enumeration → vuln discovery →
exploitation → post-exploitation → reporting), then through the environment-specific depth a
professional needs (Linux, Windows, Active Directory, web, API), and finally through the
cross-cutting skills that separate a tester from a tool-runner (credentials, lateral movement,
pivoting, containers, cloud, adversary simulation, professional practice).

Read this page before any module to answer: *what must I understand first, why does this module
exist, and how deep do I go?*

<div class="callout method">

**Design influences — principles extracted, syllabi NOT copied.** The structure synthesizes the
overlapping core of OffSec **PEN-200/OSCP** (2024 refresh), TCM Security **PNPT**, INE **eJPT
v2**, CompTIA **PenTest+ (PT0-003)**, Zero-Point Security **CRTO**, and OffSec **PEN-300/OSEP**;
the taxonomy of **MITRE ATT&CK**; the web depth of the **OWASP Web Security Testing Guide** and
**Web/ API Security Top 10**; and the process spine of **NIST SP 800-115** and the **PTES**.
See the [certification coverage matrix](#certification-coverage-matrix) and
[`references/standards-map.md`](../references/standards-map.md).

</div>

---

## The spine

```text
Ethics / Law / Rules of Engagement  ─▶  Networking & protocols for testers
        │
        ▼
Methodology (PTES / kill chain / ATT&CK)  ─▶  Recon (passive → active → OSINT)
        │
        ▼
Scanning & enumeration  ─▶  Vulnerability discovery & prioritization
        │
        ▼
Linux (use → privesc)      Windows (use → privesc)
        │                        │
        └───────────┬────────────┘
                    ▼
        Active Directory (major)  ◀── credential attacks, lateral movement feed in here
                    │
                    ▼
Web app testing (major)  ─▶  API testing
                    │
                    ▼
Exploitation fundamentals (memory corruption, mitigations, ROP concepts)
                    │
                    ▼
Credentials ─▶ Lateral movement ─▶ Pivoting & segmented networks
                    │
                    ▼
Containers & Kubernetes ─▶ Cloud (AWS/Azure/GCP) ─▶ Red-team / adversary simulation
                    │
                    ▼
Professional practice & reporting  ─▶  Assessments  ─▶  Capstone engagement
```

Cross-cutting threads present at every stage: **methodology and note-taking**, **manual
verification before tooling**, the **impact-and-remediation lens**, and the **legal/authorization
boundary**.

---

## Phases &amp; modules

Numbering: module `NN` → `lessons/module-NN/`. Difficulty 🟢 foundational · 🟡 intermediate ·
🔴 advanced · ⚫ expert/optional. "Assumes" lists hard prerequisites (see the
[dependency graph](#dependency-graph)).

### Phase 0 — Foundations &amp; methodology  🟢
> The reasoning frame and the technology every later module assumes.

| Module | Focus | Difficulty | Assumes |
|---|---|---|---|
| **M00 Foundations** | Ethics, authorization, the law; rules of engagement & scope; PTES/NIST methodology; threat modeling & attack surface; the kill chain; MITRE ATT&CK; the lab & safety architecture | 🟢 | — |
| **M01 Networking & protocols for testers** | TCP/IP, the packet's journey, ports/sockets, DNS, HTTP/HTTPS & TLS, routing/NAT, firewalls/proxies/VPNs, authentication concepts (authn vs authz, sessions, tokens) | 🟢 | M00 |

### Phase 1 — The testing workflow  🟢🟡
> The process, applied end to end on easy targets, so the shape is muscle memory before the depth.

| Module | Focus | Difficulty | Assumes |
|---|---|---|---|
| **M02 Reconnaissance** | Passive vs active; OSINT discipline & OPSEC; DNS enumeration; subdomain discovery; certificate transparency; attack-surface inventory | 🟡 | M01 |
| **M03 Scanning & enumeration** | Host discovery; TCP/UDP port scanning (how it works on the wire); service & version fingerprinting; banner & protocol enumeration; vulnerability discovery and **prioritization**; from findings to a plan | 🟡 | M01, M02 |

### Phase 2 — Linux  🟡
| Module | Focus | Difficulty | Assumes |
|---|---|---|---|
| **M04 Linux for testers & privilege escalation** | Architecture, users/groups/permissions, processes/services, shells & Bash, environment & PATH, cron, SUID/SGID, capabilities, sudo rules, kernel vs userland; a systematic local-privesc methodology (enumerate → hypothesize → verify) | 🟡 | M03 |

### Phase 3 — Windows  🟡
| Module | Focus | Difficulty | Assumes |
|---|---|---|---|
| **M05 Windows for testers & privilege escalation** | Architecture, processes/services, users/groups, registry, PowerShell; NTLM & Kerberos primer; SMB/RPC/WinRM/LDAP; tokens & impersonation; services, scheduled tasks, unquoted paths, DLL hijack; a Windows privesc methodology | 🟡 | M03 |

### Phase 4 — Active Directory  🔴 (major, multi-lesson)
| Module | Focus | Difficulty | Assumes |
|---|---|---|---|
| **M06 Active Directory** | AD as a graph: domains/forests/trusts, DCs, LDAP, users/groups/computers/OUs, GPOs, ACLs, delegation, SPNs, service accounts; authentication flows & credential material; enumeration (incl. BloodHound-style graph reasoning); Kerberoasting, AS-REP roasting, delegation abuse, ACL/GPO abuse, credential reuse; domain privilege escalation and attack-path analysis | 🔴 | M05, (M10 helps) |

### Phase 5 — Web application testing  🔴 (major, multi-lesson)
| Module | Focus | Difficulty | Assumes |
|---|---|---|---|
| **M07 Web application penetration testing** | HTTP/cookies/sessions in depth; authn/authz/access control; JWT/OAuth/OIDC; the injection family (SQLi, NoSQLi, command, SSTI); XSS; SSRF; XXE; file upload; path traversal; deserialization; prototype pollution; request smuggling; CORS/cache poisoning/deception; race conditions; **business-logic** & IDOR/BOLA; recognizing each from behavior | 🔴 | M01, M03 |

### Phase 6 — API security  🟡🔴
| Module | Focus | Difficulty | Assumes |
|---|---|---|---|
| **M08 API security** | REST & GraphQL; API discovery & schema analysis; object- & function-level authorization (BOLA/BFLA); mass assignment; excessive data exposure; rate limiting/abuse; JWT/OAuth pitfalls; versioning & undocumented endpoints (OWASP API Top 10 2023) | 🟡🔴 | M07 |

### Phase 7 — Exploitation fundamentals  🔴
| Module | Focus | Difficulty | Assumes |
|---|---|---|---|
| **M09 Exploitation & memory corruption** | Exploitation methodology; memory layout; stack/heap; buffer overflows; shellcode concepts; bad chars; return addresses; calling conventions; mitigations (ASLR, DEP/NX, stack canaries, PIE) and what defeats them; ROP concepts; when to build vs. use tooling responsibly | 🔴 | M04 |

### Phase 8 — Credentials  🟡
| Module | Focus | Difficulty | Assumes |
|---|---|---|---|
| **M10 Credential attacks** | Password policy reality; spraying vs brute force vs stuffing (and why the difference matters operationally & ethically); hashes & storage; offline cracking (Hashcat/John): wordlists, rules, masks; NTLM & Kerberos ticket material; secrets discovery (config, browser stores, keys, tokens); avoiding destructive testing | 🟡 | M05, M06 |

### Phase 9 — Lateral movement  🔴
| Module | Focus | Difficulty | Assumes |
|---|---|---|---|
| **M11 Lateral movement** | SMB/WinRM/RDP/SSH; PsExec-style, WMI, PowerShell remoting; remote-service abuse; credential reuse; pass-the-hash & pass-the-ticket; overpass-the-hash; what these look like to a defender | 🔴 | M06, M10 |

### Phase 10 — Pivoting &amp; segmented networks  🔴
| Module | Focus | Difficulty | Assumes |
|---|---|---|---|
| **M12 Pivoting & complex networks** | Routing recap; local/remote/dynamic port forwarding; SSH tunnels; SOCKS & proxychains workflows; reverse tunnels (Chisel); network discovery through a pivot; segmentation analysis; the Internet→DMZ→internal→restricted model | 🔴 | M11, M04 |

### Phase 11 — Containers  🟡🔴
| Module | Focus | Difficulty | Assumes |
|---|---|---|---|
| **M13 Containers & Kubernetes** | Docker architecture; namespaces/cgroups/capabilities; volumes & the mounted Docker socket; container-escape concepts; secrets & insecure images; supply-chain risk; Kubernetes attack surface (RBAC, service accounts, exposed kubelet/API) where it belongs in pentesting | 🟡🔴 | M04 |

### Phase 12 — Cloud security  🔴
| Module | Focus | Difficulty | Assumes |
|---|---|---|---|
| **M14 Cloud penetration testing** | IAM, roles, credentials; metadata services (IMDSv1/v2) & SSRF-to-cloud; storage exposure; security groups; identity/privilege escalation paths; cloud APIs; secrets & logging; common misconfigurations across AWS/Azure/GCP — testing skills, not cloud engineering | 🔴 | M07, M10 |

### Phase 13 — Red team / adversary simulation  🔴⚫
| Module | Focus | Difficulty | Assumes |
|---|---|---|---|
| **M15 Adversary simulation concepts** | ATT&CK as a frame; initial access, persistence, C2, privilege escalation, lateral movement, credential access, defense-evasion *concepts*; OPSEC; detection-aware testing; assembling attack chains — concepts and detection, **not** malware development | 🔴⚫ | M11, M06 |

### Phase 14 — Professional practice  🟡
| Module | Focus | Difficulty | Assumes |
|---|---|---|---|
| **M16 Professional practice & reporting** | Scope, RoE, assumptions, exclusions; test planning; evidence handling; severity (CVSS) & risk; reproduction steps; screenshots; executive summary; technical findings; attack narrative; timeline; remediation; retesting; client communication; producing a full report | 🟡 | all |

---

## Practical labs (per module)

Each module has at least one self-contained lab under `labs/`. The shared lab
([`labs/README.md`](../labs/README.md)) provides the attacker workstation, private networks, and
the `lab` helper. Labs map to modules:

| Lab | Environment | Serves |
|---|---|---|
| `lab-00-setup` | Attacker box, isolation verification, target-allowlist check | M00, safety |
| `lab-02-recon` | DNS + web + hidden services on a private range to inventory | M02, M03 |
| `lab-04-linux-privesc` | Misconfigured Linux host (SUID, sudo, cron, capabilities, PATH) | M04 |
| `lab-05-win-privesc` | Windows target (service/registry/task/DLL misconfig) — VM | M05 |
| `lab-06-ad` | Small AD forest (DC + 2 hosts) — VM, resettable snapshots | M06, M10, M11 |
| `lab-07-web` | Vulnerable web app suite (injection, access control, SSRF, upload) | M07 |
| `lab-08-api` | REST + GraphQL API with BOLA/BFLA/mass-assignment | M08 |
| `lab-09-exploit` | Deliberately vulnerable network service (overflow) in a sandbox | M09 |
| `lab-11-lateral` | Two-host credential-reuse / PtH scenario | M11 |
| `lab-12-pivot` | DMZ → internal → restricted multi-network topology | M12 |
| `lab-13-containers` | Exposed Docker socket, over-privileged container, mini-k8s | M13 |
| `lab-14-cloud` | Local cloud-IAM/metadata simulation (LocalStack-style) | M14 |

VM-based labs (Windows/AD) are built from documented, licensed evaluation media — see
[`labs/vm/README.md`](../labs/vm/README.md). We do **not** pretend Docker can model Windows/AD.

---

## Assessments &amp; capstone

Substantial, minimally guided checkpoints after major phases (specs in `assessments/`, solutions
in `solutions/`):

1. **A1 — External recon & enumeration** (after M03)
2. **A2 — Linux privilege escalation** (after M04)
3. **A3 — Windows privilege escalation** (after M05)
4. **A4 — Web application penetration test** (after M07/M08)
5. **A5 — Active Directory attack path** (after M06/M10/M11)
6. **A6 — Pivoting & segmented network** (after M12)
7. **A7 — Full penetration test** (after M16)

**Capstone** (`capstone/`): a large integrated environment — enumerate, discover surface, exploit,
foothold, escalate, pivot, compromise further systems, find sensitive assets, demonstrate impact,
collect evidence, and deliver a **professional report**. The intended attack path is never on the
student page; instructor material is in `solutions/`.

---

## Dependency graph

```text
M00 ─▶ M01 ─▶ M02 ─▶ M03 ─┬─▶ M04 ─▶ M09
                          │        └─▶ M13
                          ├─▶ M05 ─▶ M06 ─▶ M11 ─▶ M12
                          │        │        ▲
                          │        └─▶ M10 ─┘
                          └─▶ M07 ─▶ M08
                                   └─▶ M14
M06 + M11 ─▶ M15
everything ─▶ M16 ─▶ capstone
```

Reasonable study orders: strictly by number (safe), or the "web track" (M00→M03, M07, M08, M14)
and the "infra/AD track" (M00→M06, M10→M12, M15) in parallel after M03, converging at M16.

---

## Certification coverage matrix

Not a promise of exam readiness — a map of where this course's material overlaps each
certification's public objectives, so you can see what's covered and what to study additionally.

| Course area | eJPT v2 | PenTest+ PT0-003 | PNPT | OSCP / PEN-200 | CRTO | OSEP |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| Ethics, scope, RoE, methodology (M00) | ● | ● | ● | ● | ◐ | ◐ |
| Networking & protocols (M01) | ● | ● | ● | ● | — | — |
| Recon & OSINT (M02) | ● | ● | ● | ● | ◐ | — |
| Scanning & enumeration (M03) | ● | ● | ● | ● | — | — |
| Linux privesc (M04) | ◐ | ● | ● | ● | — | ◐ |
| Windows privesc (M05) | ◐ | ● | ● | ● | ◐ | ◐ |
| Active Directory (M06) | ◐ | ◐ | ● | ● | ● | ● |
| Web app testing (M07) | ● | ● | ● | ● | — | ◐ |
| API security (M08) | ◐ | ● | ◐ | ◐ | — | — |
| Exploitation/mem corruption (M09) | — | ◐ | ◐ | ◐ | — | ◐ |
| Credential attacks (M10) | ◐ | ● | ● | ● | ● | ● |
| Lateral movement (M11) | ◐ | ● | ● | ● | ● | ● |
| Pivoting (M12) | ◐ | ● | ● | ● | ● | ● |
| Containers/K8s (M13) | — | ◐ | — | — | — | — |
| Cloud (M14) | — | ● | ◐ | — | — | — |
| Adversary sim / evasion (M15) | — | ◐ | ◐ | ◐ | ● | ● |
| Reporting & communication (M16) | ◐ | ● | ● | ● | ◐ | ◐ |

● core coverage · ◐ partial/adjacent · — out of that cert's scope. Cert objective sets change;
this row-set was reviewed 2026-09 (see [`curriculum/maintenance.md`](maintenance.md)).

**Honest framing:** this course maps most completely to **PNPT** and the practical core of
**OSCP/PEN-200**; it gives a strong foundation toward **eJPT** and **PenTest+**; and it introduces
(does not fully cover) the adversary-simulation depth of **CRTO/OSEP**. Cloud and container depth
exceeds what most current pentest certs require, because real engagements increasingly need it.

---

## Known gaps &amp; deliberate exclusions

Tracked so they are chosen, not accidental:

- **Physical, wireless (802.11/WPA), and social-engineering** testing are introduced conceptually
  in M00/M15 but not built as full labs — they need hardware/RF or live human targets that the
  isolation model forbids. Pointers to safe practice environments are given.
- **Mobile app testing** (Android/iOS) is out of scope for v1; noted as a future track.
- **Full C2 framework operation and malware development** are deliberately excluded (see M15) —
  the course teaches the *concepts and detection*, not weaponization.
- **Live cloud-tenant testing** is replaced by a local simulation; provider rules of engagement
  and safe practice ranges are documented in M14.
- **Windows/AD labs require virtualization** (Hyper-V/VirtualBox) and licensed evaluation media;
  Docker is not used to fake them.

See [`competency-map.md`](competency-map.md) for the outcome-level skills checklist and
[`maintenance.md`](maintenance.md) for how this curriculum is kept current.
