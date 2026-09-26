# Capstone — instructor walkthrough, intended path & grading key

> Instructor material. Not linked from `_sidebar.md`. **This is the only document in the course that
> contains the capstone attack path — never merge any of it into `capstone/README.md` or
> `scope-and-roe.md`.** Do not distribute to students. Segment-to-lab mappings and object names below
> are the intended design built on the shipped labs; reconcile against the actual provisioning
> (`labs/lab-06-ad/provision/`, `lab-07-web`, `lab-04-linux-privesc`, `lab-11-lateral`,
> `lab-12-pivot`) before a cohort runs, and update this key if any lab changes.

## What the capstone assesses

Everything, integrated, culminating in the **report**. The student must connect five phases into one
engagement and one narrative: external web/API → host foothold & privesc → cross-segment pivot →
Active Directory domain compromise → sensitive-asset (crown-jewel) access — then deliver a complete,
two-altitude professional report. Grade the report hardest: an under-reported full compromise scores
below a well-reported partial one (16.3).

## Environment map (segment → shipped lab)

The `./labs/lab up capstone` environment composes the shipped labs into the segmented network from
[`scope-and-roe.md`](../../capstone/scope-and-roe.md) §2. Intended mapping:

| Segment | Range | Backed by | Role in the engagement |
|---|---|---|---|
| DMZ | `10.13.10.0/24` | `lab-07-web` (`web`, `internal-api`, metadata sim) | External customer portal `portal.vireo.lab`; the only externally reachable tier. |
| Internal | `10.13.20.0/24` | `lab-04-linux-privesc` + `lab-11-lateral` (`host-a`) | Linux app/host the foothold escalates on; carries the credential material for lateral movement. |
| Restricted | `10.13.30.0/24` | `lab-11-lateral` (`host-b`) + finance-data marker | Crown-jewel host / customer-contract & finance data. |
| Corporate AD | `192.168.56.0/24` (host-only) | `lab-06-ad` VM (DC01/SRV01/WS01, `lab.local`) | The Windows domain; SRV01 bridges the internal segment to the domain. |
| Segmentation | networks between the above | `lab-12-pivot` topology | The DMZ→internal→restricted isolation the student must test and pivot. |

Bridge hosts (dual-homed) are the pivot points: the DMZ host bridges to internal; an internal
host/SRV01 bridges to the domain and to restricted. Confirm the exact interface assignments against
the compose/provisioning before the cohort.

## Intended attack path (reference chain)

Multiple footholds and privesc vectors exist by design; the reference chain is the intended
"cleanest" full path. Any evidenced, reproducible route that reaches the crown jewels qualifies.

### Phase 1 — External foothold (DMZ, T1595 → T1190)

- Enumerate `portal.vireo.lab` (the `lab-07` `web` app) WSTG-style. The customer account from the
  brief logs in but confers nothing internal.
- Foothold options (any qualifies): **OS command injection** at `/ping?host=` → RCE as the app user
  (fastest); **SSTI** at `/render`; **file upload** webshell at `/upload`; or **SQLi** at `/search`
  → dump `users`+hashes → crack (Hashcat `13100`/plain) → reuse. SSRF at `/fetch?url=` reaches the
  internal-api/metadata sim and is a strong *information* finding (T1190 → cloud-metadata sim, ties
  to M14 concepts) but is not required for the chain.
- **Evidence:** command execution proof / dumped marker; DMZ host reached.

### Phase 2 — Host escalation (internal foothold, T1548/T1068)

- The foothold host (`lab-04` target) has several independent local-privesc vectors (SUID exec, sudo
  NOPASSWD, world-writable root cron, capability on a copied interpreter, PATH-abusable SUID helper).
  Any → **root**. Read `/root/flag.txt` (`LAB-FLAG-{uuid}`).

### Phase 3 — Pivot across segmentation (T1090 / T1021.004)

- From the rooted internal host, enumerate interfaces/routes (`lab-12` mechanic): the host bridges to
  segments the attacker box cannot reach directly. Establish the pivot (SSH `-J` chain, dynamic SOCKS
  + proxychains, or forwards) to reach the restricted segment and the AD host-only network.
- **Segmentation verdict:** the student must state whether "segmented off" holds — it does **not**;
  a single DMZ→internal compromise bridges to both restricted and the domain.

### Phase 4 — Credential reuse & Active Directory compromise (T1552 → T1078 → T1558/T1484/DCSync)

- On the internal host, recover credential material (the `lab-11` deploy-key/service-account reuse
  mechanic) that authenticates to a **domain-joined** host (SRV01) — e.g. `lab\svc_sql` /
  `Lab-Passw0rd!` reused, or a key/config leaking a service credential.
- Land on the domain as a low-priv/service principal, then run the **A5** attack-path playbook
  (BloodHound-style graph → Kerberoast `svc_sql` / AS-REP roast → ACL edge `WriteDacl`/`GenericAll`
  → **DCSync** or `Domain Admins`). Reach **domain compromise**: DCSync `krbtgt`/`Administrator`, or
  DA membership + DC access.
- **Evidence:** DA-only flag on DC01 (`LAB-FLAG-{uuid}`) + DCSync output (`krbtgt` hash).

### Phase 5 — Sensitive assets & impact (T1005 / T1213)

- With domain control and the restricted-segment pivot, reach the crown-jewel host (`lab-11`
  `host-b` / restricted marker) and the "customer contracts / finance" data. Read the restricted
  flag (`LAB-FLAG-{uuid}`).
- **Impact demonstration:** answer the CISO's actual question — an external foothold *does* reach
  customer data and contracts; segmentation did not prevent it; domain compromise makes it
  domain-wide.

### End-to-end ATT&CK spine

T1595/T1190 (recon→initial access) → T1059 (execution) → T1548/T1068 (privesc) → T1552 (cred access)
→ T1090/T1021.004 (pivot/lateral) → T1078 (valid accounts) → T1558.003 Kerberoast / T1484 or DACL
abuse → DCSync (T1003.006) → T1005/T1213 (collection of sensitive data).

## Flags / evidence checklist

- [ ] DMZ foothold proof (RCE / dumped marker) — `LAB-FLAG-{uuid}` (web tier).
- [ ] Internal host root — `/root/flag.txt` `LAB-FLAG-{uuid}`.
- [ ] Pivot proof — direct reach fails from attacker box; succeeds through the pivot.
- [ ] Domain compromise — DA-only flag on DC01 + DCSync `krbtgt` hash.
- [ ] Crown jewel — restricted-segment `host-b` / finance marker `LAB-FLAG-{uuid}`.
- [ ] Action log with timestamps → the report timeline.

## Common wrong turns

- **Puzzle-hopping** — treating each lab as an isolated CTF and never building the single narrative /
  timeline the capstone is graded on.
- **Path tunnel-vision** — grabbing one foothold and never enumerating the rest of the surface, so
  the report misses reportable findings the client is paying for.
- **Skipping the pivot verification** — claiming segmentation failed without the before/after
  reachability proof.
- **AD by brute force** — online spraying/lockout instead of the offline-crack / ACL graph path;
  noisy and usually breaks the environment for the next student.
- **Destructive actions** — dropping tables, disabling the DC, resetting unrecoverable passwords,
  deleting data. Safety fail; reset from snapshot.
- **Compromise-then-silence** — reaching the crown jewel but delivering a thin or jargon-filled
  report. This is the single most common capstone failure and must score as a fail on the report
  bands even if the chain was completed.
- **Over-collection** — exfiltrating bulk "customer data" rather than minimal marker evidence; the
  only permitted sink is the local sink container.
- **No in-engagement escalation** — finding the day-one Critical (internet-facing → data) and not
  recording that it was escalated per the RoE.

## Grading key

Weight the **report** heaviest. Suggested (100):

- **Coverage of the chain (25):** how many phases completed and evidenced (external → foothold →
  privesc → pivot → AD → crown jewel), marker at each stage. Partial chains graded on depth,
  cleanliness, and reporting.
- **Findings quality (15):** rubric-complete, reproducible, correct CVSS v3.1+v4.0 with rationale.
- **Report as product (20):** all template sections present; **executive summary** genuinely
  non-technical and decision-oriented; findings engineer-actionable; same facts at both altitudes.
- **Attack narrative & timeline (15):** one coherent, attacker-ordered, ATT&CK-mapped story; timeline
  timestamped and consistent with evidence; useful to a blue team.
- **Remediation roadmap (10):** risk-prioritised, effort-aware; includes the segmentation verdict and
  ≥2 strategic (pattern-level) recommendations (input-handling standard + SAST; credential/key
  hygiene; AD tiering / gMSA / ACL review; enforced segment boundaries).
- **Professionalism & safety (15):** isolation verified every session; minimal-access data handling;
  deterministic evidence naming + index; CONFIDENTIAL classification; honest limitations; critical
  finding escalated in-engagement and recorded; nothing destructive/out of scope; environment left
  clean.

**Distinction:** the report would survive a real debrief with Vireo's board *and* its two engineers —
honest posture, no FUD, severities defensible by vector, a roadmap that fixes classes of weakness,
and a direct, evidenced answer to the CISO's question ("yes, an external foothold reaches your
customer data; here is exactly how, and here is what to fix first").

**Fail:** chain not meaningfully advanced; or completed but report missing required sections / jargon
exec summary / non-reproducible findings / no marker evidence; or safety boundary breached
(destructive, out-of-scope, or isolation not verified).

## Retest / debrief note (optional extension)

For a fuller assessment, have the student run a **debrief** (walk the pyramid: posture → priorities →
details) and produce a **retest** section against one "remediated" finding (reset the environment
with the vector removed, if provisioning supports a fixed variant) — recording status
(Remediated / Partially / Not / Risk accepted) with residual risk (16.3).
