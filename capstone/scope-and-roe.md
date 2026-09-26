# Capstone — client brief, scope & rules of engagement

> Everything in this document is **synthetic** and describes only the shipped, network-isolated
> capstone lab environment. It is written in the form of a real pre-engagement package (00.1, 16.1)
> so you practise reading and working from the documents an actual client hands you. It authorizes
> testing of the lab targets **only**.

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** The "authorization" below is a teaching artifact. It authorizes you
to test **only** the isolated capstone lab targets, which have **no route to the Internet**. The
domain, hosts, accounts, data, and `LAB-FLAG-…` markers are all synthetic. Nothing here authorizes
testing any real system; the single thing separating you from a criminal is authorization tied to a
real, in-scope asset (00.1). Verify isolation (`./labs/lab check`, and an external ping/curl from
inside each VM must fail) before any offensive action. If isolation fails, stop.

</div>

---

## 0. Client description (the brief)

**Vireo Logistics Ltd.** is a mid-sized third-party logistics and freight-forwarding company
(~350 staff, three sites). They run a public **customer portal** where clients track shipments and
download proof-of-delivery documents, a set of **internal applications and file shares** on a
corporate Windows/Active Directory network, and a small **restricted segment** that holds
operational and finance data (customer contracts, personal data of consignees, and payment
references). Vireo has grown by acquisition and has never had a full penetration test.

Their new Head of Security engaged you after a near-miss: a support engineer received a phishing
email that "looked internal." Leadership's question, in their words:

> *"If an attacker got even a small foothold from the outside, how far could they actually get — and
> could they reach our customers' data and our contracts? We think our sensitive systems are
> segmented off. Prove or disprove that, and tell us what to fix first."*

You are engaged for a **grey-box** external-to-internal assessment with a single low-privilege
starting position, mirroring the phishing near-miss.

---

## 1. Parties & authority

- **Tester:** *(you)* — lead penetration tester.
- **Client signatory:** J. Okafor, Head of Security, Vireo Logistics Ltd. (authority to authorize
  testing of all in-scope assets confirmed).
- **Engagement:** "Vireo Logistics — Capstone External/Internal Penetration Test."
- **Testing window:** the duration of your capstone attempt (treat as a 5-business-day engagement).

---

## 2. Scope — IN

You are authorized to test **only** these assets (all synthetic, all isolated):

| Asset | Address / identifier | Notes |
|---|---|---|
| Customer portal (web + API) | `http://portal.vireo.lab` (DMZ, `10.13.10.0/24`) | Internet-facing in the fiction; your external entry point. |
| DMZ segment | `10.13.10.0/24` | Perimeter hosts reachable from the portal tier. |
| Internal corporate segment | `10.13.20.0/24` | Internal Linux/Windows hosts and services. |
| Restricted segment | `10.13.30.0/24` | Operational/finance data ("crown jewels"). |
| Corporate AD domain | `lab.local` — DC01/SRV01/WS01 on host-only `192.168.56.0/24` | Windows domain; VM lab. |
| Attacker workstation | `10.13.0.0/24` (`ptlab_ops`) / `192.168.56.100` | Your box. |

---

## 3. Scope — OUT (exclusions)

- Anything **not** on the ranges/domains listed in §2 — explicitly including any real host, any
  public IP, and the Internet at large.
- **Denial-of-service** of any kind (volumetric, resource-exhaustion, or crashing services to prove
  a point) — forbidden.
- **Destructive exploitation** — no deleting/altering data you cannot restore, no dropping database
  tables, no disabling the domain controller, no changing credentials you cannot reset.
- **Third-party / provider planes** — none are in scope; treat any egress attempt as out of scope
  and a finding, not an action.
- **Social engineering and phishing** — the initial foothold is *assumed*; do not model live phishing
  of humans.

---

## 4. Assumptions

- The initial low-privilege position (see §8) is treated as *already obtained* — you start from it,
  as though a phishing near-miss succeeded.
- The lab environments compose into one client network for the purposes of the engagement and
  report (see §9, *Environment*).
- The environment is reset to a clean state between attempts; do not hand-repair targets.

---

## 5. Test type

**Grey-box, external → internal.** You begin outside with one low-privilege credential and public
reachability to the portal only. Everything past the perimeter you must earn.

---

## 6. Techniques — allowed / forbidden

- **Allowed:** recon, enumeration, web/API exploitation, credential recovery and *offline* cracking,
  privilege escalation, lateral movement, pivoting/tunnelling **within in-scope segments**,
  Active Directory attack-path abuse, and evidence collection.
- **Forbidden:** DoS; destructive exploitation; online password brute-force that would lock out
  accounts (prefer targeted/offline techniques); leaving persistent implants, tunnels, or backdoors
  behind (tear everything down at closeout); attacking anything out of scope even if reachable.

---

## 7. Timing, rate limits & data handling

- **Timing window:** the full engagement window (no off-hours restriction in the lab).
- **Rate limits:** be deliberate; avoid noisy mass-scanning that would constitute abuse on a real
  network — you are also being assessed on tradecraft.
- **Data handling:** access the **minimum** data needed to demonstrate each finding. Capture the
  `LAB-FLAG-…` marker as proof; do not copy data beyond evidence. The only permitted "exfil" target
  is the local sink container. Redact anything resembling real PII in the report (there is none —
  practise the habit).

---

## 8. Starting information (what you are "given")

- **One low-privilege customer-portal account:** `cust_dmitri@clients.vireo.lab` /
  `Lab-Passw0rd!` — an ordinary customer login on `portal.vireo.lab`. It confers **no** internal or
  domain access.
- **Public reachability** to `http://portal.vireo.lab` only. You are told nothing about internal
  hostnames, services, domain accounts, or the topology beyond the DMZ.
- **No** domain credentials, **no** source code, **no** endpoint list, **no** network map past the
  perimeter, and **no** description of the intended attack path. Discovering all of that is the
  engagement.

<div class="callout key">

That is the entire package. As in a real grey-box engagement, the value you deliver is turning this
thin starting position into a defensible, evidenced account of how far a determined attacker gets —
and what Vireo must fix first.

</div>

---

## 9. Environment (how to stand it up)

Bring up the capstone segments with the lab helper (PowerShell: `./labs/lab.ps1 …`):

```bash
./labs/lab up capstone        # composes the shipped lab targets into the segmented network above
./labs/lab check              # SAFETY: confirm every target has no Internet route — must pass
./labs/lab status             # what is running, on which networks
# ... conduct the engagement from your attacker box (ptlab_ops / 192.168.56.100) ...
./labs/lab reset capstone     # clean state between attempts
./labs/lab down  capstone     # teardown at closeout
```

The AD portion uses the **VM** forest (`lab-06-ad`) — build it per
[`labs/vm/README.md`](../labs/vm/README.md) before you begin, and snapshot it clean. Which host
runs what, and where each weakness lives, is deliberately **not** documented here — enumeration is
your job. *(Instructors: the segment-to-lab mapping and provisioning are in
[`solutions/capstone/walkthrough.md`](../solutions/capstone/walkthrough.md).)*

---

## 10. Stop conditions & escalation

- **Stop and notify** (record it, then continue per the fiction) if you find evidence of a *prior*
  real compromise, real third-party data, or you reach the edge of scope — in a real engagement
  these are "stop and call" events (00.1). In the lab, record them in your log as decision points.
- **Escalation contact (fiction):** J. Okafor, Head of Security — critical findings are reported the
  day they are confirmed, via the RoE escalation path, not held for the report (16.3).

---

## 11. Deliverables & secure delivery

A complete professional report per
[`solutions/report-template/report-outline.md`](../solutions/report-template/report-outline.md),
classified **CONFIDENTIAL**, plus the evidence index. See
[`capstone/README.md`](README.md) for the full deliverable specification and grading rubric.

---

## 12. Authorization statement

*(Teaching artifact — authorizes the isolated lab targets in §2 only.)*

> Vireo Logistics Ltd. authorizes the named tester to conduct security testing of the assets
> enumerated in §2, during the engagement window, under the rules of engagement above. This
> authorization does not extend to any asset not listed, and confers no authority over any real
> system. — *J. Okafor, Head of Security (synthetic signatory).*
