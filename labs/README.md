# The local penetration-testing lab

_Last reviewed: 2026-09._

A reproducible, **network-isolated**, resettable lab of intentionally vulnerable systems. You
practice every technique here — never against systems you don't own or aren't explicitly
authorized to test.

<div class="callout legal">

**Safety architecture — the whole point.** Lab targets live on **private Docker networks with no
default route to the Internet** (and VMs on host-only/internal networks). Credentials are
**synthetic** (`lab / Lab-Passw0rd!`), flags are benign markers (`LAB-FLAG-{uuid}`), and any
"exfiltration" points at a **local sink** container. You cannot accidentally attack the public
Internet from a correctly built lab. Before every offensive session, run the isolation check
(`lab check`). If it fails, stop.

</div>

## Requirements

<div class="hw">

**Minimum:** 4-core CPU, 16 GB RAM, 60 GB free disk, virtualization enabled in BIOS/UEFI.
**Comfortable (with the AD VM lab):** 8-core, 32 GB RAM, 120 GB SSD.
**Software:** Docker Desktop (or Engine + Compose v2) and WSL2 on Windows; for Windows/AD labs,
Hyper-V **or** VirtualBox. Git. Python 3.10+. See [`../TOOLS.md`](../TOOLS.md) for pinned versions.

Docker-only labs run on the minimum spec. The Windows/AD VM lab is the memory-hungry one; you can
progress through most of the course without it and build it when you reach M05/M06.

</div>

## Architecture

```text
                    ┌──────────────────────────────────────────────┐
                    │  Host (Windows + Docker Desktop + WSL2)        │
                    │                                                │
   attacker  ──────▶│  attacker workstation  (Kali container / WSL) │
                    │        │                                       │
                    │   ┌────┴───────── private networks ─────────┐  │
                    │   │  ptlab_ops     10.13.0.0/24 (attacker)  │  │
                    │   │  ptlab_dmz      10.13.10.0/24            │  │
                    │   │  ptlab_internal 10.13.20.0/24            │  │
                    │   │  ptlab_restricted 10.13.30.0/24          │  │
                    │   └──────────────────────────────────────────┘  │
                    │   sink container (fake exfil endpoint, logs)   │
                    │                                                │
                    │  VM lab (Hyper-V/VBox, host-only):             │
                    │    DC01 (AD) · WS01 · SRV01   192.168.56.0/24  │
                    └──────────────────────────────────────────────┘
```

- **Docker labs** cover Linux, web, API, exploitation, containers, cloud-sim, pivoting.
- **VM labs** cover Windows and Active Directory — Docker cannot honestly model these, so we don't
  pretend it can (see [`vm/README.md`](vm/README.md)).
- The **pivoting lab** (`lab-12-pivot`) uses the segmented networks above so a compromised DMZ host
  is the *only* route to the internal and restricted ranges.

## The `lab` helper

Each lab is self-contained (`labs/lab-NN-slug/` with its own `docker-compose.yml`, README, attack
script, verify step, and reset). The `lab` helper wraps the common lifecycle:

```bash
./labs/lab up   lab-04-linux-privesc     # build & start a lab's targets
./labs/lab status                         # what's running, on which networks
./labs/lab check                          # SAFETY: verify targets have no Internet route
./labs/lab reset lab-04-linux-privesc     # restore to a clean state
./labs/lab down lab-04-linux-privesc      # stop & remove
```

On Windows PowerShell use `./labs/lab.ps1 <cmd>`. Under the hood these are thin wrappers over
`docker compose` in the lab's directory, plus the isolation check.

<div class="callout warn">

The helper scripts and per-lab environments are added module-by-module (see
[`../TODO_FOR_TAL.md`](../TODO_FOR_TAL.md)). This page is the architecture and safety contract they
all conform to; a lab that violates the isolation contract is a bug.

</div>

## Standard workflow

```text
clone → (once) build attacker box & VM lab → ./labs/lab up lab-NN → ./labs/lab check →
read the lesson → do the lab → do the exercise → collect evidence → ./labs/lab reset → record progress
```

## Reset &amp; teardown

Docker labs reset by tearing down and recreating (`lab reset`), which restores seed data and
clears the sink log. VM labs reset from a **clean snapshot** taken right after provisioning — the
VM build docs walk through taking it. Never "fix" a broken target by hand mid-exercise; reset it,
so the environment stays deterministic for the next run.

## Troubleshooting

- **`lab check` fails / a target can reach the Internet.** Stop. A network was created without
  `internal: true` or a container was attached to the default bridge. Fix the compose file before
  continuing.
- **Port already in use.** Another lab is up; `./labs/lab down` it first, or change the published
  port (only management ports are ever published to the host).
- **AD VM won't start / slow.** Check virtualization is enabled and RAM allocation; see
  [`vm/README.md`](vm/README.md).
- **Docker Desktop + WSL DNS weirdness.** The attacker box uses the lab resolver for `*.lab`
  names; the lab README for each environment lists the resolver IP.
