# VM labs — Windows &amp; Active Directory

_Last reviewed: 2026-09._

Docker cannot honestly model Windows internals or an Active Directory domain (Kerberos, LSASS,
SMB/NTLM, the registry, real services). This course uses **virtual machines** for M05 (Windows
privesc) and M06 (Active Directory) rather than faking them. This page is the build + safety guide;
the module lessons drive the actual exercises.

<div class="callout legal">

**Isolation for VMs.** Attach every lab VM to a **host-only** or **internal** virtual network with
**no NAT/bridged adapter**, so the VMs can talk to each other and your attacker box but not the
Internet — the same guarantee `internal: true` gives Docker. Verify from *inside* a VM (ping/curl an
external IP → must fail) before attacking, exactly as in [lesson 00.4](../../lessons/module-00/lesson-04.md).
Use **licensed evaluation media** only, and take a clean snapshot right after provisioning so you
can reset.

</div>

## Requirements

<div class="hw">

**AD lab:** 8-core CPU, 32 GB RAM recommended (16 GB minimum, tight), ~120 GB SSD.
**Hypervisor:** Hyper-V (Windows Pro/Enterprise) **or** VirtualBox 7.1+ (any host). VMware
Workstation Player works too. Enable CPU virtualization in BIOS/UEFI.

</div>

## Media (evaluation, licensed)

- **Windows Server** evaluation ISO (for the Domain Controller) — Microsoft Evaluation Center.
- **Windows 10/11 Enterprise** evaluation ISO (for the workstation/member server) — same source.
- These are time-limited eval builds intended for exactly this kind of lab. Do not use pirated
  media; do not use your production licenses.

## Topology (M06 target)

```text
host-only network 192.168.56.0/24  (NO Internet route)
  DC01   192.168.56.10   Windows Server, domain controller for lab.local
  SRV01  192.168.56.20   member server (SQL / file share / web)
  WS01   192.168.56.30   Windows 10/11 domain-joined workstation
  attacker (Kali)        192.168.56.100  (also on your Docker ptlab_ops if you bridge them)
```

Synthetic domain `lab.local`; synthetic accounts and deliberate misconfigurations are provisioned
by scripts shipped with M06 (`labs/lab-06-ad/provision/`). Credentials are synthetic
(`lab\svc_sql : Lab-Passw0rd!` etc.) and documented per-exercise.

## Build options

1. **Manual** (most control, most time): install each OS from eval media, set static IPs on the
   host-only network, promote DC01, join SRV01/WS01, then run the provisioning scripts. Fully
   walked through in M06.
2. **Automated** (recommended): the M06 lab ships **Vagrant + PowerShell/DSC**-style provisioning
   (or the well-known community AD-lab builders as a documented fallback) to stand the forest up
   reproducibly. Exact, pinned instructions live in `labs/lab-06-ad/` when that module lands.

## Snapshots &amp; reset

After provisioning and *before* any attack, snapshot every VM ("clean"). Reset = restore that
snapshot. Never hand-repair a target mid-exercise — restore it, so the environment stays
deterministic.

## Status

The Windows/AD VM build automation and provisioning scripts are delivered with modules **M05**
and **M06** (see [`../../TODO_FOR_TAL.md`](../../TODO_FOR_TAL.md)). This page is the architecture and
safety contract they conform to.
