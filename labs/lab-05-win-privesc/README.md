# Lab 05 — Windows local privilege escalation (VM)

**Module:** 05. **Type:** VM (Docker cannot model Windows internals — see
[`../vm/README.md`](../vm/README.md)). **Foothold:** `lab\lowpriv` / `Lab-Passw0rd!`.
**Objective:** escalate to `SYSTEM`/local admin and read `C:\flag.txt` (admin-only).

<div class="callout legal">

LAB TARGET ONLY. A single Windows VM on a **host-only, no-egress** virtual network, built from
**licensed evaluation media**, with synthetic accounts and a benign flag. Verify isolation from
*inside* the VM (an external ping/curl must fail) before you start — same guarantee as
[lesson 00.4](../../lessons/module-00/lesson-04.md), enforced by the virtual network.

</div>

<div class="hw">

**Needs:** a Type-2/Type-1 hypervisor (Hyper-V or VirtualBox 7.1+), ~4 GB RAM and ~40 GB disk for
one Windows 10/11 **Enterprise evaluation** VM. This lab does not need the full AD forest (that is
M06); a standalone Windows VM is enough.

</div>

## Build (once)

1. Create a Windows 10/11 Enterprise **evaluation** VM (Microsoft Evaluation Center media). Attach
   it to a **host-only** network only (no NAT/bridged adapter).
2. Copy `provision.ps1` into the VM and run it **from an elevated PowerShell** once — it creates the
   low-priv account, plants the misconfigurations, and drops the flag. (Read it first; it is short
   and commented. It only touches this throwaway VM.)
3. **Snapshot** the VM as `clean` while logged out. Reset = restore this snapshot.
4. Log in as `lab\lowpriv` / `Lab-Passw0rd!` to begin (this is your "foothold").

```powershell
# inside the VM, elevated, once:
Set-ExecutionPolicy -Scope Process Bypass -Force
./provision.ps1
```

## What's planted (independent paths)

`provision.ps1` sets up several classic, distinct vectors so 05.3 can ask for different ones — a
service with a **weak/misconfigured ACL**, an **unquoted service path** with a writable directory,
`AlwaysInstallElevated`, and an **autorun/DLL-hijack** opportunity. Each has a real remediation and
a detection story you'll write as part of the exercise. The intended paths are instructor material
in `solutions/module-05.md` — enumerate and reason first.

## Verify your work

Success = a shell running as `NT AUTHORITY\SYSTEM` (or a local admin) and the contents of
`C:\flag.txt`. Confirm your privilege with `whoami /groups` and `whoami /priv`.

## Reset

Restore the `clean` snapshot. Never hand-repair a broken target — restore, so the environment
stays deterministic.

<div class="callout warn">

Full step-by-step provisioning (`provision.ps1`) and an optional Vagrant automation are delivered
with this module's build-out; the safety/architecture contract above is fixed. If you reach this
lab before `provision.ps1` ships, you can still study 05.1–05.3 conceptually and practice
enumeration on any Windows VM you own — but do the escalation only on an isolated throwaway VM.

</div>
