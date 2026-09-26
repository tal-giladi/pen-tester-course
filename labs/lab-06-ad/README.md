# Lab 06 — Active Directory forest (VM)

**Module:** 06 (also used by M10 credentials and M11 lateral movement). **Type:** VM lab — Docker
cannot model AD (see [`../vm/README.md`](../vm/README.md)). **Domain:** `lab.local`. **Foothold:**
a low-privileged domain user. **Objective (per exercise):** enumerate the forest as a graph and
find an attack path to a high-privileged account — the path is **not** given.

<div class="callout legal">

LAB TARGET ONLY. A small forest of Windows **evaluation** VMs on a **host-only, no-egress** network,
with synthetic accounts (`lab.local\lowpriv`, service accounts like `svc_sql`, all `Lab-Passw0rd!`
-class synthetic secrets) and benign flags. Verify isolation from inside a VM before attacking.
Never run AD attacks against a domain you don't own or aren't authorized to test.

</div>

<div class="hw">

**Needs:** Hyper-V or VirtualBox 7.1+; ~8-core / 32 GB RAM recommended (16 GB tight), ~120 GB SSD.
Three VMs: **DC01** (domain controller), **SRV01** (member server: SQL/file/web), **WS01**
(domain-joined workstation). Host-only network `192.168.56.0/24`, attacker (Kali) at `.100`.

</div>

## Topology

```text
host-only 192.168.56.0/24 (NO Internet route)
  DC01   .10   Windows Server, DC for lab.local
  SRV01  .20   member server (service accounts w/ SPNs → Kerberoasting; a share)
  WS01   .30   Win10/11 workstation, domain-joined (a cached cred / local admin reuse)
  attacker .100  Kali (Impacket, NetExec, BloodHound CE, Rubeus, hashcat)
```

## Build

Two supported routes (full detail in [`../vm/README.md`](../vm/README.md)):

1. **Automated (recommended): Vagrant + PowerShell/DSC.** Use the provisioning notes in
   [`provision-notes.md`](provision-notes.md) — it promotes DC01, joins SRV01/WS01, and plants the
   deliberate misconfigurations (a Kerberoastable service account, an AS-REP-roastable account, an
   ACL edge such as `GenericAll`, and a credential-reuse path) reproducibly. The well-known
   community builder **GOAD** (Game of Active Directory) is documented as a drop-in fallback that
   produces an equivalent vulnerable forest.
2. **Manual.** Install each OS from eval media, set static IPs on the host-only network, promote
   the DC, join the members, then apply the misconfigurations from `provision-notes.md`.

After provisioning and **before** attacking, snapshot every VM as `clean`. Reset = restore it.

## What's planted (independent, for graph-reasoning)

A Kerberoastable SPN account, an AS-REP-roastable account, at least one abusable ACL edge
(e.g. `GenericAll`/`WriteDACL`), and a credential-reuse/local-admin path — so the route from
low-priv user to Domain Admin is discoverable but **not** unique or signposted (plan.md Scenario C).
Intended paths + detection are instructor material in `solutions/module-06.md` and the
Assessment A5 solution.

## Work the labs

- **M06** exercises: enumerate (BloodHound/LDAP), Kerberoast/AS-REP, abuse an ACL edge, chain to DA.
- **M10** (credentials): crack the roasted hashes offline; secrets discovery.
- **M11** (lateral movement): pass-the-hash / pass-the-ticket between SRV01/WS01/DC01.

## Reset

Restore the `clean` snapshot on each VM. Never hand-repair a target mid-exercise.
