# Lab 12 — Pivoting through a segmented network

**Module:** 12. **Time:** ~2 h. **Hardware:** any Docker host. **Topology:** attacker → DMZ →
internal → restricted, each pair on its own **internal (no-egress)** network. **Objective:** from
a DMZ foothold, pivot to the **restricted** segment and read its flag — a segment your attacker box
cannot reach directly.

```text
  ws ──net_edge── dmz ──net_internal── internal ──net_restricted── restricted (/flag)
 (you)          pivot#1               pivot#2                    (unreachable directly)
```

<div class="callout legal">

LAB TARGETS ONLY, all networks isolated (no Internet route). Foothold creds are synthetic
(`lab` / `Lab-Passw0rd!`, plus a throwaway SSH key baked into the workstation — clearly labeled,
never reuse it anywhere). Pivoting reaches *in-scope internal targets*; on a real engagement stay
within the authorized scope. Verify isolation with `./labs/lab check`.

</div>

## Run

```bash
./labs/lab up   lab-12-pivot
./labs/lab check
docker exec -it ptlab12_ws bash        # attacker workstation (edge only)
#   ssh, proxychains4, nmap, curl are installed; key is at ~/.ssh/id_ed25519
py labs/lab-12-pivot/verify.py         # acceptance test (proves the pivot chain works)
./labs/lab down lab-12-pivot
```

## The challenge

- `restricted` is **not reachable** from `ws` (prove it: `curl --max-time 4 http://restricted/flag`
  fails — no route).
- `dmz` is your foothold (`ssh lab@dmz`). It is **dual-homed** — enumerate its interfaces
  (`ip -4 addr`) to discover the `net_internal` segment and the `internal` host.
- `internal` is a second pivot, dual-homed onto `net_restricted` where the flag lives.

Reach the flag by pivoting. Two ways (both taught in [12.1](../../lessons/module-12/lesson-01.md)/
[12.2](../../lessons/module-12/lesson-02.md)):

```bash
# A) SSH ProxyJump chain (simplest to verify)
ssh -J lab@dmz lab@internal 'curl -s http://restricted/flag'

# B) Dynamic SOCKS + proxychains (the general technique)
ssh -D 1080 lab@dmz              # SOCKS proxy through the first pivot
#   then chain a second hop to reach net_restricted via internal, and proxychains your tools
```

Discover the topology yourself; the intended route and remediation (network segmentation that
actually isolates) are instructor material in `solutions/module-12.md`.

## Reset

`./labs/lab reset lab-12-pivot`.
