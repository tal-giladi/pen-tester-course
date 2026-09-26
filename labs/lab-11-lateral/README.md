# Lab 11 — Lateral movement (credential reuse)

**Module:** 11. **Time:** ~60 min. **Hardware:** any Docker host. **Targets:** `host-a` (your
foothold) and `host-b` (holds the flag), on an isolated (no-egress) network. **Attack from:** the
`ws` workstation (`docker exec -it ptlab11_ws bash`).

<div class="callout legal">

LAB TARGETS ONLY. Synthetic accounts and a throwaway SSH key (clearly labeled — never reuse it).
Isolated network. This lab shows credential-reuse lateral movement on Linux; the Windows
pass-the-hash / pass-the-ticket exercises in [11.2](../../lessons/module-11/lesson-02.md) use the AD
VM lab ([lab-06-ad](../vm/README.md)). Verify isolation with `./labs/lab check`.

</div>

## Run

```bash
./labs/lab up   lab-11-lateral
./labs/lab check
docker exec -it ptlab11_ws bash        # foothold: ssh lab@host-a
py labs/lab-11-lateral/verify.py       # acceptance test (lab health, not a solution)
./labs/lab down lab-11-lateral
```

## The challenge

You have a foothold on `host-a` (`ssh lab@host-a` from `ws`). `host-b` runs SSH but you have no
`host-b` credentials — yet. Enumerate `host-a`: what credential material is lying around, and where
does it lead? Reuse what you find to move to `host-b` and read the flag.

The reuse mechanic (a "deploy key" on host-a that opens a service account on host-b) mirrors how
real environments leak: keys in home dirs, CI configs, backups, and shared service accounts. The
intended path and remediation (key hygiene, per-host credentials, least privilege) are instructor
material in `solutions/module-11.md`.

## Reset

`./labs/lab reset lab-11-lateral`.
