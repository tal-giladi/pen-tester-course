# Lab 04 — Linux local privilege escalation

**Module:** 04. **Time:** ~2–3 h across 04.2/04.3. **Hardware:** any Docker host (minimal).
**Target:** one intentionally misconfigured Debian container (`ptlab04_target`) on an **internal
(no-egress)** network. **Foothold:** user `lab` / `Lab-Passw0rd!`. **Objective:** read
`/root/flag.txt` (root-only) — i.e. gain root.

<div class="callout legal">

LAB TARGET ONLY. Synthetic user, synthetic password, benign flag marker. The container has no
Internet route (verify with `./labs/lab check`). Never use these techniques outside authorized
targets.

</div>

## Run

```bash
./labs/lab up    lab-04-linux-privesc
./labs/lab check                          # confirm isolation before you start
# Foothold options:
ssh lab@localhost -p 2204                  # password: Lab-Passw0rd!  (ingress only)
#   or, if you prefer:
docker exec -it -u lab ptlab04_target bash
./labs/lab reset lab-04-linux-privesc      # restore clean state (undoes any tampering)
./labs/lab down  lab-04-linux-privesc
```

## What's planted

There are **multiple independent** privilege-escalation paths, so 04.2 and 04.3 can ask you to
find *different* ones. Do not read the lesson solutions first — enumerate, hypothesize, verify.

- A SUID binary that offers an exec primitive.
- A `sudo` NOPASSWD entry on an interactive program.
- A root cron job running a world-writable script (fires every minute).
- A Linux **capability** on a copied interpreter.
- A SUID helper that invokes another program by relative name (**PATH** matters).

Each has a real remediation and a detection story — you'll write both as part of the exercises
(see [04.2](../../lessons/module-04/lesson-02.md), [04.3](../../lessons/module-04/lesson-03.md)).

## Verify your work

```bash
py labs/lab-04-linux-privesc/verify.py     # checks the target still exposes each vector
```

`verify.py` is an *acceptance test for the lab itself* (that the vectors are present and the box is
isolated) — not a solution. The intended paths and remediations are instructor material in
`solutions/module-04.md`.

## Reset

`./labs/lab reset lab-04-linux-privesc` rebuilds the container from the image, undoing anything you
changed (e.g. an appended cron command). Always reset between attempts so the environment stays
deterministic.
