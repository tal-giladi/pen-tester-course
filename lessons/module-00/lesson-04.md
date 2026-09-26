# 00.4 — The lab &amp; safety architecture (build &amp; verify)

<div class="prereq">

**Prerequisites:** [00.1](lesson-01.md)–[00.3](lesson-03.md); Docker Desktop + WSL2 installed
(see [`labs/README.md`](../../labs/README.md) and [`TOOLS.md`](../../TOOLS.md)).
**Module:** M00 Foundations. **Difficulty:** 🟢 foundational — but this is your first hands-on lab.
**You will produce:** a running, verified, **Internet-isolated** lab and a habit of checking
isolation before every offensive session.

</div>

## Why this matters

You are about to spend the rest of the course attacking things. The one rule that keeps that legal
and safe is: **you only ever attack the intentionally vulnerable targets we ship, and they can't
reach the Internet.** This lesson builds that guarantee into your machine and gives you a
one-command check (`lab check`) to confirm it. If you internalize nothing else operationally from
M00, internalize *"check isolation before you attack."*

## Learning objectives

- Stand up and tear down a lab environment with the `lab` helper.
- Explain **how** Docker network isolation prevents a lab target from reaching the Internet, and
  verify it yourself rather than trusting a claim.
- Read a `docker-compose.yml` well enough to spot an isolation mistake.
- Adopt the pre-engagement isolation check as a reflex.

## Intuition

A vulnerable machine is only safe to practice on if a mistake stays contained. Two things can go
wrong: (1) your *attack* accidentally targets a real host on the Internet, or (2) a *vulnerable
target* gets compromised and is used to reach out. We defend against both by putting the targets on
a private network with **no route off your machine**. Docker makes this a one-line property
(`internal: true`); the rest is verifying it's actually true.

## The underlying technology: Docker networking &amp; isolation

When Docker Compose creates a network, by default it's a **bridge** with NAT to your host's
network — containers *can* reach the Internet. That's wrong for a target. The fix is a network
flag:

```yaml
networks:
  ptlab_targets:
    driver: bridge
    internal: true        # <-- no gateway to the outside is created; no egress
```

`internal: true` tells Docker **not to provision external connectivity** for that network — no
default route to your host's uplink. A container attached *only* to an internal network can talk to
its neighbors on that network and nothing else. That is the mechanism behind the whole safety
model. (VM labs achieve the same with **host-only/internal** virtual switches — see
[`labs/vm/README.md`](../../labs/vm/README.md).)

<div class="callout key">

**Why we verify instead of trust.** A single mistake — a target also attached to a normal bridge, a
published port, a stray `--network host` — silently reopens egress. So the lab ships an
**isolation check** that actively tries to reach the Internet *from inside a target* and fails the
whole lab if it succeeds. You run it before every session. A safety control you don't test isn't a
control.

</div>

## The `lab` helper

From the repo root:

```bash
./labs/lab up   lab-00-setup      # build & start this lab's containers
./labs/lab status                  # what's running and on which networks
./labs/lab check                   # SAFETY: prove targets can't reach the Internet
./labs/lab reset lab-00-setup      # back to clean state
./labs/lab down  lab-00-setup      # stop & remove
```

On Windows PowerShell: `./labs/lab.ps1 up lab-00-setup`, etc. Each subcommand is a thin wrapper over
`docker compose` in the lab's folder plus the isolation logic. Read the script — it's short, and a
tester should never run a "magic" script they haven't read.

## Practical lab

<div class="lab">

**Environment:** `labs/lab-00-setup`. **Time:** ~40 min. **Hardware:** any Docker host (minimal).
**Targets:** two tiny containers on an `internal: true` network + one on a normal network to
demonstrate the *difference*. **Isolation:** this lab's entire purpose is proving isolation works.

</div>

**Step 1 — bring it up and look.**

```bash
./labs/lab up lab-00-setup
./labs/lab status
```

You should see a `target` container on the internal network and (deliberately) one `leaky`
container on a normal bridge, so you can see the contrast.

**Step 2 — run the safety check.**

```bash
./labs/lab check
```

It attempts an outbound connection from *inside* the isolated target. Expected result: the target
**cannot** reach the Internet (check passes for the target), and the intentionally-`leaky`
container **can** (check flags it) — demonstrating exactly what a misconfiguration looks like. Read
the output; make sure you understand *which* container is which and *why*.

**Step 3 — see the mechanism yourself.** Open a shell in each and try to reach out:

```bash
docker compose -f labs/lab-00-setup/docker-compose.yml exec target   sh -c 'wget -T3 -qO- https://example.com || echo "BLOCKED (good: isolated target)"'
docker compose -f labs/lab-00-setup/docker-compose.yml exec leaky    sh -c 'wget -T3 -qO- https://example.com >/dev/null && echo "REACHED INTERNET (this is the bad config, shown on purpose)"'
```

**Step 4 — read the compose file.** Open `labs/lab-00-setup/docker-compose.yml` and find the one
line (`internal: true`) that makes `target` safe and note what's *missing* from `leaky`'s network.
This is the single most important line in the whole lab suite.

**Step 5 — reset and down.**

```bash
./labs/lab reset lab-00-setup
./labs/lab down  lab-00-setup
```

## Exercise

<div class="callout method">

**Situation.** You've inherited a colleague's lab compose file for a "vulnerable web target." You
must certify it safe to attack before your team uses it.

**Objective.** Determine whether the environment is properly isolated, prove your conclusion with
evidence, and fix it if it isn't.

**Starting information.** Use `labs/lab-00-setup/docker-compose.yml` as the file under review; the
`leaky` service represents the "inherited" mistake.

**Constraints.** You may only conclude "isolated" if you have *demonstrated* it from inside the
container, not merely read the file.

**Expected deliverables.**
1. A statement, per service, of whether it can reach the Internet, with the command + output that
   proves it (this is *evidence*, per the exercise standard).
2. The exact one-line change that makes the `leaky` service safe, and a re-run proving the fix.
3. A three-line "isolation acceptance check" you'd add to any lab review checklist.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
"Isolated" is a property of the <em>network</em> a container is attached to, not the container. A
container attached to <em>any</em> non-internal network has egress. Check every network a service
joins.
</details>

<details><summary>Hint 2 — where to look</summary>
Compare the <code>networks:</code> block of <code>target</code> vs <code>leaky</code>, and which
network each service lists under its own <code>networks:</code>. One word (<code>internal: true</code>)
and one attachment are the whole story.
</details>

<details><summary>Hint 3 — proving it</summary>
From inside: <code>wget</code>/<code>curl</code> to an external host with a short timeout, or
<code>getent hosts example.com</code> then a TCP connect. "No route" / timeout = isolated; a
response = egress.
</details>

## Check yourself

<div class="callout key">

1. What does `internal: true` actually change about the Docker network, in terms of routing?
2. A target container is on an internal network **and** has `ports: ["8080:80"]` published to your
   host. Can it reach the Internet? Can *you* reach it? Are those the same question?
3. Why does the lab ship a container that *can* reach the Internet on purpose?
4. Your teammate says "the compose file says `internal: true`, so it's fine, no need to check."
   Give the one-sentence professional rebuttal.
5. How would you achieve the same isolation guarantee for the Windows/AD **VM** lab?

</div>

Model answers in `solutions/module-00/`.

## References

- **Docker networking** — docs.docker.com/network (bridge networks; the `internal` option).
- **Docker Compose** file reference — the `networks` top-level key.
- **NIST SP 800-115** §5–6 — test environment isolation.
- [`labs/README.md`](../../labs/README.md) and [`labs/vm/README.md`](../../labs/vm/README.md) — this
  course's lab and safety architecture.

## What you should now be able to do

- Bring a lab up, verify its isolation, and tear it down — reflexively, before any attack.
- Explain and demonstrate *how* the isolation works, not just assert it.
- Audit a compose file for the isolation mistakes that reopen egress.
- Extend the isolation guarantee to VM-based labs.

## Progress checkpoint

```bash
py course.py complete 00.4
```

Module 00 complete. You have the ethics, the method, the modeling lens, and a safe place to work.
Next: [M01 — Networking &amp; protocols for testers](../module-01/lesson-01.md).
