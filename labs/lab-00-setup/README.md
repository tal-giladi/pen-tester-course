# Lab 00 — Setup &amp; isolation proof

**Module:** 00 (Foundations). **Time:** ~40 min. **Hardware:** any Docker host (minimal RAM/CPU).
**Targets:** `target` (isolated, `internal: true`) and `leaky` (normal bridge — a *deliberate* bad
example). **Isolation:** the point of this lab is to prove isolation works and to teach you to
detect when it doesn't.

## Goal

Verify that this course's safety model actually holds on *your* machine, and build the reflex of
checking isolation before any offensive session. You'll see, hands-on, the difference one line
(`internal: true`) makes.

## Files

- `docker-compose.yml` — one isolated target, one deliberately-leaky container, two networks.

## Run

```bash
../lab up    lab-00-setup     # from labs/ ; or ./labs/lab up lab-00-setup from repo root
../lab status
../lab check                  # SAFETY check: isolated target blocked, leaky flagged
../lab reset lab-00-setup
../lab down  lab-00-setup
```

(Windows PowerShell: `..\lab.ps1 up lab-00-setup`.)

## Expected result

- `target` **cannot** reach the Internet → the isolation check reports it safe.
- `leaky` **can** reach the Internet → the check flags it as a misconfiguration (on purpose).

## What to notice

- Isolation is a property of the **network**, not the container. `target` is safe only because the
  single network it joins is `internal: true`.
- `leaky` is identical except for which network it joins — that's the whole difference between a
  safe lab target and a dangerous one.
- Publishing a port (`ports:`) lets *you* reach a container from the host; it does **not** give the
  container Internet egress. Ingress and egress are different questions.

See [lesson 00.4](../../lessons/module-00/lesson-04.md) for the full walkthrough and exercise.
