# 04.3 — Local privilege escalation II: services, kernel, NFS, and a systematic methodology

<div class="prereq">

**Prerequisites:** [04.1](lesson-01.md) (architecture, inventory) and [04.2](lesson-02.md) (the
classic vectors and the "privileged actor + controlled input" frame). [M00](../module-00/lesson-01.md)
authorization applies throughout.
**Module:** M04. **Difficulty:** 🟡 intermediate (kernel section 🔴).
**M04 assumes** a low-privileged `lab` shell on a lab host.
**You will produce:** a *different* escalation path than the one you used in 04.2, documented as a
report-ready finding, plus a reusable escalation methodology you can apply to any host.

</div>

## Why this matters

04.2 covered the vectors you meet most often. This lesson covers the rest of the serious ones —
software running as root, kernel exploits, NFS `no_root_squash`, writable `/etc/passwd`, and the
`docker` group — and then does the more important thing: it gives you a **repeatable methodology**
so you are never dependent on a checklist. On a real engagement you will face hosts with configs no
tutorial covered. What carries you is not a memorized list but a disciplined loop — enumerate,
hypothesize, verify, exploit, clean up, document — plus the judgment to know which paths are safe
and which (kernel exploits especially) can crash the client's production box. That judgment is what
separates a professional from someone running exploits they don't understand.

## Learning objectives

- Escalate via software/services running as root (writable service binaries and unit files).
- Explain when a kernel exploit is appropriate, and the **real risk** (instability, crashes) that
  makes it a last resort under RoE.
- Exploit NFS `no_root_squash`, a writable `/etc/passwd`, and `docker`-group membership — and
  explain the mechanism of each.
- Apply a systematic, repeatable local-privesc methodology to an unfamiliar host.
- Use LinPEAS/pspy as accelerators for that methodology, understanding their limits.

## Intuition

Everything in 04.2 was "a privileged program plus an input you control." This lesson widens *what
counts as the program and the input*: the program can be a network service or systemd unit; the
input can be a file you write over NFS as root, a line you add to `/etc/passwd`, a container you
launch through the Docker socket, or — at the extreme — the kernel itself. The kernel case is
different in kind: you are no longer abusing a misconfiguration but exploiting a *bug*, and bugs in
kernel code are unstable. So the intuition for this lesson is layered: **prefer misconfiguration
over memory corruption**, because misconfigurations are deterministic and safe, and kernel exploits
are neither.

## The underlying technology & the vectors

### Software / services running as root

Daemons often run as root (04.1). Two escalation shapes:

- **Writable service binary or script.** A root service launches `/opt/app/server`, and that file —
  or a library it loads, or a config it execs — is writable by `lab`. Replace it; on restart (or a
  restart you can trigger), your code runs as root. Same logic as a writable cron script, but the
  trigger is a service restart rather than a schedule.
- **Writable systemd unit.** If `/etc/systemd/system/foo.service` (or a unit directory) is writable
  by you, edit its `ExecStart=` to run your payload, then `systemctl daemon-reload && systemctl
  restart foo` if you can, or wait for a boot/restart:

```ini
# LAB ONLY — ExecStart replaced with a payload that runs as the unit's User (root).
[Service]
ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rb; chmod +s /tmp/rb'
```

- **Locally-exposed service with a known flaw.** A service bound to `127.0.0.1` (invisible
  externally, found via `ss -tulpn`) running as root — an old Redis, a database, an admin
  socket — may have an authentication or RCE weakness that yields root code execution. Recognize it
  from the version banner; treat exploitation like any service exploit (mechanism first).

### Kernel exploits — power, and real risk

The kernel runs as the ultimate authority (04.1). A bug in syscall handling, a driver, or a
subsystem (e.g. historically Dirty COW CVE-2016-5195, Dirty Pipe CVE-2022-0847, various
`nf_tables`/`io_uring`/OverlayFS local flaws) can let userland code execute with kernel privilege —
instant root regardless of any misconfiguration. You triage candidates from `uname -r` and the
distro, cross-referenced to the CVE and a *matching, understood* exploit.

<div class="callout warn">

**Kernel exploits are a last resort.** A memory-corruption exploit that doesn't precisely match the
kernel build can **panic the machine** — you crash the client's server, cause an outage, and destroy
trust (and violate most RoEs' "no destructive/DoS" clause). Rules: prefer every misconfiguration
path first; never run a kernel exploit you haven't read and understood; confirm the exact kernel
version and build; and get **explicit client sign-off** before running one on anything resembling
production. "It gave me root but took the box down" is a failed engagement.

</div>

### NFS `no_root_squash`

NFS normally **squashes** root: a client mounting an export and acting as root is mapped to the
unprivileged `nobody` on the server, so a remote root can't write server-root files. The
`no_root_squash` export option **disables** that — a client root is treated as server root on that
share. If you have (or can get) root on *another* machine (even a VM/container you control) and the
target exports a directory with `no_root_squash`, you mount it, write a **SUID-root binary** into it
as root, then execute that binary back on the target as `lab`:

```bash
# On a box where you are root; target exports /srv with no_root_squash (see `showmount -e target`).
mount -t nfs target:/srv /mnt
cp /bin/bash /mnt/rootbash && chmod 4755 /mnt/rootbash   # SUID root, written as root
# Back on the target as lab:
/srv/rootbash -p        # SUID-root bash → uid=0
```

It works because the SUID bit and root ownership are honored on the target's filesystem, and
`no_root_squash` let you *create* a root-owned SUID file remotely. Check exports in `/etc/exports`
and via `showmount -e`.

### Writable `/etc/passwd`

`/etc/passwd` maps usernames to UIDs (04.1) and historically held password hashes in its second
field; if that field is set, it still takes precedence for some configs. If `/etc/passwd` is
writable by `lab`, add a root-equivalent account with a known password:

```bash
# LAB ONLY. openssl generates a crypt hash; the appended user has uid=0 → root.
openssl passwd -1 -salt xyz Lab-Passw0rd!         # → $1$xyz$....
echo 'hacker:$1$xyz$....:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker    # enter the password → uid=0(root)
```

It works because UID 0 in `/etc/passwd` *is* root (04.1: root is just UID 0), and a password field
in `/etc/passwd` is honored, so you created a second root account.

### `docker` group → root

Membership in the **`docker`** group (seen in `id`) lets you talk to the Docker daemon, which runs
as root. You can start a container that mounts the host filesystem and gives you root over it:

```bash
# LAB ONLY. Mount host / into the container; as container-root you now own host files.
docker run -v /:/host --rm -it alpine chroot /host sh
# or drop a SUID bash onto the host:
docker run -v /:/host --rm alpine sh -c 'cp /host/bin/bash /host/tmp/rb; chmod +s /host/tmp/rb'
/tmp/rb -p    # root on the host
```

It works because the Docker daemon is root and honors your volume mount — the `docker` group is
effectively root-equivalent by design. The same reasoning applies to the `lxd`/`lxc` group and, via
raw device access, the `disk` group. (Container internals are M13; here it's just another
privileged-actor path.)

## Why the weakness exists

The same root causes as 04.2 — least-privilege failures (CWE-250/CWE-269) — plus, for kernels,
genuine software vulnerabilities (**CWE-190/CWE-416/CWE-787**-class memory bugs) exploited for
escalation (**MITRE ATT&CK T1068 — Exploitation for Privilege Escalation**). NFS `no_root_squash`
and writable `/etc/passwd` are trust misplaced across a boundary (server trusting client root;
system trusting a writable identity file). `docker`-group-as-root is a design decision documented by
Docker itself: the group is a root-equivalent grant.

## How a tester recognizes it

`ss -tulpn` and `ps aux` for root services and their (writable?) binaries/units; `showmount -e` and
`/etc/exports` (and `mount`) for NFS `no_root_squash`; `ls -l /etc/passwd` for writability; `id` for
`docker`/`lxd`/`disk` groups; `uname -r` + distro for kernel-exploit candidates (only after
misconfigurations are exhausted).

## Tooling — what it does, key options, limits, verify by hand

- **LinPEAS** — runs the whole checklist (SUID, sudo, cron, caps, services, writable files, kernel
  version, group membership) and colour-codes by likelihood (bright red/yellow = probable). **Key
  use:** run it *after* your manual pass to catch what you missed. **Limits:** noisy (loud in logs
  and on disk — detection risk, possible RoE violation), false positives, and it can *suggest* kernel
  exploits it cannot vet for stability. A highlight is a lead — **verify every one by hand.**
- **pspy** — monitors process creation and cron execution *without root*, exposing scheduled jobs and
  short-lived root processes you can't see otherwise. **Key use:** finding cron/service activity and
  the exact command lines (which reveal PATH-called binaries, writable scripts). **Limits:** only
  shows activity while running; you must watch long enough to catch a scheduled job.
- **`linux-exploit-suggester`** — maps `uname` to candidate kernel CVEs. **Limits:** suggestions
  only; it doesn't confirm the exploit matches the build, and running an unverified one risks a
  panic. Triage, then read the exploit.

<div class="callout method">

**The systematic methodology — a repeatable loop.** This is the real deliverable of M04; internalize
it and you don't need a host-specific checklist.

1. **Enumerate** — walk the categories (04.1): identity/groups, SUID/SGID, sudo, capabilities, cron,
   services, PATH, writable files, NFS, kernel. Manual first; LinPEAS/pspy to backfill.
2. **Hypothesize** — for each finding, the three questions (privileged actor / controlled input /
   primitive). Discard leads missing a piece.
3. **Prioritize** — rank by *reliability first* (deterministic misconfig > waiting on cron > kernel
   exploit), then effort and noise. Never lead with a kernel exploit.
4. **Verify** — confirm the hypothesis with a safe, non-destructive check before committing.
5. **Exploit** — execute the chosen path; confirm with `id`/`whoami` and the flag.
6. **Clean up** — remove dropped artifacts (SUID copies, added users, edited units), note anything
   irreversible, restore state where the RoE requires.
7. **Document** — what / where / reproduction / evidence / impact / remediation / detection. This is
   the finding, and it feeds the M16 report.

Loop, don't tunnel: if a path stalls, return to step 2 with the next-ranked hypothesis.

</div>

## Exploitation / demonstration (LAB ONLY)

<div class="callout attack">

**Technique — writable systemd unit → root.** Enumeration shows `ls -l
/etc/systemd/system/lab-metrics.service` is writable by `lab`, and `sudo -l` allows
`systemctl restart lab-metrics`. Edit `ExecStart=` to drop a SUID bash, reload, restart:

```bash
# LAB ONLY
cat >> /etc/systemd/system/lab-metrics.service <<'EOF'
[Service]
ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rb; chmod +s /tmp/rb'
EOF
sudo systemctl daemon-reload && sudo systemctl restart lab-metrics
/tmp/rb -p          # → uid=0(root)
```

Why: the unit runs as root; you controlled its `ExecStart`; the payload runs with the unit's
privilege and drops a SUID-root shell you then invoke with `-p`. Same inheritance logic as 04.2,
triggered by a service restart.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** All commands here run against `lab-04-linux-privesc` on the isolated
network, as the synthetic `lab` user, for the benign `LAB-FLAG-{uuid}`. The kernel and `docker`
techniques especially can damage a real host — never run them outside the lab, and never on a real
engagement without explicit written authorization and (for kernel exploits) client sign-off (M00).

</div>

## Verification

`id` → `uid=0(root)`; `whoami` → `root`; `cat /root/flag.txt` → `LAB-FLAG-{uuid}`. For NFS, the
`/srv/rootbash -p` shell returns `uid=0`; for `/etc/passwd`, `su hacker` yields a root shell; for
docker, `chroot /host` or the SUID drop yields root on the host. No evidence, no finding.

## Impact

Identical ceiling to 04.2 — full root compromise: total data access, persistence, credential
harvesting for lateral movement (M11), log tampering, and pivoting. The NFS and docker paths often
*also* imply compromise of adjacent systems (the NFS server, other containers), widening blast
radius — call that out in the report.

## Remediation

<div class="callout defend">

- **Services/units:** service binaries, libraries, configs, and unit files must be **root-owned and
  not writable** by others; run services as least-privilege users, not root, wherever possible.
- **Kernel:** patch promptly; the only real defense against local kernel exploits is an up-to-date
  kernel (plus reduced local access).
- **NFS:** never export with `no_root_squash`; use `root_squash` (default), restrict exports to
  specific hosts, and mount with `nosuid`.
- **`/etc/passwd`/`/etc/shadow`:** must be `root`-owned, `644`/`640`, never group/other-writable;
  monitor for changes.
- **docker/lxd/disk groups:** treat membership as **granting root** — restrict it to admins; do not
  add service or low-priv users. Consider rootless Docker (M13).

</div>

## Detection / blue-team view

<div class="callout defend">

- **Service/unit tampering:** file-integrity monitoring on `/etc/systemd/system/`, unit binaries,
  and service configs; alert on non-root writes and on `daemon-reload`/`restart` by non-admins.
- **Kernel exploitation:** kernel oops/panic logs, unexpected privilege transitions, EDR flagging
  known exploit patterns; a sudden root shell with no corresponding sudo/login event.
- **NFS:** server logs of a client writing SUID files; auditd on new SUID files appearing.
- **`/etc/passwd`:** FIM alert on any modification; a new UID-0 account is a high-severity signal.
- **docker:** daemon/audit logs of containers mounting `/` or the host filesystem; process
  telemetry showing `chroot /host`.

Kernel exploitation is **MITRE ATT&CK T1068 (Exploitation for Privilege Escalation)**; the
misconfiguration paths remain **T1548** and (for scheduled triggers) **T1053**. The blue-team
throughline for the whole module: *watch the transitions to UID 0 and the writes to the files that
grant them.*

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-04-linux-privesc` (built separately) — intentionally misconfigured Linux
container on the isolated network, with multiple independent root paths (SUID/sudo/cron/caps/PATH
from 04.2, plus a writable service/unit and one of NFS/`/etc/passwd`/docker here). **Access:** the
`lab` shell. **Targets:** the lab host only; `LAB-FLAG-{uuid}` in `/root` proves root. **Time:** ~90
min. **Isolation:** private Docker network, no Internet route; reset between attempts per the lab
README. **Note:** if the lab includes a kernel-exploit path, treat it as last-resort practice and
snapshot/reset first — kernel exploits can crash the container.

</div>

Apply the seven-step methodology end to end. Find a path you did **not** use in 04.2, verify it, then
produce the full finding (what/where/repro/evidence/impact/remediation/detection) and clean up your
artifacts.

## Exercise

<div class="callout method">

**Situation.** Same authorized engagement, same `lab` host. You have already reported one escalation
path (from 04.2). The client asks whether the host has *more than one* way to root — a common,
important question, because fixing one misconfiguration doesn't help if three others remain.

**Objective.** Find a **different** root path than the one you used in 04.2, unaided by hints from
that lesson, and document it as a report-ready finding.

**Starting information.** Your `lab` shell and your 04.1 inventory. You may use LinPEAS/pspy only if
you can justify it under the RoE, and you must verify anything they flag by hand.

**Constraints.** Lab target only. If you consider a kernel exploit, you must (a) confirm the exact
kernel version, (b) state the crash risk, and (c) note that on a real engagement you'd get client
sign-off first — and prefer any misconfiguration path over it. Clean up all artifacts.

**Expected deliverables** (the finding, per the M16 rubric):
1. **What** — the vulnerability, precisely (e.g. "writable systemd unit `lab-metrics.service`").
2. **Where** — asset + exact location (path, service name, export, group).
3. **Reproduction** — steps another tester can follow.
4. **Evidence** — `id`/`whoami` = root and the `LAB-FLAG-{uuid}`.
5. **Impact** — business consequence and blast radius (does it reach other hosts?).
6. **Remediation** — specific and actionable.
7. **Detection** — telemetry that catches it, mapped to ATT&CK (T1548/T1053/T1068).

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Widen "the privileged program": besides SUID/sudo/cron, a root <em>service</em>, an NFS export, the
<code>/etc/passwd</code> file, and the <code>docker</code> group are all privileged actors. Which
one shows up in your inventory that you haven't used?
</details>

<details><summary>Hint 2 — technique family</summary>
Check <code>id</code> for dangerous groups, <code>ss -tulpn</code>/<code>ps aux</code> for root
services and their writable files/units, <code>showmount -e</code> and <code>/etc/exports</code> for
NFS, <code>ls -l /etc/passwd</code> for writability.
</details>

<details><summary>Hint 3 — where to look</summary>
Writable unit under <code>/etc/systemd/system/</code>? Then <code>ExecStart=</code> + restart. NFS
<code>no_root_squash</code>? Then write a SUID-root binary from a box you control. <code>docker</code>
group? Then mount the host <code>/</code>. Writable <code>/etc/passwd</code>? Then add a UID-0 user.
</details>

<details><summary>Hint 4 — specific investigation direction</summary>
Rank by reliability and safety: a writable unit or a docker/NFS/passwd misconfig is deterministic;
a kernel exploit is a last resort that can crash the box. If you must go kernel, confirm
<code>uname -r</code> against the exact CVE and read the exploit before running it.
</details>

## Check yourself

<div class="callout key">

1. Why is a kernel exploit usually the *last* thing you try, even when a suggester tool lists one as
   "probable"? Give the engagement consequence, not just "it might fail."
2. Explain, mechanically, why `no_root_squash` lets you drop a SUID-root binary onto a target you
   only have a `lab` shell on.
3. You are in the `docker` group but your UID is 1000 and you have no sudo. Why is this already root-
   equivalent, and what does the mount `-v /:/host` accomplish?
4. A writable `/etc/passwd` and a writable `/etc/systemd/system/x.service` both lead to root.
   Which is faster/quieter, and which leaves a more obvious detection artifact?
5. In the seven-step methodology, what does "clean up" require for the NFS path, the `/etc/passwd`
   path, and the writable-unit path respectively?

</div>

Model answers are in `solutions/module-04.md`.

## References

- **`exports(5)` / `nfs(5)`** — `root_squash` vs `no_root_squash`, `nosuid`; `showmount(8)`.
- **`systemd.service(5)` / `systemctl(1)`** — unit files, `ExecStart`, `daemon-reload`.
- **`passwd(5)` / `shadow(5)`** — the password-file format and the UID-0 = root rule.
- **Docker docs** — "the `docker` group grants root-equivalent privileges" (Docker daemon security).
- **CVE-2016-5195 (Dirty COW), CVE-2022-0847 (Dirty Pipe)** — canonical local kernel-privesc
  examples and their write-ups (study the *mechanism* and the *stability caveats*).
- **`linux-exploit-suggester`**, **LinPEAS**, **pspy** — tool docs (accelerators, not oracles).
- **HackTricks** — Linux privesc (NFS, docker group, services, kernel) — conceptual; verify by hand.
- **MITRE ATT&CK** — **T1068** Exploitation for Privilege Escalation; **T1548**; **T1053**.
- **CWE-250 / CWE-269** (privilege management); **CWE-416 / CWE-787** (memory bugs behind kernel
  exploits).

## What you should now be able to do

- Escalate via root services/units, NFS `no_root_squash`, writable `/etc/passwd`, and the `docker`
  group — explaining the mechanism of each.
- Judge when a kernel exploit is appropriate and articulate its real (crash/outage) risk.
- Apply a repeatable seven-step escalation methodology to an unfamiliar host.
- Use LinPEAS/pspy as accelerators within that methodology, with their limits in mind.
- Produce a complete, report-ready privesc finding with remediation and ATT&CK-mapped detection.

## Progress checkpoint

```bash
py course.py complete 04.3
```
</content>
