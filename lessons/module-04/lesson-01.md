# 04.1 — Linux for testers: architecture, users, permissions, processes & the shell

<div class="prereq">

**Prerequisites:** [M00 Foundations](../module-00/lesson-01.md) (ethics, methodology, threat
modeling), [M01 Networking](../module-01/lesson-01.md), [M02 Recon](../module-02/lesson-01.md),
[M03 Scanning & enumeration](../module-03/lesson-01.md). You should be comfortable reading command
output and thinking in trust boundaries ([00.3](../module-00/lesson-03.md)).
**Module:** M04 Linux for testers & privilege escalation. **Difficulty:** 🟡 intermediate.
**M04 assumes** you already have a **low-privileged shell on a lab host** (as the `lab` user) —
delivered by an earlier foothold. This module is about what you do *after* you land.
**You will produce:** a "privesc surface" inventory for a described host — the facts, grouped by
category, each paired with a hypothesis and the reasoning behind it.

</div>

## Why this matters

You have a shell as an unprivileged user. That shell can read a little, write less, and run almost
nothing that matters. Everything valuable on the host — the root-readable secret, the ability to
install persistence, the credentials in `/etc/shadow`, the pivot to the next machine — sits behind
the boundary between your UID and UID 0. Local privilege escalation is the craft of crossing that
boundary, and you cannot do it by memorizing exploits. You do it by **understanding how Linux
decides who is allowed to do what**, then finding the place where that decision was configured
wrong.

This lesson is the map. Before you hunt SUID binaries or sudo rules (04.2) or kernel bugs (04.3),
you need a working mental model of Linux privilege: where it lives, how it is inherited, and where
an administrator's convenience becomes your foothold. Get the model right and privesc stops being a
checklist and becomes reasoning.

## Learning objectives

By the end you can:

- Explain the kernel/userland split, the UID/GID model, and what "root" actually *is* to the kernel.
- Read Linux file permissions and the special bits (SUID, SGID, sticky) and predict their effect.
- Describe how a process inherits identity and privilege from its parent, and why that matters.
- Locate where interesting information lives on a host (`/etc/passwd`, `/etc/shadow`, config files,
  history, `/proc`) and reason about what each readable or writable path *implies*.
- Build a structured **privesc surface inventory** from enumeration output — facts plus hypotheses.

## Intuition

Every action on a Linux system is a request made by a *process* to the *kernel*: open this file,
run this program, send this signal. The kernel is the only thing that can touch hardware, memory,
and other processes' resources, and it answers every request by checking the requesting process's
**identity** against the **permissions** on the thing being requested. Privilege escalation is
simply arranging for a request you want — "read `/etc/shadow`", "run a shell as root" — to be made
by a process whose identity the kernel will accept. You rarely attack the kernel's check itself;
you find a process that already has the identity you want and convince it to act for you. That is
the confused-deputy pattern from 00.3, living at the operating-system level.

## The underlying technology

### Kernel vs userland

The **kernel** runs in a privileged CPU mode with full access to memory and hardware. Everything
you interact with — your shell, `ls`, a web server — is **userland**, running in an unprivileged
mode. Userland cannot touch hardware or another process directly; it must ask the kernel through
**system calls** (`open`, `execve`, `setuid`, …). The boundary between the two is the most
important trust boundary on the machine. Two consequences for a tester:

- A **kernel exploit** (04.3) crosses this boundary directly: a bug in syscall handling lets
  userland code run with kernel authority. Powerful, but fragile and risky.
- Everything else — SUID, sudo, cron, capabilities — is the kernel *correctly* enforcing rules
  that an administrator configured. Those are misconfigurations, not kernel bugs, and they are the
  overwhelming majority of real-world privesc.

### Users, UIDs, and what root really is

To the kernel, a user is a number: the **UID**. Names like `lab` or `root` are a userland
convenience mapped in `/etc/passwd`. **Root is simply UID 0.** There is nothing magic about the
name; the kernel grants sweeping authority to processes whose effective UID is 0. Anything that can
make a UID-0 process do your bidding — or change your own UID to 0 — is game over.

A process actually carries several UIDs: the **real** UID (who launched it), the **effective** UID
(what the kernel checks for permission), and the **saved** UID (a stashed value it can switch back
to). This distinction is the entire mechanism behind SUID binaries (04.2): a program can run with
an effective UID different from the user who started it.

Groups work the same way via **GIDs**: your primary group plus supplementary groups. Group
membership is a privilege vector in its own right — `docker`, `lxd`, `disk`, `sudo`, `adm` are all
groups whose members can, directly or indirectly, become root (04.3).

### File permissions and the special bits

Every file has an owner, a group, and three permission triads — owner / group / other — each with
read (`r`/4), write (`w`/2), execute (`x`/1). `ls -l` shows them:

```text
-rwsr-xr-x 1 root root 68208 Mar 14  2024 /usr/bin/passwd
```

Read that left to right: it is a file (`-`), owner (root) has `rws`, group has `r-x`, other has
`r-x`. The **`s`** where owner-execute (`x`) should be is the **SUID bit**. It means: when any user
executes this file, the resulting process runs with the *file owner's* effective UID — here, root.
That is why `passwd`, which must edit root-owned `/etc/shadow`, works when you run it. The special
bits, conceptually:

- **SUID (4000)** — execute as the file's **owner**. `rws` in the owner triad.
- **SGID (2000)** — execute as the file's **group** (on a directory: new files inherit the group).
  `rws`/`rwS` in the group triad.
- **Sticky (1000)** — on a directory (e.g. `/tmp`), only a file's owner may delete it. Defensive,
  not an escalation vector by itself.

An uppercase `S` (or `T`) means the special bit is set but the underlying execute bit is *not* —
worth noticing, because a SUID file that is not executable by you is not directly abusable.

### Processes and privilege inheritance

New processes are created by `fork` (a copy of the parent) followed by `execve` (replace the image
with a new program). The child **inherits the parent's UIDs, GIDs, environment, open file
descriptors, and working directory** unless something explicitly changes them. This inheritance is
why a shell you spawn is *yours* — and why a shell spawned by a root-owned process is *root's*.
Almost every privesc primitive reduces to: "make a process that is already privileged spawn a shell
(or write a file) that inherits its privilege instead of dropping it."

### Services and systemd

Long-running programs — web servers, databases, SSH — are **services** (daemons), started at boot
and supervised. Modern Linux uses **systemd** (`systemctl status`, unit files under
`/etc/systemd/system/` and `/lib/systemd/system/`). Services frequently run **as root** so they can
bind low ports or write system paths. A service running as root that you can influence — a writable
unit file, a writable binary it launches, an exploitable network-facing bug (04.3) — is a direct
path to root. Note *which* services run and *as whom*.

### The shell and environment

Your shell resolves a bare command like `tar` by searching each directory in **`PATH`**, left to
right, for the first match. It also carries **environment variables** that programs read for
configuration (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `IFS`, `PYTHONPATH`, …). Both are attacker-relevant:
if a privileged program runs a command by its bare name, and you control an earlier `PATH` entry,
*you* choose what runs (PATH hijacking, 04.2). If a privileged program honors an environment
variable you control, you may inject code (LD_PRELOAD via sudo `env_keep`, 04.2).

## Why the weakness exists

None of this is a bug in Linux. The model is sound; the weaknesses are **configuration under
convenience pressure**. An admin gives a script a SUID bit so operators don't need root. A sudo rule
gets a `NOPASSWD` so a cron job runs unattended. A cron script lives in a world-writable directory
because that was easy. A capability is granted instead of full root because someone read that
capabilities are "safer." Each choice trades a little security for a little convenience, and the
accumulation is your attack surface. This maps to **CWE-250 (Execution with Unnecessary
Privileges)** and **CWE-269 (Improper Privilege Management)** — the two weakness classes behind
nearly every finding in this module.

## How a tester recognizes it

You are looking for **the gap between who runs something and who can influence it**. Concretely:
files that execute with more privilege than the user who can run them (SUID/SGID, capabilities);
rules that grant you privileged actions (sudo); privileged processes that consume things you can
change (cron scripts, PATH lookups, env vars, config files); and information that is readable or
writable when it should not be (`/etc/shadow`, private keys, credentials in configs or history).
The recurring shape: **a privileged actor + an input you control.**

## Manual investigation

Enumerate deliberately, and understand each command before you run it. This is the core loop;
04.2 and 04.3 exploit what it finds.

```bash
# Who am I, and what groups do I hold? Groups are privileges.
id
# → uid=1000(lab) gid=1000(lab) groups=1000(lab),999(docker)

# What is the system, kernel, and distro? (feeds kernel-exploit triage in 04.3)
uname -a; cat /etc/os-release

# Who else has a login, and who has UID 0? Any non-root account with uid=0 is root.
cat /etc/passwd
awk -F: '($3==0){print $1}' /etc/passwd

# Is /etc/shadow readable? It should NOT be. If it is, that's the whole game.
ls -l /etc/shadow; cat /etc/shadow 2>/dev/null

# What runs, and as whom? Root-owned processes are targets.
ps aux
# What listens locally (services bound to 127.0.0.1 are often unauthenticated)?
ss -tulpn

# My environment and PATH — do writable/relative entries appear?
echo "$PATH"; env

# Where do people leave secrets: histories, configs, keys.
ls -la ~; cat ~/.bash_history 2>/dev/null
find / -name "*.conf" -o -name "id_rsa" -o -name "*.env" 2>/dev/null
```

<div class="callout method">

**The three questions per finding.** For every fact enumeration surfaces, ask: (1) *Who is the
privileged actor?* (2) *What input into it do I control?* (3) *What primitive does abusing it give
me — a shell, a file read, a file write?* If you cannot answer all three, it is not yet a path; it
is a lead. Recording leads with their missing piece is how you avoid rabbit holes.

</div>

## Tooling — what it does, key options, limits, verify by hand

Automated enumerators exist and you will meet them properly in 04.3. The most common is
**LinPEAS** (a large shell script that runs hundreds of checks and colour-codes findings by
likelihood) and **pspy** (watches process and cron activity without root, revealing scheduled jobs
you can't see in a crontab). Two rules from day one:

- **They automate the checklist you just learned — they do not replace understanding it.** LinPEAS
  flags a SUID binary; *you* decide whether it is abusable and why. A red highlight is a lead, not a
  finding.
- **Limits:** they are noisy (loud on disk and in logs — a detection concern), they miss
  context-specific paths, and they occasionally flag false positives. On a real engagement, dropping
  a 500 KB script may violate your RoE's stealth or "no new tools on host" clauses. Prefer manual
  enumeration first; reach for the tool to catch what you missed, then **verify every flag by hand.**

## Demonstration (LAB ONLY): building the surface inventory

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Every command below is run on the `lab-04-linux-privesc` container
on the isolated lab network, as the synthetic `lab` user. Enumerating a system you are not
authorized to test — even read-only `id`/`ps` — can exceed authorization on a real engagement. Stay
in the lab; obey your RoE everywhere else.

</div>

Landing on the lab host as `lab`, a first pass produces facts like these (illustrative — yours will
differ):

```text
$ id
uid=1000(lab) gid=1000(lab) groups=1000(lab)
$ sudo -l
User lab may run the following commands on lab-04:
    (root) NOPASSWD: /usr/bin/find
$ find / -perm -4000 -type f 2>/dev/null
/usr/bin/passwd
/usr/bin/find
/usr/bin/base64
$ getcap -r / 2>/dev/null
/usr/bin/python3.11 cap_setuid+ep
```

You do not exploit anything yet. You **inventory**: each fact becomes a row with a hypothesis and
the three-questions reasoning. `sudo find` as root → find can execute commands (`-exec`), so this is
likely a root shell (04.2). `python3.11` with `cap_setuid` → Python can call `setuid(0)`, likely a
root shell (04.2). Base64 SUID → a root file-*read* primitive, not a shell. That structured list —
not a shell yet — is this lesson's deliverable.

## Verification

An inventory is verified when each hypothesis names a concrete, testable primitive and you have
noted how you would confirm it non-destructively. "SUID `find` → run `find . -exec id \;` and expect
`uid=0`" is verifiable. "find looks interesting" is not. You confirm the *reasoning* now; you
confirm the *exploit* in 04.2/04.3.

## Impact

A correct surface inventory is the difference between a two-minute escalation and a two-hour one. In
report terms, the inventory becomes your evidence trail: it shows the client exactly which
misconfigurations existed and lets you tie each later exploit back to a specific, fixable cause.

## Remediation

<div class="callout defend">

**Reduce the surface, don't just patch exploits.** The durable fixes are structural: run services
and scripts as the **least privilege** that works (not root); strip unnecessary SUID/SGID bits and
capabilities; keep `/etc/shadow` unreadable (mode `640 root:shadow` or stricter); keep secrets out
of world-readable configs, histories, and process arguments; and keep the system patched. Every
specific vector in 04.2/04.3 has a specific fix, but they all trace back to CWE-250 — *don't grant
privilege you don't need.*

</div>

## Detection / blue-team view

<div class="callout defend">

Mass enumeration is noisy and detectable. Defenders can spot the recon that precedes escalation:
auditd rules logging reads of `/etc/shadow` and execution of `find`, `id`, `getcap`, and `sudo -l`
in quick succession; large scripts (LinPEAS) touching hundreds of files; a login shell doing
filesystem-wide `find` sweeps. A baseline of "what normal users run" makes an enumeration burst
stand out. This maps to reconnaissance activity feeding **MITRE ATT&CK T1548 (Abuse Elevation
Control Mechanism)** downstream.

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-04-linux-privesc` — an intentionally misconfigured Linux container on
the isolated lab network (built separately; see the lab README). **Access:** a low-privileged
`lab` shell. **Goal here:** *enumerate only* — do not escalate yet. **Time:** ~40 min. **Isolation:**
private Docker network, no Internet route; the `LAB-FLAG-{uuid}` is readable only by root — you are
mapping the paths to it, not taking it (that's 04.2/04.3).

</div>

Run the manual investigation loop above against the lab host. For each category — identity/groups,
SUID/SGID, sudo, capabilities, cron, services, PATH, readable secrets — record what you find. Do
**not** exploit anything; produce the inventory.

## Exercise

<div class="callout method">

**Situation.** You have just landed a `lab` shell on a Linux host during an authorized internal
engagement. Your time box for local escalation on this host is 90 minutes, and the client's RoE
forbids installing new tools without approval.

**Objective.** Produce a **privesc surface inventory**: a structured document of the escalation-
relevant facts on this host, each paired with a hypothesis and reasoning — *not* an exploit.

**Starting information.** Only your `lab` shell and the manual-investigation commands from this
lesson. Assume LinPEAS is unavailable (RoE).

**Constraints.** Lab target only. Enumeration only — no escalation, no writes to system paths, no
destructive commands. Everything must be justifiable to the client.

**Expected deliverables.**
1. An inventory grouped by category (identity/groups, SUID/SGID, sudo, capabilities, cron, services,
   PATH, readable/writable sensitive files).
2. For each interesting fact: the **three-questions** analysis (privileged actor / controlled input
   / primitive) and a one-line hypothesis.
3. A **ranked** short list of the top 3 paths you would pursue first, with the reasoning for the
   ranking (likelihood × effort × reliability).

</div>

<details><summary>Hint 1 — conceptual direction</summary>
You are looking for "privileged actor + input you control." Which of your findings has both halves?
A SUID binary you can't execute, or a sudo rule for a binary that can't spawn a shell, is only half.
</details>

<details><summary>Hint 2 — technique family</summary>
Group these into: run-as-someone-else (SUID/SGID, capabilities), granted-actions (sudo), and
privileged-consumers (cron scripts, PATH lookups, service-launched binaries you can write).
</details>

<details><summary>Hint 3 — where to look</summary>
<code>id</code>, <code>sudo -l</code>, <code>find / -perm -4000</code>, <code>getcap -r /</code>,
<code>ls -l /etc/shadow</code>, crontab and <code>/etc/cron*</code>, <code>ps aux</code> for root
processes, and <code>echo $PATH</code> for writable/relative entries.
</details>

<details><summary>Hint 4 — specific investigation direction</summary>
Rank by reliability first: a sudo/SUID/capability path that deterministically yields a shell beats a
cron path you must wait for, which beats a kernel exploit that might crash the box. Effort and noise
break ties.
</details>

## Check yourself

<div class="callout key">

1. `ls -l` shows `-rwsr-xr-x root root /usr/bin/foo`. What does the `s` mean, and whose privilege
   does `foo` run with when *you* execute it?
2. You find `-rwSr--r-- root root /usr/bin/bar`. Why is the uppercase `S` important, and is this
   directly abusable by you?
3. Your `id` shows `groups=...,999(docker)`. Why is that potentially as good as being root, even
   though your UID is 1000?
4. A root-owned cron job runs `/opt/backup/run.sh` every 5 minutes. Which of the three questions
   can you not yet answer, and what one command would answer it?
5. Why is manual enumeration usually preferable to dropping LinPEAS first — give both a technical
   and an engagement (RoE/detection) reason.

</div>

Model answers are in `solutions/module-04.md` (instructor material — reason through them first).

## References

- **`credentials(7)`, `execve(2)`, `setuid(2)`** — Linux man pages: real/effective/saved UIDs and
  privilege inheritance across `execve`.
- **`chmod(1)` / `inode(7)`** — the permission model and the SUID/SGID/sticky bits.
- **`systemd.service(5)` / `systemd.unit(5)`** — how services are defined and run.
- **HackTricks** — "Linux Privilege Escalation" (conceptual checklist; treat as a map, verify each
  item by hand).
- **MITRE ATT&CK T1548** — Abuse Elevation Control Mechanism (the tactic this module lives in).
- **CWE-250** Execution with Unnecessary Privileges; **CWE-269** Improper Privilege Management.
- **NIST SP 800-123** — Guide to General Server Security (least-privilege baseline).

## What you should now be able to do

- Explain the kernel/userland boundary and what "root" (UID 0) means to the kernel.
- Read Linux permissions and the SUID/SGID/sticky bits and predict their effect.
- Trace how a process inherits identity and privilege from its parent.
- Enumerate a host methodically and know where secrets and privileged actors live.
- Turn raw enumeration output into a structured, ranked privesc surface inventory with hypotheses.

## Progress checkpoint

```bash
py course.py complete 04.1
```
</content>
</invoke>
