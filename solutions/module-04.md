# Instructor / solutions — Module 04

> **Instructor material.** Not linked from `_sidebar.md`. Do the exercises before reading.

These answers assume the `lab-04-linux-privesc` container as specified: a low-priv `lab` user, a
deliberate mix of SUID/SGID, sudo, cron, PATH, and capability misconfigs (04.2) plus a writable
service/unit and one of NFS `no_root_squash` / writable `/etc/passwd` / `docker`-group (04.3), and a
`LAB-FLAG-{uuid}` readable only by root in `/root/flag.txt`. Exact binary names/paths will vary with
the built lab; grade on **reasoning and mechanism**, not on matching a specific command.

---

## 04.1 — Architecture & the privesc surface inventory

**Exercise (surface inventory).** A strong submission is a *structured, categorized* inventory where
every interesting fact carries the three-questions analysis and a hypothesis — and, crucially, **does
not escalate**. Expected categories and the kind of reasoning that earns full marks:

| Category | Example finding | Three-questions / hypothesis |
|---|---|---|
| Identity/groups | `id` shows `docker` (or `lxd`) group | actor = docker daemon (root); input = container spec; primitive = host root (04.3) — high value |
| SUID/SGID | `find / -perm -4000` lists `find`, `base64` | `find -exec` = root shell; `base64` = root file-read only (not a shell) |
| sudo | `sudo -l`: `NOPASSWD: less` | actor = less as root; input = `!sh`; primitive = root shell |
| capabilities | `getcap`: `python3 cap_setuid+ep` | interpreter can `setuid(0)` → root shell |
| cron | root job runs `/opt/*/run.sh` | need to check writability (missing piece) before it's a path |
| services | root service, writable unit/binary | replace binary/unit → root on restart |
| PATH | writable/relative entry, or SUID calls bare command | hijack the looked-up command |
| readable secrets | `/etc/shadow` readable, keys, `.env` | offline crack / direct creds |

Grading: (a) categorized, not a flat dump; (b) each fact has actor/input/primitive; (c) leads with a
missing piece (e.g. cron writability unknown) are flagged as leads, not paths; (d) **no exploitation
performed**; (e) a ranked top-3 justified by **reliability × effort × noise**. A common good ranking:
sudo/SUID/capability shell (deterministic) > writable cron/service (wait for trigger) > kernel
(risky). Docking points: dumping LinPEAS output as "the inventory"; listing SUID binaries with no
reasoning about which offer a primitive; escalating when told to enumerate only.

**Check-yourself.**
1. The `s` is the **SUID bit**: `foo` runs with the **file owner's** effective UID. Owner is root, so
   when *you* run it, it runs as root (effective UID 0), regardless of your UID 1000.
2. Uppercase `S` = SUID set but the owner **execute bit is off** — the file is not executable, so the
   SUID is inert for direct abuse. Not directly abusable by you as-is (you can't run it); note it but
   deprioritize.
3. The `docker` group can talk to the root-owned Docker daemon and start a container mounting the
   host filesystem → root over the host. It's root-equivalent by design even at UID 1000 (04.3).
4. You can't answer **"what input do I control?"** — you don't yet know if the script/dir is
   writable. One command: `ls -la /opt/backup/run.sh` (and its directory). If writable by `lab`, it's
   a path; if root-owned/unwritable, it's not.
5. **Technical:** manual enumeration teaches you *why* each finding matters and avoids false
   positives you'd have to verify anyway; you understand the host. **Engagement:** LinPEAS is loud
   (hundreds of file touches → detection), may violate a "no new tools on host" RoE clause, and its
   red highlights are leads, not proof. Manual first, tool to backfill, verify by hand.

---

## 04.2 — SUID/SGID, sudo, cron, PATH, capabilities

**Exercise (one justified, verified path + fix + detection).** A full-credit finding names the
vector, explains the **mechanism** (not just the command), shows `id=uid=0` and the flag, and gives
**both** remediation and detection mapped to ATT&CK. Illustrative model answers for the likely lab
paths:

- **SUID `find`:** `find . -exec /bin/sh -p \; -quit`. Mechanism: `find` is SUID-root so runs with
  eUID 0; `-exec` runs a command inheriting that; `-p` stops the shell resetting eUID→rUID. Fix:
  `chmod u-s /usr/bin/find`; don't SUID command-capable binaries. Detect: auditd execve of a shell
  child of `find`; new SUID file. ATT&CK T1548.001.
- **sudo `less`:** `sudo less /file` then `!/bin/sh`. Mechanism: less runs as root via sudo; `!cmd`
  spawns a subshell inheriting eUID 0. Fix: remove the rule / use a non-interactive viewer; never
  grant interactive pagers via sudo. Detect: `auth.log` sudo of `less`; shell child of `less`. T1548.003.
- **sudo `env_keep += LD_PRELOAD`:** compile a constructor `.so`, `sudo LD_PRELOAD=/tmp/x.so <cmd>`.
  Mechanism: sudo preserves `LD_PRELOAD`; the linker loads your `.so` into the root process before
  `main`; the constructor runs as root. Fix: remove `LD_PRELOAD`/`LD_LIBRARY_PATH` from `env_keep`,
  avoid `SETENV`. Detect: `LD_PRELOAD` present in a sudo'd process environment. T1548.003.
- **capability `python3 cap_setuid+ep`:** `python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'`.
  Mechanism: the capability lets the process call `setuid(0)` without SUID; an interpreter runs
  arbitrary code, so it's fully controllable. Fix: `setcap -r /usr/bin/python3`; never cap an
  interpreter. Detect: root shell parented by python holding a capability. T1548.
- **writable cron script:** append a SUID-bash drop; wait a tick; `/tmp/rb -p`. Fix: root-own +
  unwritable script/dir. Detect: FIM on cron scripts; new SUID file. T1053.
- **cron wildcard (`tar *`):** plant `--checkpoint=1` and `--checkpoint-action=exec=...` files. Fix:
  use explicit file lists or `find`, never a bare `*`; root-own the dir. Detect: tar with
  `--checkpoint-action` in process telemetry. T1053.
- **PATH hijack:** drop a malicious command earlier in PATH that a SUID/sudo/cron program calls by
  bare name. Fix: privileged programs must use absolute paths + clean PATH (`secure_path`). Detect:
  odd PATH in a privileged process. T1548 / CWE-426.

Docking: pasting a command with no mechanism; "got root" with no `id` evidence; **omitting
remediation or detection** (both are non-negotiable — a finding missing either is incomplete);
destructive actions beyond what the escalation needs; not noting cleanup of a dropped SUID binary.

**Check-yourself.**
1. `less` has a **command/shell primitive** (`!cmd`, and it can spawn `$SHELL`); `cat` has none — it
   only streams bytes. Abusability = "does the privileged binary offer a general primitive (exec/
   read/write)?" `cat` gives you a root file-*read*, not a shell; `less` gives a shell.
2. `-p` (privileged mode). Without it, `bash`/`dash` **reset the effective UID to the real UID** on
   startup (a deliberate safety behavior), dropping the SUID gain; `-p` preserves the elevated eUID,
   so the shell stays root.
3. `LD_PRELOAD` tells the dynamic linker to load your shared object into *any* dynamically-linked
   program before its own code. Even a "safe" allowed command is a dynamically-linked binary; sudo
   runs it **as root**; your `.so`'s constructor executes inside that root process before `main`. The
   danger is the preserved env var controlling code loading, independent of which command is allowed.
4. **Wildcard/argument injection.** The shell expands `*` to the filenames before `tar` sees them, so
   files you *name* like `--checkpoint-action=exec=sh shell.sh` become tar *options*; `tar` can't
   distinguish an intended filename from an injected option, and `--checkpoint-action=exec=` runs your
   command as root. You never touched the cron script — only the directory it globs.
5. An interpreter runs arbitrary code, so a `cap_setuid` on perl/python/ruby means you can call
   `setuid(0)` yourself and then exec a shell — exactly the power SUID-root would give, just delivered
   through the capability instead of the file mode bit.

---

## 04.3 — Services, kernel, NFS, methodology

**Exercise (a *different* path than 04.2, report-ready).** Full credit requires a vector **not** used
in 04.2, the seven-part finding, and cleanup. Model mechanisms:

- **Writable systemd unit:** edit `ExecStart=` to drop SUID bash; `daemon-reload` + `restart` (if
  sudo-allowed) or wait for restart; `/tmp/rb -p`. Mechanism: unit runs as root, you control
  `ExecStart`, payload inherits root. Fix: root-own + unwritable unit files; least-priv `User=`.
  Detect: FIM on `/etc/systemd/system/`, non-admin `daemon-reload`/`restart`. T1548.
- **Writable service binary:** replace `/opt/app/server`; trigger/await restart. Fix: root-own +
  unwritable binaries/libs/configs. Detect: FIM on service binaries; unexpected restart.
- **NFS `no_root_squash`:** from a box you root, `mount -t nfs target:/srv /mnt`, `cp /bin/bash
  /mnt/rb; chmod 4755 /mnt/rb`, then on target `/srv/rb -p`. Mechanism: the export doesn't squash
  client root, so you create a **root-owned SUID** file the target honors. Fix: `root_squash`,
  restrict export hosts, mount `nosuid`. Detect: server logs of client SUID writes; new SUID files.
  T1548.001.
- **Writable `/etc/passwd`:** append a UID-0 user with a known hash (`openssl passwd -1`), `su`.
  Mechanism: UID 0 in passwd **is** root; a set password field is honored → second root account. Fix:
  `644 root:root`, monitor changes. Detect: **FIM alert on any `/etc/passwd` change; new UID-0
  account = high severity.** T1548.
- **`docker` group:** `docker run -v /:/host --rm -it alpine chroot /host sh` (or drop SUID bash onto
  the host). Mechanism: daemon is root and honors your mount → host root. Fix: treat `docker`/`lxd`/
  `disk` membership as root; remove from low-priv users; consider rootless Docker. Detect: container
  mounting `/` or host FS; `chroot /host` in telemetry. T1548.
- **Kernel exploit (last resort):** only if misconfigs exhausted; confirm exact `uname -r`, read the
  exploit, state crash risk, note client sign-off needed on real systems, snapshot/reset the lab
  first. T1068.

Grading: (a) genuinely *different* vector from their 04.2 submission; (b) the seven parts present;
(c) impact addresses **blast radius** (NFS/docker often reach adjacent systems); (d) remediation AND
detection with ATT&CK IDs; (e) cleanup noted (see check-yourself Q5); (f) if kernel chosen, the
stability caveat and preference-for-misconfig reasoning are explicit — a student who reaches for a
kernel exploit while a deterministic misconfig sits unused loses points on methodology.

**Check-yourself.**
1. A kernel memory-corruption exploit that doesn't exactly match the build can **panic/crash the
   host → outage**, which violates the RoE's no-DoS/no-destructive clause and destroys client trust —
   a failed engagement even if you'd have gotten root. Deterministic misconfigs carry none of that
   risk, so they come first; "probable" from a suggester is not "verified against this build."
2. NFS normally squashes client root to `nobody`, so a remote root can't write server-root files.
   `no_root_squash` disables that, mapping client root → server root on the share. So from a box you
   control as root you can `chmod 4755` a **root-owned SUID** binary into the export; the target
   honors SUID + root ownership on its filesystem, and running it as `lab` gives eUID 0.
3. The `docker` group can command the root-running Docker daemon; that's root-equivalent regardless
   of your UID or lack of sudo. `-v /:/host` bind-mounts the **host root filesystem** into the
   container, so as container-root you read/write every host file (e.g. `chroot /host`, or drop a
   SUID bash onto the host).
4. `/etc/passwd` edit is fast and gives an immediate `su`, but leaves a **very obvious, high-severity
   artifact** — a new UID-0 line that any FIM/audit flags instantly. The writable-unit path is
   comparably fast but also leaves a changed unit file (FIM-detectable) plus a service restart event;
   it's marginally quieter than a new root account but still detectable. Either way, note the artifact
   and clean up. (Accept a well-argued case for either as "quieter" as long as the detection artifacts
   are correctly identified.)
5. **Cleanup:** NFS — remove the SUID binary from the export/`/srv`, unmount on your box; note the
   root-owned file existed. `/etc/passwd` — remove the added UID-0 line (and any shadow entry), verify
   the file matches its pre-test state. Writable unit — restore the original `ExecStart`/unit file,
   `daemon-reload`, remove any dropped `/tmp/rb`; note the restart occurred. In all cases record
   anything irreversible and any artifacts left, per the RoE.

---

## Grading notes (all three lessons)

- **Mechanism is mandatory.** "Ran the GTFOBins line, got root" without *why the primitive exists and
  why the shell inherits privilege* is a partial answer at best — the entire point of M04 is
  reasoning that transfers to unseen hosts.
- **Every technique needs remediation AND detection.** This is the recurring non-negotiable pattern;
  a finding missing either is incomplete regardless of how clean the exploit was.
- **Verification evidence** (`id`/`whoami` = root + the `LAB-FLAG-{uuid}`) is part of the finding, not
  optional.
- **Methodology over luck.** Reward reliability-first prioritization and penalize reaching for kernel
  exploits (or noisy tooling) while deterministic misconfigurations sit unused.
- **Safety.** Any submission that describes running these techniques outside the lab, or omits the
  LAB-vs-REAL boundary where relevant, fails the professionalism bar (M00).
</content>
