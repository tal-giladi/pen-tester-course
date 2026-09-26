# Assessment 2 — Linux privilege escalation

_Tests **M04** (Linux for testers; local privilege escalation — SUID/SGID, sudo, cron, PATH,
capabilities). ~2–3 h. Difficulty: 🟡. You hold a foothold; the methodology is yours to choose,
justify, and verify._

<div class="lab">

**Environment:** `labs/lab-04-linux-privesc` — one intentionally misconfigured Debian container
(`ptlab04_target`) on an internal, no-egress network. **Foothold:** user `lab` / `Lab-Passw0rd!`
(`docker exec -it -u lab ptlab04_target bash`). **Run `./labs/lab up lab-04-linux-privesc` then
`./labs/lab check` FIRST** and confirm isolation. **Reset between attempts**
(`./labs/lab reset lab-04-linux-privesc`) so the box stays deterministic — always reset, never
hand-repair.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** All work targets `ptlab04_target` on the isolated network, as the
synthetic `lab` user, against the benign `LAB-FLAG-{uuid}` in `/root`. The container has no
Internet route (verify with `./labs/lab check`). Every technique here — SUID abuse, sudo
misconfiguration, cron, PATH hijacking, capabilities — is a crime against any system you do not
own and are not explicitly authorized to test ([M00](../lessons/module-00/lesson-01.md)). Stay on
the lab host.

</div>

## Situation

You are on an **authorized internal engagement**. Phishing landed the client a low-privileged shell
on a Linux application host, and that shell has been handed to you: user `lab` on
`ptlab04_target`. The client's ask is blunt: *"Assume an attacker got a normal user account on this
box. Can they become root? Show us how, prove it, and tell us how to stop it."* You were given no
inventory and no hints about how the box is misconfigured — that is the point of the test.

## Objective

From the `lab` foothold, **discover, justify, exploit, and verify one privilege-escalation path to
root**, then produce the report-ready finding: the mechanism (why the primitive works and why you
inherit its privilege), reproduction, verification evidence, root cause, impact, and both
remediation and detection. A shell you cannot explain is not a finding.

## Starting information

- A `lab` shell on `ptlab04_target` (password `Lab-Passw0rd!` if you SSH from an attached box;
  `docker exec` needs no password).
- The proof of success: `/root/flag.txt` is readable only by root — reading it demonstrates
  escalation.
- No pre-built exploit, no enumeration output, no list of what is planted. You build the surface
  inventory yourself.

## Constraints

- **Lab target only.** Confirm isolation with `./labs/lab check` before you begin; reset with
  `./labs/lab reset lab-04-linux-privesc` between attempts.
- You must be able to **explain the mechanism** — which general primitive the privileged actor
  exposes, why it runs with privilege, and why you inherit that privilege (the SUID/inheritance,
  `env_keep`, cron, PATH, or capability reasoning). Pasting a command without the "why" fails the
  core dimension.
- **No destructive action beyond what the escalation requires.** If your path drops a SUID binary,
  writes to a cron script, or edits a config, record it as an artifact you would have to clean up
  and note the cleanup step.
- Tool leads (LinPEAS, pspy) are lead generators, not proof — **verify every flag by hand** before
  you rely on it.

## Expected deliverables

1. **Recon / surface inventory** — the privilege-relevant facts you enumerated (SUID/SGID binaries,
   `sudo -l`, cron, writable files/dirs in privileged paths, capabilities), grouped and sourced, so
   the reader sees the candidate set you chose from — not just the winning row.
2. **Vulnerability identification** — the chosen vector named precisely, mapped to its weakness
   class (e.g. CWE-250 unnecessary privilege, CWE-269 improper privilege management, CWE-426
   untrusted search path) and to MITRE ATT&CK (T1548 / T1053 as applicable).
3. **Exploit chain &amp; mechanism** — the reproduction steps *and* the mechanism: which primitive
   (shell/file-read/file-write/code-load), why it runs privileged, and why the privilege transfers
   to you. Reference the specific reasoning (e.g. shell `-p` keeping the effective UID; `LD_PRELOAD`
   loading your object into a root process; the glob becoming `tar` options).
4. **Verification evidence** — `id` showing `uid=0(root)`, `whoami` = `root`, and
   `cat /root/flag.txt` = the `LAB-FLAG-{uuid}`. Escalation without the `id`/flag output is not
   evidence.
5. **Root cause, impact, remediation, detection** — why the misconfiguration exists, what root on
   this host means in business terms (data access, persistence, credential harvest, lateral
   movement), the specific actionable fix, and the telemetry that catches it (mapped to ATT&CK).
6. **A written finding** using
   [`solutions/report-template/finding-template.md`](../solutions/report-template/finding-template.md),
   every field filled, including a justified CVSS severity rationale and a cleanup/artifacts note.

## Grading rubric

Student-visible. The vector you pick does not matter; the quality of mechanism, proof, and fix
does.

| Dimension | Points | What "good" looks like |
|---|---|---|
| **Method** | 20 | Systematic enumeration across all five vector families; a stated candidate set; the chosen path justified over the alternatives (reliability × effort × noise). |
| **Evidence** | 15 | `id`/`whoami`/flag output captured; reproduction steps another tester can follow without you. |
| **Exploitation &amp; mechanism** | 25 | The primitive and the privilege-inheritance reasoning are correct and explicit — not "it worked," but *why* it worked. |
| **Impact** | 15 | Root framed as full host compromise in business terms (data, persistence, lateral movement), not "it's bad." |
| **Remediation &amp; detection** | 15 | Specific, root-cause fix (least privilege) **and** a concrete detection mapped to ATT&CK — both required. |
| **Reporting** | 10 | Finding uses the template, every field filled, severity justified, cleanup noted. |

## Progressive hints

<details><summary>Hint 1 — conceptual direction</summary>
Every local-privesc path is the same shape: a <em>privileged actor</em> plus an <em>input you
control</em>. Before touching anything, ask which actors on this box run as root (a SUID binary,
sudo, cron, a service) and which of their inputs you can influence. Prefer a path with a clean,
deterministic primitive over one you must wait for.
</details>

<details><summary>Hint 2 — technique family</summary>
Five families cover almost all of it: a SUID/SGID binary that offers a shell or command; a
<code>sudo</code> rule that lets you run something abusable (or preserves a dangerous environment
variable); a root cron job whose script or directory you can write, or that globs a directory you
control; a privileged program that calls a helper by bare name; a Linux capability on an
interpreter. Which does your inventory reveal?
</details>

<details><summary>Hint 3 — tool category &amp; what to look at</summary>
Enumerate SUID with a permission search; list your sudo rights authoritatively; read the crontabs
and watch for short-lived root processes; inspect binaries/scripts for bare command names; list
capabilities across the filesystem. For any abusable binary, the catalog of standard-binary
breakout primitives tells you <em>what</em> works — you supply <em>why</em>.
</details>

<details><summary>Hint 4 — specific investigation direction</summary>
If it is a SUID shell-capable binary, the shell may reset the effective UID unless you keep it
privileged (the <code>-p</code> flag). If sudo preserves a code-loading environment variable,
a small constructor shared object runs your code inside the root process. If it is a capability on
an interpreter, the interpreter can simply set its UID to 0 and exec a shell. Confirm with
<code>id</code> every time — and if you wrote to a cron script, note it for cleanup.
</details>

## Check yourself

<div class="callout key">

1. You copied a shell to a writable location from a root context and set the SUID bit, but running
   it gives you `uid=1000`, not root. What flag fixes it, and what is the shell doing without it?
2. `sudo -l` shows a `NOPASSWD` rule for one binary. Why does knowing the binary matter far more
   than the missing password — and what property of the binary decides whether the rule is root or
   harmless?
3. A root cron job runs `tar -czf backup.tgz *` in a directory you can write to, and you cannot
   edit the cron script itself. How do you still get code execution as root, and why does it work?
4. `getcap` shows `cap_setuid+ep` on a copied interpreter. Why is that effectively equivalent to
   SUID-root, and what is the one-line remediation?

</div>

_Model answers, the intended paths, and the grading key are instructor material in
`solutions/assessments/A2.md` — attempt the assessment before looking._
