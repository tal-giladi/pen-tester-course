# Assessment 3 — Windows privilege escalation

_Tests **M05** (Windows for testers; local privilege escalation — service ACLs, unquoted paths,
`AlwaysInstallElevated`, scheduled tasks, DLL hijack, token privileges). ~2–3 h. Difficulty: 🟡.
You hold a low-privileged logon; the methodology is yours._

<div class="lab">

**Environment:** `labs/lab-05-win-privesc` — a single Windows VM on a **host-only, no-egress**
virtual network, built from licensed evaluation media (see
[`labs/vm/README.md`](../labs/vm/README.md)). **Foothold:** `lab\lowpriv` / `Lab-Passw0rd!`.
**Before you start,** restore the `clean` snapshot and **verify isolation from inside the VM** — an
external ping/curl must fail. **Reset = restore the `clean` snapshot** between attempts; never
hand-repair a broken target.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** All work targets the isolated `lab-05-win-privesc` VM on its
host-only network, as the synthetic `lab\lowpriv` account, against the benign `C:\flag.txt`
(admin-only). Isolation is enforced by the virtual network — confirm it before you begin. Every
technique here (reconfiguring a service, planting a binary, an elevated MSI install, editing a
task, hijacking a DLL, abusing a token privilege) is a crime against any machine you do not own and
are not explicitly authorized to test ([M00](../lessons/module-00/lesson-01.md)). This VM only.

</div>

## Situation

An **authorized internal engagement** at a client has produced an initial foothold: a standard
domain-joined-style workstation account, `lab\lowpriv`, with an interactive logon on the VM. The
client's question is the one every internal test has to answer: *"If an attacker phishes an
ordinary employee and lands on their workstation, how far can they get on that box? Show us a path
to admin or SYSTEM, prove it, and give us the fix."* You were handed the logon and nothing else —
no privilege dump, no list of what is misconfigured.

## Objective

From the `lab\lowpriv` logon, **discover, justify, exploit, and verify one local
privilege-escalation path to SYSTEM or local administrator**, then produce the report-ready
finding: mechanism, reproduction, verification evidence, root cause, impact, remediation, and
detection. As on any Windows box, membership in a group is not the same as *current* integrity —
account for that in your reasoning.

## Starting information

- An interactive logon as `lab\lowpriv` / `Lab-Passw0rd!` on the VM.
- The proof of success: `C:\flag.txt` is readable only by an administrator/SYSTEM — reading it
  demonstrates escalation.
- No enumeration output, no list of planted vectors. You build the surface inventory yourself.

## Constraints

- **Lab VM only.** Verify isolation from inside the VM first; restore the `clean` snapshot between
  attempts so the environment stays deterministic.
- You must **explain the mechanism** — which privileged actor (the SCM, Windows Installer, Task
  Scheduler, a token privilege) you abuse, which input you control, and why it yields
  SYSTEM/admin. A pasted exploit without the "why" fails the core dimension.
- **No destructive action beyond what the escalation requires.** If your path reconfigures a
  service, adds your account to a group, plants a binary/DLL, or drops an MSI, record the original
  state first and note the cleanup step (the snapshot is your safety net, but professionals record
  what they changed).
- Tool leads (WinPEAS, PowerUp) are lead generators — **verify every flag by hand** (e.g. confirm a
  writable path segment, or the actual config right) before you rely on it.

## Expected deliverables

1. **Recon / surface inventory** — the privilege-relevant facts you enumerated: your own privileges
   and integrity (`whoami /priv`, `whoami /groups`), service configurations and their ACLs,
   unquoted service paths, the `AlwaysInstallElevated` policy hives, scheduled tasks and their
   script/action writability, and any credential material — grouped, sourced, with the candidate
   vectors you considered.
2. **Vulnerability identification** — the chosen vector named precisely and mapped to its weakness
   class (e.g. CWE-732 incorrect permission assignment, CWE-428 unquoted search path, CWE-250
   unnecessary privilege) and to MITRE ATT&CK (T1543.003, T1574.009, T1548, T1053.005 as
   applicable).
3. **Exploit chain &amp; mechanism** — reproduction steps *and* the mechanism: the privileged actor,
   the controlled input, and why the privilege transfers. Where an exploit is potato-style token
   abuse, an explained mechanism with the precondition (`whoami /priv`) is acceptable — you do not
   need a weaponized PoC at this level.
4. **Verification evidence** — a shell as `NT AUTHORITY\SYSTEM` or a local admin, shown with
   `whoami` / `whoami /groups` / `whoami /priv`, and the contents of `C:\flag.txt`. "I got SYSTEM"
   without the evidence is not a finding.
5. **Root cause, impact, remediation, detection** — why the misconfiguration exists, what SYSTEM on
   this workstation means in business terms (full local compromise, credential harvest for lateral
   movement, persistence), the specific actionable fix, and the telemetry that catches it (relevant
   Windows event IDs and the ATT&CK mapping).
6. **A written finding** using
   [`solutions/report-template/finding-template.md`](../solutions/report-template/finding-template.md),
   every field filled, with a justified CVSS severity rationale and a cleanup/artifacts note.

## Grading rubric

Student-visible. Any of the planted vectors can earn full marks — the quality of mechanism, proof,
and fix is what is graded.

| Dimension | Points | What "good" looks like |
|---|---|---|
| **Method** | 20 | Systematic enumeration across services/tasks/installer-policy/token-privileges; a stated candidate set; the chosen path justified over alternatives (reliability × effort × noise); integrity-vs-membership understood. |
| **Evidence** | 15 | `whoami`/`whoami /priv`/`whoami /groups` and the flag captured; reproduction another tester can follow without you. |
| **Exploitation &amp; mechanism** | 25 | The privileged actor, controlled input, and privilege transfer are correct and explicit; a writable-prefix or config-right claim is *proven*, not assumed. |
| **Impact** | 15 | SYSTEM framed as full local compromise and a lateral-movement enabler in business terms, not "it's bad." |
| **Remediation &amp; detection** | 15 | Specific, root-cause fix (least privilege / correct ACL) **and** a concrete detection (event IDs + ATT&CK) — both required. |
| **Reporting** | 10 | Finding uses the template, every field filled, severity justified, cleanup noted. |

## Progressive hints

<details><summary>Hint 1 — conceptual direction</summary>
Same shape as any privesc: a <em>privileged actor</em> plus an <em>input you control</em>. On
Windows the actors that run as SYSTEM are services, scheduled tasks, and the installer. First
establish what you actually are right now — an admin's <em>filtered</em> token runs at Medium
integrity, so being in a group is not the same as holding the privilege. Then look for a SYSTEM
actor whose configuration you can influence.
</details>

<details><summary>Hint 2 — technique family</summary>
The classic distinct vectors: a service whose ACL lets you reconfigure it; a service with an
unquoted path and a writable earlier segment; the <code>AlwaysInstallElevated</code> policy that
runs any MSI as SYSTEM; a scheduled task whose script/action you can edit; a DLL a privileged
program loads from a directory you can write; and a token privilege (like impersonation) held by a
service context. Which does your inventory support?
</details>

<details><summary>Hint 3 — tool category &amp; what to look at</summary>
Enumerate service permissions with an access-check utility; read service <code>binPath</code>
values for unquoted paths with spaces; check <em>both</em> the HKLM and HKCU installer-policy keys;
list scheduled tasks and test the writability of their actions; for a DLL hijack, prove the failed
load and a writable search directory. A privesc audit script flags all of these — but confirm each
by hand.
</details>

<details><summary>Hint 4 — specific investigation direction</summary>
If a service grants your account the right to change its configuration, you do not need a writable
binary or an unquoted path — rewrite the <code>binPath</code> to your command and restart it; the
SCM runs it as the service account. An unquoted path is only exploitable if an earlier path segment
is <em>writable by you</em> — verify that before claiming it. <code>AlwaysInstallElevated</code>
needs <em>both</em> hives set to 1. Confirm with <code>whoami /groups</code> in a fresh session and
read the flag.
</details>

## Check yourself

<div class="callout key">

1. `whoami /groups` shows your account in the local Administrators group, yet you cannot read
   `C:\flag.txt`. Why — and what Windows mechanism explains the gap between membership and current
   access?
2. A service's `binPath` is `C:\Program Files\Vuln App\svc.exe`, unquoted. Under what single
   condition is this exploitable, and what is the one check that decides it? If that condition is
   false, what is the finding worth?
3. You have `SERVICE_CHANGE_CONFIG` on a service running as `LocalSystem` but the service binary is
   not writable and the path is quoted. Can you still reach SYSTEM? Explain the mechanism.
4. `AlwaysInstallElevated` is set to `1` in HKCU only. Does an arbitrary user's MSI install as
   SYSTEM? Why or why not?

</div>

_Model answers, the intended paths, and the grading key are instructor material in
`solutions/assessments/A3.md` — attempt the assessment before looking._
