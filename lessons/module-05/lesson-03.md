# 05.3 — Windows local privilege escalation: services, registry, tasks, DLLs & token abuse

<div class="prereq">

**Prerequisites:** [05.1 Windows for testers](lesson-01.md) — SIDs, integrity levels, UAC, the SCM,
the registry, and PowerShell enumeration; and [05.2 Authentication primer](lesson-02.md) — access
tokens, impersonation, and why `SeImpersonate`/`SeDebug` matter. Also [M00
authorization](../module-00/lesson-01.md) and [00.3 the confused deputy](../module-00/lesson-03.md).
Compare with [M04's Linux privesc](../module-04/lesson-02.md) — same reasoning, different mechanisms.
**Module:** M05. **Difficulty:** 🟡 intermediate.
**M05 assumes** a low-privileged shell on a lab Windows host. This lesson turns the 05.1 inventory
into **SYSTEM**.
**You will produce:** one *justified, verified* escalation path on the lab VM, plus its remediation
and detection as a report-ready finding.

</div>

## Why this matters

These are the vectors that take a Windows tester from a foothold to SYSTEM on internal engagements:
unquoted service paths, weak service permissions, `AlwaysInstallElevated`, autoruns, scheduled tasks,
DLL hijacking, and token abuse. They are almost never kernel exploits — they are an administrator's or
vendor's misconfiguration that hands privilege to a process you can influence. Every one is a variation
on the theme from 05.1 — *a privileged actor (usually a SYSTEM service or task) plus an input you
control* — and every one has a clean remediation and a detectable signature you must be able to write
for the client. Learn the mechanism, not the incantation, and you can escalate on hosts you've never
seen.

## Learning objectives

- Explain *why* each vector yields SYSTEM (the mechanism), not just which command to run.
- Recognize and exploit **unquoted service paths** and reason about the resolution order that causes it.
- Recognize and exploit **weak service permissions** by reconfiguring `binPath`.
- Exploit **`AlwaysInstallElevated`** and abuse **autoruns** and **scheduled tasks** you can influence.
- Recognize and exploit **DLL search-order hijacking** — and know its limits.
- Explain **`SeImpersonate` token abuse** (the "potato" family) as a mechanism, and the **UAC-bypass**
  concept — as concepts, with detection.
- For every vector, state the remediation **and** the blue-team detection — every time.

## Intuition

A service or task running as SYSTEM is a **loaded tool pointed at the machine**. If you can make that
tool run *your* code — because its binary is writable, because it will resolve a path or a DLL you
control, because you can rewrite its configuration, or because you can hand it your token to
impersonate — you inherit SYSTEM for that action. The whole game is: find the privileged actor, then
find the *input you control that decides what it executes*. None of these were designed as attack
surfaces; each is a legitimate Windows mechanism (service configuration, path resolution, DLL loading,
impersonation) turned the wrong way by a misconfiguration.

## The underlying technology, per vector

### 1. Unquoted service paths

The SCM stores each service's command line in `ImagePath`. If that path contains **spaces and is not
quoted**, Windows' `CreateProcess` tokenizes it and tries each prefix, appending `.exe`, until one
runs. `sc qc` shows the raw value:

```text
C:\> sc qc VulnSvc
[SC] QueryServiceConfig SUCCESS
        BINARY_PATH_NAME   : C:\Program Files\Vuln App\service.exe
        SERVICE_START_NAME : LocalSystem
```

Because it is unquoted, on start the SCM attempts, in order:

```text
C:\Program.exe
C:\Program Files\Vuln.exe
C:\Program Files\Vuln App\service.exe   <-- the intended one
```

If you can **write** `C:\Program.exe` or `C:\Program Files\Vuln.exe`, your binary runs as **SYSTEM**
when the service starts. The weakness is that the SCM cannot tell an intended path from an injected
prefix (**CWE-428, Unquoted Search Path**). You recognize it by an `ImagePath` with a space and no
quotes running as SYSTEM; you confirm exploitability by checking whether any earlier-resolving
directory is writable:

```powershell
# Find SYSTEM services whose PathName has a space and no leading quote:
Get-CimInstance Win32_Service |
  Where { $_.PathName -match '^[^"].*\s.*\.exe' -and $_.StartName -match 'SYSTEM' } |
  Select Name, PathName
# Then check whether an earlier path segment is writable (icacls / Get-Acl):
icacls "C:\Program Files"
```

<div class="callout warn">

The classic prefix `C:\Program.exe` requires **write access to the root of `C:\`**, which modern
default ACLs deny to standard users — so the truly exploitable case is usually a service installed in a
**custom directory with a space** (`C:\Custom Apps\svc.exe`) where that directory *is* user-writable.
Don't report an unquoted path as exploitable until you've proven a writable prefix; an unquoted path
alone is a hygiene finding, not an escalation.

</div>

### 2. Weak service permissions (reconfigure binPath)

Every service object has its own **security descriptor**. If your user (or a group you're in) has been
granted `SERVICE_CHANGE_CONFIG` (or broader like `SERVICE_ALL_ACCESS`) on a SYSTEM service, you can
simply **rewrite where it points** — no writable binary needed. `accesschk` reads the effective rights:

```text
C:\> accesschk.exe -uwcqv "lowpriv" VulnSvc
  RW VulnSvc
        SERVICE_QUERY_STATUS
        SERVICE_CHANGE_CONFIG      <-- you can reconfigure it
        SERVICE_START / SERVICE_STOP
```

The mechanism: `SERVICE_CHANGE_CONFIG` lets you set the `binPath`, and if you can also start/stop it
(or it restarts on boot), the SCM launches your new command **as the service's account (SYSTEM)**.
Same idea if only the **binary file** is writable (a subset of DLL/exe planting): replace the exe.
This is **CWE-732 (Incorrect Permission Assignment)**. Recognize it with `accesschk`/PowerUp; confirm
by reading the DACL, not by guessing.

### 3. AlwaysInstallElevated

Windows Installer can be told, by policy, to install **all** MSI packages with **elevated (SYSTEM)**
privileges. This requires the same value in **both** hives:

```text
C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    AlwaysInstallElevated    REG_DWORD    0x1
C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    AlwaysInstallElevated    REG_DWORD    0x1
```

When both are `1`, *any* user can install an MSI they crafted and it runs as SYSTEM (**CWE-250**). The
mechanism is entirely intended installer behavior enabled by a dangerous policy — often set to let
users install one specific package, unaware it applies to all. You recognize it by the two registry
values; the abuse is "build a benign MSI that spawns a shell and run `msiexec /i`." (We describe the
mechanism; you build the benign proof in the lab, and mark cleanup.)

### 4. Autoruns (registry & startup)

Programs that auto-start run in the context of whoever the entry targets. Entries under
`HKLM\...\CurrentVersion\Run` run at *any* user's logon; if the **executable** an autorun points to,
or its **registry key**, is writable by you and the entry is triggered by a higher-privileged user's
logon, your code runs as that user. Startup folders and services-as-autoruns are variants. Mechanism:
the OS faithfully launches whatever the (writable) autorun references. Recognize with `reg query` of
the Run keys and `Autoruns.exe`; confirm the target's ACL is writable and that a privileged principal
will trigger it.

### 5. Scheduled tasks

The Task Scheduler runs tasks as a configured principal, often SYSTEM or an admin, on a trigger. Two
familiar flaws mirror the Linux cron cases (04.2):

- **Writable task binary/script.** A SYSTEM task runs `C:\Scripts\maintenance.ps1`, and that file (or
  its directory) is writable by you — you edit it, and it runs as SYSTEM on the next trigger.
- **Task pointing at a writable location** or using a modifiable argument.

```powershell
Get-ScheduledTask | ForEach-Object {
  [pscustomobject]@{
    Task = $_.TaskName
    User = $_.Principal.UserId
    Action = ($_.Actions | Select-Object -Expand Execute -ErrorAction SilentlyContinue) -join ';'
  }
} | Where User -match 'SYSTEM|Administrator'
# Then check the ACL of each Action's path.
```

This is **CWE-732** again, mapped to **MITRE ATT&CK T1053 (Scheduled Task/Job)**. Recognize by
enumerating tasks with their run-as principal and action path; confirm write access to the action.

### 6. DLL search-order hijacking

When a program loads a DLL by name without a full path, Windows searches a defined **order**
(application directory, system directories, then the directories in `PATH`, with details governed by
**safe DLL search mode** and KnownDLLs). If a privileged program tries to load a DLL that **doesn't
exist** in an earlier-searched directory, or an earlier-searched directory is **writable** by you, your
malicious DLL is loaded and its `DllMain` runs with the program's privilege:

```text
Load order (simplified, safe search mode ON):
  1. the application's own directory
  2. C:\Windows\System32, C:\Windows\System (system dirs)
  3. C:\Windows
  4. current directory
  5. each directory in %PATH%      <-- writable PATH entry = hijack opportunity
```

The exploitable cases are: a **missing DLL** a SYSTEM service tries to load (you supply it in a
searched, writable dir), or a **writable application/PATH directory** earlier in the order than the
legitimate DLL. Mechanism: the loader resolves by search, and you win the search (**CWE-427,
Uncontrolled Search Path Element**). Recognize with Process Monitor (`NAME NOT FOUND` on a DLL in a
writable path) or PowerUp; confirm the directory is writable and the load is triggered by a privileged
process.

<div class="callout warn">

DLL hijacking is often the **least reliable** vector: it depends on a specific program being launched,
safe-search-mode and KnownDLLs exclude many DLLs, and modern binaries increasingly load by full path.
Treat a hijack candidate as a lead until you've observed the failed load and proven the writable
directory. Prefer a deterministic service/token path when you have one.

</div>

### 7. Token abuse — the "potato" family (SeImpersonate → SYSTEM)

05.2 set this up: a service account holding **`SeImpersonatePrivilege`** may impersonate the token of a
client that authenticates to it. The "potato" techniques (RottenPotato, JuicyPotato, PrintSpoofer,
and successors) all do the same thing conceptually:

1. You run as a service account (IIS app-pool, SQL, `LocalService`/`NetworkService`) that holds
   `SeImpersonate`.
2. You **coerce a SYSTEM process to authenticate to a local endpoint you control** — historically via
   a DCOM/RPC trick, or via the **print spooler / named-pipe** coercion in PrintSpoofer.
3. That SYSTEM authentication hands your listener a **SYSTEM token**, which — because you hold
   `SeImpersonate` — you are permitted to **impersonate**.
4. You call `CreateProcessWithToken`/`CreateProcessAsUser` with the impersonated SYSTEM token, spawning
   a process **as SYSTEM**.

<div class="callout key">

**This is not a vulnerability — it is impersonation working as designed, aimed the wrong way.** The
"weakness" is that a service account was granted `SeImpersonate` (legitimately, so it can act for its
clients) *and* an attacker could run code in that account and coerce a SYSTEM authentication. The fix
is not "patch impersonation"; it is "don't let untrusted code run as an account that holds
`SeImpersonate`, and remove the coercion primitives." Recognize the opportunity purely from
`whoami /priv` showing `SeImpersonatePrivilege: Enabled` in a service context.

</div>

<div class="callout warn">

**Concept, not weaponized code.** <span class="badge current">CURRENT, well-detected</span> This
course teaches the *mechanism and detection* of the potato family; it does **not** ship a weaponized
implementation or a coercion exploit. In the lab you demonstrate the *precondition* (`SeImpersonate`
present) and reason through the four steps; where a proof-of-concept is used, it is a standard,
signed-or-known lab tool run against the lab VM only, under authorization. `SeDebugPrivilege` is the
sibling primitive: it lets you open any process (LSASS included) — token theft and the credential
dumping of 05.2/M10.

</div>

### 8. UAC bypass (concept)

Recall from 05.1 that an administrator's normal processes run at **Medium** integrity and elevate to
**High** only through UAC. A **UAC bypass** gets High-integrity execution **without a consent prompt**,
typically by abusing an **auto-elevating** Microsoft binary that reads a **hijackable registry key or
DLL** (e.g. the classic `fodhelper.exe`/`eventvwr.exe` registry-hijack patterns). Mechanism: the
auto-elevate binary launches High, then reads a `HKCU` key you can write, and executes what you put
there — High integrity, no prompt. Because **UAC is not a security boundary** (Microsoft's own stance,
05.1), this is a same-user integrity step (Medium-admin → High-admin), *not* a cross-user escalation —
important to frame correctly in a report. Taught here as a concept with detection; not weaponized.

## Why the weakness exists

Every vector is a legitimate Windows mechanism plus an administrator/vendor granting privilege or
write access where it wasn't needed: a service installed unquoted in a spaced path, a loosened service
ACL, an installer policy applied too broadly, a task or autorun pointing at a writable file, a program
loading a DLL by name from a writable directory, a service account with `SeImpersonate` running
untrusted code. The classes are **CWE-250 (Unnecessary Privilege)**, **CWE-269 (Improper Privilege
Management)**, **CWE-732 (Incorrect Permission Assignment)**, **CWE-427/428 (search-path)** — the OS is
doing exactly what it was configured to do.

## How a tester recognizes it

From the 05.1 inventory: any SYSTEM service with an unquoted, spaced `ImagePath` **and** a writable
prefix; any service whose DACL grants you `SERVICE_CHANGE_CONFIG`/write, or whose binary you can write;
`AlwaysInstallElevated=1` in both hives; a writable autorun target/key triggered by a privileged user;
a SYSTEM/admin scheduled task with a writable action; a privileged process loading a DLL from a
writable/earlier-searched directory; and `SeImpersonatePrivilege` (or `SeDebug`) in your token. The
recurring shape: **a privileged actor + an input you control.**

## Tooling — what it does, key options, limits, verify by hand

- **PowerUp / PrivescCheck** (PowerShell) — enumerate unquoted paths, weak service ACLs,
  `AlwaysInstallElevated`, DLL-hijack candidates, and suggest the abuse. Limit: **AMSI/script-block
  logging** frequently catches these; results are leads.
- **winPEAS** — one-shot coverage of all vectors, colour-coded. Limit: loud on disk, lead generator.
- **accesschk.exe** (Sysinternals) — the authoritative effective-permissions check for services,
  files, and registry keys; use it to *verify* a PowerUp/winPEAS flag (e.g. `accesschk -uwcqv user
  svc`). Signed by Microsoft.
- **Process Monitor** (Sysinternals) — observe `NAME NOT FOUND`/`PATH NOT FOUND` DLL loads to confirm a
  real hijack candidate rather than a theoretical one.

Two rules unchanged from M04: **they automate the checklist you learned — they don't replace
understanding it**, and **verify every flag by hand** (an unquoted path with no writable prefix, or a
service you can't actually reconfigure, is not a path). Their limits: noise, detection, and RoE stealth
clauses.

## Exploitation / demonstration (LAB ONLY)

<div class="callout attack">

**Technique — weak service permissions (reconfigure binPath).** Given `accesschk` showing
`SERVICE_CHANGE_CONFIG` on the SYSTEM service `VulnSvc`, the mechanism is: rewrite its `binPath` to a
command of your choosing, then trigger a (re)start; the SCM launches your command as SYSTEM.

```text
:: LAB ONLY — mechanism illustration on lab-05-win-privesc.
:: 1. Confirm you can reconfigure it (verify, don't assume):
accesschk.exe -uwcqv lowpriv VulnSvc      :: shows SERVICE_CHANGE_CONFIG

:: 2. Point it at a benign proof action (create a marker only a privileged
::    context could): here, add lowpriv to local Administrators as the SYSTEM service.
sc config VulnSvc binPath= "cmd /c net localgroup administrators lab\lowpriv /add"

:: 3. Trigger it (start/stop, or wait for its restart):
sc stop VulnSvc & sc start VulnSvc
```

**Why it works:** `SERVICE_CHANGE_CONFIG` is the exact right to alter `binPath`; the SCM then executes
that command as the service's account, `LocalSystem`. Nothing is "hacked" — you used the configuration
right the DACL wrongly granted you. The fix is not "block `sc config`"; it is "don't grant `lowpriv`
change-config on a SYSTEM service." Verify and **restore the original `binPath`** after (cleanup).

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Every command above targets `lab-05-win-privesc` on the **isolated
host-only network with no Internet route**, as the synthetic `lab\lowpriv` user, to reach the benign
`LAB-FLAG-{uuid}` that only SYSTEM/Administrators can read. Running any of this against a system you do
not own and are not explicitly authorized to test is a crime (M00). Restate scope and authorization
before touching anything outside the lab, and restore any service configuration you change.

</div>

## Verification

Confirm escalation cleanly and non-destructively. After a successful path: `whoami` returns
`NT AUTHORITY\SYSTEM` (or, for the `net localgroup` proof, a **new** logon shows `lab\lowpriv` in
`Administrators` — verify with `whoami /groups` in a fresh session). Read the proof only a privileged
context can: `type C:\Windows\System32\config\LAB-FLAG.txt` → `LAB-FLAG-{uuid}` (or the lab's stated
path). "I got SYSTEM" without the `whoami`/flag evidence is not a finding. Record exactly which artifact
proved it — verification is part of the finding, and part of what you'll write in M16.

## Impact

SYSTEM on the host means: read every file and secret, dump credential material from LSASS/SAM (05.2 →
M10), install persistence, disable logging, and — on a domain-joined host — obtain the machine account,
cached credentials, and tickets that feed lateral movement (M11) and domain compromise (M06). In
business terms, a single low-priv foothold plus one of these misconfigurations equals full compromise
of the host and a stepping stone into the domain — exactly how you frame it in the report (M16).

## Remediation

<div class="callout defend">

- **Unquoted paths:** always **quote** `ImagePath`; install services in directories standard users
  cannot write; audit with the enumeration query above. (CWE-428)
- **Service permissions:** service DACLs should grant config/write only to administrators; never grant
  `SERVICE_CHANGE_CONFIG`/`WRITE_DAC`/write-to-binary to normal users or broad groups. (CWE-732)
- **AlwaysInstallElevated:** never enable it; if set, remove both `HKLM` and `HKCU` values via GPO.
  (CWE-250)
- **Autoruns / tasks:** autorun targets and task actions must be **admin-owned and not user-writable**,
  in non-writable directories; run tasks as the least privilege that works. (CWE-732, T1053)
- **DLL hijacking:** load DLLs by **full path**, enable **safe DLL search mode**, keep application and
  PATH directories non-writable; ship all required DLLs. (CWE-427)
- **Token abuse:** don't run untrusted code as accounts holding `SeImpersonate`; remove coercion
  primitives (patch/disable the print spooler where not needed); apply least privilege to service
  accounts. **UAC:** treat it as defense-in-depth, not a boundary; the real control is limiting who is
  a local admin.

All of these reduce to **least privilege** and **correct ACLs** (CWE-250/269/732).

</div>

## Detection / blue-team view

<div class="callout defend">

- **Service abuse:** **Event ID 7045** (a service was installed) and **7040** (start-type changed);
  Sysmon process-creation showing `sc.exe config`/`sc create`, or a service binary spawning `cmd`/
  `powershell`/`net.exe` as SYSTEM. A SYSTEM service whose child is a shell is rarely normal.
- **AlwaysInstallElevated:** `msiexec` installing a package from a user path as SYSTEM;
  registry-set auditing on the Installer policy keys.
- **Scheduled tasks:** **Event ID 4698** (task created) / 4702 (updated); Sysmon on
  `schtasks.exe`/`Register-ScheduledTask`; a task action writing to or launching from a user-writable
  path.
- **Autoruns / DLL hijack:** Sysmon **Event ID 7** (image/DLL loaded) of an unsigned DLL from an
  unusual directory into a SYSTEM process; file-integrity monitoring on Run keys and startup folders.
- **Token abuse (potato):** Sysmon **Event ID 10** (ProcessAccess) and unusual token/impersonation
  activity; a service account spawning SYSTEM processes; spooler/named-pipe coercion patterns; EDR
  alerts on `CreateProcessWithToken`. **UAC bypass:** auto-elevating binaries (`fodhelper`, `eventvwr`)
  spawning children, or writes to their hijackable `HKCU` keys.

Mapped to **MITRE ATT&CK**: **T1543** Create or Modify System Process (.003 Windows Service),
**T1574** Hijack Execution Flow (.001 DLL, .009 Unquoted Path), **T1053.005** Scheduled Task,
**T1548.002** Bypass UAC / **T1548** Abuse Elevation Control Mechanism, **T1134** Access Token
Manipulation. Recurring detection idea: *a privileged process spawning a shell, or being reconfigured
by a non-admin, is rarely normal.*

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-05-win-privesc` — an intentionally misconfigured Windows VM on the isolated
**host-only network with no Internet route** (built separately; see
[`labs/vm/README.md`](../../labs/vm/README.md) for the isolation contract, snapshots, and reset).
**Access:** the `lab\lowpriv : Lab-Passw0rd!` shell. **Targets:** the lab VM only; the
`LAB-FLAG-{uuid}` proof is readable only by SYSTEM/Administrators — reading it proves escalation.
**Time:** ~90 min. **Isolation:** verify external egress fails from inside the VM before you begin;
**restore any service/task/registry change** and **restore the clean snapshot** between attempts. The
host deliberately mixes unquoted-path, weak-service-ACL, `AlwaysInstallElevated`, scheduled-task,
DLL-hijack, and `SeImpersonate` misconfigurations.

</div>

Using your 05.1 inventory, pick **one** path, exploit it, verify with `whoami`/the flag, then write its
remediation and detection for that specific finding. Restore the snapshot and try a *second, different*
vector for practice.

## Exercise

<div class="callout method">

**Situation.** Authorized internal engagement; you hold a `lab\lowpriv` shell on the lab VM and have
your 05.1 surface inventory in hand. The client wants a demonstrated, reproducible escalation to
SYSTEM with a fix and a detection.

**Objective.** Find, **justify**, and **verify** one privilege-escalation path to SYSTEM (or local
admin), then write its remediation and detection — a report-ready finding.

**Starting information.** Your `lab\lowpriv` shell and 05.1 inventory. No pre-built exploit; PowerUp/
winPEAS only if RoE allows and you verify every flag by hand.

**Constraints.** Lab target only. You must explain *why* the primitive works (the mechanism), not just
paste a command. No destructive actions beyond what the escalation requires; **note and undo** anything
you change (a rewritten `binPath`, a dropped file, a modified task), and note that PowerShell is logged.

**Expected deliverables.**
1. The chosen vector and the **mechanism** (which privileged actor, which input you control, why it
   runs as SYSTEM/admin, why you inherit it — reference the resolution order / DACL right / token
   impersonation explicitly).
2. Reproduction steps and **verification evidence** (`whoami` = `NT AUTHORITY\SYSTEM` or new admin
   group membership; the `LAB-FLAG-{uuid}`).
3. **Remediation** (specific, actionable) **and** **detection** (telemetry/event IDs, mapped to
   ATT&CK) — both required; a finding without them is incomplete.
4. A cleanup note: exactly what you changed and how you restored it.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Return to "privileged actor + input you control." Which inventory row gives a <em>deterministic</em>
SYSTEM primitive right now — a reconfigurable service, a writable service binary, a token privilege —
versus one you must wait for (a scheduled task) or that depends on a launch (a DLL hijack)?
</details>

<details><summary>Hint 2 — technique family</summary>
Is your best row an unquoted path with a writable prefix, a weak service DACL
(<code>SERVICE_CHANGE_CONFIG</code>), <code>AlwaysInstallElevated</code> in both hives, a writable
scheduled-task action, a DLL the service fails to find in a writable dir, or
<code>SeImpersonatePrivilege</code> in your token?
</details>

<details><summary>Hint 3 — where to look</summary>
Verify before exploiting: <code>accesschk -uwcqv lowpriv &lt;svc&gt;</code> for service rights;
<code>icacls</code>/<code>Get-Acl</code> on the binary, its directory, and any earlier unquoted-path
segment; <code>reg query</code> both Installer hives; <code>whoami /priv</code> for
<code>SeImpersonate</code>. An unquoted path with no writable prefix is <em>not</em> a path.
</details>

<details><summary>Hint 4 — specific investigation direction</summary>
Weak service ACL → <code>sc config &lt;svc&gt; binPath= "..."</code> then start/stop; restore the
original <code>binPath</code> after. Unquoted path → plant the earlier-resolving <code>.exe</code> in
the writable segment and (re)start the service. <code>SeImpersonate</code> → reason through the four
potato steps (concept). Verify with <code>whoami</code> every time, and undo every change.
</details>

## Check yourself

<div class="callout key">

1. `sc qc VulnSvc` shows `BINARY_PATH_NAME : C:\Program Files\Vuln App\svc.exe` running as
   `LocalSystem`. Walk the exact order the SCM tries paths, and state the *one* additional fact you
   must verify before calling this exploitable.
2. You have `SERVICE_CHANGE_CONFIG` on a SYSTEM service but the service binary is **not** writable and
   its path is quoted. Can you still escalate? How, and via which mechanism?
3. Why must `AlwaysInstallElevated` be set in **both** `HKLM` and `HKCU` to be exploitable, and what
   does each half authorize?
4. Explain *mechanically* why holding `SeImpersonatePrivilege` on a service account leads to SYSTEM —
   including where the SYSTEM token comes from. Why is this "impersonation as designed," not a bug?
5. A colleague reports a "UAC bypass" as a privilege escalation from a standard user to admin. Why is
   that framing wrong, and what does a UAC bypass actually achieve?
6. Why is DLL search-order hijacking usually less reliable than a weak-service-ACL path, and what two
   facts must you confirm before treating a hijack candidate as real?

</div>

Model answers are in `solutions/module-05.md` (instructor material — reason through them first).

## References

- **Microsoft — Services / Service Security and Access Rights** (`SERVICE_CHANGE_CONFIG`, DACLs),
  **`sc` command**, and **Unquoted Service Path** guidance.
- **Microsoft — Dynamic-Link Library Search Order** (safe DLL search mode, KnownDLLs) and
  **AlwaysInstallElevated** policy documentation.
- **Microsoft — Task Scheduler** security; **Access Tokens / `SeImpersonatePrivilege`** and
  impersonation levels; **How UAC works** (and that it is not a security boundary).
- **Sysinternals** — `AccessChk`, `Autoruns`, `Process Monitor`, `Process Explorer`.
- **PowerSploit/PowerUp** and **PrivescCheck** — enumeration (treat output as leads; verify by hand).
- **MITRE ATT&CK** — **T1543.003** Windows Service, **T1574.001/.009** DLL / Unquoted Path Hijack,
  **T1053.005** Scheduled Task, **T1548.002** Bypass UAC, **T1134** Access Token Manipulation.
- **CWE-250** Unnecessary Privileges; **CWE-269** Improper Privilege Management; **CWE-732** Incorrect
  Permission Assignment; **CWE-427** Uncontrolled Search Path Element; **CWE-428** Unquoted Search Path.
- Original research (studied for mechanism/detection, not weaponization): the RottenPotato/JuicyPotato/
  **PrintSpoofer** family write-ups on `SeImpersonate` token abuse.

## What you should now be able to do

- Explain and exploit the core Windows local-privesc vectors — unquoted service paths, weak service
  ACLs (binPath reconfigure), `AlwaysInstallElevated`, autoruns, scheduled tasks, DLL hijacking — and
  say *why* each yields SYSTEM.
- Explain the `SeImpersonate` "potato" mechanism and the UAC-bypass concept accurately (including that
  UAC is not a boundary), as concepts with detection.
- Verify escalation with concrete evidence and clean up every change you made.
- Write the specific remediation and the ATT&CK-mapped detection for every one of these vectors — a
  report-ready finding.

## Progress checkpoint

```bash
py course.py complete 05.3
```
