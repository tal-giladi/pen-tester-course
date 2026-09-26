# 05.1 — Windows for testers: architecture, users, processes, services, registry & PowerShell

<div class="prereq">

**Prerequisites:** [M00 Foundations](../module-00/lesson-01.md) (ethics, methodology, threat
modeling — especially the [confused deputy](../module-00/lesson-03.md)), [M01
Networking](../module-01/lesson-01.md), [M02 Recon](../module-02/lesson-01.md), [M03 Scanning &
enumeration](../module-03/lesson-01.md). Reading [M04's Linux model](../module-04/lesson-01.md)
first is useful — Windows solves the same problems differently, and the contrast teaches both.
**Module:** M05 Windows for testers & privilege escalation. **Difficulty:** 🟡 intermediate.
**M05 assumes** you already hold a **low-privileged shell on a lab Windows host** (as the synthetic
`lab\lowpriv` user) — delivered by an earlier foothold. This module is what you do *after* you land.
**You will produce:** a Windows "privesc surface" inventory for a described host — the facts,
grouped by category, each paired with a hypothesis and the reasoning behind it.

</div>

## Why this matters

Most enterprise environments run on Windows, and most internal penetration tests spend the majority
of their time on Windows hosts and the Active Directory (M06) that binds them. When you land a shell
as an unprivileged user, everything valuable — local administrator, the credentials cached in memory
(05.2), the pivot to the domain — sits behind a privilege boundary that Windows enforces very
differently from Linux. You cannot escalate reliably by pasting exploits; you escalate by
**understanding how Windows decides who may do what**, then finding the place where an administrator
configured that decision wrong.

This lesson is the map for the rest of the module. Before you abuse a service, a scheduled task, a
registry key, or a token (05.3), you need a working model of Windows privilege: security identifiers,
integrity levels, UAC, the process and service model, the registry, and PowerShell as the tool you
use to interrogate all of it. Get the model right and Windows privesc stops being a checklist and
becomes reasoning — the same shift 04.1 made for Linux.

## Learning objectives

By the end you can:

- Explain the kernel/user-mode split, the SID model, and what "SYSTEM" and "Administrator" actually
  *are* to the Windows security reference monitor.
- Read a security context: users, groups, integrity levels, and privileges — and predict their effect.
- Describe processes, the **Service Control Manager (SCM)** as the systemd-equivalent, and how
  identity and tokens are inherited.
- Navigate the **registry** structure and know which hives and keys hold escalation-relevant data.
- Use **PowerShell** as your primary enumeration tool and explain what each one-liner asks the OS.
- Locate where credentials and useful information live on a Windows host — registry, `unattend.xml`,
  the SAM, and (conceptually) DPAPI-protected secrets — and reason about what each implies.

## Intuition

Every action on Windows is a request made by a *process* (really, a thread) to the kernel: open this
file, start this service, read this registry key. The kernel's **Security Reference Monitor (SRM)**
answers every request by comparing the **access token** the thread carries against the **security
descriptor** on the object being touched. Privilege escalation is arranging for a request you want —
"run a program as SYSTEM", "write into a service's binary" — to be made by a thread whose token the
SRM will accept. You rarely attack the SRM's check itself; you find a process that already carries a
powerful token and convince it to act for you, or you find an object whose security descriptor was
set too loosely. That is the confused-deputy pattern from 00.3, living inside Windows.

## The underlying technology

### Kernel mode vs user mode

Like Linux, Windows splits the world in two. **Kernel mode** (the NT kernel `ntoskrnl.exe`, drivers,
the SRM) runs with full hardware access. **User mode** is where your shell, `explorer.exe`, and every
application run, unable to touch hardware or another process directly — they ask the kernel through
**system calls** (surfaced by `ntdll.dll`). Two consequences for a tester mirror the Linux ones: a
**kernel/driver exploit** crosses the boundary directly (powerful, fragile, out of this module's
scope), while everything else — services, tasks, registry ACLs, tokens — is the kernel *correctly*
enforcing rules an administrator configured. Those misconfigurations are the overwhelming majority of
real-world local privesc, and they are what 05.3 exploits.

### SIDs — the real identity

To Windows, a user or group is not a name but a **Security Identifier (SID)**: a variable-length
string like `S-1-5-21-1004336348-1177238915-682003330-1001`. Names (`lowpriv`, `Administrators`) are
a convenience resolved through the SAM or a domain controller. A few **well-known SIDs** matter
constantly:

- `S-1-5-18` — **Local System (SYSTEM)**: the most powerful account on the host, used by the OS and
  many services. This is the Windows equivalent of "the win condition" locally.
- `S-1-5-32-544` — the **Administrators** built-in group.
- `S-1-5-19` / `S-1-5-20` — **LocalService** / **NetworkService** (lower-privileged service accounts).
- `S-1-1-0` — **Everyone**; `S-1-5-11` — **Authenticated Users**.

<div class="callout key">

**"Administrator" is not the top of the hierarchy — SYSTEM is.** A member of `Administrators` can
*become* SYSTEM (that is largely what admin privilege buys you), and much of Windows privesc is really
"low-priv user → SYSTEM" or "admin-but-limited → SYSTEM" rather than the Linux "user → root (UID 0)".
Keep SYSTEM (`S-1-5-18`) as your mental "UID 0".

</div>

### Access tokens, groups, and privileges

When you log on, the **Local Security Authority (LSASS)** builds an **access token** for your session
that lists your user SID, your group SIDs, an **integrity level**, and a set of **privileges**. Every
thread you spawn inherits a copy of this token, and the SRM checks it on every access. You inspect
your own token with `whoami`:

```text
C:\> whoami /groups
GROUP INFORMATION
-----------------
Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192

C:\> whoami /priv
PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                          State
============================= ==================================== ========
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeShutdownPrivilege           Shut down the system                 Disabled
SeImpersonatePrivilege        Impersonate a client after authn     Enabled
```

**Privileges** are named rights, roughly analogous to Linux capabilities: `SeImpersonatePrivilege`,
`SeDebugPrivilege`, `SeBackupPrivilege`, `SeTakeOwnershipPrivilege` and others each grant a specific
power independent of your group membership. Two of them — `SeImpersonate` and `SeDebug` — are enough
to reach SYSTEM on their own and are the heart of 05.2/05.3's token work. Seeing
`SeImpersonatePrivilege: Enabled` in the output above on a service account is the single most
important line an enumerator can surface, and we return to exactly why in 05.3.

### Integrity levels and UAC

Windows layers **Mandatory Integrity Control** on top of the discretionary ACL model. Every process
runs at an **integrity level** — Low, Medium, High, or System — and a lower-integrity process cannot
write to a higher-integrity object even if the ACL would otherwise allow it. Practical levels:

- **Low** — sandboxed code (e.g. a browser renderer).
- **Medium** — a normal user process, *even for a member of Administrators*.
- **High** — an *elevated* process (admin who clicked through UAC / "Run as administrator").
- **System** — SYSTEM services.

**User Account Control (UAC)** is why an administrator's ordinary processes run at *Medium*: on logon,
an admin gets two tokens, a filtered (Medium) one used by default and a full (High) one used only when
a process elevates. UAC is a convenience/consent boundary, **not a formal security boundary** —
Microsoft is explicit about this. Numerous "UAC bypass" techniques let High-integrity code run without
a prompt (05.3 covers the concept). For a tester, the immediate lesson is: being in `Administrators`
is not the same as *being* elevated; you often still need an "admin (Medium) → admin (High) → SYSTEM"
step.

### Processes, threads, and the Service Control Manager

A Windows process (`CreateProcess`) gets a copy of the parent's token by default; a service or a
scheduled task, by contrast, is launched by the OS with a token for *its* configured account. The
**Service Control Manager (`services.exe`)** is the Windows equivalent of systemd: it starts, stops,
and supervises **services**, each defined by a registry entry that records its executable path
(`ImagePath`), its start type, and the account it runs as (`SYSTEM`, `LocalService`, `NetworkService`,
or a named account). Because so many services run as **SYSTEM**, a service you can influence — its
binary is writable, its `ImagePath` is unquoted with a space, its configuration ACL lets you
reconfigure it — is a direct path to SYSTEM. This is the single richest privesc category on Windows
and 05.3 devotes most of its space to it.

### The registry

The **registry** is a hierarchical database of configuration, replacing the scattered config files of
Unix. Its root **hives**:

- **`HKLM`** (`HKEY_LOCAL_MACHINE`) — machine-wide config. Subkeys you will meet: `SYSTEM`
  (services, under `HKLM\SYSTEM\CurrentControlSet\Services`), `SOFTWARE` (installed-app config, autoruns
  at `...\Microsoft\Windows\CurrentVersion\Run`), `SAM` and `SECURITY` (local account hashes and LSA
  secrets — normally readable only by SYSTEM).
- **`HKCU`** (`HKEY_CURRENT_USER`) — the current user's settings (a per-user view of `HKU`).
- **`HKU`**, **`HKCR`**, **`HKCC`** — all users, class registrations, current hardware profile.

Values have types (`REG_SZ`, `REG_DWORD`, `REG_EXPAND_SZ`, …). The registry is attacker-relevant three
ways at once: it *configures* the escalation vectors (services, autoruns, `AlwaysInstallElevated`), it
*stores* secrets (`Winlogon` autologon passwords, VNC/PuTTY config, LSA secrets), and its keys carry
**ACLs** just like files — a writable service key is as good as a writable binary.

### PowerShell — your enumeration instrument

**PowerShell** is the tool you use to ask all of the above. Unlike `cmd`, it is object-oriented:
cmdlets return .NET objects you filter and format, and it exposes the entire .NET and WMI/CIM surface.
You use it to enumerate services, tasks, ACLs, registry values, and tokens. A few reflexes:

```powershell
# Identity, groups, privileges (parse whoami, or use .NET)
whoami /all
[System.Security.Principal.WindowsIdentity]::GetCurrent() | Select Name, Groups

# Services, their binary paths and start accounts (the SCM view)
Get-CimInstance Win32_Service | Select Name, StartName, State, PathName

# A specific service's config, the sc.exe way
sc.exe qc <ServiceName>

# Registry values (autoruns, AlwaysInstallElevated)
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'

# Scheduled tasks and who runs them
Get-ScheduledTask | Select TaskName, @{n='RunAs';e={$_.Principal.UserId}}, State

# Where can I write? (ACL of a path)
Get-Acl 'C:\Program Files\VulnApp' | Format-List
```

<div class="callout warn">

**Currency — PowerShell is watched.** <span class="badge current">CURRENT</span> Modern Windows logs
PowerShell heavily: **script-block logging**, **module logging**, transcription, and **AMSI** (the
Antimalware Scan Interface) inspect what you run. Enumeration cmdlets above are benign, but on a real
engagement your PowerShell is likely recorded. This is a detection reality you must know now; 05.3 and
M15 return to it. Prefer read-only cmdlets, and never assume the shell is unobserved.

</div>

## Why the weakness exists

None of this is a bug in Windows; the model is sound. The weaknesses are **configuration under
convenience pressure**, exactly as in Linux. A vendor installs a service that runs as SYSTEM from a
path in `C:\Program Files\` but forgets the quotes around a space. An admin loosens a service's ACL so
a help-desk group can restart it, and accidentally grants reconfigure rights. `AlwaysInstallElevated`
gets set by a group policy meant to let users install a specific package. A scheduled task runs a
script from a world-writable directory. Each choice trades a little security for convenience, and the
accumulation is your attack surface. This maps to **CWE-250 (Execution with Unnecessary Privileges)**,
**CWE-269 (Improper Privilege Management)**, and **CWE-732 (Incorrect Permission Assignment for a
Critical Resource)** — the weakness classes behind nearly every finding in this module.

## How a tester recognizes it

You are looking, as always, for **the gap between who runs something and who can influence it**.
Concretely on Windows: services and tasks that run as SYSTEM whose binary, path, or configuration you
can write; token privileges (`SeImpersonate`, `SeDebug`) on your context; registry keys that configure
elevation (`AlwaysInstallElevated`, autoruns) or store secrets; and files that hold credentials
(`unattend.xml`, saved sessions, configs). The recurring shape is the same one from M04: **a
privileged actor + an input you control.**

## Manual investigation

Enumerate deliberately, and understand each command before you run it. This loop feeds the whole
module; 05.3 exploits what it finds.

```powershell
# --- Identity ---
whoami /user /groups /priv        # your SID, groups, and (critically) privileges

# --- Services: the biggest surface ---
Get-CimInstance Win32_Service | Where StartName -match 'SYSTEM|LocalSystem' |
    Select Name, PathName, StartMode        # SYSTEM services and their exe paths
# Look for: unquoted PathName with a space; a PathName under a writable dir.

# --- Scheduled tasks ---
Get-ScheduledTask | Select TaskName, @{n='User';e={$_.Principal.UserId}}
# Look for: SYSTEM/admin tasks running a script you can modify.

# --- Autoruns / installer elevation (registry) ---
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# --- Where can I write things that privileged code runs? ---
# PATH dirs, Program Files subfolders, service binary folders — check ACLs.
$env:Path -split ';'
Get-Acl 'C:\SomeDir' | Select -Expand Access

# --- Where do secrets live? ---
Get-ChildItem C:\ -Recurse -Include unattend.xml,sysprep.xml,*.kdbx,web.config `
    -ErrorAction SilentlyContinue 2>$null
reg query 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' /v DefaultPassword

# --- System info for patch-level triage ---
systeminfo   # OS build, hotfixes; feeds any kernel/known-CVE triage
```

<div class="callout method">

**The three questions per finding.** For every fact enumeration surfaces, ask: (1) *Who is the
privileged actor* (which SYSTEM/admin service, task, or token)? (2) *What input into it do I control*
(a writable binary, a writable key, an unquoted path, a preserved environment, a privilege)? (3)
*What primitive does abusing it give me* — code execution as SYSTEM, a file write, a token I can
impersonate? If you cannot answer all three, it is a **lead**, not a path. Recording leads with their
missing piece is how you avoid rabbit holes — identical to the M04 discipline.

</div>

## Tooling — what it does, key options, limits, verify by hand

Automated enumerators exist and you will use them properly in 05.3. The staples:

- **winPEAS** — the Windows sibling of LinPEAS: hundreds of checks (services, tasks, registry,
  credentials, tokens) colour-coded by likelihood. A **lead generator**, not proof.
- **PowerUp** (part of PowerSploit, and the modern **PrivescCheck** script) — PowerShell checks for
  the classic vectors (unquoted paths, weak service ACLs, `AlwaysInstallElevated`, DLL hijack
  candidates) that also *suggest* an abuse for each.
- **Sysinternals** (`accesschk.exe`, `Autoruns`, `Process Explorer`) — Microsoft-signed tools that
  answer specific questions precisely: `accesschk` reads effective permissions on services, files,
  and registry keys; `Autoruns` enumerates every auto-start location.

Two rules from day one, unchanged from Linux: **they automate the checklist you just learned — they do
not replace understanding it**, and **verify every flag by hand**. winPEAS flagging a service is a
lead; *you* confirm the binary is writable with `Get-Acl`/`accesschk` and decide whether it is a path.
Their limits: they are **noisy** (loud on disk, and PowerShell/AMSI logging catches PowerUp), they miss
context-specific paths, and dropping a large signed-or-unsigned binary may violate your RoE's stealth
clause. Prefer manual enumeration first; reach for the tool to catch what you missed.

## Demonstration (LAB ONLY): building the surface inventory

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Every command in this lesson is run on the `lab-05-win-privesc`
Windows VM on the isolated host-only network, as the synthetic `lab\lowpriv` user. Enumerating a
system you are not authorized to test — even read-only `whoami`/`Get-Service` — can exceed
authorization on a real engagement (M00). Stay in the lab; obey your RoE everywhere else.

</div>

Landing on the lab host as `lab\lowpriv`, a first pass produces facts like these (illustrative — yours
will differ):

```text
C:\> whoami /priv
SeImpersonatePrivilege        Impersonate a client after authentication   Enabled

C:\> Get-CimInstance Win32_Service | ? StartName -match SYSTEM | select Name,PathName
Name        PathName
----        --------
VulnSvc     C:\Program Files\Vuln App\service.exe
UpdaterSvc  C:\Apps\updater\upd.exe

C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    AlwaysInstallElevated    REG_DWORD    0x1
```

You do not exploit anything yet. You **inventory**: each fact becomes a row with a hypothesis and the
three-questions reasoning. `SeImpersonatePrivilege` enabled → a token-impersonation ("potato") path to
SYSTEM is likely (05.3). `VulnSvc` runs as SYSTEM from a path containing a space with no quotes → an
**unquoted service path** candidate; check whether `C:\Program.exe` or `C:\Program Files\Vuln.exe` is
writable (05.3). `AlwaysInstallElevated = 1` in *both* `HKLM` and `HKCU` → any MSI installs as SYSTEM
(05.3). That structured, reasoned list — **not a shell yet** — is this lesson's deliverable.

## Verification

An inventory is verified when each hypothesis names a concrete, testable primitive and you have noted
how you would confirm it non-destructively. "Unquoted path `VulnSvc` → check `Get-Acl 'C:\'` and
`'C:\Program Files'` for write access; if writable, plant `C:\Program.exe`" is verifiable. "VulnSvc
looks interesting" is not. You confirm the *reasoning* now; you confirm the *exploit* in 05.3.

## Impact

A correct surface inventory is the difference between a five-minute escalation and an hour of
thrashing. In report terms the inventory is your evidence trail: it shows the client exactly which
misconfigurations existed and lets you tie each later exploit (05.3) back to a specific, fixable cause.
SYSTEM on a domain-joined host is also the launch pad for M06 (dumping cached credentials, the machine
account, tickets) — which is why 05.2's authentication primer comes next.

## Remediation

<div class="callout defend">

**Reduce the surface, don't just patch exploits.** The durable fixes are structural and all reduce to
least privilege: run services and tasks as the **least-privileged account** that works (a virtual or
managed service account, `LocalService`/`NetworkService`, never SYSTEM by default); quote every
service `ImagePath` and lock down its directory and its service ACL; do **not** set
`AlwaysInstallElevated`; keep `SAM`/`SECURITY` and secrets off writable paths; and patch. Every
specific vector in 05.3 has a specific fix, but they all trace back to **CWE-250 / CWE-269 / CWE-732**
— don't grant privilege, or writable access to a privileged resource, that you don't need.

</div>

## Detection / blue-team view

<div class="callout defend">

Mass enumeration is noisy and detectable. Defenders can spot the recon that precedes escalation:
**PowerShell script-block and module logging** (Event IDs 4103/4104) capturing enumeration cmdlets;
**Sysmon** process-creation events for `whoami /priv`, `sc.exe qc`, `reg query` of installer/Winlogon
keys, and a burst of `Get-Acl`/`accesschk` calls; and winPEAS/PowerUp's characteristic file writes and
script blocks (often caught by **AMSI**). A baseline of "what normal users run" makes an enumeration
burst stand out. This activity is **reconnaissance** feeding **MITRE ATT&CK T1082 (System Information
Discovery)**, **T1033**, **T1057**, and the **T1548 / T1134** escalation tactics it precedes.

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-05-win-privesc` — an intentionally misconfigured Windows VM on the isolated
**host-only network with no Internet route** (built separately; see [`labs/vm/README.md`](../../labs/vm/README.md)
for the isolation contract and snapshot/reset). **Access:** a low-privileged `lab\lowpriv :
Lab-Passw0rd!` shell. **Goal here:** *enumerate only* — do not escalate yet. **Time:** ~50 min.
**Isolation:** verify from *inside* the VM that external egress fails before you begin. The
`LAB-FLAG-{uuid}` proof file is readable only by SYSTEM/Administrators — you are mapping the paths to
it, not taking it (that's 05.3).

</div>

Run the manual investigation loop above against the lab host. For each category — identity/privileges,
services, scheduled tasks, autoruns/registry, writable paths, readable secrets — record what you find.
Do **not** exploit anything; produce the inventory.

## Exercise

<div class="callout method">

**Situation.** You have just landed a `lab\lowpriv` shell on a Windows host during an authorized
internal engagement. Your time box for local escalation on this host is 90 minutes, and the client's
RoE forbids dropping new tools without approval — so no winPEAS unless you ask.

**Objective.** Produce a **Windows privesc surface inventory**: a structured document of the
escalation-relevant facts on this host, each paired with a hypothesis and reasoning — *not* an exploit.

**Starting information.** Only your `lab\lowpriv` shell and the manual-investigation cmdlets from this
lesson. Assume winPEAS/PowerUp are unavailable (RoE).

**Constraints.** Lab target only. Enumeration only — no escalation, no writes to system paths, no
destructive commands. Everything must be justifiable to the client, and remember PowerShell is logged.

**Expected deliverables.**
1. An inventory grouped by category (identity/privileges, services incl. run-as account & path,
   scheduled tasks, autoruns/registry incl. `AlwaysInstallElevated`, writable paths on `PATH`/Program
   Files/service dirs, readable/writable sensitive files and registry secrets).
2. For each interesting fact: the **three-questions** analysis (privileged actor / controlled input /
   primitive) and a one-line hypothesis, mapped to the 05.3 vector you suspect.
3. A **ranked** short list of the top 3 paths you would pursue first, with the reasoning for the
   ranking (reliability × effort × noise).

</div>

<details><summary>Hint 1 — conceptual direction</summary>
You are looking for "privileged actor + input you control." A SYSTEM service whose binary you
<em>cannot</em> write, or a token privilege you don't hold, is only half. Which findings have both halves?
</details>

<details><summary>Hint 2 — technique family</summary>
Group findings into: run-as-SYSTEM things you can influence (services, tasks, autoruns), token
privileges you hold (<code>SeImpersonate</code>/<code>SeDebug</code>), and installer/registry
elevation (<code>AlwaysInstallElevated</code>). Each maps to a specific 05.3 vector.
</details>

<details><summary>Hint 3 — where to look</summary>
<code>whoami /priv</code>; <code>Get-CimInstance Win32_Service</code> for run-as account and
<code>PathName</code>; <code>Get-ScheduledTask</code>; <code>reg query</code> for
<code>AlwaysInstallElevated</code> in both HKLM and HKCU; <code>Get-Acl</code>/<code>accesschk</code>
on service binaries and their folders; a recursive search for <code>unattend.xml</code>/configs.
</details>

<details><summary>Hint 4 — specific investigation direction</summary>
Rank by reliability first: a token-privilege path (<code>SeImpersonate</code>) or a writable-service
path that deterministically yields SYSTEM beats a scheduled task you must wait for, which beats a DLL
hijack that depends on a program being launched. Note the missing verification step for each half-path.
</details>

## Check yourself

<div class="callout key">

1. Why is "I'm in the local Administrators group" *not* the same as running with High integrity, and
   what mechanism causes the difference?
2. `whoami /priv` shows `SeImpersonatePrivilege: Enabled`. Why is that line, on a service account,
   arguably more valuable to you than membership in a group — and which account SID commonly has it?
3. `Get-CimInstance Win32_Service` shows a service running as `LocalSystem` with
   `PathName = C:\Program Files\Acme\svc.exe` (no quotes). What is the specific concern, and what one
   ACL check tells you whether it's exploitable?
4. Where would you look, in the registry, for (a) the list of services, (b) an autologon password,
   and (c) the `AlwaysInstallElevated` policy — and why does the last one need to be set in *two*
   places to be useful?
5. Give one technical and one engagement (RoE/detection) reason to prefer manual PowerShell
   enumeration over dropping winPEAS first.

</div>

Model answers are in `solutions/module-05.md` (instructor material — reason through them first).

## References

- **Microsoft — Access Tokens / Authorization** (`docs.microsoft.com`): *Access Tokens*,
  *SID components*, *Well-known SIDs*, *Privilege Constants* (`SeImpersonatePrivilege`,
  `SeDebugPrivilege`).
- **Microsoft — Mandatory Integrity Control** and **How User Account Control works** (and the
  official statement that UAC is *not a security boundary*).
- **Microsoft — Services** (`Win32_Service` WMI class, Service Control Manager, `sc` command) and
  **Registry Hives / structure**.
- **Microsoft — PowerShell logging** (script-block, module, transcription) and **AMSI** overview.
- **Sysinternals** — `AccessChk`, `Autoruns`, `Process Explorer` documentation.
- **MITRE ATT&CK** — **T1082** System Information Discovery, **T1057** Process Discovery, **T1033**;
  the escalation tactics they precede: **T1548** Abuse Elevation Control Mechanism, **T1134** Access
  Token Manipulation.
- **CWE-250** Execution with Unnecessary Privileges; **CWE-269** Improper Privilege Management;
  **CWE-732** Incorrect Permission Assignment for a Critical Resource.

## What you should now be able to do

- Explain the kernel/user-mode boundary and what SYSTEM (`S-1-5-18`) means to the security reference
  monitor — your Windows "UID 0".
- Read a security context: SIDs, groups, integrity level, and privileges, and predict their effect.
- Describe the SCM/service model, scheduled tasks, and how tokens are inherited.
- Navigate the registry and know which hives/keys configure elevation or store secrets.
- Use PowerShell to enumerate a Windows host methodically, knowing what each cmdlet asks the OS.
- Turn raw enumeration output into a structured, ranked Windows privesc surface inventory with
  hypotheses mapped to the 05.3 vectors.

## Progress checkpoint

```bash
py course.py complete 05.1
```
