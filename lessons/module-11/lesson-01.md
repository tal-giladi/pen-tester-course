# 11.1 — Remote execution &amp; admin protocols: SMB/PsExec, WMI, WinRM, PowerShell Remoting, SSH &amp; RDP

<div class="prereq">

**Prerequisites:** [M00](../module-00/lesson-01.md) (authorization; the confused deputy in
[00.3](../module-00/lesson-03.md)), [05.2](../module-05/lesson-02.md) (NTLM/Kerberos, SMB/WinRM,
access tokens — the protocols underneath every method here), [06.4](../module-06/lesson-04.md)
(credential reuse as the connective tissue of an attack path), and [M10](../module-10/lesson-01.md)
(where the credentials you move with come from). Moving with credential *material* — the hash or
ticket rather than the password — is the next lesson, [11.2](lesson-02.md).
**Module:** M11 Lateral movement. **Difficulty:** 🔴 advanced.
**M11 assumes** you already hold a valid credential for one host and want execution on another. This
lesson is the *catalogue of legitimate remote-admin channels* an authenticated principal moves
through, and what each looks like on the wire and in the defender's logs.
**You will produce:** for one credential valid on host A, a justified choice of the least-noisy
remote-execution method that reaches host B in the lab, with the protocol mechanism and the exact
telemetry it generates written up as a finding.

</div>

## Why this matters

An initial foothold is one host. Every objective worth the engagement — the file server, the
database, the domain controller, the crown-jewel data — lives somewhere else. **Lateral movement is
how a single compromise becomes an enterprise compromise**, and the instructive thing about it is
that the primary methods are not exploits. They are the *same remote-administration protocols the
sysadmins use every day*: service control over SMB, WMI, WinRM/PowerShell Remoting, SSH, RDP. A
principal authenticates with a credential and asks the target to run something — exactly as a
help-desk technician would. There is usually no memory-corruption bug involved, which is precisely
why lateral movement is hard to prevent and why the defender's whole job is *telling authorized
administration apart from an intruder's*.

For you as a professional, the skill is not "run a tool." It is **choosing** among a menu of
protocols by weighing what each requires (which credential, which privilege, which port) against
what each costs (footprint on disk, artefacts in the event log, how loudly it announces itself). A
tester who understands the wire protocol underneath each method can pick the quiet one *and* tell
the client exactly which event ID would have caught them — the second half is what the report is
paid for.

## Learning objectives

By the end you can:

- Explain what each remote-execution method does **on the wire** — SMB named pipes and service
  control (PsExec family), WMI `Win32_Process.Create` over DCOM, WinRM/WS-Man SOAP, PowerShell
  Remoting over WinRM, SSH, and RDP.
- State what each method **requires** (credential, privilege level, open port) and its **trade-offs**
  (disk footprint, service/process artefacts, log signature).
- Use NetExec and the Impacket exec scripts as *mechanism demonstrations*, and verify remote
  execution by hand.
- Move host-to-host by **credential reuse** — the same local-admin or domain credential valid on
  more than one machine — and justify the least-noisy path.
- For every method, give the **remediation** and the **detection** with concrete Windows event IDs.

## Intuition

You hold a key that opens host A. Lateral movement asks a simple question: **where else does this
key work, and once it does, how do I make that host run a command?** The second half is the
surprise — you rarely need an exploit, because operating systems ship *designed-in* ways for an
administrator to run code on a machine remotely. Windows alone offers several (service control, WMI,
WinRM, RDP); Linux offers SSH. Each is a legitimate front door with a lock; a reused key fits the
lock. The confused deputy from [00.3](../module-00/lesson-03.md) reappears: the remote-admin service
runs as SYSTEM/root and acts on the authenticated request of anyone who proves they hold an admin
credential — it cannot tell the real admin from an intruder.

So the craft is about *choice*. The loudest method leaves a service and a file behind but is
reliable and yields SYSTEM; the quietest reuses an existing management channel and blends into normal
administration. Knowing the mechanics lets you trade reliability for stealth deliberately, and lets
you explain the trade to a defender in terms of the exact artefact each choice leaves.

## The underlying technology

Every method below is **authenticate, then invoke**. Authentication uses NTLM or Kerberos
([05.2](../module-05/lesson-02.md)); the invocation differs per protocol, and the telemetry follows
from the invocation.

### SMB + service control — the "PsExec" family <span class="badge found">FOUNDATIONAL</span>

The original Sysinternals *PsExec* and its offensive re-implementations rest on one fact: **SMB
(TCP 445) exposes not just file shares but the machinery of remote administration.** After an
NTLM/Kerberos logon to a target, an administrator can reach the hidden `ADMIN$` share (which maps to
`C:\Windows`) and drive the **Service Control Manager** through the `svcctl` **named pipe** on
`IPC$`. Conceptually the method places an executable (or a `cmd.exe` command line) where the SCM can
launch it, registers it as a service, and starts it; the service's standard I/O is relayed back over
a named pipe, and the service is removed afterward.

The essential properties, which are what you reason about:

- **Requires** local-administrator rights on the target (SCM and `ADMIN$` demand it) and SMB 445
  reachable.
- **Yields** execution as `NT AUTHORITY\SYSTEM`, because Windows services run in that context.
- **Costs** the loudest footprint of any method: a **service-install event (7045)** in the System
  log, **share access to `ADMIN$`/`IPC$`** (5140/5145), and frequently a **file dropped** under
  `C:\Windows`. The lower-footprint variant that runs a `cmd` one-liner avoids the dropped binary but
  still creates a service per command.

That "service install as SYSTEM from a remote logon" signature is the canonical detection, and it is
why this family is reliable but noisy.

### WMI — `Win32_Process.Create` over DCOM <span class="badge current">CURRENT</span>

**Windows Management Instrumentation** is the management API for querying and controlling Windows.
Remotely it rides **DCOM over RPC** (TCP 135 endpoint mapper, then a negotiated high port). The
process-execution path invokes the **`Create` method of the `Win32_Process` class** — a WMI
`__ExecMethod` call — to spawn a process on the target; output is read back over an SMB share.

- **Requires** admin rights and RPC/DCOM reachable (135 plus the dynamic range, or a fixed port).
- **Costs** *no service creation and no binary drop* for the execution itself — so **no 7045**. The
  tell-tale artefact is a **process-creation event (4688)** whose **parent process is
  `WmiPrvSE.exe`** (the WMI provider host), plus the output file on a share. That parentage is
  exactly how defenders distinguish WMI execution from a locally launched process.
- The spawned process runs as the **connecting user**, which is often *not* SYSTEM — a functional
  difference from the PsExec family worth noting when SYSTEM is the goal.

### WinRM and PowerShell Remoting — WS-Man SOAP <span class="badge current">CURRENT</span>

**WinRM** is Microsoft's implementation of **WS-Management**, a SOAP-over-HTTP protocol, listening on
**TCP 5985 (HTTP)** or **5986 (HTTPS)**. **PowerShell Remoting** (`Enter-PSSession`,
`Invoke-Command`) is the most common consumer: it opens a WS-Man shell and runs commands inside a
`wsmprovhost.exe` host process on the target. Membership in the local **Administrators** or **Remote
Management Users** group is required, and the WinRM service must be listening (it is enabled by
default on modern Windows Server).

- **Requires** WinRM listening (5985/5986) and an account permitted to connect.
- **Costs** a comparatively *quiet* footprint at the OS level — no service install, no dropped
  binary — which is why it is a favourite for blending in. But it is *very* visible to anyone who
  logs PowerShell: **script-block logging (Event ID 4104)**, module logging, and the
  `Microsoft-Windows-WinRM/Operational` channel capture the activity in detail. On the wire it is
  HTTP(S) to 5985/5986, easy to spot where WinRM is not normally used.

The offensive client you will see is `evil-winrm`; it is an ordinary WS-Man client that authenticates
and opens a remoting shell — the same protocol PowerShell uses, so its footprint is PowerShell
Remoting's footprint.

### SSH and RDP — the interactive channels <span class="badge current">CURRENT</span>

- **SSH (TCP 22)** is the standard remote-admin channel on Linux and, increasingly, on Windows
  (OpenSSH is a Windows feature). It authenticates with a password or a key and gives an interactive
  or scripted shell as the authenticating user. Lateral movement via SSH is often *key reuse* — a
  private key harvested on host A that is an authorized key on host B — or an agent-forwarding chain.
  Telemetry: `sshd` auth logs (`/var/log/auth.log`, `journald`), and on Windows the OpenSSH
  operational log plus **4624 logon type** entries.
- **RDP (TCP 3389)** is interactive graphical logon. It requires membership in **Remote Desktop
  Users** (or admin) and produces the most human-visible footprint of all — an interactive session,
  **logon type 10** (RemoteInteractive) in event **4624**, and profile/artefact creation on the
  target. It is the noisiest for execution but sometimes the only channel available, and credential
  reuse over RDP is common where an admin re-uses one password across desktops.

### Credential reuse — why one key opens many locks

The connective tissue ([06.4](../module-06/lesson-04.md)) is that the *same* credential is frequently
valid on many hosts: a shared **local-administrator** password imaged onto every workstation, or a
**domain** account that is admin on a fleet of servers. None of the methods above is interesting on
its own; they become lateral movement when a credential lifted from A also authenticates to B. This
is why the reuse ladder from [05.2](../module-05/lesson-02.md) matters — and why the next lesson shows
you can spend the *hash or ticket* directly, without ever recovering the password.

## Why the weakness exists

None of this is an implementation bug. It is the **designed** behaviour of remote administration
plus two structural weaknesses: **shared/reused credentials** (a local-admin password common to many
machines, an over-privileged domain account) and **flat networks** where 445/135/5985/3389 are
reachable host-to-host. The relevant weaknesses are **CWE-522** (insufficiently protected /
reusable credentials) and the class of **improper privilege management (CWE-269)** that leaves a
credential admin on far more hosts than it needs. The protocols are doing exactly what they were
built to do; the environment made one key open every door.

## How a tester recognizes it

- **A credential that is local admin on more than one host** (spray it read-only to find out — see
  Tooling). One reused local-admin password across a fleet is the classic lateral-movement enabler.
- **Reachable admin ports host-to-host**: 445 (SMB), 135 + dynamic (WMI/DCOM), 5985/5986 (WinRM),
  3389 (RDP), 22 (SSH). A flat network where these are open between peers is a lateral-movement
  fabric.
- **Which method the environment already uses** — moving through the channel admins normally use
  (WinRM in a PowerShell-managed shop) is quieter than introducing a new one (PsExec where services
  are never installed remotely).

## Manual investigation

Before any tool, reason it out:

```text
# Which of my credentials is admin WHERE? (map reachability + rights before moving)
#  - list target hosts and the ports open between them (445/135/5985/3389/22)
#  - for each candidate credential, note the account type: local admin vs domain, and its scope
# Verify admin on a target by reading an admin-only share by hand, e.g. the C$ administrative share:
#   (a successful directory listing of \\B\C$ proves local-admin-equivalent access on B)
```

The point is to establish *reachability × rights* per host before you make noise, and to record the
smallest evidence that proves access (a `C$` listing, a returned hostname) rather than launching a
payload.

## Tooling — what it does, key options, limits, verify by hand

<div class="callout method">

- **NetExec (`nxc`)** — the successor to CrackMapExec: sprays one credential across many hosts and
  many protocols (`nxc smb`, `nxc winrm`, `nxc wmi`, `nxc ssh`, `nxc rdp`) to answer "where is this
  credential valid, and where is it admin?" A `(Pwn3d!)` marker means local admin on that host. Key
  options: `-u`/`-p` (or `-H` for a hash, next lesson), `--local-auth` for local (non-domain)
  accounts, `-x`/`-X` to run a command once you have admin. *Limit:* every authentication is logged
  on every target — spraying is inherently noisy; scope it. *Verify:* confirm a `(Pwn3d!)` by reading
  `\\host\C$` yourself.
- **Impacket exec scripts** — `psexec.py` (service-based, SYSTEM), `smbexec.py` (service-based,
  lower disk footprint), `wmiexec.py` (WMI/DCOM, `WmiPrvSE` parent), `atexec.py` (Task Scheduler).
  Each is a *mechanism demonstration* of one protocol above; the value is understanding which
  artefact each leaves, not the invocation. *Limit:* each maps to a distinct, well-known detection.
- **`evil-winrm`** — a WS-Man/PowerShell-Remoting client; footprint = PS-Remoting's footprint
  (4104 script-block logs). *Limit:* useless if WinRM isn't listening or the account lacks remoting
  rights.
- **Native tools** — the honest baseline: `Enter-PSSession`/`Invoke-Command` (WinRM), `wmic`/`Get-CimInstance`
  (WMI), `sc.exe`/`services.msc` (services), `mstsc` (RDP), `ssh`. Using built-ins is quieter than
  dropping tooling and is often how a careful tester moves.

</div>

Always **verify by hand**: after any remote execution, prove it with a benign, unmistakable result —
the target's hostname and current user (`hostname`, `whoami`) or the presence of the lab flag —
rather than assuming success from a tool's exit code.

## Exploitation / demonstration (LAB ONLY)

<div class="callout attack">

**Technique — credential reuse to reach host B, choosing the quietest sufficient method.** Given a
credential proven valid on host A, first map where else it is admin, then move through the channel
that fits the environment. Illustratively, in the lab:

```text
# 1) Map: where is this credential local admin? (read-only discovery)
nxc smb 10.11.0.0/24 -u svc_ops -p '<lab-pw>' --local-auth
#   -> host B (10.11.0.20) returns (Pwn3d!)  = svc_ops is local admin on B

# 2) Verify admin by hand before executing anything:
#    list \\10.11.0.20\C$  -> a directory listing proves admin-equivalent access

# 3) Move via the channel B's admins already use (say WinRM), and prove execution benignly:
nxc winrm 10.11.0.20 -u svc_ops -p '<lab-pw>' -x "hostname & whoami"
#   -> returns B's hostname + the account context = execution confirmed
```

Why this order: discovery (1) tells you *where* the key works; hand verification (2) confirms rights
without a payload; the execution (3) is a single benign command through the least-noisy channel that
is actually available. Had only 445 been open, the PsExec family would apply — at the cost of a 7045
service-install event you would document as the trade-off.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Every command above targets the isolated `lab-11-lateral` two-host
scenario (host A and host B on a private network with no Internet route), using **synthetic**
credentials and the benign `LAB-FLAG-{uuid}`. Running any of this against a system you do not own and
are not explicitly authorized to test — including using a credential that "happens to work" on a host
outside your scope — is a crime ([M00](../module-00/lesson-01.md)) and a scope violation even when the
target belongs to your client's network. Restate scope and authorization before moving to any host,
and confirm each destination is in scope *before* you authenticate to it.

</div>

## Verification

Remote execution is verified only by **evidence from the target itself**: the command you ran
returned host B's `hostname` and the expected account from `whoami`, or produced the lab flag that
exists only on B. A tool reporting "success" is a claim; the target's own output is the finding.
Record, per hop, the method used, the credential and its type, the returned proof, and — because it
is half the deliverable — the event the method generated on the target (below).

## Impact

One reused credential plus one reachable admin port converts a single-host foothold into control of
every host that credential opens. In a flat network with a shared local-admin password, that can be
the entire workstation fleet from one machine; with an over-privileged domain account, a room full of
servers. Lateral movement is also the setup for the next escalations — a host you reach may hold a
privileged user's session whose credential material you can harvest ([06.4](../module-06/lesson-04.md),
[M10](../module-10/lesson-01.md)), turning "admin on B" into "admin everywhere." Frame the finding as
**blast radius of the reused credential**, not as "we ran a command."

## Remediation

<div class="callout defend">

- **Kill shared local-admin passwords** with **Windows LAPS** (a unique, rotated local-admin password
  per machine) — this single control breaks the most common lateral-movement path, because a
  credential lifted from A no longer opens B.
- **Least privilege and tiering** ([06.4](../module-06/lesson-04.md)): domain admin credentials never
  log on to lower-tier hosts; service and admin accounts are admin only where they must be. This
  shrinks *where* any key works.
- **Segment the network**: block 445/135/5985/3389/22 host-to-host where peers have no reason to
  administer each other; allow admin protocols only from designated management hosts (PAWs). A flat
  network is the fabric lateral movement rides.
- **Disable or restrict unused channels**: turn off WinRM/RDP where not needed; restrict who is in
  *Remote Management Users*, *Remote Desktop Users*, and local Administrators.
- **Enforce signing/authentication hardening** ([05.2](../module-05/lesson-02.md)) so credentials
  cannot be relayed onto these services, and prefer Kerberos over NTLM.

</div>

## Detection / blue-team view

<div class="callout defend">

- **Logon telemetry (all methods):** **Event ID 4624** with **LogonType 3** (network — SMB/WMI/WinRM)
  or **LogonType 10** (RemoteInteractive — RDP), and **4672** (special privileges assigned) when the
  logon is admin. One account authenticating to many hosts in quick succession is the lateral-movement
  signal regardless of method.
- **PsExec family:** **7045** (a service was installed) in the System log, especially with a random
  service name from a remote logon; **5140/5145** (network share `ADMIN$`/`IPC$` access) and
  **4688** (process creation) for the launched service — `services.exe` spawning an unexpected child
  as SYSTEM.
- **WMI:** **4688** with **parent `WmiPrvSE.exe`**; the `Microsoft-Windows-WMI-Activity/Operational`
  log records remote `Win32_Process.Create` calls.
- **WinRM / PowerShell Remoting:** **4104** (PowerShell script-block logging), module logging, and the
  `Microsoft-Windows-WinRM/Operational` channel; a `wsmprovhost.exe` process spawning children is the
  host-side tell. Unusual HTTP to 5985/5986 on the wire.
- **RDP:** **4624 LogonType 10** and **4778/4779** (session connect/disconnect); interactive session
  and profile artefacts on the target.
- **SSH (incl. Windows OpenSSH):** `sshd` auth records; on Windows the OpenSSH operational log plus
  4624. Watch for key-based logons from unexpected sources (harvested-key reuse).

Map to **MITRE ATT&CK T1021** Remote Services — **.002** SMB/Windows Admin Shares, **.003** DCOM
(WMI), **.006** WinRM, **.001** RDP, **.004** SSH — plus **T1569.002** (Service Execution, the PsExec
service) and **T1570** (Lateral Tool Transfer, the dropped binary). The recurring detection idea:
*authenticated remote execution is normal for admins from management hosts; the same activity from a
workstation, at odd hours, or fanning out to many peers is the anomaly.*

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-11-lateral` (built separately) — a **two-host credential-reuse scenario**
(host A, your foothold, and host B, the objective) on an **isolated private network with no Internet
route**. **Access:** a foothold shell / credential on host A; a credential that is *also* valid on
host B is discoverable from A. **Targets:** host B only; the `LAB-FLAG-{uuid}` on B is retrievable
only after you gain execution there. **Time:** ~75 min. **Isolation:** verify external egress fails
first; reset per the lab README between attempts (service installs and dropped files persist). The
scenario deliberately exposes more than one admin port on B so you must *choose* a method.

</div>

Map where your host-A credential is admin, verify by hand, then gain execution on host B through the
**least-noisy method that actually works** given B's open ports — and write down the event ID your
choice generated on B. Then, for practice, reach B a second way and contrast the telemetry.

## Exercise

<div class="callout method">

**Situation.** Authorized internal engagement. You hold a foothold on host A and a credential that is
valid there. Host B (the objective, holding the flag) is reachable; the client's SOC is watching, so
noise matters.

**Objective.** Determine where your credential is also valid, gain **execution on host B** by
credential reuse, and do it with the **least-noisy remote-execution method that works** — then
justify the choice against the alternatives.

**Starting information.** The host-A credential and network access to B. No pre-chosen method.

**Constraints.** Lab targets only; confirm B is in scope before authenticating to it. Verify admin by
hand before executing. Prefer built-in/quiet channels; if you must use a noisier one, say why the
quieter ones were unavailable. No destructive actions; note any artefact you leave (a service, a
file) and how you would clean it up.

**Expected deliverables.**
1. The **reachability × rights map**: which ports B exposes, and the proof (a `C$` listing or `nxc`
   `(Pwn3d!)`) that your credential is admin on B.
2. The **method chosen** and its **wire mechanism** (what it does on 445 / 135 / 5985 / 3389 / 22),
   with the **benign verification** from B itself (hostname/whoami/flag).
3. A **trade-off justification**: why this method over the others, in terms of footprint and the
   specific event ID each would have generated.
4. **Remediation** (LAPS / tiering / segmentation as they apply here) **and** **detection** (the exact
   event IDs on B, mapped to ATT&CK) — both required.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Movement is <em>reachability × rights</em>. Before choosing a method, answer two questions: which of
B's admin ports are open, and is your credential actually admin on B? Prove both before making noise.
</details>

<details><summary>Hint 2 — technique family</summary>
Match method to what B exposes and how B is normally administered. WinRM/PS-Remoting is quiet where
admins already use it (4104, no service); WMI leaves a <code>WmiPrvSE</code>-parented process and no
7045; the PsExec family is reliable and gives SYSTEM but installs a service (7045).
</details>

<details><summary>Hint 3 — where to look</summary>
Use <code>nxc</code> read-only first to find where the credential is <code>(Pwn3d!)</code>. Then pick
the method whose telemetry you can live with, and confirm execution with a single benign command
(<code>hostname &amp; whoami</code>) rather than a payload.
</details>

<details><summary>Hint 4 — the deliverable</summary>
The finding is the <em>justified choice</em>, not the shell. For each candidate method, name the event
ID it produces on B; lead your remediation with the control (usually LAPS or segmentation) that would
have stopped the credential reuse in the first place.
</details>

## Check yourself

<div class="callout key">

1. PsExec-style execution yields `NT AUTHORITY\SYSTEM`, but WMI (`Win32_Process.Create`) typically
   runs as the connecting user. Why the difference, mechanically?
2. Which single event ID most reliably distinguishes the PsExec family from WMI execution, and why
   does WMI *not* produce it?
3. You have a domain credential that is admin on B. WinRM (5985) and SMB (445) are both open. Which do
   you choose if the SOC is watching, and what artefact does each leave?
4. Explain how **LAPS** breaks the most common lateral-movement path, in terms of "one key opens many
   locks."
5. RDP and SMB logons both appear in event 4624. What field tells them apart, and what value does each
   produce?

</div>

Model answers are in `solutions/module-11.md` (try them before looking).

## References

- **Microsoft** — *SMB protocol* and administrative shares (`ADMIN$`/`IPC$`); *Service Control
  Manager*; **[MS-WMI]/[MS-WMIO]** and `Win32_Process.Create`; *WinRM / WS-Management* and
  *PowerShell Remoting (about_Remote)*; *Remote Desktop Services*; *OpenSSH for Windows*; **Windows
  LAPS**; *Enterprise Access Model / tiered administration*.
- **Sysinternals PsExec** documentation (the original, for the legitimate mechanism).
- **Impacket** — `psexec.py`, `smbexec.py`, `wmiexec.py`, `atexec.py` (reference implementations of
  each protocol's exec path).
- **NetExec (`nxc`)** documentation — protocol modules and credential validation/spraying.
- **MITRE ATT&CK** — **T1021** Remote Services (.001 RDP, .002 SMB/Admin Shares, .003 DCOM, .004 SSH,
  .006 WinRM); **T1569.002** Service Execution; **T1570** Lateral Tool Transfer; **T1078** Valid
  Accounts.
- **CWE-522** Insufficiently Protected Credentials; **CWE-269** Improper Privilege Management.

## What you should now be able to do

- Explain, on the wire, what SMB/PsExec, WMI, WinRM/PS-Remoting, SSH, and RDP each do to run a command
  remotely, and what each requires.
- Choose among them by trading footprint against reliability, and justify the choice by the exact
  event ID each leaves.
- Move host-to-host by credential reuse, verifying rights and execution by hand.
- Write the remediation (LAPS, tiering, segmentation) and the ATT&CK-mapped detection for every method.

## Progress checkpoint

```bash
py course.py complete 11.1
```
