# Instructor / solutions — Module 05

> **Instructor material.** Not linked from `_sidebar.md`. Do the exercises before reading.

Module 05 assumes a low-privileged `lab\lowpriv : Lab-Passw0rd!` shell on the `lab-05-win-privesc`
VM (isolated host-only network, no Internet route; see `labs/vm/README.md`). All work is against that
lab target only; 05.2 is deliberately non-exploitative (a reasoning module feeding M06).

---

## 05.1 — Windows for testers (surface inventory)

**Exercise (privesc surface inventory).** A strong submission groups facts by category and pairs each
with the three-questions reasoning and a suspected 05.3 vector. An illustrative inventory:

| Category | Fact | Privileged actor | Input controlled | Primitive / hypothesis (→ 05.3) |
|---|---|---|---|---|
| Privileges | `SeImpersonatePrivilege: Enabled` (service ctx) | SYSTEM auth to a local endpoint | ability to run code in the service acct + coerce SYSTEM | impersonate SYSTEM token → potato (05.3 §7) |
| Services | `VulnSvc` runs `LocalSystem`, `C:\Program Files\Vuln App\svc.exe` (unquoted, space) | SCM starting VulnSvc | possibly a writable earlier path segment | unquoted-path plant **if** prefix writable (05.3 §1) |
| Services | `UpdaterSvc` DACL grants `lowpriv` `SERVICE_CHANGE_CONFIG` | SCM starting UpdaterSvc as SYSTEM | binPath value | reconfigure binPath → SYSTEM (05.3 §2) — most reliable |
| Registry | `AlwaysInstallElevated=1` in HKLM **and** HKCU | Windows Installer | crafted MSI | any MSI installs as SYSTEM (05.3 §3) |
| Tasks | SYSTEM task runs `C:\Scripts\maint.ps1` | Task Scheduler | is the script/dir writable? | edit script → SYSTEM on trigger (05.3 §5) |
| Secrets | `unattend.xml` / Winlogon `DefaultPassword` present | — | readable file/key | plaintext creds → reuse (05.2 reuse ladder) |

**Ranking (top 3, reasoning):** (1) **UpdaterSvc weak DACL** — deterministic, immediate, no wait, no
launch dependency; verify with `accesschk -uwcqv lowpriv UpdaterSvc`. (2) **`SeImpersonate`** —
deterministic if in a service context, well-understood. (3) **`AlwaysInstallElevated`** — deterministic
but noisier (`msiexec` as SYSTEM is loud). Unquoted `VulnSvc` ranks below these because it depends on a
*writable prefix* (usually false under default `C:\`/`Program Files` ACLs); the scheduled task depends
on a trigger/wait; a DLL hijack (if any) is least reliable. Rank by reliability × effort × noise.

**Check-yourself:** (1) A local admin's default (filtered) token runs at **Medium** integrity because of
**UAC's split-token** logic; the full/High token is used only when a process elevates. So group
membership ≠ current integrity. (2) `SeImpersonate` lets you impersonate a client's token; a coerced
SYSTEM authentication then yields a SYSTEM token — it's a self-contained path to SYSTEM that group
membership isn't. `NT AUTHORITY\LocalService`/`NetworkService` and app-pool/SQL service accounts
commonly hold it (`S-1-5-19`/`S-1-5-20`). (3) The space + no quotes means `CreateProcess` tries
`C:\Program.exe` then `C:\Program Files\Acme.exe` first; the one check is **`Get-Acl`/`icacls` on those
earlier segments** — writable prefix = exploitable, otherwise hygiene-only. (4) (a) services:
`HKLM\SYSTEM\CurrentControlSet\Services`; (b) autologon: `HKLM\...\Winlogon\DefaultPassword`; (c)
Installer policy in **both** `HKLM\SOFTWARE\Policies\...\Installer` and `HKCU\...` — HKLM enables the
elevated-install policy machine-wide and HKCU opts the user in; both required. (5) Technical: you
control exactly what runs and interpret each result, avoiding winPEAS false positives; engagement:
winPEAS is loud on disk and its script blocks trip AMSI/script-block logging and may breach an RoE
"no new tools" clause.

---

## 05.2 — Authentication primer (flow analysis)

**Exercise (authentication-flow analysis).** Expected diagram: `alice`@WS01 logs on (interactive) →
opens SMB share on SRV01 → the share's app connects to `MSSQLSvc/db01` as `svc_sql`. Annotate protocol
per hop and the artifact produced. A strong exposure table:

| Artifact | Where it lives | Reusable / crackable / relayable | Mechanism | Attack (module) | Remediation |
|---|---|---|---|---|---|
| `alice` NT hash | LSASS memory on WS01 | **reusable** (password-equivalent) | NTLM auth consumes only the NT hash | Pass-the-Hash (M10/M11) | Credential Guard / RunAsPPL isolate LSASS |
| NTLM response WS01→SRV01 (if NTLM used, signing off) | on the wire | **relayable / crackable** | server never binds the response to the channel when signing off | NTLM relay (M11), offline crack (M10) | **enforce SMB signing**; prefer Kerberos |
| `alice` TGT | LSASS on WS01 | **replayable while valid** | proves KDC vouched for alice; encrypted with krbtgt key | Pass-the-Ticket (M11), Golden Ticket (M06) | Credential Guard; short lifetimes; protect krbtgt |
| Service ticket for `MSSQLSvc/db01` | any requester's memory | **offline-crackable** | encrypted with **svc_sql's password-derived key**; any user can request it | **Kerberoasting** (M06/M10) | **gMSA** (long random pw) so crack is infeasible |
| `svc_sql` key | derived from svc_sql password | crackable if password weak | human-set SPN password | Kerberoasting fallout | gMSA; least privilege on the account |

**Key teaching points to grade for:** (a) recognizing the **SQL service ticket** as the standout —
any authenticated user can request it, it's encrypted with `svc_sql`'s key, so a **human-set password
= crackable offline**; (b) correctly stating that **Credential Guard does NOT help** against
Kerberoasting (the KDC hands out the crackable ticket regardless) nor against **relay** (fixed by SMB
signing) — it blunts *LSASS-resident* PtH/PtT only; (c) **WDigest disabled** removes the
plaintext-in-memory path but not the NT hash. Reject answers that treat "Credential Guard enabled" as
covering everything.

**Check-yourself:** (1) NTLM's response is computed from only the NT hash (never the plaintext), so
holding the hash lets you complete the exchange — **pass-the-hash**. (2) Any user can request a service
ticket for any SPN; it's encrypted with the **service account's password-derived key**, so it's
offline-crackable without touching the service or holding privilege — **Kerberoasting**. (3) **TGT**:
proves the KDC authenticated you, encrypted with the **krbtgt** key, lets you request service tickets
(steal → PtT; forge → Golden Ticket). **Service ticket (TGS)**: authorizes you to one service,
encrypted with **that service account's** key, presented to the service (crackable → Kerberoasting).
(4) `SeImpersonate` lets a service impersonate a client's token — for privesc, a coerced SYSTEM token
can be impersonated to spawn SYSTEM (05.3); for credential access, impersonation/`SeDebug` opens LSASS
to read secrets (M10). (5) Credential Guard isolates LSASS secrets so the classic dump fails, and
WDigest-disabled removes plaintext — so downgrade the finding: NT hashes/TGTs in the guarded store are
not readable. Still obtainable: material from fresh interactive logons not yet protected, the machine
account, **Kerberoastable service tickets** (unaffected), and anything on hosts without Credential
Guard.

---

## 05.3 — Windows local privilege escalation

**Exercise (justified, verified escalation).** The intended "best" path on the lab VM is the **weak
service DACL** (`UpdaterSvc`, `SERVICE_CHANGE_CONFIG` for `lowpriv`) because it is deterministic and
tool-light. A complete, report-ready submission includes all four deliverables:

1. **Mechanism.** Privileged actor = the SCM launching `UpdaterSvc` as `LocalSystem`. Controlled input
   = the `binPath` value, which `SERVICE_CHANGE_CONFIG` lets `lowpriv` rewrite. Primitive = arbitrary
   command execution as SYSTEM when the service (re)starts, because the SCM runs `binPath` under the
   service's configured account. This is CWE-732 (the DACL wrongly grants config to a non-admin), not a
   Windows bug.
2. **Reproduction + verification.** `accesschk -uwcqv lowpriv UpdaterSvc` (shows `SERVICE_CHANGE_CONFIG`)
   → `sc config UpdaterSvc binPath= "cmd /c net localgroup administrators lab\lowpriv /add"` →
   `sc stop UpdaterSvc & sc start UpdaterSvc` → open a **new** session, `whoami /groups` shows
   `BUILTIN\Administrators`; elevate and `type <LAB-FLAG path>` → `LAB-FLAG-{uuid}`. (An equally valid
   variant sets `binPath` to launch a benign SYSTEM proof and reads the flag directly as SYSTEM.)
3. **Remediation + detection.** Fix: restrict the service DACL to administrators (remove
   `SERVICE_CHANGE_CONFIG` from `lowpriv`/broad groups); run the service as least privilege. Detect:
   **Event ID 7040** (start-type/config change) and process-creation of `sc.exe config`; a SYSTEM
   service child of `cmd`/`net.exe`; ATT&CK **T1543.003**.
4. **Cleanup.** Record the original `binPath` first; restore it with `sc config UpdaterSvc binPath=
   "<original>"`; remove `lowpriv` from Administrators if that variant was used; restore the snapshot.

**Acceptable alternative paths** (grade the *mechanism + verification + fix + detection*, not the
choice): unquoted `VulnSvc` **only if** the student proves a writable prefix and plants the
earlier-resolving `.exe` (CWE-428, T1574.009); `AlwaysInstallElevated` MSI (CWE-250, T1548) — must show
both hives = 1; a writable scheduled-task action (T1053.005); a `SeImpersonate` potato **explained as a
mechanism with the four steps** (do not require a weaponized PoC — conceptual justification + the
`whoami /priv` precondition is sufficient at this level); a DLL hijack **only if** they show the failed
load (Procmon `NAME NOT FOUND`) and a writable searched directory. Deduct for: claiming an unquoted path
is exploitable without a writable prefix; "I got SYSTEM" without `whoami`/flag evidence; no cleanup note;
missing either remediation or detection.

**Check-yourself:** (1) Order: `C:\Program.exe`, then `C:\Program Files\Vuln.exe`, then the intended
`C:\Program Files\Vuln App\svc.exe`. The one fact to verify: **is any earlier segment writable by you?**
(Default ACLs on `C:\` and `C:\Program Files` usually say no → not exploitable; a custom spaced dir may
be writable → exploitable.) (2) Yes — with `SERVICE_CHANGE_CONFIG` you don't need a writable binary or an
unquoted path: rewrite `binPath` to your command and (re)start; the SCM runs it as SYSTEM. The
mechanism is the config right itself. (3) HKLM enables the "install with elevated privileges" policy
for the machine; HKCU opts the current user into it. Only when **both** are `1` does an arbitrary user's
MSI install as SYSTEM — either alone does nothing. (4) A service account with `SeImpersonate` may
impersonate a client's token; a potato technique **coerces a SYSTEM process to authenticate to a local
endpoint the attacker controls**, delivering a **SYSTEM token** that the attacker is *permitted* to
impersonate (because of the privilege), then `CreateProcessWithToken` spawns a SYSTEM process. It's
impersonation working as designed, pointed the wrong way — the fix is not running untrusted code as
such an account, not "patching impersonation." (5) UAC is **not a security boundary** (Microsoft's own
stance); a bypass takes an admin's **Medium**-integrity token to **High** without a prompt — a
same-user integrity step, not standard-user→admin. Framing it as cross-user escalation overstates it.
(6) DLL hijacking depends on a specific program being launched, and safe DLL search mode / KnownDLLs /
full-path loads exclude many candidates — versus a weak-service-ACL path that fires deterministically on
demand. Confirm two facts: **the load actually fails/searches** (Procmon `NAME NOT FOUND` in an earlier
dir) and **that directory is writable by you**.
