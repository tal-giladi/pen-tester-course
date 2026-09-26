# Instructor / solutions — Module 11 (Lateral movement)

> Instructor material. Not linked from `_sidebar.md.` Do the exercises before reading.

Module 11 assumes the student already holds a valid credential (11.1) or credential *material* — an
NT hash or Kerberos ticket (11.2) — for one host and wants execution on another. All work is against
the isolated **`lab-11-lateral`** two-host credential-reuse scenario (host A, the foothold, and host
B, the objective, on a private network with no Internet route; synthetic credentials, benign
`LAB-FLAG-{uuid}`), plus the **`lab-06-ad`** VM forest for the Kerberos (PtT/overpass) paths. All
offensive content is taught as **mechanism + detection**; there are no weaponized recipes to hand
out. Grade for **mechanistic understanding, method choice justified by telemetry, and correct
event-ID-level detection**, not tool fluency.

**Scenario rule.** The concrete lab path (which ports B exposes, which credential is reused, whether
the provided artefact is a hash or a ticket) depends on the provisioning in `labs/lab-11-lateral/`.
The illustrative routes in 11.1/11.2 are *examples*, not "the answer." Reward a student who verifies
reachability and rights by hand, chooses the least-noisy sufficient method, and names the exact event
their choice generated.

---

## 11.1 — Remote execution & admin protocols

**Exercise grading.** The deliverable's value is the **justified choice**, not the shell. A strong
submission: (a) maps *reachability × rights* first — which of B's admin ports (445/135/5985/3389/22)
are open, and proof (a `\\B\C$` listing or an `nxc … (Pwn3d!)`) that the credential is admin on B;
(b) picks the least-noisy method that actually works given B's open ports **and** how B is normally
administered; (c) verifies execution with a benign command from B itself (`hostname & whoami` or the
flag), not a tool exit code; (d) names, per candidate method, the specific event ID it would generate,
and leads remediation with the control that removes the credential reuse (usually LAPS or
segmentation). Reject "I ran psexec and got a shell" with no telemetry analysis or method
justification.

**Method → wire mechanism → footprint (the table students should reconstruct):**

| Method | Wire / mechanism | Requires | Runs as | Key artefact / event |
|---|---|---|---|---|
| PsExec family (`psexec.py`) | SMB 445 → `ADMIN$` + `svcctl` named pipe on `IPC$` → create+start service | local admin, 445 | **SYSTEM** | **7045** service install; 5140/5145; dropped file |
| `smbexec.py` | same, service runs a `cmd` one-liner, output via share | local admin, 445 | SYSTEM | service per command, no dropped binary |
| WMI (`wmiexec.py`) | `Win32_Process.Create` via **DCOM/RPC** (135 + dynamic) | admin, 135+ | connecting user | **4688 parent = `WmiPrvSE.exe`**; no 7045 |
| WinRM / PS-Remoting (`evil-winrm`) | **WS-Man SOAP** over 5985/5986 → `wsmprovhost.exe` | Admins / Remote Mgmt Users, 5985 | connecting user | **4104** script-block; WinRM/Operational; no service |
| RDP | interactive graphical logon, 3389 | Remote Desktop Users, 3389 | interactive user | **4624 type 10**; 4778/4779; profile artefacts |
| SSH | shell over 22 (password or key) | valid account/key, 22 | authenticating user | `sshd` auth log; 4624 (Win OpenSSH) |

**Least-noisy reasoning.** Quietest is generally moving through the channel the environment *already*
uses: WinRM in a PowerShell-managed shop leaves 4104 but no service and no binary; WMI avoids 7045 but
is caught by `WmiPrvSE` parentage; the PsExec family is the most reliable and yields SYSTEM but is the
loudest (7045 + share access + often a file). RDP is noisiest (interactive, human-visible). "Least
noisy" is relative to the client's baseline — moving the way admins move is quieter than introducing a
never-seen method, even a technically lighter one.

**Check-yourself answers.**

1. **SYSTEM vs connecting user.** The PsExec family creates a **Windows service**, and services run in
   the **`NT AUTHORITY\SYSTEM`** context by default — the launched process inherits SYSTEM. WMI's
   `Win32_Process.Create` spawns a process **in the security context of the connecting user's remote
   session** (via `WmiPrvSE`), not as SYSTEM. So PsExec gives SYSTEM "for free"; WMI gives you only
   the rights of the account you connected with.
2. **The distinguishing event is 7045 (service installed).** The PsExec family *must* create a service
   to execute; WMI runs the process directly through the WMI provider host, so **no service is created
   and no 7045 appears**. WMI's tell is instead **4688 with parent `WmiPrvSE.exe`**. So 7045 present →
   PsExec-class; 7045 absent + `WmiPrvSE` parent → WMI.
3. **WinRM over SMB when the SOC is watching**, provided WinRM is a channel B's admins already use.
   WinRM/PS-Remoting leaves **4104 script-block logs** but *no service install and no dropped binary*,
   blending with normal administration; the PsExec-over-SMB route leaves a **7045**, `ADMIN$`/`IPC$`
   access (5140/5145), and often a file — a much louder, more attacker-shaped signature. (If WinRM is
   *not* used in the environment, the calculus flips — an out-of-baseline WinRM connection can be
   louder than expected.)
4. **LAPS** gives every machine a **unique, automatically rotated local-administrator password**, and
   therefore a unique NT hash. The "one key opens many locks" path depends on the *same* local-admin
   credential (or hash) being valid on many hosts; with LAPS the credential lifted from A simply is
   not valid on B, so credential reuse across the fleet stops at one machine.
5. **The `LogonType` field of event 4624.** SMB/WMI/WinRM network logons are **LogonType 3**
   (Network); RDP is **LogonType 10** (RemoteInteractive). (Local console interactive is type 2;
   cached/unlock differ again.)

---

## 11.2 — Credential-based movement: PtH, PtT & overpass-the-hash

**Exercise grading.** The technique is mechanically simple; the value is (a) correctly **identifying
the artefact** (32-hex NT hash vs a ticket/ccache, and for a ticket, checking validity), (b) choosing
the **matching technique** and justifying it against what the target accepts (NTLM vs Kerberos), (c)
authenticating to B **with no plaintext** and proving it from B (hostname/whoami/flag), and (d) a
**detection** section with the right event IDs *and* the honest note that these are reuse-pattern and
harvest-protection controls, not a way to make a valid credential invalid. Critically, grade whether
the student can **explain the mechanism** — NTLM computing its response from the hash, the hash *being*
the Kerberos key for overpass, Kerberos honouring an issued ticket for PtT — not just that the command
ran. Reward a student who cracked *nothing* and says so as the alarming point.

**The three artefacts, two protocols (the core distinction):**

| Technique | Artefact fed | Fed to | Result / telemetry on target |
|---|---|---|---|
| **Pass-the-hash** | NT hash | **NTLM** (SMB/WMI/WinRM/LDAP) | authenticates as user; **4624 type 3, NTLM**; 4776 |
| **Overpass-the-hash** | NT hash (= Kerberos key) | **KDC** → real TGT, then Kerberos | genuine TGT; **4768 RC4/`0x17`** with no interactive logon; then normal Kerberos |
| **Pass-the-ticket** | existing TGT or TGS | **Kerberos** (inject into session) | acts as ticket owner for its lifetime; forged TGT → **4769 with no 4768** |

**Check-yourself answers.**

1. **The NTLM response is computed as a function of the NT hash and the server challenge — the
   plaintext is never an input.** So although the password/hash never crosses the wire, anyone
   *holding* the hash can compute a valid response and complete the exchange as the user, with no
   cracking. The hash is "password-equivalent." The attack is **pass-the-hash**.
2. **Same NT hash; different consumer.** Pass-the-hash feeds the hash to **NTLM** and produces an NTLM
   logon (4624 type 3, NTLM package; 4776). Overpass-the-hash feeds the hash to the **KDC** as the
   user's Kerberos key to obtain a **real TGT**, after which everything looks like normal Kerberos.
   Telemetry difference: PtH → NTLM logons (loud in a Kerberos-first domain, caught by NTLM
   restrictions); overpass → a **4768 TGT request, often RC4/`0x17`, with no preceding interactive
   logon**, then ordinary 4769 service-ticket activity. Overpass exists precisely to avoid the NTLM
   signature.
3. **Kerberos trusts previously issued tickets and does not re-check the password on use**, so a
   valid injected ticket is honoured with no secret at all. The ticket must be **still valid** (not
   expired; a TGT to request further service tickets, or the correct TGS for one service). It must be
   **name-based**: Kerberos authenticates to a **SPN/FQDN**, so targeting a bare **IP** causes a
   fallback to NTLM (defeating the point) — you must use the host's name.
4. **Credential Guard most affects pass-the-hash and hash-based overpass**, because it VBS-isolates
   the **NT hashes and TGTs in LSASS**, so the classic harvest that produces the hash/TGT fails —
   no material, no reuse. It does **not** protect **local SAM** account hashes, cannot retract a
   **ticket already exported** before protection, and does not cover every logon type — so a
   **local-account hash** (e.g. from SAM) or an **already-stolen ticket** may still be reusable, and
   PtT with a pre-harvested ticket is largely unaffected.
5. **Overpass-the-hash** (a hash used as a Kerberos key to mint a TGT) — a TGT request appearing
   without a keyboard/interactive logon behind it, downgraded to RC4, is the signature. An attacker
   avoids the RC4 tell by using the account's **AES key** instead of the RC4 (NT-hash) key, producing
   an AES-encrypted TGT that blends with normal Kerberos — which is why detection must also baseline
   *which hosts request TGTs for which accounts*, not rely on RC4 alone.

---

## Cross-lesson grading notes

- **Safety.** Every submission must restate LAB TARGET vs REAL SYSTEM and confirm **per-destination
  scope** before authenticating to a host — reusing a credential/material that "happens to work" on an
  out-of-scope in-network host is a scope violation, and this is a teachable point, not a technicality.
- **Verification discipline.** Accept a move as proven only with **evidence from the target** (its
  hostname/whoami or the flag), never a tool's success message.
- **Detection is half the grade.** For every technique the student must name the concrete event ID(s)
  and the ATT&CK mapping (**T1021** family for 11.1; **T1550.002/.003**, **T1558**, **T1003** for
  11.2). A finding without detection + remediation is incomplete, per the course standard.
- **Remediation altitude.** Lead with the control that removes the *reuse* (LAPS, tiering,
  segmentation, Credential Guard/Protected Users), not with "reset the password" — the whole module's
  point is that the plaintext is irrelevant.
