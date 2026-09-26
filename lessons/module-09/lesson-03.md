# 09.3 — Modern mitigations &amp; what defeats them: ASLR, DEP/NX, stack canaries, PIE, CET — and ROP concepts

<div class="prereq">

**Prerequisites:** [09.1](lesson-01.md) (memory model, registers, calling conventions) and
[09.2](lesson-02.md) (the end-to-end stack smash — offset, control of RIP, shellcode, bad chars).
[M00](../module-00/lesson-01.md) authorization applies. **C/asm literacy** helps for the ROP section.
**Module:** M09. **Difficulty:** 🔴 advanced.
**You will produce:** given a binary's `checksec` output, a written analysis of which classic
techniques still work, which are dead, and *what additional primitive* (e.g. an info leak) you'd need
next — an honest exploitability assessment, not an exploit.

</div>

## Why this matters

The clean 32-bit smash of 09.2 does **not** work against a modern default target — and understanding
*why* is the single most useful thing this module teaches a professional tester. Clients don't run
`-z execstack -no-pie -fno-stack-protector` binaries; they run hardened ones. Your job is to explain
what their defenses stop, what they *don't*, and — crucially — that a memory bug on a modern target is
usually **not** a turnkey exploit but the *first primitive* in a chain that may or may not be
completable in the engagement's time box.

This lesson is also where memory-corruption knowledge pays off for **defense**. Every mitigation here
is something you can *recommend and verify* on a client's build. "The service has a stack overflow"
becomes "…and it ships without PIE or full RELRO, which turns a bug that should be hard to exploit
into an easy one — here's the compiler flag to fix it." That is a report finding a client can act on.

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Any hands-on work stays on `labs/lab-09-exploit` in its **isolated,
no-egress sandbox**, with benign `LAB-FLAG-{uuid}` / local-shell payloads only. The bypasses here are
taught **conceptually** — this lesson deliberately does **not** hand you a working modern exploit,
because building reliable bypass chains against real software is weaponization, out of this course's
scope, and only lawful against systems you own or are authorized to test (authorized research / CTF /
defense). We build *understanding*.

</div>

## Learning objectives

- Explain what each mitigation does, what attack it stops, and its limits: **DEP/NX**, **ASLR**,
  **PIE**, **stack canaries (SSP)**, **RELRO**, **CET / shadow stacks**.
- Read `checksec` output and translate it into an exploitability judgement.
- Describe the **conceptual bypass class** for each: NX → **ROP**; ASLR/PIE → **info leak**; canary →
  **leak or brute-force**; and why bypasses **compose** (you usually need several).
- Explain **Return-Oriented Programming** — gadgets, the `ret`-chained sequence, `pop rdi; ret` to
  set arguments — with a tiny conceptual example.
- Give the honest framing: modern exploitation is **chains of primitives**, and "not exploitable in
  the time we had, but here's the missing primitive" is a legitimate professional conclusion.

## Intuition

09.2 worked because three things were true at once: the stack was **executable** (you could run
shellcode there), addresses were **fixed** (you knew where `win()`/the stack was), and nothing
**checked** whether the return address had been tampered with. Each modern mitigation removes exactly
one of those gifts:

- **NX** makes the stack non-executable → your shellcode won't run *as data*. Answer: don't inject
  code, **reuse existing code** (ROP).
- **ASLR/PIE** randomizes where everything is → you no longer *know* addresses. Answer: **leak** one
  at runtime to de-randomize.
- **Canary** puts a secret guard between the buffer and the return address → an overflow is *detected*
  before `ret`. Answer: **leak** the canary or don't smash linearly.

The theme: modern defenses don't make bugs unexploitable, they make you need **more information and
more steps**. Exploitation becomes assembling primitives, and each mitigation adds a primitive you
must first obtain.

## The underlying technology — each mitigation

### DEP / NX (No-eXecute) &nbsp;<span class="badge current">CURRENT</span>

**What it does.** Marks memory pages **either writable or executable, never both** (W^X). The stack
and heap are writable → therefore **not executable**. Enforced in hardware (the NX bit) and by the OS
(Linux since the mid-2000s; Windows "DEP").

**What it stops.** The classic 09.2 finale — shellcode placed on the stack and jumped to — **dies
here**. The CPU refuses to execute instructions from a no-execute page. <span class="badge
deprecated">DEPRECATED</span>: "drop shellcode on the stack and `ret` into it" is not viable on any
modern default target.

**Conceptual bypass — ROP.** You can still *control RIP*; you just can't run injected code. So reuse
**code that already exists** in the executable and its libraries (which *are* executable) — see the
ROP section below. NX changed the shape of exploitation from "inject code" to "reuse code."

### ASLR &nbsp;<span class="badge current">CURRENT</span>

**What it does.** **Address Space Layout Randomization** places the stack, heap, and shared libraries
(and, with PIE, the executable itself) at **random base addresses** each run. On Linux, controlled by
`/proc/sys/kernel/randomize_va_space` (`0` off, `1` conservative, `2` full — the default).

**What it stops.** Hardcoded addresses. The ret2win of 09.2 assumed `win()` sat at a fixed
`0x080491d6`; under ASLR+PIE that address changes every execution, so a baked-in address is wrong
almost always.

**Conceptual bypass — information leak.** Randomization hides addresses; it doesn't *change the
layout within a region*. If you can make the program **reveal one runtime address** — a leaked stack
pointer, a libc function address from the GOT, a format-string read — you learn the base and can
compute every other address by fixed offset. **No leak, no reliable modern exploit.** (Limits:
32-bit ASLR has little entropy and was historically brute-forceable; 64-bit has enough that
brute force is impractical → you need a real leak.)

### PIE &nbsp;<span class="badge current">CURRENT</span>

**What it does.** **Position-Independent Executable** — compiles the *main binary* so it, too, can be
loaded at a random base (ASLR for the executable's own code/data, not just libraries). Built with
`-fPIE -pie`.

**What it stops.** Leaking a libc address no longer suffices to find the binary's own gadgets/
functions, because the binary itself moved. Without PIE, the executable is at a fixed base even when
libraries are randomized — a big gift to an attacker (fixed gadgets, fixed `win()`).

**Conceptual bypass.** A leak of an address **within the binary** yields the binary's base; a libc
leak yields libc's base. Under full PIE+ASLR you typically need a leak for *each* region you want to
use. This is why non-PIE binaries are flagged as a finding: they hand the attacker a fixed code base
for free.

### Stack canaries / SSP &nbsp;<span class="badge current">CURRENT</span>

**What it does.** The **Stack-Smashing Protector** places a random secret value — the **canary** (or
"stack cookie") — between the local buffers and the saved return address in the prologue, and checks
it in the epilogue *before* `ret`. If a linear overflow overwrote the return address, it also
overwrote the canary; the mismatch triggers `__stack_chk_fail` and the process aborts. Built with
`-fstack-protector-strong`.

```text
low addr   │  buf[64]              │  ← overflow writes forward
           │  ...                  │
           │  CANARY  (secret)     │  ← checked before ret; overwrite → abort
           │  saved EBP/RBP        │
 target →  │  saved RET            │
high addr  └───────────────────────┘
```

**What it stops.** The straight-line stack smash of 09.2: you cannot reach the return address by
overrunning the buffer without clobbering the canary, and the check aborts before your hijack takes
effect.

**Conceptual bypass — leak or bypass, not brute force (on 64-bit).**
- **Leak the canary** (via a separate info-disclosure bug — e.g. an over-read, a format string) and
  write it back **unchanged** in your overflow, so the check passes.
- **Brute force** — only viable in narrow cases (a *forking* server that re-uses the same canary
  across children, byte-by-byte; historically 32-bit). Not a general answer.
- **Don't overflow linearly** — overwrite a pointer or use a bug that skips the canary (out-of-bounds
  *write* at an index, not a contiguous smash). Canaries protect the *return address on linear
  overflow*, not all memory corruption.

### RELRO &nbsp;<span class="badge current">CURRENT</span>

**What it does.** **RELocation Read-Only** makes the GOT (Global Offset Table) and other relocation
data **read-only after startup**. **Partial RELRO** reorders sections; **Full RELRO** resolves all
symbols at load and marks the whole GOT read-only.

**What it stops.** A classic technique of overwriting a **GOT entry** (so calling, say, `free()`
jumps to attacker-chosen code). Full RELRO makes the GOT non-writable, killing GOT-overwrite as a
control-flow primitive. Partial RELRO leaves much of it writable.

**Conceptual bypass.** Target something still writable (other function pointers, the stack via ROP),
or accept that full RELRO closes this particular door. It's cheap to enable (`-Wl,-z,relro,-z,now`),
so its *absence* is a finding.

### CET / shadow stacks &nbsp;<span class="badge emerging">EMERGING</span>

**What it does.** **Control-flow Enforcement Technology** (Intel; AMD has an equivalent) adds two
hardware defenses: a **shadow stack** — a protected second copy of return addresses that the CPU
compares against the real one at `ret`, detecting return-address tampering (so ROP's whole premise, a
corrupted return address, is caught) — and **indirect branch tracking (IBT)**, which requires
indirect jumps/calls to land on an `endbr` instruction (constraining JOP/COP). Rolling out in recent
CPUs, OSes, and toolchains.

**What it stops.** The shadow stack directly attacks **ROP**: a `ret` to a gadget whose address
wasn't the real caller mismatches the shadow copy → fault. IBT constrains call-oriented variants.

**Conceptual bypass / honest state.** CET raises the bar substantially; research explores data-only
attacks, gadgets reachable within CET's rules, and bugs that corrupt data rather than control flow.
For a tester in 2026: note whether the target/platform has CET enabled, and treat it as a strong
control that makes classic ROP much harder — not impossible, but no longer routine.

## How a tester recognizes the posture — `checksec`

`checksec` (in pwntools, or the standalone script) reads the binary's headers and prints its
mitigations. This is your first move on any target binary:

```text
$ pwn checksec ./target
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Translate it directly into strategy:

| `checksec` line | Meaning | What it forces you toward |
|---|---|---|
| **NX enabled** | stack/heap non-executable | no shellcode-on-stack → **ROP** |
| **No canary found** | no SSP | linear stack smash reaches RET → easier |
| **Canary found** | SSP present | need a **canary leak** (or non-linear bug) |
| **PIE enabled** | binary base randomized | need a **leak of a binary address** |
| **No PIE** | binary at fixed base | fixed gadgets/functions — a gift |
| **Full RELRO** | GOT read-only | no GOT overwrite |
| **Partial/No RELRO** | GOT (partly) writable | GOT overwrite may be viable |

Also check ASLR at the OS level: `cat /proc/sys/kernel/randomize_va_space` (`2` = full).

## Return-Oriented Programming (ROP) — the concept

When NX stops you from running injected code, you run **code that's already there**. A **gadget** is a
short sequence of existing instructions ending in `ret`. By placing a *series of gadget addresses* on
the stack, each `ret` pops the next address and executes the next gadget — you've built a program out
of borrowed fragments, and the stack is your "instruction list."

The workhorse gadget loads a register from the stack. To call `system("/bin/sh")` on x86-64 (where
the first argument goes in **RDI**, per the System V ABI, 09.1), you need RDI to point at `"/bin/sh"`:

```text
gadget:  pop rdi ; ret        ; found in the binary/libc

stack layout the overflow writes (after the offset):
  ┌──────────────────────────┐
  │ &(pop rdi ; ret)          │ ← ret lands here first: executes the gadget
  │ &"/bin/sh"                │ ← `pop rdi` loads THIS into RDI, then `ret`…
  │ &system                   │ ← …`ret` jumps here: system() runs with RDI = "/bin/sh"
  └──────────────────────────┘
```

Read top-to-bottom that is: *"set RDI to the address of the string, then call system."* Real chains
also fix stack **alignment** (the ABI's 16-byte rule — a bare `ret` gadget is often inserted to
realign) and may first **leak** a libc address (to know where `system` and `pop rdi; ret` live under
ASLR). Tools like **ROPgadget** or pwntools' `ROP` object *find* gadgets and help assemble chains —
but, per the module's rule, they compute nothing you couldn't reason out by hand, and you should
understand the chain before you let a tool build it.

<div class="callout attack">

**Conceptual only — why ROP defeats NX but needs ASLR handled too.** ROP reuses executable code, so
NX (which only stops executing *data*) doesn't apply. But the gadget and `system` addresses must be
*correct*, so under ASLR/PIE you **first need a leak** to know them. That composition — leak, then
ROP — is the shape of essentially every modern stack exploit. This course teaches the shape; it does
not ship a working chain against real software.

</div>

## Why the weakness (still) exists

Mitigations are **probabilistic and incremental**, not cures. NX assumes you won't reuse existing
code (ROP breaks that assumption). ASLR assumes you can't learn an address (an info-leak bug breaks
that). Canaries assume the overflow is linear and the secret stays secret (a leak or a non-contiguous
write breaks that). RELRO protects one table. Each was added because the previous defense was
bypassed — an arms race. The **root cause remains the memory-unsafe bug** (CWE-121/787/416); every
mitigation is defense-in-depth around a defect that memory-safe languages simply don't have. That is
the honest framing for a client: *fix the bug; enable all mitigations because any one may be
bypassed.*

## Impact &amp; the honest exploitability verdict

<div class="callout method">

On a modern hardened target, a stack overflow is rarely "send bytes, get shell." A professional
verdict often reads: *"Control of RIP is achievable at offset N, but the target has NX + full ASLR +
canary + PIE. Exploitation requires (a) an information leak to defeat ASLR/PIE and recover the
canary, and (b) a ROP chain, as shellcode-on-stack is blocked by NX. We did **not** identify a leak
primitive within the engagement window; the bug is therefore assessed as **critical if a leak exists**
and at minimum a **denial-of-service** today."* That is a defensible, useful finding — far more
honest than either "unexploitable" or a fabricated exploit.

</div>

## Remediation

<div class="callout defend">

- **Enable everything** (defense-in-depth): `-fstack-protector-strong` (canary), NX (default — never
  `-z execstack`), `-fPIE -pie` (PIE + ASLR), `-Wl,-z,relro,-z,now` (full RELRO), and **CET**
  (`-fcf-protection`) on supporting toolchains/CPUs. Confirm with `checksec` on the shipped binary.
- **Fix the bug (root cause):** memory-safe APIs/languages; the mitigations only buy margin.
- **Keep the OS hardened:** `randomize_va_space=2`; don't disable ASLR for convenience in production.

</div>

## Detection / blue-team view

<div class="callout defend">

- A canary abort (`*** stack smashing detected ***` / `__stack_chk_fail`) or repeated segfaults from
  one source is an **exploitation attempt** — log and alert, don't just restart.
- **CET/CFI** faults, ROP-like execution (many short sequences ending in `ret`, unusual `ret`
  targets), and a service spawning a shell are strong indicators (EDR, control-flow integrity).
- Map to **T1203 / T1068**; absence of mitigations on a shipped binary is itself a reportable
  hardening finding.

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-09-exploit` (built separately) — the vulnerable service, in its
**isolated no-egress sandbox**. For 09.3 the lab ships (or you rebuild) variants with mitigations
**turned on** so you can *observe* their effect: run `checksec`, confirm the 09.2 shellcode-on-stack
path now fails under NX, and watch a linear overflow trigger the canary abort. **Payload:** benign
only. **Time:** ~60 min (mostly observation + written analysis; no full bypass is built).
**Isolation:** private container network, no Internet; reset per the lab README.

</div>

Observe, don't weaponize: (1) `checksec` the hardened variant; (2) resend the 09.2 stack-shellcode
exploit and confirm NX blocks execution; (3) send a linear overflow and see `*** stack smashing
detected ***` from the canary; (4) write, for each mitigation you saw, the *conceptual* bypass class
and the extra primitive it would require.

## Exercise

<div class="callout method">

**Situation.** Authorized assessment. You've confirmed a stack overflow with control of RIP (09.2) in
a client service. Before investing more time, the client wants your **exploitability assessment**
based on the binary's hardening, and what you'd need next.

**Objective.** From a `checksec` output, reason about which techniques work, which are dead, and the
**specific additional primitive** you'd need to proceed — a written analysis, **no exploit**.

**Starting information.** This `checksec` (analyse it as given):

```text
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE
```

Plus: you control RIP at a known offset; OS ASLR is on (`randomize_va_space=2`); no info-leak bug is
known *yet*.

**Constraints.** Analysis only — no exploitation, lab or otherwise. Be honest about what you *don't*
have. State assumptions.

**Expected deliverables.**
1. For **each** line of the `checksec`, state what it stops and how it shapes your approach here
   (e.g. what does **No PIE** hand you? what does **Canary found** cost you? does **Partial RELRO**
   open anything?).
2. Whether **shellcode-on-stack** is viable and why/why not; if not, the technique you'd use instead
   and why it works despite the mitigations present.
3. The **specific additional primitive(s)** you'd need to make this reliably exploitable, in order
   (hint: there is a canary and OS ASLR, but the binary is not PIE — what does that change about
   *which* leak you need?).
4. A one-paragraph **verdict** you'd put in the report (severity + the condition that would raise it),
   plus the **remediation** flags that would harden this binary.

</div>

<details><summary>Hint 1 — read checksec as a strategy sheet</summary>
Each line forces a choice. NX enabled → no stack shellcode → ROP. Canary found → you need the canary
value or a non-linear write. Then look hard at <strong>No PIE</strong> — what is fixed even though OS
ASLR randomizes libraries and the stack?
</details>

<details><summary>Hint 2 — what "No PIE" gives you</summary>
Without PIE the <em>main binary</em> (its code and gadgets and any <code>win()</code>-like function)
sits at a <strong>fixed</strong> address every run, even with OS ASLR on. So you may not need a
binary-address leak — the binary's own gadgets are already known. What do you still need a leak for?
</details>

<details><summary>Hint 3 — the canary is the wall</summary>
A linear overflow to the return address crosses the canary → abort. So either you obtain the canary
value (an info-leak / over-read primitive) and replay it intact, or you find a bug that writes past
the canary without overwriting it. Name that missing primitive explicitly — it's the crux of the
assessment.
</details>

<details><summary>Hint 4 — libc &amp; the second leak</summary>
If your ROP wants <code>system</code>/<code>/bin/sh</code> from libc, libc <em>is</em> ASLR-randomized
even though the binary isn't — so you'd also need a libc leak (e.g. read a GOT entry, which Partial
RELRO may leave readable) to locate it. Order your needed primitives: canary leak → (libc leak) → ROP.
</details>

## Check yourself

<div class="callout key">

1. Explain in one sentence each why (a) NX defeats shellcode-on-stack but not ROP, and (b) ASLR
   defeats hardcoded addresses but is itself defeated by an info leak.
2. A binary has a canary. Why does simply knowing the *offset* to the return address no longer give
   you control, and what exactly do you need instead?
3. What does a **No PIE** binary hand an attacker that a PIE binary does not — even when OS ASLR is
   fully enabled?
4. Describe, in your own words, what a ROP gadget is and how a chain of them calls
   `system("/bin/sh")` on x86-64. Why is `pop rdi; ret` the archetypal gadget there?
5. How does a **shadow stack** (CET) detect a classic ROP attack that a stack canary would miss?
6. Give the honest one-line verdict for a bug where you control RIP but the target has NX + canary +
   full ASLR + PIE and you have no leak. Is it "unexploitable"? Why or why not?

</div>

Model answers are in `solutions/module-09.md` (try them before looking).

## References

- **PaX / "Address Space Layout Randomization"** (PaX Team) — the origin of ASLR; and Linux
  `Documentation/admin-guide/mm/...` plus `randomize_va_space` (`/proc/sys/kernel/`).
- **Linux NX / ExecShield** documentation; **Microsoft "Data Execution Prevention (DEP)"** docs.
- **GCC Stack-Smashing Protector** (`-fstack-protector*`) and the SSP design notes; **RELRO** via
  `ld`'s `-z relro,-z now`.
- **Intel "Control-flow Enforcement Technology" (CET)** specification and the shadow-stack / IBT
  docs; GCC `-fcf-protection`.
- **Shacham, "The Geometry of Innocent Flesh on the Bone: Return-into-libc without Function Calls"**
  (CCS 2007) — the foundational ROP paper. **ROPgadget** and **pwntools `ROP`** for gadget discovery.
- **checksec.sh** and `pwn checksec`. **CWE-121 / CWE-787 / CWE-416**; **MITRE ATT&CK T1203, T1068**.

## What you should now be able to do

- Explain DEP/NX, ASLR, PIE, stack canaries, RELRO, and CET/shadow stacks — what each stops and its
  limits.
- Read `checksec` and turn it into an exploitability strategy.
- State the conceptual bypass class for each mitigation (ROP, info leak, canary leak/brute) and why
  real exploitation **composes** primitives.
- Explain ROP — gadgets and a `pop rdi; ret` chain to `system` — conceptually.
- Write an **honest exploitability verdict** that names the missing primitive, and the exact compiler/
  OS flags that would harden a client's binary.

## Progress checkpoint

```bash
py course.py complete 09.3
```
