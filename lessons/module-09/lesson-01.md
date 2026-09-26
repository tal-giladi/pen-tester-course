# 09.1 — Exploitation methodology &amp; the memory model: stack, heap, registers &amp; calling conventions

<div class="prereq">

**Prerequisites:** [M00](../module-00/lesson-01.md) (authorization, threat modeling — the
confused-deputy pattern in [00.3](../module-00/lesson-03.md)), [M01](../module-01/lesson-01.md)–
[M04](../module-04/lesson-01.md). You need M04's picture of a process, memory, and privilege.
**C and assembly literacy help a lot** — you should be comfortable reading a small C function and
know that code compiles to instructions the CPU executes; we teach the assembly you need as we go,
but total unfamiliarity will slow you down.
**Module:** M09 Exploitation &amp; memory corruption. **Difficulty:** 🔴 advanced.
**You will produce:** a written exploitability assessment of a vulnerable C function — the stack
diagram, what an attacker controls, and *whether and how* the return address is reachable — with **no
exploit built yet**.

</div>

## Why this matters

Memory-corruption exploitation is the part of penetration testing that looks like magic and is
actually just bookkeeping. A tester who understands it can answer the question a client pays for:
*"you found a crash — is it exploitable, and how bad is it?"* That judgement — **exploitability
assessment** — is worth far more on a report than a copied exploit. It is the difference between
"the service crashes on long input (denial of service, medium)" and "this crash gives an attacker
control of execution (remote code execution, critical)."

You also cannot understand *why modern mitigations exist* (09.3) without first understanding the
attack they were built to stop. ASLR, DEP/NX, and stack canaries are answers to a specific question:
"how does an attacker turn a memory bug into running their own code?" This lesson builds the memory
model those answers assume. Everything in M09 rests on it.

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Everything hands-on in M09 targets **only** `labs/lab-09-exploit`, a
deliberately vulnerable toy service compiled *without* modern mitigations, in an isolated sandbox
container. Its "shellcode" spawns a **local** shell in that sandbox or prints a benign
`LAB-FLAG-{uuid}` marker — it is **not** malware and opens **no** network connection to any real
host. Exploit development against software you do not own and are not explicitly authorized to test
(a client system, a real CVE target) is a crime (M00). Exploit-dev skills are for **authorized
research, CTFs, and defense**. This lesson builds *understanding*, not a weapon.

</div>

## Learning objectives

- Describe the exploitation methodology as a repeatable loop: **crash → control → redirect → payload
  → reliability**.
- Draw the process memory layout (text/data/BSS, heap, stack) and say which regions are writable,
  executable, and attacker-influenced.
- Name the registers that matter for control-flow hijacking — **EIP/RIP**, **ESP/RSP**, **EBP/RBP** —
  and what each holds.
- Explain the **stack frame**: how arguments, the saved return address, and the saved frame pointer
  are laid out, and why the *saved return address* is the attacker's target.
- Read the two calling conventions you will meet — **cdecl** (x86) and the **System V AMD64 ABI**
  (x86-64 Linux) — well enough to reason about where a return address sits.
- Perform an exploitability assessment on paper, without running anything.

## Intuition

A CPU runs instructions in the order an internal pointer tells it to. Nearly every exploit is the
same trick: **make that pointer point at instructions or data of the attacker's choosing.** Memory
corruption is the means; hijacking the instruction pointer is the end.

Here is the whole idea in one breath. A function needs to remember where to go back to when it
finishes, so the CPU writes that "return address" onto the stack — right next to a buffer the
function is about to fill with input. If the function writes more input than the buffer holds, the
extra bytes keep going and land on top of the saved return address. When the function returns, the
CPU jumps to whatever is now sitting there. If that is a value the attacker supplied, the attacker
just chose where the program goes next. Everything else in this module is detail on top of that
sentence.

## The underlying technology — process memory layout

When the OS loads a program, it lays the process's virtual address space into regions with different
purposes and permissions:

```text
 high addresses
 ┌───────────────────────────┐
 │  stack   (grows DOWN ↓)    │  local variables, saved return addrs, saved frame ptrs
 │      │                     │  per-function "frames"; writable, normally NON-exec (NX, 09.3)
 │      ▼                     │
 │            . . .           │  (gap: stack and heap grow toward each other)
 │      ▲                     │
 │      │                     │
 │  heap    (grows UP ↑)      │  malloc/new; long-lived, dynamically sized; writable, NX
 ├───────────────────────────┤
 │  BSS                       │  zero-initialised globals; writable
 │  data                      │  initialised globals/statics; writable
 │  text (.text)              │  the machine code; READ + EXECUTE, not writable
 └───────────────────────────┘
 low addresses
```

Three facts drive exploitation:

- **The stack is writable and holds control data** (return addresses). That co-location of *data you
  write* and *control the CPU trusts* is the original sin the whole module exploits.
- **The stack grows *down*** (toward lower addresses) on x86/x86-64, but a `strcpy`/`memcpy` writes
  *up* (toward higher addresses). So an overrunning copy walks **from the buffer toward the saved
  return address** — it overwrites exactly the control data you want.
- **Historically the stack was executable**; you could drop code (shellcode) into the buffer and
  jump to it. Modern CPUs mark it non-executable (NX/DEP), which is why 09.3 exists. The lab binary
  disables NX so 09.2 can teach the classic case cleanly first.

The **heap** matters for a different bug class (use-after-free, heap overflow — CWE-416, CWE-122);
we introduce it conceptually here and keep M09's hands-on work on the **stack**, which is where the
mechanism is clearest.

## Registers: the CPU's working state

A handful of registers carry the state that exploitation manipulates. (x86 names first, then the
64-bit `R` names.)

- **EIP / RIP — the instruction pointer.** Holds the address of the *next* instruction to execute.
  **This is the prize.** You cannot write to RIP directly; you change it *indirectly* by corrupting
  something the CPU loads into it — most commonly a saved return address that `ret` pops.
- **ESP / RSP — the stack pointer.** Always points at the *top* of the stack (lowest in-use stack
  address). `push` decrements it and writes; `pop` reads and increments; `call` pushes a return
  address; `ret` pops into RIP.
- **EBP / RBP — the base (frame) pointer.** A stable anchor for the *current* function's frame, so
  code can reference locals and arguments at fixed offsets even as RSP moves. Modern optimized code
  often omits it (`-fomit-frame-pointer`), addressing everything off RSP.
- **General registers** — EAX/RAX, EBX/RBX, RDI, RSI, RDX, RCX, R8–R15 — hold values and, on x86-64,
  **function arguments** (see the ABI below). Which register a value lives in matters enormously for
  later techniques (ROP, 09.3).

## The stack frame &amp; calling conventions

A **calling convention** (ABI) is the contract for how functions pass arguments, return values, and
who cleans up. You must be able to read one to know where the return address sits.

### x86 — cdecl (32-bit, the intro case)

In **cdecl**, arguments are pushed onto the stack **right-to-left**, then `call` pushes the return
address. A typical prologue then saves the old EBP and sets up the new frame:

```text
higher addresses
 ┌──────────────────────┐
 │  arg 2                │  ← pushed by caller (right-to-left)
 │  arg 1                │
 │  saved return address │  ← pushed by `call`  ── the TARGET
 │  saved EBP            │  ← pushed by callee prologue (`push ebp`)   ← EBP points here
 │  local var / buffer   │  ← `sub esp, N` reserves locals
 │  ...                  │
 │  (top)                │  ← ESP
 └──────────────────────┘
lower addresses
```

`call func` pushes the address of the instruction after the call; `ret` pops it back into EIP. The
buffer sits at **lower** addresses than the saved return address, and a forward-writing overflow
climbs from the buffer, past the saved EBP, into the saved return address. That geometry is why the
32-bit stack overflow is the canonical teaching example — it is simple and deterministic.

### x86-64 — System V AMD64 ABI (Linux/macOS)

On 64-bit Linux the **System V AMD64 ABI** passes the first six integer/pointer arguments in
**registers** — `RDI, RSI, RDX, RCX, R8, R9` — and only spills further arguments to the stack. The
return address is still pushed by `call` and popped by `ret`; the frame layout is analogous:

```text
 │  saved return address │  ← pushed by `call`  (8 bytes)
 │  saved RBP            │  ← if a frame pointer is used
 │  locals / buffer      │
```

Key differences from x86 that change *how you exploit*, not *whether*:

- **Addresses are 8 bytes**, and canonical user-space addresses have the high bytes zero (e.g.
  `0x00007fff...`). Those embedded null bytes break naive string-copy overflows (a `strcpy` stops at
  the first `\0`) — a practical constraint you will feel in 09.2.
- **Arguments are in registers**, so "call `system("/bin/sh")`" is no longer "push a pointer and
  call" — you must first *get the pointer into RDI*. That single fact is why 64-bit exploitation
  leans on **ROP** (09.3) to load registers.
- The ABI mandates a **16-byte stack alignment** at `call` sites; get it wrong and library calls
  (e.g. into `system`) can crash on a movaps instruction. A real 09.2 constraint.

**Windows x64** uses a *different* convention (first four args in `RCX, RDX, R8, R9`, plus a 32-byte
"shadow space"). The lab is Linux; we note Windows only so you are not surprised later.

## Why the weakness exists

The root cause is old and simple: **C and C++ do not check array bounds, and the stack stores
attacker-reachable data next to control data the CPU implicitly trusts.** A function like
`strcpy(buf, input)` copies until a terminating null with no idea how big `buf` is. When `input` is
longer than `buf`, the write continues into whatever follows on the stack — the saved frame pointer,
then the saved return address. The CPU has no way to know those bytes were overwritten; at `ret` it
loyally jumps to the corrupted address.

In vocabulary you will cite: this is **CWE-121 (stack-based buffer overflow)**, a specific case of
**CWE-787 (out-of-bounds write)**, itself a failure of **CWE-20 (improper input validation)** and
bounds enforcement. The unsafe primitives are well known — `strcpy`, `strcat`, `sprintf`, `gets`
(removed from C11), `scanf("%s")`, and any `memcpy`/loop with an attacker-controlled length. The
weakness exists because these were fast, convenient, and written before adversarial input was the
norm — and because the language trusts the programmer to get length right, every time, forever.

## How a tester recognizes it

You suspect a memory-corruption bug when:

- A network service or binary **crashes** on unusually long or malformed input — a segmentation
  fault, an `0xC0000005` on Windows, or the process simply dies. A crash is a *signal*, not yet a
  finding.
- Source or a decompiler shows an **unbounded copy into a fixed buffer** — `char buf[64]` with a
  `strcpy`/`gets`/`memcpy(buf, in, attacker_len)`.
- Fuzzing (M03 concepts, applied to input) produces inputs that reliably fault the target.

The tester's next question is the whole job: **does the crash corrupt something that gives control?**
A crash reading a bad pointer might be a mere DoS; a crash where the *saved return address* is
overwritten with attacker bytes (the classic tell: the instruction pointer ends up at `0x41414141`
after sending `AAAA…`) is likely code execution. Distinguishing the two is exploitability
assessment.

## Manual investigation — the debugger

The tool that makes memory visible is a **debugger**. On Linux that is **GDB**, made far more usable
for exploitation with the **pwndbg** or **GEF** extensions (they add `checksec`, register/stack/
disassembly context on every stop, `cyclic`/pattern helpers, and heap views). You will run these
against the lab binary in 09.2; here is the vocabulary so the output means something.

```text
$ gdb -q ./lab09-vuln            # pwndbg or GEF loaded via ~/.gdbinit
pwndbg> checksec                 # what mitigations are compiled in (09.3)
pwndbg> break vuln               # stop at the vulnerable function
pwndbg> run                      # (feed input; see 09.2 for the lab flow)
pwndbg> info registers rip rsp rbp   # where are we, where is the stack
pwndbg> x/24gx $rsp              # examine 24 giant (8-byte) words in hex at the stack top
pwndbg> bt                       # backtrace — the chain of saved return addresses
```

The two questions you ask the debugger at every stop: **"where is RIP (the CPU about to go)?"** and
**"what does the stack around RSP look like (what will `ret` pop)?"** Reading a stack dump — spotting
your own `0x4141…` bytes sitting where a return address should be — is the core manual skill of this
module. No tool replaces understanding that dump.

## Tooling — orientation (details in 09.2/09.3)

You will meet these in the next lessons; know their role now:

- **pwntools** (Python) — a convenience library for building input, talking to the target
  (`process`/`remote`), packing addresses (`p32`/`p64`), and generating cyclic patterns
  (`cyclic`/`cyclic_find`). It is *scaffolding*; it computes nothing you couldn't compute by hand,
  and you should be able to.
- **pattern/cyclic tools** — generate a non-repeating string so that, from the value that lands in
  RIP, you can compute the exact overflow **offset** in one step (09.2).
- **msfvenom** — generates shellcode (and encodes it to avoid bad bytes). What it *does* and why you
  always **verify** its output and bad-char handling is a 09.2 topic. In this lab, shellcode only
  spawns a local sandbox shell or prints the flag.

The methodology rule for the whole module: **understand it in the debugger first; reach for pwntools
as convenience, not as a substitute for knowing where the bytes go.**

## The exploitation methodology

Every memory-corruption exploit, from a 1996 stack smash to a modern chain, follows the same loop.
Internalize it now; the rest of M09 is filling in each stage.

1. **Crash.** Get the target to fault reproducibly. Fuzz with growing/malformed input; capture the
   exact input that kills it. (A crash alone can be a DoS finding.)
2. **Control.** Determine *what you corrupted* and whether it reaches a control value. Find the
   **offset** from the start of your input to the saved return address (cyclic pattern → 09.2).
   Success looks like RIP = your bytes.
3. **Redirect.** Point execution somewhere useful — historically your shellcode on the stack; on
   modern targets, a chain of existing code (ROP, 09.3). Account for **bad characters** that the
   input path mangles.
4. **Payload.** The code that runs once you have control — in this course, a benign lab payload
   (local shell / print `LAB-FLAG`). Understand what shellcode *is* without weaponizing it.
5. **Reliability.** Make it work more than once and under real conditions — defeat/adjust for ASLR,
   alignment, differing offsets. Reliability is where mitigations (09.3) bite and where honest
   exploitability assessment lives: *"controllable but not yet reliable"* is a real, common verdict.

<div class="callout method">

**Exploitability assessment is the deliverable, not the exploit.** For a client you rarely need a
weaponized exploit — you need a defensible answer to "how bad is this crash?" State: *what is
corrupted*, *whether control of RIP is achievable*, *what mitigations stand in the way*, and *what
additional primitive (e.g. an info leak) would be needed*. That analysis is the professional
product; a working exploit is sometimes overkill and sometimes out of RoE.

</div>

## Impact

If a crash yields control of the instruction pointer, the impact ceiling is **arbitrary code
execution** in the context of the vulnerable process — with its privileges, its file and network
access, its secrets. A network service running as root that is exploitable is a full host compromise
and a pivot point (M11/M12). This is why memory-corruption RCE is routinely rated **critical**
(CVSS 9–10) and maps to **MITRE ATT&CK T1203 (Exploitation for Client Execution)** and **T1068
(Exploitation for Privilege Escalation)**. Even when control isn't achievable, a reliable crash is a
**denial-of-service** finding (availability).

## Remediation

<div class="callout defend">

- **Don't write the bug:** use bounds-checked APIs (`strncpy`/`strlcpy`/`snprintf` with correct
  sizes, `std::string`/`std::vector`, Rust or other memory-safe languages for new code). Treat
  `gets`, `strcpy`, `sprintf`, `scanf("%s")` as forbidden. This is the only *root* fix — CWE-121/787
  is a coding defect.
- **Compiler/OS mitigations (09.3)** raise the cost even when a bug slips through: stack canaries
  (`-fstack-protector-strong`), NX/DEP, ASLR + PIE, RELRO, and CET/shadow stacks. They are
  defense-in-depth, **not** substitutes for not having the bug.
- **Fuzz and review:** AddressSanitizer (ASan) in CI catches out-of-bounds writes during testing;
  fuzzing (libFuzzer/AFL++) finds them before an attacker does.

</div>

## Detection / blue-team view

<div class="callout defend">

- **Crashes are signal.** Repeated segfaults of a service (in `dmesg`, `journalctl`, Windows WER)
  from one source are a probe. Crash-reporting pipelines should alert, not just restart.
- **Exploitation telemetry:** a network service spawning a shell or an unexpected child process is a
  strong indicator (the same "privileged process spawns a shell" heuristic from M04). EDR watches
  for anomalous child processes and for return-address/stack anomalies (control-flow integrity).
- Map detections to **T1203/T1068**; feed crash signatures to the fuzzing/patch loop.

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-09-exploit` (built separately) — a deliberately vulnerable toy network
service in an **isolated, no-egress sandbox container**, compiled **without** modern mitigations for
teaching. **Target:** the lab service only. **Payload:** benign — a **local** sandbox shell or a
printed `LAB-FLAG-{uuid}`; **no** reverse shell to any real host. **Time:** ~30 min for this lesson
(reading + paper analysis; you do not exploit anything in 09.1). **Isolation:** private container
network, no Internet route; reset per the lab README. Have GDB + pwndbg/GEF installed for 09.2.

</div>

For 09.1, attach GDB to the lab binary **only to observe**: run `checksec`, break on the vulnerable
function, and dump the stack around RSP so you can *see* the frame — buffer, saved RBP, saved return
address — that this lesson describes. Do not send an overflow yet; the goal is to connect the diagram
to real memory.

## Exercise

<div class="callout method">

**Situation.** During an authorized assessment you are given the source of a small C network handler
(below) and asked, before any exploitation, for an **exploitability assessment** — is the reported
crash-on-long-input a real code-execution risk, and what would it take?

```c
/* LAB-style handler. 32-bit build, no mitigations, for analysis only. */
void handle(int fd) {
    char name[64];
    char scratch[16];
    int  authenticated = 0;
    ssize_t n = read(fd, name, 512);   /* reads up to 512 bytes into a 64-byte buffer */
    (void)n;
    /* ... uses name, scratch, authenticated ... */
    reply(fd, name);
}
```

**Objective.** A written assessment — no exploit. Produce the stack picture and reason about control.

**Starting information.** The source above; assume 32-bit cdecl, no canary, no ASLR, stack
executable (the lab's simplifying assumptions). `name` is at a lower address than the saved return
address; `scratch` and `authenticated` are also locals in this frame.

**Constraints.** Paper/whiteboard and (optionally) GDB **observation** of the lab binary only. Do
**not** build or run an exploit. State assumptions explicitly where the layout is compiler-dependent.

**Expected deliverables.**
1. A **stack frame diagram** for `handle`, ordered low→high address, showing `name`, `scratch`,
   `authenticated`, saved EBP, and the saved return address.
2. Identify **what the attacker controls** and by how much (buffer size vs. bytes read), and name the
   CWE(s).
3. A reasoned answer to **"is the saved return address reachable, and is this likely
   code-execution or only DoS?"** — including *which other local(s)* an overflow crosses first and
   what corrupting `authenticated` alone might achieve.
4. One sentence on **what you would confirm in the debugger** (not do — confirm) to move from
   "suspected" to "controllable."

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Compare the buffer size to the number of bytes the copy can write. The gap between them is your
overflow budget. Then ask what lives, in memory order, between the buffer and the saved return
address.
</details>

<details><summary>Hint 2 — layout reasoning</summary>
Locals are not guaranteed in source order, but all locals sit at <em>lower</em> addresses than the
saved EBP and saved return address. A forward-writing overflow reaches nearer locals first, then
saved EBP, then the return address. What does hitting <code>authenticated</code> on the way do?
</details>

<details><summary>Hint 3 — control vs. crash</summary>
"Code execution" needs the overwrite to reach and control the <em>saved return address</em> with
attacker-chosen bytes. "DoS only" is when you can crash it but the corrupted value isn't something
the CPU will jump to under your control. Which is this, given 512 bytes into a 64-byte buffer 
followed by more locals and the saved return address?
</details>

<details><summary>Hint 4 — what to confirm</summary>
The one debugger observation that settles it: send a known marker of the right length and look at
where the bytes land relative to the saved return address — i.e., can you get your bytes <em>onto</em>
the saved return slot? (You compute the exact offset with a cyclic pattern in 09.2.)
</details>

## Check yourself

<div class="callout key">

1. Why is the *saved return address* the target, rather than, say, EIP directly? What actually loads
   your bytes into EIP, and when?
2. The stack grows toward lower addresses, but `strcpy` writes toward higher addresses. Explain, in
   one sentence, why those opposite directions are exactly what makes a stack overflow reach the
   return address.
3. On x86-64 System V, calling `system("/bin/sh")` is harder than on x86 cdecl even with full
   control of RIP. Why? Which register must hold what?
4. A crash puts `0x41414141` in EIP after you send a string of `A`s. What have you learned, and what
   is the *next* thing you need to measure?
5. Give one example each of a crash that is *only* a DoS and a crash that is *likely* code execution,
   and state the property that separates them.

</div>

Model answers are in `solutions/module-09.md` (try them before looking).

## References

- **Aleph One, "Smashing the Stack for Fun and Profit,"** *Phrack* 49 (1996) — the historical
  origin; read it for the mechanism, noting that its "just run shellcode on the stack" ending is
  <span class="badge deprecated">DEPRECATED</span> on modern NX systems (09.3). 
- **System V Application Binary Interface, AMD64 Architecture Processor Supplement** — the
  authoritative x86-64 Linux calling convention (argument registers, alignment, the red zone).
- **Intel 64 and IA-32 Architectures Software Developer's Manual**, Vol. 1 (basic architecture,
  registers, stack) and **AMD64 Architecture Programmer's Manual**, Vol. 1.
- **pwntools documentation** — docs.pwntools.com (packing, `process`/`remote`, `cyclic`).
- **CWE-121** Stack-based Buffer Overflow; **CWE-787** Out-of-bounds Write; **CWE-20** Improper Input
  Validation.
- **MITRE ATT&CK** — **T1203** Exploitation for Client Execution; **T1068** Exploitation for
  Privilege Escalation.

## What you should now be able to do

- Sketch a process's memory regions and say which are writable, executable, and attacker-influenced.
- Name EIP/RIP, ESP/RSP, EBP/RBP and describe the stack frame and the two calling conventions you'll
  meet.
- Explain *why* the saved return address is the target and how an overflow reaches it.
- Run the crash → control → redirect → payload → reliability loop in your head, and — critically —
  write an **exploitability assessment** of a vulnerable function without building an exploit.

## Progress checkpoint

```bash
py course.py complete 09.1
```
