# Instructor / solutions — Module 09

> **Instructor material.** Not linked from `_sidebar.md`. Do the exercises before reading.

These answers assume the `lab-09-exploit` service as specified: a deliberately vulnerable 32-bit toy
network service in an **isolated, no-egress sandbox container**, compiled **without** mitigations for
09.1/09.2 (canary off, NX off via `-z execstack`, no PIE) and with a hardened variant for 09.3. The
payload is benign — a `win()`/`print_flag()` helper printing `LAB-FLAG-{uuid}`, or a **local**
sandbox shell; **no** external callback. Exact offsets, addresses, and bad-char sets depend on the
built binary and compiler; **grade on reasoning and mechanism**, not on matching a specific number.
Every exercise is passable *without weaponization*: 09.1 is paper, 09.2's required deliverable is
*proof of RIP control*, and 09.3 is analysis only.

---

## 09.1 — Memory model, registers, calling conventions

**Exercise (exploitability assessment of `handle`, no exploit).** Full credit = a correct stack
diagram, a clear statement of what's controlled, and an honest control-vs-DoS verdict — with **no
exploit built**.

1. **Stack frame diagram (low→high).** Order of locals is compiler-dependent, but all locals sit
   below saved EBP / saved RET. A defensible diagram:

   ```text
   low addr   │ scratch[16]           │  locals (order not guaranteed)
              │ authenticated (int)   │
              │ name[64]              │  ← read() writes forward from here (512 into 64)
              │ saved EBP  (4)        │
    target →  │ saved RET  (4)        │  ← EIP loaded here by ret
   high addr  └───────────────────────┘
   ```
   Accept any layout that (a) puts all three locals below saved EBP/RET and (b) reasons explicitly
   that source order ≠ memory order. The strong answer notes it *cannot* be sure `authenticated`/
   `scratch` sit above or below `name` without checking the binary — and says so.

2. **What's controlled + CWE.** `read(fd, name, 512)` writes up to **512 bytes into a 64-byte
   buffer** → up to **448 bytes** of overflow. Attacker controls all of it. This is **CWE-121**
   (stack-based buffer overflow), a case of **CWE-787** (out-of-bounds write); the missing bounds
   check is **CWE-20**. Note `read` (unlike `strcpy`) does **not** stop at NUL, so the whole 512 can
   be arbitrary bytes including `\x00` — a subtlety worth full marks.

3. **Is RET reachable → code exec or DoS?** With 448 bytes of overflow past a 64-byte buffer, the
   write **easily reaches saved EBP and saved RET** — so this is **likely code execution**, not just
   DoS, given the lab's no-canary/no-ASLR/exec-stack assumptions. On the way it crosses the other
   locals: overwriting **`authenticated`** with a non-zero value is a *separate*, simpler primitive —
   if a later check is `if (authenticated) ...`, the overflow can flip an auth flag **without even
   reaching RET** (a classic "overwrite an adjacent variable" bug). Best answers mention both the
   full RIP hijack *and* the cheaper flag-flip.

4. **What to confirm in the debugger (confirm, not exploit).** Send a marker of known length and
   observe where bytes land relative to saved RET — i.e. can you place bytes *onto* the RET slot? The
   precise-offset measurement (cyclic pattern) is 09.2; here it's enough to say "confirm my bytes
   reach the saved return address." Accept "break on `handle`'s return, examine `$esp`/the RET slot."

**Check-yourself.**
1. You can't write EIP directly; it's set *only* by control-flow instructions. The overflow corrupts
   the **saved return address on the stack**, and `ret` (at function exit) **pops that value into
   EIP** — so the hijack takes effect at `ret`, not at the moment of the overwrite.
2. The buffer is at a *lower* address than the saved return address, and `strcpy` writes toward
   *higher* addresses — so an overrun climbs from the buffer straight into the saved return address.
   (The stack *growing* down is about how frames are allocated; the *copy* still writes upward.)
3. System V AMD64 passes the first argument in **RDI**, not on the stack — so even owning RIP, you
   must first get the pointer to `"/bin/sh"` **into RDI** before/at the call to `system`. That
   register-loading step is what pushes 64-bit exploitation toward ROP (`pop rdi; ret`).
4. You've learned RIP is **reachable/controllable** — your input overwrote the saved return address.
   You have **not** learned the **exact offset** to the 4 (or 8) bytes that land in EIP; measure that
   next with a cyclic pattern.
5. **DoS only:** a null-pointer or wild-read dereference that faults but where the faulting
   address/register isn't attacker-controlled (crash, no control). **Likely code exec:** an overflow
   that puts *attacker bytes* into the saved return address (EIP = `0x41414141`). The separating
   property: **does the corruption place attacker-controlled data into a value the CPU loads into the
   instruction pointer?**

---

## 09.2 — Stack overflow end to end (lab)

**Exercise (offset + control-of-RIP evidence on the lab binary).** The required deliverable is
**proof of RIP control**, not a full shell. Full credit:

1. **Offset + method.** ~76 on the reference build (varies). Method must be the **cyclic pattern**:
   `cyclic 200` → send → take the value in EIP → `cyclic -l <value>` → offset. Docking points for
   "I tried lengths until it worked" — that's not a measurement.
2. **Control-of-RIP evidence.** The register line from GDB after sending `A*offset + "BBBB" + …`
   showing **`EIP = 0x42424242`**. This exact confirmation is the graded artifact — a screenshot or
   copied `info registers eip` line. Offset without this confirmation is incomplete.
3. **Bad characters.** At minimum `\x00` (strcpy terminator); a line-framed input adds `\x0a`
   (and possibly `\x0d`). Must show *how* confirmed: send `\x01..\xff` after the padding, dump memory
   at `$esp`, diff sent vs. present.
4. **(Bonus) flag.** `info address win` → address → `p32(addr)` (little-endian, e.g.
   `\xd6\x91\x04\x08`) at the offset → service prints `LAB-FLAG-{uuid}`. Award bonus for the printed
   flag **and** the correctly packed address.
5. **Remediation.** One-line source fix (`snprintf(buf, sizeof buf, "%s", line)` or a length check;
   ban `strcpy`) **plus** the compiler mitigations that would have stopped it (canary, NX, PIE, RELRO
   — forward ref to 09.3).

Common failure modes to flag: pasting a canned exploit without the debugger evidence; guessing the
offset; not accounting for `\x00` and wondering why the address is truncated; forgetting
little-endian packing; claiming success from a printed banner without the register evidence.

**Check-yourself.**
1. `A`s tell you *only* that RIP is reachable (EIP = `0x41414141`) — not **where**. A cyclic (De
   Bruijn) sequence has a unique 4-byte window at every position, so the 4 bytes that land in EIP map
   to exactly one offset (`cyclic -l`), giving the offset in **one** shot with no bisection.
2. (a) **Alignment/bad byte in the address** — e.g. the address contains `\x00`, truncating the
   overflow, or (on x64) a 16-byte alignment fault in the called function. (b) **Wrong offset by a
   few bytes** — the address is landing shifted. Tell them apart in GDB: break at `ret`/examine the
   RET slot to see whether your address sits *exactly* on it (offset issue) or is present but
   `win()`/the call faults later (alignment/bad-byte issue). Also `bt` and single-step.
3. `strcpy` copies until the **first `\x00`** — a NUL inside your shellcode terminates the copy, so
   everything after it never reaches memory. Fixes: (i) generate NUL-free shellcode / encode with
   msfvenom `-b '\x00'`; (ii) reorder so nothing essential follows the first unavoidable NUL, or use
   a copy primitive that isn't NUL-terminated (`recv`/`read` length-based, as in the 09.1 exercise).
4. A **NOP sled** is a run of `\x90` (do-nothing) bytes before the shellcode; jumping *anywhere* in
   the sled slides execution down into the shellcode, so you don't need the *exact* shellcode
   address — it absorbs stack-address variance. **ret2win needs none** because it jumps to a **fixed,
   known** function address (non-PIE binary), not to a shifting stack location.
5. `EIP = 0x42424242` proves you control the instruction pointer **precisely at a known offset** —
   the core primitive. A printed flag *could* be reached another way (e.g. hitting `win()` via an
   unintended path, an off-by-something, or the helper being called for another reason) and doesn't
   by itself prove *precise* control or a clean offset. We want the primitive demonstrated, not just
   an outcome observed.

---

## 09.3 — Mitigations &amp; ROP concepts

**Exercise (analysis from `checksec`: Partial RELRO, Canary, NX, No PIE; OS ASLR on; no known
leak).** Analysis only; grade the *reasoning* and the honesty about missing primitives.

1. **Line by line.**
   - **NX enabled** → stack/heap non-executable → **no shellcode-on-stack**; must **reuse code
     (ROP)**.
   - **Canary found** → a linear overflow to RET clobbers the canary → `__stack_chk_fail` abort. You
     need the **canary value** (leak) to replay it intact, or a non-linear write.
   - **No PIE** → the **main binary is at a fixed base** even with OS ASLR on → its code, gadgets, and
     any `win()`/PLT entries are at **known addresses without any leak**. A gift.
   - **Partial RELRO** → the **GOT is (partly) writable** and, importantly, **readable** — useful for
     a **libc leak** (read a resolved GOT entry) and possibly a GOT overwrite (unlike Full RELRO).
   - (OS ASLR = 2 → **libraries and stack are randomized**, so libc addresses are *not* known despite
     No PIE.)

2. **Shellcode-on-stack?** **Not viable** — NX blocks execution of stack data. Use **ROP** with
   gadgets from the **fixed (non-PIE) binary** (known without a leak). If the chain needs libc
   (`system`/`/bin/sh`), that part needs a libc leak first.

3. **Additional primitives needed, in order.** (a) A **canary leak** (info-disclosure / over-read) so
   the overflow can preserve the canary and survive the epilogue check. (b) **Because No PIE**, the
   binary's own gadgets are already known — so you may **not** need a binary-address leak. (c) If the
   ROP target is in libc, a **libc leak** (e.g. read a GOT entry, feasible under Partial RELRO) to
   defeat library ASLR. Strong answers explicitly note that No PIE removes *one* leak requirement but
   the **canary** and **libc** leaks remain the crux — and that with *no* known leak today, it's not
   yet reliably exploitable.

4. **Verdict + remediation.** *"RIP controllable at offset N. NX forces ROP; the non-PIE binary
   supplies fixed gadgets, but the stack canary and (for a libc chain) library ASLR require
   information-leak primitives we have not identified in this window. Assessed **critical if an info
   leak exists** (full RCE achievable), currently a reliable **denial-of-service**."* Remediation
   flags: `-fPIE -pie` (close the No-PIE gift), `-Wl,-z,relro,-z,now` (Full RELRO), keep
   `-fstack-protector-strong` and NX, add `-fcf-protection` (CET) where supported — and **fix the
   overflow** (bounded copy / memory-safe code), since mitigations only add margin.

**Check-yourself.**
1. (a) NX marks data pages non-executable, so injected shellcode *as data* won't run — but ROP
   executes **existing code pages** (already executable), which NX doesn't touch. (b) ASLR randomizes
   *bases*, breaking hardcoded addresses — but an info leak reveals a runtime address, and since the
   *layout within a region is fixed*, one leaked address de-randomizes the rest.
2. The canary sits **between the buffer and the saved return address**; a linear overflow that reaches
   RET necessarily overwrites the canary, and the epilogue check aborts **before** `ret` uses your
   value. So you need the **canary's value** (to write it back unchanged) or a bug that reaches RET
   **without** crossing the canary — not just the offset.
3. A **fixed base for the whole main binary**: its functions, PLT/GOT, and especially its **ROP
   gadgets** are at known addresses every run, with **no leak required**. A PIE binary randomizes all
   of that too, so you'd need a leak of a binary address before you could use its gadgets.
4. A **gadget** is a short existing instruction sequence ending in `ret`. Placing gadget addresses in
   sequence on the stack makes each `ret` pop and run the next — a program of borrowed fragments. For
   `system("/bin/sh")` on x86-64 the first arg must be in **RDI**, so `pop rdi; ret` pops the address
   of `"/bin/sh"` off the stack into RDI, then `ret`s into `system` — hence it's the archetypal x64
   gadget.
5. A **shadow stack** keeps a protected second copy of return addresses; at each `ret` the CPU
   compares the real (attacker-corrupted) return address against the shadow copy — a mismatch faults.
   A **canary** only detects a *contiguous* overwrite of the guard slot; ROP that corrupts return
   addresses without disturbing a canary (or after leaking it) slips past the canary but is caught by
   the shadow-stack comparison.
6. **Not "unexploitable" — "not exploitable *with current primitives*."** You control RIP but lack
   the leak needed to defeat ASLR/PIE and recover the canary; NX rules out stack shellcode. Honest
   verdict: **critical if an information-leak primitive is found** (then ROP is achievable); today a
   reliable **denial-of-service**. Calling it flatly "unexploitable" is the common grading error.

---

## Grading notes (all three lessons)

- **Reward the safety posture.** No student answer should involve a real target, a networked reverse
  shell, or a real CVE. 09.1 and 09.3 require **no exploitation at all**; 09.2's bar is *proof of
  control* (RIP evidence / benign flag). Penalize any attempt to reach outside the sandbox.
- **Reward honesty over bravado.** "Controllable but not reliably exploitable without an info leak"
  is the *correct* professional answer on modern targets — full marks. A fabricated or hand-waved
  "and then I get a shell" against a hardened binary is wrong.
- **Reward mechanism.** As in M04, grade on *why* — why the return address is the target, why NX
  forces ROP, why a canary needs a leak — not on matching a specific offset/address.
- **Verification is part of the finding.** An offset without the `EIP=0x42424242` confirmation, or a
  "shell" without register/flag evidence, is incomplete — the same standard as M04's `id`/flag rule.
