# 03.1 — Host discovery &amp; port scanning: how it works on the wire

<div class="prereq">

**Prerequisites:** [00.1 Ethics &amp; authorization](../module-00/lesson-01.md),
[00.3 Threat modeling &amp; attack surface](../module-00/lesson-03.md),
[01.1 TCP/IP &amp; the three-way handshake](../module-01/lesson-01.md),
[02.1 Reconnaissance](../module-02/lesson-01.md).
**Module:** M03 Scanning &amp; enumeration. **Difficulty:** 🟡 intermediate.
**You will produce:** a defensible interpretation of ambiguous scan output — deciding, from the
*responses on the wire*, which ports are open, closed, or filtered, and what the firewall in front
of them is doing.

</div>

<div class="callout legal">

Scanning is an **active** technique: you send packets *to* the target, and those packets are
logged. It requires authorization, exactly as [00.1](../module-00/lesson-01.md) established. Every
target in this lesson is a **LAB TARGET** — a host on the isolated lab network from
[00.4](../module-00/lesson-04.md) and [`labs/lab-02-recon`](../../labs/lab-02-recon/README.md).
Never scan a host you do not own or lack written authorization to test. Throughout, `TARGET` means
a lab host, never a real system.

</div>

## Why this matters

Recon ([M02](../module-02/lesson-01.md)) told you *which hosts might exist*. Scanning tells you
*which are alive and what they expose*, and every later module begins from a port a scan found open.
But a scan is not a fact-printer; it is an **inference engine**. Nmap never "sees" that a port is
open — it sends a probe, watches what comes back (or doesn't), and *deduces* a state. A firewall, a
rate limiter, or a dropped packet can make that deduction wrong. Read output literally and you report
phantom services and miss real ones. Understand *why* a response implies a state and you can look at
ambiguous output and say what is really happening — the skill this lesson builds.

## Learning objectives

- Explain how host discovery works at each layer (ARP, ICMP, TCP) and why the layer that works
  depends on where you are on the network.
- For each scan type (SYN, connect, UDP, FIN/NULL/Xmas), state which probe goes out, which response
  maps to which port state, and **why** — tied back to the TCP handshake.
- Distinguish `open`, `closed`, and `filtered` and explain why `filtered` is the most information-
  rich (and most misread) verdict.
- Verify any scan finding by hand with `nc` or bash's `/dev/tcp`, and know the limits of speed
  scanners (masscan/rustscan).

## Intuition

Imagine knocking on doors in a building. **Host discovery** is finding which flats are occupied
before you knock on every door. **Port scanning** is the knock. When you knock, one of three things
happens: someone opens the door (open), someone shouts "go away" through it (closed), or there is
silence (filtered — nobody's home, or someone told the doorman to ignore you). The craft of scanning
is telling those three apart from the sound that comes back — and knowing a security guard (a
firewall) can manufacture silence to confuse you.

## The underlying technology: host discovery

Before scanning ports, you establish which hosts respond at all. The right technique depends on
whether you share a **broadcast domain** with the target (link back to layer 2/3 in
[01.1](../module-00/lesson-01.md)).

- **ARP (same subnet).** On your local LAN there is no more reliable discovery than ARP: "who has
  `10.10.10.7`? tell me." A host that answers *exists*, full stop — you cannot firewall away ARP and
  still be on the network. Nmap uses ARP automatically for local targets, which is why `-Pn` is
  pointless on-LAN.
- **ICMP echo (`ping`).** The classic across-subnet probe. Cheap, but frequently dropped by
  firewalls, so "no ping reply" never means "host down."
- **TCP/UDP discovery.** When ICMP is filtered, you infer liveness from transport-layer replies:
  a TCP SYN to 443 or an ACK to 80 that provokes *any* response (SYN/ACK, RST) proves a host is up
  even if it won't answer a ping.

<div class="callout method">

**The discovery trap.** Treating "didn't answer my ping" as "not there" is how testers miss whole
subnets. A host protected by a firewall that drops ICMP but forwards TCP/443 is very much alive.
Probe multiple layers before concluding a host is down; on a subnet, trust ARP over everything.

</div>

## Scan types: what goes out, what comes back, and why

A TCP connection begins with the three-way handshake from
[01.1](../module-01/lesson-01.md): `SYN → SYN/ACK → ACK`. Every TCP scan type is a variation on
*how much of that handshake you perform* and *what the target's TCP stack is obliged to do in
response*. That obligation — defined by RFC 793 — is what lets you infer state.

| Scan (`nmap`) | Probe sent | Reply → state | Why it works |
|---|---|---|---|
| **SYN / half-open** (`-sS`) | bare `SYN` | `SYN/ACK` → **open**; `RST` → **closed**; nothing → **filtered** | The stack *must* answer a SYN to a listening port with SYN/ACK; to a dead port with RST. Nmap replies `RST` instead of `ACK`, so the connection never completes. |
| **Connect** (`-sT`) | full handshake via the OS | connect succeeds → **open**; `RST` → **closed**; timeout → **filtered** | Uses the OS `connect()` syscall. Same logic, but the handshake *completes* (and is far more likely to be logged by the app). |
| **UDP** (`-sU`) | UDP datagram (often empty) | app reply → **open**; ICMP port-unreachable (type 3, code 3) → **closed**; nothing → **open\|filtered** | UDP is connectionless — there is no handshake, so silence is ambiguous. |
| **FIN / NULL / Xmas** (`-sF`/`-sN`/`-sX`) | `FIN` / no flags / `FIN+PSH+URG` | `RST` → **closed**; nothing → **open\|filtered** | RFC 793 says a closed port must `RST` any packet without SYN/RST/ACK, and an *open* port must silently drop it. Windows and many stacks violate this, so results are unreliable. |
| **ACK** (`-sA`) | bare `ACK` | `RST` → **unfiltered**; nothing/ICMP → **filtered** | Doesn't find open ports at all — it maps the *firewall*, telling you which ports a stateful filter lets through. |

<div class="callout recon">

**Read this table as cause → effect, not as commands.** The states are conclusions Nmap draws from
the *packets*. If you understand that a `SYN/ACK` reply means "a TCP stack accepted my SYN," you can
reproduce and check any of these by hand — which is the whole point.

</div>

### Why UDP scanning is unreliable

There is no handshake to lean on. Most UDP services only reply if you send a *protocol-correct*
payload (a DNS query to 53, an SNMP GET to 161). An empty probe to an open UDP port usually gets
**silence** — indistinguishable from a dropped packet — so Nmap reports `open|filtered`. "Closed"
is only knowable when the host bothers to send an ICMP port-unreachable, and hosts rate-limit those
(RFC 1812), so a `/16` UDP sweep can take hours and still be inconclusive. Practical consequence:
UDP scan a **short, targeted list** (53, 69, 123, 161, 500) with version probes (`-sV`), not "all
65535 ports."

## Why this matters to a tester: `filtered` is a finding

Beginners want every port to be `open` or `closed`. The professional pays most attention to
`filtered`, because it describes the **defense**, not the service:

- `closed` — host is up, nothing listening, **and no firewall is dropping it** (you got an RST): the
  host reachably rejects the port.
- `filtered` — *no useful reply*. Something between you and the port is swallowing packets — a
  firewall or ACL — and mapping it (with `-sA`, or by comparing behaviour across ports) is often
  worth more than any single open port.

The difference between "closed" (RST) and "filtered" (silence) is one packet, and it separates "the
host said no" from "someone stopped me from asking." Never blur them.

## How a tester recognizes and interprets output

Real Nmap output, SYN scan of a lab host:

```text
$ sudo nmap -sS -p 22,80,443,445,3306 -Pn 10.10.10.20
Nmap scan report for 10.10.10.20
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
443/tcp  closed   https
445/tcp  filtered microsoft-ds
3306/tcp filtered mysql
```

Interpret skeptically. `443 closed` = an RST came back: the host is reachable and simply isn't
serving HTTPS. `445` and `3306 filtered` = silence: a firewall is dropping them, *or* they are down
and packets are lost. You do **not** yet know a MySQL server exists behind 3306 — only that
something ate your probe. That distinction goes in your notes as a hypothesis, not a fact.

The wire confirms the mechanism. A SYN scan of an **open** port, seen in `tcpdump`:

```text
$ sudo tcpdump -ni eth0 host 10.10.10.20 and port 22
10:14:02.1  IP 10.10.10.5.53344 > 10.10.10.20.22: Flags [S], seq 0
10:14:02.1  IP 10.10.10.20.22 > 10.10.10.5.53344: Flags [S.], seq 0, ack 1   # SYN/ACK = open
10:14:02.1  IP 10.10.10.5.53344 > 10.10.10.20.22: Flags [R]                  # nmap RSTs it
```

Compare a **connect** scan (`-sT`) of the same port — note the handshake *completes* before the
teardown, which is why the target application is far more likely to log a full connection:

```text
10:15:40.2  IP 10.10.10.5.40122 > 10.10.10.20.22: Flags [S], seq 0
10:15:40.2  IP 10.10.10.20.22 > 10.10.10.5.40122: Flags [S.], ack 1
10:15:40.2  IP 10.10.10.5.40122 > 10.10.10.20.22: Flags [.], ack 1           # ACK — connection ESTABLISHED
10:15:40.2  IP 10.10.10.5.40122 > 10.10.10.20.22: Flags [R.]                 # then reset
```

That single extra `ACK` is the practical difference between `-sS` and `-sT`: SYN never establishes,
connect does. `-sS` needs raw-socket privileges (root); `-sT` does not, which is why unprivileged or
pivoted contexts fall back to it.

## Manual investigation: verify by hand

Every scan claim is checkable with tools that do exactly one thing, so you trust the result:

```bash
# Netcat: does a TCP connection actually establish? (-v verbose, -z scan without sending data)
nc -vz 10.10.10.20 22
# → Connection to 10.10.10.20 22 port [tcp/*] succeeded!   → genuinely open

# No netcat? bash speaks TCP directly via /dev/tcp:
timeout 3 bash -c 'echo > /dev/tcp/10.10.10.20/80' && echo OPEN || echo "closed/filtered"

# A hang (timeout fires) = filtered; an instant failure = closed (RST). The delay tells you which.
```

The *timing* is the tell. An open or closed port answers immediately (SYN/ACK or RST). A filtered
port makes you wait for the timeout, because nothing ever comes back. If Nmap says `filtered` but
`nc` connects instantly, re-scan — you hit a transient drop or rate limit.

## Tooling: nmap, and the speed front-ends

**Nmap** ([nmap.org](https://nmap.org/book/)) is the reference scanner. Options that matter and
what they *do*:

- `-sS` / `-sT` / `-sU` — scan technique (above). `-sn` — host discovery only, no port scan.
- `-p-` all 65535 ports; `-p 22,80` a list; `--top-ports 1000` Nmap's frequency-ranked default.
- `-Pn` — skip host discovery, treat host as up (use when ICMP is filtered and you *know* it's
  there; wasteful otherwise).
- `-T0`..`-T5` — timing templates (parallelism + delays). `-T4` is a common LAN default; `-T5` is
  aggressive and **drops accuracy** — fast scans lose replies and manufacture false `filtered`.
- `--reason` — prints *why* Nmap chose each state (`syn-ack`, `reset`, `no-response`). Always use it
  when a result surprises you; it turns the black box back into the table above.

<div class="callout warn">

**LIMITS.** Nmap infers; it can be wrong. Aggressive timing and packet loss create **false
`filtered`** (probe or reply dropped) and, rarely, **false `closed`**. A rate-limiting or
IPS device can make an open port look filtered, or feed you `RST`s for everything. Scanning
through a **NAT/pivot** distorts timing and can hide states entirely. Rule: a state that drives a
decision gets verified by hand, and any single-probe UDP/FIN result is treated as a lead, not proof.

</div>

**masscan / rustscan** are *speed front-ends*, not replacements. Masscan uses its own async stateless
TCP stack to sweep enormous ranges at line rate; RustScan quickly finds open ports then **hands them
to Nmap** for real fingerprinting. The professional pattern: a fast tool to find *what's open across
a big range*, then Nmap `-sV -sC` on just those ports. Speed buys breadth and costs fidelity —
masscan at high rates drops replies and undercounts, so never let its `open` count be the final word.

## Practical lab

<div class="lab">

**Environment:** [`labs/lab-02-recon`](../../labs/lab-02-recon/README.md) — a private
(`internal: true`) Docker range with several hosts and a firewall container. **Time:** ~50 min.
**Targets:** lab hosts only, no Internet route. Bring up with the `lab` helper as the README
documents.

</div>

1. Discovery: run `nmap -sn` across the lab range, then repeat with `--reason`. Which hosts answered
   by ARP vs ICMP vs TCP? Confirm one "down" host is actually up by probing a TCP port directly.
2. Run a SYN scan of one host with `--reason`; capture it in `tcpdump` in a second pane. Match each
   `STATE` to the flags you see on the wire.
3. Run the same scan as `-sT` and diff the packet capture — find the extra `ACK`.
4. Pick one `filtered` and one `closed` port and verify each with `nc -vz` and `/dev/tcp`. Explain
   the timing difference you observe.

## Exercise

<div class="callout method">

**Situation.** You have authorization to test one lab host, `10.10.10.30`, which sits **behind a
firewall container**. Your teammate ran three scans and left you only the output — no packet
captures — and asks you to say what's really going on before anyone touches the host.

```text
# Scan A — SYN scan, default timing
$ sudo nmap -sS -p 22,80,139,443,445,3389 --reason 10.10.10.30
22/tcp   open     ssh          syn-ack ttl 63
80/tcp   open     http         syn-ack ttl 63
139/tcp  filtered netbios-ssn  no-response
443/tcp  closed   https        reset ttl 63
445/tcp  filtered microsoft-ds no-response
3389/tcp filtered ms-wbt-server no-response

# Scan B — same ports, ACK scan
$ sudo nmap -sA -p 22,80,139,443,445,3389 --reason 10.10.10.30
22/tcp   unfiltered ssh          reset ttl 63
80/tcp   unfiltered http         reset ttl 63
139/tcp  filtered   netbios-ssn  no-response
443/tcp  unfiltered https        reset ttl 63
445/tcp  filtered   microsoft-ds no-response
3389/tcp unfiltered ms-wbt-server reset ttl 63
```

**Objective.** Produce an evidence-backed statement of (a) the true state of each port *at the
host*, and (b) what the firewall is doing — as a ruleset in plain English.

**Starting information.** Only the two outputs above. Same TTL (63) on all replies.

**Constraints.** LAB TARGET only; reason from the given evidence — you may propose one confirming
scan/command but must justify it.

**Expected deliverables.**
1. A per-port table: host-level state, firewall behaviour, and the evidence line that proves it.
2. A one-paragraph description of the firewall policy (which ports it passes, which it silently
   drops, and how you can tell drop from reject).
3. The single command you'd run to confirm your read of port **3389**, and what each outcome proves.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Two scans of the same ports disagree in an informative way. What does an ACK scan measure that a SYN
scan doesn't? What does "unfiltered" in scan B tell you about the firewall for a port that scan A
couldn't get an open/closed answer for?
</details>

<details><summary>Hint 2 — technique family</summary>
`-sA` maps the filter, not the service: `RST` back = the packet reached a TCP stack (firewall passes
it); silence = the firewall dropped it. Cross-reference each port between the two scans.
</details>

<details><summary>Hint 3 — where to look</summary>
443: scan A got a `reset` (closed) and scan B got `unfiltered`. 3389: scan A `no-response`, scan B
also `unfiltered` (a reset came back to the ACK). What does "the ACK reached the host but the SYN
didn't" imply about the rule?
</details>

<details><summary>Hint 4 — specific direction</summary>
A firewall that lets an ACK through but drops a SYN to the same port is doing SYN-specific filtering:
the port may be open *at the host* while new connections are blocked. Distinguish "port closed at
host" (443, reset in both) from "port reachable but new-connection-filtered" (3389).
</details>

## Check yourself

<div class="callout key">

1. Nmap reports a port `filtered`. Give two genuinely different causes, and the one command that
   tells them apart.
2. Why does `-sS` require root while `-sT` does not, and what defensive-logging difference follows
   from that?
3. A UDP scan of port 161 returns `open|filtered`. What extra step turns that into a definite
   `open` or `closed`, and why can't the plain scan do it?
4. You scan through a pivot (NAT) and every port shows `filtered`. Before concluding "everything is
   firewalled," what mundane explanations must you rule out?

</div>

Model answers are in `solutions/module-03.md` (instructor material — reason it through first).

## References

- **Nmap Reference Guide & *Nmap Network Scanning*** (Lyon) — port states, scan techniques, timing:
  [nmap.org/book](https://nmap.org/book/).
- **RFC 9293** (obsoletes RFC 793) — TCP; the connection state machine that every TCP scan exploits.
- **RFC 1812** — router requirements, incl. ICMP-error rate limiting (why UDP scans are slow).
- **MITRE ATT&CK T1046** — Network Service Discovery; **T1595** — Active Scanning.
- **NIST SP 800-115** §4 — technical guide to network discovery and port scanning.

## What you should now be able to do

- Choose the right host-discovery layer for where you are, and refuse to call a host "down" on one
  failed probe.
- Predict, for any scan type, which reply implies which state and explain it from the handshake.
- Tell `filtered` from `closed` and treat the firewall's behaviour as a finding in its own right.
- Verify any scan result by hand and state the limits of speed scanners.

## Progress checkpoint

```bash
py course.py complete 03.1
```
