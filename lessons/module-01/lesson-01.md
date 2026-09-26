# 01.1 — TCP/IP &amp; the packet's journey: ports, sockets, the handshake, and what a scanner really does

<div class="prereq">

**Prerequisites:** [00.1 Ethics &amp; authorization](../module-00/lesson-01.md), [00.2 Methodology](../module-00/lesson-02.md), [00.3 Threat modeling](../module-00/lesson-03.md).
**Module:** M01 Networking &amp; protocols for testers. **Difficulty:** 🟢 foundational.
**You will produce:** a written interpretation of real `nmap` and `tcpdump` output that proves, from
the packets alone, what state each port is in and where a firewall sits.

</div>

## Why this matters

Every remote finding in this course begins with a packet leaving your machine and something — or
nothing — coming back. A scanner prints `open`, `closed`, or `filtered`; a junior tester reads
those words as facts and moves on. A professional knows they are **inferences** the tool drew from
the responses it saw, and can reproduce the reasoning by hand. That difference decides whether you
believe a scan result, notice a firewall lying to you, or realize your "closed" port is actually a
dropped packet. When a tool behaves strangely — a scan that hangs, a service that answers from one
host but not another — you debug it at the packet level or not at all. This lesson gives you the
mental model that the whole recon and enumeration phase (M02, M03) is built on.

## Learning objectives

- Describe the TCP/IP layered model just enough to place a problem at the right layer.
- Read the IP, TCP, and UDP header fields a tester actually uses: addresses, ports, flags, TTL.
- Explain the TCP three-way handshake and how SYN, connect, and UDP scans each exploit it.
- Explain **why** a scanner infers `open`, `closed`, or `filtered` from the response (or silence).
- Recognize MTU and fragmentation, and why they matter for both scanning and evasion.
- Verify any scanner's verdict by reading the packets yourself.

## Intuition

Two programs on different machines want to talk. Neither shares memory, a clock, or a hard wire
they control — between them sits an unreliable mesh of routers that may drop, reorder, or delay
anything. **TCP/IP is the set of agreements that turns that mess into a usable conversation.** Think
of it as nested envelopes: your data goes in a TCP or UDP envelope (which port, which conversation),
that goes in an IP envelope (which machine), that goes in a frame (which next hop on this wire). Each
layer adds only what it needs and trusts the layer below to carry it. A scanner is just a program
that sends carefully chosen envelopes and reads the replies — or the silence — to deduce what is
listening on the other side.

## The underlying technology: layers, just enough

You do not need the full seven-layer OSI liturgy. You need to know **which layer owns a problem** so
you look in the right place:

| Layer (TCP/IP) | Unit | Addresses with | Tester cares about |
|---|---|---|---|
| Link (e.g. Ethernet) | frame | MAC address | local network, ARP, MTU |
| Internet (IP) | packet | IP address | reachability, routing, TTL, fragmentation |
| Transport (TCP/UDP) | segment / datagram | port | which service, connection state, scan logic |
| Application (HTTP, DNS, TLS…) | message | — | the actual content (01.2) |

The rule of thumb: if two hosts can't reach each other at all, suspect IP/routing (01.3). If they
reach each other but a *service* won't answer, suspect the transport layer or a firewall. If the
connection works but the data is wrong, you're at the application layer.

### The IP header — the fields that matter

An IPv4 header (RFC 791) is 20 bytes without options. The fields a tester reads:

```text
Source IP / Destination IP  — who's talking; the basis of every scope decision
Protocol                    — 6 = TCP, 17 = UDP, 1 = ICMP (what's inside)
TTL (Time To Live)          — hop countdown; a router decrements it, drops at 0
Identification / Flags / Fragment Offset — fragmentation control (see MTU below)
Total Length                — header + payload size
```

**TTL is quietly useful.** Each router decrements it by one; when it hits zero the packet is
discarded and an ICMP "time exceeded" is returned — that is exactly how `traceroute` maps a path.
The *arriving* TTL also fingerprints the sender's OS: common initial values are 64 (Linux/macOS),
128 (Windows), and 255 (many network devices). A reply arriving with TTL 122 probably started at 128
and crossed six hops — a free hint about the target's OS and distance before you send a single probe.

### TCP vs UDP — reliable stream vs fire-and-forget

**TCP (RFC 9293, formerly 793)** provides a reliable, ordered, connection-oriented byte stream. It
costs a handshake up front and tracks state on both ends. **UDP (RFC 768)** is a single datagram
with no handshake, no ordering, no delivery guarantee — you send it and hope. This difference is the
root of why TCP and UDP scanning behave so differently.

The TCP header fields a tester lives by:

```text
Source Port / Destination Port  — which conversation, which service
Sequence / Acknowledgment number — ordering & reliability; the handshake negotiates these
Flags:  SYN  — synchronize; open a connection
        ACK  — acknowledge received data
        FIN  — graceful close
        RST  — reset; "there is nothing here / go away"
        PSH, URG — push/urgent (rarely relevant to scanning)
Window  — flow control (how much the sender will accept)
```

Two flags carry most of the scanning meaning: **SYN** starts a conversation, and **RST** is a flat
refusal. Learn to read those two and most scan behavior explains itself.

## The TCP three-way handshake

Before any data flows, TCP performs a three-way handshake to synchronize sequence numbers and
confirm both directions work:

```text
Client ── SYN (seq=x) ─────────────▶ Server      "let's talk; my sequence starts at x"
Client ◀── SYN, ACK (seq=y, ack=x+1) ─ Server     "ok; mine starts at y, I got your x"
Client ── ACK (ack=y+1) ───────────▶ Server      "got it — connection established"
```

After the third packet the connection is **established** and data can flow. To close gracefully each
side sends a **FIN** and the other **ACK**s it. At any point a **RST** aborts the connection
immediately — no negotiation. That is the whole protocol you need to reason about scanning.

## Sockets and port states — and why a scanner infers each

A **socket** is one endpoint of a connection, identified by the four-tuple
`(source IP, source port, destination IP, destination port)` plus the protocol. A server "listens"
on a port; the OS routes an incoming segment to whichever process owns that socket. A port is not a
physical thing — it is a number the kernel uses to demultiplex traffic to the right program.

Now the key insight of the whole lesson. Nmap prints three states, and each is a **deduction from
how the target responded to a probe**:

<div class="callout recon">

- **`open`** — a service is listening and completed (or offered to complete) the handshake. For a
  SYN probe: the target answered **SYN/ACK**. Something is there.
- **`closed`** — the host is up and reachable, but nothing is listening on that port. The target
  answered **RST**. The port is reachable; it just has no service.
- **`filtered`** — **no useful answer came back** (silence, or an ICMP administratively-prohibited
  message). A firewall dropped the probe or its reply. The scanner cannot tell open from closed
  because something in the path is interfering.

</div>

Read that table again as *cause → effect*. `open` and `closed` both mean the packet **reached a live
host** — one had a listener, one didn't. `filtered` means you never got a straight answer, which is
itself a finding: it usually means a firewall. A useful diagnostic corollary: a host that returns
`closed` on some ports and `filtered` on others is telling you the firewall is *selective* — it
permits some ports to the host and drops others.

## Scan types as handshake tricks

Scanners are just programs that manipulate the handshake and interpret the reply:

<div class="callout method">

- **TCP connect scan** (`nmap -sT`) — asks the OS to fully `connect()`. Completes the whole
  three-way handshake, so it is reliable and needs no special privileges, but it is **loud**: the
  service sees a real connection and likely logs it.
- **SYN / half-open scan** (`nmap -sS`, the default when privileged) — sends only the SYN. If it
  gets **SYN/ACK** it marks `open` and immediately sends **RST** to tear down before the handshake
  finishes, so the connection never fully forms. Faster and quieter, but needs raw-socket privilege.
- **UDP scan** (`nmap -sU`) — sends a UDP datagram. There is no handshake, so inference is harder:
  an application reply means `open`; an **ICMP port-unreachable (type 3, code 3)** means `closed`;
  **silence** means `open|filtered` — the scanner genuinely can't distinguish a dropped probe from a
  service that simply doesn't answer that input. This is why UDP scanning is slow and ambiguous.

</div>

<div class="callout key">

The single most important sentence in this lesson: **a scanner does not "see" a port state — it
infers one from a reply (SYN/ACK, RST, ICMP) or from silence.** Change the network in between (add a
firewall, drop replies) and the same port yields a different verdict. Always ask *what packet proved
this?*

</div>

## MTU and fragmentation, briefly

Every link has a **Maximum Transmission Unit** — the largest frame it will carry (typically 1500
bytes on Ethernet). A packet larger than the path's MTU must be **fragmented** into pieces that are
reassembled at the destination, or dropped if the "Don't Fragment" bit is set (which is how **Path
MTU Discovery** finds the limit). Two reasons a tester cares:

- **Broken connectivity** — if PMTUD is blackholed (ICMP filtered), large packets vanish while small
  ones get through; a handshake succeeds but data transfer stalls. Recognizing this saves hours.
- **Evasion, historically** — splitting a probe across tiny fragments (`nmap -f`) once slipped past
  simple packet filters that only inspected the first fragment. Modern stateful firewalls reassemble
  before inspecting, so treat this as **DEPRECATED** against current defenses — know it exists, don't
  rely on it.

## How a tester recognizes and uses this on the wire

You confirm every scanner claim by watching the packets. `tcpdump` (or Wireshark) shows you the
truth the scanner summarized:

```text
# A port that is OPEN — the target answers SYN/ACK to our SYN
10.10.0.5.51920 > TARGET.80: Flags [S], seq 1, win 64240      # our SYN
TARGET.80 > 10.10.0.5.51920: Flags [S.], seq 9, ack 2, win 65160  # SYN/ACK  → open
10.10.0.5.51920 > TARGET.80: Flags [R], seq 2                 # our RST (half-open teardown)

# A port that is CLOSED — the target answers RST
10.10.0.5.51921 > TARGET.81: Flags [S], seq 1
TARGET.81 > 10.10.0.5.51921: Flags [R.], seq 1, ack 2         # RST/ACK → closed

# A port that is FILTERED — we send SYN, nothing comes back (retransmits, then silence)
10.10.0.5.51922 > TARGET.445: Flags [S], seq 1
10.10.0.5.51922 > TARGET.445: Flags [S], seq 1                # retransmit — still no reply → filtered
```

`[S]` is SYN, `[S.]` is SYN/ACK (the dot is ACK), `[R.]` is RST/ACK, `[R]` is RST. Once you can read
those, you never have to trust a scanner blindly again.

## Tooling — what it does, key options, limits, verify by hand

<div class="callout method">

**`tcpdump`** — captures packets and prints one line each. What it shows: the five-tuple, flags,
sequence/ack, TTL, length. Key options: `-n` (no DNS resolution, so capture doesn't itself generate
lookups), `-i <iface>`, `-X` (hex+ASCII payload), `host TARGET and port 80` (BPF filter),
`-w file.pcap` (save for Wireshark). *Limit:* it shows what arrives on your interface — it can't see
packets a firewall dropped upstream. *Verify:* compare what you sent vs. what returned.

**`nmap`** — sends probes and infers state. Key options: `-sS`/`-sT`/`-sU` (scan type), `-p` (ports),
`-Pn` (skip host-discovery ping — essential when ICMP is filtered or the scanner wrongly calls a live
host "down"), `--reason` (prints *why* it chose each state, e.g. `syn-ack` vs `no-response` — this is
the tool showing its own inference), `-v`. *Limit:* every verdict is only as honest as the network
path; a filtering device can make open look filtered or forge RSTs. *Verify:* run the same probe
under `tcpdump` and read the reply yourself.

</div>

<div class="callout legal">

**LAB TARGETS ONLY.** Every `TARGET` in this course is a host on the isolated lab network from
[`labs/README.md`](../../labs/README.md). Scanning is active interaction with a system — do it only
against the lab, never a real host you are not explicitly authorized to test (00.1). Even a
"harmless" port scan of a stranger's network can be an offense.

</div>

## Practical

<div class="lab">

**Environment:** the shared attacker box on the private lab network; a single `TARGET` lab host.
**Time:** ~40 min. **Targets:** one lab host only — no Internet targets.

</div>

1. In one terminal, run `sudo tcpdump -n -i <iface> host TARGET`.
2. In another, scan three ports you expect to differ — e.g. `nmap -sS --reason -p 22,81,445 TARGET`.
3. For each port, match the `--reason` string (`syn-ack`, `reset`, `no-response`) to the packets
   `tcpdump` recorded. Write, in your own words, what response (or silence) proved the state.
4. Re-run with `-sT` and note how the packet trace changes (full handshake vs. half-open + RST).
5. Note the arriving TTL and estimate the target OS family and hop distance.

## Exercise

<div class="callout method">

**Situation.** You are given a capture and a scan from an authorized test of one lab host, `TARGET`.
You must explain the network *from the evidence*, not from the tool's summary words.

**Objective.** Determine the true state of each port and locate any filtering device, justifying
every conclusion with the specific packet (or absence) that proves it.

**Starting information.** The following artifacts (lab data):

```text
$ nmap -sS --reason -p 22,80,139,445,3389 TARGET
PORT     STATE    SERVICE     REASON
22/tcp   open     ssh         syn-ack ttl 63
80/tcp   open     http        syn-ack ttl 63
139/tcp  closed   netbios-ssn reset   ttl 63
445/tcp  filtered microsoft-ds no-response
3389/tcp filtered ms-wbt-server no-response
```

```text
$ sudo tcpdump -n host TARGET
IP 10.10.0.5.40001 > TARGET.22:   Flags [S],  seq 1
IP TARGET.22   > 10.10.0.5.40001: Flags [S.], seq 100, ack 2, ttl 63
IP 10.10.0.5.40001 > TARGET.22:   Flags [R],  seq 2
IP 10.10.0.5.40002 > TARGET.139:  Flags [S],  seq 1
IP TARGET.139  > 10.10.0.5.40002: Flags [R.], seq 1, ack 2, ttl 63
IP 10.10.0.5.40003 > TARGET.445:  Flags [S],  seq 1
IP 10.10.0.5.40003 > TARGET.445:  Flags [S],  seq 1        # retransmit, no reply
IP 10.10.0.5.40004 > TARGET.3389: Flags [S],  seq 1
IP 10.10.0.5.40004 > TARGET.3389: Flags [S],  seq 1        # retransmit, no reply
```

**Constraints.** Reason from the packets only. Lab data — you are not scanning anything now.

**Expected deliverables.**
1. A per-port table: state + the exact packet (or silence) that proves it.
2. A one-paragraph argument for whether a firewall is present and, if so, roughly what rule it
   enforces — permit vs. drop, and on which ports — with your evidence.
3. One sentence on what the arriving TTL of 63 suggests about the target OS and the hop count.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Group the ports by what came back: a SYN/ACK, a RST, or nothing. Each group maps to exactly one
state. The interesting question is what the "nothing" group has in common.
</details>

<details><summary>Hint 2 — the discriminating detail</summary>
139 answered RST (reachable, no listener) but 445 and 3389 answered nothing at all. If the host is
up enough to RST on 139, why would it be totally silent on 445? What sits between you and the host
that treats those ports differently?
</details>

<details><summary>Hint 3 — the TTL clue</summary>
Common initial TTLs are 64, 128, 255. If replies arrive with 63, how many hops away is the host, and
which OS family started at that initial value?
</details>

## Check yourself

<div class="callout key">

1. Nmap says a port is `filtered`. Name two physically different situations that produce that exact
   verdict, and how you would tell them apart.
2. Why can a SYN scan be quieter than a connect scan even though both touch the same port? What does
   the target's application actually see in each case?
3. UDP scanning reports `open|filtered` far more than TCP reports `filtered`. Explain why the
   ambiguity is inherent to UDP, not a weakness of the tool.
4. You scan a host and every single port — even ones you know host services — comes back `filtered`,
   yet you can browse its website fine. What is the most likely explanation, and which nmap option
   addresses it?

</div>

Model answers are in `solutions/module-01.md` (instructor material — reason it out first).

## References

- **RFC 791** — Internet Protocol (IPv4 header, TTL, fragmentation).
- **RFC 9293** — Transmission Control Protocol (obsoletes RFC 793; handshake, flags, states).
- **RFC 768** — User Datagram Protocol.
- **RFC 1122 / 1123** — Requirements for Internet Hosts (host-side behavior).
- **RFC 792** — ICMP (port-unreachable, time-exceeded — the messages scanners read).
- **Nmap Reference Guide** — "Port Scanning Techniques" and "Host Discovery" (nmap.org/book).
- **NIST SP 800-115** §4 — technical review techniques (network discovery, port scanning).

## What you should now be able to do

- Place a connectivity problem at the right TCP/IP layer.
- Read IP/TCP/UDP header fields — addresses, ports, flags, TTL — from a capture.
- Explain the three-way handshake and how SYN, connect, and UDP scans exploit it.
- Justify every `open`/`closed`/`filtered` verdict from the packet that produced it, and spot a
  firewall from the pattern of silence.
- Verify any scanner's claim by hand with `tcpdump`.

## Progress checkpoint

```bash
py course.py complete 01.1
```
