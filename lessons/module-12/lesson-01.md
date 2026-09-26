# 12.1 — Port forwarding &amp; tunneling: local/remote/dynamic SSH, SOCKS &amp; proxychains

<div class="prereq">

**Prerequisites:** [00.1](../module-00/lesson-01.md) (authorization &amp; scope),
[01.3](../module-01/lesson-03.md) (routing, NAT, firewalls, proxies — the machinery this lesson
weaponizes), [04.1–04.2](../module-04/lesson-01.md) (a Linux foothold and shell fluency), and
[M11 Lateral movement](../module-11/lesson-01.md) (you have *a* foothold; now you must *reach
through* it).
**Module:** M12 Pivoting &amp; complex networks. **Difficulty:** 🔴 advanced.
**You will produce:** a working SSH tunnel of each type (local, remote, dynamic) against the lab
pivot, a `proxychains.conf` you can explain line by line, and a justified choice of forward type
for a stated reachability problem.

</div>

## Why this matters

You have a shell on a host. That is rarely the goal — it is a **vantage point**. The systems the
client actually cares about (the database, the domain controller, the file server) usually live on
network segments you cannot touch directly from your attack box, exactly as [01.3](../module-01/lesson-03.md)
predicted: private addressing (RFC 1918) and NAT mean the Internet has *no route* to them, and
firewalls drop your unsolicited probes. The compromised host, however, **can** reach them — that is
what it was built to do. Pivoting is the discipline of borrowing that host's network position to
reach in-scope targets you otherwise never could.

Port forwarding and tunnelling are the mechanical core of pivoting. Get them wrong and you burn
hours wondering why a scan through a proxy returns nothing; get them right and a single SSH session
turns one foothold into reachability across a whole segment. This lesson builds the mental model —
*who connects to whom* — that makes the difference between memorising four SSH flags and knowing
which one to reach for when a firewall blocks you.

## Learning objectives

- Recap *why* routing and NAT make internal hosts unreachable, and state precisely what a pivot
  changes about reachability.
- Distinguish **local (`-L`)**, **remote (`-R`)**, and **dynamic (`-D`) SSH forwarding** by the
  single question *which side initiates the TCP connections* — and pick the right one for a given
  firewall direction.
- Stand up a **SOCKS proxy** with `ssh -D` and route arbitrary tools through it with
  **proxychains-ng**, reading and writing a `proxychains.conf`.
- Run enumeration tools **through a pivot**, and explain their hard limits (no raw ICMP, no SYN
  scans, TCP-connect only) from how SOCKS actually works.
- State the segmentation remediation and the detection signature for tunnelling activity.

## Intuition

Recall the one-line truth from [01.3](../module-01/lesson-03.md): **reachability is a property of a
path, not of a host.** Your attack box and your foothold sit at different points on the network, so
they see different worlds. A pivot is simply a way to *send your traffic from the foothold's
vantage point instead of your own* — you hand a packet to the host you control and ask it to make
the connection for you, then relay the answer back.

Everything in this lesson is a variation on that one idea. The only thing that ever changes is
**which machine opens the TCP connection to whom**, and in which direction the tunnel itself is
established. Firewalls care enormously about direction (a stateful firewall permits replies to
connections that started on the trusted side and drops fresh inbound ones — [01.3](../module-01/lesson-03.md)).
So the question that selects your forwarding type is always: *which direction is still allowed, and
which side can I make initiate?*

## The underlying technology

### Routing recap — why the internal host hides

<div class="callout method">

Before any tunnel, read your position. On the foothold, `ip addr` / `ip route` (or `ipconfig` /
`route print` on Windows) tell you which networks it is *directly* attached to. A **dual-homed
host** — two interfaces, e.g. `eth0 = 10.10.0.5/24` (DMZ) and `eth1 = 172.16.20.5/24` (internal) —
is the classic pivot: it straddles a trust boundary the firewall was meant to enforce. Your attack
box has no route to `172.16.20.0/24`; the foothold has one on `eth1`. That asymmetry is the entire
opportunity.

</div>

An internal host at `172.16.20.30` is unreachable from your attack box for the reasons
[01.3](../module-01/lesson-03.md) established: its address is not routable across the boundary, NAT
creates no inbound mapping for it, and the firewall drops unsolicited inbound SYNs. None of that
constrains the dual-homed foothold, which is *on* `172.16.20.0/24`. A tunnel through the foothold
lets you issue connections as if you were standing on that interface.

### SSH port forwarding — one protocol, three directions

OpenSSH multiplexes extra TCP channels inside an existing SSH session. Because those channels ride
inside the encrypted session, a firewall sees only the SSH connection it already permitted; the
forwarded traffic is invisible to port-based rules. Three forms, and the *only* thing that differs
is who listens and who connects:

**Local forward — `ssh -L [bind:]LPORT:DEST:DPORT user@pivot`.** SSH opens a listener **on your
machine** (`LPORT`). When you connect to it, the **pivot** makes the onward connection to
`DEST:DPORT` and relays bytes back through the session.

```text
you:8080  ──▶  [ssh listener on YOU] ══SSH══▶ [pivot] ──▶ internal:80
   (you connect here)                                     (pivot connects here)
```

```bash
# LAB ONLY. Reach the internal web server (172.16.20.30:80) that you can't route to,
# by connecting to localhost:8080 on your attack box.
ssh -L 8080:172.16.20.30:80 lab@10.10.0.5
curl http://127.0.0.1:8080/          # → served by 172.16.20.30, via the pivot
```

Mental model: **you initiate, into the pivot's network.** Use `-L` when you want to reach *one*
specific service on the far side and the firewall lets you SSH *to* the pivot.

**Remote forward — `ssh -R [bind:]RPORT:DEST:DPORT user@pivot`.** The mirror image. SSH opens a
listener **on the pivot** (`RPORT`); when something on the pivot's side connects to it, **your
machine** makes the onward connection to `DEST:DPORT`.

```text
pivot:9001 ──▶ [ssh listener on PIVOT] ══SSH══▶ [YOU] ──▶ DEST:DPORT
 (far side connects here)                                (you connect here)
```

```bash
# LAB ONLY. Expose your attack box's Metasploit/HTTP listener (127.0.0.1:443) *on the pivot*,
# so an internal host that can reach the pivot but not you can call back to you.
ssh -R 9001:127.0.0.1:443 lab@10.10.0.5
```

Mental model: **the far side initiates, back toward you.** `-R` exists for the case where you
cannot connect *inbound* to the pivot's network at all — you make the pivot reach *out* to you and
then push a listener back over that same session. This is the seed of the reverse-tunnel idea that
[12.2](lesson-02.md) develops with Chisel.

**Dynamic forward — `ssh -D [bind:]LPORT user@pivot`.** Instead of one fixed `DEST:DPORT`, SSH
opens a **SOCKS proxy** on `LPORT` on your machine. Any tool that speaks SOCKS hands it a
destination *per connection*, and the pivot connects there on demand.

```text
you:1080 (SOCKS) ══SSH══▶ [pivot] ──▶ anything the pivot can reach, chosen per connection
```

```bash
# LAB ONLY. One command turns the pivot into a general-purpose proxy into its networks.
ssh -D 1080 lab@10.10.0.5
```

Mental model: **you initiate, to *anything* the pivot can reach, decided per connection.** This is
the workhorse for *enumerating* a segment, because you don't yet know which hosts or ports you
want — you want to scan the whole range. `-L` reaches a known service; `-D` reaches an unknown
network.

<div class="callout key">

The whole taxonomy collapses to two questions. **(1) Which side opens the TCP connections?** Local
and dynamic: you do (into the pivot's network). Remote: the far side does (back to you). **(2) One
fixed destination or many?** Local/remote: one (`DEST:DPORT` baked into the flag). Dynamic: many
(chosen per connection via SOCKS). Memorise those two axes and you never confuse the flags again.

</div>

### SOCKS and proxychains — routing tools that don't speak proxy

`ssh -D` gives you a SOCKS5 proxy, but most offensive tools (`nmap`, `curl`, a custom script) don't
natively know to use it. **proxychains-ng** solves this by hooking the libc connect() calls of a
program with `LD_PRELOAD` and redirecting every outbound TCP connection through the SOCKS proxy.
You prefix a command with `proxychains` and it transparently tunnels.

```ini
# /etc/proxychains.conf  (or a local copy passed with -f)
strict_chain            # use every proxy listed, in order (fail if one is down)
proxy_dns               # resolve hostnames through the proxy, not locally — avoids DNS leaks
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 1080   # the ssh -D proxy above
```

```bash
# LAB ONLY. Curl an internal host through the SOCKS proxy, resolving its name on the far side.
proxychains curl http://intranet.corp.lab/
```

`proxy_dns` matters for a subtle reason: if proxychains resolved names *locally*, your attack box
would try to look up `intranet.corp.lab` (which it can't reach) and leak the query; routing DNS
through the proxy means the pivot's resolver answers, as an internal client would.

## Why the weakness exists

Nothing here exploits a bug. Pivoting works because the network's own design — a host deliberately
connected to two segments, a firewall that trusts connections originating inside, SSH that anyone
can use to open channels — was intended for legitimate traffic and cannot tell your relayed bytes
from an administrator's. The *organisational* weakness pivoting demonstrates is **insufficient
segmentation** (CWE-923, improper restriction of communication channels): the DMZ host was allowed
to talk to the internal segment, so whoever controls it inherits that permission. That is the
finding you ultimately write up, not "SSH has a `-L` flag."

## How a tester recognises when a pivot is needed

<div class="callout method">

You need a pivot the moment you observe **an asymmetry between what your attack box can reach and
what your foothold can reach**. Concrete signals:

- Your external scan of the target range returns almost nothing, but from the foothold `ip route`
  shows a second interface on a fresh RFC 1918 range you never saw from outside.
- The foothold's `arp -a`, `ss -tnp` / `netstat -ano`, or `/etc/hosts` reference hosts and services
  on addresses your box can't route to.
- A configuration or connection string on the foothold points at `db.internal`, `10.x`, or
  `172.16.x` — the app talks to something you can't.
- A finding in the report of the form *"the DMZ web server can reach the internal database segment"*
  is itself valuable — reachability across a boundary is the point, exploited or not
  ([00.1](../module-00/lesson-01.md)).

</div>

## Manual investigation

Before tunnelling, enumerate the foothold's network position by hand so you tunnel *deliberately*:

```bash
ip addr; ip route            # interfaces and routes — find the second segment
ss -tnlp                     # what's listening locally (services only bound to loopback are prizes)
cat /etc/resolv.conf         # the internal resolver — you'll want proxy_dns to use it
arp -a                       # neighbours the host has already talked to = live internal hosts
```

Services bound to `127.0.0.1` on the pivot (a database, an admin panel) are a special case: nothing
*outside* the host can reach them, but a `-L` forward to `127.0.0.1:PORT` on the pivot exposes them
straight to you. Loopback-only services are one of the highest-value things a foothold reveals.

## Tooling — what it does, key options, limits, verify

- **OpenSSH client** (`-L`/`-R`/`-D`). Adds: `-N` (no remote command — just forward), `-f`
  (background), `-g` (let *other* hosts use your local listener — use with care, it exposes your
  proxy). *Limit:* needs SSH access to the pivot and a shell/credentials there. *Verify:* `ss -tnlp`
  shows your listener; connect and confirm the response comes from the far host.
- **proxychains-ng** (`proxychains <cmd>`, `-f conf` for a custom file). *What:* forces a program's
  TCP through the SOCKS proxy via `LD_PRELOAD`. *Limits (critical):* only intercepts **TCP** made
  through libc `connect()` — **no ICMP, no UDP-based scans, no raw-socket SYN scans**, and statically
  linked binaries slip past the hook. *Verify:* run with the proxy down and confirm the tool fails
  (proving traffic really went through it).
- **sshuttle** — a "poor man's VPN over SSH" that transparently routes whole subnets, no SOCKS-per-tool
  needed. *Limit:* still TCP (plus DNS); needs Python on the pivot; less surgical than SSH forwards.
  A convenient alternative once you understand the SSH primitives underneath.

## Demonstration (LAB ONLY)

<div class="callout attack">

**Technique — enumerate and reach an internal service through a dynamic SSH tunnel.**

```bash
# 1) Open a SOCKS proxy through the dual-homed pivot (foothold from M11).
ssh -f -N -D 1080 lab@10.10.0.5

# 2) Point proxychains at it (proxychains.conf as above), then discover live internal hosts.
#    -sT  = TCP connect scan (the ONLY scan SOCKS can carry — no raw SYN/ICMP).
#    -Pn  = skip host discovery (ping can't traverse SOCKS, so treat every host as up).
#    -n   = no DNS (or set proxy_dns and let the pivot resolve).
proxychains nmap -sT -Pn -n -p 22,80,443,445,3306 172.16.20.0/24

# 3) Reach the internal web app the scan found, straight through the proxy.
proxychains curl -s http://172.16.20.30/ | head

# 4) For a service you'll hit repeatedly, pin a local forward instead of the SOCKS route.
ssh -f -N -L 3306:172.16.20.40:3306 lab@10.10.0.5
mysql -h 127.0.0.1 -P 3306 -u lab -p    # the internal DB, as if it were local
```

Why `-sT -Pn` is not optional: proxychains can only relay what SOCKS understands, and SOCKS carries
**established TCP connections**. Nmap's default `-sS` (raw SYN) and its ICMP host-discovery both need
raw sockets the proxy cannot forward, so they silently produce nothing. `-sT` asks the OS to make a
full connect() — which proxychains *can* hook — and `-Pn` stops nmap from trying to ping first.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Every address above (`10.10.0.5`, `172.16.20.0/24`) belongs to
`labs/lab-12-pivot` on the isolated lab network, reached as the synthetic `lab` user against benign
`LAB-FLAG-{uuid}` markers. Pivoting is a legitimate technique for reaching **in-scope** internal
targets — but a tunnel makes it trivially easy to touch a host that is *out* of scope. Before every
pivot, re-confirm the destination segment is inside the authorised scope ([00.1](../module-00/lesson-01.md)).
A pivot is not permission; scope is.

</div>

## Verification

A tunnel is "working" only when you can show the traffic reached the far side. Prove it: `ss -tnlp`
lists your forward's listener; a request to `127.0.0.1:LPORT` returns content whose banner, title,
or flag identifies the **internal** host, not the pivot; `proxychains` prints its per-hop
`...OK`/`...timeout` chain line for each connection. Capture that evidence — a screenshot of the
proxied `curl` returning the internal app's `LAB-FLAG-{uuid}` is the artifact your report needs, not
"I set up a tunnel."

## Impact

One tunnelled foothold converts a single-host compromise into reachability across an entire segment
the client believed was protected by network position. In business terms: the perimeter and the
internal firewall assumed attackers would arrive *from outside*; a pivot arrives *from inside*, past
both. Everything the pivot can reach — databases, management interfaces, other footholds
([M11](../module-11/lesson-01.md)) — is now in play, and the segmentation control the client paid for
is demonstrably bypassable. That demonstrated bypass, mapped to the specific allowed path, is the
finding.

## Remediation — segmentation

<div class="callout defend">

- **Egress filtering from the pivot.** A DMZ host should reach *only* the specific internal
  endpoints its function requires (that one app port on that one DB host), by an allow-list, not the
  whole internal range. Most tunnels die if the pivot cannot open arbitrary onward connections.
- **Restrict SSH and outbound reach.** Limit which hosts may run SSH and where they may connect;
  block a DMZ host from initiating connections back to the Internet (kills reverse tunnels — [12.2](lesson-02.md)).
- **Least privilege on the foothold.** Pivoting needs a usable account on the pivot; strong auth,
  no shared credentials, and no unnecessary interactive shells raise the cost.
- **Micro-segmentation / host firewalls.** Enforce boundaries at the host, not only at the network
  edge, so compromising one host does not grant a whole VLAN. This is the NIST SP 800-125B
  segmentation principle applied inside the perimeter.

</div>

## Detection / blue-team view

<div class="callout defend">

- **Long-lived SSH sessions with unusual channel patterns** — an SSH connection carrying many
  forwarded channels, or one from a DMZ host outbound to the Internet, is anomalous. This is MITRE
  ATT&CK **T1572 (Protocol Tunneling)** and **T1090 (Proxy)**, including **T1090.001 (internal
  proxy)** for pivoting between internal hosts and **T1090.002 (external proxy)** for tunnels out.
- **A host suddenly initiating connections it never made before** — the DMZ web server opening
  connections to the internal DB VLAN, or a burst of connections across a `/24` (a proxied scan)
  from one source. Flow/NetFlow anomalies and internal IDS catch this.
- **The tunnel's fingerprint through a proxy** — proxied scans are TCP-connect only and often lack
  the timing of a normal client; `-Pn` scans leave many half-completed connections. East-west
  monitoring, not just perimeter monitoring, is what surfaces it, which is exactly why internal
  segmentation and telemetry matter.

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-12-pivot` (built separately) — a multi-network topology: your attack box
→ a dual-homed **DMZ** host (`10.10.0.5`, reachable) → an **internal** segment (`172.16.20.0/24`,
*not* routable from your box) → a **restricted** segment (12.2). **Access:** an SSH-capable `lab`
foothold on the DMZ host (from M11). **Targets:** lab hosts only; benign `LAB-FLAG-{uuid}` markers on
internal services prove reach. **Time:** ~75 min. **Isolation:** private Docker networks, no Internet
route; reset per the lab README between attempts.

</div>

1. On the DMZ foothold, map its network position by hand (`ip addr`, `ip route`, `ss -tnlp`,
   `arp -a`). Identify the second interface and any loopback-only services.
2. Stand up all three forward types in turn: a `-L` to one internal service, a `-D` SOCKS proxy, and
   a `-R` that exposes a listener on the pivot. Verify each with `ss` and a request.
3. Through the SOCKS proxy + proxychains, run a `-sT -Pn` scan of `172.16.20.0/24` and reach one
   internal service, capturing its `LAB-FLAG-{uuid}` as evidence.
4. Note which forward type you would keep for ongoing work and why.

## Exercise

<div class="callout method">

**Situation.** Authorised internal engagement. You hold an SSH foothold as `lab` on a **dual-homed**
host: `eth0 = 10.10.0.5/24` (the DMZ segment your attack box shares) and `eth1 = 172.16.20.5/24` (an
internal segment your attack box cannot route to). Scope explicitly includes `172.16.20.0/24`. The
internal segment hosts a web admin panel on `172.16.20.30:8080` and a database on
`172.16.20.40:3306`. A stateful firewall permits your attack box to SSH *to* `10.10.0.5` but drops
all other inbound traffic to the DMZ segment.

**Objective.** Reach the internal admin panel from your attack box's browser **and** be able to run
`nmap` across the internal `/24`, then justify — in mechanism terms — which forward type you chose
for each task and why the alternatives were wrong.

**Starting information.** The topology above; SSH access to the pivot; a working `proxychains`
install on your attack box.

**Constraints.** Lab target only; every destination must be inside `172.16.20.0/24` (in scope). No
scanning outside the authorised range even though the tunnel would let you. Explain mechanisms, and
capture verification evidence, not just "it worked."

**Expected deliverables.**
1. The exact command(s) you ran for each of the two tasks, and the resulting evidence (listener
   shown by `ss`, the panel's content/flag, the scan output).
2. A justification, per task, naming the forward type and answering the two selection questions
   (*which side initiates? one destination or many?*) — and stating why the other two types were a
   worse fit.
3. One sentence on how the firewall's *direction* (inbound-to-DMZ blocked, SSH-to-pivot allowed)
   shaped your choice, tying back to [01.3](../module-01/lesson-03.md).

</div>

<details><summary>Hint 1 — conceptual direction</summary>
For each task ask the two questions from the key callout. Reaching <em>one known</em> web panel is a
different problem from <em>scanning an unknown range</em> — one destination vs many. That alone
picks between <code>-L</code> and <code>-D</code>.
</details>

<details><summary>Hint 2 — technique family</summary>
You can SSH <em>to</em> the pivot, so you can make connections <em>into</em> its network — that rules
in local and dynamic forwarding and rules out needing a remote (<code>-R</code>) tunnel here. Which
of local/dynamic fits "browse one service" and which fits "scan a whole subnet"?
</details>

<details><summary>Hint 3 — where to look</summary>
For the scan, remember what SOCKS can and cannot carry. Which nmap flags are mandatory through
proxychains, and why do the defaults return nothing? For the panel, a single fixed
<code>DEST:DPORT</code> is all you need.
</details>

<details><summary>Hint 4 — specific direction</summary>
Browse the panel with <code>ssh -L 8080:172.16.20.30:8080 lab@10.10.0.5</code> then hit
<code>127.0.0.1:8080</code>. Scan through <code>ssh -D 1080</code> + <code>proxychains nmap -sT -Pn
-n ...</code>. Do NOT claim a remote forward is needed — the firewall lets you initiate toward the
pivot.
</details>

## Check yourself

<div class="callout key">

1. You can SSH to a pivot but the pivot's network cannot initiate any connection back to your attack
   box. Which forward types still work, and which becomes impossible? Explain from *who initiates*.
2. A colleague runs `proxychains nmap -sS -Pn 172.16.20.0/24` through an `ssh -D` proxy and gets zero
   results, though a `-L` forward to one of those hosts works fine. What is wrong, mechanically, and
   what is the fix?
3. A database on the pivot is bound to `127.0.0.1:5432` and rejects every connection from other
   hosts. You have a shell on the pivot. How do you reach it from your attack box, and why does that
   work when a normal network connection is refused?
4. Why does `proxy_dns` in `proxychains.conf` matter when your targets are named (e.g.
   `db.corp.lab`) rather than raw IPs? What leaks or breaks without it?
5. Your foothold is on the DMZ and a stateful firewall blocks *all* inbound connections to the DMZ,
   including SSH, but the DMZ host can reach the Internet. You cannot SSH *to* it. Which SSH forward
   direction is now your only option, and what does it require of the foothold? (This sets up 12.2.)

</div>

Model answers are in `solutions/module-12.md` (instructor material — try them first).

## References

- **OpenSSH** — `ssh(1)` (the `-L`, `-R`, `-D`, `-N`, `-g` options) and `ssh_config(5)`
  (`LocalForward`, `RemoteForward`, `DynamicForward`, `GatewayPorts`). openssh.com/manual.html.
- **RFC 4254** — The Secure Shell (SSH) Connection Protocol (§7, TCP/IP port forwarding channels).
- **RFC 1928** — SOCKS Protocol Version 5; **RFC 1929** — Username/Password auth for SOCKS5.
- **proxychains-ng** — github.com/rofl0r/proxychains-ng (README: `strict_chain`, `proxy_dns`,
  the `LD_PRELOAD` connect-hook mechanism and its TCP-only limitation).
- **sshuttle** — sshuttle.readthedocs.io (transparent-proxy-over-SSH model and its scope).
- **RFC 1918** — Private address allocation (why internal ranges don't route); **NIST SP 800-125B** —
  Secure Virtual Network Configuration (segmentation guidance).
- **MITRE ATT&CK** — **T1090** Proxy (.001 Internal, .002 External), **T1572** Protocol Tunneling,
  **T1046** Network Service Discovery.
- **CWE-923** — Improper Restriction of Communication Channel to Intended Endpoints (the
  segmentation weakness pivoting demonstrates).

## What you should now be able to do

- Read a foothold's network position and recognise, from a reachability asymmetry, that a pivot is
  needed and in scope.
- Choose local, remote, or dynamic SSH forwarding by asking *who initiates* and *one destination or
  many*, and explain why the others are wrong.
- Stand up a SOCKS proxy and drive arbitrary tools through it with proxychains, respecting its
  TCP-only limits (why `-sT -Pn` is mandatory for proxied scans).
- State the segmentation remediation and the T1090/T1572 detection signature for tunnelling.

## Progress checkpoint

```bash
py course.py complete 12.1
```
