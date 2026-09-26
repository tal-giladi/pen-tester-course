# Assessment 6 — Pivoting & segmented networks

<div class="prereq">

**Modules tested:** [M12 Pivoting & complex networks](../lessons/module-12/lesson-01.md),
[M11 Lateral movement](../lessons/module-11/lesson-01.md),
with recon/enumeration ([M03](../lessons/module-03/lesson-01.md)) applied *through* a pivot.
**Lab:** [`lab-12-pivot`](../labs/lab-12-pivot/README.md).
**Difficulty:** 🔴 advanced. **Time:** 2–3 h. **Scaffolding:** *advanced* — you are given the
foothold and the objective; you supply the route and the tooling.
**You will produce:** a segmentation map you built by discovery, the working pivot chain, evidence
from a segment your attacker box cannot reach directly, and a segmentation finding with remediation.

</div>

<div class="callout legal">

**LAB TARGET vs REAL SYSTEM.** Everything below targets **only** the `lab-12-pivot` containers, on
private **internal (no-egress)** Docker networks. The foothold credentials (`lab` / `Lab-Passw0rd!`
and the clearly-labelled throwaway SSH key) and the flag are **synthetic** — never reuse that key
anywhere. Building tunnels into other people's networks is unauthorized access on a **REAL SYSTEM**:
you pivot only into segments explicitly in scope, and on a real engagement you stop at the scope
boundary and *report the reachability* rather than crossing it (00.1, 12.x). Run `./labs/lab check`
before you start; if isolation fails, stop.

</div>

## Situation

You have a foothold on a client's **DMZ** host — the box that faces the world and that a real
attacker lands on first. The client believes their sensitive systems are "properly segmented" and
therefore safe: the crown-jewel service sits on a **restricted** network that, they insist, "nothing
external can reach." Your attacker workstation confirms their claim at face value — you *cannot*
route to the restricted host directly. Your job is to show whether "the DMZ is exposed but
segmentation protects the rest" actually holds once one DMZ host is owned.

## Objective

From the DMZ foothold, **discover the network topology and pivot to the restricted segment**, then
read the flag on the restricted host — an asset that is **not reachable** from your attacker box.
Demonstrate the full route working end to end, and characterise exactly where segmentation did and
did not stop you.

## Starting information

- A foothold on the DMZ host: `ssh lab@dmz` from the `ws` attacker workstation
  (`docker exec -it ptlab12_ws bash`). The throwaway key is at `~/.ssh/id_ed25519`;
  `ssh`, `proxychains4`, `nmap`, and `curl` are installed on `ws`.
- One fact you can prove yourself: `curl --max-time 4 http://restricted/flag` from `ws` **fails** —
  there is no direct route.
- Nothing about the intermediate hops. How many segments exist, which hosts are dual-homed, and
  which route reaches `restricted` are all for you to discover.

## Constraints

- **In scope:** the `lab-12-pivot` hosts and their segments only (`ws`, `dmz`, `internal`,
  `restricted` and the networks between them).
- **Out of scope / forbidden:** any host or network not part of this lab; the Internet; denial of
  service; leaving persistent tunnels or changes behind (tear down your forwards when done).
- **Safety boundary:** LAB TARGETS ONLY, all networks isolated. Verify with `./labs/lab check`
  before offensive action. The key is a labelled throwaway — it exists only for this lab.
- **Discovery before tooling:** enumerate each host's interfaces and reachable neighbours and build
  the map from evidence; don't assume the topology.

## Expected deliverables

1. **Segmentation map** — a diagram of the segments, which hosts are dual-homed, and which network
   each interface sits on, built from your own enumeration (interfaces, routes, reachable services
   per hop) rather than from the lab README. State how you discovered each edge.
2. **The pivot chain** — the exact, reproducible commands that establish the route from `ws` to
   `restricted` (whichever technique you choose: ProxyJump chain, dynamic SOCKS + `proxychains`,
   local/remote forwards, or a reverse tunnel). Another tester must be able to paste your steps and
   reach the flag.
3. **Evidence** — proof the flag was read *through the pivot* from a host your attacker box cannot
   reach directly, named per convention (`evidence/<YYYYMMDD-HHMMSS>_<host>_<n>.png`) and showing
   the `LAB-FLAG-…` marker, plus the "before" proof that the direct `curl` fails.
4. **A segmentation finding** (to the [finding template](../solutions/report-template/finding-template.md)):
   what the segmentation weakness is, where (which segment boundary failed and why a compromised DMZ
   host bridges it), reproduction, impact (a DMZ compromise reaches the crown jewels), CVSS
   rationale, and remediation.
5. **Root cause & remediation** — *why* a foothold on one DMZ host was enough to defeat the
   client's "segmentation," and the network-level fix that would actually isolate the restricted
   segment (not just "add a firewall rule" — say which rule, between which segments, and how you'd
   verify it).

<details><summary>Hint 1 — conceptual direction</summary>
"Segmented" and "isolated" are not the same claim. A segment is only isolated from you if <em>no
host you control</em> touches it. Ask the question a router asks: from where I stand right now, what
is the next network I can see — and is there a host that lives on both it and the one beyond?
</details>

<details><summary>Hint 2 — technique family</summary>
You will not exploit your way across; you will <em>route</em> across. The foothold host is your new
vantage point — enumerate the network as if you were sitting on it, because you are. The general
primitive is turning a host you control into a relay for your traffic; SSH gives you several forms
of that for free.
</details>

<details><summary>Hint 3 — relevant tools / what to look at</summary>
On each hop, look at <code>ip -4 addr</code> and <code>ip route</code> — a second interface is a
second network you can now reach. To carry tools (not just <code>ssh</code>) across, a dynamic SOCKS
proxy (<code>ssh -D</code>) plus <code>proxychains4</code> generalises; an <code>ssh -J</code> jump
chain is the quickest way to prove the route. The restricted segment is one hop further than the
first network you find.
</details>

<details><summary>Hint 4 — specific investigation direction</summary>
Expect <em>two</em> pivots, not one: the DMZ host bridges you to an internal network and an internal
host, and that internal host is itself dual-homed onto the restricted segment where the flag lives.
Build the chain incrementally — reach and enumerate the internal host first, confirm it can see
<code>restricted</code>, then extend your tunnel one more hop and point your tool at the flag.
Tear the tunnels down afterwards.
</details>

## Check yourself

<div class="callout key">

1. `curl http://restricted/flag` fails from `ws` but succeeds from `internal`. In one sentence each:
   what does that prove about the network, and what does it prove about the client's segmentation
   claim?
2. You have a working `ssh -J` chain and also a `-D` SOCKS + `proxychains` setup. When would you
   prefer each, and which one lets you run `nmap` against the restricted segment?
3. A dual-homed host is the thing that makes the pivot possible. From a defender's standpoint, is the
   dual-homed host the vulnerability, or is it the missing control between the segments? Defend your
   answer — it determines the remediation.
4. Your finding's impact says "an attacker can pivot." Why is that not yet a business impact, and
   what would you write instead for this client?
5. You leave a `ssh -D 1080` running after the test. Why is that both an OPSEC and a professional
   problem, and what's the correct closeout?

</div>

## Grading rubric

<div class="callout method">

| Band | Criteria |
|---|---|
| **Pass — flag via pivot** | Read the restricted flag *through* the pivot chain, with "before" proof the direct route fails; the chain is reproducible from your steps alone. |
| **Discovery** | The topology map was built from your own enumeration (interfaces/routes/reachability per hop), correctly identifying the dual-homed hosts and the two-pivot route. |
| **Finding quality** | The segmentation weakness is a complete, rubric-complete finding with business impact and a specific network-level remediation, not "add a firewall." |
| **Professionalism** | Isolation verified; tunnels torn down at closeout; evidence named deterministically and shows the marker. |
| **Distinction** | Demonstrated *both* a jump-chain and a SOCKS/proxychains route (showing tool traffic, e.g. a scan, crossing the pivot), and reasoned about detection of the tunnel; remediation includes a verification step. |
| **Fail** | Flag not reached through the pivot; or topology assumed rather than discovered; or no marker evidence; or persistent tunnels/out-of-scope hosts touched; or isolation not verified. |

</div>

_Grading key, the intended route(s), and common wrong turns are instructor material in
[`solutions/assessments/A6.md`](../solutions/assessments/A6.md) — not linked from the sidebar. Try
the assessment before looking._
