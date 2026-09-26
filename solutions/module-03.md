# Instructor / solutions — Module 03

> **Instructor material.** Not linked from `_sidebar.md`. Do the exercises before reading.

## 03.1 — Host discovery &amp; port scanning

**Exercise (firewall behind `10.10.10.30`).** The two scans together let you separate host state
from firewall behaviour. The key insight: `-sS` tells you what the *service* does *if the probe
reaches it*, while `-sA` tells you whether a packet *reaches the host's TCP stack at all*.
Cross-referencing them:

| Port | Scan A (`-sS`) | Scan B (`-sA`) | Host-level state | Firewall behaviour | Proof |
|---|---|---|---|---|---|
| 22 | open (syn-ack) | unfiltered (reset) | **open** | passes | SYN reached, service answered SYN/ACK |
| 80 | open (syn-ack) | unfiltered (reset) | **open** | passes | same as 22 |
| 443 | closed (reset) | unfiltered (reset) | **closed** (nothing listening) | passes | RST in *both* scans = packets reach a live stack that has no listener |
| 139 | filtered (no-resp) | filtered (no-resp) | **unknown** | **drops** (both SYN and ACK) | silence to both probe types = firewall eats everything to this port |
| 445 | filtered (no-resp) | filtered (no-resp) | **unknown** | **drops** | same as 139 |
| 3389 | filtered (no-resp) | unfiltered (reset) | **likely open, new-conn filtered** | **SYN-specific drop** | ACK got a RST (reached the host) but SYN got silence → firewall blocks connection *setup* only |

**Firewall policy in plain English:** default-deny with an allow-list. It *passes* traffic to 22,
80, 443 (and lets ACKs to 3389 through), and *silently drops* (not rejects — no RST/ICMP) new
connections to 139, 445, and 3389. Drop vs reject is provable from the ACK scan: a **reject** ruleset
would send RST/ICMP and show `unfiltered`; the `filtered` verdict on 139/445 in *both* scans means
the packets are dropped. 3389 is the interesting one: the host answered the stray ACK with a RST (so
the host is reachable and the port's stack is live), but the SYN was dropped — classic
"port is open behind the firewall, but the firewall blocks inbound connection initiation."

**Confirming 3389:** the honest answer is you *can't* fully confirm "open at the host" from outside a
SYN-dropping firewall with a network scan — that's the teaching point. Accept either of these,
justified: (a) `nmap -sA -p3389 --reason` repeated / `hping3 -A` to re-confirm the ACK gets a RST
(proves reachable + SYN-filtered), noting you cannot see the service state; or (b) if a pivot/inside
position becomes available later, `nc -vz 10.10.10.30 3389` from inside the boundary. Grading:
full marks require recognizing the ACK-through/SYN-dropped asymmetry and *not* claiming certainty
about the service behind a SYN-filter. Same TTL (63) across replies is corroborating evidence that
one host (not the firewall itself) is generating the RSTs.

**Common wrong turns:** (1) calling 139/445/3389 all "the same" — 3389 is distinguishable via the
ACK scan; (2) reading `filtered` as "closed/nothing there"; (3) claiming 3389 is definitely open;
(4) missing that 443's RST in *both* scans proves the host is up and the port simply has no listener.

**Check-yourself:** (1) Causes: a firewall dropping the probe, **or** the reply being lost / the host
down / rate-limited. Distinguish with a direct hand check whose timing tells you which: `nc -vz` /
`timeout 3 bash -c 'echo >/dev/tcp/host/port'` — instant fail = closed (RST), hang to timeout =
filtered, immediate success = open (re-scan, the scan was wrong). (2) `-sS` crafts raw packets and
replies with RST itself, never completing the handshake → needs `CAP_NET_RAW`/root; `-sT` uses the
OS `connect()` (no raw sockets, no privilege). Because connect *completes* the handshake, the target
**application** sees and logs a full connection — `-sT` is noisier to app-layer logging, `-sS` to
packet-layer/IDS. (3) Send a *protocol-correct* payload (e.g. an actual SNMP GET / `snmpget`, a DNS
query) — an app-layer reply proves `open`; an ICMP port-unreachable proves `closed`. The plain scan
sends an empty/generic datagram that open UDP services ignore, so silence stays ambiguous. (4) Rule
out: wrong route/no route through the pivot, the pivot tool dropping/mangling packets, timing too
aggressive for the added latency (raise timeouts, lower `-T`), MTU/fragmentation, and simply
scanning the wrong interface/range. Re-verify one known-open port by hand through the pivot first.

## 03.2 — Service &amp; version fingerprinting and enumeration

**Exercise (enumerate `10.10.10.40`).** A strong submission has a *sane order* and two findings
written to the rubric.

**Enumeration plan (good order &amp; rationale):**
1. **SMB (445/139) first** — cheapest path to *identity*: OS, domain, and (if null session allowed)
   users and shares. `nmap --script smb-os-discovery,smb-protocols,smb2-security-mode`, then
   `smbclient -N -L //TARGET/` and `enum4linux-ng TARGET`. Knowing the OS/domain sharpens every later
   step. Extract: OS/version, domain, signing status, share list, users.
2. **SNMP (161/udp)** — `onesixtyone -c communities.txt TARGET` to find a working string, then
   `snmpwalk -v2c -c public TARGET` over system/interfaces/process MIBs. Extract: OS confirmation,
   interfaces/routes, running processes, sometimes creds. Corroborates the SMB OS finding.
3. **HTTP (80)** — `curl -sI`, `-X OPTIONS`, `/robots.txt`, `nmap --script http-headers,http-methods,
   http-enum`. Extract: server/framework/version, methods, security headers, obvious paths/errors.
4. **SSH (22)** — `nc TARGET 22` banner, `nmap --script ssh2-enum-algos,ssh-auth-methods`. Extract:
   implementation/OS hint, auth methods (note if password auth is on — an M10 lead).
5. Cross-check versions by hand against Nmap's `-sV` output; flag discrepancies.

Rationale for the order: identity/OS-bearing services (SMB, SNMP) first because they make everything
downstream more precise; the two are mutually corroborating for OS. HTTP is high-surface but self-
contained. SSH is nearly free and yields an M10 lead.

**Two model findings (rubric: what / where / evidence / class / impact):**

- *Finding A — SMB null session discloses shares and users.* **What:** the SMB service permits an
  unauthenticated (null) session that enumerates share names and domain users. **Where:**
  `10.10.10.40:445`. **Evidence:** `smbclient -N -L //10.10.10.40/` returns the share table incl. an
  anonymously listed `backup` share; `enum4linux-ng 10.10.10.40` returns a user list. **Class:**
  CWE-200 information exposure / anonymous access. **Impact:** hands an attacker a valid *user list*
  with no credentials — the raw material for password spraying (M10) and a map of anonymously
  reachable data; materially lowers the cost of the next attack.
- *Finding B — default SNMP community string exposes internal topology.* **What:** the SNMP agent
  answers the default `public` community. **Where:** `10.10.10.40:161/udp`. **Evidence:**
  `snmpwalk -v2c -c public 10.10.10.40 1.3.6.1.2.1` returns `sysDescr`, interface table, and process
  list. **Class:** CWE-1188/CWE-798 default credential / info exposure. **Impact:** an unauthenticated
  attacker reads OS version, network interfaces/routes, and running software — a free internal-recon
  windfall that guides targeting and can leak credentials in process args.

**Result not to trust from a scanner alone (deliverable 3):** any `-sV` version string that implies a
CVE — e.g. an Apache/OpenSSH version — because banners are back-patched or spoofed; confirm the exact
version and behaviour by hand (`curl -I`, `nc`) before treating it as vulnerable.

**Common wrong turns:** enumerating HTTP exhaustively while ignoring the free SMB/SNMP identity wins;
brute-forcing (out of scope for the exercise); reporting the `-sV` banner as a confirmed vuln;
findings with no command/evidence attached; "it's bad" instead of business impact.

**Check-yourself:** (1) The `vsftpd 2.3.4` string may be (a) an admin-set/faked banner, (b) a distro
back-port keeping the old version string on a patched binary, or (c) a proxy's banner not the real
backend. Before reporting: confirm the version and, in the lab, that the specific weakness is
actually present — reproduce it, don't infer from the string. (2) Share *names* alone reveal internal
structure (e.g. `backup`, `finance`, hostnames/comments) and prove that anonymous access is enabled —
an information-disclosure + access-control finding regardless of read access, and often the lead to a
readable share elsewhere. (3) UDP 161 is `open|filtered` because an empty/generic probe to an open
UDP port gets no reply (03.1); a *protocol-correct* SNMP GET (the walk) elicits an application reply,
which proves `open`. The scan's ambiguity and the successful walk are consistent, not contradictory.
(4) Trust the **SSH banner over `-O`**: `-O` infers from stack quirks and is easily fooled. Innocent
explanations: the host is Linux but sits behind a NAT/load-balancer/appliance whose *stack* Nmap
fingerprinted, or `-O` had too little to work with (few open/closed ports) and guessed. Corroborate
with TTL and service banners.

## 03.3 — Vulnerability discovery &amp; prioritization

**Exercise (rank the plan for `10.10.10.50`).** A defensible ranking (accept variants that are
justified by impact × likelihood and show chaining reasoning):

| Rank | Service / hypothesis | CWE / CVE | Impact (assets) | Likelihood (reasoning) | Cheapest confirming test |
|---|---|---|---|---|---|
| 1 | MySQL `root` / no password, remote | CWE-1188/CWE-798 | **Crown jewel** — direct read of customer DB | **Very high** — `AV:N/PR:N`, already observed to succeed | `mysql -h TARGET -u root -e 'show databases;'` (lab) |
| 2 | SMB `backups` anon-readable share | CWE-200 / CWE-284 | High — may contain creds/config reaching `/admin` | High — null session already confirmed | `smbclient -N //TARGET/backups -c 'ls'` |
| 3 | Apache 2.4.49 path-traversal/RCE | CWE-22 / CVE-2021-41773 (+ -42013) | High — server compromise, path to `/admin` | Med — *confirm 2.4.49 in range &amp; not back-patched*; check KEV (listed) / EPSS (elevated) | `curl` the traversal PoC against a lab-only path |
| 4 | SNMP `public` walk | CWE-1188 | Med — internal recon / chaining fuel | High — confirmed | `snmpwalk` system/process MIB (done) |
| 5 | SSH password auth exposed | CWE-307 (no lockout?) | Med — foothold if creds found | Med — needs creds from #2/#4 first | note for M10; no brute now |

**Defending #1:** the no-auth remote `root` MySQL is *both* maximal impact (it **is** the crown
jewel) and near-certain likelihood (already observed reachable and authenticating). It beats even a
CVSS-9.8 Apache RCE, because the Apache finding's likelihood is *conditional* — the version must be
confirmed in the vulnerable range and not back-patched, and it only *leads toward* the database
whereas MySQL *is* the database. Expected value of the tester's time is highest here.

**Deprioritized/excluded (deliverable 3):** SSH password-auth brute force — deprioritized because
(a) blind brute force risks lockout and is often out of RoE, (b) its likelihood depends on
credentials you'd get more cheaply from the `backups` share or SNMP first, and (c) low marginal
impact once #1 already reaches the crown jewel. Recorded as an M10 lead, not a day-one action. Also
acceptable: excluding a low-EPSS, non-KEV, unreachable CVE surfaced by a scanner.

**Chaining note graders should reward:** recognizing that #2 (backups) or #4 (SNMP) might yield the
credential that unlocks `/admin` — i.e. a "medium" info-disclosure enabling the client's stated
concern — is the mark of prioritization maturity, even though each scores modestly alone.

**Common wrong turns:** ranking by raw CVSS (putting the unconfirmed Apache CVE #1 over the observed
no-auth DB); an exhaustive un-ranked CVE dump; treating the Apache banner as confirmed-vulnerable
without the version-range/back-patch check; ignoring the crown-jewel framing the client gave;
proposing exploitation (out of scope for a *plan*).

**Check-yourself:** (1) Test the 6.5 first when it's Internet-facing/no-auth (reachable now) while
the 9.8 sits on an unreachable internal host — CVSS base excludes *your* environment. Settle it with
reachability from the vector (`AV`, `PR`, `UI`), EPSS/KEV (is either actively exploited?), and asset
value behind each. (2) The KEV-listed, EPSS-0.85 CVE jumps to the top: identical CVSS measures
*severity if exploited*, not *probability of exploitation* — KEV = confirmed in-the-wild use, EPSS
0.85 = high near-term likelihood, versus 0.01 = effectively dormant. Prioritize the live one. (3)
Scanners mostly do version-based matching, so "critical" = "a CVE exists for this banner," not "this
host is exploitable here." False positive: flags a CVE for a version whose distro back-ported the fix
(patched binary, old string). False negative: misses an IDOR/business-logic flaw it has no signature
for — often the highest-impact finding. (4) Version matched but exploit failed: (a) the component is
back-patched despite the banner, or (b) a non-default config / compensating control / missing
pre-condition blocks it. Report: "banner indicates vulnerable version X, but exploitation could not
be reproduced in testing" — record it as unconfirmed / informational, not as a confirmed critical.
