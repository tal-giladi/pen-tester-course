# Instructor / solutions — Module 00

> **Instructor material.** Not linked from `_sidebar.md`. Do the exercises before reading.

## 00.1 — Ethics & authorization

**Exercise (Northwind).** A strong submission:
- **Scope (in):** `shop.northwind.lab` and subdomains *the client owns and can authorize*; the
  client's own AWS resources (EC2/S3/etc.) **only after** confirming account IDs and reading AWS's
  testing policy. **Scope (out):** the third-party payment processor (client cannot authorize it),
  AWS's own control-plane/shared infrastructure, any subdomain resolving to third-party SaaS.
- **"Anything related to it"** must be pinned to a concrete asset list — this vague phrase is the
  main scope trap; turn it into a question: "please enumerate the domains/hosts/accounts you own
  and authorize."
- **Biggest risk:** testing an asset the client cannot legally authorize (payment processor / AWS
  infra). Mitigated by explicit written exclusion + a recorded clarifying question + reading the
  provider policy. Secondary risk: "production, don't break anything" → RoE clause forbidding DoS
  and destructive exploitation, off-hours window, and a stop-condition/escalation contact.

**Check-yourself:** (1) No — authorization is per-owner; the co-located company never authorized
you. You should have confirmed asset *ownership* before scanning a shared range; now: stop, don't
touch it again, document, notify the client that the range contains third-party assets. (2) Capture
one screenshot/response showing *your* account can read *one* other invoice (enough to prove BOLA);
do **not** enumerate or download all invoices or the customers' PII. (3) It's the legal artifact
that proves authorization if a defender/law enforcement notices you — it changes your *legal*
standing, not the technical possibility. (4) No scope, no RoE, no authority to authorize (it's not
their account), and a hostile purpose — it's a request to commit a crime, refuse.

## 00.2 — Methodology / ATT&CK

**Exercise mapping (one good answer):**
| Story step | PTES phase | ATT&CK |
|---|---|---|
| Found web app on Internet | Intelligence gathering | Recon (T1595 Active Scanning) |
| Exploited unpatched flaw → commands | Exploitation | Initial Access **T1190**; Execution |
| DB creds in config file | Post-exploitation | Credential Access **T1552.001** Unsecured Creds in Files |
| Dumped user table | Post-exploitation | Collection **T1005**; Credential Access |
| Cracked reused password | Post-exploitation | Credential Access **T1110.002** (offline) |
| Logged into internal admin over VPN | Post-exploitation | Lateral Movement / **T1078** Valid Accounts |
| Copied records to external server | Post-exploitation | Exfiltration **T1567**/**T1041** |

**Most disruptive single fix:** patching the public app (removes **T1190** initial access — no
foothold, no chain). Reasonable alternatives argued well: not storing DB creds in the config
(breaks the pivot), or not reusing the password (breaks lateral movement). Accept any with sound
justification; the *point* is kill-chain reasoning. **Detection for T1190:** WAF/app logs showing
anomalous requests + new child processes spawned by the web server (process-creation telemetry).

**Check-yourself:** (1) Re-entering Intelligence gathering, now from *inside* — internal hosts,
internal DNS, reachable services you couldn't see externally. (2) e.g. login with stolen valid
credentials — no weaponization/delivery/installation; the kill chain's malware-shaped stages don't
fit. (3) "They're the industry's standard IDs for attacker actions, so our findings map directly to
your detection and other teams' tooling." (4) You can't reproduce or assess impact from "scanned a
host" alone; conclusions are what feed the report and the next decision.

## 00.3 — Threat modeling

**Prioritized top-5 (illustrative):** (1) IDOR/BOLA on invoice download — Info disclosure, crosses
authenticated-user boundary, high impact (customer PII) × high likelihood; cheap test: change the
ID with your test account. (2) SSRF via the internal-service-by-URL call → AWS metadata — EoP/info
disclosure, app↔internal boundary, high impact; cheap test: point it at an internal/metadata URL.
(3) SQLi in search/order lookup — tampering/info disclosure. (4) Malicious file upload on the image
uploader — EoP/RCE. (5) Auth/access-control on `/admin`. **Confused deputy:** the app fetching an
internal service by URL on the user's behalf (SSRF). DoS threat (check-yourself Q4): record it as a
*finding/recommendation* (rate-limit the login) but do **not** test it — out of RoE.

**Check-yourself:** (1) Boundaries are where a component *decides* to trust input; the decision is
where the mistake lives. (2) IDOR first — real data impact vs. a marketing-page XSS with little
asset behind it; rank by impact×likelihood, not scanner label. (3) "Your app has network access the
user doesn't; if the user controls the URL it fetches, they borrow your app's access to reach
things they can't — that's a confused deputy." (4) Neither ignore nor test: record it as a
recommendation with rationale; testing DoS violates the RoE.

## 00.4 — Lab & isolation

**Exercise.** Per-service verdict with evidence: `target` blocked (wget timeout from inside),
`leaky` reachable (wget returns). **Fix for `leaky`:** attach it to `ptlab_internal` (or make its
network `internal: true`) instead of `ptlab_egress`; re-run `wget` from inside to prove it now times
out. **Three-line acceptance check:** (a) every target service joins only `internal: true`
networks; (b) no target has Internet egress (proven from inside, not read); (c) only management
ports (if any) are published, and publishing ≠ egress.

**Check-yourself:** (1) Docker doesn't create an external gateway/NAT for the network, so there's no
default route off the host. (2) It still cannot reach the Internet (egress unchanged); *you* can
reach it (ingress via the published port). Ingress ≠ egress. (3) To teach you to recognize the
misconfiguration and to make the check meaningful (a check that can only pass proves nothing). (4)
"A safety control we don't test isn't a control — one stray attachment or `network: host` silently
reopens egress; verify from inside." (5) Host-only/internal virtual switch with no NAT/bridged
adapter, and verify from inside the VM the same way.
