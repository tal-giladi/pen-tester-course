# Glossary

Working definitions as used in this course. Grows as modules are added; terms are defined the
first time they appear in a lesson and collected here for quick lookup. Ordered alphabetically.

- **Attack surface** — the set of points where an attacker can interact with a system (open
  ports/services, web endpoints, input fields, identities, trust relationships). Mapping it is the
  first job of an engagement.
- **Authentication (authn)** — proving *who* you are. Distinct from authorization.
- **Authorization (authz)** — deciding *what* an authenticated identity may do. Most access-control
  bugs are authz failures, not authn.
- **BOLA / IDOR** — Broken Object-Level Authorization / Insecure Direct Object Reference: accessing
  another user's object by changing an identifier the server fails to authorize.
- **C2 (Command and Control)** — the channel an operator uses to control a compromised host.
  Taught as a *concept* and for detection in M15; not weaponized here.
- **CVE / CWE** — a specific disclosed vulnerability / a class of weakness. See standards map.
- **Enumeration** — methodically extracting detail from a discovered service (users, shares,
  versions, config) to turn "there is a thing here" into "here is exactly what it is."
- **Exploit** — code or a technique that turns a vulnerability into a concrete effect (a shell,
  data access, privilege gain).
- **Foothold** — the first meaningful access into an environment; the starting point for
  post-exploitation.
- **Hash (password)** — a one-way transform of a secret. Attackers crack hashes *offline* or use
  them directly (pass-the-hash) rather than recovering the password.
- **Kerberoasting** — requesting service tickets (for accounts with SPNs) and cracking them
  offline to recover service-account passwords. ATT&CK T1558.003.
- **Lateral movement** — using access on one host to reach another, typically via reused or
  derived credentials and remote-admin protocols.
- **Least privilege** — granting only the access needed. Its violation is the root of most
  privilege-escalation and lateral-movement paths.
- **Payload** — the part of an attack that produces the effect. In this course, payloads carry a
  **benign marker**, never a weaponized effect.
- **Pivot** — a compromised host used as a stepping stone to reach networks you can't reach
  directly.
- **Post-exploitation** — everything after initial access: enumerate, escalate, collect evidence,
  assess impact, move.
- **Privilege escalation** — gaining higher rights than you started with, locally (on a host) or
  in a domain/cloud.
- **Proof of Concept (PoC)** — the minimal demonstration that a vulnerability is real, using an
  inert marker rather than damage.
- **Rules of Engagement (RoE)** — the agreed constraints of an engagement: scope, timing, allowed
  techniques, contacts, and stop conditions. See M00.
- **Scope** — exactly which systems/assets are authorized for testing. Acting outside scope is
  both an ethics failure and often a crime.
- **Severity vs. risk** — severity is how bad the technical flaw is (CVSS); risk factors in
  likelihood and business context. A report communicates both.
- **SSRF** — Server-Side Request Forgery: making a server issue requests you control, often to
  reach internal services or cloud metadata.
- **Vulnerability** — a weakness that can be exploited to violate a security property
  (confidentiality, integrity, availability).

<div class="callout key">

Terms are added here as lessons introduce them. If you meet a term in a lesson that isn't here
yet, it's defined inline where first used.

</div>
