# Competency map — what you can do when you finish

_Last reviewed: 2026-09._

The curriculum exists to produce **capabilities**, not lesson completions. This is the outcome
checklist. Each competency names the modules that build it and the assessment that proves it. Tick
a competency only when you could do it on an environment you have **not** seen before.

Levels: **Recognize** (name it, explain why it matters) · **Perform** (do it with reference) ·
**Reason** (do it unaided on a novel target, justify choices, explain impact).

## Methodology &amp; professionalism

- [ ] **Scope & operate legally.** Read a scope/RoE, stay inside it, and refuse or escalate
  out-of-scope opportunities. — M00, M16 · *Reason* · A7
- [ ] **Run a repeatable process.** Recon → enumerate → discover → validate → exploit →
  post-exploit → report, with disciplined notes and evidence. — M00–M03, M16 · *Reason* · A1, A7
- [ ] **Prioritize.** Given a large attack surface, justify what deserves depth and what doesn't.
  — M02, M03 · *Reason* · A1
- [ ] **Report.** Write an executive summary and technical findings with reproduction, evidence,
  severity rationale, impact, and remediation. — M16 · *Reason* · A4, A7, capstone

## Reconnaissance &amp; enumeration

- [ ] Map an external attack surface from a domain/scope, using passive then active methods with
  OPSEC awareness. — M02 · *Reason* · A1
- [ ] Explain what a port scan does on the wire and interpret ambiguous results (filtered vs
  closed, UDP reality). — M03 · *Reason* · A1
- [ ] Fingerprint services and turn enumeration into a prioritized hypothesis list. — M03 · *Reason*

## Host security (Linux &amp; Windows)

- [ ] Enumerate a Linux host and find a local privilege-escalation path (SUID, sudo, cron,
  capabilities, PATH, kernel), verifying before exploiting. — M04 · *Reason* · A2
- [ ] Enumerate a Windows host and find a privesc path (service/registry/task/DLL, tokens). — M05
  · *Reason* · A3
- [ ] Read permissions/ACLs and explain *why* a misconfiguration is exploitable. — M04, M05 · *Reason*

## Active Directory

- [ ] Model an AD environment as a graph of identities, permissions, credentials, and trust. — M06
  · *Reason* · A5
- [ ] Enumerate AD (users, groups, SPNs, ACLs, delegation, GPOs) and find an attack path from a
  low-priv account to high privilege **without** being told the path. — M06, M10, M11 · *Reason* · A5
- [ ] Explain Kerberoasting, AS-REP roasting, delegation and ACL abuse mechanically, and how a
  defender would detect each. — M06 · *Reason*

## Web &amp; API

- [ ] Recognize each major web vulnerability class **from application behavior**, not a signature,
  and validate it safely. — M07 · *Reason* · A4
- [ ] Chain multiple independent web weaknesses into a demonstrable impact. — M07, M08 · *Reason* · A4
- [ ] Test REST and GraphQL APIs for BOLA/BFLA, mass assignment, and data exposure. — M08 · *Reason* · A4

## Exploitation &amp; post-exploitation

- [ ] Explain memory-corruption fundamentals and modern mitigations, and reason about what each
  mitigation stops and how it's bypassed conceptually. — M09 · *Perform/Reason*
- [ ] Perform credential attacks appropriately (spray vs brute vs crack), choosing the least
  destructive effective method. — M10 · *Reason* · A5
- [ ] Move laterally with reused/derived credentials (PtH/PtT) and explain the protocol underneath.
  — M11 · *Reason* · A5
- [ ] Discover and use a pivot through a segmented network (port forwarding, SOCKS, reverse tunnel).
  — M12 · *Reason* · A6

## Modern surfaces

- [ ] Identify container/orchestration misconfigurations (exposed socket, over-privilege, escapes)
  and explain the isolation boundary crossed. — M13 · *Reason*
- [ ] Identify cloud IAM/metadata/storage misconfigurations and trace a privilege-escalation path.
  — M14 · *Reason*
- [ ] Frame a chain of activity in ATT&CK terms and reason about how it would be detected. — M15 ·
  *Reason*

## Meta-skill (the point of the course)

- [ ] Faced with a system you have never seen, you can answer: *What am I looking at? Why is it
  interesting? What hypothesis do I test? What evidence supports it? What attack path does it
  create? What is the impact? What else could explain this? How would it read in a report? How do
  I reproduce it reliably?* — all modules · *Reason* · capstone
