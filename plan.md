You are an expert cybersecurity educator, penetration tester, curriculum designer, and software engineer.

Build a complete, professional, self-paced **Penetration Testing / Ethical Hacking course** for an experienced software engineer who wants to develop real-world penetration-testing skills from the fundamentals through advanced professional practice.

The result must be a real course that can be studied sequentially, not a collection of disconnected articles, cheat sheets, or CTF walkthroughs.

## 1. Primary goal

Create a curriculum comparable in breadth and depth to the knowledge covered by leading professional penetration-testing certifications, while going beyond certification memorization and teaching the underlying reasoning and practical skills.

Use modern material and continuously verify that techniques, tools, commands, vulnerabilities, and recommendations are current.

The course should develop the ability to:

* understand how attacks actually work
* identify attack surfaces
* perform reconnaissance
* enumerate systems and services
* discover vulnerabilities
* validate vulnerabilities safely
* exploit vulnerabilities in controlled environments
* escalate privileges
* move through networks
* attack Active Directory environments
* perform web application penetration testing
* test APIs
* assess authentication and authorization
* perform cloud/security testing where appropriate
* understand common modern attack chains
* document evidence
* assess impact
* write professional penetration-test reports
* communicate findings to technical and non-technical stakeholders
* reason like a professional penetration tester rather than simply run tools

The course must emphasize **methodology, reasoning, and manual understanding**, not tool memorization.

---

# 2. Certification alignment

Research the current versions and objectives of major professional penetration-testing certifications before designing the curriculum.

At minimum investigate:

* OffSec OSCP / PEN-200
* OffSec OSEP where relevant
* CompTIA PenTest+
* eJPT
* PNPT
* CRTO where relevant to adversary simulation/red-team skills
* CREST penetration-testing knowledge where publicly available
* other major certifications if they materially improve the curriculum

Do NOT simply copy certification syllabi.

Instead:

1. identify overlapping foundational knowledge
2. identify important areas each certification emphasizes
3. identify gaps between certifications
4. identify skills that professional pentesters need but certifications may under-emphasize
5. synthesize these into one coherent curriculum

Clearly distinguish:

* certification-oriented knowledge
* professional real-world skills
* optional advanced material

The course should not claim that completing it guarantees certification readiness unless that can actually be justified.

---

# 3. Research requirements

Before writing the curriculum, perform substantial research using authoritative and current sources.

Prefer:

* official certification objectives
* official vendor documentation
* OWASP
* NIST
* MITRE ATT&CK
* Microsoft security documentation
* Linux documentation
* RFCs
* major security-project documentation
* reputable security research
* original vulnerability disclosures
* high-quality conference material
* established security training resources

Use modern sources rather than relying on old blog posts.

For every major subject, determine whether the material is still relevant as of the current year.

Pay particular attention to changes in:

* Windows
* Active Directory
* Linux
* cloud environments
* web application security
* APIs
* authentication
* identity systems
* containers
* Kubernetes
* modern endpoint defenses
* modern exploitation
* privilege escalation
* network segmentation
* detection/EDR considerations
* modern attacker workflows

Do not blindly preserve outdated pentesting techniques simply because they are historically popular.

---

# 4. Course architecture

Create a progression from beginner fundamentals to advanced professional penetration testing.

A possible structure is:

### Phase 0 — Lab and methodology foundations

* ethics and authorization
* rules of engagement
* legal boundaries
* penetration-testing methodology
* threat modeling
* attack surface
* kill chain concepts
* MITRE ATT&CK
* lab architecture
* Linux fundamentals required for pentesting
* networking fundamentals
* TCP/IP
* DNS
* HTTP/HTTPS
* TLS
* routing
* NAT
* firewalls
* proxies
* VPNs
* ports and services
* sockets
* authentication concepts

### Phase 1 — Pentesting workflow

* reconnaissance
* passive reconnaissance
* active reconnaissance
* OSINT
* DNS enumeration
* subdomain discovery
* service discovery
* port scanning
* fingerprinting
* enumeration
* vulnerability discovery
* attack-surface mapping
* prioritization
* exploitation methodology
* evidence collection
* cleanup
* reporting

### Phase 2 — Linux

* Linux architecture
* permissions
* users/groups
* processes
* services
* networking
* shells
* Bash
* environment variables
* cron
* SUID/SGID
* capabilities
* sudo
* PATH issues
* file permissions
* kernel/userland concepts
* common Linux privilege-escalation patterns

### Phase 3 — Windows

* Windows architecture
* processes
* services
* users/groups
* registry
* PowerShell
* Windows authentication
* NTLM
* Kerberos
* SMB
* RPC
* WinRM
* LDAP
* Windows permissions
* tokens
* impersonation
* services
* scheduled tasks
* common privilege-escalation paths

### Phase 4 — Active Directory

This must be a major section, not a small module.

Teach:

* AD architecture
* domains
* forests
* trusts
* domain controllers
* LDAP
* Kerberos
* NTLM
* users
* groups
* computers
* organizational units
* GPOs
* ACLs
* delegation
* SPNs
* service accounts
* authentication flows
* credential material
* password attacks
* Kerberoasting
* AS-REP roasting
* delegation attacks
* ACL abuse
* GPO abuse
* credential reuse
* lateral movement
* Windows remote administration
* domain privilege escalation
* attack-path analysis
* BloodHound-style graph reasoning
* modern AD attack chains

The student should eventually be able to analyze an AD environment as a graph of identities, permissions, credentials, machines, and trust relationships.

### Phase 5 — Web application penetration testing

Use OWASP as a foundation but go deeper than the OWASP Top 10.

Cover:

* HTTP deeply
* cookies
* sessions
* authentication
* authorization
* access control
* JWT
* OAuth
* OpenID Connect
* CSRF
* XSS
* SQL injection
* NoSQL injection
* command injection
* SSTI
* SSRF
* XXE
* file upload vulnerabilities
* path traversal
* deserialization
* prototype pollution
* request smuggling
* race conditions
* business-logic vulnerabilities
* IDOR/BOLA
* privilege escalation
* authentication bypass
* password reset flaws
* session attacks
* CORS
* cache poisoning
* cache deception
* WebSockets
* modern browser security mechanisms

Do not teach these merely as definitions.

Students must learn how to recognize them from application behavior.

### Phase 6 — API security

Cover:

* REST
* GraphQL
* authentication
* authorization
* object-level authorization
* function-level authorization
* mass assignment
* excessive data exposure
* rate limiting
* API abuse
* JWT attacks
* OAuth problems
* API discovery
* schema analysis
* undocumented endpoints
* versioning problems

### Phase 7 — Exploitation

Teach exploitation methodology rather than just Metasploit usage.

Cover:

* exploit development concepts
* memory layout
* stack/heap fundamentals
* memory corruption
* buffer overflows
* shellcode concepts
* bad characters
* return addresses
* calling conventions
* mitigations
* ASLR
* DEP/NX
* stack canaries
* PIE
* ROP concepts

Use intentionally vulnerable targets.

Where appropriate, teach both:

1. understanding the vulnerability manually
2. using professional tooling

### Phase 8 — Credential attacks

Cover:

* password policies
* password spraying
* brute force
* credential stuffing
* hashes
* password cracking
* NTLM
* Kerberos tickets
* offline attacks
* wordlists
* rules
* masks
* credential reuse
* secrets discovery
* browser credentials
* configuration secrets
* API keys
* tokens

Teach when an attack is appropriate and how to avoid unnecessarily destructive testing.

### Phase 9 — Lateral movement

Teach:

* SMB
* WinRM
* RDP
* SSH
* PsExec-style techniques
* WMI
* PowerShell remoting
* remote services
* credential reuse
* pass-the-hash
* pass-the-ticket
* tunneling
* proxying
* pivoting
* SOCKS
* network segmentation bypass concepts

### Phase 10 — Pivoting and complex networks

Create multi-network labs where:

Internet → DMZ → internal network → restricted network

The student must discover routes and pivot through compromised machines.

Teach:

* routing
* port forwarding
* SSH tunnels
* SOCKS
* proxychains-style workflows
* reverse tunnels
* network discovery through pivots
* segmentation analysis

### Phase 11 — Containers

Cover:

* Docker architecture
* container isolation
* capabilities
* namespaces
* volumes
* exposed Docker sockets
* container escape concepts
* secrets
* insecure images
* supply-chain risks
* Kubernetes basics
* Kubernetes attack surface

Only include Kubernetes exploitation where it meaningfully belongs in a pentesting curriculum.

### Phase 12 — Cloud security

Introduce cloud pentesting concepts for:

* AWS
* Azure
* GCP where appropriate

Cover:

* IAM
* roles
* credentials
* metadata services
* storage
* security groups
* identity escalation
* cloud APIs
* secrets
* logging
* common cloud misconfigurations
* attack paths

Do not make this an enormous cloud-engineering course. Focus on penetration-testing skills.

### Phase 13 — Red-team / adversary simulation concepts

Introduce:

* initial access
* persistence concepts
* command and control
* privilege escalation
* lateral movement
* credential access
* defense evasion concepts
* operational security
* detection-aware testing
* attack chains

Use MITRE ATT&CK as a conceptual framework.

Avoid turning this section into malware development.

### Phase 14 — Professional penetration testing

Teach:

* scope
* rules of engagement
* assumptions
* exclusions
* test planning
* evidence handling
* severity
* risk
* remediation
* screenshots
* reproduction steps
* executive summaries
* technical findings
* attack narratives
* timelines
* retesting
* client communication

Students should produce a professional penetration-testing report.

---

# 5. Practical labs

This is one of the most important requirements.

Every significant learning unit must have practical work.

Do NOT create trivial exercises such as:

> "Run nmap against this machine."

Instead, exercises should require the student to reason.

Example:

Instead of:

> Scan the target.

Use:

> You have been given a partially documented corporate network. Several services are intentionally exposed, but only some belong to the application environment. Map the externally reachable attack surface, identify the technology stack, determine which services deserve deeper investigation, and justify your prioritization. Submit evidence supporting your conclusions.

Exercises should resemble real engagements.

---

# 6. Build a local penetration-testing laboratory

The course must include a complete reproducible local lab using Docker wherever practical.

The lab must contain intentionally vulnerable systems and services.

Build isolated environments for:

* attacker workstation
* Linux targets
* Windows targets where technically feasible
* web applications
* APIs
* databases
* Active Directory
* vulnerable network services
* pivot hosts
* segmented networks
* container targets
* cloud-security simulations where practical

Use Docker Compose and/or appropriate local virtualization where Docker alone cannot realistically reproduce the environment.

Do not pretend Docker can faithfully reproduce Windows/AD when it cannot.

If a VM is required, document the appropriate VM technology and integrate it into the lab architecture.

The lab must be:

* isolated
* reproducible
* resettable
* documented
* safe
* deterministic enough for course exercises

Provide:

* architecture diagrams
* network ranges
* credentials where appropriate
* setup scripts
* Dockerfiles
* Compose files
* reset scripts
* seed data
* exercise initialization scripts
* teardown procedures
* troubleshooting documentation

---

# 7. Safety architecture

The lab must be designed so students cannot accidentally attack the public Internet.

Prefer:

* private Docker networks
* isolated virtual networks
* intentionally vulnerable targets
* explicit target allowlists
* no unnecessary Internet exposure
* disposable environments

The course must repeatedly distinguish:

LAB TARGETS

from

REAL SYSTEMS.

Never instruct students to attack systems they do not own or lack explicit authorization to test.

---

# 8. Realistic attack scenarios

Create multi-stage scenarios.

Examples:

### Scenario A — External web assessment

Student receives:

* domain
* limited scope
* application URL
* no credentials

Student must:

1. perform reconnaissance
2. map attack surface
3. identify application technology
4. discover vulnerabilities
5. chain multiple weaknesses
6. obtain initial access
7. escalate privileges
8. collect evidence
9. determine business impact
10. produce a report

### Scenario B — Internal network assessment

Student receives:

* foothold on one workstation

They must determine how far they can move through the network.

### Scenario C — Active Directory compromise

Student starts with a low-privileged domain account.

They must discover an attack path to a high-privileged account.

Do not tell them the intended path.

### Scenario D — Segmented network

Student starts on a DMZ host.

The target is located behind an internal network.

They must discover and use an appropriate pivot.

### Scenario E — Web + infrastructure chain

The intended solution should require discovering multiple independent weaknesses and chaining them.

### Scenario F — Professional engagement

Give the student:

* scope
* rules of engagement
* client description
* limited credentials
* network information
* application information

Then require a complete assessment and professional report.

---

# 9. Exercise design

Every substantial exercise should contain:

## Situation

A realistic scenario.

## Objective

What the student must accomplish.

## Starting information

Only what a real tester would reasonably receive.

## Constraints

What is in and out of scope.

## Expected deliverables

For example:

* reconnaissance notes
* attack-surface map
* evidence
* vulnerability identification
* exploit chain
* root cause
* impact
* remediation
* report

## Hints

Progressive hints rather than immediately revealing the answer.

For example:

Hint 1 — conceptual direction

Hint 2 — technique family

Hint 3 — relevant tool/category

Hint 4 — specific investigation direction

Do NOT expose the solution in the exercise page.

---

# 10. No trivial CTF-only curriculum

CTFs can be used, but the course must not become a CTF collection.

The student must learn to answer:

* What am I looking at?
* Why is this interesting?
* What hypothesis should I test?
* What evidence supports the hypothesis?
* What attack path does this create?
* What is the impact?
* What alternative explanations exist?
* How would this appear in a professional report?
* How would I reproduce this reliably?

The student should develop investigation skills.

---

# 11. Tooling

Teach tools when they support a concept.

Potential tools include:

* Nmap
* RustScan where appropriate
* Masscan where appropriate
* Wireshark
* tcpdump
* Burp Suite
* ffuf
* gobuster
* feroxbuster
* Nikto where still relevant
* Netcat
* Socat
* curl
* wget
* DNS tools
* Responder
* Impacket
* BloodHound
* NetExec
* CrackMapExec concepts/history where relevant
* Hashcat
* John the Ripper
* Metasploit
* sqlmap
* linPEAS
* winPEAS
* PowerShell
* Evil-WinRM
* Rubeus where appropriate
* Mimikatz concepts
* Chisel
* Proxychains
* Ghidra
* pwntools
* debugger tooling

Do not blindly teach every tool.

For each important tool explain:

* what problem it solves
* what it actually does
* what protocol/technology it interacts with
* important options
* limitations
* what the output means
* how to verify the result manually

Students must understand the underlying mechanism.

---

# 12. Tool version management

Because security tooling changes quickly:

* pin important tool versions where practical
* document tested versions
* make lab builds reproducible
* record version information
* avoid tutorials that depend on undocumented behavior
* periodically identify outdated instructions

Include a `TOOLS.md` or equivalent inventory.

---

# 13. Course website

Build the course as a GitHub Pages website.

Requirements:

* responsive
* clean
* searchable
* fast
* works on desktop
* works on mobile
* easy navigation
* course progress visible
* module navigation
* previous/next lesson
* exercise links
* lab setup documentation
* references
* glossary
* command/reference material

The website must be generated from Markdown/source files in the repository.

Do not make GitHub Pages itself the source of truth.

The repository should remain the authoritative course source.

---

# 14. Progress tracking

Implement meaningful progress tracking.

The course should track:

* completed modules
* completed lessons
* completed exercises
* lab milestones
* assessments
* practical projects
* knowledge checkpoints

Prefer a GitHub-friendly mechanism.

For example:

* progress YAML/JSON
* generated progress dashboard
* checkboxes
* GitHub Issues
* GitHub Projects
* local progress file

Do not require a backend server unless there is a compelling reason.

Progress should be stored in a way that survives rebuilding the site.

---

# 15. Knowledge checks

Every major conceptual section should include questions that test understanding.

Avoid:

> What command performs X?

Prefer:

> You observe this network behavior. What hypotheses does it suggest, and what would you test next?

Use:

* conceptual questions
* scenario questions
* debugging questions
* attack-path reasoning
* interpretation of command output
* vulnerability-analysis questions

Do not automatically reveal answers.

Provide a separate solution/teacher section where appropriate.

---

# 16. Practical assessments

Create substantial assessments after major phases.

Examples:

### Assessment 1

External reconnaissance and enumeration.

### Assessment 2

Linux privilege escalation.

### Assessment 3

Windows privilege escalation.

### Assessment 4

Web application penetration test.

### Assessment 5

Active Directory attack path.

### Assessment 6

Pivoting and segmented networks.

### Assessment 7

Full penetration test.

The final assessment should be a realistic engagement with minimal guidance.

---

# 17. Final capstone

Create a large integrated environment.

The student should have to:

* enumerate
* discover attack surface
* exploit
* establish a foothold
* escalate privileges
* pivot
* compromise additional systems
* identify sensitive assets
* demonstrate impact
* document evidence
* write a professional report

Do not publish the intended attack path on the student-facing page.

Provide instructor/solution material separately.

---

# 18. Reporting training

Teach professional reporting explicitly.

Create templates for:

* executive summary
* technical finding
* vulnerability description
* affected asset
* reproduction steps
* evidence
* impact
* remediation
* references
* severity rationale

Students must practice writing findings from their own discoveries.

Do not let the course reduce pentesting to "get root."

The professional outcome is:

**discover → validate → understand → demonstrate impact → document → communicate → remediate → retest**

---

# 19. Modernity and maintenance

The course should be designed for continuous updating.

Create a mechanism for identifying:

* new major vulnerabilities
* new attack techniques
* important changes in tools
* changes in Windows/AD
* changes in web technology
* changes in cloud security
* major changes in certification objectives

However:

**Do NOT turn the course into a news feed.**

Only update core lessons when a change is sufficiently important to affect established methodology, tooling, or professional practice.

Maintain:

* `CHANGELOG.md`
* curriculum version
* lesson version where useful
* last-reviewed date
* source references

When updating a lesson, preserve the foundational material unless it is genuinely obsolete.

---

# 20. Research citations

Every substantial technical section should include references.

Prefer primary sources.

For vulnerabilities include, where appropriate:

* CVE
* CWE
* vendor advisory
* original research
* OWASP reference
* MITRE ATT&CK technique

Do not use citations merely to make the page look academic.

The reference should allow the student to investigate further.

---

# 21. Course teaching style

Teach concepts in this order whenever practical:

1. intuition
2. underlying technology
3. why the weakness exists
4. how a tester recognizes it
5. manual investigation
6. tooling
7. exploitation
8. verification
9. impact
10. remediation
11. realistic exercise

Use concrete examples.

When introducing a technical concept, show the relevant packets, HTTP requests, authentication flows, filesystem state, permissions, processes, or network behavior whenever useful.

Do not assume that running a tool means the student understands what happened.

---

# 22. Avoid cargo-cult commands

Never teach:

`run this command → receive shell`

without explaining:

* why the command works
* what protocol it uses
* what request it sends
* why the target is vulnerable
* how to recognize the vulnerability without the tool
* how to verify the result

The goal is to create a penetration tester, not a command memorizer.

---

# 23. Repository structure

Create a clean repository structure similar to:

```text
pentesting-course/
├── README.md
├── LICENSE
├── CHANGELOG.md
├── CONTRIBUTING.md
├── course/
│   ├── 00-foundations/
│   ├── 01-methodology/
│   ├── 02-recon/
│   ├── 03-enumeration/
│   ├── 04-linux/
│   ├── 05-windows/
│   ├── 06-active-directory/
│   ├── 07-web/
│   ├── 08-api/
│   ├── 09-exploitation/
│   ├── 10-credentials/
│   ├── 11-lateral-movement/
│   ├── 12-pivoting/
│   ├── 13-containers/
│   ├── 14-cloud/
│   ├── 15-red-team/
│   └── 16-professional-practice/
├── labs/
│   ├── docker/
│   ├── vm/
│   ├── networks/
│   └── scenarios/
├── exercises/
├── assessments/
├── capstone/
├── solutions/
├── references/
├── tools/
├── scripts/
├── progress/
└── website/
```

Adapt this structure if a better architecture emerges.

---

# 24. Instructor/solution separation

Student-facing content must not accidentally reveal exercise solutions.

Separate:

```text
student/
solutions/
instructor/
```

or an equivalent architecture.

The public GitHub Pages site should expose only material intended for students.

Solutions should be clearly separated and protected from accidental discovery where practical.

---

# 25. Lab automation

Make lab setup as automated as reasonably possible.

The ideal workflow should be approximately:

```text
clone repository
↓
run setup
↓
start lab
↓
verify lab
↓
start lesson
↓
perform exercise
↓
record progress
```

Provide health checks.

For example:

```text
./lab up
./lab status
./lab reset
./lab down
```

Adapt commands to the actual implementation.

Every lab should document:

* required hardware
* CPU/RAM requirements
* disk requirements
* required software
* network architecture
* startup
* shutdown
* reset
* troubleshooting

---

# 26. Environment assumptions

The primary development environment is:

* Windows
* Docker Desktop
* WSL
* Git
* GitHub

Where Docker is insufficient for a realistic Windows/Active Directory environment, explicitly use a suitable VM approach rather than constructing an unrealistic simulation.

Document the distinction between:

**Docker lab**

and

**VM lab**.

---

# 27. Quality standard

Before considering the course complete, audit it for:

* technical correctness
* outdated commands
* broken links
* missing prerequisites
* unrealistic assumptions
* exercises that are too easy
* exercises that accidentally reveal solutions
* inconsistent terminology
* missing explanations
* missing practical work
* unsafe lab configurations
* reproducibility
* certification coverage
* professional relevance

Run automated checks where possible.

---

# 28. Important design principle

The course should progressively remove assistance.

Early:

> Here is the concept. Here is how to investigate it.

Middle:

> Here is the scenario. Determine what to investigate.

Advanced:

> Here is the engagement. Determine your methodology.

Final:

> Here is the scope and the environment. Conduct the assessment.

This progression is essential.

---

# 29. Do not start by writing thousands of pages

First produce:

1. researched curriculum architecture
2. competency map
3. certification coverage matrix
4. prerequisite graph
5. lab architecture
6. repository architecture
7. website architecture
8. progress-tracking design
9. exercise design standard
10. maintenance/update strategy

Then implement the course incrementally.

Do not generate huge amounts of low-quality repetitive content simply to make the repository look complete.

Each lesson must earn its place.

---

# 30. Definition of "complete"

The project is complete only when there is:

* a coherent curriculum
* substantial theoretical teaching
* practical work for the major concepts
* realistic multi-step exercises
* local vulnerable environments
* reproducible lab setup
* Linux training
* Windows training
* Active Directory training
* web penetration testing
* API security
* exploitation fundamentals
* privilege escalation
* credential attacks
* lateral movement
* pivoting
* container security
* relevant cloud security
* professional methodology
* professional reporting
* substantial assessments
* final capstone
* progress tracking
* GitHub Pages website
* references
* versioning
* maintenance strategy

Do not declare completion merely because the website builds.

---

# 31. First task

Before implementing the course, research the current penetration-testing certification landscape and produce the proposed curriculum architecture.

Show:

1. phases
2. modules
3. lessons
4. prerequisites
5. practical labs
6. assessments
7. capstone
8. certification mapping
9. estimated difficulty
10. dependencies between subjects

Then identify any major gaps in the proposed curriculum.

Only after this architecture is coherent should you begin implementing the actual course.

The goal is a **serious, modern, technically deep penetration-testing education platform**, not a beginner cybersecurity tutorial and not a collection of CTFs.
