# Instructor / solutions — Module 14 (Cloud penetration testing)

> Instructor material. Not linked from `_sidebar.md`. Do the exercises before reading.

These answers assume `labs/lab-14-cloud` as specified: a LocalStack-style local AWS API (IAM, STS,
S3, EC2 describe/run) bound to `localhost:4566` on the isolated network, wired to the metadata
simulation carried over from `lab-07-web`, with **synthetic** identities and `LAB-FLAG-{uuid}`
markers. Seeded principals used below — `ci-deploy` (low-priv user), `app-instance-role` (the SSRF-
reachable instance role), `admin-exec` (reachable via `PassRole`+`RunInstances`), and `reporting` (an
over-trusting role) — are illustrative; exact names/paths vary with the built lab. **Grade on
reasoning, mechanism, safety discipline, and the presence of remediation AND detection**, not on
matching a specific command. The universal safety bar: any submission that describes running these
against a real tenant without *both* client authorization and provider RoE, or that touches real
`169.254.169.254`, fails the professionalism bar (M00/14.1).

---

## 14.1 — Fundamentals, IAM & scoping a leaked credential

**Exercise (blast-radius report, read-only).** Full credit is a report that (a) identifies the
principal from evidence, (b) derives the effective permission set from the actual policy JSON, (c)
states blast radius in client terms, and (d) draws the scope/RoE boundary — **with no state-changing
call anywhere in the transcript.**

Model flow and reasoning:

- **Principal:** `aws sts get-caller-identity` → `Arn: …:user/ci-deploy`, account `000000000000`.
  This is the safe, permission-free first call — the cloud `id`/`whoami`. A submission that starts by
  *using* the key aggressively (listing/downloading everything) instead of establishing identity loses
  methodology points even if nothing broke.
- **Effective permissions:** `iam list-attached-user-policies` + `list-user-policies`, then
  `get-policy-version` to read each JSON. The strong answer *quotes the dangerous statements* and
  reads them correctly — e.g. `s3:*` on `*` = full control of every bucket (read/write/**delete**/
  policy-change), and flags any `iam:PassRole`/`AssumeRole`/`CreatePolicyVersion`/`AttachUserPolicy`/
  `CreateAccessKey` as **escalation leads for 14.3** without exercising them. Where policy reads are
  denied, `SimulatePrincipalPolicy` or careful read-only probing (`s3 ls`, `ec2 describe-*`) is
  acceptable, with the note that each probe is a logged call.
- **Blast radius:** stated as business impact and worst realistic outcome, e.g. *"this CI user can read
  and delete every object in the account's buckets; if those hold backups/PII this is a full data-
  exposure and data-destruction risk; the `PassRole` grant is a likely path to account admin (14.3)."*
- **Scope/RoE note:** reading the client's own buckets/config/IAM = client-owned = in scope. Anything
  that would probe the provider's control plane beyond the account, hit shared infrastructure, or touch
  a resource the client doesn't own = out of scope; name it and stop. Shared responsibility is the
  scope oracle.

Docking: any create/modify/delete or `assume-role` (that's 14.3); "I have admin" with no policy JSON
behind it; treating the key as the finding rather than the identity; missing the escalation-lead flags;
no scope boundary.

**Check-yourself.**
1. `aws sts get-caller-identity`. It returns the principal ARN + account, needs no permissions of its
   own, and is a pure **read** — it changes nothing and (barely) logs, so it's the safest maximal-info
   first move. It answers "who am I," which sizes everything else.
2. The **`iam:PassRole`** line is the bigger *escalation* risk: combined with a compute-launch
   permission it becomes account admin (14.3). The `s3:*`/`*` line is the bigger *access* risk (all
   data now). They differ because access = "what data/resources can I touch as myself"; escalation =
   "what stronger identity can I *become*." A small-access credential with a potent escalation edge can
   be worse than a broad-access one with none.
3. Shared-responsibility answer: a cross-tenant hypervisor bug is on the **provider's** side of the
   line — it is AWS's responsibility and **not the client's to authorize you to test**. You explain
   that you cannot test the provider's infrastructure (provider RoE forbids it and the client can't
   authorize what it doesn't own); you can note the *concern* conceptually and point to the provider's
   compliance attestations, but you do not probe it.
4. `AKIA…` = a **long-lived** IAM user access key (no expiry, valid until revoked). `ASIA…` = a
   **temporary** STS credential, and it comes **with a session token** and an expiry. The session token
   is the tell: you have limited time, and the credential almost certainly came from `AssumeRole` or an
   instance/role (metadata) — i.e. a foothold that expires, so act within its lifetime and expect it to
   rotate.
5. Read-only self-enumeration is **safe** (no state change, minimal footprint, no accidental
   destruction) and **most informative** (policies tell you *everything* you can do at once, including
   things you'd never think to probe), whereas "try actions to see what works" is noisy (every attempt
   logs and may alert), incomplete (you only learn about actions you thought to try), and risky (a
   mistaken destructive verb). Enumerate authority first; act deliberately second.

---

## 14.2 — Metadata, storage & network exposure

**Exercise (SSRF → cloud creds chain + impact + IMDSv2 fix).** Full credit chains the app SSRF to the
metadata sim, establishes the *stolen identity* and its blast radius read-only, states impact in client
terms, and gives the IMDSv2 remediation **with the reason it defeats a GET-only SSRF**, plus detection.

Model answer:

- **The chain (mechanism):** confirm the SSRF fetch happens (internal lab listener, as in 07.4), then
  point it at the metadata path — `…/iam/security-credentials/` returns the role name
  (`app-instance-role`), and `…/iam/security-credentials/app-instance-role` returns the synthetic
  credential blob (key + secret + **token**). It's a single forged GET because the sim models
  **IMDSv1** (unauthenticated GET). Mechanism to state: the SSRF makes the *server* issue the request;
  the metadata service answers any request "from the instance"; the attacker borrows the instance's
  identity — the confused deputy escalated to the cloud.
- **Stolen identity + blast radius:** load all three values (temporary creds require the session
  token), `get-caller-identity` → `assumed-role/app-instance-role/…` (not the original user), then
  read-only enumerate what the role can reach (14.1 method).
- **Impact:** theft of the instance role's creds → attacker acts as the role → if over-privileged,
  account compromise from one web bug; explicitly the **Capital One (2019)** pattern (SSRF → IMDSv1 →
  role → S3, 100M+ records).
- **Remediation + detection:** enforce **IMDSv2** (`HttpTokens: required`) + **hop limit 1**, *and* fix
  the app-layer SSRF (allowlist, block link-local post-resolution), *and* least-privilege the instance
  role. The required one-liner: *IMDSv2 defeats a GET-only SSRF because obtaining the session token
  needs a `PUT` with a custom header the SSRF can't produce, so the credential GET is refused; IMDSv2 is
  a mitigation of the SSRF class, not a fix for code already on the box — hence all three defenses.*
  Detection: GuardDuty `InstanceCredentialExfiltration.OutsideAWS`, CloudTrail role-from-unexpected-IP,
  outbound `169.254.169.254` in flow/app logs. ATT&CK T1552.005 → T1078.004.

Docking: stopping at "reflection/creds observed" without loading them and proving the *new identity*;
forgetting the session token; missing the IMDSv2 mechanism sentence; giving IMDSv2 as the *only* fix
(it doesn't fix the SSRF for on-box code); no detection.

**Check-yourself.**
1. IMDSv2 requires a **`PUT /latest/api/token` with the `X-aws-ec2-metadata-token-ttl-seconds`
   header** to get a session token, then that token in the `GET`. A typical SSRF can only make the
   server issue a **simple GET** and can't set request headers, so it can't obtain the token, and
   without it the credential GET is refused. (The default **hop limit 1** further stops proxying the
   reply off-box.)
2. Both **Azure IMDS** and **GCP metadata** have *always* required a **non-standard request header**
   (`Metadata: true` and `Metadata-Flavor: Google` respectively). A naive GET-only SSRF can't add that
   header, so it fails — the same design choice IMDSv2 retrofitted onto AWS. (Accept: it's the
   required-custom-header property, not the token specifically, that they share.)
3. `--no-sign-request` succeeding proves the bucket is readable **with no credentials at all** —
   *anyone on the Internet* can read it, no compromise required. Reading it with your own valid creds
   only proves *you* (an authorized-by-your-key principal) can — a far lower-severity condition.
   Anonymous access = worst case, and it's exploitable by everyone.
4. `22/tcp` from `0.0.0.0/0` (SSH to the whole Internet) is the finding; `443/tcp` from `0.0.0.0/0` is
   probably the intended public web listener. Report wording for the SSH rule, e.g.: *"Security group
   `sg-app` permits inbound SSH (22/tcp) from `0.0.0.0/0`, exposing host management to the entire
   Internet and enabling brute-force/credential attacks; restrict to the bastion/VPN CIDR or move
   management behind SSM."*
5. You borrowed the **instance's (the server's) identity** — the instance role's temporary credentials.
   The metadata service handed them over without authentication because it was designed to trust that
   any request reaching the link-local endpoint originates from the instance's own (trusted) code; SSRF
   violates that assumption, making the server a confused deputy that fetches the creds on the
   attacker's behalf.

---

## 14.3 — Cloud identity & privilege escalation

**Exercise (one justified, verified privesc path, report-ready).** Full credit names the enabling
permission (quoting JSON), explains the **mechanism** (identity transformation / confused deputy),
shows **before/after `get-caller-identity`** plus a call only the escalated identity can make, states
impact, gives remediation **and** detection with ATT&CK, notes cleanup, and gives the Azure/GCP
equivalent. Model answers for the likely lab edges:

- **`PassRole` + `RunInstances`:** `ci-deploy` holds `iam:PassRole` on `admin-exec` **and**
  `ec2:RunInstances`. Confirm with `get-policy-version` + `SimulatePrincipalPolicy`; launch an instance
  with `--iam-instance-profile Name=admin-exec`; read the instance's metadata creds (14.2) → act as
  `admin-exec`. Mechanism: `PassRole` alone is inert; paired with a service that *runs as the passed
  role*, you give a powerful role to a machine you control and harvest its creds — confused deputy (the
  compute service runs as the role you handed it). Fix: scope `PassRole` by role-ARN + `iam:PassedToService`,
  never `PassRole` on `*`; alert on any principal holding `PassRole`+launch. Detect: CloudTrail
  `RunInstances` with a powerful instance profile by a non-deploy principal. ATT&CK T1078.004/T1098.
  Azure/GCP: GCP `iam.serviceAccounts.actAs` + deploy a GCE/Cloud Function; Azure assign a managed
  identity to a VM you control.
- **`AssumeRole` + over-broad trust policy:** `reporting`'s trust policy names `"AWS":"*"` (or the whole
  account). `aws sts assume-role --role-arn …:role/reporting` → temp creds; `get-caller-identity` →
  `assumed-role/reporting/…`. Mechanism: the trust policy is the *only* gate on assumption, and it was
  left open, so any principal walks in; chain if `reporting` can assume higher. Fix: name specific
  principals, add `ExternalId`/`aws:PrincipalOrgID` conditions, never `"Principal":"*"`. Detect:
  CloudTrail `AssumeRole` to a sensitive role from an unusual principal; Access Analyzer external-trust
  finding. ATT&CK T1078.004. Azure/GCP: GCP `iam.serviceAccounts.getAccessToken`/`signJwt`; Azure a
  managed-identity token.
- **`CreatePolicyVersion`:** create a new default version of a policy attached to `ci-deploy` with
  `*`/`*`, `--set-as-default`. Mechanism: rewrites what your own policy *says* without needing
  `AttachUserPolicy`. Fix: don't grant `CreatePolicyVersion`/`SetDefaultPolicyVersion` on policies a
  principal is attached to. Detect: CloudTrail `CreatePolicyVersion`+`SetDefaultPolicyVersion`. Azure:
  `roleAssignments/write`; GCP: `setIamPolicy`.
- **`AttachUserPolicy`/`PutUserPolicy`:** attach `AdministratorAccess` to self (or inline it).
  Mechanism: permission to modify who-has-permission is administrative by nature. Fix/Detect: treat as
  privileged; alert on broad-policy attaches. Azure `Owner`/`User Access Administrator`; GCP
  `setIamPolicy`.
- **`CreateAccessKey` for another user:** mint keys for a higher-priv user → become them (also
  persistence). Fix: restrict `CreateAccessKey` to self/admins. Detect: CloudTrail `CreateAccessKey`
  for a different user. GCP `serviceAccountKeys.create`; Azure add client secret to a service principal.

**Safety grading (critical for 14.3):** the escalating verbs *change state*. Full credit demonstrates
with the **minimum** proof (assume→`get-caller-identity`→stop; or launch→read creds→show identity) and
explicitly **does not** attach admin to a live identity or mint durable backdoor keys "to prove it," and
**notes cleanup** (detach the policy, terminate the instance, delete the key) as you'd clean a dropped
SUID binary (04.2). A student who fires the most destructive proof, or leaves backdoors, loses
professionalism points even in the lab and would be out-of-bounds on a real engagement without sign-off.
Reward `SimulatePrincipalPolicy` used to confirm the edge *before* executing.

Docking: command with no mechanism; "could have escalated" with no before/after identity evidence;
missing remediation OR detection (both required); no cleanup note; no Azure/GCP mapping; destructive
"proof" beyond the minimum.

**Check-yourself.**
1. `iam:PassRole` only lets you *hand a role to a service* — you can't use the role yourself, so alone
   it does nothing. The extra class is a **compute-launch / run-as-role permission** (`ec2:RunInstances`,
   `lambda:CreateFunction`+`Invoke`, `glue`, `cloudformation`, …): a service that *runs as the passed
   role*, which you then harvest creds from or execute code within.
2. `AttachUserPolicy` **adds a policy** (e.g. `AdministratorAccess`) to your identity — it changes
   *which policies are attached*. `CreatePolicyVersion` **rewrites the contents** of a policy already
   attached to you to `*`/`*` and sets it default — it changes *what an attached policy says*. Same
   destination (admin), different object changed: attachment vs. policy body.
3. The trust policy is the **sole gate** on who may assume a role; `"Principal":{"AWS":"*"}` means *any
   principal in any account* can `sts:AssumeRole` it and receive its credentials. So it's a complete
   finding by itself — you need no other permission of your own, and if the role has meaningful power
   (or can assume higher), it's a direct escalation/cross-account door.
4. Deputy = the **compute service** (EC2/Lambda) that launches your resource; you borrow the **passed
   role's** privilege. The service complies because it's *designed* to run workloads as whatever role
   the caller specifies via the instance profile / execution role — it dutifully assumes and exposes
   the role's creds to the workload, not distinguishing "legitimate deploy" from "attacker passing a
   powerful role to a box they control."
5. GCP equivalent of `PassRole`+`RunInstances`: **`iam.serviceAccounts.actAs`** + deploy a GCE
   instance / Cloud Function / Cloud Run that runs as that service account. Azure equivalent of "attach
   yourself admin": hold **`Owner`/`User Access Administrator`** (or `Microsoft.Authorization/roleAssignments/write`)
   and assign yourself a privileged role. The *shape* matters more than the names because the permission
   identifiers differ across clouds but the three escalation shapes — grant-yourself-power, pass-power-
   to-compute, become-another-identity — are universal; recognizing the shape lets you find the path in
   any provider you're dropped into.

---

## Grading notes (all three lessons)

- **Identity, not credential.** The recurring M14 discipline: after finding any credential/foothold, the
  first move is read-only enumeration of *what identity it is and what that identity may do or become* —
  not aggressive use. Reward this order; penalize "use first, understand later."
- **Mechanism is mandatory.** "Ran the call, got admin" without *why the permission transforms the
  identity* (confused deputy / identity graph) is a partial answer — the point is reasoning that
  transfers across accounts and clouds.
- **Remediation AND detection, every finding.** Non-negotiable, as throughout the course; a finding
  missing either is incomplete regardless of how clean the exploit was. Detection maps to CloudTrail/
  GuardDuty/Access Analyzer and ATT&CK (T1552.005, T1078.004, T1098, T1548, T1530, T1580).
- **Safety and RoE are doubled in the cloud.** Two authorization layers — client (own resources only)
  *and* provider penetration-testing policy — plus the shared-responsibility line as scope oracle. Any
  submission that touches real metadata, probes shared/provider infrastructure, or would run destructive
  IAM changes on a real account without sign-off fails the professionalism bar. In the lab: minimum
  proof, no durable backdoors, cleanup noted.
- **Verification evidence is part of the finding:** `get-caller-identity` (before/after for escalation),
  the policy/trust JSON, the API responses, and the synthetic `LAB-FLAG-{uuid}` where relevant — not
  optional.
- **Cross-cloud transfer.** Reward correct AWS→Azure→GCP shape mapping; the course teaches pentesting
  skills that transfer, not one provider's console.
