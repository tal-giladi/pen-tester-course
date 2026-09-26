# 14.1 — Cloud pentesting fundamentals: the shared-responsibility model, IAM, credentials & rules of engagement

<div class="prereq">

**Prerequisites:** [00.1 Authorization &amp; RoE](../module-00/lesson-01.md) and
[00.3 Threat modeling &amp; the confused deputy](../module-00/lesson-03.md) (the whole legal frame
and the trust-boundary lens this module leans on), [07.4 SSRF &amp; the metadata simulation](../module-07/lesson-04.md)
(you already reached a *lab* metadata endpoint), and [M10 Credential attacks](../module-10/lesson-01.md)
(where secrets live and how they leak). You must read an HTTP request fluently and think in trust
boundaries.
**Module:** M14 Cloud penetration testing. **Difficulty:** 🔴 advanced.
**You will produce:** a scoped blast-radius report for a set of *synthetic* leaked cloud
credentials — what they can do, what they can reach, and what you must **not** touch — enumerated
entirely against the local lab simulation, with zero destructive actions.

</div>

## Why this matters

When you compromise a server in a data centre, you own a box. When you compromise a *credential* in
the cloud, you own whatever that credential's identity is allowed to do — which may be one bucket, or
may be the entire account's control plane. The cloud collapses "network position" and "privilege"
into a single thing: **identity**. That is why cloud engagements live or die on how well you reason
about IAM, and why the highest-impact cloud findings are almost never memory-corruption exploits —
they are misconfigured *permissions*.

It is also why cloud is the most **legally dangerous** environment you will test. The infrastructure
you are standing on is shared with thousands of other tenants, and it belongs to a provider who did
not sign your engagement letter. A scan that would be routine on-premises can, in the cloud, hit
someone else's data or trip a provider's abuse protections. This lesson builds the two foundations
everything else in M14 rests on: **how cloud identity actually works**, and **what you are and are
not allowed to do to it**.

## Learning objectives

By the end you can:

- State the **shared-responsibility model** and use it to decide, for a given service, whether a
  weakness is the client's fault (in scope) or the provider's (never yours to test).
- Explain the AWS IAM object model — **principals, users, roles, policies, and STS/AssumeRole** — and
  map it to Azure (Entra ID, managed identities) and GCP (service accounts).
- Read an IAM policy JSON and spot an over-permissive `Action:*`/`Resource:*` or a dangerous
  `iam:PassRole`/`sts:AssumeRole` grant.
- Name the **credential types** (long-lived keys, temporary STS tokens, instance/role credentials)
  and **where they leak** (env vars, instance metadata, config files, CI/CD, source control).
- Enumerate *your own* effective permissions non-destructively, and scope a blast radius.
- Apply the **provider rules of engagement** and explain why some cloud assets are never testable.

## Intuition

Think of a traditional network as a building: rooms (hosts), corridors (the network), and locks
(credentials). Compromise spreads by *moving through corridors*. The cloud has almost no corridors.
Instead, every action — read this object, launch that machine, assume this role — is an **API call**
to the provider's control plane, and the only question the control plane asks is *"does this
identity's policy allow this action on this resource?"* There is no firewall between you and the API;
there is only IAM. So the attacker's map is not a network diagram, it is a **graph of identities and
what each may do or become**. "Privilege escalation" in the cloud means finding an edge in that graph
that lets a weak identity turn into a strong one. Keep that picture — *identities and the actions that
transform them* — and the rest of the module is filling it in.

## The underlying technology

### The shared-responsibility model <span class="badge found">FOUNDATIONAL</span>

Every cloud provider draws a line: the provider secures the cloud (physical facilities, the
hypervisor, the managed-service backend), and the customer secures what they put *in* the cloud
(their data, their IAM configuration, their network rules, their OS patching where applicable). The
line moves depending on the service model:

```text
                 IaaS (EC2 / VM)     PaaS (RDS / App Svc)   SaaS (S3 / managed)
 Data & IAM      CUSTOMER            CUSTOMER               CUSTOMER
 App / runtime   customer            customer/shared        provider
 OS / patching   CUSTOMER            provider               provider
 Hypervisor      provider            provider               provider
 Physical        provider            provider               provider
```

This is not bureaucratic trivia — it is your **scope oracle**. If you find "the hypervisor leaks
memory across tenants," that is the provider's responsibility and *not yours to test*; report the
concept, never probe it. If you find "this S3 bucket is world-readable" or "this IAM role trusts the
whole Internet," that is squarely the customer's configuration and squarely in scope. The recurring
customer-side failures — IAM, data exposure, network rules — are exactly where your findings will
concentrate, because that is the half the customer owns.

### The IAM object model (AWS, with Azure/GCP mapping) <span class="badge current">CURRENT</span>

AWS Identity and Access Management has a small vocabulary you must own:

- **Principal** — the *who*: an IAM **user** (a long-lived identity, often with access keys), a
  **role** (an identity with no long-lived credentials that principals *assume* to get temporary
  ones), an AWS service, or a federated identity.
- **Policy** — a JSON document listing `Allow`/`Deny` statements, each with an `Action` (e.g.
  `s3:GetObject`), a `Resource` (an ARN), and optional `Condition`. Policies attach to users, groups,
  or roles (identity policies) or to resources like buckets (resource policies).
- **Role + trust policy** — a role has two policies: a *permissions* policy (what it can do) and a
  *trust* policy (who is allowed to assume it). Assuming a role calls **STS** (Security Token Service)
  `AssumeRole`, which returns **temporary credentials** (access key + secret + session token) that
  expire.
- **Evaluation** — a request is allowed only if *some* policy allows it and *no* policy denies it
  (explicit deny always wins).

The same shape exists everywhere, which is why the reasoning transfers:

| Concept | AWS | Azure | GCP |
|---|---|---|---|
| Identity | IAM user / role | Entra ID user / **managed identity** | user / **service account** |
| Grant | IAM policy (JSON) | RBAC **role assignment** over a scope | IAM **role binding** on a resource |
| Temp creds | STS `AssumeRole` | managed-identity token from IMDS | SA token / impersonation |
| "Become another identity" | `sts:AssumeRole` | user-assigned MI / `Owner` on a scope | `iam.serviceAccounts.actAs` / `getAccessToken` |

### Credential types and where they leak <span class="badge current">CURRENT</span>

You will meet credentials in a handful of forms, each with a different lifetime and a different leak
path:

- **Long-lived access keys** (`AKIA…` + secret) — an IAM user's keys. They do not expire; a leaked
  one is valid until revoked. They leak from **committed source** (`.git` history, public repos),
  **config files** (`~/.aws/credentials`, `.env`), **CI/CD variables and logs**, and hard-coded app
  config.
- **Temporary STS credentials** (`ASIA…` + secret + **session token**) — issued by `AssumeRole` or by
  a role attached to compute. Short-lived; the presence of a *session token* is the tell that a
  credential is temporary.
- **Instance/role credentials** — an EC2 instance (or Azure VM, or GCE instance) with an attached
  role/identity gets rotating credentials delivered through the **instance metadata service** (IMDS)
  at `169.254.169.254`. This is the credential an **SSRF** steals (14.2), and the bridge from web to
  cloud you first saw in 07.4.

<div class="callout key">

The single most important cloud-credential fact: **a credential is only as dangerous as the identity
behind it.** An `AKIA…` key with `AdministratorAccess` is game-over; the same key shape with
`s3:GetObject` on one bucket is a minor finding. Your first job after finding *any* credential is not
to use it aggressively — it is to enumerate *what identity it is and what that identity may do.*

</div>

## Why the weakness exists

Cloud IAM defaults to "explicitly deny nothing you didn't grant," but humans grant broadly because
narrow policies are hard to write and easy to break. The failures are structural: developers paste
`"Action": "*"` to make an error go away (CWE-269, improper privilege management); roles are created
with `iam:PassRole` so an app "can launch things" without anyone modelling that this is a privilege-
escalation primitive; long-lived keys are minted for convenience and never rotated (CWE-798,
hard-coded/embedded credentials once they land in code); trust policies are widened to `"Principal":
"*"` during debugging and never tightened (CWE-284, improper access control). The provider gives you
least-privilege tools; the pressure of shipping produces most-privilege configurations. That gap is
your finding surface.

## How a tester recognizes it

- A credential whose identity has **wildcards** in `Action` or `Resource`, or the `*/AdministratorAccess`
  managed policy attached.
- Any grant of `iam:PassRole`, `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, `sts:AssumeRole`,
  `iam:CreateAccessKey`, or the equivalents — these are *escalation* permissions, not just access
  (14.3).
- **Long-lived keys in use where a role would do** (keys on a server that could carry an instance
  role), or keys that appear in more than one place (reuse).
- **Trust policies** that name a broad principal (`"AWS": "*"`, or an entire account) or a weak
  external condition.
- Credentials found *outside* a secrets manager — in env, metadata, disk, CI, or history.

## Manual investigation — enumerate your own permissions first

The disciplined first move with any cloud credential is **read-only self-enumeration**: find out who
you are and what you can do, before you do anything that changes state. Against the lab simulation:

```bash
# LAB SIM ONLY — endpoint points at the local LocalStack-style API, not real AWS.
export AWS_ENDPOINT_URL=http://localhost:4566        # the lab cloud API
aws sts get-caller-identity        # who am I? -> Account, UserId, Arn
aws iam get-user                   # my user object (if I am a user)
aws iam list-attached-user-policies --user-name <me>
aws iam list-user-policies --user-name <me>          # inline policies
aws iam get-policy-version --policy-arn <arn> --version-id v1   # read the JSON
```

`get-caller-identity` is the cloud equivalent of `id` (04.x) and `whoami` — it is non-destructive,
needs no permissions of its own, and tells you the principal ARN and account. From there you read the
attached and inline policies to build the *effective permission set*. Where the provider offers it,
**`iam:SimulatePrincipalPolicy`** answers "can this principal do action X on resource Y?" without
performing X — the ideal blast-radius tool. When you *cannot* read your own policies, you enumerate
by **careful, read-only probing** (`aws s3 ls`, `aws ec2 describe-instances`) and infer permissions
from what succeeds — but every probe is an API call that logs (Detection, below), so you probe
deliberately, not with a firehose.

An example policy you might read back, and how to read it:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "s3:*", "Resource": "*" },
    { "Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::111122223333:role/app-exec" }
  ]
}
```

Read it as a tester: statement 1 is `s3:*` on `*` — full control of **every** bucket in the account
(read, write, *delete*, and change bucket policies), a huge blast radius by itself. Statement 2 grants
`iam:PassRole` on a specific role — innocuous-looking, but it is a **privilege-escalation primitive**
(14.3): if you can also launch compute, you can pass `app-exec` to a machine you control and inherit
its (possibly higher) privileges. Recognising that second line as dangerous is the skill this module
builds.

## Tooling — what it does, key options, limits, verify by hand

- **AWS CLI (against the lab endpoint)** — the ground truth. `--endpoint-url` (or `AWS_ENDPOINT_URL`)
  points it at the local simulation; `--profile` selects a credential set. *Limit:* it does exactly
  what you type — including destructive calls — so you supply `--dry-run` where available and prefer
  `describe`/`list`/`get`/`simulate` verbs while scoping. Always your first tool.
- **ScoutSuite** (concept) — a multi-cloud *auditor*: it reads your account's config through the API
  and reports misconfigurations (public buckets, permissive SGs, weak IAM) as an HTML report. *Limit:*
  read-only and point-in-time; it finds misconfig, it does not exploit, and it needs valid read
  credentials.
- **Prowler** (concept) — CIS-benchmark and best-practice *checks* across hundreds of controls, good
  for "how does this account measure against a standard." *Limit:* a compliance lens, not an attack
  path; a passing check is not proof of no finding.
- **Pacu** (concept) — an *offensive* AWS exploitation framework (Rhino Security Labs): modules for
  enumeration and for privilege-escalation path-finding. *Limit:* it *acts* on the account — many
  modules change state — so it is strictly for authorized engagements against in-scope resources, and
  in this course only its *concepts* apply; you drive the lab with the CLI. **Verify every tool
  finding by hand with a read-only CLI call** before it goes in a report.

## Demonstration (LAB ONLY — local simulation)

<div class="callout attack" data-badge="current">

**Self-enumeration of leaked credentials against the lab sim.** You are handed a synthetic key pair
(`AKIA_LAB_…` / secret) with no context. Non-destructively establish the blast radius:

```bash
export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_ACCESS_KEY_ID=AKIA_LAB_EXAMPLE
export AWS_SECRET_ACCESS_KEY=<lab-synthetic-secret>

aws sts get-caller-identity
# -> Arn: arn:aws:iam::000000000000:user/ci-deploy  (this is who the key belongs to)

aws iam list-attached-user-policies --user-name ci-deploy
aws iam get-policy-version --policy-arn <arn> --version-id <v>   # read the actual permissions
aws s3 ls                                                        # which buckets are even visible
```

Every command here is a **read**. You have learned the identity, its policies, and a first look at
reachable resources without creating, modifying, or deleting anything. That restraint *is* the
professional method — you scope before you strike.

</div>

<div class="callout legal" data-badge="current">

**LAB TARGET vs REAL SYSTEM — and the provider RoE.** Every command above targets
`labs/lab-14-cloud`, a LocalStack-style API bound to `localhost` on the isolated network, using
**synthetic** credentials and benign `LAB-FLAG-{uuid}` markers. Real cloud testing is governed by two
layers of authorization: your **client's** written authorization (they can only authorize *their own*
resources — never the provider's shared infrastructure), **and** the **provider's published
penetration-testing policy**. AWS permits customer-initiated testing of a defined list of your own
services *without prior approval* but forbids others (e.g. DoS, and testing infrastructure you don't
own); Azure and Google publish equivalent Rules of Engagement. Some services are **never** in scope
regardless of who your client is. Never point these commands at a real tenant without *both* the
client authorization and provider-policy compliance in hand. The metadata/credential values in this
lab are fake lab markers — they authenticate to nothing real.

</div>

## Verification

Your enumeration is verified when you can state, from evidence, three things: the **principal ARN**
(`get-caller-identity` output), the **effective permission set** (the policy JSONs you read, or the
`SimulatePrincipalPolicy` results), and the **reachable resources** (the `list`/`describe` output).
"I have admin" is a claim; "the `ci-deploy` user has this attached policy granting `s3:*` on `*` and I
listed 6 buckets" is evidence. A blast-radius statement without the API responses behind it is not a
finding.

## Impact

A leaked credential's impact is exactly its identity's authority, expressed in business terms: read
of `s3:*` → potential exposure of all stored data (customer PII, backups, secrets); `iam:*` or admin →
full account takeover, including creating persistence (new users/keys) and reaching every other
resource; `iam:PassRole` + compute → escalation to whatever roles exist (14.3). Because cloud has no
corridors, one over-privileged credential often equals the whole account — which is precisely why the
finding "this CI key has admin and lives in a public repo" outranks almost any single exploit.

## Remediation

<div class="callout defend">

- **Least privilege, always.** Grant specific `Action`s on specific `Resource` ARNs; never `*/*`.
  Use `Condition` keys (source IP, MFA, `aws:PrincipalOrgID`) to constrain. Audit with Access Analyzer
  / IAM last-accessed data.
- **Prefer roles over long-lived keys.** Attach a role to compute (instance profile / managed
  identity / service account) so credentials are short-lived and rotate automatically; eliminate
  `AKIA…` user keys where a role fits, and rotate/expire the rest.
- **Guard the escalation permissions.** Treat `iam:PassRole`, `iam:CreatePolicyVersion`,
  `iam:AttachUserPolicy`, `sts:AssumeRole`, `iam:CreateAccessKey` as privileged; grant narrowly and
  with `PassRole` scoped by `iam:PassedToService` conditions.
- **Keep secrets in a secrets manager** (Secrets Manager / Key Vault / Secret Manager), never in env,
  code, or config committed to source; scan repos and CI for leaked keys.
- **Tighten trust policies** to specific principals and add external-ID/condition guards.

</div>

## Detection / blue-team view

<div class="callout defend">

Every API call in AWS lands in **CloudTrail** (Azure Activity Log / Monitor; GCP Cloud Audit Logs).
The signals: `GetCallerIdentity`/`ListPolicies`/`Simulate*` bursts from a new source IP (enumeration);
credential use from an unexpected geography or ASN (a leaked key used off-network); `AssumeRole` and
IAM-mutating calls from principals that never do them. **GuardDuty** (and Azure Defender for Cloud /
GCP Security Command Center) turns several of these into managed findings —
`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` fires when instance-role credentials are
used from outside the instance, and credential-exfil/anomalous-API findings catch stolen keys. Mapped
to **MITRE ATT&CK**: valid cloud accounts is **T1078.004**, unsecured credentials via metadata is
**T1552.005**, and cloud service/account discovery is **T1580 / T1526**. The recurring blue-team idea:
*a credential doing something its identity has never done, from somewhere it has never been.*

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-14-cloud` (built separately) — a **LocalStack-style local AWS API**
(IAM, STS, S3, EC2 describe) bound to `localhost`, wired to the **metadata simulation** carried over
from `lab-07-web`, all on the isolated Docker network. **Access:** one or more sets of synthetic
credentials (a low-priv user, plus keys you'll "find"). **Targets:** the local sim only; all
identities, buckets, and `LAB-FLAG-{uuid}` markers are synthetic. **Time:** ~75 min. **Isolation:**
private network, no Internet route, **no real cloud reachable**; reset per the lab README between
attempts. Point the CLI at the sim with `AWS_ENDPOINT_URL=http://localhost:4566`.

</div>

Set your endpoint to the sim, load the provided synthetic credentials, and run only read-only calls:
identify the principal, read its policies, and list what it can see. Do **not** create, modify, or
delete anything — this lesson's lab is the *scoping* discipline you'll rely on for the rest of M14.

## Exercise

<div class="callout method">

**Situation.** During an authorized cloud engagement (client-owned resources, provider RoE satisfied)
you discover a `.env` file in a code artifact containing an AWS access-key pair. In the lab, this is
modelled by a set of **synthetic** credentials loaded into the sim.

**Objective.** Produce a **blast-radius report** for the leaked credentials: who the identity is, what
it is allowed to do, what it can reach, and — critically — where the *boundary* is between "read to
scope" and "action that changes state or leaves scope." No destructive actions.

**Starting information.** The synthetic credentials and the lab sim endpoint. Nothing about the
identity is given — you must enumerate it.

**Constraints.** Lab sim only. **Read-only** enumeration exclusively — no create/modify/delete, no
assuming roles yet (that is 14.3). Every claim in the report must cite the exact API call and its
response. Treat provider RoE and the shared-responsibility line as if this were real: flag anything
you would *not* be allowed to touch.

**Expected deliverables.**
1. The **principal** (ARN, account) with the `get-caller-identity` evidence.
2. The **effective permission set**, derived from the attached/inline policy JSON you read (quote the
   dangerous statements) and/or `SimulatePrincipalPolicy`.
3. A **blast-radius statement** in client terms: what data/resources are at risk if this credential is
   abused, and the *worst realistic* outcome.
4. A **scoping/RoE note**: which observed capabilities are in scope (client-owned config) vs. which
   would touch provider infrastructure or out-of-scope resources, and where you would stop and ask.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
The credential is not the finding; the <em>identity behind it</em> is. Your first three calls answer
"who am I, what am I allowed, what can I see" — and all three are reads.
</details>

<details><summary>Hint 2 — technique family</summary>
<code>sts get-caller-identity</code> → <code>iam list-attached-user-policies</code> /
<code>list-user-policies</code> → <code>iam get-policy-version</code> to read the JSON. If reading
policies is denied, infer from read-only <code>s3 ls</code> / <code>ec2 describe-*</code> — but count
every probe as a logged call.
</details>

<details><summary>Hint 3 — where to look in the policy</summary>
Wildcards (<code>Action:*</code>, <code>Resource:*</code>) size the blast radius. Then scan for the
escalation verbs — <code>iam:PassRole</code>, <code>sts:AssumeRole</code>,
<code>iam:CreatePolicyVersion</code>, <code>iam:AttachUserPolicy</code>,
<code>iam:CreateAccessKey</code> — and note them as leads for 14.3, without exercising them.
</details>

<details><summary>Hint 4 — the boundary</summary>
Shared responsibility is your scope oracle. Reading your own buckets/config = client-owned = in scope.
Anything that would probe the provider's control plane beyond your account, or touch a resource the
client doesn't own, is out — name it and stop.
</details>

## Check yourself

<div class="callout key">

1. You find an access key. Before doing anything else, which single API call tells you the most, and
   why is it safe to run?
2. A policy has `"Action": "s3:*", "Resource": "*"` and also `"Action": "iam:PassRole", "Resource":
   "arn:…:role/deployer"`. Which line is the bigger *escalation* risk, and why is that not the same as
   the bigger *access* risk?
3. Using the shared-responsibility model: a client asks you to "test whether other AWS customers can
   read our data through a hypervisor bug." What do you tell them, and why?
4. Distinguish an `AKIA…` credential from an `ASIA…` credential. What does the presence of a session
   token tell you about how long you have and where it likely came from?
5. Why is enumerating your *own* permissions (read-only) both the safest and the most informative
   first move, compared with immediately trying actions to see what works?

</div>

Model answers are in `solutions/module-14.md` (try them before looking).

## References

- **AWS IAM** — *IAM User Guide*: identities, policies, policy evaluation logic; **AWS STS** —
  `AssumeRole` and temporary credentials.
- **AWS Shared Responsibility Model** — aws.amazon.com/compliance/shared-responsibility-model.
- **AWS Customer Support Policy for Penetration Testing** — the permitted-services list and
  prohibited activities (read the current version). **Microsoft Cloud Penetration Testing Rules of
  Engagement**; **Google Cloud** security/penetration-testing guidance.
- **Azure** — Managed identities for Azure resources; Entra ID role-based access control.
  **GCP** — Service accounts; IAM roles and bindings; short-lived credentials / impersonation.
- **CIS Benchmarks** — AWS/Azure/GCP Foundations (IAM, key rotation, least privilege controls).
- **MITRE ATT&CK for Cloud** — **T1078.004** Valid Accounts: Cloud Accounts; **T1552.005** Unsecured
  Credentials: Cloud Instance Metadata API; **T1580** Cloud Infrastructure Discovery; **T1526** Cloud
  Service Discovery.
- **CWE** — CWE-269 (Improper Privilege Management), CWE-284 (Improper Access Control), CWE-798
  (Use of Hard-coded Credentials), CWE-522 (Insufficiently Protected Credentials).
- **Rhino Security Labs** — AWS IAM privilege-escalation research (background for 14.3).

## What you should now be able to do

- Use the shared-responsibility model to decide whether a weakness is the client's (in scope) or the
  provider's (never yours to test).
- Read an IAM policy JSON and identify over-permissive wildcards and dangerous escalation grants.
- Explain principals/users/roles/policies and STS/AssumeRole, and map them to Azure and GCP.
- Name credential types and their leak paths, and prioritise "what is the identity" over "let me use
  it."
- Enumerate your own effective permissions non-destructively and write a defensible blast-radius
  report under provider RoE.

## Progress checkpoint

```bash
py course.py complete 14.1
```
