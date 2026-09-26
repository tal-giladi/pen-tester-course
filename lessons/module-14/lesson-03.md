# 14.3 — Cloud identity & privilege escalation: role assumption, policy misconfig & common attack paths (AWS/Azure/GCP)

<div class="prereq">

**Prerequisites:** [14.1 Cloud fundamentals &amp; IAM](lesson-01.md) (principals, policies,
STS/AssumeRole, reading policy JSON), [14.2 Metadata &amp; exposure](lesson-02.md) (you can obtain a
foothold identity), [00.3 threat modeling &amp; the confused deputy](../module-00/lesson-03.md), and
[M10 Credential attacks](../module-10/lesson-01.md).
**Module:** M14 Cloud penetration testing. **Difficulty:** 🔴 advanced.
**You will produce:** a justified, report-ready cloud privilege-escalation path — from a low-priv
synthetic principal in the lab sim to higher privilege — with the exact IAM permission that enables
it, the mechanism, verification, impact, remediation, and detection. No destructive actions.

</div>

## Why this matters

You have a foothold identity — a leaked user (14.1) or a stolen instance role (14.2). The question
that decides the engagement is: **can this identity *become* a more powerful one?** In the cloud,
privilege escalation is not a kernel exploit; it is an **IAM permission that lets you rewrite your own
authority** — attach yourself an admin policy, create a new policy version, pass a powerful role to
compute you control, or assume a role whose trust policy is too generous. These are not bugs in AWS;
they are documented, intended API calls that become escalation when granted to the wrong principal.
Rhino Security Labs catalogued ~20 of these AWS IAM privilege-escalation methods, and the same
*shapes* recur in Azure and GCP. Recognising them turns "I have a low-priv key" into "I have the
account," which is exactly the finding a client needs to hear — and exactly the finding a scanner
rarely produces, because it requires reasoning about what a permission *enables*, not just what it
*is*.

## Learning objectives

- Explain cloud privilege escalation as **identity transformation** via IAM, not memory corruption.
- Recognise the dangerous permissions — `iam:PassRole` (+ a compute-launch action),
  `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`/`AttachRolePolicy`, `iam:PutUserPolicy`,
  `iam:CreateAccessKey`, `sts:AssumeRole` — and *why* each escalates.
- Read a **trust policy** and spot an over-broad `Principal` or a missing/weak condition.
- Trace **role-assumption** and **cross-account** escalation paths.
- Map the AWS paths to their **Azure** and **GCP** equivalents so the reasoning transfers.
- Find and justify a privesc path against the lab sim non-destructively, and write it up with
  remediation and detection.

## Intuition

Come back to 14.1's picture: the account is a **graph of identities**, and each edge is "identity A
can, via some permission, gain identity B's power." A privilege-escalation path is a route through
that graph from where you are to somewhere stronger. Some edges are *direct* ("I can attach myself the
admin policy" — one hop to god). Some are *indirect* ("I can pass this powerful role to an EC2
instance, then run code on that instance as the role"). Some are *transitive* ("I can assume role X,
which can assume role Y, which is admin"). The BloodHound intuition from Active Directory (M06) is
exactly right here: **find the shortest path to Tier-0.** The permissions below are the edge types.
Your job is to enumerate your edges (14.1's read-only method) and find one that leads up.

## The underlying technology — dangerous permissions and why each escalates

<div class="callout attack">

**`iam:AttachUserPolicy` / `AttachRolePolicy` / `PutUserPolicy` — attach yourself power.** If you can
attach a managed policy to your own user (or put an inline policy on it), attach
`arn:aws:iam::aws:policy/AdministratorAccess`:

```bash
aws iam attach-user-policy --user-name me \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

Why it escalates: the permission to *modify who has permissions* is administrative by nature. One call
turns a scoped user into an admin. `PutUserPolicy` is the inline-policy variant with the same effect.

</div>

<div class="callout attack">

**`iam:CreatePolicyVersion` — rewrite a policy you're attached to.** IAM managed policies keep
versions. If you can create a new *default* version of a policy attached to you, you rewrite your own
grant to `"Action":"*","Resource":"*"`:

```bash
aws iam create-policy-version --policy-arn <policy-attached-to-me> \
  --policy-document file://admin.json --set-as-default
```

Why it escalates: `CreatePolicyVersion` with `--set-as-default` changes what the policy *says* without
needing `AttachUserPolicy`. The account trusted you to version a policy; versioning it to admin is the
abuse. (`SetDefaultPolicyVersion` on an existing broad version is the sibling.)

</div>

<div class="callout attack">

**`iam:PassRole` + a compute-launch action — pass power to a machine you control.** `PassRole` alone
does nothing; combined with the ability to *launch or update compute that assumes a role*, it is the
classic path:

```bash
# Launch an instance with a powerful role's instance profile, then read its metadata creds (14.2):
aws ec2 run-instances --iam-instance-profile Name=powerful-role --image-id … --instance-type …
# or a Lambda/Glue/CloudFormation that runs your code AS the passed role.
```

Why it escalates: you cannot use `powerful-role` directly, but you can *give it to a resource you
control* and then act through that resource. This is the **confused deputy** again — the compute
service dutifully runs as the role you passed it. It also pairs with `lambda:CreateFunction`+`InvokeFunction`,
`glue:CreateDevEndpoint`, `datapipeline`, `cloudformation`, and more — any service that "runs as a
role you specify."

</div>

<div class="callout attack">

**`sts:AssumeRole` + an over-broad trust policy — walk in the open door.** A role's *trust policy*
decides who may assume it. If it names too broad a principal, any of those principals gets the role's
power:

```json
{ "Effect": "Allow",
  "Principal": { "AWS": "*" },                       // ← anyone in ANY account
  "Action": "sts:AssumeRole" }
```

```bash
aws sts assume-role --role-arn arn:aws:iam::…:role/too-trusting --role-session-name x
# → temporary credentials for that role
```

Why it escalates: trust is the *only* gate on assumption. `"AWS":"*"`, an entire account as principal,
or a missing external-ID condition on a third-party role lets a principal assume power it was never
meant to have — including **cross-account** (a role in the target account trusting *your* account).

</div>

<div class="callout attack">

**`iam:CreateAccessKey` / `CreateLoginProfile` / `UpdateLoginProfile` — key another identity.** If you
can create access keys for *another* user (or set a console password on one), you take over that
(possibly more-privileged) user:

```bash
aws iam create-access-key --user-name higher-priv-user   # now you have THEIR keys
```

Why it escalates: minting a credential for a stronger identity is lateral-to-up movement inside IAM —
you don't change your policy, you *become someone else*. Persistence, too (a second key is a backdoor).

</div>

### The AWS → Azure → GCP mapping <span class="badge current">CURRENT</span>

The permissions differ; the *shapes* are identical:

| Escalation shape | AWS | Azure | GCP |
|---|---|---|---|
| Grant yourself power | `iam:AttachUserPolicy` / `CreatePolicyVersion` | **`Microsoft.Authorization/roleAssignments/write`** (esp. holding `Owner`/`User Access Administrator`) | `setIamPolicy` on a resource/project (e.g. `resourcemanager.projects.setIamPolicy`) |
| Pass power to compute | `iam:PassRole` + `ec2:RunInstances`/`lambda:*` | assign a **managed identity** to a VM/Function you control | **`iam.serviceAccounts.actAs`** + deploy a GCE/Cloud Function/Cloud Run |
| Become another identity | `sts:AssumeRole` (trust policy) | managed-identity token via IMDS (14.2) | **`iam.serviceAccounts.getAccessToken`** / `signJwt` / `implicitDelegation` |
| Key another identity | `iam:CreateAccessKey` | reset/attach app **client secret** / add credential to a service principal | `iam.serviceAccountKeys.create` |

The GCP `actAs` + deploy path is the direct analogue of AWS `PassRole` + launch; Azure's dangerous role
is `User Access Administrator`/`Owner` (they can grant roles, i.e. escalate). Learn the shape once and
you can find the path in any of the three.

## Why the weakness exists

IAM gives administrators fine-grained control, and these permissions exist for legitimate automation:
CI needs `PassRole` to deploy; an ops tool needs `AttachRolePolicy`; a federation setup needs a trust
policy. The failure is granting an *administrative* permission (one that alters authority) to a
principal that should only *use* resources, without recognising that "can modify permissions" ≈
"admin." It is CWE-269 (improper privilege management) and CWE-266/267 (excess/privilege escalation)
at cloud scale, compounded by the fact that these grants look innocuous in a policy — `iam:PassRole`
reads like plumbing, not like a skeleton key. The provider's model is sound; the *assignment* is where
it breaks.

## How a tester recognizes it

- Any of the dangerous verbs above in *your* effective permissions (14.1's read-only enumeration) —
  especially `iam:PassRole`, `CreatePolicyVersion`, `Attach*Policy`, `Put*Policy`, `AssumeRole`,
  `CreateAccessKey`.
- Roles whose **trust policy** names `"AWS":"*"`, an entire account, or a third-party account without
  an `ExternalId`/condition.
- A principal with `iam:PassRole` **and** any compute-launch permission (the pairing is the path).
- On Azure: principals holding `Owner`/`User Access Administrator`. On GCP:
  `iam.serviceAccounts.actAs`, `getAccessToken`, `serviceAccountKeys.create`, or `*.setIamPolicy`.

## Manual investigation

<div class="callout method">

**Enumerate edges, then find the shortest safe path — and prove it without walking it destructively.**
From 14.1, read your effective permissions and list every dangerous verb you hold and every role's
trust policy you can read. For each candidate edge, reason: *what does this let me become, and is the
target more privileged?* Prefer `iam:SimulatePrincipalPolicy` to *confirm* you're allowed the
escalating call **without making it**, and read the target role's permissions to confirm it's actually
higher. In a real engagement you demonstrate the path with the **minimum** action needed to prove it
(e.g. assume a role and `get-caller-identity`, then stop) and you **never** attach `AdministratorAccess`
to a production identity or create durable backdoor keys just to "prove" it — describe those steps,
don't detonate them. In the lab, you may complete the path against synthetic identities to see it
work, then reset.

</div>

## Tooling — what it does, key options, limits, verify by hand

- **AWS CLI (lab endpoint)** — enumerate (`iam list-*`, `get-policy-version`,
  `get-role`/`assume-role`) and, in the lab, execute the path. *Limit:* the escalating verbs *change
  state* — in a real account you use them only as far as the RoE allows and prefer `simulate` to
  confirm.
- **`iam:SimulatePrincipalPolicy`** — asks "can principal P do action A on resource R?" without doing
  A. The safest way to confirm an escalation edge exists. *Limit:* it evaluates policy, not
  runtime/service-linked nuances; confirm the actual path where the RoE permits.
- **Pacu** (concept, Rhino Security Labs) — its `iam__privesc_scan` enumerates your permissions and
  reports which of the known escalation methods you can perform. *Limit:* it *acts* — several modules
  execute the escalation — so it is for authorized, in-scope use only; here you reason with the CLI and
  the method list. **Verify every reported path by reading the underlying permission and trust policy
  yourself.**
- **CloudMapper / PMapper** (concept) — build and query the IAM graph ("who can reach admin"),
  BloodHound-style. *Limit:* model quality depends on the data pulled; treat paths as hypotheses to
  verify.

## Demonstration (LAB ONLY — local simulation)

<div class="callout attack" data-badge="current">

**A `PassRole` escalation, against the lab sim.** Your foothold user `ci-deploy` (from 14.1/14.2) has,
per its policy, `iam:PassRole` on `admin-exec` **and** `ec2:RunInstances`. Neither alone is admin;
together they are the path:

```bash
export AWS_ENDPOINT_URL=http://localhost:4566        # lab sim
# 1) Confirm the edge WITHOUT escalating:
aws iam get-policy-version --policy-arn <ci-deploy-policy> --version-id <v>   # shows PassRole+RunInstances
aws iam get-role --role-name admin-exec                                      # confirm target is powerful
# 2) In the lab, complete the path against synthetic resources:
aws ec2 run-instances --iam-instance-profile Name=admin-exec \
  --image-id ami-lab --instance-type t.lab --count 1
# 3) Read the launched instance's role creds from the metadata sim (14.2 method) -> act as admin-exec.
```

Why it works: `ci-deploy` can't call admin APIs, but it can *pass* `admin-exec` to a machine and then
harvest that machine's credentials (14.2) — inheriting a power it was never directly granted. The
confused deputy, now inside IAM.

</div>

<div class="callout attack" data-badge="current">

**A trust-policy / AssumeRole escalation, against the lab sim.** A lab role `reporting` has a trust
policy naming `"AWS":"*"` (or the whole account). Any principal — including your low-priv one — can
assume it:

```bash
aws sts assume-role --role-arn arn:aws:iam::000000000000:role/reporting \
  --role-session-name lab   # -> synthetic temporary creds for 'reporting'
# load them, then:
aws sts get-caller-identity  # -> assumed-role/reporting/lab  ← you are now 'reporting'
```

Why it works: the trust policy is the *only* gate on assumption, and it was left open. If `reporting`
can itself assume something higher, you chain (transitive edge). Prove the hop with
`get-caller-identity`, read `reporting`'s permissions, and stop.

</div>

<div class="callout legal" data-badge="current">

**LAB TARGET vs REAL SYSTEM.** Every call targets `labs/lab-14-cloud` on the isolated network against
**synthetic** identities (`ci-deploy`, `admin-exec`, `reporting`) and `LAB-FLAG-{uuid}` markers. On a
real engagement, these escalating calls **change the client's account** (a new admin attachment, a
launched instance, a new key) — perform them only within the client's written authorization *and* the
provider's RoE (14.1), demonstrate with the minimum proof, avoid durable backdoors, and clean up
(remove attachments/keys/instances) exactly as you'd clean up a dropped SUID binary on Linux (04.2).
Attaching admin to a live identity or minting backdoor keys "to prove it" is destructive and
out-of-bounds without explicit sign-off.

</div>

## Verification

An escalation is verified when you demonstrate you **hold the higher privilege**, with evidence:
`sts:get-caller-identity` returning the *new* identity (`assumed-role/reporting/…` or the admin-exec
role), plus one read that the old identity could not do (e.g. an API call that was previously denied
now succeeds). Capture the enabling permission (the policy/trust JSON), the escalating call, and the
before/after identity. "I could have escalated" is a weaker finding than "I did, here is the new
`get-caller-identity`, and I then stopped and cleaned up."

## Impact

<div class="callout key">

A working privesc path usually means **full account compromise**: admin can read all data, alter or
delete resources, create persistent backdoor identities, disable logging (CloudTrail), and pivot to
connected accounts (cross-account trust) or on-prem (federation). Framed for the client: *"a single
low-privileged CI credential can reach `AdministratorAccess` in one `PassRole` step, so the blast
radius of that credential is the entire account, not one deploy pipeline."* That sentence — the low-
priv-to-total-control gap — is the headline of most cloud reports. It also compounds the earlier
findings: the SSRF of 14.2 that stole a role becomes catastrophic if that role has an escalation edge.

</div>

## Remediation

<div class="callout defend">

- **Least privilege on the *administrative* permissions.** Treat `iam:PassRole`, `CreatePolicyVersion`,
  `SetDefaultPolicyVersion`, `Attach*Policy`, `Put*Policy`, `CreateAccessKey`, `Create/UpdateLoginProfile`,
  and `sts:AssumeRole` as privileged. Grant them narrowly, to few principals, with conditions.
- **Scope `PassRole`.** Restrict which roles can be passed and to which services with
  `iam:PassedToService` and specific role-ARN resources; never `PassRole` on `*`.
- **Tighten trust policies.** Name specific principals, require `ExternalId` on third-party roles, add
  `aws:PrincipalOrgID`/source conditions; never `"Principal":"*"` or a bare account for a sensitive
  role.
- **Detect the pairing.** Alert on any principal that holds both `PassRole` and a compute-launch
  action, or `CreatePolicyVersion` on a policy attached to itself — use Access Analyzer and IAM
  last-accessed to prune.
- **Azure/GCP:** restrict `Owner`/`User Access Administrator` and `roleAssignments/write`; restrict
  `iam.serviceAccounts.actAs`/`getAccessToken`/`serviceAccountKeys.create` and `*.setIamPolicy`; prefer
  short-lived impersonation over SA keys.

</div>

## Detection / blue-team view

<div class="callout defend">

- **CloudTrail** is the source of truth: alert on `AttachUserPolicy`/`PutUserPolicy` attaching broad
  policies, `CreatePolicyVersion`+`SetDefaultPolicyVersion`, `CreateAccessKey` for another user,
  `AssumeRole` to sensitive roles from unusual principals, and `RunInstances`/`CreateFunction` with a
  powerful `iam-instance-profile`/role by a principal that doesn't normally deploy.
- **GuardDuty / Security Hub** surface anomalous IAM behaviour and policy-widening; **Access Analyzer**
  flags roles trusting external principals and public/cross-account access.
- **Azure/GCP:** Activity/Audit logs for `roleAssignments/write`, `setIamPolicy`,
  `serviceAccountKeys.create`, and token/impersonation events; Defender for Cloud / Security Command
  Center findings.

Mapped to **MITRE ATT&CK**: privilege escalation via cloud accounts and additional cloud credentials —
**T1078.004** (Valid Accounts: Cloud), **T1098.001/.003** (Account Manipulation: Additional Cloud
Credentials / Roles), and **T1548** (Abuse Elevation Control Mechanism) at the cloud layer. The
recurring blue-team idea: *a principal changing IAM — its own or others' authority — is rarely
routine; watch the permission-changing calls, not just the data calls.*

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-14-cloud` (built separately) — the LocalStack-style local AWS API (IAM,
STS, EC2, S3) on the isolated network, seeded with a low-priv `ci-deploy` principal, an `admin-exec`
role reachable via `PassRole`+`RunInstances`, and a `reporting` role with an over-broad trust policy.
**Access:** the synthetic `ci-deploy` credentials (or a stolen role from 14.2). **Targets:** the sim
only; all identities and `LAB-FLAG-{uuid}` markers synthetic. **Time:** ~120 min. **Isolation:**
private network, no Internet route, **no real cloud reachable**; reset per the lab README (escalation
changes sim state — reset between attempts). Point the CLI at the sim with
`AWS_ENDPOINT_URL=http://localhost:4566`.

</div>

From the low-priv principal, enumerate your permissions (14.1), find at least one escalation edge
(`PassRole`+launch, `AssumeRole` on an over-trusting role, or a policy-modification verb), confirm it
with `SimulatePrincipalPolicy` and by reading the target's permissions, then complete it against the
synthetic identities and verify with `get-caller-identity`. Reset, and try a *different* edge type.

## Exercise

<div class="callout method">

**Situation.** Authorized cloud engagement (client-owned account, provider RoE satisfied). You hold a
low-privileged synthetic principal in the lab sim (a "found" CI key, or a role stolen via 14.2). The
client asks: *"if one of our CI credentials leaked, how far could an attacker get?"*

**Objective.** Find, **justify**, and **verify** one privilege-escalation path from the low-priv
principal to higher privilege, and write it up **report-ready** — the enabling permission, the
mechanism, verification evidence, impact in client terms, remediation, and detection.

**Starting information.** The low-priv credentials and the sim endpoint. No pre-built path.

**Constraints.** Lab sim only; synthetic identities only. You must explain the **mechanism** (which
permission, why it transforms your identity, whose privilege you inherit) — not just paste a command.
Demonstrate with the **minimum** proof; do **not** create durable backdoors (extra keys) or attach
admin to anything you wouldn't clean up, and note the cleanup. Confirm the edge with
`SimulatePrincipalPolicy` before executing where you can.

**Expected deliverables.**
1. The **enabling permission** (quote the policy/trust JSON) and the **escalation shape** it belongs
   to (`PassRole`+launch / `CreatePolicyVersion` / `Attach*Policy` / `AssumeRole`+trust / `CreateAccessKey`).
2. The **mechanism**: why this permission lets a scoped identity become a stronger one (state the
   confused-deputy or identity-transformation reasoning explicitly).
3. **Verification evidence**: before/after `get-caller-identity`, plus one call that only the escalated
   identity can make.
4. **Impact** in client terms (the low-priv-to-total-control gap and its blast radius).
5. **Remediation** *and* **detection** (specific IAM changes + the CloudTrail/GuardDuty signal, mapped
   to ATT&CK) — both required. Note any cleanup you performed.
6. The **Azure or GCP equivalent** of your chosen path, in one or two sentences, to show the reasoning
   transfers.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
You are looking for an <em>edge</em> in the identity graph that goes up. Re-run 14.1's read-only
enumeration and list every dangerous verb you hold and every trust policy you can read.
</details>

<details><summary>Hint 2 — which edge</summary>
Do you hold <code>iam:PassRole</code> plus a way to launch/run something (EC2/Lambda)? A policy-
modification verb (<code>CreatePolicyVersion</code>, <code>Attach*Policy</code>,
<code>Put*Policy</code>) on a policy you're attached to? Or does a role's trust policy name
<code>"AWS":"*"</code>/your account, so <code>AssumeRole</code> just works?
</details>

<details><summary>Hint 3 — confirm before you fire</summary>
Use <code>iam:SimulatePrincipalPolicy</code> to confirm you're allowed the escalating call, and read
the <em>target</em> role/policy's permissions to confirm it's actually higher, before you execute.
That's the safe, professional order.
</details>

<details><summary>Hint 4 — prove minimally, then stop</summary>
For <code>AssumeRole</code>: assume, <code>get-caller-identity</code>, read the new role's power, stop.
For <code>PassRole</code>: launch with the powerful instance profile, read its metadata creds (14.2),
show the new identity. Do <em>not</em> attach admin to a live user or mint backdoor keys to "prove"
it — describe that as the impact and clean up what you did create.
</details>

## Check yourself

<div class="callout key">

1. Why is `iam:PassRole` useless to an attacker on its own, and what is the *one* extra permission
   class that turns it into full escalation?
2. `iam:CreatePolicyVersion` and `iam:AttachUserPolicy` both make you admin. Mechanically, how do they
   differ in *what they change* to get there?
3. A role's trust policy says `"Principal": {"AWS": "*"}`. Why is that a complete privilege-escalation
   finding by itself, independent of any other permission you hold?
4. Explain a cloud `PassRole`+`RunInstances` escalation as a confused deputy: who is the deputy, whose
   privilege do you borrow, and why does the service comply?
5. Give the GCP equivalent of AWS `iam:PassRole` + `ec2:RunInstances`, and the Azure equivalent of
   "attach yourself an admin role." Why does learning the *shape* matter more than the permission
   names?

</div>

Model answers are in `solutions/module-14.md` (try them before looking).

## References

- **Rhino Security Labs** — *"AWS IAM Privilege Escalation – Methods and Mitigation"* (the ~20-method
  catalogue: `CreatePolicyVersion`, `PassRole`+services, `AttachUserPolicy`, `CreateAccessKey`, etc.)
  and the **Pacu** framework (`iam__privesc_scan`).
- **AWS IAM** — `PassRole` and `iam:PassedToService`; policy versions; **STS `AssumeRole`** and role
  **trust policies**; the **confused-deputy** guidance and `ExternalId`.
- **PMapper / CloudMapper** — IAM-graph privilege-escalation analysis.
- **Azure** — Azure RBAC, `Owner`/`User Access Administrator`, `roleAssignments/write`; **GCP** —
  `iam.serviceAccounts.actAs`/`getAccessToken`, `serviceAccountKeys.create`, `setIamPolicy`, and IAM
  privilege-escalation research (e.g. Rhino/others on GCP).
- **CIS AWS/Azure/GCP Foundations Benchmarks** — IAM least-privilege and monitoring controls.
- **MITRE ATT&CK** — **T1078.004** Valid Accounts: Cloud; **T1098.001/.003** Account Manipulation
  (Additional Cloud Credentials / Roles); **T1548** Abuse Elevation Control Mechanism; **T1580** Cloud
  Infrastructure Discovery.
- **CWE** — CWE-269 (Improper Privilege Management), CWE-266/CWE-267 (privilege issues), CWE-284
  (Improper Access Control), CWE-441 (confused deputy).

## What you should now be able to do

- Explain cloud privesc as identity transformation via IAM, and name the dangerous permissions and
  *why* each escalates.
- Read a trust policy and spot an over-broad principal or missing condition.
- Enumerate your IAM edges, confirm an escalation path with `SimulatePrincipalPolicy`, and demonstrate
  it minimally against the lab sim with before/after evidence.
- Map any AWS path to its Azure and GCP equivalent.
- Write a report-ready privesc finding with impact, remediation, and ATT&CK-mapped detection — and
  clean up what you created.

## Progress checkpoint

```bash
py course.py complete 14.3
```
