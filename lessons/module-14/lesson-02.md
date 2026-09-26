# 14.2 — Metadata, storage & network exposure: SSRF-to-cloud, IMDSv1/v2, public buckets & security groups

<div class="prereq">

**Prerequisites:** [14.1 Cloud fundamentals &amp; IAM](lesson-01.md) (you must know what an instance
role and a temporary credential are), [07.4 SSRF &amp; the metadata simulation](../module-07/lesson-04.md)
(you already reached the lab metadata endpoint as a confused deputy), [00.3 the confused deputy](../module-00/lesson-03.md),
and [M10 Credential attacks](../module-10/lesson-01.md).
**Module:** M14 Cloud penetration testing. **Difficulty:** 🔴 advanced.
**You will produce:** a demonstrated SSRF-to-cloud-credential chain against the lab simulation —
metadata theft, the identity behind the stolen token, the impact, and the **IMDSv2** remediation —
plus one storage-exposure and one network-exposure finding.

</div>

## Why this matters

This is the lesson where the web bug you learned in Module 07 becomes a **cloud account
compromise**. The single most common high-impact cloud attack path in real engagements is not exotic:
a server-side request forgery in an application reaches the instance metadata service, the metadata
service hands back the instance role's temporary credentials, and the attacker walks in as that role.
The 2019 Capital One breach — over 100 million records — was exactly this chain: an SSRF, IMDSv1
metadata, an over-privileged role, and a readable S3 bucket. Alongside metadata, the other two "front
doors" of cloud are **storage left public** (buckets/blobs/objects readable by the world) and
**network rules left open** (security groups exposing admin ports to `0.0.0.0/0`). All three are
customer-side (14.1's scope oracle), all three are found constantly, and all three have clean, known
fixes you must be able to write.

## Learning objectives

- Explain the instance **metadata service** and the concrete difference between **IMDSv1** and
  **IMDSv2** — why v2's session token and hop limit blunt SSRF — and map it to Azure IMDS and GCP
  metadata.
- Chain an application SSRF to **instance-role credential theft** against the lab metadata sim, and
  use the stolen token.
- Recognise **public storage** exposure (S3/Blob/GCS) and enumerate it non-destructively.
- Read a **security group / NSG** and spot dangerous ingress (`0.0.0.0/0` to admin ports).
- State the detection story (CloudTrail/GuardDuty/flow logs) and the remediation for each.

## Intuition

A cloud instance needs to know things about itself — its role's credentials, its region, its
user-data script. The provider delivers those over a **magic link-local address, `169.254.169.254`**,
reachable only from *inside* the instance, with **no authentication**, because "being on the instance"
was treated as proof enough. That assumption is the whole vulnerability: any code that can make the
instance issue an HTTP request *from itself* — an SSRF, a misused URL fetcher, a compromised
process — can ask the metadata service for the role's credentials, and the service, seeing a request
"from inside," answers. The confused deputy from 00.3 and 07.4 is now pointed at the crown jewels: the
deputy (the server) has an identity the attacker doesn't, and metadata hands that identity out to
anyone who can make the deputy ask.

## The underlying technology

### The instance metadata service, IMDSv1 vs IMDSv2 <span class="badge current">CURRENT</span>

**IMDSv1** is a plain, unauthenticated **GET**. Any request that reaches the endpoint gets an answer:

```http
GET /latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: 169.254.169.254
→ app-instance-role

GET /latest/meta-data/iam/security-credentials/app-instance-role HTTP/1.1
Host: 169.254.169.254
→ { "AccessKeyId":"ASIA…", "SecretAccessKey":"…", "Token":"…", "Expiration":"…" }
```

An SSRF that can make the server GET a URL is enough — one request, credentials returned. That is the
entire IMDSv1 problem.

**IMDSv2** makes it a **session-oriented, two-step** protocol. You first `PUT` to obtain a token,
supplying a required header, and only then may you `GET` with that token:

```http
PUT /latest/api/token HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token-ttl-seconds: 21600
→ <session-token>

GET /latest/meta-data/iam/security-credentials/app-instance-role HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token: <session-token>
→ { credentials… }
```

Two properties defeat typical SSRF:

1. **A `PUT` with a custom header is required.** Most SSRF primitives can only make the server issue a
   simple **GET** and cannot control request headers, so they cannot obtain the token, and without the
   token the `GET` is refused.
2. **A default IP hop limit of 1** on the response's TTL means the metadata reply won't route beyond
   the instance — so an SSRF that tries to *proxy* metadata through a container or a downstream hop is
   further constrained.

IMDSv2 does not make metadata *unreachable* by legitimate on-host code; it raises the bar so that the
weak, GET-only SSRF — the common case — can no longer reach credentials. It is a *mitigation of the
SSRF class*, not a fix for a process already running on the box.

Azure and GCP have the same shape, and the reasoning transfers:

| | AWS | Azure | GCP |
|---|---|---|---|
| Endpoint | `169.254.169.254/latest/meta-data/` | `169.254.169.254/metadata/instance` | `metadata.google.internal/computeMetadata/v1/` |
| Anti-SSRF guard | IMDSv2 token + hop limit | **required `Metadata: true` header** | **required `Metadata-Flavor: Google` header** |
| Credential path | `…/iam/security-credentials/<role>` | `…/identity/oauth2/token?resource=…` | `…/instance/service-accounts/default/token` |

Azure and GCP have *always* required a non-standard request header, which is why a naive GET-only SSRF
often fails against them and succeeds against IMDSv1 — the header requirement is the same idea IMDSv2
retrofitted onto AWS.

### Storage exposure <span class="badge current">CURRENT</span>

Object storage (S3 buckets, Azure Blob containers, GCS buckets) is private by default now, but
misconfiguration — a public bucket policy, a `public-read` ACL, "allow public access" left on, or a
bucket used as a static site — exposes objects to the world. The tester's tells: a bucket that lists
its objects to an anonymous request, an object readable without credentials, or a predictable bucket
name (`companyname-backups`) that resolves. Exposure ranges from an embarrassing public asset to a
full data breach when the "bucket" holds database dumps, secrets, or PII.

### Network exposure — security groups and NSGs <span class="badge current">CURRENT</span>

A **security group** (AWS) or **network security group** (Azure) is a stateful virtual firewall on an
instance/subnet. The classic finding is an ingress rule allowing a sensitive port from the whole
Internet:

```text
SG: sg-app     Inbound rules
  22/tcp   (SSH)   source 0.0.0.0/0     ← the entire Internet can reach SSH
  3389/tcp (RDP)   source 0.0.0.0/0     ← and RDP
  5432/tcp (Postgres) source 0.0.0.0/0  ← a database exposed to the world
  443/tcp  (HTTPS) source 0.0.0.0/0     ← this one is probably intended
```

The management and database ports open to `0.0.0.0/0` are the findings; `443` from anywhere is likely
by design. The weakness is the same everywhere: an over-broad source range on a port that should be
restricted to a bastion, a VPN, or a peered range.

## Why the weakness exists

Metadata was designed for a single-tenant, trusted-process world; the unauthenticated link-local
endpoint assumed "code on the instance is the instance's code," which SSRF violates (CWE-918 in the
app; CWE-441 confused deputy; the metadata exposure itself is the reason IMDSv2 exists). Public
storage happens because sharing is one toggle away and "public" is easy to reach for when a link needs
to work (CWE-732, incorrect permission assignment; CWE-284). Open security groups happen because
`0.0.0.0/0` is what you type to "make it work" during setup and nobody narrows it later (CWE-284). All
three are least-privilege failures on the customer side of the responsibility line.

## How a tester recognizes it

- **SSRF-to-metadata:** any SSRF or URL-fetch primitive (14.1/07.4) plus a cloud instance — try the
  metadata path (against the lab sim). A successful IMDSv1-style GET returning a role name is the tell;
  a failure that wants a token header suggests IMDSv2 (or Azure/GCP header enforcement).
- **Public storage:** an anonymous `ListObjects`/`GET` that succeeds; a bucket named in HTML/JS or DNS;
  `aws s3 ls s3://bucket --no-sign-request` returning contents.
- **Network exposure:** a security-group `describe` showing `0.0.0.0/0` (or `::/0`) on 22/3389/3306/
  5432/6379/etc.; an instance with a public IP and such a group attached.

## Manual investigation

<div class="callout method">

**Confirm the primitive, then follow it inward.** For SSRF-to-cloud, first confirm the app fetches a
URL you control (an internal lab listener) exactly as in 07.4 — *the fetch happens* — before you point
it at the metadata path; then, if you retrieve a role name, retrieve the credential blob, and only
then load it as a profile and re-run 14.1's `get-caller-identity` to learn the *identity* you just
stole. For storage, try an **unauthenticated** list/get first (`--no-sign-request`) — that proves
*public* exposure, which is a different and worse finding than access with your own credentials. For
network, read the security groups with `describe-security-groups` and reason about each rule's source
range against the port's purpose. In every case: confirm reachability minimally, then characterise
impact — never fire a weaponised or destructive action to "prove" it.

</div>

## Tooling — what it does, key options, limits, verify by hand

- **AWS CLI (lab endpoint)** — retrieve metadata via the app SSRF, load the stolen token as a profile,
  and run `describe-security-groups`, `s3 ls`. *Limit:* the stolen token is time-limited (it expires);
  it does exactly what its role allows.
- **`curl` (through the SSRF)** — the honest way to see the raw metadata request/response and prove
  IMDSv1 vs v2 behaviour. *Limit:* you're driving it through the app, so you see what the app returns.
- **ScoutSuite / Prowler** (concept, from 14.1) — flag public buckets and open security groups across
  the account in one pass. *Limit:* read-only, point-in-time; verify each flag with a direct
  unauthenticated `s3 ls`/`describe` before reporting.
- **`s3 ls --no-sign-request`** — the one-command test for *anonymous* bucket access; a positive is a
  clean public-exposure proof. *Limit:* absence isn't proof of privacy (the name may be wrong, or
  listing may be denied while objects are gettable).

## Demonstration (LAB ONLY — local simulation)

<div class="callout attack" data-badge="current">

**SSRF → instance-role credential theft (the Capital One shape), against the lab sim.** The lab app's
"import from URL" SSRF (from 07.4) reaches the lab metadata simulation. Walk the IMDSv1-style path:

```text
# through the app's SSRF parameter, against the LAB metadata sim only:
url=http://169.254.169.254.lab/latest/meta-data/iam/security-credentials/
      → app-instance-role
url=http://169.254.169.254.lab/latest/meta-data/iam/security-credentials/app-instance-role
      → { "AccessKeyId":"ASIA_LAB_…", "SecretAccessKey":"…", "Token":"…" }   (synthetic)
```

Now load the stolen *synthetic* token and learn whose identity you took:

```bash
export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_ACCESS_KEY_ID=ASIA_LAB_…
export AWS_SECRET_ACCESS_KEY=<lab-synthetic>
export AWS_SESSION_TOKEN=<lab-synthetic>          # temporary creds REQUIRE the session token
aws sts get-caller-identity     # -> assumed-role/app-instance-role/…  ← you are now the role
aws s3 ls                       # what the role can read (14.1 blast-radius method)
```

Why it works: the SSRF makes the *server* issue the metadata GET; the metadata service answers any
request "from the instance"; because it is **IMDSv1-style** (a plain GET, no token), one forged GET is
enough. You have borrowed the instance's identity — the confused deputy, escalated to the cloud.

</div>

<div class="callout defend" data-badge="current">

**Why IMDSv2 would have blocked this.** The same GET-only SSRF cannot obtain an IMDSv2 session token,
because that requires a **`PUT` with the `X-aws-ec2-metadata-token-ttl-seconds` header** — a request
shape a typical SSRF cannot produce — and without the token the credential `GET` is refused. Enforcing
IMDSv2 (`HttpTokens: required`) and a hop limit of 1 turns this account-takeover chain into a dead
end for the common SSRF. Show this in the finding: *"the same SSRF against an IMDSv2-only instance
returns 401 on the credential GET."*

</div>

<div class="callout attack" data-badge="current">

**Public storage and open security group, against the lab sim.**

```bash
# Anonymous bucket access — proves PUBLIC exposure (no credentials used):
aws --endpoint-url http://localhost:4566 s3 ls s3://lab-public-bucket --no-sign-request
  → 2026-01-01  data/  export-LAB-FLAG-<uuid>.txt        (world-readable)

# Over-permissive ingress:
aws --endpoint-url http://localhost:4566 ec2 describe-security-groups
  → sg-app: 22/tcp from 0.0.0.0/0, 5432/tcp from 0.0.0.0/0   (Internet-exposed SSH + DB)
```

The `--no-sign-request` list succeeding is unambiguous proof the bucket is public; the
`describe-security-groups` output is the network finding. Both are reads.

</div>

<div class="callout legal" data-badge="current">

**LAB TARGET vs REAL SYSTEM.** Every request above targets `labs/lab-14-cloud` and the lab metadata
simulation on the isolated network; the credentials are **synthetic** `ASIA_LAB_…`/`LAB-FLAG-{uuid}`
markers that authenticate to nothing real. Touching real cloud metadata at `169.254.169.254`,
probing a real tenant's buckets, or scanning real security groups requires **both** the client's
written authorization for *their own* resources **and** compliance with the provider's penetration-
testing policy (14.1). The metadata endpoint on a real instance is off-limits without that
authorization — it is the single most sensitive URL in the account.

</div>

## Verification

Metadata theft is verified when the stolen token *authenticates as a different, more-privileged
identity*: `get-caller-identity` returns `assumed-role/app-instance-role/…`, not your original user —
capture the SSRF request, the metadata response, and the `get-caller-identity` output together.
Storage exposure is verified by the **unauthenticated** `s3 ls`/`GET` succeeding (credentials-free is
the point). Network exposure is verified by the `describe-security-groups` output showing the specific
port and `0.0.0.0/0` source. In all three, the API response *is* the evidence.

## Impact

<div class="callout key">

- **SSRF-to-metadata** → theft of the instance role's temporary credentials → the attacker acts as
  that role. If the role is over-privileged (it usually is), this is **cloud account compromise** from
  a single web bug — recon of the whole account, data access, and often the pivot to privilege
  escalation (14.3). This is the Capital One pattern.
- **Public storage** → data breach proportional to the bucket's contents: from a public asset (minor)
  to full PII/secret/backup exposure (critical), with no authentication required to exploit.
- **Open security groups** → direct Internet reach to admin/database services → brute force,
  known-CVE exploitation, or direct unauthenticated access, bypassing the "it's internal" assumption.

</div>

## Remediation

<div class="callout defend">

- **Metadata:** enforce **IMDSv2 only** (`HttpTokens: required`) on every instance and set the
  metadata **hop limit to 1**; disable IMDS entirely where the workload needs no role. On Azure/GCP,
  rely on the required metadata header and restrict which processes reach the endpoint. And fix the
  **SSRF** at the app layer (14.1/07.4: allowlist hosts/schemes, block link-local after DNS
  resolution). Defence in depth: IMDSv2 *and* SSRF hardening *and* least-privilege instance roles, so
  a stolen token is worth little.
- **Storage:** enable account-level **Block Public Access** (S3) / disallow anonymous access (Blob/
  GCS); use bucket policies scoped to specific principals; never `public-read` for private data; scan
  continuously for public buckets.
- **Network:** restrict ingress to specific source ranges (bastion/VPN/peered CIDRs); never
  `0.0.0.0/0` on 22/3389/3306/5432/6379; put management behind a bastion or SSM/serial console; use
  NSG/SG least privilege and review rules regularly.

</div>

## Detection / blue-team view

<div class="callout defend">

- **Metadata theft:** **GuardDuty** raises
  `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` when instance-role
  credentials are used **from an IP that isn't the instance** — the strongest single signal that a
  metadata token was stolen. Also: CloudTrail showing an instance role making API calls from an
  unexpected source; VPC flow logs / app logs showing outbound requests to `169.254.169.254`.
- **Public storage:** Access Analyzer and S3 public-access findings; CloudTrail
  `PutBucketAcl`/`PutBucketPolicy` that widen access; anonymous `GetObject` in access logs.
- **Network exposure:** config-rule/Security-Hub findings for `0.0.0.0/0` on restricted ports;
  `AuthorizeSecurityGroupIngress` events widening a group.

Mapped to **MITRE ATT&CK**: **T1552.005** (Unsecured Credentials: Cloud Instance Metadata API) for the
metadata theft, **T1078.004** (Valid Accounts: Cloud) for using the stolen role, **T1530** (Data from
Cloud Storage) for the bucket, and **T1580/T1526** for the discovery. The recurring idea: *instance
credentials used from anywhere but the instance is almost always theft.*

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-14-cloud` (built separately) — the LocalStack-style local AWS API plus the
**metadata simulation** carried over from `lab-07-web`, all on the isolated network. **Access:** the
vulnerable lab app with its SSRF "import from URL" feature, plus the CLI pointed at the sim
(`AWS_ENDPOINT_URL=http://localhost:4566`). **Targets:** the sim and metadata stand-in only; synthetic
`ASIA_LAB_…` credentials and `LAB-FLAG-{uuid}` markers throughout; a `lab-public-bucket` and an
over-permissive `sg-app`. **Time:** ~120 min. **Isolation:** private network, no Internet route, **no
real cloud reachable**, no real `169.254.169.254`; reset per the lab README.

</div>

Drive the app's SSRF to the metadata sim, retrieve the synthetic role credentials, load them, and
confirm the identity with `get-caller-identity`. Separately, prove the public bucket with
`--no-sign-request` and read the exposed security group. Verify each with the evidence above, then
reset.

## Exercise

<div class="callout method">

**Situation.** Authorized cloud-adjacent web test (client-owned app and account; provider RoE
satisfied). The app has the "import from URL" feature. The client's crown-jewel worry, in their words:
*"could a bug in our website let someone into our AWS account?"*

**Objective.** **Chain the application SSRF to cloud credentials** via the lab metadata simulation,
establish the identity and blast radius of what you stole (14.1 method), state the impact in the
client's terms, and give the **IMDSv2** remediation with the reason it would have stopped this exact
chain.

**Starting information.** The lab app + SSRF parameter, the lab metadata sim, and the CLI/sim
endpoint. No pre-stolen credentials.

**Constraints.** Lab sim only; synthetic markers only; never touch real metadata. Read-only once you
hold the token — enumerate the role's reach, do **not** modify or delete. Explain the **mechanism**
(which fetch, which trust boundary, why the metadata service answered), not just the winning URL.

**Expected deliverables.**
1. The **SSRF-to-metadata chain**: the request that reached metadata, the role name, and the
   (synthetic) credential blob — with a note on *why IMDSv1-style* made a single GET sufficient.
2. The **stolen identity** (`get-caller-identity` = the assumed role) and its **blast radius** (what
   the role can read/reach), derived read-only.
3. The **impact** in client terms (tie it to the Capital One pattern if apt).
4. **Remediation:** IMDSv2 enforcement (`HttpTokens: required` + hop limit 1) *and* the app-layer SSRF
   fix, with one sentence on why IMDSv2 alone defeats a GET-only SSRF; plus the **detection**
   (GuardDuty `InstanceCredentialExfiltration`, outbound `169.254.169.254`).

</div>

<details><summary>Hint 1 — conceptual direction</summary>
This is 07.4's confused deputy pointed one hop further. Confirm the fetch happens (an internal lab
listener) before aiming at the metadata path, exactly as you did for SSRF.
</details>

<details><summary>Hint 2 — the metadata path</summary>
List the role first (<code>…/iam/security-credentials/</code>), then GET that role's name to receive
the credential JSON. Temporary credentials need all three values — key, secret, <em>and</em> session
token — to authenticate.
</details>

<details><summary>Hint 3 — after you hold the token</summary>
Load it as a profile and re-run 14.1's <code>get-caller-identity</code>: you should now be an
<code>assumed-role</code>, not your original user. Then enumerate read-only — the role's reach is the
blast radius.
</details>

<details><summary>Hint 4 — the remediation argument</summary>
Explain precisely why IMDSv2 blocks a GET-only SSRF: the token requires a <code>PUT</code> plus a
custom header the SSRF can't send, so the credential <code>GET</code> is refused. Note that IMDSv2 is
a mitigation of the SSRF class, not a fix for code already on the box — hence "IMDSv2 <em>and</em> fix
the SSRF <em>and</em> least-privilege the role."
</details>

## Check yourself

<div class="callout key">

1. A GET-only SSRF succeeds against IMDSv1 but fails against IMDSv2. Mechanically, what does IMDSv2
   require that the SSRF cannot produce?
2. Why do Azure IMDS and GCP metadata often resist a naive SSRF that would succeed against AWS
   IMDSv1? What single design choice do they share with IMDSv2?
3. You retrieve a bucket's contents with `--no-sign-request`. Why is that a *worse* finding than
   reading the same bucket with your own valid credentials?
4. A security group allows `443/tcp` and `22/tcp` both from `0.0.0.0/0`. Which is (probably) the
   finding and which is (probably) intended, and how would you word the SSH one in a report?
5. In confused-deputy terms, whose privilege did you borrow when the SSRF returned instance
   credentials, and why did the metadata service hand them over without authentication?

</div>

Model answers are in `solutions/module-14.md` (try them before looking).

## References

- **AWS EC2 Instance Metadata Service** — IMDSv1/IMDSv2 docs; **"Add defense in depth against
  open firewalls, reverse proxies, and SSRF vulnerabilities with enhancements to the EC2 IMDS"**
  (AWS Security Blog, Nov 2019 — the IMDSv2 announcement).
- **Azure Instance Metadata Service** (required `Metadata: true` header); **GCP metadata server**
  (required `Metadata-Flavor: Google` header).
- **Capital One (2019)** — the canonical SSRF→IMDSv1→role→S3 breach (public post-incident analyses
  and the US Senate / OCC findings).
- **AWS S3 Block Public Access**; **Azure Storage anonymous access**; **GCP bucket public-access
  prevention**.
- **AWS Security Groups**; **Azure Network Security Groups**; **CIS AWS/Azure/GCP Foundations
  Benchmarks** (metadata, storage, and network controls).
- **OWASP** — SSRF Prevention Cheat Sheet; **PortSwigger** — SSRF against cloud metadata.
- **MITRE ATT&CK** — **T1552.005** Cloud Instance Metadata API; **T1078.004** Valid Accounts: Cloud;
  **T1530** Data from Cloud Storage Object; **T1580** Cloud Infrastructure Discovery.
- **CWE** — CWE-918 (SSRF), CWE-441 (confused deputy), CWE-732/CWE-284 (permissions/access control).

## What you should now be able to do

- Explain IMDSv1 vs IMDSv2 and precisely why v2's token+header defeats a GET-only SSRF, and map the
  same idea to Azure/GCP metadata.
- Chain an app SSRF to instance-role credential theft against the lab sim, load the token, and
  establish the stolen identity's blast radius.
- Recognise and prove public storage exposure (anonymous access) and over-permissive security-group
  ingress.
- Write the remediation (IMDSv2 + SSRF fix + least privilege; Block Public Access; tight ingress) and
  the detection (GuardDuty, CloudTrail, flow logs) for each.

## Progress checkpoint

```bash
py course.py complete 14.2
```
