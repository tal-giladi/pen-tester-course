# 13.2 — Kubernetes attack surface: RBAC, service accounts &amp; workload escape

<div class="prereq">

**Prerequisites:** [13.1 Docker for testers](lesson-01.md).
**Module:** M13 Containers. **Difficulty:** 🔴.
**You will produce:** an in-cluster privilege assessment from a pod and one justified path to
broader cluster access or a node, with remediation.

</div>

## Why this matters

Kubernetes runs most modern container workloads, and its default posture trusts a lot. A tester who
gains code execution in a single pod frequently finds that the pod's **service-account token**, an
over-permissive **RBAC** binding, or a **privileged/hostPath** pod spec is enough to read every
secret in a namespace, schedule a pod on any node, or step onto the node itself. The skill is
reasoning about the cluster as a system of identities and permissions — the same graph mindset as
Active Directory, applied to Kubernetes.

## Learning objectives

- Describe the Kubernetes components a tester cares about and the trust between them.
- From inside a pod, enumerate the service-account token and what it can do (`kubectl auth can-i`).
- Understand *why* over-permissive RBAC, hostPath/privileged specs, and exposed kubelet/API let you
  expand access — and the remediation for each.

## Intuition

A pod is a container (13.1) plus a Kubernetes identity: a **service account**, whose token is
mounted into the pod by default. The API server enforces **RBAC** — who may do what to which
objects. Most real weaknesses are *authorization* failures: a service account with far more rights
than the workload needs, or a pod allowed to run privileged / mount the host. Find the identity,
ask the API server what it can do, and follow the graph.

## The underlying technology

<div class="callout key">

- **API server** — the front door; everything goes through it, guarded by authn + RBAC.
- **kubelet** (port 10250) — the node agent that runs pods; if it allows anonymous/authorized
  access it can be told to exec in pods.
- **etcd** — the cluster's datastore (all secrets); catastrophic if directly reachable.
- **Service account + token** — mounted at
  `/var/run/secrets/kubernetes.io/serviceaccount/{token,ca.crt,namespace}` by default.
- **RBAC** — `Role`/`ClusterRole` + `RoleBinding`/`ClusterRoleBinding`. Verbs (get/list/create/…)
  on resources (pods, secrets, …). Wildcards and `cluster-admin` bindings are the usual sins.
- **Security context / Pod Security Admission** — controls privileged, hostPath, host namespaces,
  runAsNonRoot. (The old **PodSecurityPolicy** is <span class="badge deprecated">DEPRECATED</span>;
  **Pod Security Admission** is <span class="badge current">CURRENT</span>.)

</div>

## How a tester recognizes it

From inside a pod:

```bash
# The identity you were handed
cat /var/run/secrets/kubernetes.io/serviceaccount/token   # JWT for the API server
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# What can this identity do? (the single most useful question)
kubectl auth can-i --list                    # full matrix for this token
kubectl auth can-i create pods
kubectl auth can-i get secrets -n "$NS"
kubectl get secrets -A 2>/dev/null            # if allowed, often game over
```

Each "yes" is a hypothesis. `create pods` → schedule a pod that mounts the host or runs privileged.
`get secrets` → read credentials for other systems. `create clusterrolebindings` → self-promote to
`cluster-admin`.

## Manual investigation &amp; mechanisms

<div class="callout attack">

**Over-permissive RBAC → cluster takeover (concept).** If your service account can create
`RoleBinding`/`ClusterRoleBinding` (or already has broad verbs), you bind yourself to a powerful
role and inherit its rights. If it can `create pods`, you schedule a pod whose spec mounts the node
filesystem or runs privileged — then you're on the node (this is the 13.1 escape, expressed as a
pod spec):

```yaml
# LAB ONLY — a pod that mounts the host filesystem (why: hostPath crosses pod→node)
spec:
  containers:
  - name: x
    image: alpine
    command: ["sleep","infinity"]
    volumeMounts: [{name: host, mountPath: /host}]
    securityContext: {privileged: true}
  volumes:
  - name: host
    hostPath: {path: /}
```

*Why it works:* the API server let this identity create a pod, and the pod spec asked for a host
mount / privilege the admission policy didn't forbid. Authorization + admission are the boundaries;
both were too permissive.

</div>

Other findings: **exposed kubelet** (10250) allowing exec into pods; **anonymous API access**;
**secrets readable** by the namespace's default service account; **IMDS reachable from pods** (the
node's cloud credentials — links to [M14](../module-14/lesson-02.md)); **etcd** reachable without
mTLS.

## Tooling (and limits)

- `kubectl auth can-i --list` — the authorization matrix for your token. Ground truth.
- `kubectl` — the API client; everything you do is an API call you could also make with `curl` +
  the token (verify by hand).
- `kube-hunter` / `peirates` (concept) — automate discovery/exploitation of the above; understand
  each check so you can verify and explain it, and note they can be noisy/detected.
- `trivy k8s` / `kubescape` — config scanning against Pod Security / CIS.

## Impact, remediation &amp; detection

<div class="callout defend">

**Remediation.** Least-privilege RBAC (no wildcards, no needless `cluster-admin`; scope Roles to
namespaces); disable auto-mounting the default SA token where unused
(`automountServiceAccountToken: false`); enforce **Pod Security Admission** (restrict privileged,
hostPath, host namespaces; `runAsNonRoot`); lock down the kubelet (`--anonymous-auth=false`,
authz webhook); network-policy the API/etcd/IMDS; use short-lived, audience-bound tokens. Map to
the **NSA/CISA Kubernetes Hardening Guide** and **CIS Kubernetes Benchmark**.

**Detection.** Kubernetes **audit logs** for anomalous verbs (secret reads, RBAC changes, pod
creates with hostPath/privileged), unexpected `exec`, and use of the default SA token from unusual
pods. **MITRE ATT&CK for Containers** T1610/T1611/T1613 and the cloud matrix.

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-13-containers` (the Kubernetes portion — a local `kind`/`minikube`
cluster you stand up per the lab README). **Time:** ~90 min. **Targets:** a pod with an
over-permissive service account + a permissive pod-security setting, LAB TARGET, throwaway cluster,
isolated. Bring it up per the lab README and confirm isolation.

</div>

From a pod, enumerate your service account, use `kubectl auth can-i --list`, and find a path to
either read secrets you shouldn't or schedule a host-mounting pod. Document remediation + a detection
signal.

## Exercise

<div class="callout method">

**Situation.** You have code execution in a pod in the lab cluster. Scope: the cluster.

**Objective.** Determine how far the pod's identity can take you, and demonstrate one concrete step
(read an out-of-scope-for-the-workload secret, or reach the node) — then report it.

**Starting information.** A shell in a lab pod.

**Constraints.** LAB TARGET only; throwaway cluster; benign markers. Don't destroy cluster state
beyond what the proof needs; reset afterward.

**Expected deliverables.** (1) The pod's service-account identity and its `can-i` matrix.
(2) The path you took (RBAC abuse or hostPath/privileged pod), with evidence. (3) Impact.
(4) Remediation (RBAC + Pod Security) and one audit-log detection signal.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
You were handed an identity whether you asked or not. Where does Kubernetes mount it, and what's
the one command that tells you everything it can do?
</details>

<details><summary>Hint 2 — technique family</summary>
Two broad routes: <em>read</em> something valuable (secrets) or <em>create</em> something powerful
(a pod that mounts the node, or a binding that promotes you). Check <code>can-i create pods</code>
and <code>can-i get secrets</code> first.
</details>

<details><summary>Hint 3 — where to look</summary>
<code>/var/run/secrets/kubernetes.io/serviceaccount/</code> for the token;
<code>kubectl auth can-i --list</code> for the matrix. A hostPath/privileged pod spec turns
"create pods" into "own the node" (see 13.1).
</details>

## Check yourself

<div class="callout key">

1. Why is "get code exec in one pod" often equivalent to "read every secret in the namespace"?
2. A pod cannot create pods but *can* create `RoleBindings`. Are you stuck? Why or why not?
3. What does `automountServiceAccountToken: false` change, and when is it safe to set?
4. Explain why an exposed kubelet on 10250 is dangerous even without the API server.
5. Which single control (RBAC least-privilege vs Pod Security Admission) would you push first for a
   client, and why does it depend on their findings?

</div>

Model answers in `solutions/module-13.md`.

## References

- **Kubernetes docs** — RBAC, Service Accounts, Security Contexts, **Pod Security Admission**,
  Securing the kubelet, Auditing.
- **NSA/CISA Kubernetes Hardening Guide**; **CIS Kubernetes Benchmark**.
- **MITRE ATT&CK for Containers** — T1610, T1611, T1613; Cloud matrix for IMDS-from-pod.
- **CWE-269** (improper privilege management), **CWE-306** (missing authentication).

## What you should now be able to do

- Enumerate a pod's identity and permissions and reason about the cluster as an authorization graph.
- Recognize and explain over-permissive RBAC, permissive pod security, and exposed
  kubelet/API/etcd — and the path each opens.
- Write RBAC + Pod Security remediation and name an audit-log detection signal.

## Progress checkpoint

```bash
py course.py complete 13.2
```

Module 13 complete. Next in the infra track: [M14 — Cloud penetration testing](../module-14/lesson-01.md).
