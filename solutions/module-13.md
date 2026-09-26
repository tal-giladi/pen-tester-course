# Instructor / solutions — Module 13

> **Instructor material.** Not linked from `_sidebar.md`. Do the exercises before reading.

## 13.1 — Docker escape

**Exercise.** Assessment should note: container confirmed via `/proc/1/cgroup` + `/.dockerenv`;
capabilities from `/proc/1/status` CapEff; **`/var/run/docker.sock` is mounted** — the finding.
Escape: `docker -H unix:///var/run/docker.sock run --rm -v ptlab13_hostdata:/h alpine cat /h/flag.txt`
(a real host would use `-v /:/host`). Evidence = the command + `LAB-FLAG-docker-socket-escape`.
Impact: full host compromise (the daemon is root); every container/secret on the host is exposed.
Remediation: don't mount the socket (use a scoped API proxy if unavoidable); `--cap-drop=ALL`, non-root
`USER`, `no-new-privileges`. Detection: daemon API calls from a workload, `docker run -v /:/…`,
mount/`nsenter` syscalls (Falco/auditd) — ATT&CK T1611.

**Check-yourself.** (1) A container shares the host **kernel**; isolation is namespaces/cgroups/caps,
not a separate kernel like a VM — a kernel bug or a relaxed control crosses it. (2) Yes — privileged
grants all caps + devices + no seccomp/AppArmor, enabling mount/cgroup-`release_agent`-style host
access without the socket. (3) "The socket is the root daemon's API; anything that can call it can
start a container that mounts and rewrites your host — it *is* host root." (4) `cap_sys_admin` allows
mounting filesystems and many privileged operations — it's the closest single cap to full host root.
(5) Running non-root + `--cap-drop=ALL` + no socket/host mounts removes most paths; cost is that
some workloads must be refactored to not need root/host access.

## 13.2 — Kubernetes

**Exercise.** Identity from `/var/run/secrets/kubernetes.io/serviceaccount/token` + namespace;
`kubectl auth can-i --list`. Path is either **read** (`get secrets` → dump namespace secrets) or
**create** (`create pods` → schedule a hostPath/privileged pod → node; or `create
(cluster)rolebindings` → bind to `cluster-admin`). Evidence = the `can-i` matrix + the action's
output. Impact scoped to what the token reaches (namespace vs cluster vs node). Remediation:
least-privilege RBAC (no wildcards/`cluster-admin`), `automountServiceAccountToken: false`, Pod
Security Admission (block privileged/hostPath), locked-down kubelet. Detection: audit logs for
secret reads / RBAC changes / privileged-pod creates.

**Check-yourself.** (1) The default SA token is mounted into the pod and often has `get/list
secrets` in its namespace — code exec then trivially reads them. (2) Not stuck: creating a
RoleBinding that binds you to a powerful existing Role (or ClusterRole) grants its verbs — a
self-promotion path. (3) It stops the SA token being auto-mounted into the pod, removing the
in-pod credential; safe when the workload doesn't call the API server. (4) The kubelet (10250) can
exec in / read logs of pods on its node; anonymous/authorized access to it bypasses the API
server's RBAC. (5) Depends on findings: if broad RBAC is the sin, push least-privilege RBAC first;
if privileged/hostPath pods are allowed, push Pod Security Admission first — lead with whichever
their actual attack path used.
