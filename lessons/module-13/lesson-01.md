# 13.1 — Docker for testers: isolation, capabilities, the mounted socket &amp; escape

<div class="prereq">

**Prerequisites:** [00.4 lab & isolation](../module-00/lesson-04.md), [M04 Linux](../module-04/lesson-01.md).
**Module:** M13 Containers. **Difficulty:** 🟡🔴.
**You will produce:** a container-privilege assessment and one justified escape path to the host on
the lab, with remediation and detection.

</div>

## Why this matters

You have already used containers all through this course — the lab runs in them. Now you assess
them as a target. Engineers often believe a container is a security boundary as strong as a VM. It
is not: a container is a **normal Linux process** with some kernel-enforced restrictions
(namespaces, cgroups, capabilities). When those restrictions are relaxed — a mounted Docker socket,
`--privileged`, an extra capability, a host mount — the boundary is thin or gone, and "container
compromise" becomes "host compromise." Recognizing that gap is a common, high-impact finding.

## Learning objectives

- Explain what actually isolates a container (and what doesn't), in kernel terms.
- Recognize from inside a shell that you're in a container and enumerate your privileges.
- Understand *why* the classic misconfigurations (mounted socket, privileged, dangerous
  capabilities, host mounts) let a container reach the host — mechanism, not incantation.
- State the remediation and the detection story for each.

## Intuition

A VM virtualizes hardware; the guest kernel is separate. A container shares the **host kernel** and
is just isolated *views* of resources. Think of it as a process wearing a costume: namespaces give
it its own view of PIDs, mounts, network, users; cgroups limit its resources; capabilities trim
what root inside it can do. Remove enough of the costume — or hand it a tool that talks straight to
the host — and it's just a root process on your host. Every escape in this lesson is really "a way
the costume was never actually put on."

## The underlying technology

<div class="callout key">

- **Namespaces** (`man 7 namespaces`): isolated views of PID, mount, network, UTS, IPC, user.
  `lsns` lists them. Sharing a namespace with the host (e.g. `--pid=host`, `--net=host`) removes
  that isolation.
- **cgroups**: resource limits (CPU/memory). Not primarily a security boundary, but the historic
  `release_agent` escape abused cgroup v1.
- **Capabilities** (`man 7 capabilities`): root's powers split into units (e.g. `CAP_NET_RAW`,
  `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`). A default Docker container drops many; `--privileged` grants
  **all** of them (and disables seccomp/AppArmor and exposes devices). `CAP_SYS_ADMIN` is
  famously close to "root on the host."
- **The Docker daemon runs as root** on the host. Anything that can talk to the daemon's socket
  (`/var/run/docker.sock`) can ask it to run a container — including one that mounts the host's
  filesystem. That's why a mounted socket is game over.

</div>

The security take-away: **container isolation is a set of kernel features that must all be in
place.** Testing containers is largely checking which ones were weakened.

## How a tester recognizes it

First, confirm you're in a container and enumerate the costume:

```bash
# Am I in a container? (any of these are strong hints)
cat /proc/1/cgroup                     # docker/… or kubepods/… paths
ls -la /.dockerenv 2>/dev/null         # present in many Docker images
cat /proc/1/status | grep CapEff       # effective capabilities bitmask
capsh --decode=$(grep CapEff /proc/1/status | awk '{print $2}')   # human-readable caps

# What can I reach?
ls -la /var/run/docker.sock 2>/dev/null   # a mounted Docker socket = high impact
mount | grep -E ' / |host'                 # host paths mounted in?
env                                        # secrets baked into the container?
```

Each answer is a hypothesis: a readable `docker.sock`, an over-broad `CapEff`, a host bind-mount,
or secrets in `env` each map to a known escalation.

## Manual investigation &amp; the mechanisms

<div class="callout attack">

**The mounted Docker socket (the classic).** If `/var/run/docker.sock` is mounted into the
container, you can drive the host's root daemon. Conceptually: ask the daemon to start a new
container that bind-mounts the host root filesystem, then read/write it — because the daemon does
this *as root on the host*.

```bash
# LAB ONLY. Requires a docker client in the container (or talk to the socket via curl).
docker -H unix:///var/run/docker.sock run -v /:/host --rm -it alpine \
    cat /host/etc/shadow        # you are now reading the HOST's files
```

*Why it works:* the socket is the daemon's API; the daemon is root on the host; you asked it to
mount the host and it obliged. The trust boundary crossed is "container → host root," and it was
never really there once the socket was exposed.

</div>

<div class="callout attack">

**`--privileged` / `CAP_SYS_ADMIN` (concept).** A privileged container has all capabilities, host
devices, and no seccomp/AppArmor. With `CAP_SYS_ADMIN` you can mount filesystems and (historically)
abuse cgroup-v1 `release_agent` to have the host run a program you control. The details vary by
kernel/runtime; the point for a tester is: **privileged ≈ root on the host**, so finding a
privileged container is finding a host compromise waiting to happen.

</div>

Other common findings: **host path mounts** (`-v /:/host` or `/etc`, `/root`, `/var/run`),
**shared host namespaces** (`--pid=host` lets you see/ptrace host processes), **secrets in image
layers** (`docker history --no-trunc`, files or `ENV` with credentials), and **insecure/untrusted
images** (supply-chain risk — you inherit whatever the base image carries).

## Tooling (and its limits)

- `capsh --print` / `/proc/1/status` — read your capabilities. Ground truth; verify by hand.
- `trivy image <img>` — scans an image for known-vulnerable packages and misconfig. Finds *known*
  issues; won't tell you the socket is mounted at runtime — that's your enumeration.
- `deepce` / `amicontained` (concept) — enumeration helpers that automate the checks above. Useful,
  but understand each check first so you can verify and explain it.

## Impact, remediation &amp; detection

<div class="callout defend">

**Remediation.** Don't mount `docker.sock` into containers (use a proxy with a locked-down API if
you must); never run `--privileged` unless truly required; drop all capabilities and add back only
what's needed (`--cap-drop=ALL --cap-add=...`); run as a non-root user (`USER`); enable
`--read-only` and `--security-opt=no-new-privileges`; use user namespaces; don't bake secrets into
images (use secret stores); pin and scan base images. Map to the **CIS Docker Benchmark**.

**Detection.** Watch for container processes spawning host-affecting actions: new containers with
host mounts, `docker run -v /:/…`, unexpected use of the daemon API, mount/`nsenter` syscalls (via
Falco/auditd/eBPF), and processes escaping their cgroup. **MITRE ATT&CK T1611 (Escape to Host)**,
T1610 (Deploy Container), T1613 (Container Discovery).

</div>

## Practical lab

<div class="lab">

**Environment:** `labs/lab-13-containers`. **Time:** ~75 min. **Targets:** a deliberately
misconfigured container (mounted Docker socket) on an isolated host — LAB TARGET, throwaway.
**Isolation:** the lab network has no egress; the "host" you reach is the lab's own Docker host in
a disposable context. Run `./labs/lab up lab-13-containers` then `./labs/lab check`.

</div>

Work through: confirm you're containerized, enumerate capabilities and mounts, find the exposed
socket, and use it to read a host-only benign flag — then write the remediation and how a defender
would have seen it.

## Exercise

<div class="callout method">

**Situation.** You've landed a shell in a container running a web service (the lab). Your scope
includes "the container host if reachable from the app tier."

**Objective.** Determine whether this container can reach its host, and if so, prove it by reading a
host-only marker — then report it professionally.

**Starting information.** A shell in the lab container.

**Constraints.** LAB TARGET only; `./labs/lab check` passes first. Read the marker as evidence;
don't damage the host context. Stay within the lab.

**Expected deliverables.** (1) Your container-privilege assessment (caps, mounts, socket, namespaces).
(2) The escape path you used, with the command and its output as evidence. (3) Impact (what host
access means for the engagement). (4) Remediation and one detection signal.

</div>

<details><summary>Hint 1 — conceptual direction</summary>
Isolation is a set of kernel features that must all be present. Which one is missing here? Start by
listing what's mounted and what capabilities you hold.
</details>

<details><summary>Hint 2 — technique family</summary>
A file under <code>/var/run/</code> is the daemon's API. Who runs that daemon, and with what
privileges?
</details>

<details><summary>Hint 3 — where to look</summary>
<code>ls -la /var/run/docker.sock</code>. If it's there and you have a docker client (or can
<code>curl --unix-socket</code> it), you can ask the host's root daemon to start a container that
mounts the host filesystem.
</details>

## Check yourself

<div class="callout key">

1. Why is a container *not* as strong a boundary as a VM? Answer in kernel terms.
2. A container is `--privileged` but has **no** Docker socket mounted. Is it still a host-escape
   risk? Why?
3. Explain to a developer, in one sentence, why mounting `docker.sock` "just to let the app manage
   containers" is equivalent to giving the app root on the host.
4. Your enumeration shows `CapEff` includes `cap_sys_admin`. Why does that one capability worry you
   more than most?
5. Which single remediation removes the most escape paths at once, and what does it cost?

</div>

Model answers in `solutions/module-13.md`.

## References

- **Docker docs** — *Docker security*, *Runtime privilege and Linux capabilities*, *Docker daemon
  attack surface* (the socket).
- **`man 7 capabilities`, `man 7 namespaces`, `man 7 cgroups`.**
- **CIS Docker Benchmark**; **NIST SP 800-190** Application Container Security Guide.
- **MITRE ATT&CK** — T1611 Escape to Host, T1610 Deploy Container, T1613 Container Discovery.
- **CWE-250** (execution with unnecessary privileges), **CWE-668** (exposure of resource).

## What you should now be able to do

- Explain what isolates a container and enumerate which protections are present.
- Recognize the mounted-socket, privileged, capability, and host-mount misconfigurations and *why*
  each crosses the container→host boundary.
- Read a host marker from the lab via the socket, and write the remediation + detection.

## Progress checkpoint

```bash
py course.py complete 13.1
```
