# Lab 07 / 08 — Vulnerable web app &amp; API ("Northwind Shop")

**Modules:** 07 (web) and 08 (API). **Time:** several hours across the module. **Hardware:** any
Docker host. **Targets:** a deliberately vulnerable Flask app (`web`) + an internal-only service
and cloud-metadata **simulation** (`internal`), on an **internal (no-egress)** network. **Attack
from:** the `workstation` container on the lab network.

<div class="callout legal">

LAB TARGET ONLY. Synthetic users/data, benign `LAB-FLAG-*` markers. The network has **no Internet
route** — this is deliberate: it means the app's SSRF (`/fetch`) can never reach the real Internet
or real cloud metadata. Verify with `./labs/lab check`. Never point these techniques at systems you
don't own or aren't authorized to test.

</div>

## Why you attack from a container (not localhost)

The lab network is `internal: true`, so Docker does **not** publish the app's port to your host
(and the app has no Internet egress). You attack from the `workstation` container, which sits on
the lab network — exactly how a tester works from a box inside the target's network. The app is
reachable there as `http://web:5000`.

```bash
./labs/lab up   lab-07-web
./labs/lab check                      # confirm isolation
docker exec -it ptlab07_ws sh         # your attacker shell (curl/openssl/nmap)
#   inside:  curl http://web:5000/
py labs/lab-07-web/verify.py          # acceptance test (lab health, not a solution)
./labs/lab down lab-07-web
```

**GUI / Burp Suite:** attach your Kali attacker box to the Docker network `ptlab07_appnet`
(`docker network connect ptlab07_appnet <your-kali-container>`), then browse/proxy to
`http://web:5000`. All exercises are fully doable with `curl` from the workstation if you prefer.

## The surface (intentional vulnerabilities)

| Endpoint | Class | Module |
|---|---|---|
| `/search?q=` | SQL injection **and** reflected XSS | 07.3 / 07.4 |
| `/api/orders/<id>` | IDOR / BOLA (no ownership check) | 07.2 / 08.1 |
| `/login` | weak JWT (weak HMAC secret, `alg:none` accepted); cookie missing flags | 07.1 / 07.2 |
| `/api/admin/users` | BFLA (trusts client-controlled `role` claim) | 08.1 |
| `/profile` | stored XSS (bio rendered unescaped) | 07.4 |
| `/fetch?url=` | SSRF → internal service &amp; metadata simulation | 07.4 / 08 / 14 |
| `/ping?host=` | OS command injection | 07.3 |
| `/download?file=` | path traversal | 07.5 |
| `/render?name=` | server-side template injection (SSTI) | 07.3 |
| `/upload` | unrestricted file upload | 07.5 |

Internal-only (reachable **only** via SSRF): `http://internal-api/secret` and the metadata
simulation `http://metadata/latest/meta-data/...`. Intended solutions are instructor material in
`solutions/module-07-part1.md`, `solutions/module-07-part2.md`, and `solutions/module-08.md`.

## Reset

`./labs/lab reset lab-07-web` rebuilds and re-seeds (undoes stored-XSS/profile/upload changes).
