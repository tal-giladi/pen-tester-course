# Lab 02 — Reconnaissance (northwind.lab estate)

**Module:** 02. **Time:** ~75 min. **Hardware:** any Docker host (minimal). **Targets:** the
fictional `northwind.lab` DNS + web estate on an **internal (no-egress)** network. **Recon shell:**
the `workstation` container (dig/curl/openssl/nmap baked in). **Resolver:** ns1 at `10.13.0.53`.

<div class="callout legal">

LAB TARGETS ONLY — `northwind.lab` is fictional and isolated (no Internet route; verify with
`./labs/lab check`). Active recon touches the target and requires authorization on a real
engagement (see [00.1](../../lessons/module-00/lesson-01.md)). Never enumerate real third parties
without written authorization.

</div>

## Run

```bash
./labs/lab up    lab-02-recon
./labs/lab check                       # confirm isolation first
docker exec -it ptlab02_ws bash        # your recon shell on the lab network
#   inside: dig, curl, openssl, nmap are available; resolver is 10.13.0.53
py labs/lab-02-recon/verify.py         # acceptance test (lab health, not a solution)
./labs/lab down  lab-02-recon
```

## The estate

- **ns1 `10.13.0.53`** — primary + lab resolver (AXFR correctly denied).
- **ns2 `10.13.0.54`** — a forgotten secondary, **AXFR open to anyone** (the flaw). `dig NS
  northwind.lab` reveals both nameservers; try a zone transfer against *each*.
- **web `10.13.0.10`** — many virtual hosts: `www`, `shop` (leaks `X-Powered-By: PHP`), `dev`
  (debug headers, non-prod leak), `api` (`/swagger.json`), `admin`, `vpn-old` (old appliance
  banner), `promo`/`checkout`. `robots.txt` and `sitemap.xml` leak paths and names.
- **workstation `10.13.0.100`** — where you work.

## Things to discover (don't peek at solutions)

- A **zone transfer** that dumps every name — including `internal-crm.northwind.lab`, which points
  to RFC 1918 space and is **not externally reachable** (note it; don't prioritize external tests).
- A **virtual host not in DNS** (`staging.northwind.lab`) reachable only via the `Host:` header —
  found by vhost fuzzing.
- A name that exists **only in a TLS certificate SAN** (`legacy.northwind.lab`) — found by
  inspecting the cert with `openssl s_client`.
- Distinct **fingerprints** per host from their live headers.

Assemble a confirmed, evidence-backed, **prioritized** attack-surface map (the M02 exercise). The
intended findings and priorities are instructor material in `solutions/module-02.md`.
