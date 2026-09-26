# Lab 08 — Vulnerable REST + GraphQL API

**Module:** 08. **Time:** ~2 h. **Hardware:** any Docker host. **Target:** a deliberately
vulnerable API (`api`) on an **internal (no-egress)** network. **Attack from:** the `workstation`
container (`docker exec -it ptlab08_ws sh`); the API is `http://api:5000`.

<div class="callout legal">

LAB TARGET ONLY. Synthetic users/data, benign `LAB-FLAG-*` markers, isolated network. Verify with
`./labs/lab check`. Never test an API you don't own or aren't authorized to test.

</div>

## Run

```bash
./labs/lab up   lab-08-api
./labs/lab check
docker exec -it ptlab08_ws sh          # inside: curl http://api:5000/
py labs/lab-08-api/verify.py           # acceptance test (lab health, not a solution)
./labs/lab down lab-08-api
```

## The surface (OWASP API Security Top 10, 2023)

| Endpoint | Flaw | OWASP |
|---|---|---|
| `POST /api/v1/login` | weak JWT (weak HMAC secret) | API2 |
| `GET /api/v1/users/<id>` | BOLA + excessive data exposure (returns `ssn`, `password_hash`) | API1, API3 |
| `POST /api/v1/users` | mass assignment (client sets `role`) | API3 |
| `GET /api/v1/admin/flag` | BFLA (checks a claim exists, not that it equals admin) | API5 |
| `GET /api/v2/users/<id>` | improper inventory (v2 forgot auth entirely) | API9 |
| `POST /graphql` | introspection enabled; `adminSecret`/`allUsers` lack authorization | API1/API5/API8 |
| `GET /api/v1/openapi.json` | discovery aid (documents the surface) | API9 |

Synthetic users: `alice`/`bob`/`admin` (password `password`). Intended solutions are instructor
material in `solutions/module-08.md`. Reset: `./labs/lab reset lab-08-api`.
