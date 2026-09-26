# Lab 14 — Cloud simulation (LocalStack)

**Module:** 14. **Time:** ~90 min. **Hardware:** Docker host with ~2 GB free for the LocalStack
image. **Target:** a **local cloud simulation** (LocalStack: S3/IAM/STS) with deliberate
misconfigurations, on an isolated (no-egress) network. **Attack from:** the `ws` workstation
(`docker exec -it ptlab14_ws bash`), which has `aws`/`awslocal` pointed at the simulation.

<div class="callout legal">

LAB TARGET ONLY. This is **not** a real cloud tenant — it's a local simulation with synthetic
credentials and benign `LAB-FLAG` markers. Real cloud testing requires the client's authorization
**and** compliance with the provider's penetration-testing policy (AWS/Azure/GCP each publish one).
Never point these techniques at a real account without both. Verify isolation with `./labs/lab check`.

</div>

## Run

```bash
./labs/lab up   lab-14-cloud          # first run pulls the LocalStack image (large)
./labs/lab check
docker exec -it ptlab14_ws bash
#   inside (AWS_ENDPOINT_URL is preset to http://localstack:4566):
aws --endpoint-url "$AWS_ENDPOINT_URL" s3 ls
py labs/lab-14-cloud/verify.py        # acceptance test (lab health, not a solution)
./labs/lab down lab-14-cloud
```

> The M14 lessons write `AWS_ENDPOINT_URL=http://localhost:4566` for a LocalStack you run on your
> own host; in this lab the endpoint is the container `http://localstack:4566` (preset in the
> workstation). Same idea, different hostname because you attack from an on-network box.

## The surface (intentional misconfigurations)

- A **public S3 bucket** `northwind-public` (world-readable) with a flag under `backups/`.
- A **private** bucket `northwind-secrets` that should stay private (contrast).
- An IAM user `lowpriv` with an **over-permissive policy** (`iam:*`, `s3:*`, `sts:AssumeRole`).
- An `admin-role` with an over-broad trust policy (assume-role privilege-escalation path).

Enumerate what your credentials can do, find the public exposure, and reason about the IAM
privilege-escalation path (see [14.3](../../lessons/module-14/lesson-03.md)). The SSRF→metadata
path is exercised in [lab-07](../lab-07-web/README.md) (metadata simulation). Intended solutions are
instructor material in `solutions/module-14.md`.

## Reset

`./labs/lab reset lab-14-cloud`.
