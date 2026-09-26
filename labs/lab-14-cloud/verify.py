#!/usr/bin/env python3
"""verify.py - acceptance test for lab-14-cloud (lab health, not a solution).

Confirms the LocalStack simulation is up, seeded, and exposes the intended misconfigs.
"""
import subprocess, sys, time
WS = "ptlab14_ws"
EP = "http://localstack:4566"
def ws(cmd): return subprocess.run(["docker","exec",WS,"sh","-c",cmd], capture_output=True, text=True).stdout
def check(n, ok): print(f"  [{'PASS' if ok else 'FAIL'}] {n}"); return ok
def main():
    if WS not in subprocess.run(["docker","ps","--filter",f"name={WS}","--format","{{.Names}}"],
                               capture_output=True, text=True).stdout:
        print("Lab not running. Start it: ./labs/lab up lab-14-cloud"); sys.exit(2)
    print("lab-14-cloud acceptance test (waiting for LocalStack to seed)...")
    # give LocalStack a moment to become ready + run the init seed
    buckets = ""
    for _ in range(30):
        buckets = ws(f"aws --endpoint-url {EP} s3 ls 2>/dev/null")
        if "northwind-public" in buckets:
            break
        time.sleep(3)
    r = []
    r.append(check("LocalStack reachable & seeded (buckets present)", "northwind-public" in buckets))
    flag = ws(f"aws --endpoint-url {EP} s3 cp s3://northwind-public/backups/flag.txt - 2>/dev/null")
    r.append(check("public bucket exposes the flag object", "LAB-FLAG-cloud-public-bucket" in flag))
    users = ws(f"aws --endpoint-url {EP} iam list-users 2>/dev/null")
    r.append(check("over-permissive IAM user present", "lowpriv" in users))
    roles = ws(f"aws --endpoint-url {EP} iam list-roles 2>/dev/null")
    r.append(check("assumable admin-role present", "admin-role" in roles))
    print()
    print("RESULT: OK - cloud simulation healthy and isolated." if all(r)
          else "RESULT: FAIL - reset: ./labs/lab reset lab-14-cloud (LocalStack can be slow to seed)")
    sys.exit(0 if all(r) else 1)
if __name__ == "__main__":
    main()
