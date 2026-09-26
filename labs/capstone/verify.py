#!/usr/bin/env python3
"""verify.py - acceptance test for the capstone environment (lab health, not a solution).

Confirms the integrated, segmented engagement stands up: the DMZ web surface is
reachable and still vulnerable (initial access), the restricted segment is NOT directly
reachable, and the pivot chain ws->dmz->internal reaches the crown-jewel flag. The
intended full path is instructor material in solutions/capstone/walkthrough.md.
"""
import subprocess, sys
WS = "ptlabcap_ws"
def ws(cmd): return subprocess.run(["docker","exec",WS,"sh","-c",cmd], capture_output=True, text=True).stdout
def check(n, ok): print(f"  [{'PASS' if ok else 'FAIL'}] {n}"); return ok
def main():
    if WS not in subprocess.run(["docker","ps","--filter",f"name={WS}","--format","{{.Names}}"],
                               capture_output=True, text=True).stdout:
        print("Capstone not running. Start it: ./labs/lab up capstone"); sys.exit(2)
    r = []; print("capstone acceptance test:")
    r.append(check("DMZ web surface reachable (initial access)",
                   "Northwind" in ws("curl -s --max-time 5 http://portal:5000/")))
    r.append(check("web surface is exploitable (SQLi proof)",
                   "LAB-FLAG-sqli" in ws("curl -s \"http://portal:5000/search?q=x%27%20UNION%20SELECT%20value,1%20FROM%20secrets--%20-\"")))
    direct = ws("curl -s --max-time 4 http://restricted/flag 2>&1")
    r.append(check("restricted segment NOT directly reachable", "LAB-FLAG" not in direct))
    chain = ws('ssh -o ConnectTimeout=6 -o StrictHostKeyChecking=no -o BatchMode=yes '
               '-J lab@dmz lab@internal "curl -s --max-time 5 http://restricted/flag" 2>/dev/null')
    r.append(check("pivot chain reaches the crown-jewel flag",
                   "LAB-FLAG-capstone-crown-jewel" in chain))
    print()
    print("RESULT: OK - capstone environment healthy and isolated." if all(r)
          else "RESULT: FAIL - reset: ./labs/lab reset capstone")
    sys.exit(0 if all(r) else 1)
if __name__ == "__main__":
    main()
