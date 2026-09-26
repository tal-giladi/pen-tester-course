#!/usr/bin/env python3
"""verify.py - acceptance test for lab-11-lateral (lab health, not a solution)."""
import subprocess, sys
WS = "ptlab11_ws"
def ws(cmd): return subprocess.run(["docker","exec",WS,"sh","-c",cmd], capture_output=True, text=True).stdout
def check(n, ok): print(f"  [{'PASS' if ok else 'FAIL'}] {n}"); return ok
def main():
    if WS not in subprocess.run(["docker","ps","--filter",f"name={WS}","--format","{{.Names}}"],
                               capture_output=True, text=True).stdout:
        print("Lab not running. Start it: ./labs/lab up lab-11-lateral"); sys.exit(2)
    r = []; print("lab-11-lateral acceptance test:")
    r.append(check("foothold: ws -> host-a over SSH",
                   "host-a" in ws('ssh -o ConnectTimeout=6 -o BatchMode=yes lab@host-a hostname 2>/dev/null')))
    r.append(check("reusable credential material present on host-a",
                   "id_ed25519" in ws('ssh -o ConnectTimeout=6 -o BatchMode=yes lab@host-a "ls ~/.ssh" 2>/dev/null')))
    flag = ws('ssh -o ConnectTimeout=6 -o BatchMode=yes lab@host-a '
              '"ssh -o StrictHostKeyChecking=no -o BatchMode=yes -i ~/.ssh/id_ed25519 svc@host-b cat flag.txt" 2>/dev/null')
    r.append(check("reused key reaches host-b and reads the flag",
                   "LAB-FLAG-lateral-credential-reuse" in flag))
    print()
    print("RESULT: OK - lateral-movement lab healthy and isolated." if all(r)
          else "RESULT: FAIL - reset: ./labs/lab reset lab-11-lateral")
    sys.exit(0 if all(r) else 1)
if __name__ == "__main__":
    main()
