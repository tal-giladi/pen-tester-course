#!/usr/bin/env python3
"""verify.py - acceptance test for lab-12-pivot (lab health, not a solution).

Confirms: restricted is NOT reachable directly from the workstation, the DMZ foothold
works, and the full pivot chain (ws -> dmz -> internal -> restricted) reaches the flag.
"""
import subprocess, sys
WS = "ptlab12_ws"
def ws(cmd): return subprocess.run(["docker","exec",WS,"sh","-c",cmd], capture_output=True, text=True).stdout
def check(n, ok): print(f"  [{'PASS' if ok else 'FAIL'}] {n}"); return ok
def main():
    if WS not in subprocess.run(["docker","ps","--filter",f"name={WS}","--format","{{.Names}}"],
                               capture_output=True, text=True).stdout:
        print("Lab not running. Start it: ./labs/lab up lab-12-pivot"); sys.exit(2)
    r = []; print("lab-12-pivot acceptance test:")
    direct = ws("curl -s --max-time 4 http://restricted/flag 2>&1")
    r.append(check("restricted is NOT directly reachable from ws", "LAB-FLAG" not in direct))
    r.append(check("DMZ foothold reachable over SSH",
                   "dmz" in ws('ssh -o ConnectTimeout=6 -o BatchMode=yes lab@dmz hostname 2>/dev/null')))
    chain = ws('ssh -o ConnectTimeout=6 -o BatchMode=yes -J lab@dmz lab@internal '
               '"curl -s --max-time 5 http://restricted/flag" 2>/dev/null')
    r.append(check("pivot chain ws->dmz->internal reaches restricted flag",
                   "LAB-FLAG-pivot-restricted-segment-reached" in chain))
    print()
    print("RESULT: OK - segmented pivot lab healthy and isolated." if all(r)
          else "RESULT: FAIL - reset: ./labs/lab reset lab-12-pivot")
    sys.exit(0 if all(r) else 1)
if __name__ == "__main__":
    main()
