#!/usr/bin/env python3
"""verify.py - acceptance test for lab-13-containers (lab health, not a solution)."""
import os, subprocess, sys
os.environ["MSYS_NO_PATHCONV"] = "1"
C = "ptlab13_target"
def ex(cmd): return subprocess.run(["docker","exec",C,"sh","-c",cmd], capture_output=True, text=True).stdout
def check(n, ok): print(f"  [{'PASS' if ok else 'FAIL'}] {n}"); return ok
def main():
    if C not in subprocess.run(["docker","ps","--filter",f"name={C}","--format","{{.Names}}"],
                               capture_output=True, text=True).stdout:
        print("Lab not running. Start it: ./labs/lab up lab-13-containers"); sys.exit(2)
    r = []; print("lab-13-containers acceptance test:")
    r.append(check("Docker socket is mounted into the container",
                   "docker.sock" in ex("ls -la /var/run/docker.sock")))
    r.append(check("socket drives the host daemon (docker version)",
                   "Server" in ex("docker -H unix:///var/run/docker.sock version 2>&1")))
    r.append(check("socket escape reads seeded host data",
                   "LAB-FLAG-docker-socket-escape" in
                   ex("docker -H unix:///var/run/docker.sock run --rm -v ptlab13_hostdata:/h alpine cat /h/flag.txt 2>&1")))
    print()
    print("RESULT: OK - container-escape lab healthy and isolated." if all(r)
          else "RESULT: FAIL - reset: ./labs/lab reset lab-13-containers")
    sys.exit(0 if all(r) else 1)
if __name__ == "__main__":
    main()
