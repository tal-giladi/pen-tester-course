#!/usr/bin/env python3
"""verify.py - acceptance test for lab-04-linux-privesc.

Confirms the lab TARGET is up, ISOLATED (no Internet egress), and still exposes each
planted privilege-escalation vector. This validates the *lab*, not your solution - the
intended paths and remediations are instructor material in solutions/module-04.md.

Usage:  py labs/lab-04-linux-privesc/verify.py
Requires the lab running:  ./labs/lab up lab-04-linux-privesc
"""
import subprocess, sys

C = "ptlab04_target"

def dexec(user, cmd):
    r = subprocess.run(["docker", "exec", "-u", user, C, "sh", "-c", cmd],
                       capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()

def check(name, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  - {detail}" if detail and not ok else ""))
    return ok

def main():
    # container running?
    up = subprocess.run(["docker", "ps", "--filter", f"name={C}", "--format", "{{.Names}}"],
                        capture_output=True, text=True).stdout.strip()
    if C not in up:
        print(f"Target {C} is not running. Start it: ./labs/lab up lab-04-linux-privesc")
        sys.exit(2)

    results = []
    print("lab-04-linux-privesc acceptance test:")

    # isolation: egress must be blocked
    rc, _ = dexec("root", "wget -q -T3 -O /dev/null http://1.1.1.1 && echo REACH || echo BLOCKED")
    _, out = dexec("root", "wget -q -T3 -O /dev/null http://1.1.1.1 2>/dev/null && echo REACH || echo BLOCKED")
    results.append(check("isolated (no Internet egress)", out.endswith("BLOCKED"), out))

    # flag exists and is root-only
    _, mode = dexec("root", "stat -c '%a %U' /root/flag.txt")
    results.append(check("root-only flag present", mode.startswith("600 root"), mode))
    _, labcat = dexec("lab", "cat /root/flag.txt 2>&1 || echo DENIED")
    results.append(check("flag not readable by 'lab'", "LAB-FLAG" not in labcat, labcat))

    # vector 1: SUID find
    _, s = dexec("lab", "find /usr/bin/find -perm -4000 >/dev/null 2>&1 && echo yes || echo no")
    results.append(check("vector: SUID find", s == "yes"))

    # vector 2: sudo NOPASSWD less
    _, s = dexec("lab", "sudo -n -l 2>/dev/null | grep -q less && echo yes || echo no")
    results.append(check("vector: sudo NOPASSWD less", s == "yes"))

    # vector 3: world-writable root cron script
    _, s = dexec("lab", "test -w /opt/backup/run.sh && echo yes || echo no")
    _, cron = dexec("root", "test -f /etc/cron.d/lab-backup && echo yes || echo no")
    results.append(check("vector: writable root cron script", s == "yes" and cron == "yes"))

    # vector 4: cap_setuid on /opt/pypriv
    _, s = dexec("lab", "getcap /opt/pypriv 2>/dev/null | grep -qi cap_setuid && echo yes || echo no")
    results.append(check("vector: cap_setuid interpreter", s == "yes"))

    # vector 5: SUID helper (PATH hijack)
    _, s = dexec("lab", "find /usr/local/bin/statuscheck -perm -4000 >/dev/null 2>&1 && echo yes || echo no")
    results.append(check("vector: SUID PATH-hijack helper", s == "yes"))

    print()
    if all(results):
        print("RESULT: OK - lab is healthy and isolated. Happy hunting (find root, read the flag).")
        sys.exit(0)
    print("RESULT: FAIL - reset the lab: ./labs/lab reset lab-04-linux-privesc")
    sys.exit(1)

if __name__ == "__main__":
    main()
