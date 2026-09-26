#!/usr/bin/env python3
"""verify.py - acceptance test for lab-02-recon (lab health, not a solution).

Confirms the estate is up, isolated, and still exposes each recon element:
resolution, the AXFR misconfig on ns2 (but not ns1), a DNS-hidden vhost, and the
cert-SAN pivot name. Intended findings live in solutions/module-02.md.

Usage:  py labs/lab-02-recon/verify.py     (requires ./labs/lab up lab-02-recon)
"""
import subprocess, sys

WS = "ptlab02_ws"

def ws(cmd):
    r = subprocess.run(["docker", "exec", WS, "sh", "-c", cmd], capture_output=True, text=True)
    return (r.stdout + r.stderr)

def check(name, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  - {detail}" if detail and not ok else ""))
    return ok

def main():
    up = subprocess.run(["docker", "ps", "--filter", f"name={WS}", "--format", "{{.Names}}"],
                        capture_output=True, text=True).stdout
    if WS not in up:
        print("Lab not running. Start it: ./labs/lab up lab-02-recon"); sys.exit(2)

    r = []
    print("lab-02-recon acceptance test:")
    r.append(check("resolver answers (www -> 10.13.0.10)",
                   "10.13.0.10" in ws("dig +short www.northwind.lab @10.13.0.53")))
    r.append(check("ns1 REFUSES zone transfer",
                   "Transfer failed" in ws("dig axfr northwind.lab @10.13.0.53")))
    axfr = ws("dig axfr northwind.lab @10.13.0.54")
    r.append(check("ns2 ALLOWS zone transfer (the misconfig)", "internal-crm" in axfr))
    r.append(check("AXFR leaks the RFC1918-only name", "10.0.5.10" in axfr))
    r.append(check("hidden vhost 'staging' served only via Host header",
                   "STAGING" in ws("curl -s -H 'Host: staging.northwind.lab' http://10.13.0.10/")))
    r.append(check("'staging' is NOT in DNS",
                   ws("dig +short staging.northwind.lab @10.13.0.53").strip() == ""))
    r.append(check("shop leaks an app-server banner",
                   "PHP" in ws("curl -s -D - -o /dev/null -H 'Host: shop.northwind.lab' http://10.13.0.10/")))
    r.append(check("cert SAN pivot name 'legacy' present",
                   "legacy.northwind.lab" in ws(
                     "echo | openssl s_client -connect 10.13.0.10:443 -servername www.northwind.lab 2>/dev/null "
                     "| openssl x509 -noout -ext subjectAltName 2>/dev/null")))
    print()
    if all(r):
        print("RESULT: OK - recon estate healthy and isolated.")
        sys.exit(0)
    print("RESULT: FAIL - reset the lab: ./labs/lab reset lab-02-recon")
    sys.exit(1)

if __name__ == "__main__":
    main()
