# Tools inventory &amp; fallbacks

_Last reviewed: 2026-09._

Security tooling moves fast. This file pins the tools the course relies on, records the version it
was written and tested against, and — because any external tool can vanish or change behavior —
gives a **fallback** so the *objective* survives even if the primary tool disappears. Lessons
teach the underlying mechanism first, so a tool swap never breaks understanding.

For each tool: **what problem it solves**, not just its name. The lesson that introduces it goes
deeper (key options, limits, what the output means, how to verify by hand).

<div class="callout warn">

Versions below are the tested references, not hard requirements. Kali/Parrot rolling releases
track most of these. When you install a different version, note it; if a command's behavior
differs, that is itself a lesson (§21 "avoid tutorials that depend on undocumented behavior").

</div>

## Platform

| Tool | Tested version | Purpose | Fallback |
|---|---|---|---|
| Kali Linux (attacker box) | 2025.x rolling | Preloaded toolset for the attacker workstation | Parrot OS Security; or Debian + the `scripts/install-tools.sh` subset |
| Docker Engine + Compose | 27.x / v2.29+ | Runs the isolated lab targets & networks | Podman + `podman compose` (most labs) |
| VirtualBox **or** Hyper-V | 7.1.x / Win 11 | Windows & AD VMs (Docker can't model these) | VMware Workstation Player |
| WSL2 (Windows hosts) | Ubuntu 24.04 | Linux tooling on a Windows host | Full Kali VM |

## Discovery &amp; scanning

| Tool | Tested version | Purpose | Fallback |
|---|---|---|---|
| Nmap | 7.95 | Host discovery, port scan, version/OS detection, NSE scripts | `masscan` (speed) + manual `nc`/`/dev/tcp`; `rustscan` front-end |
| RustScan | 2.3.x | Fast port sweep feeding Nmap | `nmap -T4 --min-rate`; `masscan` |
| masscan | 1.3.x | Very fast wide-range port sweep | `nmap` with `--min-rate` |
| tcpdump / Wireshark | 4.99 / 4.4 | See what a tool actually puts on the wire | `tshark`; `ngrep` |

## Recon / OSINT

| Tool | Tested version | Purpose | Fallback |
|---|---|---|---|
| dnsx / dnsrecon | latest / 1.x | DNS enumeration | `dig`, `host`, `nslookup` (always available) |
| subfinder | 2.6.x | Passive subdomain discovery | `amass`; certificate-transparency queries via `curl` to crt.sh |
| amass | 4.x | Attack-surface mapping | `subfinder` + manual sources |

## Web / API

| Tool | Tested version | Purpose | Fallback |
|---|---|---|---|
| Burp Suite (Community) | 2025.x | Intercepting proxy, repeater, decoder | OWASP ZAP; `mitmproxy` |
| ffuf | 2.1.x | Content/parameter fuzzing | `feroxbuster`; `gobuster` |
| feroxbuster | 2.11.x | Recursive content discovery | `ffuf`; `gobuster` |
| gobuster | 3.6.x | Directory/DNS/vhost brute forcing | `ffuf` |
| sqlmap | 1.8.x | SQL-injection confirmation & exploitation | manual injection (taught first) |
| nikto | 2.5.x | Quick web server misconfig checks | manual header/robots review |
| nuclei | 3.x | Templated known-issue checks | manual verification |
| curl / httpie | 8.x / 3.x | Raw HTTP by hand — the ground truth | `openssl s_client` for TLS |

## Credentials

| Tool | Tested version | Purpose | Fallback |
|---|---|---|---|
| Hashcat | 6.2.6 | GPU/CPU offline hash cracking | John the Ripper |
| John the Ripper (jumbo) | 1.9.0-j | CPU cracking, format detection (`*2john`) | Hashcat |
| hydra | 9.5 | Online login testing (lab only) | `ncrack`; `medusa`; scripted `ffuf` |
| SecLists | rolling | Wordlists (rockyou, usernames, discovery) | curated project lists |

## Windows / Active Directory

| Tool | Tested version | Purpose | Fallback |
|---|---|---|---|
| NetExec (nxc) | 1.x | SMB/WinRM/LDAP enumeration & auth (CrackMapExec successor) | Impacket scripts individually |
| Impacket | 0.12.x | Protocol-level tooling (secretsdump, psexec, GetUserSPNs…) | manual protocol interaction; NetExec |
| BloodHound CE + collectors | 6.x / SharpHound | AD attack-path graph analysis | manual LDAP queries; `bloodhound.py` |
| Responder | 3.x | LLMNR/NBT-NS/mDNS poisoning (lab only) | `mitm6` for IPv6 |
| Rubeus / Certipy | latest | Kerberos & AD CS abuse | Impacket equivalents |
| Evil-WinRM | 3.x | Interactive WinRM shell | `nxc winrm`; native PowerShell remoting |
| mimikatz (concepts) | 2.2.x | Credential material on Windows (taught mostly as concept) | `nanodump`, `pypykatz` (offline) |

## Post-exploitation / privesc / pivoting

| Tool | Tested version | Purpose | Fallback |
|---|---|---|---|
| linPEAS / winPEAS | rolling | Enumeration checklists for local privesc | `LinEnum`; manual methodology (taught first) |
| pspy | 1.2.x | Watch processes/cron without root | manual `/proc` inspection |
| Chisel | 1.10.x | TCP/UDP tunneling over HTTP for pivoting | `ssh -L/-R/-D`; `socat` |
| proxychains-ng | 4.17 | Route tools through a SOCKS pivot | `-x` proxy flags where supported |
| socat / netcat (OpenBSD) | 1.8 / 1.226 | Sockets, relays, listeners | `/dev/tcp`; `ncat` (from Nmap) |

## Exploitation

| Tool | Tested version | Purpose | Fallback |
|---|---|---|---|
| Metasploit Framework | 6.4.x | Exploit/payload framework, `msfvenom`, handlers | manual exploit + `nc` listener (taught first) |
| pwntools | 4.x | Exploit development (I/O, ELF, ROP, shellcode) | raw `struct`/`socket` scripting |
| GDB + pwndbg / GEF | 15.x | Debugging memory-corruption labs | `radare2`; `lldb` |
| Ghidra | 11.x | Static reverse engineering | `radare2`/`Cutter`; `objdump` |

## Containers / cloud

| Tool | Tested version | Purpose | Fallback |
|---|---|---|---|
| kubectl / kind | 1.31 / 0.24 | Interact with / stand up a local k8s cluster | `minikube`; Docker-only labs |
| trivy | 0.5x | Image/config vulnerability scanning | `grype`; manual `docker history` |
| LocalStack | 3.x | Local AWS API for the cloud lab | Moto; documented read-only real-tenant exercises |
| Pacu (concepts) | latest | AWS exploitation framework (concept-level in the local sim) | manual AWS CLI against LocalStack |

## Notes

- The course teaches the **manual** technique before any of the above where feasible, so the tool
  is a convenience, not a dependency.
- Anything requiring a GPU (heavy Hashcat) is flagged in the lesson's `.lab` box; CPU-friendly
  alternatives and pre-cracked examples are provided.
- `scripts/install-tools.sh` (Debian/Ubuntu/WSL) installs the open-source subset with pinned
  versions where the package manager allows.
