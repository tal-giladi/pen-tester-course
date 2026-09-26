#!/usr/bin/env bash
# install-tools.sh — install the open-source subset of the course toolset on a
# Debian/Ubuntu/WSL attacker box. Pins where the package manager allows; otherwise
# installs current stable. See ../TOOLS.md for the tested versions and fallbacks.
#
# Usage:  bash scripts/install-tools.sh          (uses sudo for apt)
# This installs OFFENSIVE tooling — use it only on your own attacker workstation for
# authorized testing / this course's isolated labs.
set -euo pipefail

echo "[*] This installs the course's open-source tools. Ctrl-C within 5s to abort."
sleep 5
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

echo "[*] apt packages..."
$SUDO apt-get update
$SUDO apt-get install -y --no-install-recommends \
    nmap netcat-openbsd socat curl wget dnsutils whois \
    python3 python3-pip python3-venv git jq \
    hydra john hashcat \
    proxychains4 openssh-client sshpass \
    gobuster ffuf \
    docker.io 2>/dev/null || true

echo "[*] pipx / pip tools (impacket, netexec, etc.)..."
$SUDO apt-get install -y --no-install-recommends pipx || $SUDO pip3 install --break-system-packages pipx || true
python3 -m pipx ensurepath 2>/dev/null || true
for tool in impacket netexec; do
  pipx install "$tool" 2>/dev/null || pip3 install --break-system-packages "$tool" 2>/dev/null || \
    echo "  ! could not install $tool via pip — see TOOLS.md fallbacks"
done

echo "[*] SecLists wordlists (large; optional)..."
if [ ! -d /usr/share/seclists ]; then
  $SUDO git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists 2>/dev/null || \
    echo "  ! skipped SecLists (clone failed) — install manually if needed"
fi

cat <<'NOTE'

[+] Done (best-effort). Notable tools and where to get them if apt didn't provide them:
    - Burp Suite Community      -> portswigger.net/burp (GUI; or use OWASP ZAP / mitmproxy)
    - BloodHound CE + collectors-> github.com/SpecterOps/BloodHound
    - feroxbuster               -> github.com/epi052/feroxbuster (cargo/binary release)
    - Chisel                    -> github.com/jpillora/chisel (binary release)
    - Evil-WinRM, Rubeus, Certipy, mimikatz -> per-tool repos (see TOOLS.md)
    - Metasploit                -> apt install metasploit-framework (or the Rapid7 installer)
Kali/Parrot already ship most of these. Verify versions against TOOLS.md.
NOTE
