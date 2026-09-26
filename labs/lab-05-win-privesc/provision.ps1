<#
provision.ps1 — set up lab-05-win-privesc on a THROWAWAY, ISOLATED Windows eval VM.

LAB TARGET ONLY. Run once, elevated, on a Windows 10/11 evaluation VM attached to a
host-only (no-egress) network. It creates a low-priv account, plants several INDEPENDENT
local-privesc misconfigurations, and drops a benign admin-only flag. Read before running.
Take a `clean` snapshot AFTER running this and log out; reset = restore that snapshot.

Nothing here reaches outside this VM. Every value is synthetic.
#>
$ErrorActionPreference = 'Stop'

Write-Host '[*] Creating low-privilege foothold account lab\lowpriv ...'
$pw = ConvertTo-SecureString 'Lab-Passw0rd!' -AsPlainText -Force
if (-not (Get-LocalUser -Name 'lowpriv' -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name 'lowpriv' -Password $pw -FullName 'Lab Low Priv' -Description 'lab foothold' | Out-Null
    Add-LocalGroupMember -Group 'Users' -Member 'lowpriv'
}

Write-Host '[*] Dropping the objective flag (admin/SYSTEM-only) ...'
$flag = 'C:\flag.txt'
"LAB-FLAG-win-privesc-$([guid]::NewGuid())" | Out-File -FilePath $flag -Encoding ascii -Force
# Restrict to Administrators + SYSTEM only.
icacls $flag /inheritance:r /grant:r 'Administrators:F' 'SYSTEM:F' | Out-Null

# --- Vector 1: service with a WEAK ACL (a normal user can reconfigure its binPath) -------
Write-Host '[*] Vector 1: weak-ACL service (lab_weaksvc) ...'
New-Service -Name 'lab_weaksvc' -BinaryPathName 'C:\Windows\System32\svchost.exe -k lab' `
    -DisplayName 'Lab Weak Service' -StartupType Manual -ErrorAction SilentlyContinue | Out-Null
# Grant Users the ability to change the service config + start/stop (the misconfig).
# SDDL: allow (A) service-all-access-ish to Authenticated Users (AU).
$sddl = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;RPWPCR;;;AU)(A;;CCLCSWLOCRRC;;;IU)'
& sc.exe sdset lab_weaksvc $sddl | Out-Null

# --- Vector 2: UNQUOTED service path with a writable intermediate directory --------------
Write-Host '[*] Vector 2: unquoted service path (lab_unquoted) ...'
New-Item -ItemType Directory -Path 'C:\Lab Apps\Service' -Force | Out-Null
# Path has spaces and is NOT quoted -> Windows tries C:\Lab.exe, then C:\Lab Apps\...
New-Service -Name 'lab_unquoted' -BinaryPathName 'C:\Lab Apps\Service\svc.exe' `
    -DisplayName 'Lab Unquoted Service' -StartupType Manual -ErrorAction SilentlyContinue | Out-Null
# Make an intermediate dir writable by normal users (the misconfig).
icacls 'C:\Lab Apps' /grant 'Users:(OI)(CI)M' | Out-Null

# --- Vector 3: AlwaysInstallElevated (MSI installs run as SYSTEM) -------------------------
Write-Host '[*] Vector 3: AlwaysInstallElevated ...'
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Value 1 -PropertyType DWord -Force | Out-Null
New-Item -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Force | Out-Null
New-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Value 1 -PropertyType DWord -Force | Out-Null

# --- Vector 4: autorun binary in a user-writable location (autorun/DLL-hijack style) ------
Write-Host '[*] Vector 4: writable autorun target ...'
New-Item -ItemType Directory -Path 'C:\Lab Apps\Autorun' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'LabHelper' `
    -Value 'C:\Lab Apps\Autorun\helper.exe' -PropertyType String -Force | Out-Null
icacls 'C:\Lab Apps\Autorun' /grant 'Users:(OI)(CI)M' | Out-Null

Write-Host ''
Write-Host '[+] Provisioning complete. Now: log out, take a "clean" snapshot, then log in as'
Write-Host '    lab\lowpriv / Lab-Passw0rd! to begin. Objective: read C:\flag.txt as admin/SYSTEM.'
Write-Host '    Verify isolation from inside the VM before attacking (external ping must fail).'
