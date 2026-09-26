# lab-06-ad — provisioning notes (validate on your own isolated VMs)

Reproducible steps to build the `lab.local` forest and plant the deliberate misconfigurations.
Run these on **throwaway, host-only, no-egress** Windows evaluation VMs. Every value is synthetic.
These are notes to apply with Vagrant+DSC or by hand; adapt paths/versions to your media.

## 1. DC01 — promote the domain

```powershell
# On DC01 (static IP 192.168.56.10, host-only adapter only)
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName "lab.local" -DomainNetbiosName "LAB" `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "Lab-Passw0rd!" -AsPlainText -Force) -Force
# reboots
```

## 2. Accounts &amp; deliberate weaknesses (on DC01 after promotion)

```powershell
$pw = ConvertTo-SecureString 'Lab-Passw0rd!' -AsPlainText -Force
New-ADUser lowpriv  -AccountPassword $pw -Enabled $true                      # your foothold
New-ADUser svc_sql  -AccountPassword $pw -Enabled $true `
  -ServicePrincipalNames "MSSQLSvc/srv01.lab.local:1433"                      # Kerberoastable (has SPN)
New-ADUser svc_web  -AccountPassword $pw -Enabled $true
Set-ADAccountControl -Identity svc_web -DoesNotRequirePreAuth $true           # AS-REP roastable

# An abusable ACL edge: give a low-priv group GenericAll over a higher-priv user (plant a path)
New-ADGroup -Name "Helpdesk" -GroupScope Global
Add-ADGroupMember Helpdesk lowpriv
# (apply GenericAll for Helpdesk on a target principal via dsacls / Set-Acl — see below)
# dsacls "CN=svc_web,CN=Users,DC=lab,DC=local" /G "LAB\Helpdesk:GA"

# A benign flag readable only by Domain Admins
"LAB-FLAG-ad-domain-admin" | Out-File C:\DA-only-flag.txt
icacls C:\DA-only-flag.txt /inheritance:r /grant:r "Domain Admins:F" "SYSTEM:F"
```

## 3. SRV01 &amp; WS01 — join the domain

```powershell
# On each member (static IP, host-only only), then reboot:
Add-Computer -DomainName lab.local -Credential (Get-Credential LAB\Administrator) -Restart
```

Plant a **credential-reuse / local-admin** path: e.g. make `lowpriv` (or a service account) a local
admin on WS01, or cache a higher-priv credential on SRV01 — so pass-the-hash / reuse from a foothold
opens another host (M11). Keep it discoverable but not signposted.

## 4. Snapshot

Log out, snapshot every VM as `clean`. Reset = restore that snapshot.

## Fallback: GOAD

If you prefer a maintained builder, **GOAD (Game of Active Directory)** provisions an equivalent
intentionally-vulnerable forest via Vagrant/Ansible. Use it on the same host-only, no-egress
network and take a clean snapshot. Our exercises map onto GOAD's environment (Kerberoasting,
AS-REP, ACL abuse, delegation, credential reuse) — the *methodology* is identical.

<div class="callout legal">

Isolation is mandatory: host-only/internal virtual network, no NAT/bridged adapter, verified from
inside a VM (external ping/curl must fail) before any attack. Evaluation media only.

</div>
