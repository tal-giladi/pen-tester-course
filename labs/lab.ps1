# lab.ps1 — Windows PowerShell wrapper mirroring ./labs/lab. Read it before running.
#   ./labs/lab.ps1 up|down|reset|status|check [lab-dir]
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidateSet('up','down','reset','status','check')][string]$Command,
  [string]$Lab
)
$ErrorActionPreference = 'Stop'
$LabsDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Prefix  = 'ptlab'
$ExtHost = '1.1.1.1'
$Timeout = 3

function Compose { param([string]$dir, [string[]]$rest)
  $file = Join-Path $LabsDir "$dir/docker-compose.yml"
  if (-not (Test-Path $file)) { throw "No docker-compose.yml in labs/$dir" }
  & docker compose -f $file @rest
}
function LabContainers { docker ps --filter "name=$Prefix" --format '{{.Names}}' }
function EgressReachable { param([string]$c)
  $script = "if command -v wget >/dev/null 2>&1; then wget -q -T $Timeout -O /dev/null http://$ExtHost 2>/dev/null && exit 0 || exit 1; " +
            "elif command -v curl >/dev/null 2>&1; then curl -s -m $Timeout -o /dev/null http://$ExtHost 2>/dev/null && exit 0 || exit 1; " +
            "elif command -v nc >/dev/null 2>&1; then nc -z -w $Timeout $ExtHost 80 >/dev/null 2>&1 && exit 0 || exit 1; else exit 2; fi"
  docker exec $c sh -c $script *> $null
  return ($LASTEXITCODE -eq 0)
}

switch ($Command) {
  'up'     { if(-not $Lab){throw 'lab dir required'}; Compose $Lab @('up','-d','--build'); Write-Host "Up: $Lab. Run './labs/lab.ps1 check' before attacking." }
  'down'   { if(-not $Lab){throw 'lab dir required'}; Compose $Lab @('down','-v','--remove-orphans'); Write-Host "Down: $Lab" }
  'reset'  { if(-not $Lab){throw 'lab dir required'}; Compose $Lab @('down','-v','--remove-orphans'); Compose $Lab @('up','-d','--build'); Write-Host "Reset: $Lab" }
  'status' {
    Write-Host 'Running lab containers:'
    docker ps --filter "name=$Prefix" --format '  {{.Names}}  {{.Image}}  {{.Status}}'
    Write-Host "`nNetworks:"; docker network ls --filter 'name=ptlab' --format '  {{.Name}}  {{.Driver}}'
  }
  'check'  {
    $any=$false; $leak=$false
    Write-Host "Isolation check — attempting egress to $ExtHost from each lab container:"
    foreach ($c in (LabContainers)) {
      $any=$true
      if (EgressReachable $c) {
        if ($c -match 'leaky') { Write-Host "  [DEMO] $c  CAN reach the Internet  (intentional bad example in lab-00)" }
        else { Write-Host "  [FAIL] $c  CAN reach the Internet  <-- NOT SAFE. Fix isolation."; $leak=$true }
      } else { Write-Host "  [ OK ] $c  blocked (isolated)" }
    }
    if (-not $any) { Write-Host "  (no $Prefix* containers running)"; break }
    if ($leak) { Write-Host "`nRESULT: FAIL — a target can reach the Internet. Do not proceed."; exit 1 }
    Write-Host "`nRESULT: OK — no unexpected egress. Safe to proceed."
  }
}
