
<# Atomic-RansomSuite.ps1 — Ransomware-style Atomic test launcher (safe by default)

Profiles
  Core     : SAFE discovery + staging + impact-like (T1486) with cleanup
  Extended : Adds persistence/LOLbins/remote exec (still non-destructive; needs admin in places)
  Impact   : Adds truly destructive impact (e.g., T1490, T1489) — ONLY with -Unsafe in a snapshot!

Usage (elevated PowerShell recommended):
  # Quick safe run (Core)
  powershell -NoProfile -ExecutionPolicy Bypass -File .\Atomic-RansomSuite.ps1 -Install -GetPrereqs -Execute -Cleanup

  # See what will run (no exec)
  .\Atomic-RansomSuite.ps1 -ShowOnly -Profile Core

  # Extended profile (still safe) + cleanup
  .\Atomic-RansomSuite.ps1 -Profile Extended -GetPrereqs -Execute -Cleanup

  # Impact profile (SNAPSHOT ONLY) — includes T1490, T1489
  .\Atomic-RansomSuite.ps1 -Profile Impact -GetPrereqs -Execute -Cleanup -Unsafe

  # Add your own technique IDs on top of a profile
  .\Atomic-RansomSuite.ps1 -Profile Core -Execute -Cleanup -ExtraTechniques T1218.011,T1218.010
#>

[CmdletBinding()]
param(
  [switch]$Install,
  [switch]$GetPrereqs,
  [switch]$Execute,
  [switch]$Cleanup,
  [switch]$ShowOnly,

  [ValidateSet('Core','Extended','Impact')]
  [string]$Profile = 'Core',

  [string[]]$ExtraTechniques,

  [string]$AtomicsPath = 'C:\AtomicRedTeam\atomics',
  [switch]$Unsafe
)

$ErrorActionPreference = 'Stop'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

function Ensure-Atomic {
  try { Get-PSRepository -Name PSGallery | Out-Null } catch { Register-PSRepository -Default }

  if ($Install -or -not (Get-Module -ListAvailable -Name Invoke-AtomicRedTeam)) {
    Write-Host "[*] Installing Invoke-AtomicRedTeam + powershell-yaml..." -ForegroundColor Cyan
    Install-Module -Name Invoke-AtomicRedTeam,powershell-yaml -Scope CurrentUser -Force
  }
  Import-Module Invoke-AtomicRedTeam -Force

  if (-not (Test-Path $AtomicsPath)) {
    Write-Host "[*] Downloading atomics to C:\AtomicRedTeam ..." -ForegroundColor Cyan
    $tmp = Join-Path $env:TEMP "install-atomicredteam.ps1"
    Invoke-WebRequest 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing -OutFile $tmp
    . $tmp
    Install-AtomicRedTeam -getAtomics | Out-Null
  }

  if (-not (Test-Path $AtomicsPath)) { throw "Atomics folder not found at '$AtomicsPath'." }

  $script:LogDir = 'C:\AtomicRedTeam\runlogs'
  New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
  $script:Transcript = Join-Path $LogDir ("AtomicRun_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
  try { Stop-Transcript | Out-Null } catch {}
  Start-Transcript -Path $Transcript | Out-Null

  $PSDefaultParameterValues = @{ "Invoke-AtomicTest:PathToAtomicsFolder" = $AtomicsPath }
}

function Build-Techniques([string]$profile) {
  # Curated set oriented to ransomware workflows (Windows focus).
  # Everything here has Atomic cleanup; still run in a lab.
  $core = @(
    'T1486',         # Data Encrypted for Impact (safe atomics workspace)
    'T1083',         # File & Directory Discovery
    'T1082',         # System Information Discovery
    'T1016',         # System Network Configuration Discovery
    'T1057',         # Process Discovery
    'T1033',         # Account Discovery
    'T1046',         # Network Service Scanning
    'T1105',         # Ingress Tool Transfer (harmless download)
    'T1560.001',     # Archive Collected Data: Archive via Utility
    'T1053.005'      # Scheduled Task (persistence-lite; Atomic cleans up)
  )

  $extended = $core + @(
    'T1218.011',     # Rundll32 (Signed Binary Proxy Execution)
    'T1218.010',     # Regsvr32 (Signed Binary Proxy Execution)
    'T1047',         # WMI (exec/enum)
    'T1021.002',     # SMB/Windows Admin Shares (where applicable)
    'T1547.001',     # Registry Run Keys/Startup Folder (persistence) — cleanup included
    'T1036.003'      # Masquerading: Rename system utilities
  )

  $impact = $extended + @(
    'T1489',         # Service Stop  (IMPACT — snapshot/offline lab)
    'T1490'          # Inhibit System Recovery (IMPACT — snapshot/offline lab)
  )

  switch ($profile) {
    'Core'     { return $core }
    'Extended' { return $extended }
    'Impact'   { return $impact }
  }
}

function Filter-Destructive([string[]]$t, [switch]$Unsafe) {
  $blocked = @('T1490','T1489','T1485','T1070','T1070.004') # recovery tamper/service stop/data destroy/log clear
  if ($Unsafe) { return $t }
  $safe = $t | Where-Object { $_ -notin $blocked }
  if ($safe.Count -lt $t.Count) {
    Write-Warning "Removed destructive techniques (use -Unsafe in a SNAPSHOT lab to include): $($t | ? {$_ -in $blocked} -join ', ')"
  }
  if (-not $safe) { throw "No techniques left after safety filtering." }
  return $safe
}

# ---- Main ----
Ensure-Atomic

$techs = Build-Techniques -profile $Profile
if ($ExtraTechniques) { $techs += $ExtraTechniques }
$techs = $techs | Select-Object -Unique
$techs = Filter-Destructive -t $techs -Unsafe:$Unsafe

Write-Host "`n[INFO] Profile: $Profile  |  Techniques: $($techs -join ', ')" -ForegroundColor Cyan

if ($ShowOnly) {
  foreach ($t in $techs) { Write-Host "`n=== $t ===" -ForegroundColor Yellow; Invoke-AtomicTest $t -ShowDetailsBrief }
  Stop-Transcript | Out-Null
  Write-Host "`n[✓] Transcript: $Transcript" -ForegroundColor Cyan
  exit
}

if ($GetPrereqs) {
  foreach ($t in $techs) { Write-Host "`n[+] GetPrereqs $t" -ForegroundColor Yellow; Invoke-AtomicTest $t -GetPrereqs -Verbose }
}

if ($Execute) {
  foreach ($t in $techs) {
    Write-Host "`n[+] Execute $t" -ForegroundColor Green
    Invoke-AtomicTest $t -Confirm:$false -Verbose
  }
}

if ($Cleanup) {
  foreach ($t in $techs) {
    Write-Host "`n[+] Cleanup $t" -ForegroundColor Yellow
    Invoke-AtomicTest $t -Cleanup -Verbose
  }
}

Stop-Transcript | Out-Null
Write-Host "`n[✓] Finished. Transcript: $Transcript" -ForegroundColor Cyan
