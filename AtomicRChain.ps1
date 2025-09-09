#Requires -Version 5.1
[CmdletBinding()]
param(
  [string]$AtomicRoot = "C:\AtomicRedTeam",
  [string]$OutCsv = "$env:USERPROFILE\Desktop\atomic_run_log.csv",
  [string]$ArtifactsDir = "$env:USERPROFILE\Desktop\atomic_outputs",
  [int]$OutputChars = 800,
  [switch]$IncludeDestructive,
  [switch]$DiscoveryOnly
)

# TTPs required by the client (from CSV)
$RequiredTTPs = @(
  'T1070.001','T1574.001','T1112','T1564.008','T1219','T1049','T1218.007','T1484.001',
  'T1518.001','T1218.005','T1003.003','T1562.004','T1016','T1558','T1135','T1087.002',
  'T1548.002','T1056.001','T1057','T1562.008','T1048.003','T1489','T1055.001','T1562.001'
)

# Parent→sub-tech mapping for coverage (Atomic uses sub-tech IDs)
$TtpAliases = @{
  'T1558' = @('T1558.003','T1558.004')  # Kerberoast + AS-REP roast covers parent ask (and UnPAC-the-Hash style)
}


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

function Safe-OneLine {
  param([string]$s)
  if (-not $s) { return "" }
  $s = $s -replace "\r?\n", " ; "
  $s = ($s -replace "\s+", " ").Trim()
  return $s
}

# Resolve the executor and the command that Atomic will run (best-effort)
function Resolve-AtomicDetails {
  param(
    [string]$Technique,
    [int]$TestNumber,
    [hashtable]$InputArgs
  )
  $execName = ""
  $cmdLine  = ""

  try {
    $t = Get-AtomicTechnique -Technique $Technique -PathToAtomicsFolder "$AtomicRoot\atomics"
    $tn = [Math]::Max(1, $TestNumber)
    $idx = $tn - 1
    if ($t.atomic_tests.Count -gt $idx) {
      $test = $t.atomic_tests[$idx]
      # executor name
      if ($test.executor -and $test.executor.name) { $execName = [string]$test.executor.name }
      # command template
      if ($test.executor -and $test.executor.command) { $cmdLine = [string]$test.executor.command }

      # placeholder replacement #{arg}
      if ($test.input_arguments) {
        $keys = @()
        foreach ($kv in $test.input_arguments.PSObject.Properties) { $keys += $kv.Name }
        foreach ($k in $keys) {
          $placeholder = '#{' + $k + '}'
          $val = $null
          if ($InputArgs -and $InputArgs.ContainsKey($k)) {
            $val = [string]$InputArgs[$k]
          } else {
            $defProp = $test.input_arguments.$k.PSObject.Properties['default']
            if ($defProp) { $val = [string]$defProp.Value }
          }
          if ($null -ne $val) { $cmdLine = $cmdLine.Replace($placeholder, $val) }
        }
      }
    }
  } catch {
    # ignore; leave empty
  }

  $cmdLine = Safe-OneLine $cmdLine
  return [pscustomobject]@{ Executor = $execName; ResolvedCommand = $cmdLine }
}

function Start-Atomic {
  param(
    [string]$Technique,
    [int[]]$Tests,
    [hashtable]$InputArgs,
    [string]$Note,
    [switch]$Dangerous
  )

  if ($Dangerous -and -not $IncludeDestructive) {
    Write-Host "[-] Skipping $Technique ($Note) because -IncludeDestructive was not set." -ForegroundColor Yellow
    return
  }

  if (-not $Tests -or $Tests.Count -eq 0) { $Tests = @(1) }

  foreach ($tn in $Tests) {
    $tsStart = Get-Date
    $status  = "Unknown"
    $msg     = ""
    $snippet = ""
    $execName = ""
    $resolved = ""

    # transcript path
    $safeNote = ($Note -replace '[^a-zA-Z0-9_\-\. ]','_') -replace '\s+','_'
    $logPath  = Join-Path $ArtifactsDir ("{0}_{1}_{2}_{3}.log" -f $Technique, $tn, $safeNote, (Get-Date -Format 'yyyyMMdd-HHmmss'))

    # try to resolve executor + command (before running)
    $det = Resolve-AtomicDetails -Technique $Technique -TestNumber $tn -InputArgs $InputArgs
    $execName = $det.Executor
    $resolved = $det.ResolvedCommand

    try {
      Write-Host "[>] $Technique (test $tn) — $Note"
      try { Stop-Transcript | Out-Null } catch {}
      Start-Transcript -Path $logPath -Force | Out-Null

      Invoke-AtomicTest $Technique -TestNumbers $tn -GetPrereqs -PathToAtomicsFolder "$AtomicRoot\atomics" -InputArgs $InputArgs -ErrorAction Stop | Out-Null
      Invoke-AtomicTest $Technique -TestNumbers $tn -PathToAtomicsFolder "$AtomicRoot\atomics" -InputArgs $InputArgs -ErrorAction Stop | Out-Null

      $status = "Executed"
    } catch {
      $status = "Error"
      $msg = $_.Exception.Message
      Write-Warning "  ! $Technique test $tn failed: $msg"
    } finally {
      try { Stop-Transcript | Out-Null } catch {}
      $tsEnd = Get-Date

      if (Test-Path $logPath) {
        $raw = Get-Content -Path $logPath -Raw -ErrorAction SilentlyContinue
        # remove transcript headers/footers (optional best-effort)
        $clean = $raw -replace '(?s)\*{5,}.*?\*{5,}',''
        $clean = Safe-OneLine $clean
        if ($clean.Length -gt $OutputChars) {
          $snippet = $clean.Substring([Math]::Max(0, $clean.Length - $OutputChars))
        } else {
          $snippet = $clean
        }
      }

      $row = [pscustomobject]@{
        Timestamp      = $tsStart.ToString("s")
        TechniqueID    = $Technique
        TestNumber     = $tn
        Note           = $Note
        Status         = $status
        DurationSec    = [int]($tsEnd - $tsStart).TotalSeconds
        Message        = $msg
        Executor       = $execName
        ResolvedCommand= $resolved
        OutputPath     = $logPath
        OutputSnippet  = $snippet
      }
      $append = Test-Path $OutCsv
      $row | Export-Csv -Path $OutCsv -NoTypeInformation -Append:$append
    }
  }
}

# ----------------- Bootstrap -----------------
Ensure-InvokeAtomic
$null = New-Item -ItemType Directory -Force -Path (Split-Path $OutCsv) -ErrorAction SilentlyContinue
$null = New-Item -ItemType Directory -Force -Path $ArtifactsDir -ErrorAction SilentlyContinue
Write-Host "[*] Results -> $OutCsv"
Write-Host "[*] Logs    -> $ArtifactsDir`n"

# ----------------- Chain definition -----------------
$chain = @()

# --- Already present / Discovery & basics ---
$chain += @{ T='T1082'     ; N='System Information Discovery'               ; Tests=@(1); Args=@{}; Danger=$false }
$chain += @{ T='T1033'     ; N='Account Discovery (whoami /all)'            ; Tests=@(1); Args=@{}; Danger=$false }
$chain += @{ T='T1046'     ; N='Network Service Discovery'                  ; Tests=@(1); Args=@{}; Danger=$false }
$chain += @{ T='T1087.002' ; N='Domain Account Discovery'                   ; Tests=@(1); Args=@{}; Danger=$false } # REQUIRED
$chain += @{ T='T1482'     ; N='Domain Trust Discovery'                     ; Tests=@(1); Args=@{}; Danger=$false }

# --- REQUIRED new discovery items ---
$chain += @{ T='T1049'     ; N='System Network Connections Discovery'       ; Tests=@(1); Args=@{}; Danger=$false } # REQUIRED
$chain += @{ T='T1016'     ; N='System Network Configuration Discovery'     ; Tests=@(1); Args=@{}; Danger=$false } # REQUIRED
$chain += @{ T='T1057'     ; N='Process Discovery (tasklist/Get-Process)'   ; Tests=@(1); Args=@{}; Danger=$false } # REQUIRED
$chain += @{ T='T1518.001' ; N='Security Software Discovery (wmic)'         ; Tests=@(1); Args=@{}; Danger=$false } # REQUIRED
$chain += @{ T='T1135'     ; N='Network Share Discovery (net view/share)'   ; Tests=@(1); Args=@{}; Danger=$false } # REQUIRED

# --- Signed binary proxy execution family ---
$chain += @{ T='T1218.011' ; N='Signed Binary Proxy Execution (rundll32)'   ; Tests=@(1); Args=@{}; Danger=$false }
$chain += @{ T='T1218.007' ; N='Signed Binary Proxy (msiexec)'              ; Tests=@(1); Args=@{}; Danger=$false } # REQUIRED
$chain += @{ T='T1218.005' ; N='Signed Binary Proxy (mshta)'                ; Tests=@(1); Args=@{}; Danger=$false } # REQUIRED

# --- Hijack execution flow / DLL tricks ---
$chain += @{ T='T1574.001' ; N='DLL Search Order Hijacking (Atomic sample)' ; Tests=@(1); Args=@{}; Danger=$true }  # REQUIRED (may need admin / AV exclusions)

# --- Remote access software (sim/safe) ---
$chain += @{ T='T1219'     ; N='Remote Access Software (ScreenConnect/AnyDesk simulation)' ; Tests=@(1); Args=@{}; Danger=$true } # REQUIRED

# --- Ingress tool transfer / C2 ---
$chain += @{ T='T1105'     ; N='Ingress Tool Transfer (certutil)'           ; Tests=@(1); Args=@{ input_url="https://example.com/file.bin"; output_file="$env:TEMP\file.bin" }; Danger=$false }

# --- Credential Access ---
$chain += @{ T='T1558.003' ; N='Kerberoasting'                              ; Tests=@(1); Args=@{}; Danger=$false } # covers parent T1558 ask
$chain += @{ T='T1558.004' ; N='AS-REP Roasting'                            ; Tests=@(1); Args=@{}; Danger=$false } # covers parent T1558 ask
$chain += @{ T='T1003.001' ; N='OS Credential Dumping (LSASS/comsvcs)'      ; Tests=@(1); Args=@{}; Danger=$true  }
$chain += @{ T='T1003.003' ; N='NTDS Credential Dumping from Shadow Copy'   ; Tests=@(1); Args=@{}; Danger=$true  } # REQUIRED

# --- Lateral Movement (proof-of-intent atomics) ---
$chain += @{ T='T1047'     ; N='WMI Execution (simulation/local)'           ; Tests=@(1); Args=@{}; Danger=$false }
$chain += @{ T='T1021.006' ; N='WinRM (simulation)'                          ; Tests=@(1); Args=@{}; Danger=$false }
$chain += @{ T='T1021.002' ; N='SMB/PSExec (simulation)'                     ; Tests=@(1); Args=@{}; Danger=$false }

# --- Defense Evasion & Policy tamper ---
$chain += @{ T='T1112'     ; N='Modify Registry (Enable WDigest)'           ; Tests=@(1); Args=@{}; Danger=$true  } # REQUIRED
$chain += @{ T='T1070.001' ; N='Clear Windows Event Logs'                   ; Tests=@(1); Args=@{}; Danger=$true  } # REQUIRED
$chain += @{ T='T1562.004' ; N='Impair Defenses (Firewall netsh block UDP)' ; Tests=@(1); Args=@{}; Danger=$true  } # REQUIRED
$chain += @{ T='T1562.008' ; N='Disable Security Tools (Defender off)'      ; Tests=@(1); Args=@{}; Danger=$true  } # REQUIRED
$chain += @{ T='T1562.001' ; N='Disable/Modify Security Tools (services)'   ; Tests=@(1); Args=@{}; Danger=$true  } # REQUIRED
$chain += @{ T='T1548.002' ; N='Bypass UAC (fodhelper/cmstp technique)'     ; Tests=@(1); Args=@{}; Danger=$true  } # REQUIRED

# --- Persistence / Privilege / Policy ---
$chain += @{ T='T1053.005' ; N='Scheduled Task (daily)'                     ; Tests=@(1); Args=@{}; Danger=$false }
$chain += @{ T='T1547.001' ; N='Run Key Persistence'                        ; Tests=@(1); Args=@{}; Danger=$false }
$chain += @{ T='T1136.001' ; N='Create Local Account'                       ; Tests=@(1); Args=@{}; Danger=$false }
$chain += @{ T='T1098'     ; N='Account Manipulation (add to group)'        ; Tests=@(1); Args=@{}; Danger=$false }
$chain += @{ T='T1484.001' ; N='Domain Policy Modification (GPO)'           ; Tests=@(1); Args=@{}; Danger=$true  } # REQUIRED (likely fail without DA — that’s OK, still logs)

# --- Collection ---
$chain += @{ T='T1056.001' ; N='Keylogging (simulation)'                    ; Tests=@(1); Args=@{}; Danger=$false } # REQUIRED
$chain += @{ T='T1560.001' ; N='Archive Collected Data (7-Zip)'             ; Tests=@(1); Args=@{}; Danger=$false }

# --- Exfiltration ---
$chain += @{ T='T1048.003' ; N='Exfil over Unencrypted Non-C2 (FTP)'        ; Tests=@(1); Args=@{}; Danger=$false } # REQUIRED
# (Optionally also add T1041 HTTP exfil if you use it)
# $chain += @{ T='T1041'    ; N='Exfil over HTTP (simulated)'                ; Tests=@(1); Args=@{}; Danger=$false }

# --- Impact ---
$chain += @{ T='T1489'     ; N='Service Stop (simulate impact)'             ; Tests=@(1); Args=@{}; Danger=$true  } # REQUIRED
$chain += @{ T='T1490'     ; N='Inhibit System Recovery (vssadmin/bcdedit)' ; Tests=@(1); Args=@{}; Danger=$true  }
$chain += @{ T='T1486'     ; N='Data Encrypted for Impact (simulated)'      ; Tests=@(1); Args=@{}; Danger=$true  }

# ---- Coverage verification (shows what's missing BEFORE execution) ----
$present = ($chain | ForEach-Object { $_.T } | Sort-Object -Unique)

# Expand aliases so 'T1558' is considered covered by its subs
$coveredAlso = @()
foreach ($k in $TtpAliases.Keys) {
  if ($TtpAliases[$k] | Where-Object { $_ -in $present }) { $coveredAlso += $k }
}
$presentPlus = ($present + $coveredAlso) | Sort-Object -Unique

$missing = $RequiredTTPs | Where-Object { $_ -notin $presentPlus }
if ($missing.Count -gt 0) {
  Write-Warning ("[!] Missing REQUIRED TTPs: {0}" -f ($missing -join ', '))
} else {
  Write-Host "[✓] All REQUIRED TTPs are included in the chain."
}


# ----------------- Execute -----------------
foreach ($step in $chain) {
  Start-Atomic -Technique $step.T -Tests $step.Tests -InputArgs $step.Args -Note $step.N -Dangerous:([bool]$step.Danger)
}

Write-Host "`n[✓] Chain complete."
Write-Host "[*] CSV : $OutCsv"
Write-Host "[*] Logs: $ArtifactsDir"
