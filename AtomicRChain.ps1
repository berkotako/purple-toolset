#Requires -Version 5.1
<#
  AtomicChainRecOut.ps1
  - Simple CSV + per-test transcripts (executor + resolved command + readable timing)
  - Prereqs Preflight: Check + Install (-CheckPrereqs then -GetPrereqs) for each test
  - PS 5.1 compatible; Istanbul time by default
#>

[CmdletBinding()]
param(
  [string]$AtomicRoot   = "C:\AtomicRedTeam",
  [string]$OutCsv       = "$env:USERPROFILE\Desktop\atomic_run_log.csv",
  [string]$ArtifactsDir = "$env:USERPROFILE\Desktop\atomic_outputs",

  # Human-readable time (Istanbul)
  [string]$TimeFormat   = 'yyyy-MM-dd HH:mm:ss.fff zzz',
  [string]$TimeZoneId   = 'Turkey Standard Time',

  [switch]$IncludeDestructive
)

$ErrorActionPreference = 'Stop'

# ----------------- Helpers -----------------
function Format-LocalTime {
  param([datetime]$dt)
  try {
    $tz = [System.TimeZoneInfo]::FindSystemTimeZoneById($TimeZoneId)
    $loc = [System.TimeZoneInfo]::ConvertTime($dt, $tz)
  } catch { $loc = $dt }
  return $loc.ToString($TimeFormat)
}
function Format-Duration {
  param([TimeSpan]$ts)
  "{0:00}:{1:00}:{2:00}.{3:000}" -f $ts.Hours, $ts.Minutes, $ts.Seconds, $ts.Milliseconds
}
function Safe-OneLine {
  param([string]$s)
  if (-not $s) { return "" }
  $s = $s -replace "\r?\n", " ; "
  ($s -replace "\s+", " ").Trim()
}

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

# Best-effort: read executor & command from technique YAML to append in log footer
function Resolve-AtomicDetails {
  param(
    [string]$Technique,
    [int]$TestNumber
  )
  $execName = ""
  $cmdLine  = ""
  try {
    $t  = Get-AtomicTechnique -Technique $Technique -PathToAtomicsFolder "$AtomicRoot\atomics"
    $ix = [Math]::Max(0, $TestNumber - 1)
    if ($t.atomic_tests.Count -gt $ix) {
      $test = $t.atomic_tests[$ix]
      if ($test.executor -and $test.executor.name)    { $execName = [string]$test.executor.name }
      if ($test.executor -and $test.executor.command) { $cmdLine  = Safe-OneLine ([string]$test.executor.command) }
    }
  } catch { }
  [pscustomobject]@{ Executor = $execName; ResolvedCommand = $cmdLine }
}

# ----------------- Prereqs Preflight -----------------
function Ensure-AllPrereqs {
  param([array]$Chain, [string]$PrereqDir)

  Write-Host "[*] Preflight: Checking & Installing Atomic prerequisites..."
  foreach ($step in $Chain) {
    $tech  = $step.T
    $note  = $step.N
    $tests = if ($step.Tests -and $step.Tests.Count -gt 0) { $step.Tests } else { @(1) }

    if ($step.Danger -and -not $IncludeDestructive) {
      Write-Host "[-] Skipping prereqs for $tech ($note) because -IncludeDestructive not set." -ForegroundColor Yellow
      continue
    }

    foreach ($tn in $tests) {
      $safeNote = (($note -replace '[^a-zA-Z0-9_\-\. ]','_') -replace '\s+','_')
      $logName  = "{0}_{1}_{2}_{3}.log" -f $tech, $tn, $safeNote, (Get-Date -Format 'yyyyMMdd-HHmmss')
      $logPath  = Join-Path $PrereqDir $logName

      $start = Get-Date
      $sw = [System.Diagnostics.Stopwatch]::StartNew()
      try {
        try { Stop-Transcript | Out-Null } catch { }
        Start-Transcript -Path $logPath -Force | Out-Null
        Invoke-AtomicTest $tech -TestNumbers $tn -CheckPrereqs -PathToAtomicsFolder "$AtomicRoot\atomics" -ErrorAction SilentlyContinue | Out-Null
        Invoke-AtomicTest $tech -TestNumbers $tn -GetPrereqs   -PathToAtomicsFolder "$AtomicRoot\atomics" -ErrorAction SilentlyContinue | Out-Null
      } catch { } finally {
        try { Stop-Transcript | Out-Null } catch { }
        $sw.Stop()
        $end = Get-Date
        try {
          $footer = @()
          $footer += ""
          $footer += "----- Prereqs Footer ----------------------------------------"
          $footer += ("Technique      : {0} (test {1})" -f $tech, $tn)
          $footer += ("Start Local    : {0}" -f (Format-LocalTime $start))
          $footer += ("End   Local    : {0}" -f (Format-LocalTime $end))
          $footer += ("Duration       : {0}" -f (Format-Duration $sw.Elapsed))
          $footer += "-------------------------------------------------------------"
          Add-Content -Path $logPath -Value ($footer -join "`r`n")
        } catch { }
      }
    }
  }
  Write-Host "[*] Preflight complete.`n"
}

# ----------------- Test Runner -----------------
function Start-Atomic {
  param(
    [string]$Technique,
    [int[]]$Tests,
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
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    $status   = "Unknown"
    $safeNote = (($Note -replace '[^a-zA-Z0-9_\-\. ]','_') -replace '\s+','_')
    $logName  = "{0}_{1}_{2}_{3}.log" -f $Technique, $tn, $safeNote, (Get-Date -Format 'yyyyMMdd-HHmmss')
    $logPath  = Join-Path $ArtifactsDir $logName

    $det      = Resolve-AtomicDetails -Technique $Technique -TestNumber $tn
    $execName = $det.Executor
    $resolved = $det.ResolvedCommand

    try {
      Write-Host "[>] $Technique (test $tn) — $Note"
      try { Stop-Transcript | Out-Null } catch { }
      Start-Transcript -Path $logPath -Force | Out-Null

      # Execute test
      Invoke-AtomicTest $Technique -TestNumbers $tn -PathToAtomicsFolder "$AtomicRoot\atomics" -ErrorAction Stop | Out-Null

      $status = "Executed"
    } catch {
      $status = "Error"
      Write-Warning ("  ! {0} test {1} failed: {2}" -f $Technique, $tn, $_.Exception.Message)
    } finally {
      try { Stop-Transcript | Out-Null } catch { }
      $sw.Stop()
      $tsEnd = Get-Date

      # Append footer with exec + command + readable times
      try {
        $footer = @()
        $footer += ""
        $footer += "----- Atomic Footer -----------------------------------------"
        $footer += ("Technique      : {0} (test {1})" -f $Technique, $tn)
        if ($execName) { $footer += ("Executor       : {0}" -f $execName) }
        if ($resolved) { $footer += ("Command        : {0}" -f $resolved) }
        $footer += ("Start Local    : {0}" -f (Format-LocalTime $tsStart))
        $footer += ("End   Local    : {0}" -f (Format-LocalTime $tsEnd))
        $footer += ("Duration       : {0}" -f (Format-Duration $sw.Elapsed))
        $footer += "-------------------------------------------------------------"
        Add-Content -Path $logPath -Value ($footer -join "`r`n")
      } catch { }

      # Simple CSV row
      $row = New-Object psobject -Property ([ordered]@{
        StartTimeLocal = Format-LocalTime $tsStart
        EndTimeLocal   = Format-LocalTime $tsEnd
        DurationHMS    = Format-Duration $sw.Elapsed
        Technique      = $Technique
        Test           = $tn
        Note           = $Note
        Status         = $status
        OutputPath     = $logPath
      })
      $append = Test-Path $OutCsv
      $row | Export-Csv -Path $OutCsv -NoTypeInformation -Append:$append
    }
  }
}

# ----------------- Setup -----------------
Ensure-InvokeAtomic
$null = New-Item -ItemType Directory -Force -Path (Split-Path $OutCsv) -ErrorAction SilentlyContinue
$null = New-Item -ItemType Directory -Force -Path $ArtifactsDir -ErrorAction SilentlyContinue
$PrereqDir = Join-Path $ArtifactsDir 'prereqs'
$null = New-Item -ItemType Directory -Force -Path $PrereqDir -ErrorAction SilentlyContinue

Write-Host "[*] CSV        -> $OutCsv"
Write-Host "[*] Logs       -> $ArtifactsDir"
Write-Host "[*] PrereqLogs -> $PrereqDir`n"

# ----------------- TTP Chain (risky ones gated) -----------------
$chain = @(
  # Discovery / inventory (safe)
  @{ T='T1049'     ; N='System Network Connections Discovery'        ; Tests=@(1); Danger=$false }
  @{ T='T1016'     ; N='System Network Configuration Discovery'      ; Tests=@(1); Danger=$false }
  @{ T='T1057'     ; N='Process Discovery'                           ; Tests=@(1); Danger=$false }
  @{ T='T1518.001' ; N='Security Software Discovery (WMIC)'         ; Tests=@(1); Danger=$false }
  @{ T='T1135'     ; N='Network Share Discovery'                     ; Tests=@(1); Danger=$false }
  @{ T='T1087.002' ; N='Domain Account Discovery'                    ; Tests=@(1); Danger=$false }

  # Signed binary proxy execution (safe)
  @{ T='T1218.007' ; N='Signed Binary Proxy (msiexec)'               ; Tests=@(1); Danger=$false }
  @{ T='T1218.005' ; N='Signed Binary Proxy (mshta)'                 ; Tests=@(1); Danger=$false }

  # Remote access software / simulators (risky)
  @{ T='T1219'     ; N='Remote Access Software (simulation)'         ; Tests=@(1); Danger=$true }

  # Hijack / injection (risky)
  @{ T='T1574.001' ; N='DLL Search Order Hijacking (sample)'         ; Tests=@(1); Danger=$true }
  @{ T='T1055.001' ; N='Process Injection (CreateRemoteThread)'      ; Tests=@(1); Danger=$true }

  # Credential Access
  @{ T='T1558.003' ; N='Kerberoasting'                               ; Tests=@(1); Danger=$false }
  @{ T='T1558.004' ; N='AS-REP Roasting'                             ; Tests=@(1); Danger=$false }
  @{ T='T1003.003' ; N='NTDS Dump from Shadow Copy'                  ; Tests=@(1); Danger=$true }

  # Defense Evasion / Impair Defenses (risky)
  @{ T='T1112'     ; N='Modify Registry (Enable WDigest)'            ; Tests=@(1); Danger=$true }
  @{ T='T1070.001' ; N='Clear Windows Event Logs'                    ; Tests=@(1); Danger=$true }
  @{ T='T1562.004' ; N='Impair Defenses (Firewall via netsh)'        ; Tests=@(1); Danger=$true }
  @{ T='T1562.008' ; N='Disable Security Tools (Defender off)'       ; Tests=@(1); Danger=$true }
  @{ T='T1562.001' ; N='Disable/Modify Security Tools (services)'    ; Tests=@(1); Danger=$true }
  @{ T='T1548.002' ; N='Bypass UAC (fodhelper/cmstp)'                ; Tests=@(1); Danger=$true }
  @{ T='T1564.008' ; N='Email Rules for Hiding (Outlook)'            ; Tests=@(1); Danger=$true }  # needs Outlook

  # Exfiltration
  @{ T='T1048.003' ; N='Exfil over Unencrypted Non-C2 (FTP)'         ; Tests=@(1); Danger=$false }

  # Impact (risky)
  @{ T='T1489'     ; N='Service Stop (impact simulation)'            ; Tests=@(1); Danger=$true }
)

# ----------------- Preflight + Execute -----------------
Ensure-AllPrereqs -Chain $chain -PrereqDir $PrereqDir

foreach ($step in $chain) {
  Start-Atomic -Technique $step.T -Tests $step.Tests -Note $step.N -Dangerous:([bool]$step.Danger)
}

Write-Host "`n[✓] Chain complete."
Write-Host "[*] CSV : $OutCsv"
Write-Host "[*] Logs: $ArtifactsDir"
