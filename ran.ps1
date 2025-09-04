
<#
  Prep-RanSim.ps1
  - Downloads the GitHub repo lawndoc/RanSim (no execution)
  - Creates random dummy files in a target folder you choose
  - Prints the manual command you'd run: .\RanSim.ps1 -Mode encrypt -TargetPath "<YourFolder>"

  Usage:
    # Create an empty folder first (recommended)
    New-Item -ItemType Directory -Path "C:\Lab\RanSimTarget" -Force | Out-Null

    # Run the prep
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Prep-RanSim.ps1 `
      -TargetPath "C:\Lab\RanSimTarget" -Files 600 -MinKB 16 -MaxKB 256 `
      -RepoRoot "C:\Lab\Tools"

    # Then, MANUALLY:
    cd "C:\Lab\Tools\RanSim-main"
    .\RanSim.ps1 -Mode encrypt -TargetPath "C:\Lab\RanSimTarget"
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$TargetPath,                # Folder for dummy files (prefer an EMPTY folder!)
  [int]$Files   = 400,
  [int]$MinKB   = 32,
  [int]$MaxKB   = 256,
  [string]$RepoRoot = (Join-Path $PWD "RanSim-main"),
  [switch]$AllowNonEmpty              # Set if you intentionally want to use a non-empty folder
)

$ErrorActionPreference = 'Stop'

# --- 0) Basic safety checks ---
if (-not (Test-Path $TargetPath)) {
  New-Item -ItemType Directory -Path $TargetPath -Force | Out-Null
}

# Refuse to fill a non-empty folder unless explicitly allowed
$existing = Get-ChildItem -Path $TargetPath -Force -ErrorAction SilentlyContinue
if ($existing -and -not $AllowNonEmpty) {
  throw "TargetPath '$TargetPath' is not empty. Create/use an empty folder or pass -AllowNonEmpty if you really intend to use it."
}

if ($MinKB -gt $MaxKB) { $t=$MinKB; $MinKB=$MaxKB; $MaxKB=$t }

# --- 1) Download the GitHub repo (zip) and extract (no execution) ---
$zipUrl = 'https://github.com/lawndoc/RanSim/archive/refs/heads/main.zip'
$repoParent = Split-Path -Parent $RepoRoot
if ([string]::IsNullOrWhiteSpace($repoParent)) { $repoParent = $PWD }
New-Item -ItemType Directory -Force -Path $repoParent | Out-Null

$zipPath = Join-Path $repoParent 'RanSim-main.zip'
Write-Host "[*] Downloading: $zipUrl" -ForegroundColor Cyan
Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing

Write-Host "[*] Extracting to $repoParent" -ForegroundColor Cyan
try {
  Expand-Archive -Path $zipPath -DestinationPath $repoParent -Force
} catch {
  # Fallback extraction (Shell COM) if Expand-Archive isn't available
  $shell = New-Object -ComObject Shell.Application
  $zip = $shell.NameSpace($zipPath)
  $dst = $shell.NameSpace($repoParent)
  $dst.CopyHere($zip.Items(), 0x10)  # 0x10 = No UI
}

# Final repo directory
$RepoDir = Join-Path $repoParent 'RanSim-main'
if (-not (Test-Path (Join-Path $RepoDir 'RanSim.ps1'))) {
  throw "Could not find RanSim.ps1 under '$RepoDir'. Check the download/extract step."
}

# --- 2) Create random dummy files in TargetPath ---
Write-Host "[*] Creating $Files dummy files ($MinKB–$MaxKB KB) in $TargetPath ..." -ForegroundColor Cyan
$exts = @('.txt','.docx','.xlsx','.pdf','.jpg')
$rng  = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try {
  for ($i=0; $i -lt $Files; $i++) {
    $ext  = $exts[$i % $exts.Count]
    $name = "dummy_{0:D6}{1}" -f $i, $ext
    $sizeKB = Get-Random -Minimum $MinKB -Maximum ($MaxKB + 1)

    $bytes = New-Object byte[] ($sizeKB * 1024)
    $rng.GetBytes($bytes)

    [IO.File]::WriteAllBytes((Join-Path $TargetPath $name), $bytes)
    if (($i+1) % 100 -eq 0) { Write-Host ("    ...{0} files" -f ($i+1)) }
  }
}
finally { $rng.Dispose() }

Write-Host "[✓] Dummy file set ready." -ForegroundColor Green

# --- 3) Show the manual command to run (explicit, no auto-execution here) ---
Write-Host ""
Write-Host "Repo location: $RepoDir" -ForegroundColor Yellow
Write-Host "Target path : $TargetPath" -ForegroundColor Yellow
Write-Host ""
Write-Host "Next steps (manual):" -ForegroundColor Magenta
Write-Host "  cd `"$RepoDir`""
Write-Host "  .\RanSim.ps1 -Mode encrypt -TargetPath `"$TargetPath`""
Write-Host ""
Write-Host "[!] Run ONLY in a lab against dummy files you just created." -ForegroundColor Red
