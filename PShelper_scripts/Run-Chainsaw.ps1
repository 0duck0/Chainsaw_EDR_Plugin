[CmdletBinding()]
param(
  [string]$RulesPath   = "E:\Chainsaw_Project\chainsaw\rules",
  [string]$MappingPath = "E:\Chainsaw_Project\CB_Sigma_Map\CB_Sigma_map.yml",
  [string]$Artefacts   = "E:\Chainsaw_Project\normalized_events",
  [string]$OutputDir   = "E:\Chainsaw_Project\findings",
  [switch]$Full,
  [switch]$Metadata
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Ensure output dir exists
if (-not (Test-Path -LiteralPath $OutputDir)) {
  New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

# Build args (IMPORTANT: -o must be a DIRECTORY for --csv)
$stamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$log    = Join-Path $OutputDir "chainsaw_run_$stamp.log"
$tmpCsv = Join-Path $OutputDir "sigma.csv"                  # Chainsaw writes this name
$outCsv = Join-Path $OutputDir "chainsaw_findings_$stamp.csv"

# Clean any leftover sigma.csv from prior runs
if (Test-Path -LiteralPath $tmpCsv) { Remove-Item -LiteralPath $tmpCsv -Force }

# Assemble argument list
$args = @(
  'hunt',
  '--load-unknown',
  '--skip-errors',
  '--extension','jsonl',
  '-s', $RulesPath,
  '--mapping', $MappingPath,
  '--csv',
  '--output', $OutputDir,
  $Artefacts
)

if ($Full)     { $args += '--full' }
if ($Metadata) { $args += '--metadata' }

# Run chainsaw and capture stderr to log; keep stdout quiet with -q
$args += '-q'

# Invoke reliably and get exit code
$exe = Join-Path (Get-Location) 'chainsaw.exe'
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $exe
$psi.ArgumentList.AddRange($args)
$psi.RedirectStandardError = $true
$psi.RedirectStandardOutput = $false
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true

$proc = New-Object System.Diagnostics.Process
$proc.StartInfo = $psi
[void]$proc.Start()
$stderr = $proc.StandardError.ReadToEnd()
$proc.WaitForExit()

# Write log
$stderr | Out-File -LiteralPath $log -Encoding UTF8

# Check results
if ($proc.ExitCode -ne 0) {
  Write-Warning ("Chainsaw exit code: {0}. See log: {1}" -f $proc.ExitCode, $log)
}
if (Test-Path -LiteralPath $tmpCsv) {
  Move-Item -LiteralPath $tmpCsv -Destination $outCsv -Force
  Write-Host ("Results -> {0}" -f $outCsv)
} else {
  Write-Warning "Expected '$tmpCsv' was not created."
  Write-Host "Args used:"
  $args -join ' '
  Write-Host ("Log -> {0}" -f $log)
  # Show a quick directory listing for troubleshooting
  Get-ChildItem -LiteralPath $OutputDir | Sort-Object LastWriteTime -Descending | Select-Object LastWriteTime,Length,Name | Format-Table
}
