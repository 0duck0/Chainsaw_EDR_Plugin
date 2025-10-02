# Append process.segment_id to each JSON filename (pure .NET version)
[CmdletBinding()]
param(
  [string]$Path = "E:\Chainsaw_Project\CB_Process_Data\NCEUPWS14101T_20250829",
  [switch]$Recurse,
  [switch]$ReplaceExistingSuffix,
  [switch]$DryRun
)

Write-Host "[Rename-JsonBySegmentId.ps1 .NET-only] Path=$Path Recurse=$($Recurse.IsPresent) DryRun=$($DryRun.IsPresent)"

# Normalize absolute path
$root = [System.IO.Path]::GetFullPath($Path)

# Enumerate *.json files
$searchOption = [System.IO.SearchOption]::TopDirectoryOnly
if ($Recurse) { $searchOption = [System.IO.SearchOption]::AllDirectories }

$files = [System.IO.Directory]::EnumerateFiles($root, "*.json", $searchOption)

$any = $false
foreach ($full in $files) {
  $any = $true
  try {
    # Read file (raw)
    $text = [System.IO.File]::ReadAllText($full)

    # Regex first
    $m = [System.Text.RegularExpressions.Regex]::Match($text, '"segment_id"\s*:\s*(\d+)')
    $seg = $null
    if ($m.Success) {
      $seg = $m.Groups[1].Value
    } else {
      # Fallback JSON parse (PowerShell ConvertFrom-Json), but guarded
      try {
        $obj = $text | ConvertFrom-Json -ErrorAction Stop
        if ($obj -and $obj.process -and $obj.process.segment_id) { $seg = [string]$obj.process.segment_id }
      } catch { }
    }

    if ([string]::IsNullOrEmpty($seg)) {
      Write-Warning ("No segment_id found: " + [System.IO.Path]::GetFileName($full))
      continue
    }

    $dir  = [System.IO.Path]::GetDirectoryName($full)
    $name = [System.IO.Path]::GetFileName($full)
    $base = [System.IO.Path]::GetFileNameWithoutExtension($name)
    $ext  = [System.IO.Path]::GetExtension($name)

    # Adjust base according to ReplaceExistingSuffix
    $digitsRx = new-object System.Text.RegularExpressions.Regex('-\d+$')
    if ($digitsRx.IsMatch($base)) {
      $existing = $digitsRx.Match($base).Value.TrimStart('-')
      if ($existing -eq $seg) {
        Write-Host ("SKIP (already correct): " + $name)
        continue
      }
      if ($ReplaceExistingSuffix) {
        $base = $digitsRx.Replace($base, "-" + $seg)
      } else {
        $base = $base + "-" + $seg
      }
    } else {
      $base = $base + "-" + $seg
    }

    $newFull = [System.IO.Path]::Combine($dir, $base + $ext)

    if ([string]::Equals($newFull, $full, [System.StringComparison]::OrdinalIgnoreCase)) {
      Write-Host ("SKIP (no change): " + $name)
      continue
    }

    if ([System.IO.File]::Exists($newFull)) {
      Write-Warning ("Target exists, skipping: " + $newFull)
      continue
    }

    $leafNew = [System.IO.Path]::GetFileName($newFull)

    if ($DryRun) {
      Write-Host ("DRY RUN: {0} -> {1}" -f $name, $leafNew)
    } else {
      # Do the rename using File.Move
      [System.IO.File]::Move($full, $newFull)
      Write-Host ("OK: {0} -> {1}" -f $name, $leafNew)
    }
  }
  catch {
    # Show the real underlying error message
    Write-Warning ("FAIL: " + [System.IO.Path]::GetFileName($full) + ": " + ($_.Exception.Message))
  }
}

if (-not $any) {
  Write-Host "No JSON files found under: $root"
}
