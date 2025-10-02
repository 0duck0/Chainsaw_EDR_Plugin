<#  Run Chainsaw against normalized_events_iso:
.\chainsaw.exe hunt `
  "E:\Chainsaw_Project\chainsaw\rules" `
  "E:\Chainsaw_Project\normalized_events_iso" `
  --kind sigma `
  --mapping "E:\Chainsaw_Project\CB_Sigma_Map\CB_Sigma_map.yml" `
  --skip-errors --csv -o "E:\Chainsaw_Project\Sigma_Alerts.csv" --load-unknown
#>

function Convert-ToRfc3339 {
  param([string]$s, [string]$fallback=$null)
  if ([string]::IsNullOrWhiteSpace($s)) { $s = $fallback }
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  Normalize-TimeString $s
}
# then set: EventTime = Convert-ToRfc3339 $candidateTime $topTime

<#
This pass rewrites any EventTime like 08/26/2025 18:09:39Z (and several other variants) into strict ISO-8601 YYYY-MM-DDTHH:MM:SS.fffZ
#>
# --- Helpers (PS 5.1-safe) ---
function Normalize-TimeString {
  param([Parameter(Mandatory)][string]$Value)

  $Value = $Value.Trim()

  # remove any embedded ANSI like ESC[38;5;11m if present
  $Value = $Value -replace "`e\[[0-9;]*m",""

  $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor `
            [System.Globalization.DateTimeStyles]::AdjustToUniversal

  $fmt = @(
    'yyyy-MM-ddTHH:mm:ss.fffffffZ',
    'yyyy-MM-ddTHH:mm:ss.fffZ',
    'yyyy-MM-ddTHH:mm:ssZ',
    'yyyy-MM-dd HH:mm:ss.fffffff',
    'yyyy-MM-dd HH:mm:ss',
    'MM/dd/yyyy HH:mm:ssZ',
    'M/d/yyyy H:mm:ssZ',
    'MM/dd/yyyy HH:mm:ss',
    'M/d/yyyy H:mm:ss'
  )

  foreach ($f in $fmt) {
    $dto = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParseExact($Value, $f, [cultureinfo]::InvariantCulture, $styles, [ref]$dto)) {
      return $dto.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [cultureinfo]::InvariantCulture)
    }
  }

  # last-chance: broad parse
  try {
    $dto = [datetimeoffset]::Parse($Value, [cultureinfo]::InvariantCulture, $styles)
    return $dto.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [cultureinfo]::InvariantCulture)
  } catch {
    return $Value  # leave as-is so we can spot unfixables
  }
}

function New-StreamWriterUtf8NoBom { param([string]$Path)
  $enc = New-Object System.Text.UTF8Encoding($false)
  return [System.IO.StreamWriter]::new($Path, $false, $enc)
}

# --- Repair pass: JSONL -> JSONL (normalized timestamps) ---
$src = 'E:\Chainsaw_Project\normalized_events'
$dst = 'E:\Chainsaw_Project\normalized_events_iso'
New-Item -ItemType Directory -Force -Path $dst | Out-Null

Get-ChildItem -LiteralPath $src -Filter *.normalized.jsonl | ForEach-Object {
  if ($_.Length -eq 0) { return }  # skip truly empty files

  $out = Join-Path $dst $_.Name
  $sw  = New-StreamWriterUtf8NoBom -Path $out
  try {
    foreach ($line in Get-Content -LiteralPath $_.FullName) {
      $t = $line.Trim()
      if (-not $t) { continue }

      try { $obj = $t | ConvertFrom-Json } catch { continue }

      if ($obj.PSObject.Properties['EventTime']) {
        $obj.EventTime = Normalize-TimeString $obj.EventTime
      }

      $sw.WriteLine(($obj | ConvertTo-Json -Depth 64 -Compress))
    }
  } finally { $sw.Dispose() }
}

# Quick verification: no US-style dates left
Select-String "$dst\*.normalized.jsonl" -Pattern '"EventTime":"\d{1,2}/\d{1,2}/\d{4}' -List -Quiet
