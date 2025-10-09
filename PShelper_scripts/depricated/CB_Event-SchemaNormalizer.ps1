<#
.SYNOPSIS
  Normalize Carbon Black EDR v5 process JSONs (with sorted_events) into a Sigma/Chainsaw-friendly JSONL schema.

.DESCRIPTION
  - Works on Windows PowerShell 5.1+
  - Validates JSON (fails fast if malformed)
  - Supports single process doc or an array of docs per file
  - Safely handles missing event arrays under StrictMode
  - Preserves | inside script blocks
  - Normalizes: regmod, filemod, modload, fileless_scriptload, netconn (v5 object and legacy v1 pipe),
                childproc (v3+), crossproc (RemoteThread/ProcessOpen; from sorted_events OR legacy crossproc_complete)
  - Decodes Process/Thread access masks for ProcessOpen events
  - Ensures ALL EventTime values are strict RFC3339 (e.g. 2025-08-26T18:09:39.000Z)
  - Walks a source directory of JSON files, validates JSON, writes one .normalized.jsonl per input file
  - Optional: also writes one combined JSONL across all inputs (-CombineOutput)
  - Emits a run summary on console and saves NormalizationSummary.json

.PARAMETER SourceDir
  Directory containing input JSON files.

.PARAMETER OutDir
  Directory to write normalized JSONL files.

.PARAMETER Pattern
  File glob pattern (default: *.json).

.PARAMETER CombineOutput
  If set, also create a combined JSONL across all inputs in OutDir\combined.normalized.jsonl
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$SourceDir,

  [Parameter(Mandatory = $true)]
  [string]$OutDir,

  [Parameter(Mandatory = $false)]
  [string]$Pattern = '*.json',

  [switch]$CombineOutput
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $SourceDir)) { throw "SourceDir not found: $SourceDir" }
if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

# ----------------------
# Helpers: access masks
# ----------------------
function Decode-ProcessAccessMask {
  param([int]$Mask)
  $names = @()
  if ($Mask -band 0x0001) { $names += 'PROCESS_TERMINATE' }
  if ($Mask -band 0x0002) { $names += 'PROCESS_CREATE_THREAD' }
  if ($Mask -band 0x0008) { $names += 'PROCESS_VM_OPERATION' }
  if ($Mask -band 0x0010) { $names += 'PROCESS_VM_READ' }
  if ($Mask -band 0x0020) { $names += 'PROCESS_VM_WRITE' }
  if ($Mask -band 0x0040) { $names += 'PROCESS_DUP_HANDLE' }
  if ($Mask -band 0x0080) { $names += 'PROCESS_CREATE_PROCESS' }
  if ($Mask -band 0x0100) { $names += 'PROCESS_SET_QUOTA' }
  if ($Mask -band 0x0200) { $names += 'PROCESS_SET_INFORMATION' }
  if ($Mask -band 0x0400) { $names += 'PROCESS_QUERY_INFORMATION' }
  if ($Mask -band 0x0800) { $names += 'PROCESS_SUSPEND_RESUME' }
  if ($Mask -band 0x1000) { $names += 'PROCESS_QUERY_LIMITED_INFORMATION' }
  if ($Mask -band 0x00100000) { $names += 'SYNCHRONIZE' }
  return $names
}
function Decode-ThreadAccessMask {
  param([int]$Mask)
  $names = @()
  if ($Mask -band 0x0001) { $names += 'THREAD_TERMINATE' }
  if ($Mask -band 0x0002) { $names += 'THREAD_SUSPEND_RESUME' }
  if ($Mask -band 0x0008) { $names += 'THREAD_GET_CONTEXT' }
  if ($Mask -band 0x0010) { $names += 'THREAD_SET_CONTEXT' }
  if ($Mask -band 0x0020) { $names += 'THREAD_SET_INFORMATION' }
  if ($Mask -band 0x0040) { $names += 'THREAD_QUERY_INFORMATION' }
  if ($Mask -band 0x0080) { $names += 'THREAD_SET_THREAD_TOKEN' }
  if ($Mask -band 0x0100) { $names += 'THREAD_IMPERSONATE' }
  if ($Mask -band 0x0200) { $names += 'THREAD_DIRECT_IMPERSONATION' }
  if ($Mask -band 0x00100000) { $names += 'SYNCHRONIZE' }
  return $names
}

# ----------------------
# Helpers: safe property access
# ----------------------
function Get-Prop {
  param([Parameter(Mandatory=$true)][object]$o,
        [Parameter(Mandatory=$true)][string]$name)
  $p = $o.PSObject.Properties[$name]
  if ($p -and $null -ne $p.Value -and "$($p.Value)" -ne "") { return $p.Value }
  return $null
}
function Resolve-First {
  param([Parameter(Mandatory=$true)][object]$o,
        [Parameter(Mandatory=$true)][string[]]$names)
  foreach ($n in $names) {
    $v = Get-Prop $o $n
    if ($null -ne $v) { return $v }
  }
  return $null
}

# ----------------------
# Helpers: timestamp normalization (PS 5.1-safe)
# ----------------------
function Normalize-TimeString {
  param([Parameter(Mandatory)][string]$Value)

  $v = $Value.Trim()
  # Strip any stray ANSI color codes if present (ESC[...m)
  $v = $v -replace "`e\[[0-9;]*m",""

  $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor `
            [System.Globalization.DateTimeStyles]::AdjustToUniversal

  $fmt = @(
    'yyyy-MM-ddTHH:mm:ss.fffffffZ',
    'yyyy-MM-ddTHH:mm:ss.fffZ',
    'yyyy-MM-ddTHH:mm:ssZ',
    'yyyy-MM-dd HH:mm:ss.ffffff',
    'yyyy-MM-dd HH:mm:ss.fff',
    'yyyy-MM-dd HH:mm:ss',
    'MM/dd/yyyy HH:mm:ssZ',
    'M/d/yyyy H:mm:ssZ',
    'MM/dd/yyyy HH:mm:ss',
    'M/d/yyyy H:mm:ss'
  )

  foreach ($f in $fmt) {
    $dto = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParseExact($v, $f, [cultureinfo]::InvariantCulture, $styles, [ref]$dto)) {
      return $dto.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [cultureinfo]::InvariantCulture)
    }
  }

  try {
    $dto = [datetimeoffset]::Parse($v, [cultureinfo]::InvariantCulture, $styles)
    return $dto.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [cultureinfo]::InvariantCulture)
  } catch {
    return $v  # leave as-is if unparseable so we can inspect later
  }
}
function Convert-ToRfc3339 {
  param([string]$s, [string]$fallback = $null)
  if ([string]::IsNullOrWhiteSpace($s)) { $s = $fallback }
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  Normalize-TimeString $s
}

# Friendly warning helper
function Write-NormWarn {
  param([string]$Type,[string]$Time,[object]$Event,[string]$Message)
  try {
    $snippet = $Event | ConvertTo-Json -Depth 6 -Compress
  } catch { $snippet = "$Event" }
  Write-Warning ("Normalization error on event (type='{0}', time='{1}'): {2}`nOffending event: {3}" -f $Type,$Time,$Message,$snippet)
}

# ----------------------
# Core: normalization
# ----------------------
function Convert-ToNormalizedRows {
  param([Parameter(Mandatory = $true)][object]$ProcessDoc)

  if (-not ($ProcessDoc.PSObject.Properties.Name -contains 'process')) { return @() }
  $p = $ProcessDoc.process
  if (-not $p) { return @() }

  $SrcImage  = $p.path
  $SrcHost   = $p.hostname
  $SrcGuid   = $p.unique_id
  $SrcPid    = $p.process_pid

  # Collect events
  $events = @()
  if ($p.PSObject.Properties.Name -contains 'sorted_events') {
    if ($null -ne $p.sorted_events) { $events += $p.sorted_events }
  }

  # Legacy top-level crossproc_complete
  if ($ProcessDoc.PSObject.Properties.Name -contains 'crossproc_complete') {
    if ($null -ne $ProcessDoc.crossproc_complete) {
      foreach ($line in $ProcessDoc.crossproc_complete) {
        if ($null -eq $line) { continue }
        $events += [pscustomobject]@{ type = 'crossproc'; time = $null; data = $line }
      }
    }
  }

  if (-not $events) { return @() }

  $rows = foreach ($e in $events) {
    try {
      $t       = if ($e.PSObject.Properties.Name -contains 'type') { $e.type } else { $null }
      $topTimeRaw = if ($e.PSObject.Properties.Name -contains 'time') { $e.time } else { $null }
      $topTime = Convert-ToRfc3339 $topTimeRaw $null

      $hasData = $e.PSObject.Properties.Name -contains 'data'
      $dataVal = if ($hasData) { $e.data } else { $e }

      if ($t -eq 'childproc' -and $null -ne $dataVal -and -not ($dataVal -is [pscustomobject])) {
        $dataVal = [pscustomobject]$dataVal
      }

      switch ($t) {

        'regmod' {
          if (-not ($dataVal -is [string])) { continue }
          $f = ($dataVal -split '\|')
          if ($f.Count -lt 3) { continue }
          $op = 0; [void][int]::TryParse($f[0], [ref]$op)
          $regOp = switch ($op) { 1{'RegCreate'} 2{'RegWrite'} 4{'RegDeleteKey'} 8{'RegDeleteValue'} default{'RegOp'} }
          $eventTime = Convert-ToRfc3339 $f[1] $topTime

          [pscustomobject]@{
            EventType       = 'Reg'
            EventTime       = $eventTime
            Host            = $SrcHost
            SourceProcessId = $SrcGuid
            SourcePid       = $SrcPid
            SourceImage     = $SrcImage
            RegOp           = $regOp
            TargetObject    = $f[2]
            TamperFlag      = $( if ($f.Count -ge 4 -and $f[3] -ne '') { $f[3] } else { $null } )
          }
        }

        'filemod' {
          if (-not ($dataVal -is [string])) { continue }
          $f = ($dataVal -split '\|', 7)
          if ($f.Count -lt 3) { continue }
          $op = 0; [void][int]::TryParse($f[0], [ref]$op)
          $fileOp = switch ($op) { 1{'FileCreate'} 2{'FileWriteFirst'} 4{'FileDelete'} 8{'FileWriteLast'} default{'FileOp'} }
          $eventTime = Convert-ToRfc3339 $f[1] $topTime

          [pscustomobject]@{
            EventType       = 'File'
            EventTime       = $eventTime
            Host            = $SrcHost
            SourceProcessId = $SrcGuid
            SourcePid       = $SrcPid
            SourceImage     = $SrcImage
            FileOp          = $fileOp
            TargetFilename  = $f[2]
            HashAfterWrite  = $( if ($f.Count -ge 4 -and $f[3] -ne '') { $f[3] } else { $null } )
            FileTypeId      = $( if ($f.Count -ge 5 -and $f[4] -ne '') { $f[4] } else { $null } )
            TamperFlag      = $( if ($f.Count -ge 6 -and $f[5] -ne '') { $f[5] } else { $null } )
          }
        }

        'modload' {
          if (-not ($dataVal -is [string])) { continue }
          $f = ($dataVal -split '\|')
          if ($f.Count -lt 3) { continue }

          [pscustomobject]@{
            EventType       = 'ImageLoad'
            EventTime       = Convert-ToRfc3339 $f[0] $topTime
            Host            = $SrcHost
            SourceProcessId = $SrcGuid
            SourcePid       = $SrcPid
            SourceImage     = $SrcImage
            HashMd5         = $f[1]
            ImageLoaded     = $f[2]
            HashSha256      = $( if ($f.Count -ge 4 -and $f[3] -ne '') { $f[3] } else { $null } )
          }
        }

        'fileless_scriptload' {
          if (-not ($dataVal -is [string])) { continue }
          $f = ($dataVal -split '\|')
          if ($f.Count -lt 3) { continue }
          $scriptText = if ($f.Count -ge 4) { ($f[3..($f.Count-1)] -join '|') } else { $null }
          $pidInt = $null; [void][int]::TryParse($f[1], [ref]$pidInt)

          [pscustomobject]@{
            EventType        = 'FilelessScriptLoad'
            EventTime        = Convert-ToRfc3339 $f[0] $topTime
            Host             = $SrcHost
            SourceProcessId  = $SrcGuid
            SourcePid        = $SrcPid
            SourceImage      = $SrcImage
            ScriptEnginePid  = $pidInt
            ScriptSha256     = $f[2]
            ScriptContent    = $scriptText
          }
        }

        'netconn' {
          if ($null -eq $dataVal) { continue }

          if ($dataVal -is [string]) {
            # Legacy v1: "time|ip|port|proto|domain|outboundBool"
            $f = ($dataVal -split '\|')
            if ($f.Count -lt 6) { continue }
            $isOutbound = ($f[5] -eq 'true' -or $f[5] -eq 'True')
            $proto      = $f[3]

            $localIP  = $null; $localPort  = $null
            $remoteIP = $null; $remotePort = $null
            if ($isOutbound) { $remoteIP = $f[1]; $remotePort = $f[2] }
            else { $localIP = $f[1]; $localPort = $f[2] }

            [pscustomobject]@{
              EventType       = 'NetworkConnect'
              EventTime       = Convert-ToRfc3339 $f[0] $topTime
              Host            = $SrcHost
              SourceProcessId = $SrcGuid
              SourcePid       = $SrcPid
              SourceImage     = $SrcImage
              Proto           = $proto
              Domain          = $f[4]
              Direction       = $( if ($isOutbound) { 'Outbound' } else { 'Inbound' } )
              LocalIP         = $localIP
              LocalPort       = $localPort
              RemoteIP        = $remoteIP
              RemotePort      = $remotePort
            }
          } else {
            # v5 object
            $d = $dataVal
            $dirRaw = Get-Prop $d 'direction'
            $direction =
              if ($dirRaw -is [bool]) { if ($dirRaw) { 'Outbound' } else { 'Inbound' } }
              elseif ("$dirRaw" -match '^(true|1)$') { 'Outbound' }
              else { 'Inbound' }

            [pscustomobject]@{
              EventType       = 'NetworkConnect'
              EventTime       = Convert-ToRfc3339 (Get-Prop $d 'timestamp') $topTime
              Host            = $SrcHost
              SourceProcessId = $SrcGuid
              SourcePid       = $SrcPid
              SourceImage     = $SrcImage
              Proto           = (Get-Prop $d 'proto')
              Domain          = (Get-Prop $d 'domain')
              Direction       = $direction
              LocalIP         = (Get-Prop $d 'local_ip')
              LocalPort       = (Get-Prop $d 'local_port')
              RemoteIP        = (Get-Prop $d 'remote_ip')
              RemotePort      = (Get-Prop $d 'remote_port')
              BlockType       = (Get-Prop $d 'block_type')
            }
          }
        }

        'childproc' {
          if ($null -eq $dataVal) { continue }
          $d = $dataVal

          $typeVal = Get-Prop $d 'type'
          $evtType = if ($typeVal -eq 'start') { 'ProcessCreate' } else { 'ProcessTerminate' }

          # Time fallback: end -> start -> timestamp -> wrapper time
          $rawTime = Resolve-First $d @('end','start','timestamp')
          $evtTime = Convert-ToRfc3339 $rawTime $topTime

          [pscustomobject]@{
            EventType         = $evtType
            EventTime         = $evtTime
            Host              = $SrcHost
            SourceProcessId   = $SrcGuid
            SourcePid         = $SrcPid
            SourceImage       = $SrcImage
            NewProcessId      = Get-Prop $d 'processId'
            NewProcessPid     = Get-Prop $d 'pid'
            NewProcessName    = Get-Prop $d 'path'
            NewProcessMD5     = Get-Prop $d 'md5'
            NewProcessSHA256  = Get-Prop $d 'sha256'
            ChildEvent        = $typeVal
            IsSuppressed      = Get-Prop $d 'is_suppressed'
            IsTampered        = Get-Prop $d 'is_tampered'
            ChildCommandLine  = Get-Prop $d 'commandLine'
            ChildUser         = Get-Prop $d 'userName'
          }
        }

        'crossproc' {
          # "type|time|target_unique_id|target_md5|target_path|subtype|requested_access|tamper|[extraFlag]|[extraHash]"
          $line = $dataVal
          if (-not ($line -is [string])) { continue }
          $f = ($line -split '\|')
          if ($f.Count -lt 5) { continue }

          $cType   = $f[0]
          $evtType = if ($cType -eq 'RemoteThread') { 'CreateRemoteThread' } elseif ($cType -eq 'ProcessOpen') { 'ProcessOpen' } else { $cType }
          $openSubtypeRaw = if ($f.Count -ge 6 -and $f[5] -ne '') { $f[5] } else { $null }
          $maskRaw        = if ($f.Count -ge 7 -and $f[6] -ne '') { $f[6] } else { $null }
          $tamperFlag     = if ($f.Count -ge 8 -and $f[7] -ne '') { $f[7] } else { $null }
          $extraFlag      = if ($f.Count -ge 9 -and $f[8] -ne '') { $f[8] } else { $null }
          $extraHash      = if ($f.Count -ge 10 -and $f[9] -ne '') { $f[9] } else { $null }

          $openSubtype = $null
          if ($openSubtypeRaw -ne $null) { $tmp = 0; if ([int]::TryParse($openSubtypeRaw, [ref]$tmp)) { $openSubtype = $tmp } }

          $mask = $null
          if ($maskRaw -ne $null) {
            if ($maskRaw -like '0x*') { try { $mask = [Convert]::ToInt32($maskRaw, 16) } catch { $mask = $null } }
            else { $tmp = 0; if ([int]::TryParse($maskRaw, [ref]$tmp)) { $mask = $tmp } }
          }

          $accessNames = $null
          if ($evtType -eq 'ProcessOpen' -and $mask -ne $null) {
            if ($openSubtype -eq 2) { $accessNames = Decode-ThreadAccessMask -Mask $mask }
            else { $accessNames = Decode-ProcessAccessMask -Mask $mask }
          }

          [pscustomobject]@{
            EventType         = $evtType
            EventTime         = Convert-ToRfc3339 $f[1] $topTime
            Host              = $SrcHost
            SourceProcessId   = $SrcGuid
            SourcePid         = $SrcPid
            SourceImage       = $SrcImage
            TargetUniqueId    = $f[2]
            TargetMd5         = $f[3]
            TargetImage       = $f[4]
            OpenSubtype       = $openSubtype
            GrantedAccessMask = $mask
            GrantedAccess     = $accessNames
            TamperFlag        = $tamperFlag
            ExtraFlag         = $extraFlag
            ExtraHash         = $extraHash
          }
        }

        default { continue }
      }

    } catch {
      Write-NormWarn -Type $t -Time $topTimeRaw -Event $e -Message $_.Exception.Message
      continue
    }
  }

  return $rows
}

# ----------------------
# Main: iterate files, normalize, write JSONL (+ optional combined)
# ----------------------
$files = Get-ChildItem -LiteralPath $SourceDir -File -Filter $Pattern -ErrorAction Stop
if ($files.Count -eq 0) {
  Write-Warning "No files matched pattern '$Pattern' in $SourceDir"
  return
}

$totIn = 0; $totOut = 0; $totEvents = 0
$eventTypeCounts = @{}
$perFileCounts   = @{}

$combinedWriter = $null
$combinedPath   = Join-Path -Path $OutDir -ChildPath 'combined.normalized.jsonl'
if ($CombineOutput) {
  $combinedWriter = New-Object System.IO.StreamWriter($combinedPath, $false, [System.Text.UTF8Encoding]::new($false))
}

foreach ($fi in $files) {
  $totIn++
  try {
    $raw = Get-Content -LiteralPath $fi.FullName -Raw
    $null = $raw | Test-Json -ErrorAction Stop
  } catch {
    Write-Warning ("Skipping invalid JSON: {0}  ({1})" -f $fi.Name, $_.Exception.Message)
    continue
  }

  $json = $raw | ConvertFrom-Json
  $docs = @()
  if ($json -is [System.Collections.IEnumerable] -and -not ($json -is [string])) { $docs = $json } else { $docs = @($json) }

  $outRows = New-Object System.Collections.Generic.List[object]
  foreach ($doc in $docs) {
    $rows = Convert-ToNormalizedRows -ProcessDoc $doc
    if ($rows) { foreach ($r in $rows) { [void]$outRows.Add($r) } }
  }

  # count by type for this file
  $fileCounts = @{}
  foreach ($r in $outRows) {
    $et = $r.EventType
    if (-not $fileCounts.ContainsKey($et)) { $fileCounts[$et] = 0 }
    $fileCounts[$et]++
    if (-not $eventTypeCounts.ContainsKey($et)) { $eventTypeCounts[$et] = 0 }
    $eventTypeCounts[$et]++
  }
  $perFileCounts[$fi.Name] = $fileCounts

  $base = [System.IO.Path]::GetFileNameWithoutExtension($fi.Name)
  $outFile = Join-Path -Path $OutDir -ChildPath ($base + '.normalized.jsonl')

  # Write JSONL (one event per line), UTF-8 no BOM
  $sw = New-Object System.IO.StreamWriter($outFile, $false, [System.Text.UTF8Encoding]::new($false))
  try {
    foreach ($row in $outRows) {
      $line = ($row | ConvertTo-Json -Depth 12 -Compress)
      $sw.WriteLine($line)
      if ($CombineOutput) { $combinedWriter.WriteLine($line) }
      $totEvents++
    }
  } finally {
    $sw.Dispose()
  }
  $totOut++
  Write-Host ("Normalized {0} events -> {1}" -f $outRows.Count, $outFile)
}

if ($CombineOutput) {
  $combinedWriter.Dispose()
  Write-Host ("Also wrote combined output -> {0}" -f $combinedPath)
}

# summary
$summary = [ordered]@{
  SourceDir      = $SourceDir
  OutDir         = $OutDir
  FilesProcessed = $totIn
  FilesWritten   = $totOut
  EventsTotal    = $totEvents
  ByEventType    = $eventTypeCounts
  PerFile        = $perFileCounts
  CombinedOutput = ($(if ($CombineOutput) { $combinedPath } else { $null }))
}
$summaryPath = Join-Path -Path $OutDir -ChildPath 'NormalizationSummary.json'
$summary | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $summaryPath -Encoding UTF8

Write-Host ("Done. Files processed: {0}, outputs: {1}, events normalized: {2}" -f $totIn, $totOut, $totEvents)
Write-Host ("Summary saved -> {0}" -f $summaryPath)
