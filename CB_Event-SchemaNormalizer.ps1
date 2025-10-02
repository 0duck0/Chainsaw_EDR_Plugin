<#
.SYNOPSIS
  Normalize Carbon Black EDR /API/V5/ process JSONs (sorted_events) into a Sigma/Chainsaw-friendly JSONL schema.

.DESCRIPTION
  - Works on Windows PowerShell 5.1+
  - Validates JSON (fails fast if malformed)
  - Supports single process doc or an array of docs per file
  - Safely handles missing event arrays under StrictMode
  - Preserves | inside script blocks
  - Normalizes: regmod, filemod, modload, fileless_scriptload, netconn (v5 object and legacy v1 pipe),
                childproc (v3+), crossproc (RemoteThread/ProcessOpen; from sorted_events OR legacy crossproc_complete)
  - Decodes Process/Thread access masks for ProcessOpen events
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

if (-not (Test-Path -LiteralPath $SourceDir)) {
  throw "SourceDir not found: $SourceDir"
}
if (-not (Test-Path -LiteralPath $OutDir)) {
  New-Item -ItemType Directory -Path $OutDir | Out-Null
}

# ----------------------
# Helpers
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

function Get-Prop {
  param(
    [Parameter(Mandatory=$true)][object]$o,
    [Parameter(Mandatory=$true)][string]$name
  )
  $p = $o.PSObject.Properties[$name]
  if ($p -and $null -ne $p.Value -and "$($p.Value)" -ne "") { return $p.Value }
  return $null
}

function Resolve-First {
  param(
    [Parameter(Mandatory=$true)][object]$o,
    [Parameter(Mandatory=$true)][string[]]$names
  )
  foreach ($n in $names) {
    $v = Get-Prop $o $n
    if ($null -ne $v) { return $v }
  }
  return $null
}

function Ensure-Property {
  param(
    [Parameter(Mandatory=$true)][object]$o,
    [Parameter(Mandatory=$true)][string]$name,
    [Parameter()][object]$value
  )
  $prop = $o.PSObject.Properties[$name]
  if ($prop) { $prop.Value = $value }
  else { Add-Member -InputObject $o -NotePropertyName $name -NotePropertyValue $value -Force }
}

<# This TimeConversion is depricated
   A replacement has been inserted below
function Convert-ToRfc3339 {
  param(
    [string]$Timestamp,
    [string]$Fallback = $null
  )
  if ([string]::IsNullOrWhiteSpace($Timestamp)) { $Timestamp = $Fallback }
  if ([string]::IsNullOrWhiteSpace($Timestamp)) { return $null }

  $s = $Timestamp.Trim()

  # "YYYY-MM-DD HH:MM:SS(.fraction)?(Z|+HH:MM|-HH:MM)?"
  if ($s -match '^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+\-]\d{2}:\d{2})?$') {
    $s2 = $s -replace '\s+', 'T', 1
    if ($s2 -notmatch '([Zz]|[+\-]\d{2}:\d{2})$') { $s2 += 'Z' }
    return $s2
  }

  # "YYYY-MM-DDTHH:MM:SS(.fraction)?(Z|+HH:MM|-HH:MM)?"
  if ($s -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+\-]\d{2}:\d{2})?$') {
    if ($s -notmatch '([Zz]|[+\-]\d{2}:\d{2})$') { return $s + 'Z' }
    return $s
  }

  return $s
}
#>
# Updated TimeConversion Function:
function Convert-ToRfc3339 {
  param(
    [string]$Timestamp,
    [string]$Fallback = $null
  )
  if ([string]::IsNullOrWhiteSpace($Timestamp)) { $Timestamp = $Fallback }
  if ([string]::IsNullOrWhiteSpace($Timestamp)) { return $null }

  $s = $Timestamp.Trim()

  # Normalize a trailing ' UTC' to 'Z'
  if ($s -match '\s+UTC$') { $s = $s -replace '\s+UTC$','Z' }

  # If it's "YYYY-MM-DD HH:MM:SS(.fraction)?(TZ)?" convert the first space to 'T'
  if ($s -match '^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+\-]\d{2}:\d{2}|[+\-]\d{4})?$') {
    $s = $s -replace '\s+', 'T', 1
  }

  # If offset is compact +HHMM/-HHMM, add the colon -> +HH:MM
  if ($s -match '([+\-]\d{4})$') {
    $s = $s -replace '([+\-]\d{2})(\d{2})$', '$1:$2'
  }

  # If no TZ suffix, assume UTC and append Z
  if ($s -notmatch '([Zz]|[+\-]\d{2}:\d{2})$') {
    $s += 'Z'
  }

  return $s
}

# ----------------------
# Core: normalization function
# ----------------------
function Convert-ToNormalizedRows {
  param(
    [Parameter(Mandatory = $true)]
    [object]$ProcessDoc
  )

  if (-not ($ProcessDoc.PSObject.Properties.Name -contains 'process')) { return @() }
  $p = $ProcessDoc.process
  if (-not $p) { return @() }
  if (-not ($p -is [pscustomobject])) { $p = [pscustomobject]$p }

  # Defensive process header resolution (no direct dot-refs under StrictMode)
  $SrcImage = Resolve-First $p @('path','process_path','image_path','image')
  $SrcHost  = Resolve-First $p @('hostname','host','device_name','computer_name')
  $SrcGuid  = Resolve-First $p @('unique_id','process_guid','process_id','id')
  $SrcPid   = Resolve-First $p @('process_pid','pid','process_pid32','process_pid64')

  # Collect events defensively
  $events = @()
  if ($p.PSObject.Properties.Name -contains 'sorted_events') {
    if ($null -ne $p.sorted_events) { $events += $p.sorted_events }
  }

  # Legacy top-level crossproc_complete: wrap pipe strings
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
      $topTime = if ($e.PSObject.Properties.Name -contains 'time') { $e.time } else { $null }
      $topTime = Convert-ToRfc3339 $topTime
      $hasData = $e.PSObject.Properties.Name -contains 'data'
      $dataVal = if ($hasData) { $e.data } else { $e }

      # Guarantee childproc has 'end' (end -> start -> wrapper time)
      if ($t -eq 'childproc' -and $null -ne $dataVal) {
        $d = $dataVal
        if (-not ($d -is [pscustomobject])) { $d = [pscustomobject]$d }
        $endVal = Resolve-First $d @('end','start')
        if (-not $endVal) { $endVal = $topTime }
        Ensure-Property -o $d -name 'end' -value $endVal
        $dataVal = $d
      }

      switch ($t) {

        'regmod' {
          if (-not ($dataVal -is [string])) { continue }
          $f = ($dataVal -split '\|')
          if ($f.Count -lt 3) { continue }
          $op = 0; [void][int]::TryParse($f[0], [ref]$op)
          $regOp = switch ($op) { 1{'RegCreate'} 2{'RegWrite'} 4{'RegDeleteKey'} 8{'RegDeleteValue'} default{'RegOp'} }
          $eventTime = Convert-ToRfc3339 ($(if ($f[1]) { $f[1] } else { $topTime })) $topTime

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
          $eventTime = Convert-ToRfc3339 ($(if ($f[1]) { $f[1] } else { $topTime })) $topTime

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
          $eventTime = Convert-ToRfc3339 ($(if ($f[0]) { $f[0] } else { $topTime })) $topTime

          [pscustomobject]@{
            EventType       = 'ImageLoad'
            EventTime       = $eventTime
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
          $eventTime = Convert-ToRfc3339 ($(if ($f[0]) { $f[0] } else { $topTime })) $topTime

          [pscustomobject]@{
            EventType        = 'FilelessScriptLoad'
            EventTime        = $eventTime
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
            $eventTime  = Convert-ToRfc3339 ($(if ($f[0]) { $f[0] } else { $topTime })) $topTime
            $proto      = $f[3]

            $localIP  = $null; $localPort  = $null
            $remoteIP = $null; $remotePort = $null
            if ($isOutbound) {
              $remoteIP   = $f[1]; $remotePort = $f[2]
            } else {
              $localIP    = $f[1]; $localPort  = $f[2]
            }

            [pscustomobject]@{
              EventType       = 'NetworkConnect'
              EventTime       = $eventTime
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
            $direction = $( if ($d.direction -eq $true -or $d.direction -eq 'true') { 'Outbound' } else { 'Inbound' } )
            $eventTime = Convert-ToRfc3339 ($(if ($null -ne $d.timestamp -and $d.timestamp -ne '') { $d.timestamp } else { $topTime })) $topTime
            [pscustomobject]@{
              EventType       = 'NetworkConnect'
              EventTime       = $eventTime
              Host            = $SrcHost
              SourceProcessId = $SrcGuid
              SourcePid       = $SrcPid
              SourceImage     = $SrcImage
              Proto           = $d.proto
              Domain          = $d.domain
              Direction       = $direction
              LocalIP         = $d.local_ip
              LocalPort       = $d.local_port
              RemoteIP        = $d.remote_ip
              RemotePort      = $d.remote_port
              BlockType       = $d.block_type
            }
          }
        }

        'childproc' {
          if ($null -eq $dataVal) { continue }
          $d = $dataVal

          $typeVal = Get-Prop $d 'type'
          $evtType = if ($typeVal -eq 'start') { 'ProcessCreate' } else { 'ProcessTerminate' }

          # Time fallback: end -> start -> timestamp -> wrapper time
          $evtTime = Resolve-First $d @('end','start','timestamp')
          if (-not $evtTime) { $evtTime = $topTime }
          $evtTime = Convert-ToRfc3339 $evtTime $topTime

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
          $eventTime = Convert-ToRfc3339 ($(if ($f[1]) { $f[1] } else { $topTime })) $topTime

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
            EventTime         = $eventTime
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
    }
    catch {
      Write-Warning ("Normalization error on event (type='{0}', time='{1}'): {2}" -f $e.type, $e.time, $_.Exception.Message)
      try { Write-Host ("Offending event: " + ($e | ConvertTo-Json -Depth 8 -Compress)) } catch {}
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
    if ($rows) {
      foreach ($r in $rows) { [void]$outRows.Add($r) }
    }
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

  # Write JSONL (one event per line)
  $sw = New-Object System.IO.StreamWriter($outFile, $false, [System.Text.UTF8Encoding]::new($false))
  try {
    foreach ($row in $outRows) {
      if ($outRows.Count -gt 0) {
        $line = ($row | ConvertTo-Json -Depth 12 -Compress)
        $sw.WriteLine($line)
        if ($CombineOutput) { $combinedWriter.WriteLine($line) }
        $totEvents++
      } else {
          Write-Host ("No events -> skipping output for {0}" -f $fi.Name)
      }
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

function Convert-ToIPv4 {
    <#
    .SYNOPSIS
        Converts a signed 32-bit integer (or string) into an IPv4 dotted-quad.
    .DESCRIPTION
        - If the input already looks like an IPv4 address (dotted-quad), it is returned unchanged.
        - Accepts negative or positive integers (string or numeric). Uses two's complement & 0xFFFFFFFF.
        - Supports endianness control:
            * Big  : Treat the integer as network byte order (most common).
            * Little: Treat the integer as little-endian.
    .PARAMETER InputObject
        The value to convert. Accepts pipeline input.
    .PARAMETER Endian
        'Big' (default) or 'Little'.
    .EXAMPLE
        -702790267 | Convert-ToIPv4           # Big-endian -> e.g., 214.28.69.133
    .EXAMPLE
        -702790267 | Convert-ToIPv4 -Endian Little  # Little-endian -> e.g., 133.69.28.214
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [Alias('Value','Ip')]
        $InputObject,

        [ValidateSet('Big','Little')]
        [string]$Endian = 'Big'
    )
    process {
        $v = $InputObject

        if ($null -eq $v) { return $null }

        # If already dotted-quad, pass through unchanged
        if ($v -is [string] -and $v -match '^\s*(\d{1,3}\.){3}\d{1,3}\s*$') {
            return $v.Trim()
        }

        # Try parse as integer
        try {
            $n = [int64]$v
        } catch {
            # Not an int and not dotted-quad; return original
            return $v
        }

        # Unsigned 32-bit view
        $u = [uint32]($n -band 0xFFFFFFFF)

        # Break into bytes (big-endian order first)
        $b0 = [byte](($u -shr 24) -band 0xFF)
        $b1 = [byte](($u -shr 16) -band 0xFF)
        $b2 = [byte](($u -shr 8)  -band 0xFF)
        $b3 = [byte]($u -band 0xFF)

        if ($Endian -eq 'Big') {
            return ('{0}.{1}.{2}.{3}' -f $b0,$b1,$b2,$b3)
        } else {
            return ('{0}.{1}.{2}.{3}' -f $b3,$b2,$b1,$b0)
        }
    }
}

function Ensure-IPv4 {
    <#
    .SYNOPSIS
        Ensures a field is represented as dotted-quad IPv4 text.
    .DESCRIPTION
        If the input is already dotted-quad, it's returned unchanged; otherwise it converts the signed int.
        By default assumes Big-endian (network byte order). Use -Endian Little if your source stores ints little-endian.
    .PARAMETER Value
        The value to normalize.
    .PARAMETER Endian
        'Big' (default) or 'Little'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $Value,
        [ValidateSet('Big','Little')]
        [string]$Endian = 'Big'
    )
    process {
        $Value | Convert-ToIPv4 -Endian $Endian
    }
}

# --- IPv4 field auto-normalization helpers ------------------------------------
function Convert-PropertyToIPv4 {
    param(
        [string]$Name,
        $Value,
        [ValidateSet('Big','Little')]
        [string]$Endian = 'Big'
    )
    # If property name suggests it is an IP, normalize; otherwise pass through.
    if ($null -eq $Name) { return $Value }
    if ($Name -match '(^|_)(ip|ip_addr|ip_address)$' -or $Name -like '*_ip' -or $Name -ieq 'ip') {
        return ($Value | Ensure-IPv4 -Endian $Endian)
    }
    return $Value
}

function Convert-IpFieldsRecursive {
    <#
    .SYNOPSIS
        Recursively walks an object (PSCustomObject/Hashtable/Array) and converts any properties
        that look like IPs (e.g., *_ip, ip, ip_address) into dotted-quad via Ensure-IPv4.
    .PARAMETER InputObject
        The input object to normalize. Returned by reference (same instance) when possible.
    .PARAMETER Endian
        Whether integer IPs are stored in Big or Little endian. Default 'Big'.
    .EXAMPLE
        $obj = Get-Content a.json -Raw | ConvertFrom-Json
        $obj | Convert-IpFieldsRecursive | Out-Null
        $obj.process.interface_ip  # now dotted-quad if it was an int
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $InputObject,
        [ValidateSet('Big','Little')]
        [string]$Endian = 'Big'
    )
    process {
        $obj = $InputObject
        if ($null -eq $obj) { return $null }

        if ($obj -is [System.Collections.IDictionary]) {
            foreach ($k in @($obj.Keys)) {
                $obj[$k] = Convert-IpFieldsRecursive -InputObject (Convert-PropertyToIPv4 -Name $k -Value $obj[$k] -Endian $Endian) -Endian $Endian
            }
            return $obj
        }

        if ($obj -is [System.Collections.IEnumerable] -and -not ($obj -is [string])) {
            $i = 0
            foreach ($item in @($obj)) {
                $obj[$i] = Convert-IpFieldsRecursive -InputObject $item -Endian $Endian
                $i++
            }
            return $obj
        }

        if ($obj -is [psobject]) {
            foreach ($p in $obj.PSObject.Properties) {
                $p.Value = Convert-IpFieldsRecursive -InputObject (Convert-PropertyToIPv4 -Name $p.Name -Value $p.Value -Endian $Endian) -Endian $Endian
            }
            return $obj
        }

        return $obj
    }
}

function Normalize-JsonIPs {
    <#
    .SYNOPSIS
        Loads JSON from -Path or accepts an object via -InputObject, converts any integer IP fields
        to dotted-quad (based on property names), and optionally writes JSON to -OutFile.
    .PARAMETER Path
        Path to a JSON file to read.
    .PARAMETER InputObject
        An object already loaded (e.g., from ConvertFrom-Json).
    .PARAMETER Endian
        'Big' (default) or 'Little' endian for integer interpretation.
    .PARAMETER OutFile
        If specified, writes normalized JSON to this path (pretty-printed).
    .OUTPUTS
        Returns the normalized object.
    .EXAMPLE
        Normalize-JsonIPs -Path events.json -OutFile events.normalized.json
    #>
    [CmdletBinding(DefaultParameterSetName='ByPath')]
    param(
        [Parameter(ParameterSetName='ByPath', Mandatory=$true)]
        [string]$Path,

        [Parameter(ParameterSetName='ByObject', Mandatory=$true)]
        $InputObject,

        [ValidateSet('Big','Little')]
        [string]$Endian = 'Big',

        [string]$OutFile,

        [int]$JsonDepth = 32
    )
    if ($PSCmdlet.ParameterSetName -eq 'ByPath') {
        $obj = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    } else {
        $obj = $InputObject
    }

    $null = $obj | Convert-IpFieldsRecursive -Endian $Endian

    if ($OutFile) {
        $json = $obj | ConvertTo-Json -Depth $JsonDepth
        $json | Set-Content -LiteralPath $OutFile -Encoding UTF8
    }

    return $obj
}
# --- end IPv4 field auto-normalization helpers --------------------------------
