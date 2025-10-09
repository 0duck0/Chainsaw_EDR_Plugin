<#
Convert Carbon Black "process" JSON docs (with sorted_events) into Sigma-friendly JSONL.
- Emits a synthetic ProcessCreate from the process header
- Normalizes timestamps to UTC RFC3339
- UTF-8 (no BOM) output
Tested on Windows PowerShell 5.1+

.\CB_ToSigmaJsonl.ps1 -SourceDir "E:\Chainsaw_Project\CB_Process_Data\NCEUPWS14101T" -OutDir "E:\Chainsaw_Project\normalized_events" -CombineOutput
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$SourceDir,
  [Parameter(Mandatory=$true)][string]$OutDir,
  [string]$Pattern = '*.json',
  [switch]$CombineOutput
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $SourceDir)) { throw "SourceDir not found: $SourceDir" }
if (-not (Test-Path -LiteralPath $OutDir))   { New-Item -ItemType Directory -Path $OutDir | Out-Null }

# ---------- Helpers ----------
function Get-Prop {
  param([object]$o,[string]$name)
  if ($null -eq $o) { return $null }
  $p = $o.PSObject.Properties[$name]
  if ($p -and $null -ne $p.Value -and "$($p.Value)" -ne "") { return $p.Value }
  return $null
}

function Normalize-TimeString {
  param([string]$Value)
  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  $v = $Value.Trim()
  $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor `
            [System.Globalization.DateTimeStyles]::AdjustToUniversal
  $fmt = @(
    'yyyy-MM-ddTHH:mm:ss.fffffffZ','yyyy-MM-ddTHH:mm:ss.fffZ','yyyy-MM-ddTHH:mm:ssZ',
    'yyyy-MM-dd HH:mm:ss.ffffff','yyyy-MM-dd HH:mm:ss.fff','yyyy-MM-dd HH:mm:ss',
    'yyyy/MM/ddTHH:mm:ss.fffZ','yyyy/MM/ddTHH:mm:ssZ',
    'MM/dd/yyyy HH:mm:ssZ','M/d/yyyy H:mm:ssZ','MM/dd/yyyy HH:mm:ss','M/d/yyyy H:mm:ss'
  )
  $ci = [System.Globalization.CultureInfo]::InvariantCulture
  foreach ($f in $fmt) {
    $dto=[datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParseExact($v,$f,$ci,$styles,[ref]$dto)) {
      return $dto.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ',$ci)
    }
  }
  try {
    $dto=[datetimeoffset]::Parse($v,$ci,$styles)
    return $dto.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ',$ci)
  } catch { return $Value } # leave as-is if truly unparseable
}

function Warn-Norm { param([string]$msg,[object]$obj)
  try { $j = $obj | ConvertTo-Json -Depth 7 -Compress } catch { $j = "$obj" }
  Write-Warning "$msg`nOffending: $j"
}

# access mask decoders (for ProcessOpen/RemoteThread)
function Decode-ProcessAccessMask { param([int]$Mask)
  $n=@(); if($Mask -band 0x0001){$n+='PROCESS_TERMINATE'}; if($Mask -band 0x0002){$n+='PROCESS_CREATE_THREAD'}
  if($Mask -band 0x0008){$n+='PROCESS_VM_OPERATION'}; if($Mask -band 0x0010){$n+='PROCESS_VM_READ'}
  if($Mask -band 0x0020){$n+='PROCESS_VM_WRITE'}; if($Mask -band 0x0040){$n+='PROCESS_DUP_HANDLE'}
  if($Mask -band 0x0080){$n+='PROCESS_CREATE_PROCESS'}; if($Mask -band 0x0100){$n+='PROCESS_SET_QUOTA'}
  if($Mask -band 0x0200){$n+='PROCESS_SET_INFORMATION'}; if($Mask -band 0x0400){$n+='PROCESS_QUERY_INFORMATION'}
  if($Mask -band 0x0800){$n+='PROCESS_SUSPEND_RESUME'}; if($Mask -band 0x1000){$n+='PROCESS_QUERY_LIMITED_INFORMATION'}
  if($Mask -band 0x00100000){$n+='SYNCHRONIZE'}; return $n
}
function Decode-ThreadAccessMask { param([int]$Mask)
  $n=@(); if($Mask -band 0x0001){$n+='THREAD_TERMINATE'}; if($Mask -band 0x0002){$n+='THREAD_SUSPEND_RESUME'}
  if($Mask -band 0x0008){$n+='THREAD_GET_CONTEXT'}; if($Mask -band 0x0010){$n+='THREAD_SET_CONTEXT'}
  if($Mask -band 0x0020){$n+='THREAD_SET_INFORMATION'}; if($Mask -band 0x0040){$n+='THREAD_QUERY_INFORMATION'}
  if($Mask -band 0x0080){$n+='THREAD_SET_THREAD_TOKEN'}; if($Mask -band 0x0100){$n+='THREAD_IMPERSONATE'}
  if($Mask -band 0x0200){$n+='THREAD_DIRECT_IMPERSONATION'}; if($Mask -band 0x00100000){$n+='SYNCHRONIZE'}
  return $n
}

function Emit-HeaderProcessCreate {
  param([object]$p)
  $evtTime = Normalize-TimeString (Get-Prop $p 'start')
  $HostName = Get-Prop $p 'hostname'
  $srcPid  = Get-Prop $p 'process_pid'
  $srcGuid = Get-Prop $p 'unique_id'
  $img     = Get-Prop $p 'path'

  $md5     = Get-Prop $p 'process_md5'
  $sha256  = Get-Prop $p 'process_sha256'

  # optional signer enrichment if present
  $company=$null; $signed=$null; $sigStatus=$null
  $bins = Get-Prop $p 'binaries'
  if ($md5 -and $bins) {
    $k = $md5.ToString().ToUpperInvariant()
    $entry = $bins.$k
    if (-not $entry) {
      foreach ($n in $bins.PSObject.Properties.Name) { if ($n.ToUpperInvariant() -eq $k){ $entry = $bins.$n; break } }
    }
    if ($entry) {
      $sigStatus = Get-Prop $entry 'digsig_result'
      $company   = Get-Prop $entry 'digsig_publisher'
      if ($sigStatus) { $signed = @('signed','valid','ok') -contains ($sigStatus.ToString().ToLowerInvariant()) }
    }
  }

  [pscustomobject]@{
    EventType        = 'ProcessCreate'
    EventTime        = $evtTime
    Host             = $HostName
    SourceImage      = $img
    SourcePid        = $srcPid
    SourceProcessId  = $srcGuid

    Image            = $img
    CommandLine      = Get-Prop $p 'cmdline'
    User             = Get-Prop $p 'username'
    ParentImage      = Get-Prop $p 'parent_name'
    ParentProcessId  = Get-Prop $p 'parent_pid'
    md5              = $md5
    sha256           = $sha256

    Company          = $company
    Signed           = $signed
    SignatureStatus  = $sigStatus
  }
}

# ---------- Core conversion ----------
function Convert-Doc {
  param([object]$doc)

  if (-not ($doc.PSObject.Properties.Name -contains 'process')) { return @() }
  $p = $doc.process
  if (-not $p) { return @() }

  $rows = New-Object System.Collections.Generic.List[object]

  # 1) Synthetic header ProcessCreate
  try { [void]$rows.Add( (Emit-HeaderProcessCreate -p $p) ) }
  catch { Warn-Norm "Header emit failed: $($_.Exception.Message)" $p }

  $HostName = Get-Prop $p 'hostname'
  $srcGuid  = Get-Prop $p 'unique_id'
  $srcPid   = Get-Prop $p 'process_pid'
  $srcImg   = Get-Prop $p 'path'

  $events = @()
  if ($p.PSObject.Properties.Name -contains 'sorted_events' -and $null -ne $p.sorted_events) {
    $events = $p.sorted_events
  }

  foreach ($e in $events) {
    try {
      $t = Get-Prop $e 'type'
      $topTime = Normalize-TimeString (Get-Prop $e 'time')

      # some CB feeds wrap payload in 'data' or embed directly
      $payload = if ($e.PSObject.Properties.Name -contains 'data') { $e.data } else { $e }

      switch ($t) {
        'regmod' {
          if (-not ($payload -is [string])) { break }
          $f = $payload.Split('|')
          if ($f.Count -lt 3) { break }
          $op=[int]0; [void][int]::TryParse($f[0],[ref]$op)
          $regOp = switch ($op) { 1{'RegCreate'} 2{'RegWrite'} 4{'RegDeleteKey'} 8{'RegDeleteValue'} default{'RegOp'} }
          $evtTimeStr = Normalize-TimeString ($f[1])
          $evtOut = if ($evtTimeStr) { $evtTimeStr } else { $topTime }
          $rows.Add([pscustomobject]@{
            EventType='Reg'; EventTime=$evtOut; Host=$HostName
            SourceImage=$srcImg; SourcePid=$srcPid; SourceProcessId=$srcGuid
            RegOp=$regOp; TargetObject=$f[2]
          }) | Out-Null
        }

        'filemod' {
          if (-not ($payload -is [string])) { break }
          $f = $payload.Split('|',7)
          if ($f.Count -lt 3) { break }
          $op=[int]0; [void][int]::TryParse($f[0],[ref]$op)
          $fileOp = switch ($op) { 1{'FileCreate'} 2{'FileWriteFirst'} 4{'FileDelete'} 8{'FileWriteLast'} default{'FileOp'} }
          $evtTimeStr = Normalize-TimeString ($f[1])
          $evtOut = if ($evtTimeStr) { $evtTimeStr } else { $topTime }
          $rows.Add([pscustomobject]@{
            EventType='File'; EventTime=$evtOut; Host=$HostName
            SourceImage=$srcImg; SourcePid=$srcPid; SourceProcessId=$srcGuid
            FileOp=$fileOp; TargetFilename=$f[2]
          }) | Out-Null
        }

        'modload' {
          if (-not ($payload -is [string])) { break }
          $f = $payload.Split('|')
          if ($f.Count -lt 3) { break }
          $evtTimeStr = Normalize-TimeString ($f[0])
          $evtOut = if ($evtTimeStr) { $evtTimeStr } else { $topTime }
          $rows.Add([pscustomobject]@{
            EventType='ImageLoad'; EventTime=$evtOut; Host=$HostName
            SourceImage=$srcImg; SourcePid=$srcPid; SourceProcessId=$srcGuid
            md5=$f[1]; ImageLoaded=$f[2]
            sha256=$(if ($f.Count -ge 4 -and $f[3]) { $f[3] } else { $null })
          }) | Out-Null
        }

        'fileless_scriptload' {
          if (-not ($payload -is [string])) { break }
          $f = $payload.Split('|')
          if ($f.Count -lt 3) { break }
          $evtTimeStr = Normalize-TimeString ($f[0])
          $evtOut = if ($evtTimeStr) { $evtTimeStr } else { $topTime }
          $pidInt=$null; [void][int]::TryParse($f[1],[ref]$pidInt)
          $rows.Add([pscustomobject]@{
            EventType='FilelessScriptLoad'; EventTime=$evtOut; Host=$HostName
            SourceImage=$srcImg; SourcePid=$srcPid; SourceProcessId=$srcGuid
            ScriptEnginePid=$pidInt; sha256=$f[2]
          }) | Out-Null
        }

        'netconn' {
          if ($payload -is [string]) {
            # legacy v1: "time|ip|port|proto|domain|outboundBool"
            $f = $payload.Split('|'); if ($f.Count -lt 6) { break }
            $evtTimeStr = Normalize-TimeString ($f[0])
            $evtOut = if ($evtTimeStr) { $evtTimeStr } else { $topTime }
            $isOut = ($f[5] -eq 'true' -or $f[5] -eq 'True')
            $rows.Add([pscustomobject]@{
              EventType='NetworkConnect'; EventTime=$evtOut; Host=$HostName
              SourceImage=$srcImg; SourcePid=$srcPid; SourceProcessId=$srcGuid
              Protocol=$f[3]; DestinationHostname=$f[4]; Direction=$(if($isOut){'Outbound'}else{'Inbound'})
              SourceIp=$(if($isOut){$null}else{$f[1]}); SourcePort=$(if($isOut){$null}else{$f[2]})
              DestinationIp=$(if($isOut){$f[1]}else{$null}); DestinationPort=$(if($isOut){$f[2]}else{$null})
            }) | Out-Null
          } else {
            # v5 object
            $d=$payload
            $evtTimeStr = Normalize-TimeString (Get-Prop $d 'timestamp')
            $evtOut = if ($evtTimeStr) { $evtTimeStr } else { $topTime }
            $dirRaw  = Get-Prop $d 'direction'
            $direction = if ($dirRaw -is [bool]) { if ($dirRaw) {'Outbound'} else {'Inbound'} }
              elseif (("$dirRaw") -match '^(true|1)$') {'Outbound'} else {'Inbound'}
            $rows.Add([pscustomobject]@{
              EventType='NetworkConnect'; EventTime=$evtOut; Host=$HostName
              SourceImage=$srcImg; SourcePid=$srcPid; SourceProcessId=$srcGuid
              Protocol=(Get-Prop $d 'proto'); DestinationHostname=(Get-Prop $d 'domain'); Direction=$direction
              SourceIp=(Get-Prop $d 'local_ip'); SourcePort=(Get-Prop $d 'local_port')
              DestinationIp=(Get-Prop $d 'remote_ip'); DestinationPort=(Get-Prop $d 'remote_port')
            }) | Out-Null
          }
        }

        'childproc' {
          # object payload expected: start/end/path/md5/sha256/pid/processId/userName/commandLine/type
          $d = $null
          if ($payload -is [pscustomobject]) { $d = $payload } else { $d = [pscustomobject]$payload }
          $kind = (Get-Prop $d 'type')
          $evt  = if ($kind -eq 'start') {'ProcessCreate'} else {'ProcessTerminate'}
          $rawT = (Get-Prop $d 'end'); if (-not $rawT) { $rawT = (Get-Prop $d 'start') }
          if (-not $rawT) { $rawT = (Get-Prop $d 'timestamp') }
          $evtTimeStr = Normalize-TimeString $rawT
          $evtOut = if ($evtTimeStr) { $evtTimeStr } else { $topTime }
          $rows.Add([pscustomobject]@{
            EventType=$evt; EventTime=$evtOut; Host=$HostName
            SourceImage=$srcImg; SourcePid=$srcPid; SourceProcessId=$srcGuid
            Image=(Get-Prop $d 'path'); CommandLine=(Get-Prop $d 'commandLine'); User=(Get-Prop $d 'userName')
            md5=(Get-Prop $d 'md5'); sha256=(Get-Prop $d 'sha256')
            ParentImage=(Get-Prop $p 'path'); ParentProcessId=$srcPid
          }) | Out-Null
        }

        'crossproc' {
          if (-not ($payload -is [string])) { break }
          # "type|time|target_unique_id|target_md5|target_path|subtype|requested_access|tamper|..."
          $f = $payload.Split('|'); if ($f.Count -lt 5) { break }
          $cType=$f[0]
          $evtType = if ($cType -eq 'RemoteThread') {'CreateRemoteThread'} elseif ($cType -eq 'ProcessOpen') {'ProcessOpen'} else {$cType}
          $evtTimeStr = Normalize-TimeString ($f[1])
          $evtOut = if ($evtTimeStr) { $evtTimeStr } else { $topTime }
          $openSubtype=$null; $mask=$null
          if ($f.Count -ge 6 -and $f[5]) { $tmp=0; if([int]::TryParse($f[5],[ref]$tmp)){$openSubtype=$tmp} }
          if ($f.Count -ge 7 -and $f[6]) {
            $maskRaw=$f[6]
            if ($maskRaw -like '0x*'){ try{$mask=[Convert]::ToInt32($maskRaw,16)}catch{$mask=$null} }
            else { $tmp=0; if([int]::TryParse($maskRaw,[ref]$tmp)){$mask=$tmp} }
          }
          $access=$null
          if ($evtType -eq 'ProcessOpen' -and $mask -ne $null) {
            $access = if ($openSubtype -eq 2) { Decode-ThreadAccessMask -Mask $mask } else { Decode-ProcessAccessMask -Mask $mask }
          }
          $rows.Add([pscustomobject]@{
            EventType=$evtType; EventTime=$evtOut; Host=$HostName
            SourceImage=$srcImg; SourcePid=$srcPid; SourceProcessId=$srcGuid
            TargetImage=$f[4]; GrantedAccessMask=$mask; GrantedAccess=$access
          }) | Out-Null
        }
      }
    } catch {
      Warn-Norm "Event conversion failed: $($_.Exception.Message)" $e
    }
  }

  return $rows
}

# ---------- Main ----------
$files = Get-ChildItem -LiteralPath $SourceDir -File -Filter $Pattern -ErrorAction Stop
if ($files.Count -eq 0) { Write-Warning "No files matched pattern '$Pattern' in $SourceDir"; return }

$combinedWriter=$null
if ($CombineOutput) {
  $combinedWriter = New-Object System.IO.StreamWriter(
    (Join-Path $OutDir 'combined.normalized.jsonl'),
    $false,
    (New-Object System.Text.UTF8Encoding($false))
  )
}

foreach ($fi in $files) {
  try {
    $raw = Get-Content -LiteralPath $fi.FullName -Raw
    $null = $raw | Test-Json -ErrorAction Stop
  } catch {
    Write-Warning "Skipping invalid JSON: $($fi.Name) ($($_.Exception.Message))"
    continue
  }

  $json = $raw | ConvertFrom-Json
  $docs = if ($json -is [System.Collections.IEnumerable] -and -not ($json -is [string])) { $json } else { @($json) }

  $outFile = Join-Path $OutDir ($fi.BaseName + '.normalized.jsonl')
  $sw = New-Object System.IO.StreamWriter($outFile, $false, (New-Object System.Text.UTF8Encoding($false)))
  try {
    foreach ($doc in $docs) {
      $rows = Convert-Doc -doc $doc
      foreach ($r in $rows) {
        $line = ($r | ConvertTo-Json -Depth 12 -Compress)
        $sw.WriteLine($line)
        if ($CombineOutput) { $combinedWriter.WriteLine($line) }
      }
    }
  } finally { $sw.Dispose() }

  Write-Host "Wrote -> $outFile"
}

if ($combinedWriter) {
  $combinedWriter.Dispose()
  Write-Host ("Also wrote -> {0}" -f (Join-Path $OutDir 'combined.normalized.jsonl'))
}
