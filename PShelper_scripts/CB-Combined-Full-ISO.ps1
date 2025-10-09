# CB-Combined-Full-ISO.ps1
<#
.\CB-Combined-Full-ISO.ps1 `
  -InputPath "E:\Chainsaw_Project\CB_Process_Data\NCEUPWS14101T" `
  -OutputPath "E:\Hayabusa_Project\hayabusa\flattened_CBdata" `
  -DropOriginalData

#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$InputPath,
  [Parameter(Mandatory)][string]$OutputPath,
  [switch]$DropOriginalData
)
$ErrorActionPreference = 'Stop'

# ========================
# Helpers
# ========================
function _EnsureDir { param([string]$p) if ($p -and -not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null } }
function _LeafFromPath { param([string]$p) if ($p) { try { Split-Path -Leaf $p } catch { $null } } }

function _SafeIndex { param($arr, [int]$i) if ($null -eq $arr -or $i -lt 0 -or $i -ge $arr.Count) { $null } else { $arr[$i] } }
function _SplitPipe { param([string]$s, [int]$max=0) if ([string]::IsNullOrWhiteSpace($s)) { @() } elseif ($max -gt 0) { $s -split '\|', $max } else { $s -split '\|' } }

function _IntOrNull { param($v) if ($null -eq $v -or $v -eq '') { return $null }; try { return [int]$v } catch { return $null } }
function _BoolFromStr {
  param($v)
  if ($null -eq $v) { return $null }
  if ($v -is [bool]) { return [bool]$v }
  $s = "$v".Trim().ToLowerInvariant()
  switch ($s) {
    {$_ -in @('true','t','yes','y','1')} { return $true }
    {$_ -in @('false','f','no','n','0')} { return $false }
    default { return $null }
  }
}
function _IsHexWithLength { param([string]$s, [int]$n) if ([string]::IsNullOrWhiteSpace($s)) { $false } else { return ($s -match ('^[A-Fa-f0-9]{' + $n + '}$')) } }

function _ProtocolNameFromNum {
  param($proto)
  $p = _IntOrNull $proto
  if ($p -eq $null) { return $proto }
  switch ($p) {
    6  { 'TCP' }
    17 { 'UDP' }
    1  { 'ICMP' }
    2  { 'IGMP' }
    41 { 'IPv6' }
    default { "$p" }
  }
}
function _DirectionNameFromBool {
  param($v)
  $b = _BoolFromStr $v
  if ($b -eq $null) { return $v }
  if ($b) { 'outbound' } else { 'inbound' }
}

function _CbFileTypeName {
  param([int]$code)
  switch ($code) {
    0 { 'Unknown' }
    1 { 'PE/EXE' }
    2 { 'DLL' }
    3 { 'Driver' }
    4 { 'Script' }
    5 { 'Document' }
    6 { 'Archive' }
    default { "$code" }
  }
}
function _CbFilemodActionName {
  param([int]$op)
  switch ($op) {
    1 { 'create' }
    2 { 'first_write' }
    4 { 'delete' }
    8 { 'last_write' }
    default { "$op" }
  }
}

function _SplitRegistryPath {
  param([string]$rawPath)
  if ([string]::IsNullOrWhiteSpace($rawPath)) { return @{ path=$null; key=$null; value=$null } }
  $idx = $rawPath.LastIndexOf('\')
  if ($idx -gt 0 -and $idx -lt ($rawPath.Length-1)) {
    return @{ path=$rawPath; key=$rawPath.Substring(0,$idx); value=$rawPath.Substring($idx+1) }
  } else {
    return @{ path=$rawPath; key=$rawPath; value=$null }
  }
}

function _MapEventID {
  param([string]$etype, [hashtable]$df)

  $t = ($etype ?? '').ToLowerInvariant()
  switch ($t) {
    'childproc' { return 1 }      # Sysmon Process Create
    'netconn'   { return 3 }      # Sysmon Network Connection
    'modload'   { return 7 }      # Sysmon Image Loaded
    'filemod'   { return 11 }     # Sysmon File Create (best fit for most filemods)
    'crossproc' {
      # We already parse $df.action as 'RemoteThread' or 'ProcessOpen'
      if ($df.ContainsKey('action') -and $df.action -match '^(?i)RemoteThread$') { return 8 }   # CreateRemoteThread
      elseif ($df.ContainsKey('action') -and $df.action -match '^(?i)ProcessOpen$') { return 10 } # ProcessAccess
      else { return 8 }
    }
    'regmod' {
      # If you parse a reg action, refine mapping:
      if ($df.ContainsKey('reg_action')) {
        switch ($df.reg_action) {
          'create'       { return 12 }  # Registry object create/delete
          'delete_key'   { return 12 }
          'first_write'  { return 13 }  # Registry value set
          'delete_value' { return 12 }  # (closest Sysmon category)
          default        { return 12 }
        }
      } else { return 12 }
    }
    default { return $null }
  }
}


# ---------- Timestamp normalization ----------
function _ParseToUtc {
  param($v)
  if ($null -eq $v) { return $null }
  if ($v -is [datetime]) { return ([datetime]$v).ToUniversalTime() }
  $s = [string]$v
  try {
    # Epoch millis/seconds
    if ($s -match '^\d{13}$') { return ([datetimeoffset]::FromUnixTimeMilliseconds([int64]$s).UtcDateTime) }
    if ($s -match '^\d{10}$') { return ([datetimeoffset]::FromUnixTimeSeconds([int64]$s).UtcDateTime) }

    $formats = @(
      "yyyy-MM-dd HH:mm:ss.FFFFFFF",
      "yyyy-MM-dd HH:mm:ss",
      "MM/dd/yyyy HH:mm:ss",
      "M/d/yyyy H:mm:ss",
      "yyyy-MM-ddTHH:mm:ss.FFFFFFFK",
      "yyyy-MM-ddTHH:mm:ssK",
      "yyyy-MM-ddTHH:mm:ss.FFFFFFF'Z'",
      "yyyy-MM-ddTHH:mm:ss'Z'",
      "yyyy/MM/ddTHH:mm:ss.FFFFFFF'Z'",
      "yyyy/MM/ddTHH:mm:ss'Z'",
      "yyyy/MM/dd HH:mm:ss",
      "yyyy/MM/ddTHH:mm:ss"
    )
    $style = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $dt = [datetime]::ParseExact($s, $formats, [System.Globalization.CultureInfo]::InvariantCulture, $style)
    return $dt.ToUniversalTime()
  } catch {
    try {
      # Fallback general parse
      $dt2 = [datetime]::Parse($s, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal)
      return $dt2.ToUniversalTime()
    } catch {
      return $null
    }
  }
}
function _ToIsoZ {
  param($v)
  $dt = _ParseToUtc $v
  if ($dt -ne $null) {
    return $dt.ToString("yyyy'/'MM'/'dd'T'HH':'mm':'ss'.000Z'")
  }
  return $null
}
function _IsoOrOrig {
  param($v)
  $iso = _ToIsoZ $v
  if ($iso) { $iso } else { $v }
}

# ========================
# Event normalization
# ========================
function Add-DataFieldsToEvent {
  param([pscustomobject]$Ev, [switch]$Drop)

  # Copy to ordered table so we can mutate
  $out = [ordered]@{}
  foreach ($p in $Ev.PSObject.Properties) { $out[$p.Name] = $p.Value }

  # Top-level time normalization
  if ($out.Contains('time') -and $out['time']) { $out['time'] = _IsoOrOrig $out['time'] }

  $df = [ordered]@{}
  $type = $out['type']
  $hasData = $out.Contains('data')

  if ($hasData -and ($out['data'] -is [pscustomobject] -or $out['data'] -is [hashtable])) {
    foreach ($dprop in $out['data'].psobject.properties) { $df[$dprop.Name] = $dprop.Value }

    # Derive leaf for non-modload
    if ($df.Contains('path') -and $df['path'] -and ($type -notmatch '^(?i)modload$')) {
      $df['childproc_name'] = _LeafFromPath $df['path']
    }

    # netconn enrich
    if ($type -match '^(?i)netconn$') {
      if ($df['proto'] -ne $null) { $df['protocol'] = _ProtocolNameFromNum $df['proto'] }
      if ($df.Contains('direction')) { $df['direction'] = _DirectionNameFromBool $df['direction'] }

      $dir = $df['direction']
      $localIp   = $df['local_ip']
      $localPort = $df['local_port']
      $remoteIp  = $df['remote_ip']
      $remotePort= $df['remote_port']

      if ($dir -eq 'outbound') {
        $df['SourceIp']        = $localIp
        $df['SourcePort']      = $localPort
        $df['DestinationIp']   = $remoteIp
        $df['DestinationPort'] = $remotePort
      }
      elseif ($dir -eq 'inbound') {
        $df['SourceIp']        = $remoteIp
        $df['SourcePort']      = $remotePort
        $df['DestinationIp']   = $localIp
        $df['DestinationPort'] = $localPort
      }
      else {
        if ($localIp)   { $df['SourceIp']        = $localIp }
        if ($localPort) { $df['SourcePort']      = $localPort }
        if ($remoteIp)  { $df['DestinationIp']   = $remoteIp }
        if ($remotePort){ $df['DestinationPort'] = $remotePort }
      }
    }

    # Normalize any embedded time keys
    if ($df.Contains('eventTime') -and $df['eventTime']) { $df['eventTime'] = _IsoOrOrig $df['eventTime'] }
    if ($df.Contains('time')      -and $df['time'])      { $df['time']      = _IsoOrOrig $df['time'] }
  }
  elseif ($hasData -and ($out['data'] -is [string])) {
    $s = $out['data']
    switch -regex ($type) {
      '^(?i)modload$' {
        $p = _SplitPipe $s 4
        $df['eventTime'] = _IsoOrOrig (_SafeIndex $p 0)
        $df['md5']       = _SafeIndex $p 1
        $df['path']      = _SafeIndex $p 2
        if ($df['path']) { $df['ImageLoaded'] = _LeafFromPath $df['path'] }
        $df['sha256']    = _SafeIndex $p 3
      }
      '^(?i)fileless_scriptload$' {
        $p = _SplitPipe $s 4
        $df['eventTime'] = _IsoOrOrig (_SafeIndex $p 0)
        $df['typeCode']  = _SafeIndex $p 1
        $df['sha256']    = _SafeIndex $p 2
        $df['fileless_scriptload_cmdline'] = _SafeIndex $p 3
        $df['scriptSnippet']               = $df['fileless_scriptload_cmdline']
      }
      '^(?i)filemod$' {
        $p   = _SplitPipe $s
        $op  = _IntOrNull (_SafeIndex $p 0)
        $df['operationCode'] = $op
        $df['operation']     = _CbFilemodActionName $op
        $df['eventTime']     = _IsoOrOrig (_SafeIndex $p 1)
        $df['path']          = _SafeIndex $p 2
        if ($df['path']) { $df['filename'] = _LeafFromPath $df['path'] }
        $postMd5 = _SafeIndex $p 3
        if ($op -eq 8 -and $postMd5) {
          $df['postWriteMd5'] = $postMd5
          $df['isLastWrite']  = $true
          $df['md5']          = $postMd5
        } elseif ($op -eq 8) {
          $df['isLastWrite']  = $true
        }
        $fileTypeCode = _IntOrNull (_SafeIndex $p 4)
        if ($fileTypeCode -ne $null) { $df['fileTypeCode'] = $fileTypeCode; $name = _CbFileTypeName $fileTypeCode; if ($name) { $df['fileTypeName'] = $name } }
        $tamperTok = _SafeIndex $p 5
        if (-not [string]::IsNullOrWhiteSpace($tamperTok)) { $df['isTamper'] = _BoolFromStr $tamperTok }
        for ($i = $p.Count - 1; $i -ge 3; $i--) { if (_IsHexWithLength -s $p[$i] -n 64) { $df['sha256'] = $p[$i]; break } }
      }
      '^(?i)crossproc$' {
        $p = _SplitPipe $s
        $df['action']        = _SafeIndex $p 0
        $df['eventTime']     = _IsoOrOrig (_SafeIndex $p 1)
        $df['processId']     = _SafeIndex $p 2
        $df['md5']           = _SafeIndex $p 3
        $df['targetPath']    = _SafeIndex $p 4
        if ($df['targetPath']) { $df['targetName'] = _LeafFromPath $df['targetPath'] }
        $df['sha256']        = _SafeIndex $p 9
      }
      '^(?i)childproc$' {
        $p = _SplitPipe $s
        $df['md5']         = _SafeIndex $p 0
        $df['path']        = _SafeIndex $p 1
        if ($df['path'])   { $df['childproc_name'] = _LeafFromPath $df['path'] }
        $df['commandLine'] = _SafeIndex $p 2
        $df['userName']    = _SafeIndex $p 3
        $df['sha256']      = _SafeIndex $p 4
        $df['pid']         = _SafeIndex $p 5
        $df['processId']   = _SafeIndex $p 6
      }
      '^(?i)regmod$' {
        $p = _SplitPipe $s 4
        $flag      = _SafeIndex $p 0
        $eventTime = _SafeIndex $p 1
        $regPath   = _SafeIndex $p 2
        $isValue   = _BoolFromStr (_SafeIndex $p 3)

        $df['flag']      = $flag
        $df['eventTime'] = _IsoOrOrig $eventTime
        $split = _SplitRegistryPath $regPath
        $df['registry_path']   = $split.path
        $df['registry_key']    = $split.key
        $df['registry_value']  = $split.value
        if ($isValue -ne $null) { $df['registry_isValue'] = $isValue }

        $df['reg_action'] = switch ($flag) {
          '1' { 'create' }
          '2' { 'first_write' }
          '4' { 'delete_key' }
          '8' { 'delete_value' }
          default { $flag }
        }
      }
      default {
        $p = _SplitPipe $s
        if ($p.Count -gt 0) { $df['token0'] = _IsoOrOrig (_SafeIndex $p 0) }
        for ($i=1; $i -lt [Math]::Min($p.Count,6); $i++) { $df["token$($i)"] = _SafeIndex $p $i }
      }
    }
  }
  elseif ($out.Contains('data_fields') -and $out['data_fields']) {
    $dfobj = $out['data_fields']
    if ($dfobj.PSObject.Properties.Name -contains 'eventTime' -and $dfobj.eventTime) { $dfobj.eventTime = _IsoOrOrig $dfobj.eventTime }
    if ($dfobj.PSObject.Properties.NAme -contains 'time'      -and $dfobj.time)      { $dfobj.time      = _IsoOrOrig $dfobj.time }
    foreach ($p in $dfobj.PSObject.Properties) { $df[$p.Name] = $p.Value }
  }
  $eid = _MapEventID -etype $type -df $df
  if ($eid -ne $null) { $out['EventID'] = $eid }

  $out['data_fields'] = [pscustomobject]$df
  if ($Drop -and $out.Contains('data')) { $out.Remove('data') }
  return [pscustomobject]$out
}

# ========================
# Worker
# ========================
function Do-Convert {
  param(
    [Parameter(Mandatory)][string]$InputPath,
    [Parameter(Mandatory)][string]$OutputPath,
    [switch]$DropOriginalData
  )

  $raw = Get-Content -LiteralPath $InputPath -Raw -Encoding UTF8
  try { $root = $raw | ConvertFrom-Json -Depth 64 } catch { throw "Failed to parse JSON: $InputPath. $_" }

  if ($root -is [pscustomobject]) {
    $wrapper = $root
    $events = $null; $proc = $null

    if ($wrapper.PSObject.Properties.Name -contains 'process' -and $wrapper.process.PSObject.Properties.Name -contains 'sorted_events') {
      $events = @($wrapper.process.sorted_events); $proc = $wrapper.process
    } elseif ($wrapper.PSObject.Properties.Name -contains 'sorted_events') {
      $events = @($wrapper.sorted_events); $proc = $wrapper
    } else {
      if ($wrapper -is [System.Collections.IEnumerable]) { $new = foreach ($ev in $wrapper) { Add-DataFieldsToEvent -Ev $ev -Drop:$DropOriginalData } }
      else { $new = @(Add-DataFieldsToEvent -Ev $wrapper -Drop:$DropOriginalData) }
      _EnsureDir (Split-Path -Parent $OutputPath)
      $new | ConvertTo-Json -Depth 64 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
      Write-Host "Wrote $($new.Count) events to: $OutputPath"
      return
    }

    # Build synthetic, normalize timestamps
    $synthetic = [ordered]@{
      type        = 'childproc'
      time        = _IsoOrOrig ($proc.start)
      hostname    = if ($wrapper.hostname) { $wrapper.hostname } elseif ($proc.hostname) { $proc.hostname } else { $null }
      data        = 'synthetic_from_wrapper'
      data_fields = [ordered]@{
        eventTime     = _IsoOrOrig ($proc.start)
        path          = $proc.path
        ImageLoaded   = $null
        childproc_name = $proc.process_name
        commandLine   = $proc.cmdline
        userName      = $proc.username
        md5           = $proc.process_md5
        sha256        = $proc.process_sha256
        pid           = $proc.process_pid
        processId     = $proc.id
        parentImage   = $proc.parent_name
        parentPid     = $proc.parent_pid
      }
    }
    $synthetic.Image           = $synthetic.data_fields.path
    $synthetic.CommandLine     = $synthetic.data_fields.commandLine
    $synthetic.User            = $synthetic.data_fields.userName
    $synthetic.ProcessId       = $synthetic.data_fields.pid
    $synthetic.ParentImage     = $synthetic.data_fields.parentImage
    $synthetic.ParentProcessId = $synthetic.data_fields.parentPid
    $synthetic.EventID         = 1  # childproc ~ Sysmon EID 1


    $norm = foreach ($ev in $events) { Add-DataFieldsToEvent -Ev $ev -Drop:$DropOriginalData }
    $flat = @([pscustomobject]$synthetic) + @($norm)
    _EnsureDir (Split-Path -Parent $OutputPath)
    $flat | ConvertTo-Json -Depth 64 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    Write-Host "Wrote $($flat.Count) records (incl. synthetic) to: $OutputPath"
  }
  else {
    $new = foreach ($ev in $root) { Add-DataFieldsToEvent -Ev $ev -Drop:$DropOriginalData }
    _EnsureDir (Split-Path -Parent $OutputPath)
    $new | ConvertTo-Json -Depth 64 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    Write-Host "Wrote $($new.Count) events to: $OutputPath"
  }
}

# ========================
# Dispatcher
# ========================
if (Test-Path -LiteralPath $InputPath -PathType Container) {
  _EnsureDir $OutputPath
  $inFull  = (Resolve-Path -LiteralPath $InputPath).Path
  $outFull = (Resolve-Path -LiteralPath $OutputPath).Path
  Get-ChildItem -LiteralPath $inFull -Filter *.json -File -Recurse | ForEach-Object {
    $rel = $_.FullName.Substring($inFull.Length).TrimStart('\','/')
    $dest = Join-Path $outFull $rel
    _EnsureDir (Split-Path -Parent $dest)
    Write-Host "Processing $($_.FullName) -> $dest"
    Do-Convert -InputPath $_.FullName -OutputPath $dest -DropOriginalData:$DropOriginalData
  }
}
elseif (Test-Path -LiteralPath $InputPath -PathType Leaf) {
  if (Test-Path -LiteralPath $OutputPath -PathType Container) {
    Do-Convert -InputPath $InputPath -OutputPath (Join-Path $OutputPath (Split-Path -Leaf $InputPath)) -DropOriginalData:$DropOriginalData
  } else {
    _EnsureDir (Split-Path -Parent $OutputPath)
    Do-Convert -InputPath $InputPath -OutputPath $OutputPath -DropOriginalData:$DropOriginalData
  }
}
else {
  throw "InputPath not found: $InputPath"
}
