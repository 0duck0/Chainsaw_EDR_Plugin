[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string]$InputPath,
  [Parameter(Mandatory)] [string]$OutputPath,
  [switch]$DropOriginalData   # removes original "data" fields inside events after creating data_fields
)

$ErrorActionPreference = 'Stop'

# ---------------- helpers ----------------
function _SafeIndex { param($arr, [int]$i) if ($null -eq $arr -or $i -lt 0 -or $i -ge $arr.Count) { $null } else { $arr[$i] } }
function _SplitPipe { param([string]$s, [int]$max=0) if ($null -eq $s) { @() } elseif ($max -gt 0) { $s -split '\|', $max } else { $s -split '\|' } }
function _LeafFromPath { param([string]$p) if ($p) { try { Split-Path -Leaf $p } catch { $null } } }
function _BoolFromStr { param([string]$s) if ($null -eq $s) { return $null } switch -regex ($s.Trim()) { '^(?i)true$' { $true } '^(?i)false$' { $false } default { $s } } }
function _ProtocolNameFromNum { param($n) switch ([int]$n) { 1 {'ICMP'} 6 {'TCP'} 17 {'UDP'} default { "$n" } } }
function _CbFileTypeName {
    param([int]$code)
    switch ($code) {
        1  { 'PE' }
        2  { 'ELF' }
        3  { 'UniversalBin' }
        8  { 'EICAR' }
        16 { 'OfficeLegacy' }
        17 { 'OfficeOpenXml' }
        48 { 'PDF' }
        64 { 'ArchivePkzip' }
        65 { 'ArchiveLzh' }
        66 { 'ArchiveLzw' }
        67 { 'ArchiveRar' }
        68 { 'ArchiveTar' }
        69 { 'Archive7zip' }
        96 { 'LNK' }    # <-- add this
        default { if ($null -ne $code) { "Unknown($code)" } else { $null } }
    }
}

function _DirectionNameFromBool {
    param($v)
    # Accept $true/$false or "true"/"false"
    $b = $v
    if ($v -is [string]) {
        if ($v.Trim() -match '^(?i)true$')  { $b = $true }
        elseif ($v.Trim() -match '^(?i)false$') { $b = $false }
    }
    if ($b -is [bool]) { if ($b) { 'outbound' } else { 'inbound' } } else { $v }
}

function _SplitRegistryPath {
  param([string]$rawPath)
  if (-not $rawPath) { return @{ path=$null; key=$null; value=$null } }
  $p = $rawPath -replace '\\\\','\'
  $unp = $p.Trim('"')
  $parts = $unp -split '\\'
  if ($parts.Count -ge 2) {
    return @{ path=$p; key=($parts[0..($parts.Count-2)] -join '\'); value=$parts[-1] }
  } else { return @{ path=$p; key=$unp; value=$null } }
}

function Read-JsonFlex {
  param([string]$Path)
  $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
  try {
    $j = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($j -is [System.Collections.IEnumerable] -and -not ($j -is [string])) { ,@($j) } else { ,@($j) }
  } catch {
    $items = @()
    foreach ($line in Get-Content -LiteralPath $Path -ErrorAction Stop) {
      $t = $line.Trim()
      if ($t) { try { $items += ,($t | ConvertFrom-Json -ErrorAction Stop) } catch { Write-Warning "Skipping non-JSON line: $t" } }
    }
    ,$items
  }
}

function _IntOrNull { param($s) if ([string]::IsNullOrWhiteSpace($s)) { $null } else { try { [int]$s } catch { $s } } }

function _IsHexWithLength {
    param([string]$s, [int]$n)
    if ([string]::IsNullOrWhiteSpace($s)) { return $false }
    return ($s.Length -eq $n -and $s -match '^[0-9a-fA-F]+$')
}

function _CbFileTypeName {
    param([int]$code)
    switch ($code) {
        0  { 'unknown' }
        1  { 'PE' }
        2  { 'ELF' }
        3  { 'UniversalBin' }
        8  { 'EICAR' }
        16 { 'OfficeLegacy' }
        17 { 'OfficeOpenXml' }
        48 { 'PDF' }
        64 { 'ArchivePkzip' }
        65 { 'ArchiveLzh' }
        66 { 'ArchiveLzw' }
        67 { 'ArchiveRar' }
        68 { 'ArchiveTar' }
        69 { 'Archive7zip' }
        default { if ($null -ne $code) { "Unknown($code)" } else { $null } }
    }
}

function _CbFilemodActionName {
    param([int]$op)
    switch ($op) {
        1 { 'create' }
        2 { 'first_write' }
        4 { 'delete' }
        8 { 'last_write' }
        default { if ($null -ne $op) { "op_$op" } else { $null } }
    }
}

# ---------------- core: event -> event (adds data_fields) ----------------
function Add-DataFieldsToEvent {
  param([pscustomobject]$Ev, [switch]$Drop)

  # Clone to ordered output so we can optionally drop "data"
  $out = [ordered]@{}
  foreach ($p in $Ev.PSObject.Properties) { $out[$p.Name] = $p.Value }

  # Build data_fields
  $df = [ordered]@{}

  $type = $Ev.type
  $hasData = $Ev.PSObject.Properties.Name -contains 'data'

  if ($hasData -and ($Ev.data -is [pscustomobject] -or $Ev.data -is [hashtable])) {
    # Object-form data: copy as normalized fields under data_fields
	<#
    foreach ($dprop in $Ev.data.psobject.properties) { $df[$dprop.Name] = $dprop.Value }
    if ($df.ContainsKey('path') -and $df['path']) { $df['childproc_name'] = _LeafFromPath $df['path'] }
#>
	foreach ($dprop in $Ev.data.psobject.properties) { $df[$dprop.Name] = $dprop.Value }
	# Only derive a leaf name automatically for non-modload events
	if ($df.Contains('path') -and $df['path'] -and ($type -notmatch '^(?i)modload$')) {
		$df['childproc_name'] = _LeafFromPath $df['path']
	}

    # netconn extras
    if ($type -match '^(?i)netconn$') {
		# 1) Protocol name
		if ($df['proto'] -ne $null) {
			$df['protocol'] = _ProtocolNameFromNum $df['proto']   # TCP / UDP / ICMP / "<number>"
		}

		# 2) Direction -> 'outbound' / 'inbound'
		if ($df.Contains('direction')) {
			$df['direction'] = _DirectionNameFromBool $df['direction']
		}

		# 3) Sysmon-style aliases: Source/Destination based on direction
		#    We assume local_* is the host, remote_* is the peer.
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
			# Unknown direction: fall back to conventional names but still expose aliases
			# (treat local as source, remote as destination)
			if ($localIp)   { $df['SourceIp']        = $localIp }
			if ($localPort) { $df['SourcePort']      = $localPort }
			if ($remoteIp)  { $df['DestinationIp']   = $remoteIp }
			if ($remotePort){ $df['DestinationPort'] = $remotePort }
		}
	}


  }
  elseif ($hasData -and ($Ev.data -is [string])) {
    $s = $Ev.data
    switch -regex ($type) {
      '^(?i)modload$' {
        # eventTime|md5|path|sha256
        $p = _SplitPipe $s 4
        $df['eventTime'] = _SafeIndex $p 0
        $df['md5']       = _SafeIndex $p 1
        $df['path']      = _SafeIndex $p 2
        if ($df['path']) { $df['ImageLoaded'] = _LeafFromPath $df['path'] }
        $df['sha256']    = _SafeIndex $p 3
      }
      '^(?i)fileless_scriptload$' {
        # eventTime|typeCode|sha256|snippet
        $p = _SplitPipe $s 4
        $df['eventTime']     = _SafeIndex $p 0
        $df['typeCode']      = _SafeIndex $p 1
        $df['sha256']        = _SafeIndex $p 2
        $df['fileless_scriptload_cmdline'] = _SafeIndex $p 3
		$df['scriptSnippet']               = $df['fileless_scriptload_cmdline']  # alias for compatibility
      }
	  '^(?i)filemod$' {
		  # filemod_complete variant (observed with extra tokens)
		  # Index layout (minimum):
		  #   0 = operation (1 create, 2 first_write, 4 delete, 8 last_write)
		  #   1 = event time
		  #   2 = path
		  # Optional / variable:
		  #   3 = post-write MD5 (valid if op=8 last_write)
		  #   4 = file type code (int)
		  #   5 = tamper flag ("true"/"false") OR empty
		  #   6..N = extra tokens; if any token is a 64-hex, treat it as sha256
    $p   = _SplitPipe $s

    # 0: operation
    $op  = _IntOrNull (_SafeIndex $p 0)
    $df['operationCode'] = $op
    $df['operation']     = _CbFilemodActionName $op

    # 1: time, 2: path
    $df['eventTime'] = (_SafeIndex $p 1)
    $df['path']      = (_SafeIndex $p 2)
    if ($df['path']) { $df['filename'] = _LeafFromPath $df['path'] }

    # 3: post-write MD5 (only meaningful for last_write)
    $postMd5 = _SafeIndex $p 3
    if ($op -eq 8 -and $postMd5) {
        $df['postWriteMd5'] = $postMd5
        $df['isLastWrite']  = $true
        $df['md5']          = $postMd5
    } elseif ($op -eq 8) {
        $df['isLastWrite']  = $true
    }

    # 4: file type code (optional); skip if null/empty/0
    $fileTypeCode = _IntOrNull (_SafeIndex $p 4)
    if ($fileTypeCode -ne $null) {
        $df['fileTypeCode'] = $fileTypeCode
        $name = _CbFileTypeName $fileTypeCode
        if ($name) { $df['fileTypeName'] = $name }
    }

    # 5: tamper flag (optional)
    $tamperTok = _SafeIndex $p 5
    if (-not [string]::IsNullOrWhiteSpace($tamperTok)) {
        $df['isTamper'] = _BoolFromStr $tamperTok
    }

    # Tail: detect SHA256 anywhere (prefer the last 64-hex token)
    for ($i = $p.Count - 1; $i -ge 3; $i--) {
        if (_IsHexWithLength -s $p[$i] -n 64) { $df['sha256'] = $p[$i]; break }
    }
}

      '^(?i)crossproc$' {
        # RemoteThread|time|processId|md5|targetPath|token5|token6|is_suppressed|is_tampered|sha256
        $p = _SplitPipe $s
        $action        = _SafeIndex $p 0
        $eventTime     = _SafeIndex $p 1
        $processId     = _SafeIndex $p 2
        $md5           = _SafeIndex $p 3
        $targetPath    = _SafeIndex $p 4
        $token5        = _SafeIndex $p 5
        $token6        = _SafeIndex $p 6
        $is_suppressed = _BoolFromStr (_SafeIndex $p 7)
        $is_tampered   = _BoolFromStr (_SafeIndex $p 8)
        $sha256        = _SafeIndex $p 9

        $df['action']        = $action
        $df['eventTime']     = $eventTime
        $df['processId']     = $processId
        $df['md5']           = $md5
        $df['targetPath']    = $targetPath
        if ($targetPath)     { $df['targetName'] = _LeafFromPath $targetPath }
        $df['is_suppressed'] = $is_suppressed
        $df['is_tampered']   = $is_tampered
        $df['sha256']        = $sha256

        if ($action -match '^(?i)ProcessOpen$') {
          if ($token5 -ne $null) { $df['openFlag']      = $token5 }     # often "1"
          if ($token6 -ne $null) { $df['grantedAccess'] = $token6 }     # decimal mask
        } elseif ($action -match '^(?i)RemoteThread$') {
          if ($token5 -ne $null) { $df['threadFlag1'] = $token5 }
          if ($token6 -ne $null) { $df['threadFlag2'] = $token6 }
        }
      }
      '^(?i)childproc$' {
        # Usually object-form, but handle string fallback:
        $p = _SplitPipe $s
        $df['md5']           = _SafeIndex $p 0
        $df['path']          = _SafeIndex $p 1
        if ($df['path'])     { $df['childproc_name'] = _LeafFromPath $df['path'] }
        $df['commandLine']   = _SafeIndex $p 2
        $df['userName']      = _SafeIndex $p 3
        $df['sha256']        = _SafeIndex $p 4
        $df['pid']           = _SafeIndex $p 5
        $df['processId']     = _SafeIndex $p 6
        $df['type']          = _SafeIndex $p 8
        $df['end']           = _SafeIndex $p 9
      }
      '^(?i)regmod$' {
        # flag|eventTime|registry_path|isValueBool
        $p = _SplitPipe $s 4
        $flag      = _SafeIndex $p 0
        $eventTime = _SafeIndex $p 1
        $regPath   = _SafeIndex $p 2
        $isValue   = _BoolFromStr (_SafeIndex $p 3)

        $df['flag']      = $flag
        $df['eventTime'] = $eventTime
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
        # Unknown string layout: keep a few tokens but *do not* drop the original
        $p = _SplitPipe $s
        0..([Math]::Min($p.Count-1, 5)) | ForEach-Object {
          $df["token$_"] = _SafeIndex $p $_
        }
      }
    }
  }

  # Attach data_fields (even if empty, so consumers can rely on it)
  $out['data_fields'] = $df

  if ($Drop -and $out.Contains('data')) { $out.Remove('data') }

  return [pscustomobject]$out
}

# ---------------- main ----------------
$rootObjs = Read-JsonFlex -Path $InputPath

# We’ll preserve whatever you give us:
# 1) If the top-level has "process.sorted_events" -> enrich those in-place.
# 2) If it has "sorted_events" -> enrich those in-place.
# 3) If it’s already a list of events -> enrich each and output list.
# 4) Any other properties (e.g., binaries, metadata, etc.) are left untouched.

if ($rootObjs.Count -eq 1 -and $rootObjs[0].PSObject.Properties.Name -contains 'process' -and $rootObjs[0].process.sorted_events) {
  # Wrapper object with process.sorted_events
  $wrapper = $rootObjs[0].PSObject.Copy()

  $newEvents = @()
  foreach ($ev in $wrapper.process.sorted_events) {
    $newEvents += Add-DataFieldsToEvent -Ev $ev -Drop:$DropOriginalData
  }
  $wrapper.process.sorted_events = $newEvents

  $json = $wrapper | ConvertTo-Json -Depth 64
}
elseif ($rootObjs.Count -eq 1 -and $rootObjs[0].PSObject.Properties.Name -contains 'sorted_events') {
  # Wrapper with sorted_events directly
  $wrapper = $rootObjs[0].PSObject.Copy()

  $newEvents = @()
  foreach ($ev in $wrapper.sorted_events) {
    $newEvents += Add-DataFieldsToEvent -Ev $ev -Drop:$DropOriginalData
  }
  $wrapper.sorted_events = $newEvents

  $json = $wrapper | ConvertTo-Json -Depth 64
}
else {
  # Treat as a list of event objects
  $newEvents = foreach ($ev in $rootObjs) { Add-DataFieldsToEvent -Ev $ev -Drop:$DropOriginalData }
  $json = $newEvents | ConvertTo-Json -Depth 64
}

# Write file
$dir = Split-Path -Parent -Path $OutputPath
if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
$enc = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OutputPath, $json, $enc)

Write-Host "Updated wrapper written to: $OutputPath"
