[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string]$InputPath,
  [Parameter(Mandatory)] [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

function _LeafFromPath { param([string]$p) if ($p) { try { Split-Path -Leaf $p } catch { $null } } }
function _AsUtc {
  param([string]$s)
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  # Accept "yyyy-MM-dd HH:mm:ss.ffffff" or ISO; keep original if parse fails
  try {
    $dt = [datetime]::Parse($s, [System.Globalization.CultureInfo]::InvariantCulture)
    # Chainsaw/Sigma don't require strict ISO; keep original formatting for stability
    return $s
  } catch { return $s }
}

# ----- load wrapper -----
$wrapper = Get-Content -LiteralPath $InputPath -Raw | ConvertFrom-Json -ErrorAction Stop

# Shape check: allow either wrapper.process.sorted_events or wrapper.sorted_events
$events = @()
$proc    = $null
$segId   = $null

if ($wrapper.PSObject.Properties.Name -contains 'process') {
  $proc  = $wrapper.process
  $segId = $wrapper.process.segment_id
  if ($proc -and $proc.sorted_events) {
    $events = @($proc.sorted_events)
  }
} elseif ($wrapper.PSObject.Properties.Name -contains 'sorted_events') {
  $events = @($wrapper.sorted_events)
  # Best-effort: pull process-like fields if present at top-level
  $proc = $wrapper
} else {
  # Already flat? Then just dump as-is
  $wrapper | ConvertTo-Json -Depth 64 | Set-Content -Encoding UTF8 $OutputPath
  Write-Host "Wrote (already-flat) events to: $OutputPath"
  exit 0
}

# ----- build synthetic process-creation event -----
# Use typical fields emitted by your normalizer:
# path, cmdline, username, process_pid, parent_name, parent_pid, process_md5, process_sha256, start, hostname, segment_id
$synthetic = [ordered]@{
  type        = 'childproc'                           # so it maps like Sysmon process_create
  time        = _AsUtc ($proc.start)                  # prefer process.start; fallback below
  segment_id  = if ($segId) { $segId } else { $wrapper.segment_id }
  hostname    = if ($wrapper.hostname) { $wrapper.hostname } elseif ($proc.hostname) { $proc.hostname } else { $null }
  data        = 'synthetic_from_wrapper'              # marker; harmless
  data_fields = [ordered]@{
    eventTime     = _AsUtc ($proc.start)
    path          = $proc.path
    ImageLoaded   = $null                              # not used here
    childproc_name = _LeafFromPath $proc.path
    commandLine   = $proc.cmdline
    userName      = $proc.username
    md5           = $proc.process_md5
    sha256        = $proc.process_sha256
    pid           = $proc.process_pid
    processId     = $proc.id                           # CB process GUID if present
    parentImage   = $proc.parent_name
    parentPid     = $proc.parent_pid
  }
}

# Fill some gaps if missing
if (-not $synthetic.time)      { $synthetic.time      = $wrapper.time }
if (-not $synthetic.data_fields.eventTime) { $synthetic.data_fields.eventTime = $synthetic.time }

# Optional: also expose “actor” process context at the top level of the event
# (Some Sigma rules key off Image/CommandLine directly)
$synthetic.Image       = $synthetic.data_fields.path
$synthetic.CommandLine = $synthetic.data_fields.commandLine
$synthetic.User        = $synthetic.data_fields.userName
$synthetic.ProcessId   = $synthetic.data_fields.pid
$synthetic.ParentImage = $synthetic.data_fields.parentImage
$synthetic.ParentProcessId = $synthetic.data_fields.parentPid

# ----- produce flat array: [ synthetic, ...existing events... ] -----
# We *don’t* modify your existing events; they already have data_fields from your flattener
$flat = @($synthetic) + @($events)

# ----- write -----
$flat | ConvertTo-Json -Depth 64 | Set-Content -Encoding UTF8 $OutputPath
Write-Host "Wrote flat array ($($flat.Count) events incl. synthetic) to: $OutputPath"
