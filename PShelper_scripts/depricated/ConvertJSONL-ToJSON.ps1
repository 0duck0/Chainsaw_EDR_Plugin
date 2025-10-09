$src = 'E:\Chainsaw_Project\normalized_events'
$dst = 'E:\Chainsaw_Project\normalized_events_json'
New-Item -ItemType Directory -Force -Path $dst | Out-Null

Get-ChildItem $src -Filter *.normalized.jsonl | ForEach-Object {
  if ($_.Length -eq 0) { return }  # skip empty files (prevents EOF errors)

  $out = Join-Path $dst ($_.BaseName + '.json')

  # Stream-write a JSON array to avoid high memory use
  $sw = New-StreamWriterUtf8NoBom -Path $out
  try {
    $sw.WriteLine('[')
    $first = $true
    foreach ($line in Get-Content -LiteralPath $_.FullName) {
      $line = $line.Trim()
      if (-not $line) { continue }
      try { $obj = $line | ConvertFrom-Json } catch { continue }
      $json = $obj | ConvertTo-Json -Depth 64 -Compress
      if ($first) { $first = $false } else { $sw.WriteLine(',') }
      $sw.Write($json)
    }
    $sw.WriteLine(']')
  } finally {
    $sw.Dispose()
  }
}
