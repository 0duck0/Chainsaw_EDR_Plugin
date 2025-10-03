$in  = 'E:\Chainsaw_Project\normalized_CBdata'       # wrappers (with process.sorted_events)
$out = 'E:\Chainsaw_Project\normalized_CBdata_flat'  # flat arrays with synthetic + events
$exp = 'E:\Chainsaw_Project\PS-HelperScripts\Expand-CBWrapper-ToFlat.ps1'

New-Item -ItemType Directory -Path $out -Force | Out-Null

Get-ChildItem -LiteralPath $in -Filter *.json -File -Recurse | ForEach-Object {
  $rel  = $_.FullName.Substring($in.Length).TrimStart('\','/')
  $dest = Join-Path $out $rel
  $dir  = Split-Path $dest -Parent
  if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  & $exp -InputPath $_.FullName -OutputPath $dest
}
