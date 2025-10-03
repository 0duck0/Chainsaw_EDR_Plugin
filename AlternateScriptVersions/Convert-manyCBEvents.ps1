$in = 'E:\Chainsaw_Project\CB_Process_Data\NCEUPWS14101T'
$out = 'E:\Chainsaw_Project\normalized_CBdata'
$script = 'G:\MOVE\Chainsaw_project\PowerShell_HelperScripts\Convert-CBEventsFlatten.ps1'
New-Item -ItemType Directory -Path $out -Force | Out-Null

Get-ChildItem -LiteralPath $in -Filter *.json -File -Recurse |
  ForEach-Object -Parallel {
    $rel     = $_.FullName.Substring($using:in.Length).TrimStart('\','/')
    $dest    = Join-Path $using:out $rel
    $destDir = Split-Path $dest -Parent
    if (!(Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
    & $using:script -InputPath $_.FullName -OutputPath $dest -DropOriginalData -Verbose
  } -ThrottleLimit 8