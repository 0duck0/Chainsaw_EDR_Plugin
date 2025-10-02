# Re-write each YAML with UTF-8 *without* BOM and ensure no tabs
$files = Get-ChildItem 'E:\Chainsaw_Project\chainsaw\rules\smoke_rules' -Filter *.yml
$enc = New-Object System.Text.UTF8Encoding($false)

foreach ($f in $files) {
  $raw = Get-Content -LiteralPath $f.FullName -Raw
  if (Select-String -InputObject $raw -Pattern "`t" -Quiet) {
    Write-Warning "Tabs found in $($f.Name) — replace them with spaces."
  }
  [System.IO.File]::WriteAllText($f.FullName, $raw, $enc)
}
