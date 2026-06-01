$exe = Get-ChildItem -Recurse -Filter W365LocalScanner.exe -Path src\W365LocalScanner\bin\Debug | Select-Object -First 1 -ExpandProperty FullName
Write-Output "EXE: $exe"
& $exe 2>&1 | Out-Null
$json = Get-Content src\W365LocalScanner\W365ScanResults.json -Raw | ConvertFrom-Json
$t = $json.results | Where-Object { $_.Id -eq 'L-TCP-07' }
Write-Output "STATUS: $($t.Status)"
Write-Output "VALUE : $($t.ResultValue)"
Write-Output "----- DetailedInfo -----"
Write-Output $t.DetailedInfo
