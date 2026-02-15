$ErrorActionPreference = 'Continue'
Set-Location C:\W365ConnectivityTool
$lines = @("protocol=https","host=github.com","") | & "C:\Program Files\Git\cmd\git.exe" credential fill 2>$null
$u = ''; $p = ''
foreach($l in $lines) {
    if($l -match '^username=(.+)') { $u = $matches[1] }
    if($l -match '^password=(.+)') { $p = $matches[1] }
}
$url = "https://${u}:${p}@github.com/PaulCollinge/W365ConnectivityTool.git"
$stderr = & "C:\Program Files\Git\cmd\git.exe" push $url main 2>&1
$result = @{
    ExitCode = $LASTEXITCODE
    Output = ($stderr | ForEach-Object { $_.ToString() }) -join "`n"
}
$result | ConvertTo-Json | Set-Content C:\W365ConnectivityTool\_push_result.json
Write-Host "PUSH COMPLETED - exit=$($result.ExitCode)"
