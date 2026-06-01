param([string]$Label = "")

$fqdns = @(
  'rdgateway-c225-UKS-r1.wvd.microsoft.com',
  'world.relay.avd.microsoft.com',
  'login.microsoftonline.com'
)

Write-Output "=== DNS resolution $Label  $(Get-Date -Format HH:mm:ss) ==="
foreach ($f in $fqdns) {
  try {
    $ips = (Resolve-DnsName -Name $f -Type A -ErrorAction Stop | Where-Object IPAddress).IPAddress -join ', '
  } catch {
    $ips = "ERROR: $($_.Exception.Message)"
  }
  Write-Output ("{0,-45} -> {1}" -f $f, $ips)
}

Write-Output ""
Write-Output "=== NRPT DNS policies (GSA installs these to hijack DNS) ==="
$nrpt = Get-DnsClientNrptPolicy -ErrorAction SilentlyContinue
if ($nrpt) { $nrpt | Select-Object Namespace, NameServers, DAEnable | Format-Table -AutoSize }
else { Write-Output "(none)" }

Write-Output ""
Write-Output "=== GSA synthetic-IP routes (6.x) ==="
$syn = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object DestinationPrefix -match '^6\.'
if ($syn) { $syn | Format-Table DestinationPrefix, InterfaceAlias, Protocol -AutoSize }
else { Write-Output "(none)" }

Write-Output ""
Write-Output "=== Route for the resolved RDP gateway + TURN IPs ==="
foreach ($f in @('rdgateway-c225-UKS-r1.wvd.microsoft.com','world.relay.avd.microsoft.com')) {
  try {
    $ip = ([System.Net.Dns]::GetHostAddresses($f) | Where-Object AddressFamily -eq 'InterNetwork')[0].IPAddressToString
    $rt = Find-NetRoute -RemoteIPAddress $ip -ErrorAction SilentlyContinue | Select-Object -First 1
    Write-Output ("{0,-45} ip={1,-15} via {2} (src {3})" -f $f, $ip, $rt.InterfaceAlias, $rt.IPAddress)
  } catch {
    Write-Output ("{0,-45} -> resolve/route error" -f $f)
  }
}
