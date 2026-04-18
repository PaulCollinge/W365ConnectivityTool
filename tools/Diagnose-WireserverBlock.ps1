<#
.SYNOPSIS
    Diagnoses why outbound TCP 80 to the Azure wireserver (168.63.129.16) is
    being blocked on a Windows 365 Cloud PC / AVD session host / Azure VM.

.DESCRIPTION
    On a stock Azure VM, user-mode TCP to 168.63.129.16:80 is reachable by
    design (DHCP options, guest-agent control plane, session-host health).
    A timeout therefore almost always indicates a LOCAL block. This script
    runs a series of read-only checks to identify the cause:

      1. Classifies the socket failure (TimedOut vs Refused vs Unreachable)
      2. Cross-checks IMDS (which also traverses 168.63.129.16) to tell a
         port/IP-specific block apart from a whole link-local egress block
      3. Inspects the route to 168.63.129.16
      4. Enumerates Windows Firewall outbound Block rules that could match
      5. Enumerates IPsec Deny rules
      6. Reports MDM/Intune enrolment state
      7. Detects common EDR / endpoint-security agents that might be
         interposing at the network layer
      8. Reports the firewall logging state and how to enable it briefly
         to capture the smoking gun

    All checks are read-only. Elevation is NOT required, but running
    elevated yields more complete firewall rule detail.

.NOTES
    Companion to the W365 Connectivity Tool Local Scanner when a
    'Session Host Required Endpoints' scan flags the Azure wireserver
    (168.63.129.16:80) as unreachable.

    Project: https://github.com/PaulCollinge/W365ConnectivityTool
#>

[CmdletBinding()]
param(
    [string]$WireserverIp = '168.63.129.16',
    [int]   $TimeoutMs    = 4000
)

Write-Host "=== Wireserver block diagnosis ($WireserverIp`:80) ===`n" -ForegroundColor Cyan

# ────────────────────────────────────────────────────────────────────
# 1. Socket-level classification
# ────────────────────────────────────────────────────────────────────
$err = $null
try {
    $c = [Net.Sockets.TcpClient]::new()
    $t = $c.ConnectAsync($WireserverIp, 80)
    if (-not $t.Wait($TimeoutMs)) { $err = 'TimedOut (silently dropped)' }
    elseif ($t.IsFaulted)         { $err = $t.Exception.GetBaseException().SocketErrorCode }
    else                          { $err = 'OK' }
    $c.Close()
} catch {
    $err = $_.Exception.GetBaseException().Message
}
Write-Host "TCP 80 -> $WireserverIp : $err" -ForegroundColor Yellow

# ────────────────────────────────────────────────────────────────────
# 2. Does the platform path work? IMDS also traverses 168.63.129.16
# ────────────────────────────────────────────────────────────────────
try {
    $imds = Invoke-RestMethod 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' `
                -Headers @{ Metadata = 'true' } -TimeoutSec 4
    Write-Host "IMDS reachable (platform path OK) -> $($imds.compute.vmSize) in $($imds.compute.location)" -ForegroundColor Green
    Write-Host "  => Port-80-specific or IP-specific block from user-mode, not a link-local egress block" -ForegroundColor Green
} catch {
    Write-Host "IMDS also failing -> link-local egress is blocked as a whole" -ForegroundColor Red
}

# ────────────────────────────────────────────────────────────────────
# 3. Route table
# ────────────────────────────────────────────────────────────────────
$route = Get-NetRoute -DestinationPrefix "$WireserverIp/32" -ErrorAction SilentlyContinue
if ($route) {
    Write-Host "`nRoute for $WireserverIp :"
    $route | Format-Table ifIndex, NextHop, RouteMetric, InterfaceAlias -AutoSize
} else {
    Write-Host "`nNo specific route -> uses default gateway (normal)"
}

# ────────────────────────────────────────────────────────────────────
# 4. Windows Firewall outbound Block rules that could match
# ────────────────────────────────────────────────────────────────────
Write-Host "`nWindows Firewall outbound Block rules potentially matching:" -ForegroundColor Cyan
$matches = Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True -ErrorAction SilentlyContinue |
    ForEach-Object {
        $rule   = $_
        $ports  = $rule | Get-NetFirewallPortFilter
        $addrs  = $rule | Get-NetFirewallAddressFilter
        $portHit = ($ports.RemotePort -contains '80') -or ($ports.RemotePort -contains 'Any')
        $addrHit = ($addrs.RemoteAddress -match '168\.63\.129\.16|Any|LocalSubnet|Internet')
        if ($portHit -and $addrHit) {
            [pscustomobject]@{
                Name       = $rule.DisplayName
                Group      = $rule.DisplayGroup
                Profile    = $rule.Profile
                RemoteAddr = ($addrs.RemoteAddress -join ',')
                RemotePort = ($ports.RemotePort -join ',')
            }
        }
    }
if ($matches) { $matches | Format-Table -AutoSize } else { Write-Host "  (none found)" }

# ────────────────────────────────────────────────────────────────────
# 5. IPsec Deny rules
# ────────────────────────────────────────────────────────────────────
$ipsec = Get-NetIPsecRule -ErrorAction SilentlyContinue | Where-Object { $_.Action -eq 'Deny' -and $_.Enabled -eq 'True' }
if ($ipsec) {
    Write-Host "IPsec Deny rules present:"
    $ipsec | Select-Object DisplayName, Profile, Action | Format-Table -AutoSize
}

# ────────────────────────────────────────────────────────────────────
# 6. MDM / Intune enrolment
# ────────────────────────────────────────────────────────────────────
$dsreg    = (dsregcmd /status) -join "`n"
$isIntune = $dsreg -match 'MDMUrl\s*:\s*https'
$mdm      = if ($isIntune) { ($dsreg | Select-String 'MDMUrl').ToString().Trim() } else { 'not MDM-enrolled' }
Write-Host "`nMDM: $mdm" -ForegroundColor Cyan

# ────────────────────────────────────────────────────────────────────
# 7. Known EDR / endpoint-security agents
# ────────────────────────────────────────────────────────────────────
$edrMap = @{
    'MsSense'         = 'Microsoft Defender for Endpoint (Sense)'
    'Sense'           = 'Microsoft Defender for Endpoint (Sense)'
    'CSFalconService' = 'Crowdstrike Falcon'
    'SentinelAgent'   = 'SentinelOne'
    'CylanceSvc'      = 'Cylance'
    'TaniumClient'    = 'Tanium'
    'CarbonBlack'     = 'Carbon Black'
    'HealthService'   = 'MMA / Log Analytics agent'
}
$found = Get-Service -ErrorAction SilentlyContinue |
         Where-Object { $edrMap.ContainsKey($_.Name) -and $_.Status -eq 'Running' }
if ($found) {
    Write-Host "`nEDR / endpoint-security agents running:" -ForegroundColor Cyan
    $found | ForEach-Object { "  - $($edrMap[$_.Name]) ($($_.Name))" }
} else {
    Write-Host "`nNo common EDR services detected"
}

# ────────────────────────────────────────────────────────────────────
# 8. Windows Firewall logging state + hint
# ────────────────────────────────────────────────────────────────────
Write-Host "`nFirewall log state:"
Get-NetFirewallProfile | Select-Object Name, LogAllowed, LogBlocked, LogFileName | Format-Table -AutoSize
Write-Host "Tip: if LogBlocked is False, enable briefly with (run elevated):" -ForegroundColor DarkGray
Write-Host "  Set-NetFirewallProfile -All -LogBlocked True -LogFileName %systemroot%\system32\logfiles\firewall\pfirewall.log" -ForegroundColor DarkGray
Write-Host "  then retry the probe and grep the log for $WireserverIp" -ForegroundColor DarkGray

# ────────────────────────────────────────────────────────────────────
# Interpretation hints
# ────────────────────────────────────────────────────────────────────
Write-Host "`n=== How to read this ===" -ForegroundColor Cyan
@'
  TimedOut               -> silent drop (classic firewall deny)
  ConnectionRefused      -> something intercepting (proxy / WinHTTP override)
  Network/HostUnreachable-> routing problem (VPN steering link-local into a tunnel)

  IMDS OK + wireserver fails -> block is port-80- or IP-specific, not all link-local
  Firewall rule matched      -> likely culprit; note the Group (MDM/Intune if GUID/DLL-name)
  Intune-enrolled + blocking -> check Intune admin centre -> Endpoint security -> Firewall
  EDR running, no rule match -> block may be inside the EDR (network isolation / ASR)
  Firewall log shows DROP     -> that rule name is the smoking gun
'@
