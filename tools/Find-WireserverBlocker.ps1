<#
.SYNOPSIS
    Names the local driver / filter that is rejecting the W365LocalScanner
    scanner's connect to 168.63.129.16:80 with WSAEACCES.

.DESCRIPTION
    Read-only. Enables WFP failure auditing, asks you to re-run the scanner
    so a fresh drop event is generated, then parses event 5157 to identify
    the rejecting filter, and cross-checks Defender / GSA / common EDRs.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'

function Hdr($t) {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor DarkGray
    Write-Host $t -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor DarkGray
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Must run elevated. Start an admin PowerShell and re-run." -ForegroundColor Red
    return
}

Hdr "Step 1/4 - Baseline: PowerShell can reach 168.63.129.16:80"
try {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $tcp = New-Object Net.Sockets.TcpClient
    $tcp.Connect('168.63.129.16', 80); $sw.Stop(); $tcp.Close()
    Write-Host ("  OK ({0} ms) - network is fine; any block is process-scoped." -f $sw.ElapsedMilliseconds) -ForegroundColor Green
} catch {
    Write-Host ("  FAIL from PS too: {0}" -f $_.Exception.Message) -ForegroundColor Red
    Write-Host "  This is NOT a per-process filter - run tools/Diagnose-WireserverBlock.ps1 instead." -ForegroundColor Yellow
    return
}

Hdr "Step 2/4 - Enabling WFP connection-drop audit"
& auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable | Out-Null
Write-Host "  Enabled." -ForegroundColor DarkGray

Hdr "Step 3/4 - Run the scanner now"
Write-Host "  1. Leave this window open." -ForegroundColor Yellow
Write-Host "  2. In another window, run W365LocalScanner.exe and wait for 'Session Host Required Endpoints' to finish (it will fail with 'forbidden')." -ForegroundColor Yellow
Write-Host "  3. Come back here and press Enter." -ForegroundColor Yellow
Read-Host "  Press Enter after the scanner finishes" | Out-Null

Hdr "Step 4/4 - Finding the filter that rejected 168.63.129.16"
Start-Sleep -Seconds 2
$events = @()
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 5157
        StartTime = (Get-Date).AddMinutes(-10)
    } -ErrorAction SilentlyContinue | Where-Object { $_.Message -match '168\.63\.129\.16' }
} catch { }

if (-not $events -or $events.Count -eq 0) {
    Write-Host "  No 5157 drops for 168.63.129.16 in the last 10 min." -ForegroundColor Yellow
    Write-Host "  Audit may not have been active when the scanner ran. Re-run the scanner NOW (audit is on)," -ForegroundColor Yellow
    Write-Host "  then re-run this script and press Enter again at step 3." -ForegroundColor Yellow
} else {
    Write-Host ("  Found {0} drop event(s) for 168.63.129.16." -f $events.Count) -ForegroundColor Green
    Write-Host ""
    $filterIds = @{}
    $events | Select-Object -First 5 | ForEach-Object {
        $m = $_.Message
        $app    = ([regex]::Match($m, 'Application Name:\s*(.+)')).Groups[1].Value.Trim()
        $filter = ([regex]::Match($m, 'Filter Run-Time ID:\s*(\d+)')).Groups[1].Value.Trim()
        $layer  = ([regex]::Match($m, 'Layer Name:\s*(.+)')).Groups[1].Value.Trim()
        $dport  = ([regex]::Match($m, 'Destination Port:\s*(\d+)')).Groups[1].Value.Trim()
        Write-Host ("  Time:   {0}" -f $_.TimeCreated)
        Write-Host ("  App:    {0}" -f $app)
        Write-Host ("  Layer:  {0}" -f $layer)
        Write-Host ("  DPort:  {0}" -f $dport)
        Write-Host ("  Filter: {0}" -f $filter) -ForegroundColor Cyan
        Write-Host ""
        if ($filter) { $filterIds[$filter] = $true }
    }

    if ($filterIds.Count -gt 0) {
        Write-Host "  Dumping WFP state and matching filter IDs..." -ForegroundColor DarkGray
        $xmlPath = Join-Path $env:TEMP "wfp_state.xml"
        & netsh wfp show state file="$xmlPath" | Out-Null
        if (Test-Path $xmlPath) {
            try {
                [xml]$wfp = Get-Content $xmlPath
                foreach ($fid in $filterIds.Keys) {
                    $node = $wfp.SelectSingleNode("//item[filterId='$fid']")
                    if (-not $node) { $node = $wfp.SelectSingleNode("//filter[filterId='$fid']") }
                    if ($node) {
                        $name = $node.displayData.name
                        $desc = $node.displayData.description
                        $provName = $null
                        if ($node.providerKey) {
                            $pk = $node.providerKey
                            $provNode = $wfp.SelectSingleNode("//provider[providerKey='$pk']")
                            if ($provNode) { $provName = $provNode.displayData.name }
                        }
                        Write-Host ("  --- Filter {0} ---" -f $fid) -ForegroundColor Cyan
                        Write-Host ("    Name:        {0}" -f $name)
                        Write-Host ("    Description: {0}" -f $desc)
                        Write-Host ("    Provider:    {0}" -f $provName) -ForegroundColor Yellow
                    } else {
                        Write-Host ("  Filter {0}: not found in WFP state snapshot" -f $fid) -ForegroundColor DarkYellow
                    }
                }
            } catch {
                Write-Host ("  Could not parse WFP state XML: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
                Write-Host ("  Raw dump kept at {0} for manual inspection." -f $xmlPath) -ForegroundColor Yellow
            }
            Remove-Item $xmlPath -ErrorAction SilentlyContinue
        }
    }
}

Hdr "Cross-checks"
try {
    $np = (Get-MpPreference).EnableNetworkProtection
    $t  = @{0='Disabled';1='Enabled';2='AuditMode'}[[int]$np]
    Write-Host ("  Defender network protection: {0}" -f $t)
    if ($np -eq 1) {
        Write-Host "  Try: Set-MpPreference -EnableNetworkProtection AuditMode ; re-run scanner." -ForegroundColor Yellow
        Write-Host "       If it then passes, MDE network protection is the blocker." -ForegroundColor Yellow
    }
} catch { }

$checks = @(
    @{N='Global Secure Access'; M='GlobalSecureAccess'}
    @{N='Defender NDIS filter'; M='WdNisDrv'}
    @{N='Defender WFP callout'; M='WdFilter'}
    @{N='CrowdStrike';          M='CSAgent|csagent'}
    @{N='SentinelOne';          M='SentinelAgent|sentinelone'}
    @{N='Cisco AnyConnect/Umbrella'; M='umbrella|vpnagent'}
    @{N='Zscaler';              M='Zscaler|ZSATray'}
    @{N='Netskope';             M='stagentsvc|nsclient'}
)
$svc = (Get-Service).Name
foreach ($c in $checks) {
    if ($svc -match $c.M) { Write-Host ("  Present: {0}" -f $c.N) -ForegroundColor Yellow }
}

Write-Host ""
Write-Host "Share the 'Name / Description / Provider' lines - they identify the blocker." -ForegroundColor Green
