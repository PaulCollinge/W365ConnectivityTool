<#
.SYNOPSIS
    One-shot: reproduces the 168.63.129.16 block from an unsigned test exe,
    captures the Windows Filtering Platform drop event (5157), and names the
    filter/driver that rejected the connection.

.DESCRIPTION
    Read-mostly. The only state it changes is enabling WFP connection-drop
    auditing for the duration of the run (auditpol), which it restores on exit.

    Run elevated:
        irm https://raw.githubusercontent.com/PaulCollinge/W365ConnectivityTool/main/tools/Find-WireserverBlocker.ps1 | iex

.NOTES
    No admin = no event log access. The script will tell you and exit.
#>

[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'

function Write-Section($text) {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor DarkGray
    Write-Host $text -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor DarkGray
}

# --- elevation check -------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal]`
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This script must run elevated. Right-click PowerShell -> Run as administrator." -ForegroundColor Red
    return
}

Write-Section "Step 1/5 - Baseline reachability from PowerShell"
$psBaseline = $null
try {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $tcp = New-Object Net.Sockets.TcpClient
    $tcp.Connect('168.63.129.16', 80)
    $sw.Stop()
    $psBaseline = [int]$sw.ElapsedMilliseconds
    $tcp.Close()
    Write-Host ("  OK - PowerShell connected in {0} ms" -f $psBaseline) -ForegroundColor Green
} catch {
    Write-Host ("  FAIL - PowerShell itself cannot connect: {0}" -f $_.Exception.Message) -ForegroundColor Red
    Write-Host "  That points at a blanket network/destination block, not a per-process filter." -ForegroundColor Yellow
    Write-Host "  Run tools/Diagnose-WireserverBlock.ps1 for a broad-scope diagnostic instead." -ForegroundColor Yellow
    return
}

Write-Section "Step 2/5 - Enable WFP connection-drop auditing"
$auditBefore = & auditpol /get /subcategory:"Filtering Platform Connection" 2>$null
& auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable | Out-Null
Write-Host "  Enabled (will restore at end)." -ForegroundColor DarkGray

# --- build a tiny unsigned test exe in temp -------------------------------
Write-Section "Step 3/5 - Reproduce block with a local unsigned probe"
$tempExe = Join-Path $env:TEMP ("wsprobe_{0}.exe" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
$src = @'
using System;
using System.Net.Sockets;
class P {
  static int Main() {
    try {
      using var c = new TcpClient();
      var t = c.ConnectAsync("168.63.129.16", 80);
      if (!t.Wait(8000)) { Console.WriteLine("TIMEOUT"); return 2; }
      Console.WriteLine("OK");
      return 0;
    } catch (Exception ex) {
      Console.WriteLine("ERR: " + (ex.InnerException?.Message ?? ex.Message));
      return 1;
    }
  }
}
'@
$csc = Get-ChildItem -Path "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" -ErrorAction SilentlyContinue
if (-not $csc) {
    Write-Host "  .NET Framework csc.exe not found; skipping local-exe repro, relying on existing events." -ForegroundColor Yellow
} else {
    $srcFile = [IO.Path]::ChangeExtension($tempExe, '.cs')
    Set-Content -Path $srcFile -Value $src -Encoding Ascii
    $cscOut = & $csc.FullName /nologo /target:exe /out:$tempExe $srcFile 2>&1
    Remove-Item $srcFile -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path $tempExe)) {
        Write-Host "  csc failed to produce an exe. Output:" -ForegroundColor Yellow
        $cscOut | ForEach-Object { Write-Host ("    {0}" -f $_) -ForegroundColor DarkYellow }
        Write-Host "  Falling back: running connect from this PowerShell process so at least one 5157 event lands (may not be blocked since powershell.exe isn't the target process)." -ForegroundColor Yellow
        try {
            $tcp2 = New-Object Net.Sockets.TcpClient
            $tcp2.Connect('168.63.129.16', 80)
            $tcp2.Close()
        } catch { }
    } else {
        $out = ''
        try {
            $out = & $tempExe 2>&1 | Out-String
        } catch {
            $out = "invoke error: $($_.Exception.Message)"
        }
        $out = $out.Trim()
        $color = if ($out -match 'OK') { 'Green' } elseif ($out -match 'forbidden|access permissions|10013') { 'Red' } else { 'Yellow' }
        Write-Host ("  Probe exit: {0}" -f $out) -ForegroundColor $color
    }

    # small wait so the audit event lands
    Start-Sleep -Seconds 2
}

Write-Section "Step 4/5 - Scan WFP drops (Security log, event 5157)"
$events = @()
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 5157
        StartTime = (Get-Date).AddMinutes(-3)
    } -ErrorAction SilentlyContinue | Where-Object { $_.Message -match '168\.63\.129\.16' }
} catch { }

if (-not $events -or $events.Count -eq 0) {
    Write-Host "  No WFP drops found for 168.63.129.16 in the last 3 minutes." -ForegroundColor Yellow
    Write-Host "  If the scanner still shows 'forbidden', re-run it NOW and then re-run this script." -ForegroundColor Yellow
} else {
    Write-Host ("  Found {0} drop event(s). Summary:" -f $events.Count) -ForegroundColor Green
    $events | Select-Object -First 5 | ForEach-Object {
        $m = $_.Message
        $app    = ([regex]::Match($m, 'Application Name:\s*(.+)')).Groups[1].Value.Trim()
        $filter = ([regex]::Match($m, 'Filter Run-Time ID:\s*(\d+)')).Groups[1].Value.Trim()
        $layer  = ([regex]::Match($m, 'Layer Name:\s*(.+)')).Groups[1].Value.Trim()
        $dport  = ([regex]::Match($m, 'Destination Port:\s*(\d+)')).Groups[1].Value.Trim()
        Write-Host ""
        Write-Host ("    Time:   {0}" -f $_.TimeCreated)
        Write-Host ("    App:    {0}" -f $app)
        Write-Host ("    Layer:  {0}" -f $layer)
        Write-Host ("    DPort:  {0}" -f $dport)
        Write-Host ("    Filter: {0}" -f $filter) -ForegroundColor Cyan
        if ($filter) {
            $fw = & netsh wfp show filters dir=out 2>$null | Out-String
            $match = ($fw -split "`r?`n" | Select-String -Pattern "\s$filter\b" -Context 0,15 -SimpleMatch:$false)
            if (-not $match) {
                # fallback: dump one filter by id
                $xml = & netsh wfp show state file="$env:TEMP\wfp_state.xml" 2>$null
                Write-Host "    (Could not match filter in live enumeration. Dumped state to $env:TEMP\wfp_state.xml)" -ForegroundColor DarkGray
            } else {
                Write-Host "    -- filter details (first match) --" -ForegroundColor DarkGray
                $match | ForEach-Object { Write-Host ("      {0}" -f $_.Line) }
            }
        }
    }
}

Write-Section "Step 5/5 - Cross-check Defender + common EDR/agents"
try {
    $nppref = (Get-MpPreference).EnableNetworkProtection
    $npText = switch ($nppref) { 0 {'Disabled'} 1 {'Enabled'} 2 {'AuditMode'} default {"$nppref"} }
    Write-Host ("  Defender network protection: {0}" -f $npText)
    if ($nppref -eq 1) {
        Write-Host "  Suggest: Set-MpPreference -EnableNetworkProtection AuditMode ; re-run scanner ; if green, MDE is the culprit." -ForegroundColor Yellow
    }
} catch { }

$drivers = @(
    @{ Name='Global Secure Access';   Match='GlobalSecureAccess' }
    @{ Name='Defender NDIS filter';   Match='WdNisDrv' }
    @{ Name='Defender WFP callout';   Match='WdFilter' }
    @{ Name='CrowdStrike Falcon';     Match='CSAgent|csagent' }
    @{ Name='SentinelOne';            Match='SentinelAgent|sentinelone' }
    @{ Name='Cisco Umbrella/AnyConnect'; Match='umbrella|vpnagent' }
    @{ Name='Zscaler';                Match='Zscaler|ZSATray' }
    @{ Name='Netskope';               Match='stagentsvc|nsclient' }
)
$services = Get-Service | Select-Object -ExpandProperty Name
foreach ($d in $drivers) {
    if ($services -match $d.Match) {
        Write-Host ("  Present: {0}" -f $d.Name) -ForegroundColor Yellow
    }
}

# --- restore audit policy --------------------------------------------------
if ($auditBefore -match 'No Auditing') {
    & auditpol /set /subcategory:"Filtering Platform Connection" /failure:disable | Out-Null
}
if (Test-Path $tempExe) { Remove-Item $tempExe -Force -ErrorAction SilentlyContinue }

Write-Host ""
Write-Host "Done. Share the 'Filter:' value and the surrounding 'filter details' block." -ForegroundColor Green
Write-Host "That uniquely identifies which driver/policy rejected the connection." -ForegroundColor Green
