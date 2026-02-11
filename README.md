# Windows 365 / AVD Connectivity Diagnostics

A two-part connectivity diagnostic tool for Windows 365 and Azure Virtual Desktop:

1. **Web Dashboard** — runs browser-based tests (endpoint reachability, latency, WebRTC/STUN, location)
2. **Local Scanner** — a downloadable `.exe` that runs deeper OS-level tests (raw TCP/UDP, WiFi, proxy, TLS inspection, DNS CNAME chains)

Import the local scanner results into the web dashboard to see a combined diagnostic view.

## Architecture

```
┌─────────────────────────────────────┐
│        Web Dashboard (Browser)       │
│  GitHub Pages static site            │
│                                      │
│  ✓ HTTPS endpoint reachability      │
│  ✓ Gateway latency (fetch timing)   │
│  ✓ DNS resolution performance       │
│  ✓ WebRTC / STUN connectivity       │
│  ✓ NAT type detection (WebRTC)      │
│  ✓ User location & ISP              │
│  ✓ Connection type                  │
│                                      │
│  📁 Import Local Scanner results    │
└─────────────────────────────────────┘
           ▲ JSON import
           │
┌─────────────────────────────────────┐
│     Local Scanner (.exe)             │
│  Self-contained .NET 8 console app   │
│                                      │
│  ✓ Raw TCP port connectivity        │
│  ✓ DNS CNAME chain / Private Link   │
│  ✓ TLS inspection detection         │
│  ✓ Proxy / VPN / SWG detection      │
│  ✓ TURN relay UDP 3478              │
│  ✓ STUN NAT type (UDP socket)       │
│  ✓ WiFi signal strength             │
│  ✓ Gateway/router latency (ping)    │
│  ✓ Network adapter details          │
│  ✓ Machine performance              │
│  ✓ Teams optimization check         │
│                                      │
│  → Outputs W365ScanResults.json     │
└─────────────────────────────────────┘
```

## Quick Start

### Web Dashboard
Visit the GitHub Pages deployment or open `docs/index.html` locally:
1. Click **Run Browser Tests** — runs all browser-capable diagnostics
2. Download the Local Scanner for deeper tests
3. Run the scanner, then click **Import Local Results** and select the JSON file

### Local Scanner
```powershell
# Download from GitHub Releases, then:
.\W365LocalScanner.exe

# Optionally specify output path:
.\W365LocalScanner.exe MyResults.json
```

The scanner produces `W365ScanResults.json` in the current directory. Import it into the web dashboard.

## Project Structure

```
W365ConnectivityTool/
├── docs/                          # Web dashboard (GitHub Pages)
│   ├── index.html
│   ├── css/styles.css
│   └── js/
│       ├── config.js              # Endpoint configuration
│       ├── browser-tests.js       # Browser test implementations
│       ├── ui.js                  # UI rendering
│       └── app.js                 # Main application logic
├── src/
│   ├── W365ConnectivityTool/      # WPF desktop app (full-featured)
│   └── W365LocalScanner/          # Console app (JSON output)
├── .github/workflows/
│   ├── deploy-pages.yml           # Deploy website to GitHub Pages
│   └── build-scanner.yml          # Build & release scanner exe
└── README.md
```

## Test Matrix

| Test | Browser | Local Scanner | Notes |
|------|---------|---------------|-------|
| Endpoint HTTPS Reachability | ✅ | — | Uses `fetch()` with `no-cors` |
| User Location | ✅ | — | ip-api.com GeoIP |
| ISP Detection | ✅ | — | ip-api.com |
| Connection Type | ✅ | — | Network Information API |
| Gateway HTTPS Reachability | ✅ | — | Fetch timing |
| Gateway Latency | ✅ | — | 5-sample fetch timing |
| DNS Resolution Performance | ✅ | — | Fetch timing proxy |
| WebRTC / STUN | ✅ | — | RTCPeerConnection ICE |
| NAT Type (WebRTC) | ✅ | — | ICE candidate analysis |
| WiFi Signal Strength | — | ✅ | `netsh wlan` |
| Router/Gateway Latency | — | ✅ | ICMP ping |
| Network Adapters | — | ✅ | .NET NetworkInterface |
| Bandwidth Estimation | — | ✅ | HTTP download test |
| Machine Performance | — | ✅ | CPU/RAM/OS info |
| Teams Optimization | — | ✅ | Registry + process check |
| Raw TCP Port Connectivity | — | ✅ | TcpClient socket |
| DNS CNAME Chain | — | ✅ | nslookup + DNS.Resolve |
| TLS Inspection | — | ✅ | SslStream cert validation |
| Proxy/VPN/SWG Detection | — | ✅ | System proxy, WinHTTP, env, VPN adapters |
| TURN Relay (UDP 3478) | — | ✅ | UdpClient STUN request |
| TURN Relay Location | — | ✅ | GeoIP on relay IP |
| NAT Type (Socket STUN) | — | ✅ | Raw STUN binding |
| TURN TLS Inspection | — | ✅ | SslStream to relay:443 |
| TURN Proxy/VPN | — | ✅ | VPN adapter + firewall check |

## Building

### Local Scanner
```powershell
# Build
dotnet build src/W365LocalScanner/W365LocalScanner.csproj

# Publish self-contained exe
dotnet publish src/W365LocalScanner/W365LocalScanner.csproj -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -p:PublishTrimmed=true -o publish
```

### WPF Desktop App
```powershell
dotnet build src/W365ConnectivityTool/W365ConnectivityTool.csproj
dotnet run --project src/W365ConnectivityTool/W365ConnectivityTool.csproj
```

## Deployment

1. **Push to GitHub** — the `deploy-pages.yml` workflow automatically deploys the web dashboard to GitHub Pages
2. **Create a tag** (e.g. `git tag v1.0.0 && git push --tags`) — the `build-scanner.yml` workflow builds and publishes the scanner exe as a GitHub Release
3. Update the download link in `docs/index.html` to point to your GitHub Releases URL

## Requirements

- **Web Dashboard**: Any modern browser (Chrome, Edge, Firefox, Safari)
- **Local Scanner**: Windows 10/11 (x64), no dependencies (self-contained .NET 8)
- **WPF App**: Windows 10/11 with .NET 10 SDK

## References

- [Windows 365 Network Requirements](https://learn.microsoft.com/windows-365/enterprise/requirements-network)
- [AVD Required URLs](https://learn.microsoft.com/azure/virtual-desktop/required-fqdn-endpoint)
- [RDP Shortpath](https://learn.microsoft.com/azure/virtual-desktop/rdp-shortpath)
- [Teams on AVD](https://learn.microsoft.com/azure/virtual-desktop/teams-on-avd)
