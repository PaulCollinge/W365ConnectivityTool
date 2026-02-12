# Windows 365 / AVD Connectivity Diagnostics

A lightweight diagnostic tool that tests network connectivity for **Windows 365 Cloud PC** and **Azure Virtual Desktop (AVD)** environments from the client's perspective.

1. **Download & run** the scanner exe — no install, no admin rights
2. It performs ~23 network tests in ~30 seconds
3. Results **automatically open** in a web dashboard

```
┌──────────────────┐         ┌──────────────────────────────────┐
│  Local Scanner   │────────▶│  Web Dashboard (GitHub Pages)    │
│  W365Local       │  opens  │  paulcollinge.github.io/         │
│  Scanner.exe     │  browser│  W365ConnectivityTool            │
└──────────────────┘         └──────────────────────────────────┘
```

## Quick Start

### 1. Download the scanner

[**⬇ Download W365LocalScanner.exe**](https://github.com/PaulCollinge/W365ConnectivityTool/releases/latest/download/W365LocalScanner.exe)

Run it — results automatically open in your browser.

### 2. View the web dashboard

The dashboard is at [**paulcollinge.github.io/W365ConnectivityTool**](https://paulcollinge.github.io/W365ConnectivityTool/). The scanner opens this automatically, but you can also visit it directly to run browser-side tests.

## Verify the download

Every release includes a **SHA256 checksum** in the [release notes](https://github.com/PaulCollinge/W365ConnectivityTool/releases/latest) and is built with [GitHub artifact attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds) (SLSA provenance).

```powershell
# Verify checksum (compare with value in release notes)
(Get-FileHash W365LocalScanner.exe -Algorithm SHA256).Hash
```

```bash
# Verify build provenance (requires GitHub CLI)
gh attestation verify W365LocalScanner.exe --repo PaulCollinge/W365ConnectivityTool
```

## Privacy

- **No data leaves your machine** except to the endpoints being tested
- Results are passed to the dashboard via the browser URL (stays local)
- No telemetry, no tracking, no external servers
- Dashboard runs entirely client-side on GitHub Pages
- Full source code is in this repo

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
| User Location | ✅ | — | ipinfo.io GeoIP (HTTPS) |
| ISP Detection | ✅ | — | ipinfo.io (HTTPS) |
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
| DNS Hijacking Check | — | ✅ | Verifies DNS responses resolve to Azure IPs |
| TLS Inspection | — | ✅ | SslStream cert validation |
| Proxy/VPN/SWG Detection | — | ✅ | System proxy, WinHTTP, env, VPN adapters |
| Gateway Used & Proximity | — | ✅ | GeoIP on gateway IP, distance calc |
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
