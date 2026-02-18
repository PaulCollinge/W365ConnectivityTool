## v1.4.12  TURN Relay RTT Measurement

### Changes
- **L-UDP-03**: Now measures round-trip time (RTT) to the TURN relay via STUN binding request/response
  - Result shows latency: `TURN relay reachable at x.x.x.x:3478  12ms RTT`
  - `DetailedInfo` includes `Latency: 12ms` line
- Dashboard export summary surfaces the TURN RTT alongside location

### Dashboard (v60)
- Export summary now shows TURN latency: `TURN Relay: ...  12ms RTT`
- RDP Egress fallback to scanner GeoIP when no cloud session (v59)
- Renamed TCP/UDP Path Security  TCP/UDP-based RDP Path Optimisation (v58)
- Connectivity Overview summary section in export (v57)

### Verification
```
SHA256: 3E7A6B190422EF797CFE2C53EC0F85DB0A853C4690F5782711450A6D3C4A2EBB
```

### Usage
```powershell
.\W365LocalScanner.exe
```
Requires Windows, run from the machine you connect to Cloud PCs from.
Import the JSON into the [web dashboard](https://paulcollinge.github.io/W365ConnectivityTool/).