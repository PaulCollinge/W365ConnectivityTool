# Handoff — Windows 365 Connectivity Tool

Operational handoff for the team taking this tool to official Microsoft distribution.
This page is a **pointer to facts**, not a duplicate of them — it links to the
authoritative docs and lists the open items a new owner must action.

Current scanner version: **v1.13.6** (`src/W365LocalScanner/W365LocalScanner.csproj`).

## What this is

Two components, one product:

| Component | Source | Output | Signed |
|---|---|---|---|
| Scanner | `src/W365LocalScanner` (.NET 8 console) | `W365LocalScanner.exe` — self-contained, single-file, trimmed, win-x64 | Yes (Authenticode) |
| Dashboard | `docs/` | static HTML/JS/CSS site (GitHub Pages today) | No |

The scanner runs locally (no install, no admin), writes `W365ScanResults.json`,
and opens the dashboard which renders the results. The **dashboard URL embedded
in the scanner source is the only runtime coupling** between the two.

See [README.md](README.md) for the user-facing description and CLI options,
[DESIGN.md](DESIGN.md) for the test catalogue and architecture.

## Authoritative domain rule (do not regress)

**W365/AVD RDP gateway selection follows the client's EGRESS location**, resolved
via Azure Front Door anycast against AFD's live global latency/load telemetry —
**not** the Cloud PC / session-host region. A "far" gateway means the nearest
regions were at capacity / load-shedding at connect time (service-side, usually
transient). Do **not** reintroduce any "gateway follows CPC region" model into the
parsers or verdicts (`ExtractRegionFromGatewayFqdn`, L-TCP-09 `RunGatewayUsed`,
Test 27 `RunCloudLocalEgress`, Key Findings).

## Build & release

The canonical commands and the signing contract live in [BUILD.md](BUILD.md).
Key rules:

- **Any change under `src/W365LocalScanner/**` requires a `<Version>` bump** (all
  three fields: Version / FileVersion / AssemblyVersion) + a `vX.Y.Z` tag.
  `scanner-version-guard.yml` **fails CI** if scanner source changed since the
  last tag but the version still matches that tag.
- Pushing the tag triggers `build-scanner.yml` (publish → sign → checksum →
  provenance → GitHub Release).
- **Dashboard-only changes** (`docs/**`) just push to `main` (triggers
  `deploy-pages.yml`). No tag. Bump the footer build number in `docs/index.html`.

## CI/CD & signing

Workflow: `.github/workflows/build-scanner.yml`

- Publishes the self-contained exe, then signs with **Azure Trusted Signing**
  (`azure/trusted-signing-action@v0.5.0`), computes SHA256, attaches SLSA
  build provenance (`actions/attest-build-provenance@v2`), and publishes a
  GitHub Release.
- Signing is **gated on repo variable `TRUSTED_SIGNING_ACCOUNT`** — until the
  MS signing identity is wired up, builds run unsigned. Required to enable:
  - Secrets: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`
  - Variables: `TRUSTED_SIGNING_ENDPOINT`, `TRUSTED_SIGNING_ACCOUNT`, `TRUSTED_SIGNING_PROFILE`

## Open items for the new owner

1. **Repoint distribution.** The scanner download is currently a **public GitHub
   Release** (`/releases/latest/download/W365LocalScanner.exe`). Move it to the
   intended auth-gated, read-only MS-hosted location and update the README +
   any embedded links.
2. **Rehost the dashboard.** Target is an MS-owned host (BUILD.md notes
   `connectivity.windows.microsoft.cloud`). The dashboard URL is **embedded in
   the scanner source** — rehosting requires a scanner source change and a new
   signed release.
3. **Wire up Azure Trusted Signing** with the MS signing identity (vars/secrets
   above).
4. **Privacy review of third-party GeoIP egress** (see below).
5. **Web security review of the dashboard CSP** (see below).

## Security & privacy posture

Clean findings from the pre-handoff review:

- Runs as standard user — **no elevation manifest** (asInvoker).
- Registry access is **read-only** (OpenSubKey; no SetValue/CreateSubKey).
- `Process.Start` calls use fixed commands / escaped args, `UseShellExecute=false`.
- Output path validated (rejects UNC `\\` and `..` traversal).
- **No vulnerable dependencies** (`dotnet list package --vulnerable`).
- **No telemetry** — the tool does not phone home; results stay on-device unless
  the user explicitly exports/shares them.
- AI analysis is **pure client-side rules** — no API key, no model endpoint.
- Reproducible build (Deterministic + ContinuousIntegrationBuild + embedded PDB)
  + Authenticode + SLSA provenance in CI.

Two items needing formal sign-off before official distribution:

- **Third-party GeoIP egress.** To estimate approximate location, the tool sends
  the machine's/relay's **public IP** (never credentials or identity) over HTTPS
  to non-MS services — scanner: ipinfo.io → ipapi.co → ipwho.is → geojs.io;
  dashboard: ipinfo.io → freeipapi.com → geojs.io → ipwho.is, plus Nominatim
  (reverse-geocoding when the user grants location permission). Disclosed in
  [THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES) and [README.md](README.md#privacy).
  **Recommendation:** privacy review to approve, or swap to an MS-owned
  geolocation service (e.g. Azure Maps).
- **Dashboard CSP `script-src 'unsafe-inline'`** (`docs/index.html`). Present
  because the dashboard uses pervasive inline event handlers. Dropping
  `unsafe-inline` requires a deliberate refactor to `addEventListener` + an
  external bootstrap — scope it as its own work item; it touches most of
  `index.html`.

## Repo map

| Path | Purpose |
|---|---|
| `src/W365LocalScanner/Program.cs` | Scanner — all tests, geolocation, host detection |
| `docs/` | Static dashboard (deployed via GitHub Pages) |
| `docs/js/` | `app.js`, `browser-tests.js`, `map.js`, `ai-analysis.js`, `ui.js`, `config.js` |
| `tools/*.ps1` | Unsigned diagnostic helper scripts |
| `BUILD.md` | Canonical build / signing contract |
| `DESIGN.md` | Architecture and test catalogue |
| `THIRD-PARTY-NOTICES` | External services and licences |
| `.github/workflows/` | `build-scanner.yml`, `deploy-pages.yml`, `scanner-version-guard.yml` |
