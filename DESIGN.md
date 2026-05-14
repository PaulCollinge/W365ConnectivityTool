# Design notes: W365 Connectivity Tool

This document captures the non-obvious design decisions, environment-specific
behaviour, and known pitfalls that informed the current implementation. It is
written for engineers picking the tool up for the first time.

It is intentionally focused on "things that have caused bugs before" rather
than a tour of the codebase. The code itself is the source of truth for
mechanics; this doc is the source of truth for *why*.

---

## 1. Architecture overview

```
┌──────────────────────┐         ┌──────────────────────────────────┐
│  W365LocalScanner    │ writes  │  Web dashboard (GitHub Pages)    │
│  (.NET WinExe)       │  JSON   │  docs/  — config.js, browser-    │
│                      │  +opens │  tests.js, ai-analysis.js,       │
│  src/W365LocalScanner│ browser │  map.js, app.js, ui.js, etc.     │
└──────────────────────┘         └──────────────────────────────────┘
        │                                       │
        ▼                                       ▼
   ~23 network probes from               Browser-side probes
   the local machine                     (DNS-over-HTTPS, fetch
   (C-* and L-* test IDs)                latency, STUN, WebRTC, etc.)
                                         (B-* test IDs)
```

Test ID prefix conventions:

| Prefix | Source                | Notes                                   |
|--------|------------------------|-----------------------------------------|
| `C-*`  | Cloud-PC-side scanner  | Run *on the CPC* (IMDS, wireserver, etc.) |
| `L-*`  | Local-machine scanner  | Run on the user's physical device       |
| `B-*`  | Browser dashboard      | Run in the page the user has open       |

When `W365ScanResults.json` is imported into the dashboard, results from all
three sources are merged on test ID. Provenance is preserved by ID prefix — do
not flatten it.

---

## 2. Network-path semantics

> Getting which *side* of the connection a probe reflects wrong produces
> confusing UI (e.g. "TURN says East US 2 but I'm on a UK VPN — is something
> broken?"). The answer is "no, and here's why" — encoded below.

### Client-side vs server-side endpoints

| Endpoint | Side | Determined by | VPN/SWG steering? |
|---|---|---|---|
| RD Gateway (`rdgateway-cNNN-<REGION>-rN.wvd.microsoft.com`) | **Client** entry point | Client-side DNS → Traffic Manager geo-DNS returning the nearest regional gateway to the *resolver's egress IP* | **Yes** — VPN egress country picks the gateway region. East-US-2 CPC + UK-egress VPN ⇒ UK RDGW (legitimate, not a bug). |
| TURN relay (`world.relay.avd.microsoft.com`) | **Server** side (media relay for the VM) | CPC-side DNS returns the CPC's own region's TURN | **No, when the scanner runs on the CPC** — see "Azure platform DNS" below. So TURN region == CPC region is the expected green state. |
| AFD Edge (`*.wvd.microsoft.com`, anycast) | **Client** side | Anycast BGP from the client's egress | **Yes** — VPN changes which PoP terminates. |
| Client-resolved DNS timings | **Client** side | Resolver the client is using | **Yes** |

### Region-mismatch diagnostic

Use **exact slug equality**, not free-text location matching:

- **CPC region** — from IMDS via `C-NET-01` (e.g. `Azure Region: West Europe (westeurope)`)
- **RDGW region** — from the short-code in the gateway FQDN in `L-TCP-09`/`C-TCP-09`
  (e.g. `rdgateway-c200-UKW-r1.wvd.microsoft.com` ⇒ `UKW` ⇒ `ukwest`)
- **TURN region** — from Azure Service Tags subnet mapping in `L-UDP-04`

Comparison buckets in [docs/js/map.js](docs/js/map.js):

- `compareAzureRegions(a, b)` → `'same' | 'intra' | 'cross' | 'unknown'`
- `'same'` → green
- `'intra'` → amber (flagged for RDGW only when VPN is active; always annotated for TURN)
- `'cross'` → red (always flagged — should be impossible without path interception)

`gatewayShortCodeToAzureSlug()` in [docs/js/map.js](docs/js/map.js) and
`GetAzureRegionName()` in [src/W365LocalScanner/Program.cs](src/W365LocalScanner/Program.cs)
**must cover the same set of regions** — keep them in sync.

### The Azure platform DNS subtlety

`168.63.129.16` is a Microsoft-owned IP that Azure VMs use as their default DNS
resolver. Traffic to it is intercepted at the hypervisor layer and does **not**
follow the guest's default route — even when that route is a full-tunnel VPN.
This is why:

- TURN resolves to the CPC's own region from inside a CPC even when a
  full-tunnel VPN routes everything else through London.
- IMDS (`169.254.169.254`) likewise bypasses VPNs *when reachable*.

The user-mode reachability of `168.63.129.16` itself is a different matter —
see §3.

---

## 3. Environment classification (CPC vs Azure VM vs physical client)

The tool runs in three different environments with overlapping but distinct
expectations. Confusing them has caused multiple false-positive bugs.

### Wireserver (`168.63.129.16:80`) reachability

- **Stock Azure VM**: user-mode TCP succeeds. A timeout is a real local block
  (firewall / EDR / Intune profile) and should be flagged.
- **Modern MS-provided Cloud PC images**: ship with Microsoft WFP filters that
  restrict `168.63.129.16` user-mode socket access to the Guest Agent process
  (`WaAppAgent` / `RDAgent`). User-mode probes return `WSAEACCES` (10013) on
  every healthy CPC. This is **expected**, not a third-party EDR signal.

The codebase had this carve-out for port `32526` but not for port `80`. Both
ports get the same treatment on CPC images. Treat WSAEACCES on this IP from a
user-mode probe as **Warning**, not Failed, and rely on Guest Agent heartbeat
/ extension install health for the real wireserver-break signal.

### "Am I on a Cloud PC?" detection

This decision drives a lot of dashboard behaviour (which cards to show, which
test IDs to expect, whether to surface the "run the local scanner" CTA). It
has been wrong twice in the past:

1. **The Windows 365 client writes `HKLM\SOFTWARE\Microsoft\Windows 365` on
   regular laptops.** Treating that registry key alone as a CPC signal causes
   laptops running the scanner to self-classify as Cloud PCs, mis-route their
   data into the CPC cards, and emit `scanMode: cloudpc` in the JSON. Always
   gate registry-based fallback detection on a signal that **only** exists in
   the target environment — for CPC, the `WindowsAzureGuestAgent` service.
2. **Don't alias data across host boundaries in the UI.** The dashboard's
   "This Device" / "ISP" cards must only be populated from browser-side tests
   running on the host the browser is on. Re-using CPC-side IP/ISP data for
   those cards when only a CPC scan was imported produces "your laptop's
   traffic appears to egress via Zscaler" diagrams when the laptop is on a
   plain ISP.

### Round-tripping the export format

The scanner emits `scanMode: 'cloudpc'` at the top level. The dashboard's
"Export Results" feature must preserve top-level provenance fields, otherwise
importing your own export looks like a fresh client scan and CPC-origin
browser results (`B-LE-01`/`B-LE-02` with `source: browser`) flow into the
importer's "This Device" cards. Either preserve the markers on export, or
infer origin from the **shape** of the results (presence of `C-*` IDs) so
detection survives lossy producers.

---

## 4. Test model: soft vs hard endpoints

Not every endpoint that a probe targets is a *required* connectivity path.
Treat probes as having three orthogonal attributes:

1. **What the probe saw** (raw fact: HTTP 200, TCP RST, timeout, etc.)
2. **Whether the requirement is hard or soft** (does failure block real use?)
3. **What a failure most likely means** (config, EDR, network, expected
   behaviour on this environment, etc.)

Collapsing these into a single pass/fail message loses information and trains
users to mistrust the tool. Specifically:

- **A single questionable soft-endpoint result must not force an overall
  Failed verdict** — but it must produce a visible Warning, not be silently
  excluded. Silent exclusion is an invisible bug.
- Messages should be of the form *"X should work; if it doesn't, check
  A/B/C"* rather than *"X might fail; probably benign, ignore."* The former
  is actionable; the latter trains users to ignore real findings.

---

## 5. Correlation and inference rules

The dashboard runs several cross-test correlations (see
[docs/js/ai-analysis.js](docs/js/ai-analysis.js)). When adding or changing
these:

- **Use the strongest signal available, not the most convenient one.** Before
  inferring a property from a weaker probe, grep all existing tests for direct
  evidence. Example: "is RDP egressing via the corporate ZTNA tunnel?" is
  answered authoritatively by the route table captured in `L-TCP-07` (does
  the tunnel adapter capture `40.64.144.0/20`, `51.5.0.0/16`, or the resolved
  RDP gateway IP?). Inferring it from `B-LE-02` (the browser's ISP string) is
  a heuristic and should only be used to corroborate, not as the primary
  decision input.
- **Findings labelled with a specific technical cause must be deterministic
  about that cause; otherwise rename the finding to what it actually
  detects.** Example: "different HTTP and STUN egress IPs in the same
  country" is most commonly produced by IPv4/IPv6 dual-stack (HTTP via v6,
  STUN via v4), and is **not** a deterministic signal of CGNAT — CGNAT
  subscribers don't expose `100.64.0.0/10` addresses externally anyway. The
  honest deterministic signal for CGNAT is traceroute hops in
  `100.64.0.0/10`. If the underlying check isn't specific to the named cause,
  rename to a neutral description ("different egress paths") and let the
  user investigate. Mis-naming trains users to distrust the whole tool.
- **Mode flags are not provenance flags.** `cloudPcMode` is set whenever a
  CPC JSON is imported, regardless of where the browser is running. It must
  not be used to decide whether a card represents host data — only the
  test-ID prefix should drive that.

### Result-merge call sites

`W365ScanResults.json` data reaches the page through two distinct entry
points:

1. **Manual import** via `processImportedData(...)` in
   [docs/js/app.js](docs/js/app.js).
2. **Scanner-auto-opened tab** where the scanner pre-loads the JSON and
   *then* browser tests run.

Any post-import merge or normalisation step must be invoked at **every**
call site that could be the last writer of the merged shape. Otherwise the
scanner-auto-open flow ends up with stale data because the merge only ran on
the manual-import path. Two grep passes for the data-shape's callers will
catch this in seconds.

---

## 6. Scanner release flow

The scanner exe is **not** rebuilt automatically on pushes to `main`. The
`build-scanner.yml` workflow only triggers on `v*` tag pushes. The landing
page's download button points at
`/releases/latest/download/W365LocalScanner.exe`, so if the latest tag is
stale relative to `main`, users download a stale binary and any client-side
tests added since that tag won't be present.

### Whenever scanner C# code changes (`src/W365LocalScanner/**`)

1. Bump all three in
   [src/W365LocalScanner/W365LocalScanner.csproj](src/W365LocalScanner/W365LocalScanner.csproj):
   - `<Version>`
   - `<FileVersion>`
   - `<AssemblyVersion>`
2. `git commit -am "release(scanner): v<new> — <summary>"`
3. `git tag -a v<new> -m "v<new>"`
4. `git push && git push origin v<new>`
5. Watch the tag-triggered workflow complete, then verify
   `releases/latest` points at the new tag before asking users to
   re-download.

### Guard

`.github/workflows/scanner-version-guard.yml` fails CI on PRs/pushes to `main`
if files under `src/W365LocalScanner/**` changed but the csproj `<Version>`
still matches the latest `v*` tag.

**Subtlety**: the legitimate "bump csproj + tag + push together" flow is
string-identical to the bad case (csproj == latest tag). The guard
short-circuits with PASS when HEAD is at or behind the tag commit
(`git merge-base --is-ancestor`). When releasing, push the branch and the tag
together — both events arrive in one workflow run, the tag exists by the time
the guard runs, and the short-circuit fires.

### Cache-buster

The static site's cache-buster (query strings `?v=NNN` in
[docs/index.html](docs/index.html)) is independent of scanner releases. Bump
it on **every** docs-side change.

---

## 7. Pitfalls to avoid (summary)

A short checklist distilled from past regressions:

- Enumerate every code path that creates a given data shape before adding a
  merge/post-processing step. Place the merge at every last-writer site, not
  just one.
- Test both orderings of any timing-dependent flow before declaring done.
- Don't use registry/service keys for environment detection unless they're
  unique to that environment.
- Don't alias data across host boundaries in the UI.
- Round-trip your own export format end-to-end.
- Findings named for a specific cause must deterministically detect that
  cause, or be renamed.
- Soft-endpoint failures get Warning, not silent exclusion, not Failed.
- WSAEACCES from a user-mode probe to `168.63.129.16` on a Cloud PC is
  expected, not an EDR signal.
