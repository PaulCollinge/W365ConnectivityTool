# Build & Release

Canonical build commands for the Windows 365 Connectivity Tool. This file is the
contract between the source repository and any downstream signing / packaging
pipeline. Anything not documented here is not guaranteed to be reproducible.

## Product

A single signed binary plus a static dashboard:

| Component | Target | Output | Signed? |
|---|---|---|---|
| `src/W365LocalScanner` | `net8.0` (console) | `W365LocalScanner.exe` (self-contained, single-file, trimmed, win-x64) | Yes |
| `docs/` | static HTML/JS/CSS | hosted site (currently GitHub Pages, target: `connectivity.windows.microsoft.cloud`) | No |

The scanner runs locally, writes `W365ScanResults.json`, and opens the hosted
dashboard which loads the results. The dashboard URL is the only configuration
that ties the two together at runtime.

## Prerequisites

- .NET SDK 8.0.x

The scanner is self-contained and has no runtime prerequisite on user machines.

## Canonical publish command

Run from the repository root. Output path is stable and relative.

```powershell
dotnet publish src/W365LocalScanner/W365LocalScanner.csproj `
  --configuration Release `
  --output publish/W365LocalScanner `
  -p:ContinuousIntegrationBuild=true
```

Output: `publish/W365LocalScanner/W365LocalScanner.exe` (single self-contained
file, ~30–40 MB).

The csproj already pins `PublishSingleFile`, `SelfContained`,
`RuntimeIdentifier=win-x64`, and `PublishTrimmed` — no additional flags needed.

## Reproducibility

The project sets `<Deterministic>true</Deterministic>`,
`<ContinuousIntegrationBuild>` (activated by `-p:ContinuousIntegrationBuild=true`
on the publish command, or by `CI=true` in the environment),
`<DebugType>embedded</DebugType>`, and `<EmbedUntrackedSources>true</EmbedUntrackedSources>`.

Given the same .NET SDK version, same commit, and `ContinuousIntegrationBuild=true`,
the produced binary is byte-identical across machines. Verify with:

```powershell
Get-FileHash publish/W365LocalScanner/W365LocalScanner.exe -Algorithm SHA256
```

## Signing pipeline expectations

The signing pipeline (Microsoft-managed) consumes the publish output above and
signs it with an Authenticode certificate. The pipeline must NOT modify the
binary other than to apply the signature. Specifically:

- Do not strip the embedded PDB (debugging symbols and reproducibility metadata).
- Do not re-link or re-sign with a different `FileVersion` / `ProductVersion`;
  these come from the csproj `<Version>` and are part of the source contract.
- The signed binary's pre-signature SHA256 should match the unsigned hash
  produced above. Publish both hashes alongside each release for auditability.

## Release ritual (source side)

1. Bump `<Version>` in `src/W365LocalScanner/W365LocalScanner.csproj`.
2. Update release notes (file naming convention: `_release_notes_vMAJOR.MINOR.PATCH.md`
   during development; folded into `_release_notes.md` on cut).
3. Commit on `main` with message `release: vX.Y.Z - <short summary>`.
4. Tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.
5. Hand the tag to the signing pipeline. Pipeline signs from the tagged commit
   only — never from `HEAD`.

## Out of scope

- The static dashboard under `docs/` is published via GitHub Pages (today) and
  will move to an MS-hosted target. It has no build step and is not part of the
  signed-binary pipeline. The scanner embeds the dashboard URL; if the dashboard
  is rehosted, update the scanner source and cut a new signed release.
- `tools/*.ps1` are unsigned diagnostic helpers. If they need to ship signed,
  use Authenticode on the `.ps1` files separately (the scripts already declare
  `Set-StrictMode -Version Latest` and have no external dependencies).
