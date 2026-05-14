# Build & Release

Canonical build commands for the Windows 365 Connectivity Tool. This file is the
contract between the source repository and any downstream signing / packaging
pipeline. Anything not documented here is not guaranteed to be reproducible.

## Products

Two artefacts ship as a single product, versioned in lock-step:

| Project | Target | Output |
|---|---|---|
| `src/W365ConnectivityTool` | `net10.0-windows` (WPF) | `W365ConnectivityTool.exe` (framework-dependent) |
| `src/W365LocalScanner` | `net8.0` (console) | `W365LocalScanner.exe` (self-contained, single-file, trimmed, win-x64) |

Both csproj files declare the same `<Version>`. Update them together.

## Prerequisites

- .NET SDK 8.0.x (for the scanner)
- .NET SDK 10.0.x (for the WPF app)
- Windows host (WPF requires `net10.0-windows`)

The published WPF app requires the .NET 10 Desktop Runtime on the target machine.
The scanner is self-contained and has no runtime prerequisite.

## Canonical publish commands

Run from the repository root. Output paths are stable and relative.

### WPF app (framework-dependent, win-x64)

```powershell
dotnet publish src/W365ConnectivityTool/W365ConnectivityTool.csproj `
  --configuration Release `
  --runtime win-x64 `
  --self-contained false `
  --output publish/W365ConnectivityTool `
  -p:ContinuousIntegrationBuild=true
```

Output: `publish/W365ConnectivityTool/W365ConnectivityTool.exe` (+ supporting DLLs).

### Local Scanner (self-contained, single-file)

The scanner csproj already pins `PublishSingleFile`, `SelfContained`,
`RuntimeIdentifier=win-x64`, and `PublishTrimmed`. The publish command is
therefore minimal:

```powershell
dotnet publish src/W365LocalScanner/W365LocalScanner.csproj `
  --configuration Release `
  --output publish/W365LocalScanner `
  -p:ContinuousIntegrationBuild=true
```

Output: `publish/W365LocalScanner/W365LocalScanner.exe` (single self-contained
file, ~30–40 MB).

## Reproducibility

Both projects set `<Deterministic>true</Deterministic>`,
`<ContinuousIntegrationBuild>` (activated by `-p:ContinuousIntegrationBuild=true`
on the publish command, or by `CI=true` in the environment),
`<DebugType>embedded</DebugType>`, and `<EmbedUntrackedSources>true</EmbedUntrackedSources>`.

Given the same .NET SDK version, same commit, and `ContinuousIntegrationBuild=true`,
the produced binaries are byte-identical across machines. Verify with:

```powershell
Get-FileHash publish/W365ConnectivityTool/W365ConnectivityTool.exe -Algorithm SHA256
Get-FileHash publish/W365LocalScanner/W365LocalScanner.exe -Algorithm SHA256
```

## Signing pipeline expectations

The signing pipeline (Microsoft-managed) consumes the publish outputs above and
signs them with an Authenticode certificate. The pipeline must NOT modify the
binaries other than to apply the signature. Specifically:

- Do not strip embedded PDBs (debugging symbols and reproducibility metadata).
- Do not re-link or re-sign with a different `FileVersion` / `ProductVersion`;
  these come from the csproj `<Version>` and are part of the source contract.
- The signed binary's pre-signature SHA256 should match the unsigned hash
  produced above. Publish both hashes alongside each release for auditability.

## Release ritual (source side)

1. Bump `<Version>` in **both** csproj files to the new value.
2. Update release notes (file naming convention: `_release_notes_vMAJOR.MINOR.PATCH.md`
   during development; folded into `_release_notes.md` on cut).
3. Commit on `main` with message `release: vX.Y.Z - <short summary>`.
4. Tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.
5. Hand the tag to the signing pipeline. Pipeline signs from the tagged commit
   only — never from `HEAD`.

## Out of scope

- The static dashboard under `docs/` is published via GitHub Pages directly from
  `main`; it has no build step and is not part of the signed-binary pipeline.
- `tools/*.ps1` are unsigned diagnostic helpers. If they need to ship signed,
  use Authenticode on the `.ps1` files separately (the scripts already declare
  `Set-StrictMode -Version Latest` and have no external dependencies).
