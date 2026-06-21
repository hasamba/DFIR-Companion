# Chocolatey package — `dfir-companion`

`choco install dfir-companion` installs the **portable Windows build** (the Node
single-executable published with each GitHub release) and bundles the **capture extension**
on disk for offline "Load unpacked". No Node.js install is required.

```
choco install dfir-companion
dfir-companion            # → http://127.0.0.1:4773/dashboard
choco upgrade dfir-companion
choco uninstall dfir-companion
```

## What's in here

This directory is a **template**, not a directly-packable package:

| File | Purpose |
| ---- | ------- |
| `dfir-companion.nuspec` | Package metadata. Carries a `__VERSION__` placeholder. |
| `tools/chocolateyinstall.ps1` | Downloads + verifies + unzips the portable build **and** the capture extension; sets the data-dir env var. Carries `__URL64__`/`__CHECKSUM64__` + `__EXT_URL64__`/`__EXT_CHECKSUM64__`. |
| `tools/chocolateyuninstall.ps1` | Removes the env var; **keeps** the user's data dir. |
| `tools/VERIFICATION.txt` | How to verify the two downloads (required by the community repo). Carries the URL/SHA256 placeholders. |
| `tools/LICENSE.txt` | License notice (AGPL-3.0-only). |

The placeholders are filled in by **`companion/scripts/build-choco.mjs`**, which copies this
template into `companion/dist-choco/` and optionally runs `choco pack`.

## How the install behaves

- The portable zip is unzipped into the package's `tools\` dir; Chocolatey auto-shims
  `dfir-companion.exe` onto `PATH` as `dfir-companion`.
- Writable data is redirected **out** of the admin-owned install dir. The install sets exactly
  one persistent env var — `DFIR_ENV_FILE` → `%LOCALAPPDATA%\DFIR-Companion\.env` (the bootstrap
  pointer) — then seeds that `.env` from the bundled `.env.example` and writes
  `DFIR_CASES_ROOT=%LOCALAPPDATA%\DFIR-Companion\cases` into it. Keeping cases-root in the file
  (not a second env var) means the `.env` stays the single config source and an analyst's edit
  isn't silently shadowed by a real env var.
- The **capture extension** is downloaded (its own SHA256) and unpacked into
  `%LOCALAPPDATA%\DFIR-Companion\extension` for offline "Load unpacked" — not auto-installed
  into the browser (no portable, browser-agnostic way to do that). The folder is refreshed on
  each install/upgrade.
- **No firewall rule** is created — the server binds `127.0.0.1` only (localhost invariant).
- Uninstall removes the binary, shim, and env var but **preserves** `%LOCALAPPDATA%\DFIR-Companion`
  (it holds evidence).

## Build locally

```powershell
cd companion
# Verify against real release zips you've downloaded (computes each SHA256):
npm run package:choco -- `
  --zip C:\path\to\dfir-companion-v0.25.0-win-x64.zip `
  --ext-zip C:\path\to\dfir-capture-extension-v0.25.0.zip --pack
# …or pass known checksums directly:
npm run package:choco -- --version 0.25.0 --checksum <sha256> --ext-checksum <sha256> --pack
# → companion/dist-choco/dfir-companion.0.25.0.nupkg
```

Test the package end-to-end (elevated shell):

```powershell
choco install dfir-companion --source "companion\dist-choco" -y
```

## Publishing

CI does this automatically on every `v*` tag — see the `chocolatey` job in
[`.github/workflows/release-artifacts.yml`](../../.github/workflows/release-artifacts.yml).
It packs with the SHA256s the `windows-exe` and `extension-zip` jobs computed for the same
assets, attaches the `.nupkg` to the GitHub Release, and pushes to the Chocolatey community
repo **only when the `CHOCOLATEY_API_KEY` secret is configured** (a no-op otherwise, so it's
safe to merge before the account exists). The first publish is moderated (~1 hour); later
versions are automated.

To push by hand:

```powershell
choco push companion\dist-choco\dfir-companion.0.25.0.nupkg --source https://push.chocolatey.org/ --api-key <key>
```
