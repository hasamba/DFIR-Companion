# Chocolatey package — `dfir-companion`

`choco install dfir-companion` installs the **portable Windows build** (the Node
single-executable published with each GitHub release). No Node.js install is required.

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
| `tools/chocolateyinstall.ps1` | Downloads + verifies + unzips the release; sets data-dir env vars. Carries `__URL64__` / `__CHECKSUM64__`. |
| `tools/chocolateyuninstall.ps1` | Removes the env vars; **keeps** the user's cases/config. |
| `tools/VERIFICATION.txt` | How to verify the downloaded binary (required by the community repo). |
| `tools/LICENSE.txt` | License notice (AGPL-3.0-only). |

The three placeholders are filled in by **`companion/scripts/build-choco.mjs`**, which copies
this template into `companion/dist-choco/` and optionally runs `choco pack`.

## How the install behaves

- The release zip is unzipped into the package's `tools\` dir; Chocolatey auto-shims
  `dfir-companion.exe` onto `PATH` as `dfir-companion`.
- Writable data is redirected **out** of the admin-owned install dir. The install sets exactly
  one persistent env var — `DFIR_ENV_FILE` → `%LOCALAPPDATA%\DFIR-Companion\.env` (the bootstrap
  pointer) — then seeds that `.env` from the bundled `.env.example` and writes
  `DFIR_CASES_ROOT=%LOCALAPPDATA%\DFIR-Companion\cases` into it. Keeping cases-root in the file
  (not a second env var) means the `.env` stays the single config source and an analyst's edit
  isn't silently shadowed by a real env var.
- **No firewall rule** is created — the server binds `127.0.0.1` only (localhost invariant).
- Uninstall removes the binary, shim, and env vars but **preserves** `%LOCALAPPDATA%\DFIR-Companion`
  (it holds evidence).

## Build locally

```powershell
cd companion
# Verify against a real release zip you've downloaded (computes its SHA256):
npm run package:choco -- --zip C:\path\to\dfir-companion-v0.25.0-win-x64.zip --pack
# …or pass a known checksum directly:
npm run package:choco -- --version 0.25.0 --checksum <sha256> --pack
# → companion/dist-choco/dfir-companion.0.25.0.nupkg
```

Test the package end-to-end (elevated shell):

```powershell
choco install dfir-companion --source "companion\dist-choco" -y
```

## Publishing

CI does this automatically on every `v*` tag — see the `chocolatey` job in
[`.github/workflows/release-artifacts.yml`](../../.github/workflows/release-artifacts.yml).
It packs with the SHA256 the `windows-exe` job computed for the same zip, attaches the
`.nupkg` to the GitHub Release, and pushes to the Chocolatey community repo **only when the
`CHOCOLATEY_API_KEY` secret is configured** (a no-op otherwise, so it's safe to merge before
the account exists). The first publish is moderated (~1 hour); later versions are automated.

To push by hand:

```powershell
choco push companion\dist-choco\dfir-companion.0.25.0.nupkg --source https://push.chocolatey.org/ --api-key <key>
```
