$ErrorActionPreference = 'Stop'

# DFIR Companion — Chocolatey install script.
#
# Downloads the portable Windows build (the Node single-executable zip published with each
# GitHub release), verifies its SHA256, and unzips it into the package's tools directory.
# Chocolatey auto-creates a `dfir-companion` shim on PATH for the extracted EXE.
#
# The download URL + SHA256 in $packageArgs below are substituted by
# companion/scripts/build-choco.mjs at pack time (this is a template — do not pack it directly).

$packageName = 'dfir-companion'
$toolsDir    = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"

$packageArgs = @{
  packageName    = $packageName
  unzipLocation  = $toolsDir
  url64bit       = '__URL64__'
  checksum64     = '__CHECKSUM64__'
  checksumType64 = 'sha256'
}

Install-ChocolateyZipPackage @packageArgs

# --- Redirect writable data OUT of the admin-owned install dir -------------------------------
# The package lives under C:\ProgramData\chocolatey\lib\dfir-companion (admin-owned), which a
# non-elevated analyst can't write to. The server resolves .env + cases/ next to the EXE by
# default, so we point them at a per-user, writable location.
#
# We set exactly ONE persistent environment variable: DFIR_ENV_FILE (the bootstrap pointer —
# it can't live in the .env it names). Everything else, including DFIR_CASES_ROOT, is written
# INTO that .env so the file stays the single source of config truth (consistent with every
# other install type, and no env var silently shadows a value the analyst edits in the file).
$dataDir  = Join-Path $env:LOCALAPPDATA 'DFIR-Companion'
$casesDir = Join-Path $dataDir 'cases'
$envFile  = Join-Path $dataDir '.env'

if (-not (Test-Path $casesDir)) {
  New-Item -ItemType Directory -Path $casesDir -Force | Out-Null
}

# Seed a user-writable .env from the bundled example on first install (never overwrite an
# existing one — it may hold the analyst's API keys).
if (-not (Test-Path $envFile)) {
  $envExample = Join-Path $toolsDir '.env.example'
  if (Test-Path $envExample) {
    Copy-Item -Path $envExample -Destination $envFile -Force
  } else {
    New-Item -ItemType File -Path $envFile -Force | Out-Null
  }
}

# Ensure the .env points cases at the writable profile dir — but only if the analyst hasn't
# already set their own (idempotent across re-installs/upgrades; never clobbers a custom value).
if (-not (Select-String -Path $envFile -Pattern '^\s*DFIR_CASES_ROOT\s*=' -Quiet)) {
  Add-Content -Path $envFile -Value @(
    '',
    '# Added by the Chocolatey installer: keep cases in your user profile, not the install dir.',
    "DFIR_CASES_ROOT=$casesDir"
  )
}

# The only persistent env var: where to find the .env above.
Install-ChocolateyEnvironmentVariable -VariableName 'DFIR_ENV_FILE' -VariableValue $envFile -VariableType 'User'

# --- Bundle the capture extension (offline "Load unpacked") ----------------------------------
# The browser extension can't be auto-installed into Chrome/Comet portably, but shipping the
# built files on disk gives air-gapped/forensic workstations (no Web Store access) a one-folder
# "Load unpacked" target. We download the same dfir-capture-extension zip the release publishes,
# verify its own SHA256, and unpack it into the user data dir. The extension subtree is fully
# app-managed (not evidence), so we clear it first to avoid stale files across upgrades.
$extDir = Join-Path $dataDir 'extension'
$extZip = Join-Path $env:TEMP 'dfir-capture-extension.zip'

Get-ChocolateyWebFile -PackageName "$packageName-extension" -FileFullPath $extZip `
  -Url64bit '__EXT_URL64__' -Checksum64 '__EXT_CHECKSUM64__' -ChecksumType64 'sha256'
if (Test-Path $extDir) { Remove-Item -Path $extDir -Recurse -Force }
Get-ChocolateyUnzip -FileFullPath $extZip -Destination $extDir -PackageName "$packageName-extension"
Remove-Item -Path $extZip -Force -ErrorAction SilentlyContinue

Write-Host ''
Write-Host 'DFIR Companion installed.' -ForegroundColor Green
Write-Host '  Run:    dfir-companion        (then open http://127.0.0.1:4773/dashboard)'
Write-Host "  Cases:  $casesDir"
Write-Host "  Config: $envFile   (edit to set AI provider / threat-intel keys; all optional)"
Write-Host '  The server binds 127.0.0.1 only — no firewall rule is created or needed.'
Write-Host ''
Write-Host 'Capture extension (optional) bundled for offline install:' -ForegroundColor Green
Write-Host "  $extDir"
Write-Host '  Load it via chrome://extensions -> Developer mode -> Load unpacked -> that folder.'
Write-Host '  (Or install it from the Chrome Web Store once published.)'
Write-Host ''
