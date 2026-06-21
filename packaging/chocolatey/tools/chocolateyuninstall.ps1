$ErrorActionPreference = 'Stop'

# DFIR Companion — Chocolatey uninstall script.
#
# Chocolatey removes the extracted binary, the bundled public/ + data/ assets, and the
# auto-generated `dfir-companion` shim itself. We only need to undo the one environment variable
# we set on install (DFIR_ENV_FILE). We deliberately KEEP the user's data directory (cases +
# .env + the unpacked extension) — deleting forensic evidence on an uninstall would be
# unacceptable.

Uninstall-ChocolateyEnvironmentVariable -VariableName 'DFIR_ENV_FILE' -VariableType 'User'

$dataDir = Join-Path $env:LOCALAPPDATA 'DFIR-Companion'
if (Test-Path $dataDir) {
  Write-Host ''
  Write-Host "Your cases, config, and bundled extension are preserved at: $dataDir" -ForegroundColor Yellow
  Write-Host 'Delete that folder by hand if you no longer need the evidence.'
  Write-Host ''
}
