# Builds the Windows installer: app, service and driver library in one setup.exe.
#
#   ./scripts/build-windows.ps1 -Wintun C:\path\to\wintun\bin\amd64\wintun.dll
#
# Needs Rust (MSVC), Node.js (to run the Tauri bundler) and wintun.dll from https://www.wintun.net.
param([string]$Wintun)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$bin = Join-Path $root 'app\bin'
$bundled = Join-Path $bin 'wintun.dll'

New-Item -ItemType Directory -Force $bin | Out-Null
if ($Wintun) { Copy-Item $Wintun $bundled -Force }
elseif (-not (Test-Path $bundled)) { throw 'Pass -Wintun with the path to wintun.dll (amd64).' }

# The library is loaded by a service running as SYSTEM, so insist on an intact signature.
$signature = Get-AuthenticodeSignature $bundled
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'WireGuard') {
    throw "wintun.dll is not validly signed by WireGuard (status: $($signature.Status))."
}

Push-Location $root
try {
    cargo build --release --locked -p ripsec-client --bin ripsec-service
    if ($LASTEXITCODE) { throw 'building the service failed' }
    Copy-Item 'target\release\ripsec-service.exe' $bin -Force

    Set-Location app
    npx --yes '@tauri-apps/cli@2.12.5' build --config tauri.bundle.conf.json
    if ($LASTEXITCODE) { throw 'building the installer failed' }
    Get-ChildItem 'target\release\bundle\nsis\*-setup.exe' | ForEach-Object { "Installer: $($_.FullName)" }
}
finally { Pop-Location }
