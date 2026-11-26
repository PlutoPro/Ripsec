# Builds the Android app as an APK.
#
#   ./scripts/build-android.ps1                  # for phones (64 bit ARM)
#   ./scripts/build-android.ps1 -Target x86_64   # for the emulator
#
# Needs the Android SDK with an NDK, a JDK (17 or later), Node.js, and Rust with the matching
# target (rustup target add aarch64-linux-android). The APK is a debug build, signed with the
# local debug key: fine for your own devices, not for distribution.
param([ValidateSet('aarch64', 'x86_64')][string]$Target = 'aarch64')

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent

if (-not $env:ANDROID_HOME) { $env:ANDROID_HOME = Join-Path $env:LOCALAPPDATA 'Android\Sdk' }
if (-not (Test-Path $env:ANDROID_HOME)) { throw 'Set ANDROID_HOME to your Android SDK.' }
if (-not $env:NDK_HOME) {
    $ndk = Get-ChildItem (Join-Path $env:ANDROID_HOME 'ndk') -Directory -ErrorAction SilentlyContinue |
        Sort-Object { [version]$_.Name } | Select-Object -Last 1
    if (-not $ndk) { throw 'Install an NDK with the SDK manager, or set NDK_HOME.' }
    $env:NDK_HOME = $ndk.FullName
}
if (-not $env:JAVA_HOME) {
    $java = Get-Command java -ErrorAction SilentlyContinue
    if (-not $java) { throw 'Install a JDK, or set JAVA_HOME.' }
    $env:JAVA_HOME = Split-Path (Split-Path $java.Source)
}

Push-Location (Join-Path $root 'app')
try {
    npm ci --no-fund --no-audit
    if ($LASTEXITCODE) { throw 'npm failed' }
    if (-not (Test-Path 'gen\android')) {
        npm run tauri -- android init --ci --skip-targets-install
        if ($LASTEXITCODE) { throw 'creating the Android project failed' }
    }
    npm run tauri -- android build --debug --apk --target $Target
    if ($LASTEXITCODE) { throw 'building the APK failed' }
    Get-ChildItem 'gen\android\app\build\outputs\apk' -Recurse -Filter '*.apk' | ForEach-Object { "APK: $($_.FullName)" }
}
finally { Pop-Location }
