# Build Windows x86_64 binaries.
#
#   pwsh -File dist\build-windows.ps1
#
# Output: dist\build\windows-x86_64\{rop-finder.exe,rop-finder-mcp.exe,
#         SHA256SUMS,rop-finder-windows-x86_64.zip}
$ErrorActionPreference = 'Stop'
$Repo = Split-Path -Parent $PSScriptRoot
Set-Location $Repo

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "cargo not found. Install Rust from https://rustup.rs"
}
# rf-scan depends on capstone-sys, which compiles ~44 MB of vendored C with the
# `cc` crate. On MSVC that needs the Visual Studio C++ build tools.
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    Write-Warning "cl.exe not on PATH. capstone-sys needs the MSVC C++ build tools."
    Write-Warning "Run from a 'x64 Native Tools Command Prompt', or install:"
    Write-Warning "  https://visualstudio.microsoft.com/visual-cpp-build-tools/"
}

# Strip the build machine out of the binary. `strip = ""symbols""` in
# [profile.release] drops the symbol table, but panic locations come from the
# file!() macro and are baked in as &'static str -- only --remap-path-prefix
# removes those, and it cannot be expressed in a profile. Measured on the
# pre-fix build: 178 occurrences of the maintainer's home directory in
# rop-finder.exe, 330 in rop-finder-mcp.exe (ENG-09).
$CargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
$env:RUSTFLAGS = "--remap-path-prefix=$CargoHome=/cargo --remap-path-prefix=$Repo=/src"
Write-Host "==> RUSTFLAGS = $env:RUSTFLAGS"

cargo build --release --locked -p rop-finder -p rop-finder-mcp
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

$Out = Join-Path $Repo 'dist\build\windows-x86_64'
if (Test-Path $Out) { Remove-Item -Recurse -Force $Out }
New-Item -ItemType Directory -Force -Path $Out | Out-Null

$Bins = @('rop-finder.exe', 'rop-finder-mcp.exe')
foreach ($b in $Bins) { Copy-Item "target\release\$b" (Join-Path $Out $b) }
Set-Location $Out

# Verify the remapping actually worked rather than assuming it.
$leaked = 0
foreach ($b in $Bins) {
    $bytes = [System.IO.File]::ReadAllBytes((Join-Path $Out $b))
    $text  = [System.Text.Encoding]::ASCII.GetString($bytes)
    $user  = Split-Path -Leaf $env:USERPROFILE
    $n = ([regex]::Matches($text, [regex]::Escape($user))).Count
    Write-Host ("    {0,-20} build-path hits: {1}" -f $b, $n)
    $leaked += $n
}
if ($leaked -gt 0) { Write-Warning "$leaked build-path strings survived; check RUSTFLAGS took effect." }

$lines = foreach ($b in $Bins) {
    "$((Get-FileHash $b -Algorithm SHA256).Hash.ToLower())  $b"
}
[System.IO.File]::WriteAllLines((Join-Path $Out 'SHA256SUMS'), $lines)

$Zip = 'rop-finder-windows-x86_64.zip'
Compress-Archive -Path ($Bins + 'SHA256SUMS') -DestinationPath $Zip -Force
Add-Content -Path 'SHA256SUMS' -Value "$((Get-FileHash $Zip -Algorithm SHA256).Hash.ToLower())  $Zip"

Write-Host "`n==> smoke test"
& ".\rop-finder.exe" --version | Select-Object -First 1
& ".\rop-finder.exe" --binary "$Repo\tests\fixtures\elf-Linux-x86" --depth 10 | Select-Object -Last 1

Write-Host "`n==> artifacts in $Out"
Get-ChildItem | Format-Table Name, Length -AutoSize
Get-Content SHA256SUMS
