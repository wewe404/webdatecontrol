# PDCurses setup for webdatecontrol ncurses UI
$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$PdcRoot = "$ProjectRoot\pdcurses"

Write-Host "=== PDCurses Setup ===" -ForegroundColor Cyan

# Build path without hardcoding Chinese characters in source
$zuJian = [char]0x7EC4 + [char]0x4EF6  # 组件
$clPath = "D:\vc2022\$zuJian\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe"

if (-not (Test-Path $clPath)) {
    Write-Host "[ERROR] cl.exe not found!" -ForegroundColor Red
    exit 1
}
$clDir = Split-Path $clPath -Parent
$env:Path = "$clDir;$env:Path"
Write-Host "[OK] MSVC: $clPath" -ForegroundColor Green

if (Test-Path $PdcRoot) {
    Write-Host "[*] Already installed" -ForegroundColor Green
    exit 0
}

$PdcUrl = "https://github.com/wmcbrine/PDCurses/archive/refs/heads/master.zip"
$ZipFile = "$env:TEMP\pdcurses.zip"
$PdcSrc = "$env:TEMP\PDCurses-master"
$BatFile = "$env:TEMP\build_pdcurses.bat"

Write-Host "[1/3] Downloading PDCurses ..." -ForegroundColor Cyan
try {
    [Net.ServicePointManager]::SecurityProtocol = 3072
    Invoke-WebRequest -Uri $PdcUrl -OutFile $ZipFile -UseBasicParsing
} catch {
    Write-Host "[FAIL] Download error: $_" -ForegroundColor Red
    exit 1
}
Write-Host "    OK" -ForegroundColor Green

Write-Host "[2/3] Extracting ..." -ForegroundColor Cyan
if (Test-Path $PdcSrc) { Remove-Item -Recurse -Force $PdcSrc }
Expand-Archive -Path $ZipFile -DestinationPath "$env:TEMP" -Force
Write-Host "    OK" -ForegroundColor Green

Write-Host "[3/3] Building ..." -ForegroundColor Cyan
Push-Location "$PdcSrc\wincon"

@"
@echo off
chcp 65001 >nul
nmake /f Makefile.vc /nologo
if errorlevel 1 exit /b 1
"@ | Out-File -FilePath $BatFile -Encoding ASCII

cmd.exe /c "$BatFile" 2>&1 | ForEach-Object { Write-Host "    $_" }
$buildOk = $LASTEXITCODE -eq 0
Remove-Item $BatFile -Force -ErrorAction SilentlyContinue
Pop-Location

if (-not $buildOk) {
    Write-Host "[FAIL] Build failed" -ForegroundColor Red
    exit 1
}

Write-Host "    Installing ..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path "$PdcRoot\include" | Out-Null
New-Item -ItemType Directory -Force -Path "$PdcRoot\lib" | Out-Null
Copy-Item "$PdcSrc\curses.h" "$PdcRoot\include\" -Force
Copy-Item "$PdcSrc\panel.h" "$PdcRoot\include\" -Force -ErrorAction SilentlyContinue

$copied = $false
foreach ($lib in @("pdcurses.lib", "panel.lib")) {
    $src = "$PdcSrc\wincon\$lib"
    if (Test-Path $src) {
        Copy-Item $src "$PdcRoot\lib\" -Force
        Write-Host "    Copied: $lib"
        $copied = $true
    }
}
if (-not $copied) {
    Write-Host "[WARN] No .lib files found" -ForegroundColor Yellow
}

Remove-Item -Recurse -Force $PdcSrc -ErrorAction SilentlyContinue
Remove-Item -Force $ZipFile -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== PDCursues installed! ===" -ForegroundColor Green
Write-Host "Next: build.bat ncurses"
