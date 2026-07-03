@echo off
chcp 936 >nul

set VSWHERE="C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq delims=" %%i in (`%VSWHERE% -latest -products * -property installationPath`) do set VSINSTALL=%%i

if "%VSINSTALL%"=="" (
    echo Error: Visual Studio not found.
    exit /b 1
)

call "%VSINSTALL%\Common7\Tools\VsDevCmd.bat" -arch=x64

cl /utf-8 /EHsc /Fe:main.exe /I include /I "C:\Program Files\Npcap\Include" ^
    src\main.c src\capture.c src\pcap_io.c src\net_utils.c ^
    src\protocol.c src\bpf_filter.c ^
    /link /LIBPATH:"C:\Program Files\Npcap\Lib\x64" ^
    wpcap.lib Packet.lib ws2_32.lib advapi32.lib

if %errorlevel% neq 0 (
    echo Build failed.
    exit /b %errorlevel%
)

echo Build succeeded: main.exe
