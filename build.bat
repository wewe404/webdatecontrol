@echo off
chcp 65001 >nul

call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=x64

cl /utf-8 /EHsc /Fe:main.exe /I include /I "C:\Program Files\Npcap\Include" src\main.c src\capture.c src\net_utils.c /link /LIBPATH:"C:\Program Files\Npcap\Lib\x64" wpcap.lib Packet.lib

if %errorlevel% neq 0 (
    echo 编译失败
    exit /b %errorlevel%
)

echo 编译成功，生成 main.exe