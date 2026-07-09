@echo off
chcp 65001 >nul

set C=D:\vc2022\组件\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe
set I=/I include /I "C:\Program Files\Npcap\Include" /I "D:\vc2022\组件\VC\Tools\MSVC\14.44.35207\include" /I "C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\ucrt" /I "C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um" /I "C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared"
set L=/LIBPATH:"C:\Program Files\Npcap\Lib\x64" /LIBPATH:"D:\vc2022\组件\VC\Tools\MSVC\14.44.35207\lib\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\ucrt\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64"
set S=src\main.c src\capture.c src\net_utils.c src\eth_parser.c src\ip_parser.c src\ipv6_parser.c src\tcp_parser.c src\udp_parser.c src\icmp_parser.c src\dns_parser.c src\http_parser.c src\bpf_filter.c src\stats.c src\protocol_analyze.c src\tcp_reassembly.c
set N=src\ncurses_ui.c src\capture.c src\net_utils.c src\eth_parser.c src\ip_parser.c src\ipv6_parser.c src\tcp_parser.c src\udp_parser.c src\icmp_parser.c src\dns_parser.c src\http_parser.c src\bpf_filter.c src\stats.c src\protocol_analyze.c src\tcp_reassembly.c
if "%1"=="ncurses" goto nc
if "%1"=="help" goto help
"%C%" /utf-8 /EHsc /Fe:main.exe %I% %S% /link %L% wpcap.lib Packet.lib ws2_32.lib
if errorlevel 1 (echo FAIL & exit /b 1)
echo OK - main.exe
goto :eof
:nc
if not exist pdcurses\include\curses.h (echo Install PDCurses first & exit /b 1)
"%C%" /utf-8 /EHsc /Fe:main_ncurses.exe %I% /I pdcurses\include %N% /link %L% /LIBPATH:pdcurses\lib wpcap.lib Packet.lib ws2_32.lib pdcurses.lib user32.lib advapi32.lib
if errorlevel 1 (echo FAIL & exit /b 1)
echo OK - main_ncurses.exe
goto :eof
:help
echo Usage: build.bat [ncurses|help]
goto :eof