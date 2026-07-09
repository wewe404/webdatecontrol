# webdatecontrol
网络数据包的捕获与协议解析工具
运行本项目需要：

1. Visual Studio 2022，并安装“使用 C++ 的桌面开发”
2. Npcap Installer，安装时勾选 WinPcap API-compatible Mode
3. Npcap SDK，解压到 C:\Program Files\Npcap

然后用 VS Code 打开项目，按 Ctrl + Shift + B 编译，再运行 main.exe。

## 中文运行说明

为了避免中文菜单乱码，运行程序前请先在 VS Code 终端输入：

```powershell
chcp 65001
```

然后编译程序：

```powershell
.\build.bat
```

编译成功后运行：

```powershell
.\main.exe
```

如果中文仍然乱码，请重新执行：

```powershell
chcp 65001
.\main.exe
```
```
ncursesUI使用说明：
首先在PowerShell运行
.\pdcurses_setup.ps1   
然后运行
.\build.bat ncurses
.\main_ncurses.exe
```
