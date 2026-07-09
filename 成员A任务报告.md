# 成员A任务完成报告

## 网络数据包捕获与协议解析工具 — 抓包引擎 & PCAP 文件层

### 一、任务概览

根据项目分工方案，成员A（成员1）主要负责抓包引擎与 PCAP 文件层，为后续协议解析、流量统计和展示模块提供稳定的数据包来源与离线抓包文件支持。

| 模块 | 文件 | 核心功能 |
|------|------|---------|
| 抓包引擎 | capture.h / capture.c | 网卡枚举、打开指定网卡、连续抓包、超时处理 |
| PCAP 文件层 | capture.h / capture.c | PCAP 保存、离线读取回放、按 BPF 规则读取 |
| 抓包过滤 | capture.c | pcap_compile / pcap_setfilter 基础过滤接口 |
| 网络工具函数 | net_utils.h / net_utils.c | MAC/IP 地址格式化、16 位校验和计算、自测 |
| 性能测试 | capture.c | 包速率、吞吐量、pcap_stats 丢包统计 |
| 主程序集成 | main.c | 成员A相关菜单入口、网卡选择及功能调度 |

> 说明：成员A负责抓包引擎和文件层，不负责 DNS、HTTP、TCP/UDP 等详细协议解析。抓到的原始数据包和 PCAP 文件由其他成员的协议解析模块继续处理。

### 二、各模块详细说明

#### 2.1 网卡枚举与抓包初始化

核心流程：

```text
pcap_findalldevs()
        ↓
显示本机网卡列表
        ↓
用户选择指定网卡
        ↓
pcap_open_live()
        ↓
获得 pcap_t 抓包句柄
```

核心功能：
- 使用 `pcap_findalldevs()` 获取本机可用网卡列表；
- 显示网卡名称和网卡描述；
- 支持用户通过编号选择指定网卡；
- 使用 `pcap_open_live()` 打开网卡；
- snaplen 设置为 65535，尽量完整捕获数据包；
- 开启混杂模式；
- 设置读取超时时间，避免抓包接口永久无响应。

主要函数：
- `list_devices()`
- `capture_init()`
- `select_device()`
- `start_capture()`
- `stop_capture()`

#### 2.2 连续抓包与抓包统计

当前抓包循环主要基于 `pcap_next_ex()` 实现。

```text
pcap_next_ex()
      ↓
返回 1：成功捕获数据包
返回 0：本次等待超时
返回 -1/-2：错误或结束
```

核心功能：
- 连续抓取指定数量的数据包；
- 输出每个数据包长度；
- 统计总包数和总字节数；
- 计算平均包长、最大包长和最小包长；
- 对连续超时进行计数，避免低流量网卡下程序长时间看似“卡死”。

主要函数：
- `capture_one_packet()`
- `capture_packets_with_stats()`

当前实现选择 `pcap_next_ex()`，主要是因为菜单程序需要支持“指定抓包数量、超时判断和主动结束”，使用显式循环更方便控制。后续如果需要长时间持续抓包，也可以接入 `pcap_loop()` 和 callback 模式。

#### 2.3 PCAP 文件保存与读取回放

PCAP 保存流程：

```text
pcap_dump_open()
       ↓
获取 pcap_dumper_t
       ↓
pcap_next_ex() 获取数据包
       ↓
pcap_dump() 写入文件
       ↓
pcap_dump_close()
```

PCAP 回放流程：

```text
pcap_open_offline()
        ↓
打开 PCAP 文件
        ↓
pcap_next_ex()
        ↓
逐包读取
        ↓
输出包长和统计信息
```

核心功能：
- 将实时抓到的数据包保存为 `.pcap` 文件；
- 保存文件可直接使用 Wireshark 打开验证；
- 支持重新打开已有 PCAP 文件；
- 逐个读取 PCAP 文件中的数据包；
- 输出 `len` 和 `caplen`；
- 统计文件中的总包数和总字节数。

主要函数：
- `capture_save_to_file()`
- `read_pcap_file()`

使用 Npcap/libpcap 提供的 PCAP 接口可以自动处理 PCAP Global Header 和 Packet Header 的标准写入与读取，降低手动二进制读写导致的格式错误风险。

#### 2.4 BPF 过滤接口

成员A在抓包引擎侧提供基础 BPF 过滤能力，用于实时抓包和 PCAP 文件读取测试。

```text
文本过滤规则
    ↓
pcap_compile()
    ↓
BPF 字节码
    ↓
pcap_setfilter()
    ↓
只接收符合规则的数据包
```

支持的规则示例：

```text
tcp
udp
icmp
tcp port 80
host 192.168.31.143
tcp and port 443
```

核心功能：
- 编译 BPF 文本过滤表达式；
- 将过滤规则应用到实时抓包句柄；
- 对离线 PCAP 文件应用过滤规则；
- 批量读取符合条件的数据包；
- 统计匹配包数和总字节数。

主要函数：
- `apply_filter()`
- `read_pcap_file_with_filter()`

> 本模块中的 BPF 功能属于抓包引擎侧基础接口；项目中更完整的 BPF 规则校验、测试套件和统一封装由成员C模块负责。

#### 2.5 网络工具函数

成员A实现了抓包和网络数据处理常用的辅助工具函数。

核心功能：
- `mac_ntop()`：将 6 字节 MAC 地址转换为可读字符串；
- `ip_ntop()`：将 IPv4 地址转换为点分十进制字符串；
- `checksum16()`：计算 16 位 Internet 校验和；
- `net_utils_self_test()`：使用固定测试数据验证工具函数输出。

示例输出：

```text
MAC 转换结果：00:1A:2B:3C:4D:5E
IP 转换结果：192.168.31.143
校验和结果：0xA877
```

相关文件：
- `include/net_utils.h`
- `src/net_utils.c`

#### 2.6 抓包性能与丢包统计

为便于后续压测和性能优化，成员A实现了抓包引擎侧性能测试入口。

核心指标：
- 捕获包数；
- 捕获字节数；
- 平均包速率 `packets/s`；
- 平均吞吐量 `Mbps`；
- `pcap_stats()` 返回的 `ps_recv`；
- `ps_drop`；
- `ps_ifdrop`；
- 估算丢包率。

主要函数：
- `performance_capture_test()`
- `menu_performance_test()`

计算思路：

```text
packets/s = 捕获包数 ÷ 实际运行时间
Mbps = 捕获总字节数 × 8 ÷ 时间 ÷ 1,000,000
```

`pcap_stats()` 用于获取抓包驱动层统计数据，为后续定位高流量场景下的丢包和性能瓶颈提供依据。

### 三、时间线对照

| 文档安排 | 实际完成 |
|---------|---------|
| 第1天：调研 libpcap/Npcap API 全流程 | ✅ 完成 `pcap_findalldevs`、`pcap_open_live`、`pcap_next_ex` 流程调研与验证 |
| 第2天：编写 `capture_init()` 骨架和网卡选择 | ✅ 完成网卡枚举、编号选择、指定网卡打开 |
| 第3天：完善抓包初始化参数 | ✅ 完成 snaplen、混杂模式和 timeout 配置 |
| 第4天：完成数据包接收循环 | ✅ 基于 `pcap_next_ex()` 完成可控抓包循环和超时处理 |
| 第5天：实现 PCAP 文件写入 | ✅ 使用 `pcap_dump_open()` / `pcap_dump()` 保存标准 PCAP 文件 |
| 第6天：实现 PCAP 文件读取回放 | ✅ 使用 `pcap_open_offline()` 逐包读取并统计 |
| 第7天：完善网络工具函数 | ✅ 完成 `mac_ntop()`、`ip_ntop()`、`checksum16()` 及自测 |
| 第8天：提供 PCAP 批量筛选读取接口 | ✅ 支持按 BPF 规则批量读取指定协议/主机/端口流量 |
| 第9天：抓包模块内部链路整合 | ✅ 完成网卡选择→抓包→统计→保存/回放→菜单入口整合 |
| 第10天：性能测试 | ✅ 完成定时抓包、pps、Mbps 等性能指标统计入口 |
| 第11天：丢包与性能分析准备 | ✅ 使用 `pcap_stats()` 输出接收包数、丢包数和估算丢包率 |

与原计划的差异说明：
- 当前实时抓包循环使用 `pcap_next_ex()`，没有直接使用 `pcap_loop()` callback 模式。这样更方便菜单程序控制抓包数量、超时和主动退出。
- PCAP 文件读写采用 libpcap 标准接口完成，没有手动二进制构造 Global Header 和 Packet Header。
- 1 Gbps Scapy 混合流量专项压测仍需在全组联调环境中统一执行；当前已完成抓包引擎侧性能和丢包统计工具。

### 四、文件清单

```text
webdatecontrol/
├── include/
│   ├── capture.h          ← [A] 抓包引擎与PCAP文件接口
│   └── net_utils.h        ← [A] 网络工具函数接口
├── src/
│   ├── capture.c          ← [A] 抓包、过滤、PCAP读写、性能统计实现
│   ├── net_utils.c        ← [A] MAC/IP转换和校验和实现
│   └── main.c             ← [A/C/D] 主程序集成，A提供抓包相关菜单入口
├── build.bat              ← 全组编译脚本
└── README.md              ← 项目运行说明
```

### 五、与其他成员模块的接口关系

成员A负责整个项目的数据入口。

```text
网卡/Npcap
    ↓
成员A：抓包引擎
    ↓
原始数据包 / PCAP文件
    ↓
成员B：底层协议解析
    ↓
成员C：DNS/HTTP、BPF统一封装、统计
    ↓
成员D：展示或其他扩展功能
```

成员A不解析 DNS、HTTP 等应用层协议，主要负责稳定获取数据包、保存 PCAP 文件和提供离线读取能力。

### 六、编译验证

开发环境：

```text
Windows
Visual Studio 2022 / MSVC x64
Npcap Runtime
Npcap SDK
VS Code
```

使用项目根目录下的 `build.bat` 编译：

```powershell
.\build.bat
```

运行前为避免中文乱码，可先执行：

```powershell
chcp 65001
```

运行：

```powershell
.\main.exe
```

当前成员A相关源文件可以正常参与项目编译，并完成网卡枚举、抓包、BPF过滤、PCAP保存/回放、工具函数自测和性能统计测试。

### 七、答辩准备 — 技术问题回答要点

**Q1：Npcap 是什么？**

> Npcap 是 Windows 平台下的网络抓包驱动和开发库，可以理解为 Windows 下常用的 libpcap 实现。项目通过它提供的 API 获取网卡、打开网卡、捕获数据包、设置 BPF 过滤和读写 PCAP 文件。

**Q2：为什么当前使用 `pcap_next_ex()`，而不是 `pcap_loop()`？**

> `pcap_next_ex()` 每次主动获取一个数据包，并明确返回成功、超时或错误状态。当前程序是菜单式工具，需要控制抓包数量、处理超时和主动结束，因此显式循环更容易管理。`pcap_loop()` 更适合持续抓包和 callback 驱动模式，后续持续抓包场景也可以切换到该模式。

**Q3：如何处理抓包时长时间没有数据的问题？**

> `pcap_open_live()` 设置读取超时，`pcap_next_ex()` 返回 0 表示本次等待超时。程序对连续超时进行计数，达到一定次数后提前结束抓包，避免用户误以为程序卡死。

**Q4：BPF 过滤的原理是什么？**

> 先使用 `pcap_compile()` 把文本规则编译成 BPF 字节码，再使用 `pcap_setfilter()` 挂载到抓包句柄。设置成功后，只有符合规则的数据包会交给抓包程序，从而减少无关流量。

**Q5：PCAP 文件是怎么保存和读取的？**

> 保存时使用 `pcap_dump_open()` 创建标准 PCAP 文件，再用 `pcap_dump()` 逐包写入。读取时使用 `pcap_open_offline()` 打开文件，再通过 `pcap_next_ex()` 逐包回放。Global Header 和 Packet Header 的标准格式由 libpcap 接口处理。

**Q6：`len` 和 `caplen` 有什么区别？**

> `len` 是原始数据包在网络上的真实长度，`caplen` 是实际捕获并保存的长度。如果 snaplen 小于数据包长度，`caplen` 可能小于 `len`。当前 snaplen 设置为 65535，一般可以完整捕获普通数据包。

**Q7：如何判断抓包是否发生丢包？**

> 调用 `pcap_stats()` 获取统计信息。`ps_recv` 表示驱动收到的包数，`ps_drop` 表示由于缓冲区等原因被丢弃的包数，`ps_ifdrop` 表示网络接口层报告的丢包数。程序根据这些数据计算估算丢包率。

**Q8：如何处理缓冲区溢出？**

> 当前通过减少每个数据包接收路径中的额外处理、抓包和复杂协议解析分层、使用 BPF 提前过滤无关数据，并利用 `pcap_stats()` 监控 `ps_drop`。如果高流量压测中发现丢包继续增加，可以进一步采用 `pcap_loop()` callback、批量处理或增加抓包缓冲区等方式优化。
