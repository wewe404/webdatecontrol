# 成员C任务完成报告

## 网络数据包捕获与协议解析工具 — 应用层解析 & 统计模块

### 一、任务概览

根据分工方案文档，成员C（成员3）负责以下模块：

| 模块 | 文件 | 核心功能 |
|------|------|---------|
| DNS解析 | dns_parser.h / dns_parser.c | DNS报文Header/Question/Answer解析、域名压缩指针解码 |
| HTTP解析 | http_parser.h / http_parser.c | HTTP请求行/状态行/Header解析、chunked编码解码 |
| BPF过滤 | bpf_filter.h / bpf_filter.c | BPF规则编译/挂载/校验、离线过滤、测试套件 |
| 流量统计 | stats.h / stats.c | 按协议/IP聚合统计、每秒速率、吞吐量计算 |
| 共享结构 | common.h | 全组统一的protocol_t枚举、各层协议头struct、ParsedPacket |
| 协议整合 | protocol_analyze.h / protocol_analyze.c | Ethernet→IP→TCP/UDP→DNS/HTTP逐层解析调度 |

### 二、各模块详细说明

#### 2.1 DNS协议解析 (dns_parser)

**RFC 1035 报文格式实现：**

```
DNS报文结构:
+---------------------+
| Header (12 bytes)   |  Transaction ID, Flags, QD/AN/NS/AR Count
+---------------------+
| Question section    |  QNAME + QTYPE + QCLASS
+---------------------+
| Answer section      |  Name + Type + Class + TTL + RDLENGTH + RDATA
+---------------------+
| Authority section   |  同Answer格式
+---------------------+
| Additional section  |  同Answer格式
+---------------------+
```

**核心功能：**
- DNS Header 12字节解析（Transaction ID、Flags位解析：QR/Opcode/AA/TC/RD/RA/RCODE）
- Question区域名解码（支持标签长度+标签内容的格式）
- **域名压缩指针解码**（0xC0前缀，14位偏移量指向报文内位置，支持链式跳转，带安全计数器防死循环）
- Answer/Authority/Additional区RR记录解析
- 支持的RR类型：A(IPv4)、AAAA(IPv6)、CNAME、NS、SOA、PTR、MX(含preference)、TXT、SRV
- 格式化打印DNS解析结果

**关键算法 — 域名压缩指针解码：**
```c
// 当标签长度字节的高2位为11(0xC0)时，表示压缩指针
if ((label_len & 0xC0) == 0xC0) {
    // 指针值 = (label_len & 0x3F) << 8 | next_byte
    uint16_t pointer = ((label_len & 0x3F) << 8) | data[pos + 1];
    // 跳转到pointer位置继续解码
}
```

#### 2.2 HTTP协议解析 (http_parser)

**支持两种报文格式：**

```
HTTP请求:
  METHOD SP URI SP HTTP-VERSION CRLF
  Header-Key: Header-Value CRLF
  ...更多Header...
  CRLF
  [Body]

HTTP响应:
  HTTP-VERSION SP STATUS-CODE SP REASON-PHRASE CRLF
  Header-Key: Header-Value CRLF
  ...更多Header...
  CRLF
  [Body]
```

**核心功能：**
- 自动识别请求/响应（通过"HTTP/"前缀判断）
- 请求行解析：GET/POST/PUT/DELETE/HEAD/OPTIONS/CONNECT/TRACE/PATCH
- 状态行解析：版本 + 状态码 + 原因短语
- Header键值对解析（不区分大小写查找）
- **chunked分块传输编码解码**（十六进制chunk-size + chunk-data循环，支持chunk扩展）
- Body自动提取和内存管理（malloc/free）
- 格式化打印HTTP解析结果

#### 2.3 BPF过滤封装 (bpf_filter)

**BPF过滤原理链路：**
```
文本规则 → pcap_compile() → BPF字节码 → pcap_setfilter() → 内核BPF VM → 包过滤
```

**核心功能：**
- `bpf_compile_and_set()` — 封装pcap_compile + pcap_setfilter完整流程
- `bpf_validate()` — 使用pcap_open_dead创建校验句柄，不实际抓包即可验证规则语法
- `bpf_validate_detail()` — 返回详细错误信息
- `bpf_filter_offline()` — 对离线pcap文件应用过滤并显示匹配包
- `bpf_filter_offline_with_stats()` — 统计总包数和匹配包数
- `bpf_print_common_rules()` — 打印常见BPF规则示例（协议/端口/主机/组合/进阶）
- `bpf_run_test_suite()` — 批量测试15种规则（tcp/udp/icmp/port/host/AND/OR/NOT/空/畸形）

#### 2.4 流量统计 (stats)

**统计策略：**
- 协议统计：固定数组（protocol_t枚举值作为索引）
- IP对统计：开放寻址哈希表（素数257桶，双向IP聚合）

**核心功能：**
- 按协议类型统计报文数、字节数、占比
- 按IP对统计流量（src_ip ^ dst_ip哈希，双向聚合）
- 每秒速率计算（packets/s, Mbps）
- 实时抓包统计（`stats_capture()`，每秒打印摘要）
- 离线文件统计（`stats_from_pcap()`）
- 带BPF过滤的离线统计（`stats_from_pcap_with_filter()`）
- 格式化报告输出（总计/协议/IP对/速率）

**IP对哈希表冲突处理：** 开放寻址线性探测，最大512个条目

#### 2.5 协议分析整合层 (protocol_analyze)

> 注：本模块包含Ethernet/IP/TCP/UDP低层解析功能，正式架构中由成员B负责。
> 在成员B代码就绪前提供完整的协议栈解析能力，使C的模块可独立运行测试。

**解析链路：**
```
原始数据包
  → parse_ethernet() → MAC地址 + EtherType(0x0800=IPv4, 0x86DD=IPv6, 0x0806=ARP)
  → parse_ipv4() → version/IHL/total_length/protocol/TTL/src_ip/dst_ip
  → parse_tcp() / parse_udp() / parse_icmp()
  → 应用层解析调度:
      TCP port 80/8080/8000/443 → parse_http()
      UDP/TCP port 53 → parse_dns()
  → 填充 ParsedPacket 结构体
```

**网络字节序处理：** 所有多字节字段手动从大端转换（`data[0]<<8 | data[1]` 等）

### 三、时间线对照

| 文档安排 | 实际完成 |
|---------|---------|
| 第1天: 调研DNS/HTTP格式，写parse_dns骨架 | ✅ dns_parser.c 完整实现 |
| 第2天: DNS压缩指针处理 | ✅ decode_dns_name() 支持压缩指针 |
| 第3天: parse_dns()完整版 | ✅ Header flags位解析 + Question域名解码 |
| 第4天: parse_http() | ✅ 请求行/状态行/Header Key:Value |
| 第5天: BPF过滤对接 | ✅ bpf_compile_and_set() |
| 第6天: 流量统计模块 | ✅ 协议/IP统计 + 每秒吞吐量 |
| 第7天: DNS/HTTP解析完善 | ✅ DNS应答段 + HTTP chunked编码 |
| 第8天: 流量统计可视化 | ✅ 格式化打印 + UI状态栏接口 |
| 第9天: BPF全覆盖测试 | ✅ bpf_run_test_suite() 15种规则 |
| 第10天: 统计准确性验证 | ✅ 与Wireshark对比接口 |
| 第11天: 性能测试协助 | ✅ stats_capture() 实时监控 |

### 四、文件清单

```
webdatecontrol/
├── include/
│   ├── common.h           ← [C] 全组共享数据结构
│   ├── dns_parser.h       ← [C] DNS解析接口
│   ├── http_parser.h      ← [C] HTTP解析接口
│   ├── bpf_filter.h       ← [C] BPF过滤接口
│   ├── stats.h            ← [C] 流量统计接口
│   ├── protocol_analyze.h ← [C] 协议分析整合层接口
│   ├── capture.h          ← [A] 抓包引擎接口
│   └── net_utils.h        ← [A] 工具函数接口
├── src/
│   ├── dns_parser.c       ← [C] DNS解析实现 (460行)
│   ├── http_parser.c      ← [C] HTTP解析实现 (340行)
│   ├── bpf_filter.c       ← [C] BPF过滤实现 (280行)
│   ├── stats.c            ← [C] 流量统计实现 (370行)
│   ├── protocol_analyze.c ← [C] 协议整合层实现 (380行)
│   ├── main.c             ← [A/C/D] 主程序 (菜单1-16)
│   ├── capture.c          ← [A] 抓包引擎实现
│   └── net_utils.c        ← [A] 工具函数实现
├── build.bat              ← 编译脚本 (含C的5个新文件)
└── README.md              ← 项目说明
```

### 五、编译验证

使用MSVC 19.39 + 桩pcap.h完成语法检查，**8个源文件全部编译通过**。

完整编译需要安装Npcap SDK：
1. 下载Npcap SDK解压到 `C:\Program Files\Npcap`
2. 运行 `build.bat` 编译

### 六、答辩准备 — 技术问题回答要点

**Q1: BPF过滤原理？**
> pcap_compile将文本规则编译为BPF虚拟机字节码，pcap_setfilter将字节码注入内核/驱动层。过滤在内核完成，只有匹配的包才传递到用户态，减少上下文切换开销。

**Q2: 流量统计的哈希表冲突怎么处理？**
> 使用开放寻址线性探测。哈希函数为 `(src_ip ^ dst_ip) % TABLE_SIZE`，双向IP聚合。冲突时从哈希位置开始线性向后探测空槽，最大512个条目。

**Q3: DNS域名压缩指针如何解码？**
> 当标签长度字节高2位为11(0xC0)时，剩余14位是指向DNS报文内偏移量的指针。从指针位置继续解码，支持链式跳转。设有安全计数器防止循环指针导致死循环。

**Q4: HTTP chunked编码如何解码？**
> chunked编码由多个chunk组成，每个chunk以十六进制chunk-size行开始，后跟CRLF和chunk-data。最后一个chunk的size为0。解码时逐个读取chunk-size，复制对应长度的data，跳过CRLF。
