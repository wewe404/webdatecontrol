# 成员 D（组长）任务报告

## 一、基本信息

| 项目     | 内容                                                                 |
| -------- | -------------------------------------------------------------------- |
| 课题     | 题目07：网络数据包捕获与协议解析工具                                 |
| 角色     | D（组长）                                                            |
| 核心职责 | ncurses 终端界面 + TCP 流重组 + 主控循环整合 + 答辩组织              |
| 代码模块 | `ncurses_ui.c`、`tcp_reassembly.c/h`、`main.c`（整合）               |
| 代码统计 | 新增约 **840 行**（ncurses_ui.c 513 行 + tcp_reassembly.c/h 327 行） |

---

## 二、实现模块

### 2.1 ncurses 终端界面（进阶 C，+5 分）

**文件:** `src/ncurses_ui.c`（513 行）

**架构设计：**

使用 **shell-out 模式**（业界 TUI 标准做法，vim/less 同款）：

```
主循环 (timeout=-1 阻塞)
  └→ 菜单绘制 (draw_title / draw_menu / draw_helpbar)
  └→ getch() 等待按键
       ├→ 方向键：移动高亮
       ├→ 数字/符号：快捷键（1-9, 0, !@#$%^&）
       ├→ q/ESC：确认退出
       └→ Enter/空格：
            └→ shell_out(func, title)
                  ├→ def_prog_mode + endwin       ← 退出 curses
                  ├→ SetConsoleMode(行缓冲)        ← 保证 scanf 可用
                  ├→ printf 输出 + 函数交互
                  ├→ _getch() 等待按键             ← 用户查看终端输出
                  ├→ flushinp + reset_prog_mode    ← 恢复 curses
                  └→ 回到菜单循环
```

**关键特性：**

| 特性       | 实现方式                                                            |
| ---------- | ------------------------------------------------------------------- |
| 彩色菜单   | `init_pair` 定义 6 组颜色对：标题蓝底白字、高亮青底黑字、分类黄字等 |
| 键盘导航   | 方向键 `KEY_UP`/`KEY_DOWN` 移动 + 17 个快捷键（1-9, 0, !@#$%^&）    |
| 无闪烁     | `timeout(-1)` 阻塞式 getch，只在有按键时重绘                        |
| 无残留染色 | `draw_item()` 每行先用正常颜色清空整行，再绘制                      |
| 行缓冲还原 | `endwin()` 后用 `SetConsoleMode(ENABLE_LINE_INPUT \| ...)`          |
| 中文字符   | 使用 `\uXXXX` Unicode 转义码，彻底避免编码问题                      |
| 17 项功能  | 原菜单 16 项 + 新增 TCP 流重组入口                                  |

**界面布局：**

```
┌───────────────────────────────────────────────────────────┐
│          网络数据包捕获与协议解析工具                      │
│  -- 抓包与文件操作 --                                     │
│   1. 查看网卡列表                        ← 高亮项         │
│   2. 连续抓包并显示统计信息                               │
│   ...                                                     │
│  -------------------------------------------------------  │
│  -- 协议解析与统计 --                                     │
│   9. 协议分析                                             │
│   ...                                                     │
│  17. TCP 流重组 + HTTP 提取（进阶）   ← 新增              │
│                                                           │
│ 状态栏: 就绪                                              │
│ 方向键移动 | Enter选择 | 1-9,0快捷键 | q退出              │
└───────────────────────────────────────────────────────────┘
```

**版本迭代记录：**

| 版本 | 问题                                   | 解决方案                      |
| ---- | -------------------------------------- | ----------------------------- |
| v1   | `timeout(0)` 菜单疯狂闪烁              | → `timeout(-1)` 阻塞等待      |
| v2   | `_dup2` 输出捕获与 curses 冲突         | → shell-out 模式，不捕获输出  |
| v3   | 高亮切换后残留染色空白                 | → 每行先整行清空再绘制        |
| v4   | `FlushConsoleInputBuffer` 导致无法输入 | → 删除，改用 `SetConsoleMode` |
| v5   | 中文编码导致显示乱码                   | → `\uXXXX` 转义码，零编码依赖 |

### 2.2 TCP 流重组 + HTTP 提取（进阶 A，+5 分）

**文件:** `include/tcp_reassembly.h`（82 行）、`src/tcp_reassembly.c`（327 行）

**算法流程：**

```
读取 pcap 文件
  │
  ├→ pcap_next_ex 逐包读取
  │     │
  │     └→ analyze_packet 解析各层协议
  │           │
  │           └→ tr_feed(parsed_packet)
  │                 │
  │                 ├→ 检查是否为 TCP 包
  │                 ├→ 按 4 元组 (src_ip, dst_ip, src_port, dst_port) 查找流
  │                 ├→ 未找到 → 新建流，初始化半流
  │                 ├→ 按序列号计算相对偏移
  │                 │     rel = seq - base_seq
  │                 │     └→ 处理重叠 / 乱序
  │                 ├→ 扩展缓冲区 → memcpy 复制载荷
  │                 └→ 检查双向 FIN → 标记完成
  │
  ├→ 全部包处理完毕 → tr_flush_all
  │
  └→ tr_write_http_pairs
        │
        ├→ 遍历已完成流
        ├→ find_http_pair 搜索 "GET/POST" 和 "HTTP/" 边界
        ├→ 找到 → 写入 req_NNN.txt / resp_NNN.txt
        └→ 返回 HTTP 会话数
```

**关键数据结构：**

```
tcp_stream_t:
  ├── src_ip, dst_ip          ← 4 元组
  ├── src_port, dst_port
  ├── half[0] (客户端方向)    ← 半流
  │     ├── data[]            ← 已排序的载荷缓冲区
  │     ├── data_len          ← 已接收长度
  │     ├── next_seq          ← 期望下一序列号（相对）
  │     ├── has_syn / has_fin
  │     └── base_seq          ← 首个 SYN 的绝对序列号
  ├── half[1] (服务端方向)    ← 同 client 结构
  └── complete                ← 双向 FIN 标记

TcpReassembler:
  ├── streams[512]            ← 最多同时跟踪 512 流
  ├── stream_count
  └── total_bytes_reassembled
```

### 2.3 IPv6 解析补充

**文件:** `include/ipv6_parser.h`（14 行）、`src/ipv6_parser.c`（33 行）

解析 IPv6 固定头（40 字节，RFC 2460），提取 `next_header`（TCP=6/UDP=17/ICMPv6=58），在 `protocol_analyze.c` 中接续到 TCP/UDP/ICMP 解析器。

---

## 三、AI 辅助对话记录

### 对话 1：ncurses shell-out vs output-capture 方案选型

**问题：** curses 模式下如何在不退出的情况下显示函数输出？
**AI 建议：** 提供了两种方案对比——`_dup2` 重定向 stdout vs `def_prog_mode/endwin` shell-out。分析了各自优缺点后选择 shell-out，因为兼容所有现有 `printf/scanf` 代码，无需改造。
**截图：** `docs/ai_dialogue_01.png`
**解决：** `shell_out()` 函数仅 10 行，统一管理 curses 状态切换。

### 对话 2：TCP 流重组 seq/ack 排序算法

**问题：** 如何按 TCP 序列号重组乱序到达的数据包？
**AI 建议：** 解释了相对偏移量算法——记录 `base_seq`（SYN 的序列号），后续包计算 `rel = seq - base_seq`，按 `rel` 写入缓冲区。同时给出重叠处理逻辑（`rel < next_seq` 时跳过已接收部分）。
**截图：** `docs/ai_dialogue_02.png`
**关键代码：** `half_feed()` 中的偏移量计算和边界处理。

### 对话 3：Windows 批处理文件编码问题

**问题：** `build.bat` 中的中文路径在 cmd.exe/PowerShell 下频繁报 "path not found"。
**AI 建议：** 分析了 GBK vs UTF-8 编码冲突——`chcp 65001` 设置 UTF-8 代码页，但文件以 GBK 保存，导致路径字节被错误解释。解决方案是统一使用 UTF-8 编码（无 BOM）。
**截图：** `docs/ai_dialogue_03.png`

---

## 四、验收清单

### 基础功能检查

| #   | 功能                     | 状态 | 说明                                                    |
| --- | ------------------------ | ---- | ------------------------------------------------------- |
| 1   | 抓包引擎（混杂模式）     | ✅   | `pcap_open_live(..., 1, ...)`                           |
| 2   | 协议解析（含 IPv6）      | ✅   | Eth/IPv4/IPv6/TCP/UDP/ICMP/DNS/HTTP，新增 `ipv6_parser` |
| 3   | BPF 过滤                 | ✅   | `bpf_compile_and_set` + 离线/在线过滤                   |
| 4   | 流量统计（实时 PPS/BPS） | ✅   | `stats_t` 含 `current_pps/avg_mbps`                     |
| 5   | PCAP 读写                | ✅   | 保存/回放完整                                           |

### 进阶功能检查

| #   | 功能            | 状态 | 说明                                        |
| --- | --------------- | ---- | ------------------------------------------- |
| A   | TCP 流重组      | ✅   | 512 流并发跟踪，支持乱序，HTTP 提取至文件   |
| C   | ncurses 终端 UI | ✅   | 17 项彩色菜单，键盘导航，shell-out 可靠运行 |

### 已知限制

- IPv6 扩展头（Hop-by-Hop、Routing 等）未完整解析，仅跳过
- TCP 流重组只处理基本 SYN/数据/FIN 流程，不支持窗口缩放和选择性确认（SACK）
- ncurses UI 输出为终端文本模式，非实时更新的数据包列表（简化 shell-out 方案）

---

## 五、贡献总结

| 贡献项                     | 行数        | 占比    |
| -------------------------- | ----------- | ------- |
| `ncurses_ui.c`             | 513 行      | 12%     |
| `tcp_reassembly.c`         | 327 行      | 8%      |
| `ipv6_parser.c/h`          | 47 行       | 1%      |
| `include/tcp_reassembly.h` | 82 行       | 2%      |
| **D 成员小计**             | **~969 行** | **23%** |
| 项目总计                   | ~4136 行    | 100%    |

---

_报告生成日期：2026-07-09_
_D（组长）—— 网络数据包捕获与协议解析工具 _
