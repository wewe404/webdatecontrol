/*
 * protocol.c — 协议解析实现
 * ============================
 *
 * 实现思路（逐层逐协议详解）：
 *
 * 整体架构 —— 分层解析器设计模式
 * ---------------------------------
 * 协议解析的核心问题：网络是严格分层的（OSI 模型），
 * 每一层从上一层 payload 中解析出自己的头部，然后将剩余载荷交给下一层。
 *
 * 实现为 parse_packet() 一个入口函数，内部按以下流水线工作：
 *
 *   raw_data
 *      │
 *      ▼  [L2] parse_ethernet()  ─── ether_type=0x0800
 *      ▼  [L3] parse_ipv4()     ─── protocol=6
 *      ▼  [L4] parse_tcp()      ─── dst_port=80
 *      ▼  [L7] parse_http()     ─── 应用层
 *
 * 每一层解析成功后都会在 pkt->proto_stack[] 中压入协议类型，
 * 同时返回下一层 payload 的指针和长度供继续解析。
 *
 * 为什么不用回调链模式？
 * 项目初期解析器数量有限，简单流水线比注册+回调更容易理解和调试。
 * 等到扩展解析器数量时（如 DHCP、TLS），再改为注册机制。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "protocol.h"
#include "net_utils.h"

/* ================================================================
 * 第2层：以太网
 * ================================================================
 *
 * 解析步骤：
 * 1. 检查长度 >= 14 字节（以太网头最小长度）
 * 2. 直接按 EthHeader 结构读取（#pragma pack 保证无填充）
 * 3. ntohs 转换 ether_type 到主机序
 * 4. 源/目的 MAC 保持原始字节序（人类读时才格式化）
 *
 * 边界情况：
 * - 带 VLAN tag (ether_type=0x8100)：实际 ether_type 在 tag 后面
 *   的 4 字节处，需要额外跳过
 * - 长度 < 14：不完整帧，无法解析
 */
int parse_ethernet(const unsigned char *data, unsigned int len,
                   EthHeader *eth)
{
    if (!data || !eth || len < sizeof(EthHeader))
        return -1;

    /* 直接拷贝 14 字节头部 */
    memcpy(eth->dst_mac, data, 6);
    memcpy(eth->src_mac, data + 6, 6);
    eth->ether_type = ntohs(*(unsigned short*)(data + 12));

    return sizeof(EthHeader);  /* 返回 14 */
}

/* ================================================================
 * 第3层：IPv4
 * ================================================================
 *
 * 解析步骤：
 * 1. 长度检查 >= 20 字节（IPv4 最小长度）
 * 2. 解析 ver_ihl：高 4 位应 == 4（IPv4），低 4 位是头部长度(×4 字节)
 * 3. 头部长度 = (ver_ihl & 0x0F) * 4，必须 >= 20
 * 4. total_length 用 ntohs 转换，必须 >= 头部长度
 * 5. 分片偏移 = ntohs(flags_frag) & 0x1FFF（低 13 位）
 * 6. 协议号直接读取 protocol 字段
 * 7. 校验和验证（可选但推荐）
 *
 * 为什么会分片？
 * - 网络设备（MTU）限制帧大小，IPv4 允许路由器分片
 * - Flags.MF=1 表示后面还有分片
 * - FragmentOffset=0 表示这是第一个分片
 * - 分片包只有第一个分片才有 TCP/UDP 头部！
 *   因此对非零偏移的分片包，我们不继续解析 L4
 */
int parse_ipv4(const unsigned char *data, unsigned int len,
               Ipv4Header *ipv4)
{
    if (!data || !ipv4 || len < 20)
        return -1;

    /* 直接拷贝 20 字节固定头部 */
    memcpy(ipv4, data, sizeof(Ipv4Header));

    /* 检查版本号 */
    unsigned char version = (ipv4->ver_ihl >> 4) & 0x0F;
    if (version != 4) return -1;

    /* 计算头部长度并验证 */
    unsigned char ihl = ipv4->ver_ihl & 0x0F;
    unsigned int header_len = ihl * 4;
    if (header_len < 20 || header_len > 60) return -1;

    /* 转换多字节字段到主机序 */
    ipv4->total_length   = ntohs(ipv4->total_length);
    ipv4->identification = ntohs(ipv4->identification);
    ipv4->flags_frag     = ntohs(ipv4->flags_frag);

    /* 总长度验证 */
    if (ipv4->total_length < header_len || ipv4->total_length > len)
        return -1;

    return (int)header_len;
}

int verify_ipv4_checksum(const Ipv4Header *ipv4)
{
    /*
     * IP 校验和只覆盖头部。
     * 计算时先将 checksum 字段当做 0，然后取反。
     * 验证时将整个头部求 checksum，结果应为 0xFFFF。
     *
     * 这里我们不修改原结构，而是拷贝一份然后清 checksum。
     */
    Ipv4Header tmp;
    memcpy(&tmp, ipv4, sizeof(Ipv4Header));
    tmp.checksum = 0;
    unsigned short calc = checksum((unsigned short*)&tmp, sizeof(Ipv4Header));
    return calc == 0xFFFF;
}

/* ================================================================
 * 第3层：IPv6
 * ================================================================
 *
 * 解析步骤：
 * 1. 长度检查 >= 40 字节
 * 2. 版本号在 ver_tc_flow 的高 4 位
 * 3. payload_length 从头部直接读取（不包含 40 字节固定头）
 * 4. next_header 和 hop_limit 直接读取
 * 5. 地址 128 位 = 16 字节，总共 32 字节源+目的
 *
 * IPv6 vs IPv4 关键差异：
 * - IPv6 没有校验和（依赖 L2 和 L4 校验）
 * - IPv6 路由器不分片（分片由端到端 Path MTU Discovery 完成）
 * - IPv6 地址为 128 位，简化了路由聚合
 * - IPv6 支持扩展头部链（next_header 链式指向）
 */
int parse_ipv6(const unsigned char *data, unsigned int len,
               Ipv6Header *ipv6)
{
    if (!data || !ipv6 || len < sizeof(Ipv6Header))
        return -1;

    memcpy(ipv6, data, sizeof(Ipv6Header));

    /* 检查版本号 */
    unsigned char version = (ipv6->ver_tc_flow >> 28) & 0x0F;
    if (version != 6) return -1;

    /* 转换多字节字段 */
    ipv6->payload_length = ntohs(ipv6->payload_length);

    if (ipv6->payload_length > 0 && (unsigned int)(40 + ipv6->payload_length) > len)
        return -1;

    return sizeof(Ipv6Header);  /* 返回 40 */
}

int ipv6_skip_ext_headers(const unsigned char *data, unsigned int len,
                          unsigned char next_header,
                          unsigned char *out_protocol)
{
    /*
     * IPv6 扩展头链解析：
     *
     * 每个扩展头的前两个字节：
     *   Byte 0: Next Header（下一个头部类型）
     *   Byte 1: Header Extension Length（有些扩展头的长度字段位置不同）
     *
     * 常见的扩展头（按 next_header 值）：
     *   0  — Hop-by-Hop Options: [next(1) + len(1) + options...]
     *   43 — Routing: [next(1) + len(1) + type(1) + segments(1) + ...]
     *   44 — Fragment: [next(1) + reserved(1) + offset(13) + M(1) + id(32)]
     *   60 — Destination Options: [next(1) + len(1) + options...]
     *
     * 注意 Fragment Header (44) 特殊：
     *   固定 8 字节，不是 len×8+8 的格式
     *   Fragment Offset > 0 的包不包含后续 L4 头部！
     *
     * 我们持续跳过直到 next_header 不再是扩展头类型。
     */
    unsigned int offset = 0;
    unsigned char nh = next_header;

    while (nh == 0 || nh == 43 || nh == 44 || nh == 60) {
        if (offset + 2 > len) return -1;

        if (nh == 44) {
            /* Fragment Header：固定 8 字节 */
            unsigned short frag_info = ntohs(*(unsigned short*)(data + offset + 2));
            unsigned short frag_offset = (frag_info >> 3) & 0x1FFF;
            nh = data[offset];

            if (frag_offset > 0) {
                /* 非首分片，没有 L4 头部 */
                *out_protocol = 0;  /* 无法解析上层协议 */
                return (int)offset + 8;
            }
            offset += 8;
        } else {
            /* 其他扩展头：标准 [next(1) + len(1)] 格式 */
            int ext_len = (data[offset + 1] + 1) * 8;
            nh = data[offset];
            offset += ext_len;
        }

        if (offset > len) return -1;
    }

    *out_protocol = nh;
    return (int)offset;
}

/* ================================================================
 * 第4层：TCP
 * ================================================================
 *
 * 解析步骤：
 * 1. 长度检查 >= 20 字节（TCP 最小头部）
 * 2. 拷贝 20 字节固定部分到 TcpHeader
 * 3. ntohs 转换端口、window、urgent_pointer
 * 4. ntohl 转换 seq 和 ack
 * 5. data_offset_flags 的高 4 位是 DataOffset（×4 = 头部长度）
 * 6. data_offset_flags 的低 12 位是标志位（9 位实际使用）
 *
 * TCP 三次握手演示：
 *   [SYN]     Seq=X                    → 客户端发起连接
 *   [SYN,ACK] Seq=Y, Ack=X+1          → 服务端确认并同步
 *   [ACK]     Seq=X+1, Ack=Y+1        → 客户端确认，连接建立
 * 
 * 这种由 ack=seq+1 的语义可用于后续会话流重组（进阶功能）。
 */
int parse_tcp(const unsigned char *data, unsigned int len,
              TcpHeader *tcp)
{
    if (!data || !tcp || len < sizeof(TcpHeader))
        return -1;

    memcpy(tcp, data, sizeof(TcpHeader));

    /* 转换多字节字段到主机序 */
    tcp->src_port      = ntohs(tcp->src_port);
    tcp->dst_port      = ntohs(tcp->dst_port);
    tcp->seq_number    = ntohl(tcp->seq_number);
    tcp->ack_number    = ntohl(tcp->ack_number);
    tcp->window        = ntohs(tcp->window);
    tcp->urgent_pointer= ntohs(tcp->urgent_pointer);
    /* data_offset_flags 和 checksum 保留网络序 */

    /* 验证头部长度 */
    int header_len = TCP_DATA_OFFSET(tcp) * 4;
    if (header_len < 20 || header_len > 60) return -1;
    if ((unsigned int)header_len > len) return -1;

    return header_len;
}

int tcp_payload_offset(const TcpHeader *tcp)
{
    return TCP_DATA_OFFSET(tcp) * 4;
}

const char* tcp_flags_to_str(unsigned short flags, char *buf, size_t size)
{
    /*
     * 将 TCP 标志位转换为人类可读字符串。
     * 类似 Wireshark 的 Flags [SYN, ACK] 格式。
     *
     * 标志位按 Wireshark 顺序排列：FIN → SYN → RST → PSH → ACK → URG
     */
    if (!buf || size < 1) return "";

    const char *names[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"};
    unsigned short bits[] = {
        TCP_FLAG_FIN, TCP_FLAG_SYN, TCP_FLAG_RST, TCP_FLAG_PSH,
        TCP_FLAG_ACK, TCP_FLAG_URG, TCP_FLAG_ECE, TCP_FLAG_CWR
    };
    int n = sizeof(bits) / sizeof(bits[0]);

    buf[0] = '\0';
    size_t pos = 0;
    int first = 1;

    for (int i = 0; i < n; i++) {
        if (flags & bits[i]) {
            int needed = (int)strlen(names[i]) + (first ? 0 : 1) + 1;
            if (pos + (size_t)needed > size) break;

            if (!first) {
                buf[pos++] = ',';
            }
            pos += sprintf(buf + pos, "%s", names[i]);
            first = 0;
        }
    }

    if (first) {
        /* 没有标志位，可能是 keep-alive 包或数据包 */
        sprintf(buf, ".");
    }

    return buf;
}

/* ================================================================
 * 第4层：UDP
 * ================================================================
 *
 * UDP 是"尽力而为"的传输层协议：
 * - 无连接：发完即走，不维护状态
 * - 无重传：丢包不重发（由应用层决定）
 * - 无排序：包可能乱序到达
 * - 头部极简：仅 8 字节
 *
 * 通常在 UDP 之上的协议：
 *   DNS(53)、DHCP(67/68)、NTP(123)、QUIC(443/80)、
 *   SNMP(161/162)、RTP（音视频流）
 *
 * UDP 校验和在 IPv4 中可选（为 0 时不校验），
 * 在 IPv6 中强制要求。
 */
int parse_udp(const unsigned char *data, unsigned int len,
              UdpHeader *udp)
{
    if (!data || !udp || len < sizeof(UdpHeader))
        return -1;

    memcpy(udp, data, sizeof(UdpHeader));

    udp->src_port = ntohs(udp->src_port);
    udp->dst_port = ntohs(udp->dst_port);
    udp->length   = ntohs(udp->length);

    if (udp->length < sizeof(UdpHeader) || udp->length > len)
        return -1;

    return sizeof(UdpHeader);
}

/* ================================================================
 * 第4层：ICMPv4
 * ================================================================
 *
 * ICMP 是 IP 的控制协议，用于报告错误和诊断。
 * 最常见的用途：ping（Type 8/0 的 Echo Request/Reply）。
 *
 * 处理 ICMP 时的一个常见陷阱：
 * ICMP 是不可达消息（Type 3）时，payload 包含
 * 原始 IP 头部 + 前 8 字节 L4 数据，用来告诉发送方
 * 哪个连接出了问题。解析时不能把这些数据当 L7 处理。
 */
int parse_icmp(const unsigned char *data, unsigned int len,
               IcmpHeader *icmp)
{
    if (!data || !icmp || len < sizeof(IcmpHeader))
        return -1;

    memcpy(icmp, data, sizeof(IcmpHeader));
    icmp->checksum = ntohs(icmp->checksum);

    return sizeof(IcmpHeader);
}

int parse_icmpv6(const unsigned char *data, unsigned int len,
                 Icmpv6Header *icmp6)
{
    if (!data || !icmp6 || len < sizeof(Icmpv6Header))
        return -1;

    memcpy(icmp6, data, sizeof(Icmpv6Header));
    icmp6->checksum = ntohs(icmp6->checksum);

    return sizeof(Icmpv6Header);
}

/* ================================================================
 * 第7层：DNS
 * ================================================================
 *
 * DNS 是一种"一言难尽"的协议……简单说：
 * - 头部固定 12 字节，之后跟着不定长的 Question/Answer 部分
 * - 域名用长度前缀编码（3www6google3com0 = www.google.com）
 * - 支持指针压缩（高 2 位 = 11 表示指向报文其他位置）
 *
 * 我们的实现原则：
 * 只解析头部（12 字节固定部分）+ 输出几个关键问答域的文本表示，
 * 不做完整 DNS 响应解析（那是一个几千行的工作）。
 */
int parse_dns(const unsigned char *data, unsigned int len,
              DnsHeader *dns)
{
    if (!data || !dns || len < sizeof(DnsHeader))
        return -1;

    memcpy(dns, data, sizeof(DnsHeader));

    dns->id      = ntohs(dns->id);
    dns->flags   = ntohs(dns->flags);
    dns->qdcount = ntohs(dns->qdcount);
    dns->ancount = ntohs(dns->ancount);
    dns->nscount = ntohs(dns->nscount);
    dns->arcount = ntohs(dns->arcount);

    return sizeof(DnsHeader);
}

int dns_decode_name(const unsigned char *msg, unsigned int msg_len,
                    unsigned int pos, char *out, unsigned int out_size)
{
    /*
     * DNS 域名解码（核心实现）
     *
     * 域名编码格式示例：
     *   "www.google.com" → [3]www[6]google[3]com[0]
     *   每个 label 以一个字节的长度前缀开始，以 0x00 结束
     *
     * 指针压缩格式：
     *   当遇到一个字节的高 2 位为 11 (0xC0) 时：
     *   这个字节和下一个字节组成一个 14 位的偏移量，指向报文中的某个位置
     *   → 去那个位置继续读取域名
     *
     * 例子：
     *   报文偏移 0x20 处: [3]www[6]google[3]com[0]
     *   报文偏移 0x40 处: [0xC0][0x20]       ← 指针指向 0x20
     *   解码 0x40 的结果也是 "www.google.com"
     */
    if (!msg || !out || pos >= msg_len || out_size < 1)
        return -1;

    unsigned int current_pos = pos;
    unsigned int out_pos = 0;
    int jumped = 0;      /* 是否已经跳过指针（指针只跳一次）*/
    unsigned int jump_target = 0;

    while (current_pos < msg_len) {
        unsigned char label_len = msg[current_pos];

        if (label_len == 0) {
            /* 域名结束 */
            current_pos++;
            break;
        }

        if ((label_len & 0xC0) == 0xC0) {
            /*
             * 指针压缩！
             * 高 2 位 = 11，低 14 位 = 偏移量
             * 例如 0xC0 0x20 → 偏移 0x0020
             */
            if (current_pos + 1 >= msg_len) return -1;

            unsigned short offset = ((label_len & 0x3F) << 8) | msg[current_pos + 1];

            if (!jumped) {
                /* 记录跳转前的位置（指针后 2 字节）*/
                jump_target = current_pos + 2;
                jumped = 1;
            }

            current_pos = offset;
            continue;
        }

        /* 正常 label */
        current_pos++;
        if (current_pos + label_len > msg_len) return -1;

        /* 拷贝 label 到输出缓冲区 */
        if (out_pos > 0 && out_pos < out_size - 1) {
            out[out_pos++] = '.';
        }
        for (int i = 0; i < label_len && out_pos < out_size - 1; i++) {
            out[out_pos++] = msg[current_pos++];
        }
    }

    out[out_pos] = '\0';

    /* 如果跳过指针，返回指针后的位置；否则返回结束位置 */
    return jumped ? (int)jump_target : (int)current_pos;
}

/* ================================================================
 * 第7层：HTTP
 * ================================================================
 *
 * HTTP 是文本协议，解析时关注第一行：
 *   请求: GET /index.html HTTP/1.1\r\n
 *   响应: HTTP/1.1 200 OK\r\n
 *
 * 我们的实现只解析第一行 + Host 头。
 * 完整 HTTP 解析需要处理：
 * - 多行头部
 * - Content-Length
 * - Chunked Transfer Encoding
 * - 连接复用（keep-alive）
 * - HTTP/2 帧
 * 这些是几十倍的工作量，超出了目前项目范围。
 */
int parse_http(const unsigned char *data, unsigned int len,
               HttpInfo *http)
{
    if (!data || !http || len < 4) return -1;

    /* 初始化为零 */
    memset(http, 0, sizeof(HttpInfo));

    /*
     * 判断是请求还是响应：
     * 请求的第一行以 METHOD 开头（大写英文字母）
     * 响应的第一行以 "HTTP/" 开头
     */
    int is_request = 1;
    if (len >= 5 && memcmp(data, "HTTP/", 5) == 0) {
        is_request = 0;
    }

    /* 复制前两个字节到临时缓冲区，确保 \0 结尾 */
    char *text = (char*)malloc(len + 1);
    if (!text) return -1;
    memcpy(text, data, len);
    text[len] = '\0';

    int header_end = -1;

    /* 找 \r\n\r\n（空行，标记头部结束）*/
    for (unsigned int i = 0; i + 3 < len; i++) {
        if (text[i] == '\r' && text[i+1] == '\n' &&
            text[i+2] == '\r' && text[i+3] == '\n') {
            header_end = (int)i + 4;
            break;
        }
    }

    if (header_end < 0) {
        free(text);
        return -1;
    }

    /* 解析第一行 */
    if (is_request) {
        http->is_request = 1;
        /* METHOD URI HTTP/Version */
        sscanf(text, "%15s %511s %15s",
               http->method, http->uri, http->version);
    } else {
        http->is_request = 0;
        /* HTTP/Version STATUS_CODE REASON */
        int matched = sscanf(text, "%15s %d %63[^\r\n]",
                             http->version, &http->status_code,
                             http->reason_phrase);
        if (matched < 2) {
            free(text);
            return -1;
        }
    }

    /* 查找 Host 头部 */
    const char *host_prefix = "Host: ";
    const char *host_lower = "host: ";
    const char *host_ptr = NULL;

    host_ptr = strstr(text, host_prefix);
    if (!host_ptr) host_ptr = strstr(text, host_lower);

    if (host_ptr) {
        host_ptr += 6;  /* 跳过 "Host: " */
        /* 跳过空格 */
        while (*host_ptr == ' ') host_ptr++;
        /* 拷贝到换行 */
        int hlen = 0;
        while (host_ptr[hlen] && host_ptr[hlen] != '\r' &&
               host_ptr[hlen] != '\n' && hlen < (int)sizeof(http->host) - 1) {
            hlen++;
        }
        memcpy(http->host, host_ptr, hlen);
        http->host[hlen] = '\0';
    }

    free(text);
    return header_end;
}

/* ================================================================
 * 统一的协议解析入口 —— 分层解析流水线
 * ================================================================
 *
 * 这是整个项目协议解析的"心脏"。
 * 从 L2 开始，每解析一层，就将剩余数据传给下一层解析器，
 * 直到无法继续解析或达到 L7 应用层。
 *
 * 实现为递归下降风格（其实是循环压栈），
 * 每层解析后 push_proto 入栈。
 *
 * 状态流转:
 *
 *   pkt->linktype == LINKTYPE_ETHERNET
 *     → parse_ethernet → ether_type 分流
 *         │
 *         ├── 0x0800 → parse_ipv4 → protocol 分流
 *         │               ├── 6  → parse_tcp → dport 分流
 *         │               │              ├── 80/8080 → parse_http
 *         │               │              ├── 443     → PROTO_TLS (暂不解析)
 *         │               │              └── other   → 停在 TCP
 *         │               ├── 17 → parse_udp → dport 分流
 *         │               │              ├── 53      → parse_dns
 *         │               │              └── other   → 停在 UDP
 *         │               └── 1  → parse_icmp → 停在 ICMP
 *         │
 *         ├── 0x86DD → parse_ipv6 → 跳过扩展头 → 同上 protocol 分流
 *         │
 *         └── 0x0806 → PROTO_ARP → 停在 ARP（暂不解析 ARP 细节）
 *
 * 错误处理原则：
 * - 任何一层解析失败，停止继续解析
 * - 无法识别的 ether_type/protocol/port 停在当前层
 * - 永远不会因为解析而崩溃（长度检查到位）
 */
int parse_packet(Packet *pkt)
{
    if (!pkt || !pkt->data || pkt->data_len < 14)
        return -1;

    /* 跳过已解析的包 */
    if (pkt->parsed)
        return 0;

    const unsigned char *payload = pkt->data;
    unsigned int remaining = pkt->data_len;

    /* ========== L2: 以太网 ========== */
    if (pkt->linktype != LINKTYPE_ETHERNET)
        return -1;

    EthHeader eth;
    int hlen = parse_ethernet(payload, remaining, &eth);
    if (hlen < 0) return -1;

    packet_push_proto(pkt, PROTO_ETHERNET);

    payload += hlen;
    remaining -= hlen;

    /* ========== L3: 根据 EtherType 分流 ========== */
    if (eth.ether_type == 0x0800) {
        /* ===== IPv4 ===== */
        Ipv4Header ipv4;
        hlen = parse_ipv4(payload, remaining, &ipv4);
        if (hlen < 0) return -1;

        packet_push_proto(pkt, PROTO_IPV4);

        /* 检查是否是分片包（非首分片没有 L4 头）*/
        unsigned short frag_offset = ipv4.flags_frag & 0x1FFF;
        unsigned short more_frags  = (ipv4.flags_frag >> 13) & 1;
        if (frag_offset > 0) {
            /* 非首分片，没有 L4 头部 */
            pkt->parsed = 1;
            return 0;
        }

        payload += hlen;
        remaining = ipv4.total_length - hlen;  /* 用 total_length 而非 data_len */

        /* ===== L4: 根据 protocol 分流 ===== */
        switch (ipv4.protocol) {
            case 1: {  /* ICMP */
                IcmpHeader icmp;
                hlen = parse_icmp(payload, remaining, &icmp);
                if (hlen < 0) return -1;
                packet_push_proto(pkt, PROTO_ICMP);
                break;
            }
            case 6: {  /* TCP */
                TcpHeader tcp;
                hlen = parse_tcp(payload, remaining, &tcp);
                if (hlen < 0) return -1;
                packet_push_proto(pkt, PROTO_TCP);

                /* L7: 检查端口 */
                const unsigned char *l7 = payload + hlen;
                unsigned int l7len = remaining - hlen;

                if ((tcp.dst_port == 80 || tcp.dst_port == 8080 ||
                     tcp.src_port == 80 || tcp.src_port == 8080) &&
                    l7len > 0) {
                    HttpInfo http;
                    if (parse_http(l7, l7len, &http) > 0) {
                        packet_push_proto(pkt, PROTO_HTTP);
                    }
                }
                /* TLS (443) 暂不解析，但可以标记 */
                else if (tcp.dst_port == 443 || tcp.src_port == 443) {
                    packet_push_proto(pkt, PROTO_TLS);
                }
                break;
            }
            case 17: {  /* UDP */
                UdpHeader udp;
                hlen = parse_udp(payload, remaining, &udp);
                if (hlen < 0) return -1;
                packet_push_proto(pkt, PROTO_UDP);

                /* L7: 检查端口 */
                const unsigned char *l7 = payload + hlen;
                unsigned int l7len = remaining - hlen;

                if ((udp.dst_port == 53 || udp.src_port == 53) && l7len >= 12) {
                    DnsHeader dns;
                    if (parse_dns(l7, l7len, &dns) > 0) {
                        packet_push_proto(pkt, PROTO_DNS);
                    }
                }
                break;
            }
            default:
                /* 其他协议（IGMP, GRE 等）停在 L3 */
                break;
        }

    } else if (eth.ether_type == 0x86DD) {
        /* ===== IPv6 ===== */
        Ipv6Header ipv6;
        hlen = parse_ipv6(payload, remaining, &ipv6);
        if (hlen < 0) return -1;

        packet_push_proto(pkt, PROTO_IPV6);

        payload += hlen;
        remaining -= hlen;

        /* 跳过扩展头链 */
        unsigned char real_protocol;
        int ext_len = ipv6_skip_ext_headers(payload, remaining,
                                            ipv6.next_header, &real_protocol);
        if (ext_len < 0) return -1;

        payload += ext_len;
        remaining -= ext_len;

        /* L4: 根据协议类型分流（和 IPv4 的 switch 逻辑一致）*/
        switch (real_protocol) {
            case 58: {  /* ICMPv6 */
                Icmpv6Header icmp6;
                hlen = parse_icmpv6(payload, remaining, &icmp6);
                if (hlen < 0) return -1;
                packet_push_proto(pkt, PROTO_ICMPV6);
                break;
            }
            case 6: {  /* TCP over IPv6 */
                TcpHeader tcp;
                hlen = parse_tcp(payload, remaining, &tcp);
                if (hlen < 0) return -1;
                packet_push_proto(pkt, PROTO_TCP);

                const unsigned char *l7 = payload + hlen;
                unsigned int l7len = remaining - hlen;
                if ((tcp.dst_port == 80 || tcp.dst_port == 8080 ||
                     tcp.src_port == 80 || tcp.src_port == 8080) && l7len > 0) {
                    HttpInfo http;
                    if (parse_http(l7, l7len, &http) > 0) {
                        packet_push_proto(pkt, PROTO_HTTP);
                    }
                } else if (tcp.dst_port == 443 || tcp.src_port == 443) {
                    packet_push_proto(pkt, PROTO_TLS);
                }
                break;
            }
            case 17: {  /* UDP over IPv6 */
                UdpHeader udp;
                hlen = parse_udp(payload, remaining, &udp);
                if (hlen < 0) return -1;
                packet_push_proto(pkt, PROTO_UDP);

                const unsigned char *l7 = payload + hlen;
                unsigned int l7len = remaining - hlen;
                if ((udp.dst_port == 53 || udp.src_port == 53) && l7len >= 12) {
                    DnsHeader dns;
                    if (parse_dns(l7, l7len, &dns) > 0) {
                        packet_push_proto(pkt, PROTO_DNS);
                    }
                }
                break;
            }
        }

    } else if (eth.ether_type == 0x0806) {
        /* ARP — 只入栈，不解析细节 */
        packet_push_proto(pkt, PROTO_ARP);
    }

    pkt->parsed = 1;
    return 0;
}

/* ================================================================
 * 协议字段打印输出
 * ================================================================
 */

void print_ethernet(const EthHeader *eth)
{
    char mac_buf[18];
    printf("  Ethernet:\n");
    printf("    Source MAC:      %s\n",
           mac_ntop(eth->src_mac, mac_buf, sizeof(mac_buf)));
    printf("    Destination MAC: %s\n",
           mac_ntop(eth->dst_mac, mac_buf, sizeof(mac_buf)));
    printf("    EtherType:       0x%04x", eth->ether_type);

    switch (eth->ether_type) {
        case 0x0800: printf(" (IPv4)"); break;
        case 0x86DD: printf(" (IPv6)"); break;
        case 0x0806: printf(" (ARP)");  break;
        case 0x8100: printf(" (VLAN)"); break;
    }
    printf("\n");
}

void print_ipv4(const Ipv4Header *ipv4)
{
    char src_str[16], dst_str[16];
    unsigned short flags = (ipv4->flags_frag >> 13) & 7;
    unsigned short frag_offset = ipv4->flags_frag & 0x1FFF;

    printf("  IPv4:\n");
    printf("    Source:           %s\n",
           ipv4_ntop(&ipv4->src_addr, src_str, sizeof(src_str)));
    printf("    Destination:      %s\n",
           ipv4_ntop(&ipv4->dst_addr, dst_str, sizeof(dst_str)));
    printf("    Version/IHL:      %d/%d (%d bytes)\n",
           (ipv4->ver_ihl >> 4) & 0x0F, ipv4->ver_ihl & 0x0F,
           (ipv4->ver_ihl & 0x0F) * 4);
    printf("    Total Length:     %d\n", ipv4->total_length);
    printf("    TTL:              %d\n", ipv4->ttl);
    printf("    Protocol:         %d", ipv4->protocol);

    switch (ipv4->protocol) {
        case 1:  printf(" (ICMP)"); break;
        case 6:  printf(" (TCP)");  break;
        case 17: printf(" (UDP)");  break;
        case 2:  printf(" (IGMP)"); break;
    }
    printf("\n");

    printf("    Flags:            ");
    if (flags & 0x02) printf("[DF] "); else printf("[ ] ");
    if (flags & 0x01) printf("[MF] "); else printf("[ ] ");
    printf("(fragment_offset=%d)\n", frag_offset);

    printf("    Checksum:         0x%04x", ntohs(ipv4->checksum));
    /* 验证校验和需要一份完整拷贝，这里省略 */
    printf("\n");
}

void print_ipv6(const Ipv6Header *ipv6)
{
    char src_str[48], dst_str[48];
    unsigned int tc = (ipv6->ver_tc_flow >> 20) & 0xFF;
    unsigned int flow = ipv6->ver_tc_flow & 0xFFFFF;

    printf("  IPv6:\n");
    printf("    Source:           %s\n",
           ipv6_ntop(&ipv6->src_addr, src_str, sizeof(src_str)));
    printf("    Destination:      %s\n",
           ipv6_ntop(&ipv6->dst_addr, dst_str, sizeof(dst_str)));
    printf("    Traffic Class:    %u\n", tc);
    printf("    Flow Label:       %u\n", flow);
    printf("    Payload Length:   %d\n", ipv6->payload_length);
    printf("    Next Header:      %d\n", ipv6->next_header);
    printf("    Hop Limit:        %d\n", ipv6->hop_limit);
}

void print_tcp(const TcpHeader *tcp, const unsigned char *raw_tcp,
               unsigned int tcp_len)
{
    char flags_str[32];

    printf("  TCP:\n");
    printf("    Source Port:      %d\n", tcp->src_port);
    printf("    Destination Port: %d\n", tcp->dst_port);
    printf("    Sequence Number:  %u (0x%08x)\n",
           tcp->seq_number, tcp->seq_number);
    printf("    Ack Number:       %u (0x%08x)\n",
           tcp->ack_number, tcp->ack_number);
    printf("    Flags:            [%s]\n",
           tcp_flags_to_str(TCP_FLAGS(tcp), flags_str, sizeof(flags_str)));
    printf("    Window:           %d\n", tcp->window);
    printf("    Data Offset:      %d (%d bytes)\n",
           TCP_DATA_OFFSET(tcp), TCP_DATA_OFFSET(tcp) * 4);
    printf("    Checksum:         0x%04x\n", ntohs(tcp->checksum));
    printf("    Urgent Pointer:   %d\n", tcp->urgent_pointer);
}

void print_udp(const UdpHeader *udp)
{
    printf("  UDP:\n");
    printf("    Source Port:      %d\n", udp->src_port);
    printf("    Destination Port: %d\n", udp->dst_port);
    printf("    Length:           %d\n", udp->length);
    printf("    Checksum:         0x%04x\n", ntohs(udp->checksum));
}

void print_icmp(const IcmpHeader *icmp)
{
    const char *type_str = "Unknown";
    switch (icmp->type) {
        case 0:  type_str = "Echo Reply";        break;
        case 3:  type_str = "Destination Unreachable"; break;
        case 5:  type_str = "Redirect";           break;
        case 8:  type_str = "Echo Request";       break;
        case 11: type_str = "Time Exceeded";      break;
    }
    printf("  ICMP:\n");
    printf("    Type:             %d (%s)\n", icmp->type, type_str);
    printf("    Code:             %d\n", icmp->code);
    printf("    Checksum:         0x%04x\n", icmp->checksum);
}

void print_icmpv6(const Icmpv6Header *icmp6)
{
    const char *type_str = "Unknown";
    switch (icmp6->type) {
        case 1:   type_str = "Destination Unreachable"; break;
        case 128: type_str = "Echo Request";            break;
        case 129: type_str = "Echo Reply";              break;
        case 133: type_str = "Router Solicitation";     break;
        case 134: type_str = "Router Advertisement";    break;
        case 135: type_str = "Neighbor Solicitation";   break;
        case 136: type_str = "Neighbor Advertisement";  break;
    }
    printf("  ICMPv6:\n");
    printf("    Type:             %d (%s)\n", icmp6->type, type_str);
    printf("    Code:             %d\n", icmp6->code);
    printf("    Checksum:         0x%04x\n", icmp6->checksum);
}

void print_dns(const DnsHeader *dns, const unsigned char *data,
               unsigned int len)
{
    printf("  DNS:\n");
    printf("    Transaction ID:   0x%04x\n", dns->id);
    printf("    Flags:            0x%04x", dns->flags);

    if (DNS_IS_RESPONSE(dns)) {
        printf(" (Response, RCODE=%d)", DNS_RCODE(dns));
    } else {
        printf(" (Query, Opcode=%d)", DNS_OPCODE(dns));
    }
    printf("\n");

    printf("    Questions:        %d\n", dns->qdcount);
    printf("    Answers:          %d\n", dns->ancount);
    printf("    Authority:        %d\n", dns->nscount);
    printf("    Additional:       %d\n", dns->arcount);

    /* 尝试解码第一个问题的域名 */
    if (dns->qdcount > 0 && data && len >= (unsigned int)sizeof(DnsHeader)) {
        char name[256];
        int ret = dns_decode_name(data, len, sizeof(DnsHeader),
                                   name, sizeof(name));
        if (ret > 0) {
            printf("    Query Name:       %s\n", name);
        }
    }
}

void print_http(const HttpInfo *http)
{
    printf("  HTTP:\n");
    if (http->is_request) {
        printf("    Request:          %s %s %s\n",
               http->method, http->uri, http->version);
    } else {
        printf("    Response:         %s %d %s\n",
               http->version, http->status_code, http->reason_phrase);
    }
    if (http->host[0]) {
        printf("    Host:             %s\n", http->host);
    }
    if (http->content_length > 0) {
        printf("    Content-Length:   %u\n", http->content_length);
    }
}

void print_packet_summary(const Packet *pkt)
{
    /*
     * 一行摘要格式（类似 tcpdump 输出）：
     *
     * 12:34:56.789012 IP 192.168.1.1.443 > 192.168.1.100.54321: Flags [P.], seq 1:100, ack 200, win 65535, length 99
     *
     * 这需要我们从 Packet 中提取信息——但当前 Packet 结构
     * 不保存解析后的具体协议字段（比如 TCP seq/ack）。
     *
     * 因此这里做一个轻量版本：显示时间戳 + 协议栈 + 长度。
     * 完整的详细摘要需要将解析后的协议信息存回 Packet。
     */
    struct tm tm_buf;
    char timebuf[32];
    time_t sec = (time_t)pkt->header.ts.tv_sec;
    localtime_s(&tm_buf, &sec);
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", &tm_buf);

    /* 构建协议栈描述字符串 */
    char proto_str[64] = "";
    for (int i = 0; i < pkt->proto_depth; i++) {
        if (i > 0) strcat(proto_str, "/");
        strcat(proto_str, protocol_name(pkt->proto_stack[i]));
    }

    printf("%s.%06lu %s [%s] len=%u",
           timebuf,
           (unsigned long)pkt->header.ts.tv_usec,
           proto_str,
           pkt->truncated ? "Truncated" : "OK",
           pkt->header.len);
}
