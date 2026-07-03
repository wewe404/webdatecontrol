#ifndef PROTOCOL_H
#define PROTOCOL_H

/*
 * protocol.h — 协议解析模块
 * ===========================
 *
 * 职责: 定义所有网络协议头的二进制结构，提供逐层解析函数
 *
 * 设计原则:
 * 1. 所有结构体用 #pragma pack(1) 紧凑对齐，避免编译器填充导致偏移错误
 * 2. 多字节字段用网络字节序（Big-Endian），解析时用 ntohs/ntohl 转主机序
 * 3. 解析函数只读不写输入缓冲区，线程安全
 * 4. 解析结果存入 Packet 的 proto_stack 供上层使用
 */

#include <winsock2.h>
#include <windows.h>
#include "packet.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * 第2层：以太网 (Ethernet II)
 * ================================================================
 * 以太网帧头 14 字节：
 *   +--------+--------+--------+--------+--------+--------+
 *   |        目的 MAC (6B)        |        源 MAC (6B)        |
 *   +--------+--------+--------+--------+--------+--------+
 *   | EtherType (2B)  |  Payload ...
 *   +--------+--------+
 *
 * EtherType 常见值:
 *   0x0800 — IPv4
 *   0x86DD — IPv6
 *   0x0806 — ARP
 *   0x8100 — VLAN (802.1Q)
 *
 * 实现要点：
 * - MAC 地址是 6 字节 OUI + NIC 格式
 * - EtherType 需要 ntohs 转换主机序再匹配
 * - 最小帧长 64 字节（含 FCS），最大 1518 字节
 * - FCS（帧尾 4 字节校验和）通常被网卡剥离，抓包时不可见
 */
#pragma pack(push, 1)
typedef struct {
    unsigned char  dst_mac[6];      /* 目的 MAC 地址 */
    unsigned char  src_mac[6];      /* 源 MAC 地址 */
    unsigned short ether_type;      /* EtherType（网络字节序）*/
} EthHeader;

/* 802.1Q VLAN 标签（在 EthHeader 之后，EtherType 之前）*/
typedef struct {
    unsigned short tpid;            /* Tag Protocol ID = 0x8100 */
    unsigned short tci;             /* Tag Control Info: PCP+DEI+VID */
} VlanTag;
#pragma pack(pop)

/*
 * 解析以太网帧头
 * 输入: data — 原始帧数据（至少 14 字节）
 *       len  — 数据长度
 * 输出: eth  — 解析后的以太网头部
 * 返回: 以太网头部长度（14），失败返回 -1
 */
int parse_ethernet(const unsigned char *data, unsigned int len,
                   EthHeader *eth);

/* ================================================================
 * 第3层：IPv4 (RFC 791)
 * ================================================================
 * IPv4 头部 20~60 字节（标准 20 字节 + 选项）：
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version|  IHL  |TypeOfService|          TotalLength           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Identification        |Flags|      FragmentOffset    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  TimeToLive |    Protocol    |         HeaderChecksum         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       SourceAddress                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    DestinationAddress                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options (if IHL > 5)                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Protocol 常见值:
 *   1  — ICMP
 *   6  — TCP
 *   17 — UDP
 *   2  — IGMP
 *
 * 实现要点：
 * - IHL 以 4 字节为单位，IHL = 5 表示标准 20 字节头部
 * - TotalLength 包含头部和数据总长
 * - 分片相关：Flags.MF=1 表示还有更多分片，FragmentOffset 以 8 字节为单位
 * - HeaderChecksum 需要验证（调用 net_utils 的 checksum）
 * - 选项字段需要跳过到 IHL×4 的位置
 */
#pragma pack(push, 1)
typedef struct {
    unsigned char  ver_ihl;         /* 版本(高4位) + 头部长度(低4位) */
    unsigned char  tos;             /* 服务类型 */
    unsigned short total_length;    /* 总长度 */
    unsigned short identification;  /* 标识符 */
    unsigned short flags_frag;      /* 标志(高3位) + 分片偏移(低13位) */
    unsigned char  ttl;             /* 生存时间 */
    unsigned char  protocol;        /* 上层协议 */
    unsigned short checksum;        /* 头部校验和 */
    struct in_addr src_addr;        /* 源 IP */
    struct in_addr dst_addr;        /* 目的 IP */
} Ipv4Header;

/* IPv4 选项最大空间 = 60 - 20 = 40 字节 */
#define IPV4_MAX_OPTIONS 40
#pragma pack(pop)

/* 解析 IPv4 头部 */
int parse_ipv4(const unsigned char *data, unsigned int len,
               Ipv4Header *ipv4);

/* 校验 IPv4 头部校验和（返回 1=校验和正确）*/
int verify_ipv4_checksum(const Ipv4Header *ipv4);

/* ================================================================
 * 第3层：IPv6 (RFC 8200)
 * ================================================================
 * IPv6 固定头部 40 字节：
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |Version| Traffic Class |           Flow Label                  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         Payload Length        |  Next Header  |   Hop Limit   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   +                         Source Address                        +
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   +                      Destination Address                      +
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Next Header 常见值:
 *   0   — Hop-by-Hop Options（逐跳选项，需跳过）
 *   6   — TCP
 *   17  — UDP
 *   58  — ICMPv6
 *   43  — Routing Header
 *   44  — Fragment Header
 *   60  — Destination Options
 *
 * 实现要点：
 * - IPv6 没有 checksum，不需要校验
 * - Next Header 可能有扩展链（需要逐个跳过）
 * - 地址是 128 位，格式化时用 IPv6 冒号十六进制表示法
 */
#pragma pack(push, 1)
typedef struct {
    unsigned int   ver_tc_flow;     /* 版本(4位) + 流量类(8位) + 流标签(20位) */
    unsigned short payload_length;  /* 载荷长度（不包含固定头部） */
    unsigned char  next_header;     /* 下一个头部类型 */
    unsigned char  hop_limit;       /* 跳数限制 */
    struct in6_addr src_addr;       /* 源 IPv6 地址 (16 字节) */
    struct in6_addr dst_addr;       /* 目的 IPv6 地址 (16 字节) */
} Ipv6Header;

/* IPv6 扩展头部通用结构 */
typedef struct {
    unsigned char next_header;
    unsigned char hdr_ext_len;     /* 扩展头长度（单位：8 字节，不含前 2 字节）*/
} Ipv6ExtHeader;
#pragma pack(pop)

/* 解析 IPv6 头部 */
int parse_ipv6(const unsigned char *data, unsigned int len,
               Ipv6Header *ipv6);

/*
 * 跳过 IPv6 扩展头链，找到真正的上层协议
 * 输入: data — IPv6 头部之后的 payload
 *       len  — payload 长度
 *       next_header — IPv6 头部的 next_header 字段
 * 输出: out_protocol — 最终的上层协议号
 * 返回: 扩展头链总长度（从 IPv6 payload 起始到上层协议头的偏移）
 */
int ipv6_skip_ext_headers(const unsigned char *data, unsigned int len,
                          unsigned char next_header,
                          unsigned char *out_protocol);

/* ================================================================
 * 第4层：TCP (RFC 793)
 * ================================================================
 * TCP 头部 20~60 字节：
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Source Port          |        Destination Port       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Sequence Number                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     Acknowledgment Number                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Data| Reserved|C|E|U|A|P|R|S|F|            Window            |
 * |Offset|  (3bit)|W|C|R|C|S|S|Y|I|                            |
 * |      |        |R|E|G|K|H|T|N|N|                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Checksum            |         Urgent Pointer        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options (if DataOffset > 5)               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * TCP Flags 各比特含义:
 *   URG — 紧急指针有效
 *   ACK — 确认号有效
 *   PSH — 推送（接收方应立即交给应用层）
 *   RST — 重置连接
 *   SYN — 同步序号（连接建立）
 *   FIN — 结束连接
 *
 * 实现要点：
 * - DataOffset 以 4 字节为单位，最小 5（20 字节），最大 15（60 字节）
 * - Sequence Number 和 Acknowledgment Number 用 32 位无符号整数
 *    用于 TCP 会话重组中的乱序重排
 * - Checksum 需要计算伪头部 + TCP 段
 * - Options 常见类型：MSS(2)、Window Scale(3)、SACK(5)、Timestamp(8)
 */
#pragma pack(push, 1)
typedef struct {
    unsigned short src_port;         /* 源端口 */
    unsigned short dst_port;         /* 目的端口 */
    unsigned int   seq_number;       /* 序列号 */
    unsigned int   ack_number;       /* 确认号 */
    unsigned short data_offset_flags;/* 数据偏移(4位) + 保留(3位) + 标志(9位) */
    unsigned short window;           /* 窗口大小 */
    unsigned short checksum;         /* 校验和 */
    unsigned short urgent_pointer;   /* 紧急指针 */
    /* 选项和填充紧随其后 */
} TcpHeader;

/* TCP 数据偏移（以 4 字节为单位）的提取与设置宏 */
#define TCP_DATA_OFFSET(tcph)  (((tcph)->data_offset_flags >> 12) & 0x0F)
#define TCP_FLAGS(tcph)        ((tcph)->data_offset_flags & 0x01FF)

/* TCP 标志位掩码 */
#define TCP_FLAG_FIN  0x001
#define TCP_FLAG_SYN  0x002
#define TCP_FLAG_RST  0x004
#define TCP_FLAG_PSH  0x008
#define TCP_FLAG_ACK  0x010
#define TCP_FLAG_URG  0x020
#define TCP_FLAG_ECE  0x040
#define TCP_FLAG_CWR  0x080
#define TCP_FLAG_NS   0x100

/* 将 TCP flags 转换为可读字符串（如 "SYN,ACK"）*/
const char* tcp_flags_to_str(unsigned short flags, char *buf, size_t size);
#pragma pack(pop)

/* 解析 TCP 头部 */
int parse_tcp(const unsigned char *data, unsigned int len,
              TcpHeader *tcp);

/* 计算 TCP 数据部分偏移（跳过头部+选项）*/
int tcp_payload_offset(const TcpHeader *tcp);

/* ================================================================
 * 第4层：UDP (RFC 768)
 * ================================================================
 * UDP 头部 8 字节（无选项、极简设计）：
 *   +--------+--------+--------+--------+
 *   |     Source Port    |   Destination Port  |
 *   +--------+--------+--------+--------+
 *   |        Length      |       Checksum     |
 *   +--------+--------+--------+--------+
 *
 * 实现要点：
 * - UDP 是尽力而为、无连接的传输层协议
 * - Length 包含头部（8 字节）+ 数据
 * - Checksum 可选（IPv4 中为 0 表示不校验，IPv6 中强制）
 * - 端口号用于区分上层应用：
 *     53  — DNS
 *     67/68 — DHCP
 *     443 — QUIC/HTTPS
 */
#pragma pack(push, 1)
typedef struct {
    unsigned short src_port;        /* 源端口 */
    unsigned short dst_port;        /* 目的端口 */
    unsigned short length;          /* UDP 数据报长度（含头部）*/
    unsigned short checksum;        /* 校验和（可选）*/
} UdpHeader;
#pragma pack(pop)

/* 解析 UDP 头部 */
int parse_udp(const unsigned char *data, unsigned int len,
              UdpHeader *udp);

/* ================================================================
 * 第4层：ICMPv4 (RFC 792)
 * ================================================================
 * ICMP 头部 4 字节 + 可变内容：
 *   +--------+--------+--------+--------+
 *   |   Type    |   Code    |   Checksum  |
 *   +--------+--------+--------+--------+
 *   |       Identifier      |  Sequence Number   |  (Echo 类型)
 *   +--------+--------+--------+--------+
 *
 * 常见 Type/Code:
 *   0/0  — Echo Reply (ping 响应)
 *   3/0  — Destination Unreachable (网络不可达)
 *   3/1  — Destination Unreachable (主机不可达)
 *   3/3  — Destination Unreachable (端口不可达)
 *   8/0  — Echo Request (ping 请求)
 *   11/0 — Time Exceeded (TTL 超时)
 *
 * 实现要点：
 * - Checksum 覆盖整个 ICMP 报文（和 IP 不同，不是只校验头部）
 * - Type 决定后续内容格式：
 *     0/8: Identifier + Sequence Number
 *     3/11: 原始 IP 头部 + 前 8 字节数据
 *     5: 网关 IP 地址
 */
#pragma pack(push, 1)
typedef struct {
    unsigned char  type;            /* 消息类型 */
    unsigned char  code;            /* 代码 */
    unsigned short checksum;        /* 校验和（覆盖整个 ICMP 报文）*/
    /* 后续内容取决于 type/code */
} IcmpHeader;

/* ICMP Echo (ping) 请求/回复 */
typedef struct {
    unsigned short identifier;      /* 标识符 */
    unsigned short sequence;        /* 序列号 */
} IcmpEcho;

/* ICMP 不可达/超时 — 后面跟着引发错误的原始 IP 头+前 8 字节 */
typedef struct {
    unsigned short unused;
    unsigned short next_hop_mtu;    /* 用于 Type=3/Code=4 (Frag Needed) */
} IcmpUnreach;
#pragma pack(pop)

/* 解析 ICMPv4 */
int parse_icmp(const unsigned char *data, unsigned int len,
               IcmpHeader *icmp);

/* ================================================================
 * ICMPv6 (RFC 4443)
 * ================================================================
 * 头部结构和 ICMPv4 一样（Type + Code + Checksum），
 * 但 Type/Code 含义不同：
 *   1/0 — Destination Unreachable
 *   128/0 — Echo Request
 *   129/0 — Echo Reply
 *   133~137 — Neighbor Discovery (NDP)
 */
#pragma pack(push, 1)
typedef struct {
    unsigned char  type;
    unsigned char  code;
    unsigned short checksum;
} Icmpv6Header;
#pragma pack(pop)

int parse_icmpv6(const unsigned char *data, unsigned int len,
                 Icmpv6Header *icmp6);

/* ================================================================
 * 第7层：DNS (RFC 1035)
 * ================================================================
 * DNS 头部 12 字节：
 *   +--------+--------+--------+--------+
 *   |            Transaction ID         |
 *   +--------+--------+--------+--------+
 *   |  Flags (16 bit)                   |
 *   +--------+--------+--------+--------+
 *   |           Questions               |
 *   +--------+--------+--------+--------+
 *   |            Answer RRs             |
 *   +--------+--------+--------+--------+
 *   |            Authority RRs           |
 *   +--------+--------+--------+--------+
 *   |            Additional RRs         |
 *   +--------+--------+--------+--------+
 *   |  Question Section (variable)       |
 *   +--------+--------+--------+--------+
 *   |  Answer Section (variable)         |
 *   +--------+--------+--------+--------+
 *
 * DNS Flags:
 *   Bit 15: QR (0=查询, 1=响应)
 *   Bit 12~14: Opcode (0=标准查询)
 *   Bit 11: AA (权威应答)
 *   Bit 10: TC (截断)
 *   Bit 9:  RD (递归期望)
 *   Bit 8:  RA (递归可用)
 *   Bits 7~4: RCODE (返回码: 0=无错误, 3=域名不存在)
 *
 * 实现要点：
 * - 域名采用长度前缀编码（如 3www6google3com0）
 * - 支持指针压缩（高 2 位为 11 时表示指向报文中的某个偏移）
 * - 资源记录类型：A(1)、AAAA(28)、CNAME(5)、MX(15)、TXT(16)
 */
#pragma pack(push, 1)
typedef struct {
    unsigned short id;              /* 事务 ID */
    unsigned short flags;           /* 标志位 */
    unsigned short qdcount;         /* 问题数 */
    unsigned short ancount;         /* 回答数 */
    unsigned short nscount;         /* 权威数 */
    unsigned short arcount;         /* 附加数 */
} DnsHeader;

/* DNS 查询标志位快捷宏 */
#define DNS_QR(hdr)      (((hdr)->flags >> 15) & 1)
#define DNS_OPCODE(hdr)  (((hdr)->flags >> 11) & 0x0F)
#define DNS_RCODE(hdr)   ((hdr)->flags & 0x0F)
#define DNS_IS_RESPONSE(hdr) (DNS_QR(hdr) == 1)
#pragma pack(pop)

/*
 * 解析 DNS 报文
 * 不同于其他协议（一次解析一层头），DNS 解析比较复杂：
 * - 我们需要解析不定长的域名（带指针压缩）
 * - 我们需要遍历 Question 和 Answer 部分
 * - 这里我们只做轻量解析：提取 ID、QR、RCODE、问题数量和回答数量
 * - 完整 DNS 解析器代码量较大（需要名称解压缩 + RR 类型解析），
 *   属于进阶需求
 * 返回 DNS 头部长度（12）或 -1
 */
int parse_dns(const unsigned char *data, unsigned int len,
              DnsHeader *dns);

/*
 * 解码 DNS 域名（支持指针压缩）
 * 从 msg 偏移 pos 处开始读取域名，解码到 out 中
 * 返回解析后的偏移（跳过了整个域名），-1 表示错误
 *
 * 指针压缩原理：
 *   域名中的每个 label 如果高 2 位为 11，则表示这是指针指向：
 *   (byte & 0xC0) == 0xC0 → 取低 14 位的偏移，跳到该处继续读取
 *   否则正常读取长度前缀 label
 */
int dns_decode_name(const unsigned char *msg, unsigned int msg_len,
                    unsigned int pos, char *out, unsigned int out_size);

/* ================================================================
 * 第7层：HTTP (RFC 7230)
 * ================================================================
 * HTTP 是基于 TCP 的文本协议，无固定头部结构。
 * 请求格式：
 *   METHOD URI HTTP/1.1\r\n
 *   Header1: value1\r\n
 *   Header2: value2\r\n
 *   \r\n
 *   Body
 *
 * 响应格式：
 *   HTTP/1.1 STATUS_CODE REASON_PHRASE\r\n
 *   Header1: value1\r\n
 *   \r\n
 *   Body
 *
 * 实现要点：
 * - 基于文本行解析，\r\n 分隔
 * - 请求行和状态行各占第一行
 * - Content-Length 或 Transfer-Encoding: chunked 决定 body 边界
 * - HTTP/2 是二进制协议，不在此范围
 * - 这里做轻量解析：识别方法/URI/状态码，不做完整解码
 */
typedef struct {
    /* 请求相关 */
    char  method[16];        /* GET / POST / PUT / DELETE ... */
    char  uri[512];          /* 请求 URI */
    int   is_request;        /* 1=请求, 0=响应 */

    /* 响应相关 */
    int   status_code;       /* 200 / 404 / 500 ... */
    char  reason_phrase[64]; /* OK / Not Found ... */

    char  version[16];       /* HTTP/1.0 / HTTP/1.1 */
    char  host[256];         /* Host 头部 */
    unsigned int content_length; /* Content-Length（如果存在）*/
} HttpInfo;

/*
 * 轻量级 HTTP 解析
 * 只解析第一行（请求行/状态行）+ Host 头
 * 返回 HTTP 头部总长度（包括 \r\n\r\n），或 -1
 *
 * 注意：HTTP 可能跨多个 TCP 段，这里假设 payload 中包含完整头部
 */
int parse_http(const unsigned char *data, unsigned int len,
               HttpInfo *http);

/* ================================================================
 * 统一的协议解析入口
 * ================================================================
 * 这个函数是整个协议解析模块的"总调度器"。
 * 它接收一个 Packet（只填充了原始数据和链路层信息），
 * 从 L2 开始逐层向上解析，填充 proto_stack。
 * 
 * 调用流程：
 *   Packet 进入 → parse_ethernet → parse_ipv4/parse_ipv6
 *                                     ↓
 *                              parse_tcp/parse_udp/parse_icmp
 *                                     ↓
 *                              parse_dns/parse_http
 *                                     ↓
 *                        proto_stack 填充完毕
 */

/*
 * 解析一个完整的数据包（从 L2 到 L7）
 * 输入/输出: pkt — 需要包含原始数据和链路类型，解析后 proto_stack 被填充
 * 返回: 0=成功, -1=解析失败
 *
 * 注意：此函数会修改 pkt->proto_stack，但不会修改 pkt->data
 */
int parse_packet(Packet *pkt);

/* ================================================================
 * 协议字段打印输出（用于 -v 详细模式）
 * ================================================================
 * 将解析后的协议头部打印为可读文本，
 * 类似 tcpdump -v 的详细输出格式
 */

/* 打印以太网头部信息 */
void print_ethernet(const EthHeader *eth);

/* 打印 IPv4 头部信息 */
void print_ipv4(const Ipv4Header *ipv4);

/* 打印 IPv6 头部信息 */
void print_ipv6(const Ipv6Header *ipv6);

/* 打印 TCP 头部信息（含 flags 字符串）*/
void print_tcp(const TcpHeader *tcp, const unsigned char *raw_tcp,
               unsigned int tcp_len);

/* 打印 UDP 头部信息 */
void print_udp(const UdpHeader *udp);

/* 打印 ICMP 头部信息 */
void print_icmp(const IcmpHeader *icmp);

/* 打印 ICMPv6 头部信息 */
void print_icmpv6(const Icmpv6Header *icmp6);

/* 打印 DNS 信息 */
void print_dns(const DnsHeader *dns, const unsigned char *data,
               unsigned int len);

/* 打印 HTTP 信息 */
void print_http(const HttpInfo *http);

/* 打印协议栈摘要行（类似 tcpdump 一行模式）*/
void print_packet_summary(const Packet *pkt);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_H */
