#ifndef PACKET_H
#define PACKET_H

/*
 * packet.h - 统一数据包结构体
 * ===========================
 * 这是 A/B/C/D 所有模块之间传递数据的"通用货币"。
 * 抓包引擎(A)产出 Packet -> 协议解析(B/C)填充协议栈 -> UI(D)展示
 */

#include <winsock2.h>
#include <pcap.h>

#ifdef _MSC_VER
#pragma warning(disable:4200)  /* 允许零长度数组（flexible array）*/
#endif

/* ========== 数据链路层类型 ========== */
typedef enum {
    LINKTYPE_NULL     = 0,
    LINKTYPE_ETHERNET = 1,   /* DLT_EN10MB，最常见 */
    LINKTYPE_RAW      = 12,  /* DLT_RAW */
    LINKTYPE_UNKNOWN  = -1
} LinkType;

/* ========== 协议类型枚举 ========== */
typedef enum {
    PROTO_UNKNOWN    = 0,
    PROTO_ETHERNET   = 1,
    PROTO_IPV4       = 2,
    PROTO_IPV6       = 3,
    PROTO_ARP        = 4,
    PROTO_TCP        = 5,
    PROTO_UDP        = 6,
    PROTO_ICMP       = 7,
    PROTO_ICMPV6     = 8,
    PROTO_DNS        = 9,
    PROTO_HTTP       = 10,
    PROTO_TLS        = 11
} ProtocolType;

/* ========== 协议名称映射 ========== */
#if defined(__GNUC__)
__attribute__((unused)) static __inline const char* protocol_name(ProtocolType t)
#elif defined(_MSC_VER)
#pragma warning(disable:4505)  /* 未使用的静态函数 */
static __inline const char* protocol_name(ProtocolType t)
#else
static __inline const char* protocol_name(ProtocolType t)
#endif
{
    switch (t) {
        case PROTO_UNKNOWN:  return "Unknown";
        case PROTO_ETHERNET: return "Ethernet";
        case PROTO_IPV4:     return "IPv4";
        case PROTO_IPV6:     return "IPv6";
        case PROTO_ARP:      return "ARP";
        case PROTO_TCP:      return "TCP";
        case PROTO_UDP:      return "UDP";
        case PROTO_ICMP:     return "ICMP";
        case PROTO_ICMPV6:   return "ICMPv6";
        case PROTO_DNS:      return "DNS";
        case PROTO_HTTP:     return "HTTP";
        case PROTO_TLS:      return "TLS";
        default:             return "???";
    }
}

/* ========== 统一数据包结构 ========== */
typedef struct {
    struct pcap_pkthdr header;       /* 时间戳 + 长度信息 */
    const u_char      *data;         /* 指向原始数据包数据的指针 */
    unsigned int       data_len;     /* 实际数据长度（<= header.caplen）*/
    LinkType           linktype;     /* 链路层类型 */

    /* 协议栈追踪 —— B/C 模块解析时从底向上填充 */
    ProtocolType       proto_stack[16];
    int                proto_depth;  /* 当前解析到的协议层数 */

    /* 状态标志 */
    unsigned int       parsed   : 1; /* 是否已完成协议解析 */
    unsigned int       filtered : 1; /* 是否被 BPF 过滤规则命中 */
    unsigned int       truncated: 1; /* 是否被 snaplen 截断 */
} Packet;

/* ========== Packet 辅助函数 ========== */

/* 重置 Packet（新建时调用）*/
static __inline void packet_reset(Packet *pkt) {
    if (!pkt) return;
    memset(&pkt->header, 0, sizeof(pkt->header));
    pkt->data       = NULL;
    pkt->data_len   = 0;
    pkt->linktype   = LINKTYPE_UNKNOWN;
    pkt->proto_depth= 0;
    pkt->parsed     = 0;
    pkt->filtered   = 0;
    pkt->truncated  = 0;
}

/* 向协议栈推入一层协议 */
static __inline void packet_push_proto(Packet *pkt, ProtocolType proto) {
    if (pkt->proto_depth < 16) {
        pkt->proto_stack[pkt->proto_depth++] = proto;
    }
}

/* 获取协议栈最顶层协议 */
static __inline ProtocolType packet_top_proto(const Packet *pkt) {
    return pkt->proto_depth > 0
        ? pkt->proto_stack[pkt->proto_depth - 1]
        : PROTO_UNKNOWN;
}

/* 检查协议栈中是否包含某协议 */
static __inline int packet_has_proto(const Packet *pkt, ProtocolType proto) {
    for (int i = 0; i < pkt->proto_depth; i++) {
        if (pkt->proto_stack[i] == proto)
            return 1;
    }
    return 0;
}

#endif /* PACKET_H */
