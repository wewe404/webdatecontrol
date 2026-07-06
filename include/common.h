/**
 * common.h - 全组统一数据结构定义
 *
 * 由四人在第一天协商确定，后续所有模块基于此结构对接。
 * 成员C负责维护应用层协议枚举和ParsedPacket的app层字段。
 *
 * 对应文档：第五章 模块间数据接口定义
 */

#ifndef COMMON_H
#define COMMON_H

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <sys/time.h>
#endif

#include <stdint.h>

/* ---- 常量定义 ---- */
#define MAC_ADDR_LEN    6       /* MAC地址长度（字节） */
#define IP4_ADDR_LEN    4       /* IPv4地址长度（字节） */
#define IP6_ADDR_LEN    16      /* IPv6地址长度（字节） */
#define MAX_PAYLOAD     65535   /* 最大载荷长度 */
#define MAX_DNS_NAME    256     /* DNS域名最大长度 */
#define MAX_HTTP_HEADER 8192    /* HTTP头部最大长度 */

/* ---- 协议类型枚举 ---- */
typedef enum {
    PROTO_UNKNOWN = 0,
    PROTO_IPV4,
    PROTO_IPV6,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
    PROTO_DNS,
    PROTO_HTTP_REQUEST,
    PROTO_HTTP_RESPONSE,
    PROTO_ARP
} protocol_t;

/* ---- Ethernet 帧头 (IEEE 802.3) ---- */
typedef struct {
    uint8_t  dst_mac[MAC_ADDR_LEN];   /* 目的MAC地址 */
    uint8_t  src_mac[MAC_ADDR_LEN];   /* 源MAC地址 */
    uint16_t ether_type;              /* 以太类型: 0x0800=IPv4, 0x86DD=IPv6, 0x0806=ARP */
} eth_hdr_t;

/* ---- IPv4 头 (RFC 791) ---- */
typedef struct {
    uint8_t  version_ihl;        /* 高4位: version, 低4位: IHL(头长度/4) */
    uint8_t  dscp_ecn;           /* 区分服务字段 */
    uint16_t total_length;       /* 总长度 */
    uint16_t identification;     /* 标识 */
    uint16_t flags_fragment;     /* 标志(3位) + 片偏移(13位) */
    uint8_t  ttl;                /* 生存时间 */
    uint8_t  protocol;           /* 上层协议: 6=TCP, 17=UDP, 1=ICMP */
    uint16_t header_checksum;    /* 头校验和 */
    uint32_t src_ip;             /* 源IP地址（网络字节序） */
    uint32_t dst_ip;             /* 目的IP地址（网络字节序） */
} ipv4_hdr_t;

/* ---- TCP 头 (RFC 793) ---- */
typedef struct {
    uint16_t src_port;           /* 源端口 */
    uint16_t dst_port;           /* 目的端口 */
    uint32_t seq_num;            /* 序列号 */
    uint32_t ack_num;            /* 确认号 */
    uint8_t  data_offset;        /* 高4位: 数据偏移(头长度/4) */
    uint8_t  flags;              /* 标志位: FIN|SYN|RST|PSH|ACK|URG */
    uint16_t window_size;        /* 窗口大小 */
    uint16_t checksum;           /* 校验和 */
    uint16_t urgent_pointer;     /* 紧急指针 */
} tcp_hdr_t;

/* ---- UDP 头 (RFC 768) ---- */
typedef struct {
    uint16_t src_port;           /* 源端口 */
    uint16_t dst_port;           /* 目的端口 */
    uint16_t length;             /* UDP长度（含头） */
    uint16_t checksum;           /* 校验和 */
} udp_hdr_t;

/* ---- ICMP 头 (RFC 792) ---- */
typedef struct {
    uint8_t  type;               /* 类型 */
    uint8_t  code;               /* 代码 */
    uint16_t checksum;           /* 校验和 */
    uint32_t rest;               /* 其余字段（因类型而异） */
} icmp_hdr_t;

/* ---- DNS 头 (RFC 1035) ---- */
typedef struct {
    uint16_t transaction_id;     /* 事务ID */
    uint16_t flags;              /* 标志位 */
    uint16_t qd_count;           /* Question数量 */
    uint16_t an_count;           /* Answer数量 */
    uint16_t ns_count;           /* Authority数量 */
    uint16_t ar_count;           /* Additional数量 */
} dns_hdr_t;

/* ---- 统一解析结果结构体 ---- */
/* 这是唯一的跨模块数据结构，所有模块通过它传递数据 */
typedef struct {
    /* 各层协议类型 */
    protocol_t    layer2_proto;          /* 链路层协议 */
    protocol_t    layer3_proto;          /* 网络层协议 */
    protocol_t    layer4_proto;          /* 传输层协议 */
    protocol_t    app_proto;             /* 应用层协议 (HTTP/DNS等) */

    /* 各层协议头 */
    eth_hdr_t     eth;                   /* Ethernet头 */
    ipv4_hdr_t    ipv4;                  /* IPv4头 */
    tcp_hdr_t     tcp;                   /* TCP头 */
    udp_hdr_t     udp;                   /* UDP头 */
    icmp_hdr_t    icmp;                  /* ICMP头 */
    dns_hdr_t     dns;                   /* DNS头 */

    /* 载荷数据 */
    uint8_t       payload[MAX_PAYLOAD];  /* 应用层载荷 */
    uint16_t      payload_len;           /* 载荷长度 */

    /* 元数据 */
    struct timeval ts;                   /* 抓包时间戳 */
    uint32_t       packet_len;           /* 原始包总长度 */
    uint32_t       captured_len;         /* 实际抓取长度 */
} ParsedPacket;

/* ---- 解析器统一接口 ---- */
/* 由成员B实现 parse_packet()，成员C的模块在ParsedPacket基础上做应用层解析 */

#endif /* COMMON_H */
