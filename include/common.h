/**
 * common.h - 全组统一数据结构定义
 *
 * 由四人在第一天协商确定，后续所有模块基于此结构对接。
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
#define MAC_ADDR_LEN    6
#define IP4_ADDR_LEN    4
#define IP6_ADDR_LEN    16
#define MAX_PAYLOAD     65535
#define MAX_DNS_NAME    256
#define MAX_HTTP_HEADER 8192

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
#pragma pack(push, 1)
typedef struct {
    uint8_t  dst_mac[MAC_ADDR_LEN];
    uint8_t  src_mac[MAC_ADDR_LEN];
    uint16_t ether_type;
} eth_hdr_t;
#pragma pack(pop)

/* ---- IPv6 头 (RFC 2460) ---- */
#pragma pack(push, 1)
typedef struct {
    uint32_t vtc_flow;        /* version(4) + traffic_class(8) + flow_label(20) */
    uint16_t payload_length;
    uint8_t  next_header;     /* 6=TCP, 17=UDP, 58=ICMPv6 */
    uint8_t  hop_limit;
    uint8_t  src_ip[IP6_ADDR_LEN];
    uint8_t  dst_ip[IP6_ADDR_LEN];
} ipv6_hdr_t;
#pragma pack(pop)

/* ---- IPv4 头 (RFC 791) ---- */
#pragma pack(push, 1)
typedef struct {
    uint8_t  version_ihl;
    uint8_t  dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t header_checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} ipv4_hdr_t;
#pragma pack(pop)

/* ---- TCP 头 (RFC 793) ---- */
#pragma pack(push, 1)
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset;
    uint8_t  flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
} tcp_hdr_t;
#pragma pack(pop)

/* ---- UDP 头 (RFC 768) ---- */
#pragma pack(push, 1)
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_hdr_t;
#pragma pack(pop)

/* ---- ICMP 头 (RFC 792) ---- */
#pragma pack(push, 1)
typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint32_t rest;
} icmp_hdr_t;
#pragma pack(pop)

/* ---- DNS 头 (RFC 1035) ---- */
#pragma pack(push, 1)
typedef struct {
    uint16_t transaction_id;
    uint16_t flags;
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;
} dns_hdr_t;
#pragma pack(pop)

/* ---- 统一解析结果结构体 ---- */
typedef struct {
    protocol_t    layer2_proto;
    protocol_t    layer3_proto;
    protocol_t    layer4_proto;
    protocol_t    app_proto;

    eth_hdr_t     eth;
    ipv4_hdr_t    ipv4;
    ipv6_hdr_t    ipv6;
    tcp_hdr_t     tcp;
    udp_hdr_t     udp;
    icmp_hdr_t    icmp;
    dns_hdr_t     dns;

    uint8_t       payload[MAX_PAYLOAD];
    uint16_t      payload_len;

    struct timeval ts;
    uint32_t       packet_len;
    uint32_t       captured_len;
} ParsedPacket;

#endif /* COMMON_H */
