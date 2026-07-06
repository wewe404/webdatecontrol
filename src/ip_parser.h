#pragma once
#include <stdint.h>

// IPv4 头部结构体（最小20字节，带选项时更长）
typedef struct {
    uint8_t  version_ihl;      // 高4位: 版本(4), 低4位: 头部长度(IHL)
    uint8_t  dscp_ecn;         // 差分服务 + 显式拥塞通知
    uint16_t total_length;     // 总长度（包含头部+数据）
    uint16_t identification;   // 标识符
    uint16_t flags_fragment;   // 高3位: 标志位, 低13位: 分片偏移
    uint8_t  ttl;              // 生存时间 (Time To Live)
    uint8_t  protocol;         // 上层协议 (6=TCP, 17=UDP, 1=ICMP)
    uint16_t header_checksum;  // 头部校验和
    uint32_t src_ip;           // 源IP地址
    uint32_t dst_ip;           // 目标IP地址
} __attribute__((packed)) ipv4_header_t;

// 解析 IPv4 头部
// 参数: raw_data - 指向 IP 层数据的起始地址（即以太网载荷的起始位置）
// 返回: IP 载荷（即上层协议数据）的起始偏移量（字节数），-1 表示解析失败
int parse_ipv4(const unsigned char *raw_data);