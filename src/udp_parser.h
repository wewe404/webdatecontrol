#pragma once
#include <stdint.h>

// UDP 头部结构体（8字节）
typedef struct {
    uint16_t src_port;      // 源端口
    uint16_t dst_port;      // 目标端口
    uint16_t length;        // UDP 报文总长度（头部 + 数据）
    uint16_t checksum;      // 校验和
} __attribute__((packed)) udp_header_t;

// 解析 UDP 头部
// 参数: raw_data - 指向 UDP 层数据的起始位置（即 IP 载荷的起始地址）
//       ip_payload_len - IP 载荷的总长度
// 返回: UDP 载荷相对于 raw_data 的偏移量（固定 8 字节），-1 表示解析失败
int parse_udp(const unsigned char *raw_data, uint16_t ip_payload_len);