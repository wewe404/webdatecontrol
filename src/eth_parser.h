#pragma once
#include <stdint.h>

// 以太网头部结构体（14字节）
// __attribute__((packed)) 防止编译器字节对齐，确保结构体在内存中紧凑排列
typedef struct {
    uint8_t dst_mac[6];   // 目标MAC地址
    uint8_t src_mac[6];   // 源MAC地址
    uint16_t ether_type;  // 上层协议类型（0x0800=IPv4, 0x0806=ARP, 0x86DD=IPv6）
} __attribute__((packed)) ethernet_header_t;

// 解析以太网头部
// 参数: raw_data - 原始数据包指针
// 返回: 上层协议类型（如 0x0800 表示 IPv4），-1 表示解析失败
int parse_ethernet(const unsigned char *raw_data);