#pragma once
#include <stdint.h>

// ICMP 头部结构体（8字节）
typedef struct {
    uint8_t type;          // 类型（0=Echo Reply, 8=Echo Request, 3=Destination Unreachable...）
    uint8_t code;          // 代码（具体含义取决于 type）
    uint16_t checksum;     // 校验和
    // 后面可能跟不同的内容（如 Echo 的 identifier 和 sequence），但这里只解析前 8 字节
} __attribute__((packed)) icmp_header_t;

// 解析 ICMP 头部
// 参数: raw_data - 指向 ICMP 层数据的起始位置
//       ip_payload_len - IP 载荷的总长度
// 返回: 0 成功，-1 失败
int parse_icmp(const unsigned char *raw_data, uint16_t ip_payload_len);