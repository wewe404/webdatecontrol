#pragma once
#include <stdint.h>

// TCP 头部结构体（20字节，不含选项）
typedef struct {
    uint16_t src_port;      // 源端口
    uint16_t dst_port;      // 目标端口
    uint32_t seq_num;       // 序列号
    uint32_t ack_num;       // 确认号
    uint8_t  data_offset;   // 高4位: 数据偏移（头部长度，单位4字节）
    uint8_t  flags;         // 标志位: CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
    uint16_t window_size;   // 窗口大小
    uint16_t checksum;      // 校验和
    uint16_t urgent_ptr;    // 紧急指针
} __attribute__((packed)) tcp_header_t;

// 解析 TCP 头部
// 参数: raw_data - 指向 TCP 层数据的起始位置（即 IP 载荷的起始地址）
//       ip_payload_len - IP 载荷的总长度（用于做边界检查）
// 返回: TCP 载荷（数据部分）相对于 raw_data 的偏移量（即头部长度），-1 表示解析失败
int parse_tcp(const unsigned char *raw_data, uint16_t ip_payload_len);