#include "tcp_parser.h"
#include <arpa/inet.h>
#include <stdio.h>

int parse_tcp(const unsigned char *raw_data, uint16_t ip_payload_len) {
    if (raw_data == NULL || ip_payload_len < 20) {
        // TCP 头部最小 20 字节
        return -1;
    }

    tcp_header_t *tcp = (tcp_header_t *)raw_data;

    // 提取端口（网络字节序转主机字节序）
    uint16_t src_port = ntohs(tcp->src_port);
    uint16_t dst_port = ntohs(tcp->dst_port);

    // 提取头部长度（高4位，单位4字节）
    uint8_t tcp_header_len = (tcp->data_offset >> 4) * 4;
    if (tcp_header_len < 20 || tcp_header_len > ip_payload_len) {
        printf("【TCP】头部长度异常: %d 字节\n", tcp_header_len);
        return -1;
    }

    // 提取标志位（按位解析）
    uint8_t syn = (tcp->flags & 0x02) ? 1 : 0;
    uint8_t ack = (tcp->flags & 0x10) ? 1 : 0;
    uint8_t fin = (tcp->flags & 0x01) ? 1 : 0;
    uint8_t rst = (tcp->flags & 0x04) ? 1 : 0;
    uint8_t psh = (tcp->flags & 0x08) ? 1 : 0;

    // 打印调试信息
    printf("【TCP层】\n");
    printf("  源端口: %d, 目标端口: %d\n", src_port, dst_port);
    printf("  序列号: %u, 确认号: %u\n", ntohl(tcp->seq_num), ntohl(tcp->ack_num));
    printf("  头部长度: %d 字节\n", tcp_header_len);
    printf("  标志位: %s%s%s%s%s\n",
           syn ? "SYN " : "",
           ack ? "ACK " : "",
           fin ? "FIN " : "",
           rst ? "RST " : "",
           psh ? "PSH " : "");
    printf("  窗口大小: %d\n", ntohs(tcp->window_size));

    // 返回 TCP 载荷相对于 raw_data 的偏移（即跳过头部）
    return tcp_header_len;
}