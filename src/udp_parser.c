#include "udp_parser.h"
#include <arpa/inet.h>
#include <stdio.h>

int parse_udp(const unsigned char *raw_data, uint16_t ip_payload_len) {
    if (raw_data == NULL || ip_payload_len < 8) {
        // UDP 头部固定 8 字节
        return -1;
    }

    udp_header_t *udp = (udp_header_t *)raw_data;

    uint16_t src_port = ntohs(udp->src_port);
    uint16_t dst_port = ntohs(udp->dst_port);
    uint16_t udp_len = ntohs(udp->length);

    printf("【UDP层】\n");
    printf("  源端口: %d, 目标端口: %d\n", src_port, dst_port);
    printf("  UDP长度: %d 字节\n", udp_len);

    // UDP 头部固定 8 字节，数据从第 8 字节开始
    return 8;
}