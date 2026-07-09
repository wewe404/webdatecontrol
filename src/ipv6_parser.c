/**
 * ipv6_parser.c - IPv6协议解析模块实现
 *
 * 解析IPv6固定头（40字节，RFC 2460），
 * 填充 ParsedPacket.ipv6 各字段及 layer3_proto。
 *
 * 注意：IPv6扩展头目前未完整解析，仅跳过。
 */

#include "ipv6_parser.h"
#include <stdio.h>

int parse_ipv6(const unsigned char *raw_data, uint32_t len, ParsedPacket *pkt)
{
    if (raw_data == NULL || pkt == NULL || len < 40) {
        return -1;
    }

    /* 前4字节：version(4) + traffic_class(8) + flow_label(20) */
    pkt->ipv6.vtc_flow = ((uint32_t)raw_data[0] << 24) |
                         ((uint32_t)raw_data[1] << 16) |
                         ((uint32_t)raw_data[2] << 8)  | raw_data[3];

    /* Payload Length (不包括固定头本身的40字节) */
    pkt->ipv6.payload_length = ((uint16_t)raw_data[4] << 8) | raw_data[5];

    /* Next Header (相当于IPv4的protocol字段) */
    pkt->ipv6.next_header = raw_data[6];

    /* Hop Limit */
    pkt->ipv6.hop_limit = raw_data[7];

    /* 源地址 (16字节) */
    for (int i = 0; i < 16; i++)
        pkt->ipv6.src_ip[i] = raw_data[8 + i];

    /* 目的地址 (16字节) */
    for (int i = 0; i < 16; i++)
        pkt->ipv6.dst_ip[i] = raw_data[24 + i];

    /* 设置三层协议 */
    pkt->layer3_proto = PROTO_IPV6;

    return 40; /* IPv6固定头长度 */
}
