/**
 * eth_parser.c - Ethernet协议解析模块实现
 *
 * 解析14字节Ethernet帧头，提取MAC地址和EtherType，
 * 填充 ParsedPacket.eth 及 layer2_proto。
 */

#include "eth_parser.h"
#include <stdio.h>

int parse_ethernet(const unsigned char *raw_data, uint32_t len, ParsedPacket *pkt)
{
    if (raw_data == NULL || pkt == NULL || len < 14) {
        return -1;
    }

    /* 复制MAC地址 */
    for (int i = 0; i < 6; i++) {
        pkt->eth.dst_mac[i] = raw_data[i];
        pkt->eth.src_mac[i] = raw_data[6 + i];
    }

    /* 解析EtherType (网络字节序→主机字节序) */
    pkt->eth.ether_type = ((uint16_t)raw_data[12] << 8) | raw_data[13];

    /* 设置链路层协议 */
    switch (pkt->eth.ether_type) {
    case 0x0800: pkt->layer2_proto = PROTO_IPV4; break;
    case 0x86DD: pkt->layer2_proto = PROTO_IPV6; break;
    case 0x0806: pkt->layer2_proto = PROTO_ARP;  break;
    default:     pkt->layer2_proto = PROTO_UNKNOWN; break;
    }

    return 14; /* Ethernet头长度 */
}
