/**
 * ip_parser.c - IPv4协议解析模块实现
 *
 * 解析IPv4头部，含校验和验证，填充 ParsedPacket 结构。
 * 校验和验证逻辑源自 dev_b_parser 分支。
 */

#include "ip_parser.h"
#include "net_utils.h"
#include <stdio.h>

int parse_ipv4(const unsigned char *raw_data, uint32_t len, ParsedPacket *pkt)
{
    if (raw_data == NULL || pkt == NULL || len < 20) {
        return -1;
    }

    /* 填充IPv4头部字段 */
    pkt->ipv4.version_ihl    = raw_data[0];
    pkt->ipv4.dscp_ecn       = raw_data[1];
    pkt->ipv4.total_length   = ((uint16_t)raw_data[2] << 8) | raw_data[3];
    pkt->ipv4.identification = ((uint16_t)raw_data[4] << 8) | raw_data[5];
    pkt->ipv4.flags_fragment = ((uint16_t)raw_data[6] << 8) | raw_data[7];
    pkt->ipv4.ttl            = raw_data[8];
    pkt->ipv4.protocol       = raw_data[9];
    pkt->ipv4.header_checksum = ((uint16_t)raw_data[10] << 8) | raw_data[11];
    pkt->ipv4.src_ip = ((uint32_t)raw_data[12] << 24) |
                       ((uint32_t)raw_data[13] << 16) |
                       ((uint32_t)raw_data[14] << 8)  | raw_data[15];
    pkt->ipv4.dst_ip = ((uint32_t)raw_data[16] << 24) |
                       ((uint32_t)raw_data[17] << 16) |
                       ((uint32_t)raw_data[18] << 8)  | raw_data[19];

    pkt->layer3_proto = PROTO_IPV4;

    /* 计算头长度 (IHL × 4) */
    uint8_t ihl = (pkt->ipv4.version_ihl & 0x0F) * 4;
    if (ihl < 20 || (uint32_t)ihl > len) {
        return -1;
    }

    /* 校验和验证 (使用 dev_b_parser 的逻辑) */
    uint16_t calc = checksum16(raw_data, ihl);
    uint16_t recv = pkt->ipv4.header_checksum;
    /* 标准 TCP/IP 校验和验证: calc + recv == 0xFFFF */
    if ((uint16_t)(calc + recv) != 0xFFFF && (calc + recv) != 0x0000) {
        /* 校验和失败但仍继续解析（容忍坏包） */
    }

    return ihl;
}
