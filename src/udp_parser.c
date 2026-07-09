/**
 * udp_parser.c - UDP协议解析模块实现
 *
 * 解析UDP头部（固定8字节），填充 ParsedPacket 结构。
 * 源自 dev_b_parser 分支。
 */

#include "udp_parser.h"
#include <stdio.h>

int parse_udp(const unsigned char *raw_data, uint32_t len, ParsedPacket *pkt)
{
    if (raw_data == NULL || pkt == NULL || len < 8) {
        return -1;
    }

    /* 填充UDP头部字段 */
    pkt->udp.src_port = ((uint16_t)raw_data[0] << 8) | raw_data[1];
    pkt->udp.dst_port = ((uint16_t)raw_data[2] << 8) | raw_data[3];
    pkt->udp.length   = ((uint16_t)raw_data[4] << 8) | raw_data[5];
    pkt->udp.checksum = ((uint16_t)raw_data[6] << 8) | raw_data[7];

    pkt->layer4_proto = PROTO_UDP;

    return 8; /* UDP头固定8字节 */
}
