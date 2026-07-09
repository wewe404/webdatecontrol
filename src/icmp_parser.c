/**
 * icmp_parser.c - ICMP协议解析模块实现
 *
 * 解析ICMP头部（最小4字节），填充 ParsedPacket 结构。
 * 源自 dev_b_parser 分支。
 */

#include "icmp_parser.h"
#include <stdio.h>

int parse_icmp(const unsigned char *raw_data, uint32_t len, ParsedPacket *pkt)
{
    if (raw_data == NULL || pkt == NULL || len < 4) {
        return -1;
    }

    /* 填充ICMP头部字段 */
    pkt->icmp.type     = raw_data[0];
    pkt->icmp.code     = raw_data[1];
    pkt->icmp.checksum = ((uint16_t)raw_data[2] << 8) | raw_data[3];

    pkt->layer4_proto = PROTO_ICMP;

    return 0; /* ICMP本身无固定载荷偏移，后续数据由上层解释 */
}
