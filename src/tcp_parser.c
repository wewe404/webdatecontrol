/**
 * tcp_parser.c - TCP协议解析模块实现
 *
 * 解析TCP头部，含标志位解析，填充 ParsedPacket 结构。
 * 源自 dev_b_parser 分支。
 */

#include "tcp_parser.h"
#include <stdio.h>

int parse_tcp(const unsigned char *raw_data, uint32_t len, ParsedPacket *pkt)
{
    if (raw_data == NULL || pkt == NULL || len < 20) {
        return -1;
    }

    /* 填充TCP头部字段 */
    pkt->tcp.src_port       = ((uint16_t)raw_data[0] << 8) | raw_data[1];
    pkt->tcp.dst_port       = ((uint16_t)raw_data[2] << 8) | raw_data[3];
    pkt->tcp.seq_num        = ((uint32_t)raw_data[4] << 24) |
                              ((uint32_t)raw_data[5] << 16) |
                              ((uint32_t)raw_data[6] << 8)  | raw_data[7];
    pkt->tcp.ack_num        = ((uint32_t)raw_data[8] << 24) |
                              ((uint32_t)raw_data[9] << 16) |
                              ((uint32_t)raw_data[10] << 8) | raw_data[11];
    pkt->tcp.data_offset    = raw_data[12];
    pkt->tcp.flags          = raw_data[13];
    pkt->tcp.window_size    = ((uint16_t)raw_data[14] << 8) | raw_data[15];
    pkt->tcp.checksum       = ((uint16_t)raw_data[16] << 8) | raw_data[17];
    pkt->tcp.urgent_pointer = ((uint16_t)raw_data[18] << 8) | raw_data[19];

    pkt->layer4_proto = PROTO_TCP;

    /* 计算头长度 (data_offset高4位 × 4) */
    uint8_t tcp_hdr_len = ((pkt->tcp.data_offset >> 4) & 0x0F) * 4;
    if (tcp_hdr_len < 20 || (uint32_t)tcp_hdr_len > len) {
        tcp_hdr_len = 20; /* 降级为最小头长度 */
    }

    return tcp_hdr_len;
}
