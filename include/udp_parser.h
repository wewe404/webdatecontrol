/**
 * udp_parser.h - UDP协议解析模块
 *
 * 源自 dev_b_parser 分支，整合为统一 ParsedPacket 接口。
 * 解析UDP头部（固定8字节），填充 ParsedPacket.udp 及 layer4_proto。
 *
 * @return UDP头长度(8), -1失败
 */
#ifndef UDP_PARSER_H
#define UDP_PARSER_H

#include "common.h"

int parse_udp(const unsigned char *raw_data, uint32_t len, ParsedPacket *pkt);

#endif
