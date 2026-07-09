/**
 * icmp_parser.h - ICMP协议解析模块
 *
 * 源自 dev_b_parser 分支，整合为统一 ParsedPacket 接口。
 * 解析ICMP头部（最小4字节），填充 ParsedPacket.icmp 及 layer4_proto。
 *
 * @return 0成功, -1失败
 */
#ifndef ICMP_PARSER_H
#define ICMP_PARSER_H

#include "common.h"

int parse_icmp(const unsigned char *raw_data, uint32_t len, ParsedPacket *pkt);

#endif
