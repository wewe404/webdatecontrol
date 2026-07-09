/**
 * ip_parser.h - IPv4协议解析模块
 *
 * 源自 dev_b_parser 分支，整合为统一 ParsedPacket 接口。
 * 解析IPv4头部（最小20字节），含校验和验证，
 * 填充 ParsedPacket.ipv4 及 layer3_proto。
 *
 * @return IP头长度(字节)，-1失败
 */
#ifndef IP_PARSER_H
#define IP_PARSER_H

#include "common.h"

int parse_ipv4(const unsigned char *raw_data, uint32_t len, ParsedPacket *pkt);

#endif
