/**
 * ipv6_parser.h - IPv6协议解析模块接口
 *
 * 解析IPv6固定头（40字节），提取next_header和地址，
 * 填充 ParsedPacket.ipv6 及 layer3_proto。
 *
 * @return IPv6头长度(40)，-1失败
 */

#ifndef IPV6_PARSER_H
#define IPV6_PARSER_H

#include "common.h"

int parse_ipv6(const unsigned char *raw_data, uint32_t len, ParsedPacket *pkt);

#endif /* IPV6_PARSER_H */
