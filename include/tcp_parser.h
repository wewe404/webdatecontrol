/**
 * tcp_parser.h - TCP协议解析模块
 *
 * 源自 dev_b_parser 分支，整合为统一 ParsedPacket 接口。
 * 解析TCP头部（最小20字节），填充 ParsedPacket.tcp 及 layer4_proto。
 *
 * @return TCP头长度(字节)，-1失败
 */
#ifndef TCP_PARSER_H
#define TCP_PARSER_H

#include "common.h"

int parse_tcp(const unsigned char *raw_data, uint32_t len, ParsedPacket *pkt);

#endif
