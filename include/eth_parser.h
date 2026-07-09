/**
 * eth_parser.h - Ethernet协议解析模块
 *
 * 源自 dev_b_parser 分支，整合为统一 ParsedPacket 接口。
 * 解析14字节Ethernet帧头，填充 ParsedPacket.eth 及 layer2_proto。
 *
 * @return Ethernet头长度(14), -1失败
 */
#ifndef ETH_PARSER_H
#define ETH_PARSER_H

#include "common.h"

int parse_ethernet(const unsigned char *raw_data, uint32_t len, ParsedPacket *pkt);

#endif
