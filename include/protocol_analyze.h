/**
 * protocol_analyze.h - 协议分析整合层接口
 *
 * 整合 eth_parser/ip_parser/tcp_parser/udp_parser/icmp_parser
 * 及其他模块的功能，提供从原始数据包到 ParsedPacket 的一站式解析。
 *
 * 数据流：
 *   原始数据包 -> analyze_packet() -> 调用各层独立解析器 -> 填充ParsedPacket
 *                                   -> 调用DNS/HTTP应用层解析
 */

#ifndef PROTOCOL_ANALYZE_H
#define PROTOCOL_ANALYZE_H

#include "common.h"

int analyze_packet(const uint8_t *raw_data, uint32_t len, ParsedPacket *pkt);
void print_packet_info(const ParsedPacket *pkt);
void print_packet_brief(const ParsedPacket *pkt, int seq);
int analyze_pcap_file(const char *filename, int verbose);
int analyze_pcap_file_with_filter(const char *filename, const char *filter_exp,
                                   int verbose);

#endif
