/**
 * protocol_analyze.h - 协议分析整合层接口
 *
 * 成员C创建的整合模块
 *
 * 注意：本模块包含Ethernet/IP/TCP/UDP低层解析功能，
 * 正式架构中这部分应由成员B的eth_parser/ip_parser/tcp_parser等模块负责。
 * 在成员B代码就绪前，本模块提供完整的协议栈解析能力，
 * 使成员C的DNS/HTTP解析和流量统计模块可以独立运行和测试。
 * 成员B代码就绪后，可将本模块中的低层解析替换为B的接口。
 *
 * 数据流：
 *   原始数据包 -> analyze_packet() -> 逐层解析 -> 填充ParsedPacket
 *                                            -> 调用DNS/HTTP应用层解析
 */

#ifndef PROTOCOL_ANALYZE_H
#define PROTOCOL_ANALYZE_H

#include "common.h"

/**
 * analyze_packet - 解析原始数据包，填充ParsedPacket结构
 * @param raw_data 原始数据包（从pcap获取的以太网帧）
 * @param len      数据包长度
 * @param pkt      输出参数，解析结果
 * @return 0成功, -1失败
 */
int analyze_packet(const uint8_t *raw_data, uint32_t len, ParsedPacket *pkt);

/**
 * print_packet_info - 打印数据包解析信息
 * @param pkt 已解析的数据包
 */
void print_packet_info(const ParsedPacket *pkt);

/**
 * print_packet_brief - 打印数据包简要信息（单行）
 * @param pkt  已解析的数据包
 * @param seq  序号
 */
void print_packet_brief(const ParsedPacket *pkt, int seq);

/**
 * analyze_pcap_file - 分析pcap文件中的所有数据包
 * @param filename pcap文件名
 * @param verbose  是否打印详细信息
 * @return 解析的数据包数量, -1失败
 */
int analyze_pcap_file(const char *filename, int verbose);

/**
 * analyze_pcap_file_with_filter - 按BPF过滤分析pcap文件
 * @param filename   pcap文件名
 * @param filter_exp BPF过滤规则
 * @param verbose    是否打印详细信息
 * @return 匹配并解析的数据包数量, -1失败
 */
int analyze_pcap_file_with_filter(const char *filename, const char *filter_exp,
                                   int verbose);

#endif /* PROTOCOL_ANALYZE_H */
