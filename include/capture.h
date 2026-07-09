/*
 * capture.h - 抓包引擎模块接口声明
 *
 * 成员A负责模块
 *
 * 提供实时抓包、BPF过滤、
 * PCAP文件保存回放及性能统计接口。
 */
#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

/* 显示所有可用网卡 */
int list_devices(void);

/* 初始化抓包模块 */
pcap_t* capture_init(const char *device);

/* 开始抓包 */
void start_capture(pcap_t *handle);

/* 抓取一个数据包 */
void capture_one_packet(pcap_t *handle);

/* 连续抓包并统计 */
void capture_packets_with_stats(pcap_t *handle, int packet_count);

/* 抓包并保存为pcap文件 */
void capture_save_to_file(pcap_t *handle, int packet_count, const char *filename);

/* 读取pcap文件回放 */
void read_pcap_file(const char *filename);

/* 按BPF规则读取pcap文件 */
void read_pcap_file_with_filter(const char *filename, const char *filter_exp);

/* 抓包性能测试 */
void performance_capture_test(pcap_t *handle, int seconds);

/* 设置BPF过滤规则 */
int apply_filter(pcap_t *handle, const char *filter_exp);

/* 停止抓包 */
void stop_capture(pcap_t *handle);

#endif