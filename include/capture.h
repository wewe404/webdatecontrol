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

/* 停止抓包 */
void stop_capture(pcap_t *handle);

#endif