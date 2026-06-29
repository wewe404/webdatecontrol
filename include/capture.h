#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

/* 初始化抓包模块 */
pcap_t* capture_init(const char *device);

/* 开始抓包 */
void start_capture(pcap_t *handle);

/* 停止抓包 */
void stop_capture(pcap_t *handle);

#endif