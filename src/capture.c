#include <stdio.h>
#include "capture.h"

/* 初始化抓包模块 */
pcap_t* capture_init(const char *device)
{
    printf("初始化抓包模块：%s\n", device);
    return NULL;
}

/* 开始抓包 */
void start_capture(pcap_t *handle)
{
    printf("开始抓包...\n");
}

/* 停止抓包 */
void stop_capture(pcap_t *handle)
{
    printf("停止抓包...\n");
}