#include <stdio.h>
#include <pcap.h>
#include "capture.h"

/* 显示所有可用网卡 */
int list_devices(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    int count = 0;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("获取网卡失败：%s\n", errbuf);
        return -1;
    }

    printf("可用网卡列表：\n");

    for (dev = alldevs; dev != NULL; dev = dev->next) {
        printf("%d. %s", ++count, dev->name);

        if (dev->description != NULL) {
            printf(" - %s", dev->description);
        }

        printf("\n");
    }

    pcap_freealldevs(alldevs);

    if (count == 0) {
        printf("未找到可用网卡。\n");
        return -1;
    }

    return count;
}

/* 初始化抓包模块 */
pcap_t* capture_init(const char *device)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_live(device, 65535, 1, 1000, errbuf);

    if (handle == NULL) {
        printf("打开网卡失败：%s\n", errbuf);
        return NULL;
    }

    printf("成功打开网卡：%s\n", device);
    return handle;
}

/* 开始抓包 */
void start_capture(pcap_t *handle)
{
    if (handle == NULL) {
        printf("抓包句柄为空。\n");
        return;
    }

    printf("抓包模块已准备完成。\n");
}

/* 抓取一个数据包 */
void capture_one_packet(pcap_t *handle)
{
    struct pcap_pkthdr *header;
    const u_char *data;

    int res;

    while ((res = pcap_next_ex(handle, &header, &data)) == 0)
    {
        // 一直等到抓到数据包
    }

    if (res == 1)
    {
        printf("捕获成功！\n");
        printf("长度：%u 字节\n", header->len);
    }
    else
    {
        printf("抓包失败！\n");
    }
}

/* 停止抓包 */
void stop_capture(pcap_t *handle)
{
    if (handle != NULL) {
        pcap_close(handle);
        printf("抓包句柄已关闭。\n");
    }
}