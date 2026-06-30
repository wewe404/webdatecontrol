#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <pcap.h>
#include "capture.h"

/* 程序入口 */
int main()
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *dev;
    int choice, count = 0;

    /* 获取网卡列表 */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        printf("获取网卡失败：%s\n", errbuf);
        return 1;
    }

    printf("========== 可用网卡 ==========\n");

    dev = alldevs;
    while (dev != NULL)
    {
        printf("%d. %s", ++count, dev->name);

        if (dev->description != NULL)
            printf(" - %s", dev->description);

        printf("\n");

        dev = dev->next;
    }

    if (count == 0)
    {
        printf("没有找到可用网卡！\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    printf("\n请输入要抓包的网卡编号：");
    scanf("%d", &choice);

    if (choice < 1 || choice > count)
    {
        printf("输入编号无效！\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    dev = alldevs;
    for (int i = 1; i < choice; i++)
        dev = dev->next;

    pcap_t *handle = capture_init(dev->name);

    if (handle == NULL)
    {
        pcap_freealldevs(alldevs);
        return 1;
    }

    start_capture(handle);

    printf("\n开始抓取10个数据包...\n\n");

    for (int i = 0; i < 10; i++)
    {
        printf("===== 第 %d 个数据包 =====\n", i + 1);
        capture_one_packet(handle);
        printf("\n");
    }

    stop_capture(handle);

    pcap_freealldevs(alldevs);

    printf("抓包结束！\n");

    return 0;
}