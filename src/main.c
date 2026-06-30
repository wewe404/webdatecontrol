#include <stdio.h>
#include <pcap.h>
#include "capture.h"

/* 程序入口 */
int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    list_devices();

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("获取网卡失败：%s\n", errbuf);
        return 1;
    }

    if (alldevs == NULL) {
        printf("没有找到可用网卡。\n");
        return 1;
    }

    pcap_t *handle = capture_init(alldevs->name);

    if (handle != NULL) {
        start_capture(handle);
        stop_capture(handle);
    }

    pcap_freealldevs(alldevs);

    return 0;
}