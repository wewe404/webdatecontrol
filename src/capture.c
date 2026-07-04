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
        printf("Get devices failed: %s\n", errbuf);
        return -1;
    }

    printf("========== Device List ==========\n");

    for (dev = alldevs; dev != NULL; dev = dev->next) {
        printf("%d. %s", ++count, dev->name);

        if (dev->description != NULL) {
            printf(" - %s", dev->description);
        }

        printf("\n");
    }

    pcap_freealldevs(alldevs);

    if (count == 0) {
        printf("No device found.\n");
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
        printf("Open device failed: %s\n", errbuf);
        return NULL;
    }

    printf("Open device success: %s\n", device);
    return handle;
}

/* 开始抓包 */
void start_capture(pcap_t *handle)
{
    if (handle == NULL) {
        printf("Capture handle is NULL.\n");
        return;
    }

    printf("Capture module is ready.\n");
}

/* 抓取一个数据包 */
void capture_one_packet(pcap_t *handle)
{
    struct pcap_pkthdr *header;
    const u_char *data;
    int res;

    while ((res = pcap_next_ex(handle, &header, &data)) == 0) {
        /* 等待数据包 */
    }

    if (res == 1) {
        printf("Capture success, length: %u bytes\n", header->len);
    } else {
        printf("Capture failed.\n");
    }
}

/* 连续抓包并统计 */
void capture_packets_with_stats(pcap_t *handle, int packet_count)
{
    struct pcap_pkthdr *header;
    const u_char *data;
    int res;
    int captured = 0;
    unsigned int total_bytes = 0;
    unsigned int max_len = 0;
    unsigned int min_len = 0;

    printf("\n========== Capture With Stats ==========\n");

    while (captured < packet_count) {
        res = pcap_next_ex(handle, &header, &data);

        if (res == 1) {
            captured++;

            printf("Packet %d: length = %u bytes\n", captured, header->len);

            total_bytes += header->len;

            if (captured == 1) {
                max_len = header->len;
                min_len = header->len;
            } else {
                if (header->len > max_len) {
                    max_len = header->len;
                }

                if (header->len < min_len) {
                    min_len = header->len;
                }
            }
        } else if (res == 0) {
            /* 超时继续等待 */
            continue;
        } else {
            printf("Capture error.\n");
            break;
        }
    }

    if (captured > 0) {
        printf("\n========== Capture Statistics ==========\n");
        printf("Total packets : %d\n", captured);
        printf("Total bytes   : %u\n", total_bytes);
        printf("Average length: %u bytes\n", total_bytes / captured);
        printf("Max length    : %u bytes\n", max_len);
        printf("Min length    : %u bytes\n", min_len);
    }
}

/* 抓包并保存为pcap文件 */
void capture_save_to_file(pcap_t *handle, int packet_count, const char *filename)
{
    struct pcap_pkthdr *header;
    const u_char *data;
    pcap_dumper_t *dumper;
    int res;
    int saved = 0;

    dumper = pcap_dump_open(handle, filename);

    if (dumper == NULL) {
        printf("Create pcap file failed.\n");
        return;
    }

    printf("\nStart saving packets to file: %s\n", filename);

    while (saved < packet_count) {
        res = pcap_next_ex(handle, &header, &data);

        if (res == 1) {
            pcap_dump((u_char *)dumper, header, data);
            saved++;

            printf("Saved packet %d, length: %u bytes\n", saved, header->len);
        } else if (res == 0) {
            continue;
        } else {
            printf("Save packet failed.\n");
            break;
        }
    }

    pcap_dump_close(dumper);

    printf("Pcap file saved successfully.\n");
}

/* 读取pcap文件回放 */
void read_pcap_file(const char *filename)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr *header;
    const u_char *data;
    int res;
    int count = 0;
    unsigned int total_bytes = 0;

    handle = pcap_open_offline(filename, errbuf);

    if (handle == NULL) {
        printf("Open pcap file failed: %s\n", errbuf);
        return;
    }

    printf("\n========== Read Pcap File ==========\n");
    printf("File name: %s\n", filename);

    while ((res = pcap_next_ex(handle, &header, &data)) >= 0) {
        if (res == 0) {
            continue;
        }

        count++;
        total_bytes += header->len;

        printf("Packet %d: length = %u bytes, captured length = %u bytes\n",
               count, header->len, header->caplen);
    }

    printf("\n========== Pcap File Statistics ==========\n");
    printf("Total packets: %d\n", count);
    printf("Total bytes  : %u\n", total_bytes);

    pcap_close(handle);
}

/* 设置BPF过滤规则 */
int apply_filter(pcap_t *handle, const char *filter_exp)
{
    struct bpf_program fp;

    if (pcap_compile(handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("Compile filter failed: %s\n", pcap_geterr(handle));
        return -1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        printf("Set filter failed: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        return -1;
    }

    pcap_freecode(&fp);

    printf("BPF filter applied: %s\n", filter_exp);
    return 0;
}

/* 停止抓包 */
void stop_capture(pcap_t *handle)
{
    if (handle != NULL) {
        pcap_close(handle);
        printf("Capture handle closed.\n");
    }
}