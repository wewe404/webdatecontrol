#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include "capture.h"

/* 清空输入缓冲区 */
void clear_input_buffer(void)
{
    int ch;

    while ((ch = getchar()) != '\n' && ch != EOF) {
    }
}

/* 选择网卡 */
int select_device(char *device_name, int size)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    int count = 0;
    int choice;
    int i;

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

    if (count == 0) {
        printf("No device found.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nSelect device number: ");
    scanf("%d", &choice);

    if (choice < 1 || choice > count) {
        printf("Invalid device number.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    dev = alldevs;

    for (i = 1; i < choice; i++) {
        dev = dev->next;
    }

    strncpy(device_name, dev->name, size - 1);
    device_name[size - 1] = '\0';

    pcap_freealldevs(alldevs);

    return 0;
}

/* 实时抓包 */
void menu_capture(void)
{
    char device_name[512];
    int count;
    pcap_t *handle;

    if (select_device(device_name, sizeof(device_name)) != 0) {
        return;
    }

    printf("Input packet count: ");
    scanf("%d", &count);

    if (count <= 0) {
        count = 10;
    }

    handle = capture_init(device_name);

    if (handle == NULL) {
        return;
    }

    start_capture(handle);
    capture_packets_with_stats(handle, count);
    stop_capture(handle);
}

/* 保存pcap文件 */
void menu_save_pcap(void)
{
    char device_name[512];
    char filename[256];
    int count;
    pcap_t *handle;

    if (select_device(device_name, sizeof(device_name)) != 0) {
        return;
    }

    printf("Input packet count: ");
    scanf("%d", &count);

    if (count <= 0) {
        count = 10;
    }

    printf("Input pcap filename: ");
    scanf("%255s", filename);

    handle = capture_init(device_name);

    if (handle == NULL) {
        return;
    }

    start_capture(handle);
    capture_save_to_file(handle, count, filename);
    stop_capture(handle);
}

/* 读取pcap文件 */
void menu_read_pcap(void)
{
    char filename[256];

    printf("Input pcap filename: ");
    scanf("%255s", filename);

    read_pcap_file(filename);
}

/* BPF过滤抓包 */
void menu_filter_capture(void)
{
    char device_name[512];
    char filter_exp[256];
    int count;
    pcap_t *handle;

    if (select_device(device_name, sizeof(device_name)) != 0) {
        return;
    }

    printf("Input packet count: ");
    scanf("%d", &count);

    if (count <= 0) {
        count = 10;
    }

    clear_input_buffer();

    printf("Input BPF filter, for example: tcp / udp / icmp / tcp port 80\n");
    printf("Filter: ");
    fgets(filter_exp, sizeof(filter_exp), stdin);

    filter_exp[strcspn(filter_exp, "\n")] = '\0';

    handle = capture_init(device_name);

    if (handle == NULL) {
        return;
    }

    if (apply_filter(handle, filter_exp) == 0) {
        start_capture(handle);
        capture_packets_with_stats(handle, count);
    }

    stop_capture(handle);
}

/* 显示菜单 */
void show_menu(void)
{
    printf("\n========== Packet Capture Tool ==========\n");
    printf("1. Show device list\n");
    printf("2. Capture packets with statistics\n");
    printf("3. Capture and save to pcap file\n");
    printf("4. Read pcap file\n");
    printf("5. Capture with BPF filter\n");
    printf("0. Exit\n");
    printf("Select: ");
}

/* 程序入口 */
int main()
{
    int choice;

    while (1) {
        show_menu();
        scanf("%d", &choice);

        switch (choice) {
        case 1:
            list_devices();
            break;

        case 2:
            menu_capture();
            break;

        case 3:
            menu_save_pcap();
            break;

        case 4:
            menu_read_pcap();
            break;

        case 5:
            menu_filter_capture();
            break;

        case 0:
            printf("Exit program.\n");
            return 0;

        default:
            printf("Invalid choice.\n");
            break;
        }
    }

    return 0;
}