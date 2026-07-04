#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include "capture.h"
#include "net_utils.h"

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

    printf("========== 可用网卡列表 ==========\n");

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

    printf("\n请选择要抓包的网卡编号: ");
    scanf("%d", &choice);

    if (choice < 1 || choice > count) {
        printf("网卡编号无效.\n");
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

    printf("请输入抓包数量: ");
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

    printf("请输入抓包数量: ");
    scanf("%d", &count);

    if (count <= 0) {
        count = 10;
    }

    printf("请输入pcap文件名: ");
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

    printf("请输入pcap文件名: ");
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

    printf("请输入抓包数量: ");
    scanf("%d", &count);

    if (count <= 0) {
        count = 10;
    }

    clear_input_buffer();

    printf("请输入BPF过滤规则，例如 tcp / udp / icmp / tcp port 80\n");
    printf("过滤规则: ");
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

/* 按过滤规则读取pcap文件 */
void menu_read_pcap_with_filter(void)
{
    char filename[256];
    char filter_exp[256];

    printf("请输入pcap文件名：");
    scanf("%255s", filename);

    clear_input_buffer();

    printf("请输入BPF过滤规则，例如 tcp / udp / icmp / host 192.168.31.143\n");
    printf("过滤规则：");
    fgets(filter_exp, sizeof(filter_exp), stdin);

    filter_exp[strcspn(filter_exp, "\n")] = '\0';

    read_pcap_file_with_filter(filename, filter_exp);
}

/* 性能测试 */
void menu_performance_test(void)
{
    char device_name[512];
    int seconds;
    pcap_t *handle;

    if (select_device(device_name, sizeof(device_name)) != 0)
    {
        return;
    }

    printf("请输入测试时长，单位秒：");
    scanf("%d", &seconds);

    handle = capture_init(device_name);

    if (handle == NULL)
    {
        return;
    }

    performance_capture_test(handle, seconds);

    stop_capture(handle);
}

/* 显示菜单 */
void show_menu(void)
{
    printf("\n========== 网络数据包捕获工具 ==========\n");
    printf("1. 查看网卡列表\n");
    printf("2. 连续抓包并显示统计信息\n");
    printf("3. 抓包并保存为pcap文件\n");
    printf("4. 读取pcap文件回放\n");
    printf("5. 使用BPF过滤规则抓包\n");
    printf("6. 按BPF规则读取pcap文件\n");
    printf("7. 工具函数自测\n");
    printf("8. 抓包性能测试\n");
    printf("0. 退出程序\n");
    printf("请选择功能：");
}

/* 程序入口 */
int main()
{
        SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
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

            case 6:
    menu_read_pcap_with_filter();
    break;

case 7:
    net_utils_self_test();
    break;

case 8:
    menu_performance_test();
    break;


case 0:
    printf("退出程序。\n");
    return 0;

default:
    printf("输入无效，请重新选择。\n");
    break;
        }
    }

    return 0;
}