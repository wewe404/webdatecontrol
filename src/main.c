/**
 * main.c - 网络数据包捕获与协议解析工具 主程序
 *
 * 综合版本：整合了 member A/D 的抓包功能 和 member C 的应用层解析/统计/BPF过滤功能
 * 使用独立模块化解析器：eth_parser / ip_parser / tcp_parser / udp_parser / icmp_parser (源自 dev_b_parser 分支)
 * 使用应用层解析模块：dns_parser / http_parser / bpf_filter / stats (源自 main 分支)
 *
 * 功能菜单：
 *   1-8:  抓包与文件操作 (基础功能)
 *   9-16: 协议解析与流量统计 (高级功能)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>

#include "capture.h"
#include "net_utils.h"
#include "common.h"
#include "dns_parser.h"
#include "http_parser.h"
#include "bpf_filter.h"
#include "stats.h"
#include "protocol_analyze.h"

/* 清空输入缓冲区 */
void clear_input_buffer(void)
{
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF) { }
}

/* 选择网卡 */
int select_device(char *device_name, int size)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    int count = 0;
    int choice;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Get devices failed: %s\n", errbuf);
        return -1;
    }

    printf("========== 可用网卡列表 ==========\n");
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        printf("%d. %s", ++count, dev->name);
        if (dev->description != NULL)
            printf(" - %s", dev->description);
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
    for (int i = 1; i < choice; i++)
        dev = dev->next;

    strncpy(device_name, dev->name, size - 1);
    device_name[size - 1] = '\0';

    pcap_freealldevs(alldevs);
    return 0;
}

/* ==================== 菜单函数 ==================== */

/* 1. 查看网卡列表 (已在 capture.c 中实现) */

/* 2. 实时抓包并统计 */
void menu_capture(void)
{
    char device_name[512];
    int count;
    pcap_t *handle;

    if (select_device(device_name, sizeof(device_name)) != 0) return;
    printf("请输入抓包数量: ");
    scanf("%d", &count);
    if (count <= 0) count = 10;

    handle = capture_init(device_name);
    if (handle == NULL) return;

    start_capture(handle);
    capture_packets_with_stats(handle, count);
    stop_capture(handle);
}

/* 3. 保存pcap文件 */
void menu_save_pcap(void)
{
    char device_name[512];
    char filename[256];
    int count;
    pcap_t *handle;

    if (select_device(device_name, sizeof(device_name)) != 0) return;
    printf("请输入抓包数量: ");
    scanf("%d", &count);
    if (count <= 0) count = 10;
    printf("请输入pcap文件名: ");
    scanf("%255s", filename);

    handle = capture_init(device_name);
    if (handle == NULL) return;

    start_capture(handle);
    capture_save_to_file(handle, count, filename);
    stop_capture(handle);
}

/* 4. 读取pcap文件 */
void menu_read_pcap(void)
{
    char filename[256];
    printf("请输入pcap文件名: ");
    scanf("%255s", filename);
    read_pcap_file(filename);
}

/* 5. BPF过滤抓包 */
void menu_filter_capture(void)
{
    char device_name[512];
    char filter_exp[256];
    int count;
    pcap_t *handle;

    if (select_device(device_name, sizeof(device_name)) != 0) return;
    printf("请输入抓包数量: ");
    scanf("%d", &count);
    if (count <= 0) count = 10;

    clear_input_buffer();
    printf("请输入BPF过滤规则，例如 tcp / udp / icmp / tcp port 80\n");
    printf("过滤规则: ");
    fgets(filter_exp, sizeof(filter_exp), stdin);
    filter_exp[strcspn(filter_exp, "\n")] = '\0';

    handle = capture_init(device_name);
    if (handle == NULL) return;

    if (apply_filter(handle, filter_exp) == 0) {
        start_capture(handle);
        capture_packets_with_stats(handle, count);
    }
    stop_capture(handle);
}

/* 6. 按过滤规则读取pcap文件 */
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

/* 7. 工具函数自测 */
void menu_self_test(void)
{
    net_utils_self_test();
}

/* 8. 性能测试 */
void menu_performance_test(void)
{
    char device_name[512];
    int seconds;
    pcap_t *handle;

    if (select_device(device_name, sizeof(device_name)) != 0) return;
    printf("请输入测试时长，单位秒：");
    scanf("%d", &seconds);

    handle = capture_init(device_name);
    if (handle == NULL) return;

    performance_capture_test(handle, seconds);
    stop_capture(handle);
}

/* 9. 协议分析 */
void menu_protocol_analyze(void)
{
    char filename[256];
    char filter_exp[256];
    int has_filter = 0;

    printf("请输入pcap文件名：");
    scanf("%255s", filename);
    clear_input_buffer();

    printf("是否使用BPF过滤规则？(y/n)：");
    int c = getchar();
    if (c == 'y' || c == 'Y') {
        clear_input_buffer();
        printf("请输入过滤规则：");
        fgets(filter_exp, sizeof(filter_exp), stdin);
        filter_exp[strcspn(filter_exp, "\n")] = '\0';
        has_filter = 1;
    } else {
        clear_input_buffer();
    }

    if (has_filter)
        analyze_pcap_file_with_filter(filename, filter_exp, 1);
    else
        analyze_pcap_file(filename, 1);
}

/* 10. DNS解析演示 */
void menu_dns_parse(void)
{
    char filename[256];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr *header;
    const u_char *data;
    int res;
    int dns_count = 0;
    int total = 0;

    printf("请输入pcap文件名：");
    scanf("%255s", filename);

    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        printf("打开文件失败：%s\n", errbuf);
        return;
    }

    printf("\n========== DNS报文解析 ==========\n");
    printf("文件：%s\n", filename);

    while ((res = pcap_next_ex(handle, &header, &data)) >= 0) {
        if (res == 0) continue;
        total++;

        ParsedPacket pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.ts = header->ts;
        pkt.packet_len = header->len;
        pkt.captured_len = header->caplen;

        if (analyze_packet(data, (uint32_t)header->caplen, &pkt) == 0) {
            if (pkt.app_proto == PROTO_DNS && pkt.payload_len > 0) {
                dns_count++;
                printf("\n--- DNS报文 #%d ---\n", dns_count);

                dns_result_t dns;
                if (parse_dns(pkt.payload, pkt.payload_len, &dns) == 0)
                    print_dns(&dns);
                else
                    printf("DNS解析失败\n");

                if (dns_count >= 20) {
                    printf("\n(已达20个DNS报文上限，停止解析)\n");
                    break;
                }
            }
        }
    }

    printf("\n--- DNS解析统计 ---\n");
    printf("总数据包数：%d\n", total);
    printf("DNS报文数  ：%d\n", dns_count);
    printf("=================================\n");

    pcap_close(handle);
}

/* 11. HTTP解析演示 */
void menu_http_parse(void)
{
    char filename[256];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr *header;
    const u_char *data;
    int res;
    int http_count = 0;
    int total = 0;

    printf("请输入pcap文件名：");
    scanf("%255s", filename);

    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        printf("打开文件失败：%s\n", errbuf);
        return;
    }

    printf("\n========== HTTP报文解析 ==========\n");
    printf("文件：%s\n", filename);

    while ((res = pcap_next_ex(handle, &header, &data)) >= 0) {
        if (res == 0) continue;
        total++;

        ParsedPacket pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.ts = header->ts;
        pkt.packet_len = header->len;
        pkt.captured_len = header->caplen;

        if (analyze_packet(data, (uint32_t)header->caplen, &pkt) == 0) {
            if ((pkt.app_proto == PROTO_HTTP_REQUEST ||
                 pkt.app_proto == PROTO_HTTP_RESPONSE) && pkt.payload_len > 0) {
                http_count++;
                printf("\n--- HTTP报文 #%d ---\n", http_count);

                http_result_t http;
                if (parse_http(pkt.payload, pkt.payload_len, &http) == 0)
                    print_http(&http);
                else
                    printf("HTTP解析失败\n");
                free_http_result(&http);

                if (http_count >= 20) {
                    printf("\n(已达20个HTTP报文上限，停止解析)\n");
                    break;
                }
            }
        }
    }

    printf("\n--- HTTP解析统计 ---\n");
    printf("总数据包数   ：%d\n", total);
    printf("HTTP报文数   ：%d\n", http_count);
    printf("==================================\n");

    pcap_close(handle);
}

/* 12. BPF过滤测试套件 */
void menu_bpf_test_suite(void)
{
    char filename[256];
    printf("请输入pcap文件名：");
    scanf("%255s", filename);
    bpf_run_test_suite(filename);
}

/* 13. BPF常见规则示例 */
void menu_bpf_rules(void)
{
    bpf_print_common_rules();

    printf("\n是否要测试某个规则？(y/n)：");
    clear_input_buffer();
    int c = getchar();
    if (c == 'y' || c == 'Y') {
        clear_input_buffer();
        char filename[256];
        char filter_exp[256];

        printf("请输入pcap文件名：");
        scanf("%255s", filename);
        clear_input_buffer();
        printf("请输入过滤规则：");
        fgets(filter_exp, sizeof(filter_exp), stdin);
        filter_exp[strcspn(filter_exp, "\n")] = '\0';

        bpf_filter_offline(filename, filter_exp);
    }
}

/* 14. 流量统计（实时抓包） */
void menu_stats_realtime(void)
{
    char device_name[512];
    int seconds;
    pcap_t *handle;
    stats_t stats;

    if (select_device(device_name, sizeof(device_name)) != 0) return;
    printf("请输入统计时长(秒，0=持续)：");
    scanf("%d", &seconds);

    handle = capture_init(device_name);
    if (handle == NULL) return;

    stats_capture(handle, seconds, &stats);
    stop_capture(handle);
}

/* 15. 流量统计（pcap文件） */
void menu_stats_pcap(void)
{
    char filename[256];
    stats_t stats;

    printf("请输入pcap文件名：");
    scanf("%255s", filename);

    if (stats_from_pcap(filename, &stats) == 0)
        stats_print(&stats);
}

/* 16. 流量统计（pcap文件+过滤） */
void menu_stats_pcap_filter(void)
{
    char filename[256];
    char filter_exp[256];
    stats_t stats;

    printf("请输入pcap文件名：");
    scanf("%255s", filename);
    clear_input_buffer();
    printf("请输入BPF过滤规则：");
    fgets(filter_exp, sizeof(filter_exp), stdin);
    filter_exp[strcspn(filter_exp, "\n")] = '\0';

    if (stats_from_pcap_with_filter(filename, filter_exp, &stats) == 0)
        stats_print(&stats);
}

/* ==================== 菜单显示 ==================== */

void show_menu(void)
{
    printf("\n========== 网络数据包捕获与协议解析工具 ==========\n");
    printf("--- 抓包与文件 ---\n");
    printf(" 1. 查看网卡列表\n");
    printf(" 2. 连续抓包并显示统计信息\n");
    printf(" 3. 抓包并保存为pcap文件\n");
    printf(" 4. 读取pcap文件回放\n");
    printf(" 5. 使用BPF过滤规则抓包\n");
    printf(" 6. 按BPF规则读取pcap文件\n");
    printf(" 7. 工具函数自测\n");
    printf(" 8. 抓包性能测试\n");
    printf("--- 协议解析与统计 ---\n");
    printf(" 9. 协议分析（解析pcap文件各层协议）\n");
    printf("10. DNS报文解析演示\n");
    printf("11. HTTP报文解析演示\n");
    printf("12. BPF过滤测试套件（批量规则测试）\n");
    printf("13. BPF常见规则示例\n");
    printf("14. 流量统计（实时抓包统计）\n");
    printf("15. 流量统计（pcap文件统计）\n");
    printf("16. 流量统计（pcap文件+BPF过滤）\n");
    printf(" 0. 退出程序\n");
    printf("===================================================\n");
    printf("请选择功能：");
}

int main()
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    int choice;

    while (1) {
        show_menu();
        scanf("%d", &choice);

        switch (choice) {
        case 1:  list_devices();             break;
        case 2:  menu_capture();             break;
        case 3:  menu_save_pcap();           break;
        case 4:  menu_read_pcap();           break;
        case 5:  menu_filter_capture();      break;
        case 6:  menu_read_pcap_with_filter(); break;
        case 7:  menu_self_test();           break;
        case 8:  menu_performance_test();    break;
        case 9:  menu_protocol_analyze();    break;
        case 10: menu_dns_parse();           break;
        case 11: menu_http_parse();          break;
        case 12: menu_bpf_test_suite();      break;
        case 13: menu_bpf_rules();           break;
        case 14: menu_stats_realtime();      break;
        case 15: menu_stats_pcap();          break;
        case 16: menu_stats_pcap_filter();   break;
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
