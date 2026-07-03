/*
 * main.c — 主程序入口
 * ====================
 *
 * 功能说明（整合所有模块）：
 *   1. 选择网卡 -> 实时抓包
 *   2. 输入 BPF 过滤表达式（可选）
 *   3. 抓包 -> 协议解析 -> 显示
 *
 * 运行模式：
 *   普通模式: 交互式，选网卡 + 输过滤表达式
 *   测试模式: 传递参数 --test，跳过交互，自动选第一个物理网卡
 *             如: main.exe --test
 *             或: main.exe --test "tcp port 80"
 *
 * 注意：Npcap 抓包需要管理员权限！
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "capture.h"
#include "protocol.h"
#include "bpf_filter.h"

/* ========== 全局配置 ========== */
static int g_verbose = 0;
static int g_hexdump = 0;
static int g_packet_count = 0;
static int g_filtered_count = 0;

/* ========== 前向声明 ========== */
static void print_packet_fields(const Packet *pkt);
static void hex_dump(const unsigned char *data, unsigned int len);

/* ========== 回调函数 ========== */

void on_packet(Packet *pkt, void *userdata)
{
    BpfContext *bpf = (BpfContext*)userdata;
    g_packet_count++;

    if (bpf && bpf->compiled) {
        if (!bpf_match(bpf, pkt)) {
            return;
        }
    }
    g_filtered_count++;

    parse_packet(pkt);

    print_packet_summary(pkt);

    printf("  [");
    for (int i = 0; i < pkt->proto_depth; i++) {
        if (i > 0) printf(" > ");
        printf("%s", protocol_name(pkt->proto_stack[i]));
    }
    printf("]\n");

    if (g_verbose) {
        printf("\n");
        print_packet_fields(pkt);
    }

    if (g_hexdump) {
        hex_dump(pkt->data, pkt->data_len > 64 ? 64 : pkt->data_len);
    }

    printf("\n");
}

/* ========== 辅助显示函数 ========== */

static void print_packet_fields(const Packet *pkt)
{
    if (!pkt || !pkt->data || pkt->data_len < 14) return;

    const unsigned char *data = pkt->data;
    unsigned int len = pkt->data_len;

    EthHeader eth;
    if (parse_ethernet(data, len, &eth) < 0) return;
    print_ethernet(&eth);

    if (eth.ether_type == 0x0800) {
        Ipv4Header ipv4;
        int ip4_hlen = parse_ipv4(data + 14, len - 14, &ipv4);
        if (ip4_hlen < 0) return;
        print_ipv4(&ipv4);

        const unsigned char *l4 = data + 14 + ip4_hlen;
        unsigned int l4len = ipv4.total_length - ip4_hlen;

        switch (ipv4.protocol) {
            case 1: {
                IcmpHeader icmp;
                if (parse_icmp(l4, l4len, &icmp) > 0) print_icmp(&icmp);
                break;
            }
            case 6: {
                TcpHeader tcp;
                int tcp_hlen = parse_tcp(l4, l4len, &tcp);
                if (tcp_hlen > 0) {
                    print_tcp(&tcp, l4, l4len);
                    const unsigned char *l7 = l4 + tcp_hlen;
                    unsigned int l7len = l4len - tcp_hlen;
                    if (l7len > 0 && (tcp.dst_port == 80 || tcp.src_port == 80 ||
                                       tcp.dst_port == 8080 || tcp.src_port == 8080)) {
                        HttpInfo http;
                        if (parse_http(l7, l7len, &http) > 0) print_http(&http);
                    }
                }
                break;
            }
            case 17: {
                UdpHeader udp;
                if (parse_udp(l4, l4len, &udp) > 0) {
                    print_udp(&udp);
                    if (udp.src_port == 53 || udp.dst_port == 53) {
                        DnsHeader dns;
                        if (parse_dns(l4 + 8, l4len - 8, &dns) > 0)
                            print_dns(&dns, l4 + 8, l4len - 8);
                    }
                }
                break;
            }
        }
    } else if (eth.ether_type == 0x86DD) {
        Ipv6Header ipv6;
        int ip6_hlen = parse_ipv6(data + 14, len - 14, &ipv6);
        if (ip6_hlen < 0) return;
        print_ipv6(&ipv6);
    }
}

static void hex_dump(const unsigned char *data, unsigned int len)
{
    for (unsigned int i = 0; i < len; i += 16) {
        printf("  0x%04x: ", i);
        for (unsigned int j = 0; j < 16; j++) {
            if (i + j < len)
                printf("%02x ", data[i + j]);
            else
                printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" ");
        for (unsigned int j = 0; j < 16 && i + j < len; j++) {
            unsigned char c = data[i + j];
            printf("%c", (c >= 32 && c < 127) ? c : '.');
        }
        printf("\n");
    }
}

/* ========== 测试模式（跳过交互输入）========== */

static int run_test_mode(const char *filter_expr)
{
    printf("[1/6] 正在枚举网卡...\n");
    int count = list_devices();
    if (count <= 0) {
        printf("[-] 未找到可用网卡。\n");
        printf("    提示: 请以管理员身份运行此程序\n");
        return 1;
    }

    /* 优先挑选物理网卡：WiFi > 有线网卡 > 其他，跳过虚拟网卡 */
    int chosen = -1;
    int wifi_idx = -1;
    int eth_idx = -1;
    int first_real = -1;

    for (int i = 1; i <= count; i++) {
        const char *desc = get_device_desc(i);
        const char *name = get_device_by_index(i);

        /* 跳过明确的虚拟网卡 */
        if (desc) {
            if (strstr(desc, "VMware") || strstr(desc, "VirtualBox") ||
                strstr(desc, "WAN Miniport") || strstr(desc, "TAP-Windows") ||
                strstr(desc, "Radmin VPN") || strstr(desc, "Bluetooth") ||
                strstr(desc, "Wi-Fi Direct"))
                continue;
            if (name && strstr(name, "NPF_Loopback"))
                continue;
        }

        if (first_real < 0) first_real = i;

        if (desc) {
            if (strstr(desc, "Wi-Fi") || strstr(desc, "Wireless") || strstr(desc, "WLAN")) {
                if (wifi_idx < 0) wifi_idx = i;
                continue;
            }
            if (strstr(desc, "Ethernet") || strstr(desc, "GbE") ||
                strstr(desc, "Realtek") || strstr(desc, "Intel") ||
                strstr(desc, "PCIe")) {
                if (eth_idx < 0) eth_idx = i;
                continue;
            }
        }
    }

    /* 优先级: WiFi > 有线 > 第一个物理网卡 */
    if (wifi_idx > 0)      chosen = wifi_idx;
    else if (eth_idx > 0)  chosen = eth_idx;
    else if (first_real > 0) chosen = first_real;
    else                   chosen = 1;

    if (wifi_idx > 0 || eth_idx > 0) {
        printf("    探测到物理网卡: ");
        if (wifi_idx > 0) printf("[WiFi #%d] ", wifi_idx);
        if (eth_idx > 0)  printf("[Ethernet #%d] ", eth_idx);
        printf("\n");
    }

    const char *dev_name = get_device_by_index(chosen);
    printf("[2/6] 选择网卡: #%d %s\n", chosen, dev_name ? dev_name : "(null)");
    if (!dev_name) {
        printf("[-] 无效的网卡编号\n");
        free_device_list();
        return 1;
    }

    /* BPF 过滤 */
    BpfContext bpf;
    memset(&bpf, 0, sizeof(bpf));

    if (filter_expr && strlen(filter_expr) > 0) {
        printf("[3/6] 编译 BPF 过滤: \"%s\"\n", filter_expr);
        if (bpf_compile(&bpf, filter_expr, 65535, 1) != 0) {
            printf("[-] BPF 编译失败，不过滤\n");
        }
    } else {
        printf("[3/6] 未设置 BPF 过滤，捕获所有包\n");
    }

    printf("[4/6] 打开网卡 \"%s\"...\n", dev_name);
    pcap_t *handle = capture_init(dev_name);
    if (!handle) {
        printf("[-] 打开网卡失败！\n");
        printf("    最常见原因: 未以管理员权限运行\n");
        bpf_destroy(&bpf);
        free_device_list();
        return 1;
    }

    printf("[5/6] 开始抓包（等待 10 个包，最多等 30 秒超时）...\n");
    printf("     提示: 在另一个窗口执行 ping -t 114.114.114.114 产生流量\n\n");

    /* 增加超时检测：最多等 30 秒 */
    int ret = start_capture_loop(handle, on_packet, &bpf, 10);

    printf("\n[6/6] 抓包结束\n");
    printf("  总捕获包数:     %d\n", g_packet_count);
    printf("  通过过滤包数:   %d\n", g_filtered_count);

    stop_capture(handle);
    bpf_destroy(&bpf);
    free_device_list();

    if (ret != 0) {
        printf("[-] start_capture_loop 返回: %d\n", ret);
    }

    return 0;
}

/* ========== 交互模式 ========== */

static int run_interactive_mode(void)
{
    printf("[1/6] 正在枚举网卡...\n");
    int count = list_devices();
    if (count <= 0) {
        printf("[-] 未找到可用网卡。\n");
        printf("    提示: 请以管理员身份运行此程序\n");
        return 1;
    }

    int choice;
    printf("\n请输入要抓包的网卡编号 (1-%d): ", count);
    if (scanf("%d", &choice) != 1) {
        printf("[-] 输入无效\n");
        while (getchar() != '\n');
        return 1;
    }
    while (getchar() != '\n');

    if (choice < 1 || choice > count) {
        printf("[-] 无效的网卡编号\n");
        return 1;
    }

    const char *dev_name = get_device_by_index(choice);
    if (!dev_name) {
        printf("[-] 获取网卡名称失败\n");
        return 1;
    }
    printf("[2/6] 选择网卡: #%d %s\n", choice, dev_name);

    /* BPF */
    BpfContext bpf;
    memset(&bpf, 0, sizeof(bpf));

    printf("[3/6] BPF 过滤表达式（留空=不过滤）:\n");
    printf("  示例: tcp port 80\n");
    printf("  示例: host 192.168.1.1\n");
    printf("  示例: tcp port 80 and host 192.168.1.1\n");
    printf("  > ");
    char filter_expr[256] = "";
    if (fgets(filter_expr, sizeof(filter_expr), stdin)) {
        size_t flen = strlen(filter_expr);
        if (flen > 0 && filter_expr[flen - 1] == '\n')
            filter_expr[flen - 1] = '\0';
    }

    if (strlen(filter_expr) > 0) {
        if (bpf_compile(&bpf, filter_expr, 65535, 1) != 0) {
            printf("[-] BPF 编译失败，不过滤\n");
        }
    }

    /* 显示选项 */
    char buf[8];
    printf("\n详细模式? (y/n, 默认 n): ");
    if (fgets(buf, sizeof(buf), stdin) && (buf[0]=='y'||buf[0]=='Y'))
        g_verbose = 1;

    printf("十六进制显示? (y/n, 默认 n): ");
    if (fgets(buf, sizeof(buf), stdin) && (buf[0]=='y'||buf[0]=='Y'))
        g_hexdump = 1;

    int capture_count = 10;
    char cnt[16];
    printf("抓包数量 (默认 10): ");
    if (fgets(cnt, sizeof(cnt), stdin)) {
        int n = atoi(cnt);
        if (n > 0) capture_count = n;
    }

    /* 打开网卡 */
    printf("[4/6] 打开网卡 \"%s\"...\n", dev_name);
    pcap_t *handle = capture_init(dev_name);
    if (!handle) {
        printf("[-] 打开网卡失败！请以管理员权限运行\n");
        bpf_destroy(&bpf);
        free_device_list();
        return 1;
    }

    printf("[5/6] 开始抓包（共 %d 个包）...\n", capture_count);
    printf("     提示: 在另一个窗口执行 ping -t 114.114.114.114 产生流量\n\n");

    int ret = start_capture_loop(handle, on_packet, &bpf, capture_count);

    printf("\n[6/6] 抓包结束\n");
    printf("  总捕获包数:     %d\n", g_packet_count);
    printf("  通过过滤包数:   %d\n", g_filtered_count);
    if (strlen(filter_expr) > 0)
        printf("  过滤表达式:     \"%s\"\n", filter_expr);

    stop_capture(handle);
    bpf_destroy(&bpf);
    free_device_list();

    if (ret != 0) {
        printf("[-] start_capture_loop 返回: %d（0=成功, -1=错误, -2=中断）\n", ret);
    }

    return 0;
}

/* ========== 主入口 ========== */

int main(int argc, char *argv[])
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    setbuf(stdout, NULL);  /* 立即刷新，不缓冲，方便管道调试 */

    /* 检查是否以管理员运行（仅提示，不阻止）*/
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elev;
    DWORD size = sizeof(TOKEN_ELEVATION);
    int is_admin = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken) &&
        GetTokenInformation(hToken, TokenElevation, &elev, size, &size)) {
        is_admin = elev.TokenIsElevated;
    }
    if (hToken) CloseHandle(hToken);

    if (!is_admin) {
        printf("\n=========================================================\n");
        printf("  [!] 未以管理员权限运行！\n");
        printf("\n");
        printf("  Npcap 在 Windows 上需要管理员权限才能抓包。\n");
        printf("\n");
        printf("  正确打开方式：\n");
        printf("    1. 关闭此窗口\n");
        printf("    2. 开始菜单搜索 cmd → 右键 → 以管理员身份运行\n");
        printf("    3. cd /d E:\\\\作业\\\\26年软件工程实践\\\\clone\n");
        printf("    4. main.exe --test\n");
        printf("\n=========================================================\n");
        printf("按 Enter 键退出...");
        getchar();
        return 1;
    }

    if (argc >= 2 && strcmp(argv[1], "--test") == 0) {
        /* 测试模式 */
        const char *filter = (argc >= 3) ? argv[2] : NULL;
        return run_test_mode(filter);
    } else {
        /* 交互模式 */
        return run_interactive_mode();
    }
}
