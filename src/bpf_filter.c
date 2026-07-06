/**
 * bpf_filter.c - BPF过滤规则封装模块实现
 *
 * 成员C负责模块
 *
 * 本模块封装了libpcap的BPF过滤功能，提供更友好的接口。
 * capture.c中已有简单的apply_filter()函数，本模块提供更完整的功能：
 *   - 规则语法验证（不实际抓包即可检查规则合法性）
 *   - 离线文件过滤
 *   - 过滤结果统计
 *   - 常见规则示例和测试套件
 *
 * pcap_compile参数说明：
 *   optimize=1: 启用BPF字节码优化，生成更高效的过滤代码
 *   netmask: 对于离线文件使用PCAP_NETMASK_UNKNOWN；
 *            对于实时抓包应使用网卡所在网段的子网掩码
 */

#include <stdio.h>
#include <string.h>
#include "bpf_filter.h"

int bpf_compile_and_set(pcap_t *handle, const char *filter_exp)
{
    struct bpf_program fp;

    if (handle == NULL || filter_exp == NULL) {
        printf("参数错误：handle或filter_exp为空\n");
        return -1;
    }

    /* 编译BPF规则：optimize=1启用优化，netmask=UNKNOWN适用于离线和大多数场景 */
    if (pcap_compile(handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("BPF规则编译失败：%s\n", pcap_geterr(handle));
        return -1;
    }

    /* 挂载过滤器到pcap句柄 */
    if (pcap_setfilter(handle, &fp) == -1) {
        printf("BPF规则挂载失败：%s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        return -1;
    }

    pcap_freecode(&fp);
    return 0;
}

int bpf_validate(const char *filter_exp)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *dead_handle;

    /* 创建一个"dead" pcap句柄专门用于规则校验 */
    dead_handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (dead_handle == NULL) {
        return 0;
    }

    struct bpf_program fp;
    int result = pcap_compile(dead_handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN);

    if (result == 0) {
        pcap_freecode(&fp);
    }

    pcap_close(dead_handle);
    (void)errbuf; /* 避免未使用变量警告 */
    return (result == 0) ? 1 : 0;
}

int bpf_validate_detail(const char *filter_exp, char *errbuf, int errbuf_size)
{
    pcap_t *dead_handle;

    dead_handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (dead_handle == NULL) {
        snprintf(errbuf, errbuf_size, "无法创建校验句柄");
        return 0;
    }

    struct bpf_program fp;
    int result = pcap_compile(dead_handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN);

    if (result == 0) {
        pcap_freecode(&fp);
        errbuf[0] = '\0';
    } else {
        snprintf(errbuf, errbuf_size, "%s", pcap_geterr(dead_handle));
    }

    pcap_close(dead_handle);
    return (result == 0) ? 1 : 0;
}

int bpf_filter_offline(const char *filename, const char *filter_exp)
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
        printf("打开pcap文件失败：%s\n", errbuf);
        return -1;
    }

    /* 编译并设置过滤规则 */
    if (bpf_compile_and_set(handle, filter_exp) != 0) {
        pcap_close(handle);
        return -1;
    }

    printf("\n========== BPF过滤读取 ==========\n");
    printf("文件名   ：%s\n", filename);
    printf("过滤规则 ：%s\n", filter_exp);
    printf("----------------------------------\n");

    while ((res = pcap_next_ex(handle, &header, &data)) >= 0) {
        if (res == 0) continue;

        count++;
        total_bytes += header->len;

        printf("[包 %d] 长度=%u字节 捕获=%u字节 时间=%ld.%06ld\n",
               count, header->len, header->caplen,
               (long)header->ts.tv_sec, (long)header->ts.tv_usec);
    }

    printf("\n--- 过滤统计 ---\n");
    printf("匹配包数   ：%d\n", count);
    printf("总字节数   ：%u\n", total_bytes);
    if (count > 0) {
        printf("平均包长度 ：%u字节\n", total_bytes / count);
    }
    printf("=================================\n");

    pcap_close(handle);
    return 0;
}

int bpf_filter_offline_with_stats(const char *filename, const char *filter_exp,
                                   int *total_out, int *matched_out)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr *header;
    const u_char *data;
    int res;
    int matched = 0;

    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        return -1;
    }

    /* 先统计总包数（不过滤） */
    int total = 0;
    while ((res = pcap_next_ex(handle, &header, &data)) >= 0) {
        if (res == 0) continue;
        total++;
    }
    pcap_close(handle);

    /* 重新打开并应用过滤 */
    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        return -1;
    }

    if (bpf_compile_and_set(handle, filter_exp) != 0) {
        pcap_close(handle);
        return -1;
    }

    while ((res = pcap_next_ex(handle, &header, &data)) >= 0) {
        if (res == 0) continue;
        matched++;
    }

    pcap_close(handle);

    if (total_out) *total_out = total;
    if (matched_out) *matched_out = matched;
    return 0;
}

void bpf_print_common_rules(void)
{
    printf("\n========== 常见BPF过滤规则示例 ==========\n");
    printf("\n--- 基础协议过滤 ---\n");
    printf("  tcp                      仅TCP流量\n");
    printf("  udp                      仅UDP流量\n");
    printf("  icmp                     仅ICMP流量\n");
    printf("  arp                      仅ARP流量\n");
    printf("  ip                       仅IPv4流量\n");
    printf("  ip6                      仅IPv6流量\n");

    printf("\n--- 端口过滤 ---\n");
    printf("  port 80                  源或目的端口80\n");
    printf("  port 53                  DNS流量\n");
    printf("  port 443                 HTTPS流量\n");
    printf("  src port 80              源端口80\n");
    printf("  dst port 53              目的端口53\n");
    printf("  portrange 80-90          端口范围80-90\n");

    printf("\n--- 主机过滤 ---\n");
    printf("  host 192.168.1.1         源或目的IP\n");
    printf("  src host 192.168.1.1     仅源IP\n");
    printf("  dst host 192.168.1.1     仅目的IP\n");
    printf("  net 192.168.1.0/24       整个网段\n");

    printf("\n--- 组合过滤 (AND/OR/NOT) ---\n");
    printf("  tcp port 80 and host 1.2.3.4\n");
    printf("  tcp port 80 or tcp port 443\n");
    printf("  not arp and not icmp\n");
    printf("  src host 192.168.1.1 and dst port 80\n");

    printf("\n--- 进阶过滤 ---\n");
    printf("  tcp[tcpflags] & tcp-syn != 0    SYN包\n");
    printf("  tcp[tcpflags] & tcp-fin != 0    FIN包\n");
    printf("  ip[8] = 1                       TTL=1的包\n");
    printf("  less 100                        包长度<100\n");
    printf("  greater 1000                    包长度>1000\n");
    printf("==========================================\n");
}

void bpf_run_test_suite(const char *filename)
{
    printf("\n========== BPF过滤规则测试套件 ==========\n");
    printf("测试文件：%s\n\n", filename);

    /* 测试规则列表 */
    struct {
        const char *rule;
        const char *desc;
    } tests[] = {
        {"tcp",                    "TCP协议过滤"},
        {"udp",                    "UDP协议过滤"},
        {"icmp",                   "ICMP协议过滤"},
        {"port 80",                "端口80过滤"},
        {"port 53",                "端口53(DNS)过滤"},
        {"port 443",               "端口443(HTTPS)过滤"},
        {"host 192.168.1.1",       "主机IP过滤"},
        {"tcp port 80",            "TCP+端口组合"},
        {"tcp port 80 and host 192.168.1.1", "AND组合"},
        {"tcp port 80 or tcp port 443",      "OR组合"},
        {"not arp",                "NOT排除"},
        {"src host 192.168.1.1",   "源IP过滤"},
        {"dst port 53",            "目的端口过滤"},
        {"",                       "空规则(匹配全部)"},
        {"!!!invalid",             "畸形规则(应失败)"},
    };

    int num_tests = sizeof(tests) / sizeof(tests[0]);
    int i;

    printf("%-45s %-20s %-10s %-10s %-10s\n",
           "规则", "描述", "合法性", "总包数", "匹配数");
    printf("--------------------------------------------------------------------------------\n");

    for (i = 0; i < num_tests; i++) {
        char errbuf[256];
        int valid;

        if (tests[i].rule[0] == '\0') {
            /* 空规则特殊处理 */
            valid = 1;
            errbuf[0] = '\0';
        } else {
            valid = bpf_validate_detail(tests[i].rule, errbuf, sizeof(errbuf));
        }

        if (!valid) {
            printf("%-45s %-20s %-10s\n",
                   tests[i].rule[0] ? tests[i].rule : "(空)",
                   tests[i].desc,
                   "不合法");
            continue;
        }

        int total = 0, matched = 0;
        if (bpf_filter_offline_with_stats(filename, tests[i].rule, &total, &matched) == 0) {
            printf("%-45s %-20s %-10s %-10d %-10d\n",
                   tests[i].rule[0] ? tests[i].rule : "(空)",
                   tests[i].desc,
                   "合法",
                   total,
                   matched);
        } else {
            printf("%-45s %-20s %-10s %-10s\n",
                   tests[i].rule[0] ? tests[i].rule : "(空)",
                   tests[i].desc,
                   "合法",
                   "文件错误");
        }
    }

    printf("================================================================================\n");
    printf("测试完成。\n");
}
