/**
 * stats.c - 流量统计模块实现
 *
 * 统计策略：
 *   1. 协议统计：使用固定数组，索引对应protocol_t枚举值
 *   2. IP对统计：使用开放寻址哈希表
 *   3. 每秒速率：在stats_refresh()中计算
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#ifdef _WIN32
#include <winsock2.h>
#include <sys/timeb.h>
#else
#include <arpa/inet.h>
#include <sys/time.h>
#endif
#include "stats.h"
#include "protocol_analyze.h"
#include "bpf_filter.h"

static const char *proto_name(protocol_t proto)
{
    switch (proto) {
    case PROTO_UNKNOWN:       return "Unknown";
    case PROTO_IPV4:          return "IPv4";
    case PROTO_IPV6:          return "IPv6";
    case PROTO_TCP:           return "TCP";
    case PROTO_UDP:           return "UDP";
    case PROTO_ICMP:          return "ICMP";
    case PROTO_DNS:           return "DNS";
    case PROTO_HTTP_REQUEST:  return "HTTP-Req";
    case PROTO_HTTP_RESPONSE: return "HTTP-Rsp";
    case PROTO_ARP:           return "ARP";
    default:                  return "Other";
    }
}

static double timeval_diff_ms(struct timeval *start, struct timeval *end)
{
    double sec = (double)(end->tv_sec - start->tv_sec);
    double usec = (double)(end->tv_usec - start->tv_usec);
    return sec * 1000.0 + usec / 1000.0;
}

static unsigned int ip_hash(uint32_t src_ip, uint32_t dst_ip)
{
    uint32_t key = src_ip ^ dst_ip;
    key = (key ^ (key >> 16)) * 0x45d9f3b;
    key = (key ^ (key >> 16)) * 0x45d9f3b;
    key = key ^ (key >> 16);
    return (unsigned int)(key % STATS_IP_MAX_ENTRIES);
}

static ip_pair_stat_t *find_or_create_ip_stat(stats_t *stats,
                                               uint32_t src_ip, uint32_t dst_ip)
{
    if (stats->ip_stat_count >= STATS_IP_MAX_ENTRIES)
        return &stats->ip_stats[0];

    unsigned int idx = ip_hash(src_ip, dst_ip);

    for (int i = 0; i < STATS_IP_MAX_ENTRIES; i++) {
        unsigned int probe = (idx + i) % STATS_IP_MAX_ENTRIES;
        ip_pair_stat_t *entry = &stats->ip_stats[probe];

        if (entry->packet_count == 0) {
            entry->src_ip = src_ip;
            entry->dst_ip = dst_ip;
            stats->ip_stat_count++;
            return entry;
        }

        if ((entry->src_ip == src_ip && entry->dst_ip == dst_ip) ||
            (entry->src_ip == dst_ip && entry->dst_ip == src_ip)) {
            return entry;
        }
    }

    return &stats->ip_stats[0];
}

void stats_init(stats_t *stats)
{
    if (stats == NULL) return;

    memset(stats, 0, sizeof(stats_t));

    protocol_t protos[] = {
        PROTO_UNKNOWN, PROTO_IPV4, PROTO_IPV6, PROTO_TCP, PROTO_UDP,
        PROTO_ICMP, PROTO_DNS, PROTO_HTTP_REQUEST, PROTO_HTTP_RESPONSE, PROTO_ARP
    };
    const char *names[] = {
        "Unknown", "IPv4", "IPv6", "TCP", "UDP",
        "ICMP", "DNS", "HTTP-Req", "HTTP-Rsp", "ARP"
    };

    for (int i = 0; i < STATS_PROTO_COUNT; i++) {
        stats->proto_stats[i].proto = protos[i];
        stats->proto_stats[i].proto_name = names[i];
    }
    stats->proto_stat_count = STATS_PROTO_COUNT;

#ifdef _WIN32
    struct _timeb tb;
    _ftime(&tb);
    stats->start_time.tv_sec = (long)tb.time;
    stats->start_time.tv_usec = tb.millitm * 1000;
#else
    gettimeofday(&stats->start_time, NULL);
#endif
    stats->last_time = stats->start_time;
}

static void update_proto_stat(stats_t *stats, protocol_t proto, uint32_t len)
{
    for (int i = 0; i < stats->proto_stat_count; i++) {
        if (stats->proto_stats[i].proto == proto) {
            stats->proto_stats[i].packet_count++;
            stats->proto_stats[i].byte_count += len;
            return;
        }
    }
    stats->proto_stats[0].packet_count++;
    stats->proto_stats[0].byte_count += len;
}

void stats_update(stats_t *stats, const ParsedPacket *pkt)
{
    if (stats == NULL || pkt == NULL) return;

    stats->total_packets++;
    stats->total_bytes += pkt->packet_len;

    if (pkt->layer3_proto != PROTO_UNKNOWN)
        update_proto_stat(stats, pkt->layer3_proto, pkt->packet_len);
    if (pkt->layer4_proto != PROTO_UNKNOWN)
        update_proto_stat(stats, pkt->layer4_proto, pkt->packet_len);
    if (pkt->app_proto != PROTO_UNKNOWN)
        update_proto_stat(stats, pkt->app_proto, pkt->packet_len);
    if (pkt->layer3_proto == PROTO_UNKNOWN && pkt->layer4_proto == PROTO_UNKNOWN)
        update_proto_stat(stats, PROTO_UNKNOWN, pkt->packet_len);

    if (pkt->layer3_proto == PROTO_IPV4) {
        ip_pair_stat_t *entry = find_or_create_ip_stat(stats,
                                                        pkt->ipv4.src_ip,
                                                        pkt->ipv4.dst_ip);
        entry->packet_count++;
        entry->byte_count += pkt->packet_len;
    }
}

void stats_update_raw(stats_t *stats, const uint8_t *data, uint32_t len)
{
    if (stats == NULL || data == NULL || len == 0) return;

    ParsedPacket pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.packet_len = len;
    pkt.captured_len = len;

    if (analyze_packet(data, len, &pkt) == 0) {
        stats_update(stats, &pkt);
    } else {
        stats->total_packets++;
        stats->total_bytes += len;
        update_proto_stat(stats, PROTO_UNKNOWN, len);
    }
}

void stats_refresh(stats_t *stats)
{
    if (stats == NULL) return;

    struct timeval now;
#ifdef _WIN32
    struct _timeb tb;
    _ftime(&tb);
    now.tv_sec = (long)tb.time;
    now.tv_usec = tb.millitm * 1000;
#else
    gettimeofday(&now, NULL);
#endif

    double total_sec = timeval_diff_ms(&stats->start_time, &now) / 1000.0;
    stats->last_time = now;
    stats->elapsed_sec = total_sec;

    if (total_sec > 0) {
        stats->avg_pps = (double)stats->total_packets / total_sec;
        stats->avg_mbps = ((double)stats->total_bytes * 8.0) / total_sec / 1000000.0;
    }
}

void stats_print_proto(const stats_t *stats)
{
    printf("\n--- 按协议类型统计 ---\n");
    printf("%-15s %-15s %-15s %-10s\n", "协议", "报文数", "字节数", "占比");
    printf("------------------------------------------------------------\n");

    for (int i = 0; i < stats->proto_stat_count; i++) {
        if (stats->proto_stats[i].packet_count == 0) continue;

        double pct = stats->total_packets > 0 ?
            (double)stats->proto_stats[i].packet_count * 100.0 / stats->total_packets : 0;

        printf("%-15s %-15llu %-15llu %.1f%%\n",
               stats->proto_stats[i].proto_name,
               (unsigned long long)stats->proto_stats[i].packet_count,
               (unsigned long long)stats->proto_stats[i].byte_count,
               pct);
    }
    printf("------------------------------------------------------------\n");
}

void stats_print_ip(const stats_t *stats)
{
    printf("\n--- 按IP对统计 ---\n");
    printf("%-18s %-20s %-15s %-15s\n", "源IP", "目的IP", "报文数", "字节数");
    printf("------------------------------------------------------------------------\n");

    int shown = 0;
    for (int i = 0; i < STATS_IP_MAX_ENTRIES && shown < 50; i++) {
        if (stats->ip_stats[i].packet_count == 0) continue;

        char src_buf[32], dst_buf[32];
        unsigned char *src = (unsigned char *)&stats->ip_stats[i].src_ip;
        unsigned char *dst = (unsigned char *)&stats->ip_stats[i].dst_ip;
        snprintf(src_buf, sizeof(src_buf), "%u.%u.%u.%u", src[0], src[1], src[2], src[3]);
        snprintf(dst_buf, sizeof(dst_buf), "%u.%u.%u.%u", dst[0], dst[1], dst[2], dst[3]);

        printf("%-18s %-20s %-15llu %-15llu\n",
               src_buf, dst_buf,
               (unsigned long long)stats->ip_stats[i].packet_count,
               (unsigned long long)stats->ip_stats[i].byte_count);
        shown++;
    }

    if (shown == 0)
        printf("  (无IP对统计数据)\n");
    else if (stats->ip_stat_count > 50)
        printf("  ... (共 %d 个IP对，仅显示前50个)\n", stats->ip_stat_count);

    printf("------------------------------------------------------------------------\n");
}

void stats_print_summary(const stats_t *stats)
{
    printf("总包数=%llu 总字节=%llu ",
           (unsigned long long)stats->total_packets,
           (unsigned long long)stats->total_bytes);
    if (stats->elapsed_sec > 0)
        printf("平均速率=%.1f pps %.4f Mbps", stats->avg_pps, stats->avg_mbps);
    printf("\n");
}

void stats_print(const stats_t *stats)
{
    if (stats == NULL) return;

    printf("\n========== 流量统计报告 ==========\n");
    printf("统计时长     : %.2f 秒\n", stats->elapsed_sec);
    printf("总报文数     : %llu\n", (unsigned long long)stats->total_packets);
    printf("总字节数     : %llu (%.2f MB)\n",
           (unsigned long long)stats->total_bytes,
           (double)stats->total_bytes / (1024.0 * 1024.0));
    printf("IP对数量     : %d\n", stats->ip_stat_count);

    if (stats->elapsed_sec > 0) {
        printf("平均包速率   : %.2f packets/s\n", stats->avg_pps);
        printf("平均吞吐量   : %.4f Mbps\n", stats->avg_mbps);
        printf("平均包大小   : %.1f bytes\n",
               stats->total_packets > 0 ?
               (double)stats->total_bytes / stats->total_packets : 0);
    }

    stats_print_proto(stats);
    stats_print_ip(stats);
    printf("===================================\n");
}

void stats_capture(pcap_t *handle, int seconds, stats_t *stats)
{
    if (handle == NULL || stats == NULL) return;

    struct pcap_pkthdr *header;
    const u_char *data;
    int res;

    stats_init(stats);

    printf("\n========== 实时流量统计 ==========\n");
    if (seconds > 0)
        printf("统计时长：%d 秒\n", seconds);
    else
        printf("持续统计中（按Ctrl+C停止）...\n");
    printf("----------------------------------\n");

    time_t start = time(NULL);
    time_t last_print = start;
    uint64_t last_packets = 0;
    uint64_t last_bytes = 0;

    while (1) {
        res = pcap_next_ex(handle, &header, &data);

        if (res == 1) {
            stats_update_raw(stats, data, (uint32_t)header->caplen);

            time_t now = time(NULL);
            if (now - last_print >= 1) {
                uint64_t delta_packets = stats->total_packets - last_packets;
                uint64_t delta_bytes = stats->total_bytes - last_bytes;
                double pps = (double)delta_packets;
                double mbps = (double)delta_bytes * 8.0 / 1000000.0;

                printf("[%lds] 包数=%llu 速率=%.0f pps %.4f Mbps\n",
                       (long)(now - start),
                       (unsigned long long)stats->total_packets,
                       pps, mbps);

                last_print = now;
                last_packets = stats->total_packets;
                last_bytes = stats->total_bytes;
            }

            if (seconds > 0 && (int)(now - start) >= seconds) break;
        } else if (res == 0) {
            if (seconds > 0) {
                time_t now = time(NULL);
                if ((int)(now - start) >= seconds) break;
            }
            continue;
        } else {
            printf("抓包错误。\n");
            break;
        }
    }

    stats_refresh(stats);
    stats_print(stats);
}

int stats_from_pcap(const char *filename, stats_t *stats)
{
    return stats_from_pcap_with_filter(filename, NULL, stats);
}

int stats_from_pcap_with_filter(const char *filename, const char *filter_exp,
                                 stats_t *stats)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr *header;
    const u_char *data;
    int res;

    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        printf("打开pcap文件失败：%s\n", errbuf);
        return -1;
    }

    if (filter_exp != NULL && filter_exp[0] != '\0') {
        if (bpf_compile_and_set(handle, filter_exp) != 0) {
            pcap_close(handle);
            return -1;
        }
    }

    stats_init(stats);

    while ((res = pcap_next_ex(handle, &header, &data)) >= 0) {
        if (res == 0) continue;
        stats_update_raw(stats, data, (uint32_t)header->caplen);
    }

    stats_refresh(stats);
    pcap_close(handle);
    return 0;
}
