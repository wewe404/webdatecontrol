/**
 * stats.h - 流量统计模块接口
 *
 * 成员C负责模块
 * 功能：
 *   - 按协议类型实时统计报文数、字节数
 *   - 按IP地址对统计流量
 *   - 每秒刷新计算吞吐量（packets/s, Mbps）
 *   - 格式化输出统计报告
 *   - 支持实时抓包和离线文件统计
 *
 * 对应文档任务：
 *   第6天: 实现流量统计模块（按协议类型/IP地址统计、每秒刷新计算吞吐量）
 *   第8天: 流量统计可视化输出（格式化打印到终端）
 *   第10天: 流量统计准确性验证（与Wireshark Statistics对比）
 *   第11天: 协助A做性能测试，监控过滤+统计对吞吐的影响
 *
 * 统计数据结构设计：
 *   协议统计使用数组（协议类型有限，数组索引即可）
 *   IP统计使用简单哈希表（处理IP对聚合）
 */

#ifndef STATS_H
#define STATS_H

#include "common.h"
#include <pcap.h>

/* ---- 统计条目：按协议类型 ---- */
#define STATS_PROTO_COUNT 10

typedef struct {
    protocol_t  proto;          /* 协议类型 */
    const char *proto_name;     /* 协议名称 */
    uint64_t    packet_count;   /* 报文数 */
    uint64_t    byte_count;     /* 字节数 */
} proto_stat_t;

/* ---- 统计条目：按IP对 ---- */
#define STATS_IP_HASH_SIZE 257  /* 哈希表大小（素数） */
#define STATS_IP_MAX_ENTRIES 512

typedef struct {
    uint32_t src_ip;            /* 源IP（网络字节序），0表示空槽 */
    uint32_t dst_ip;            /* 目的IP（网络字节序） */
    uint64_t packet_count;      /* 报文数 */
    uint64_t byte_count;        /* 字节数 */
} ip_pair_stat_t;

/* ---- 主统计结构 ---- */
typedef struct {
    /* 协议统计 */
    proto_stat_t proto_stats[STATS_PROTO_COUNT];
    int          proto_stat_count;

    /* IP对统计（哈希表） */
    ip_pair_stat_t ip_stats[STATS_IP_MAX_ENTRIES];
    int            ip_stat_count;

    /* 总计统计 */
    uint64_t total_packets;     /* 总报文数 */
    uint64_t total_bytes;       /* 总字节数 */
    uint64_t filtered_packets;  /* 被过滤的报文数 */

    /* 时间相关统计 */
    struct timeval start_time;  /* 统计开始时间 */
    struct timeval last_time;   /* 上次刷新时间 */
    double         elapsed_sec; /* 总运行时间(秒) */

    /* 每秒速率统计 */
    double current_pps;         /* 当前每秒包数 */
    double current_bps;         /* 当前每秒字节数 */
    double avg_pps;             /* 平均每秒包数 */
    double avg_mbps;            /* 平均吞吐量(Mbps) */
} stats_t;

/**
 * stats_init - 初始化统计模块
 * @param stats 统计结构指针
 */
void stats_init(stats_t *stats);

/**
 * stats_update - 更新统计数据（每收到一个包调用）
 * @param stats    统计结构指针
 * @param pkt      已解析的数据包
 */
void stats_update(stats_t *stats, const ParsedPacket *pkt);

/**
 * stats_update_raw - 用原始数据包更新统计（不需要完整解析）
 * @param stats    统计结构指针
 * @param data     原始数据包
 * @param len      数据包长度
 */
void stats_update_raw(stats_t *stats, const uint8_t *data, uint32_t len);

/**
 * stats_refresh - 刷新每秒速率统计
 * @param stats 统计结构指针
 */
void stats_refresh(stats_t *stats);

/**
 * stats_print - 打印完整统计报告
 * @param stats 统计结构指针
 */
void stats_print(const stats_t *stats);

/**
 * stats_print_proto - 仅打印协议统计
 * @param stats 统计结构指针
 */
void stats_print_proto(const stats_t *stats);

/**
 * stats_print_ip - 仅打印IP对统计
 * @param stats 统计结构指针
 */
void stats_print_ip(const stats_t *stats);

/**
 * stats_print_summary - 打印摘要统计（适合状态栏显示）
 * @param stats 统计结构指针
 */
void stats_print_summary(const stats_t *stats);

/**
 * stats_capture - 带统计的实时抓包
 * @param handle  pcap句柄
 * @param seconds 抓包时长(秒)，0表示持续到用户中断
 * @param stats   统计结构指针
 */
void stats_capture(pcap_t *handle, int seconds, stats_t *stats);

/**
 * stats_from_pcap - 从pcap文件统计流量
 * @param filename pcap文件名
 * @param stats    统计结构指针
 * @return 0成功, -1失败
 */
int stats_from_pcap(const char *filename, stats_t *stats);

/**
 * stats_from_pcap_with_filter - 从pcap文件按BPF过滤统计流量
 * @param filename   pcap文件名
 * @param filter_exp BPF过滤规则，NULL表示不过滤
 * @param stats      统计结构指针
 * @return 0成功, -1失败
 */
int stats_from_pcap_with_filter(const char *filename, const char *filter_exp,
                                 stats_t *stats);

#endif /* STATS_H */
