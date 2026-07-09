#ifndef STATS_H
#define STATS_H

#include "common.h"
#include <pcap.h>

#define STATS_PROTO_COUNT 10

typedef struct {
    protocol_t  proto;
    const char *proto_name;
    uint64_t    packet_count;
    uint64_t    byte_count;
} proto_stat_t;

#define STATS_IP_HASH_SIZE 257
#define STATS_IP_MAX_ENTRIES 512

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint64_t packet_count;
    uint64_t byte_count;
} ip_pair_stat_t;

typedef struct {
    proto_stat_t proto_stats[STATS_PROTO_COUNT];
    int          proto_stat_count;

    ip_pair_stat_t ip_stats[STATS_IP_MAX_ENTRIES];
    int            ip_stat_count;

    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t filtered_packets;

    struct timeval start_time;
    struct timeval last_time;
    double         elapsed_sec;

    double current_pps;
    double current_bps;
    double avg_pps;
    double avg_mbps;
} stats_t;

void stats_init(stats_t *stats);
void stats_update(stats_t *stats, const ParsedPacket *pkt);
void stats_update_raw(stats_t *stats, const uint8_t *data, uint32_t len);
void stats_refresh(stats_t *stats);
void stats_print(const stats_t *stats);
void stats_print_proto(const stats_t *stats);
void stats_print_ip(const stats_t *stats);
void stats_print_summary(const stats_t *stats);
void stats_capture(pcap_t *handle, int seconds, stats_t *stats);
int stats_from_pcap(const char *filename, stats_t *stats);
int stats_from_pcap_with_filter(const char *filename, const char *filter_exp,
                                 stats_t *stats);

#endif
