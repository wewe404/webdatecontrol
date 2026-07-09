/**
 * tcp_reassembly.h — TCP 流重组模块接口
 *
 * 按四元组 (src_ip, dst_ip, src_port, dst_port) 索引 TCP 流，
 * 按序列号排序重组载荷，提取完整 HTTP 请求/响应。
 *
 * 验收标准：能完整提取 ≥ 5 个真实网页请求的请求/响应对。
 */

#ifndef TCP_REASSEMBLY_H
#define TCP_REASSEMBLY_H

#include "common.h"
#include <stdio.h>

/* 配置常量 */
#define TR_MAX_STREAMS      512      /* 最多同时跟踪的流数 */
#define TR_MAX_DATA_PER_SIDE (256 * 1024)  /* 每方向最大 256KB */
#define TR_OUTPUT_DIR       "reassembly_output"  /* 输出目录 */

/* TCP 流方向 */
typedef enum {
    TR_DIR_CLIENT = 0,   /* 发起连接的一方 */
    TR_DIR_SERVER = 1    /* 接受连接的一方 */
} tr_dir_t;

/* 单向半流：累积某一方向的数据 */
typedef struct {
    uint8_t  *data;           /* 累积的载荷 */
    uint32_t  data_len;       /* 当前累积长度 */
    uint32_t  data_cap;       /* 缓冲区容量 */
    uint32_t  next_seq;       /* 期望的下一个序列号（相对） */
    uint32_t  base_seq;       /* 该方向第一个包的 seq（绝对） */
    int       has_syn;        /* 是否见过 SYN */
    int       has_fin;        /* 是否见过 FIN */
    int       initialized;    /* base_seq 是否已设置 */
} tr_half_stream_t;

/* TCP 流完整状态 */
typedef struct {
    uint32_t  src_ip;
    uint32_t  dst_ip;
    uint16_t  src_port;
    uint16_t  dst_port;

    tr_half_stream_t half[2];  /* 0=发出 SYN 方, 1=响应方 */

    int       complete;        /* 双向 FIN 或标记完成 */
    int       slot_used;       /* 此槽位是否被占用 */
    struct timeval start_ts;   /* 流起始时间 */
} tcp_stream_t;

/* 重组器 */
typedef struct {
    tcp_stream_t streams[TR_MAX_STREAMS];
    int          stream_count;
    int          total_packets_fed;
    int          total_bytes_reassembled;
} TcpReassembler;

/* ---- API ---- */

/* 初始化重组器 */
void tr_init(TcpReassembler *tr);

/* 向重组器喂一个已解析的数据包（仅 TCP 包有意义） */
void tr_feed(TcpReassembler *tr, const ParsedPacket *pkt);

/* 标记所有未完成流为完成（在处理完所有包后调用） */
void tr_flush_all(TcpReassembler *tr);

/* 将已完成流中的 HTTP 请求/响应写入输出目录下的文件 */
/* 返回成功写入的文件对数 */
int tr_write_http_pairs(TcpReassembler *tr);

/* 打印统计信息 */
void tr_print_stats(const TcpReassembler *tr);

/* 从一个 pcap 文件执行完整的 TCP 重组 + HTTP 提取 */
/* filename: pcap 文件路径 */
/* filter_exp: BPF 过滤规则（可 NULL） */
/* 返回提取到的 HTTP 会话数 */
int tcp_reassemble_from_pcap(const char *filename, const char *filter_exp);

#endif /* TCP_REASSEMBLY_H */
