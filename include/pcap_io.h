#ifndef PCAP_IO_H
#define PCAP_IO_H

/*
 * pcap_io.h - PCAP 文件读写模块
 * ==============================
 * 职责：
 *   1. 将抓到的数据包写入 .pcap 文件（保存抓包结果）
 *   2. 从 .pcap 文件读取数据包并回放（离线分析/测试）
 *
 * .pcap 文件格式简介：
 *   [Global Header] (24 字节)
 *   [Packet Record 1] -->
 *        [Packet Header] (16 字节)
 *        [Packet Data]   (可变长度)
 *   [Packet Record 2] -->
 *        ...
 *
 * 参考：https://wiki.wireshark.org/Development/LibpcapFileFormat
 */

#include <stdio.h>
#include <pcap.h>
#include "packet.h"
#include "capture.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========== PCAP 文件二进制格式定义 ========== */

/*
 * PCAP 全局文件头（24 字节）
 *
 * 字段说明：
 * - magic:     0xa1b2c3d4（微秒级时间戳）或 0xa1b23c4d（纳秒级）
 * - version_major: 主版本号，通常为 2
 * - version_minor: 次版本号，通常为 4
 * - thiszone:  时区修正（秒），通常为 0（不修正）
 * - sigfigs:   时间戳精度，通常为 0
 * - snaplen:   最大捕获长度，如 65535
 * - linktype:  链路层类型，Ethernet=1
 */
#pragma pack(push, 1)
typedef struct {
    unsigned int   magic;          /* 魔数: 0xa1b2c3d4 */
    unsigned short version_major;  /* 主版本号: 2 */
    unsigned short version_minor;  /* 次版本号: 4 */
    int            thiszone;       /* 时区偏移(秒) */
    unsigned int   sigfigs;        /* 时间戳精度 */
    unsigned int   snaplen;        /* 最大抓取长度 */
    unsigned int   linktype;       /* 链路层类型 (1=Ethernet) */
} PcapGlobalHeader;

/*
 * PCAP 包记录头（16 字节）
 *
 * 字段说明：
 * - ts_sec:    时间戳（秒，UNIX 时间戳）
 * - ts_usec:   时间戳（微秒，或纳秒取决于 magic）
 * - incl_len:  文件中该包的实际长度（caplen）
 * - orig_len:  原始包长度（可能被 snaplen 截断）
 */
typedef struct {
    unsigned int ts_sec;           /* 时间戳-秒 */
    unsigned int ts_usec;          /* 时间戳-微秒 */
    unsigned int incl_len;         /* 存储长度 */
    unsigned int orig_len;         /* 原始长度 */
} PcapPacketHeader;
#pragma pack(pop)

/* ========== 写入 ========== */

/*
 * 打开一个 .pcap 文件用于写入
 * - filename: 文件路径
 * - linktype: 链路层类型（通常 LINKTYPE_ETHERNET=1）
 * 返回 FILE* 指针，失败返回 NULL
 * 
 * 说明：
 * 文件打开后会立即写入 24 字节的 Global Header。
 * 后续每写一个包，内部自动追加 Packet Header。
 */
FILE* pcap_open_write(const char *filename, LinkType linktype);

/*
 * 将一个 Packet 写入已打开的 .pcap 文件
 * - fp:   pcap_open_write 返回的文件指针
 * - pkt:  要写入的数据包
 * 返回 0=成功, -1=失败
 *
 * 说明：
 * 自动根据 pkt.header.ts 构造 Packet Header，
 * 然后先写 Packet Header，再写 Packet Data。
 */
int pcap_write_packet(FILE *fp, const Packet *pkt);

/*
 * 直接将原始数据写入 .pcap 文件（无 Packet 包装）
 * 当没有使用 Packet 结构时的便捷接口
 */
int pcap_write_raw(FILE *fp, const struct pcap_pkthdr *header,
                   const u_char *data);

/*
 * 将多个 Packet 批量写入 .pcap 文件
 */
int pcap_write_batch(FILE *fp, const Packet *pkts, int count);

/*
 * 关闭 .pcap 写入文件
 */
void pcap_close_write(FILE *fp);

/* ========== 读取与回放 ========== */

/*
 * 打开 .pcap 文件用于回放读取（使用 libpcap 的 pcap_open_offline）
 * - filename: .pcap 文件路径
 * - errbuf:   错误缓冲区（至少 PCAP_ERRBUF_SIZE 字节）
 * 返回 pcap_t* 句柄，失败返回 NULL
 *
 * 说明：
 * 直接使用 libpcap 的 pcap_open_offline 打开文件，
 * 然后可以用 pcap_loop / pcap_next_ex 读取包。
 * 这样链路上的 E B C 模块无需改动即可处理离线文件。
 */
pcap_t* pcap_open_replay(const char *filename, char *errbuf);

/*
 * 回放 .pcap 文件中的所有包（注入解析流程）
 * - filename: .pcap 文件路径
 * - handler:  包处理回调（可以是 parse + display 的封装）
 * - userdata: 回调用户数据
 * 返回 0=成功, -1=失败
 *
 * 典型用法：
 *   pcap_replay("test.pcap", process_and_display, NULL);
 *
 * 内部实现：
 *   1. 用 pcap_open_offline 打开文件
 *   2. 用 pcap_loop 逐包读取
 *   3. 对每个包用 pcap_callback_adapter 适配后调用 handler
 *   4. 关闭文件
 */
int pcap_replay(const char *filename, packet_handler_t handler, void *userdata);

/*
 * 手动解析 .pcap 文件（不依赖 libpcap，纯文件 I/O）
 * 用于理解 .pcap 格式原理，或在不支持 libpcap 回放的极端场景
 * - filename:  .pcap 文件路径
 * - handler:   包处理回调
 * - userdata:  用户数据
 * 返回 0=成功, -1=失败
 */
int pcap_parse_raw(const char *filename, packet_handler_t handler, void *userdata);

#ifdef __cplusplus
}
#endif

#endif /* PCAP_IO_H */
