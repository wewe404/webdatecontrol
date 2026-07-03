/*
 * pcap_io.c - PCAP 文件读写实现
 * ==============================
 *
 * 实现思路详解：
 *
 * 1. PCAP 文件格式
 *    ------------------------------------------------
 *    .pcap 是最流行的网络抓包存储格式（Wireshark/tcpdump 通用）。
 *    结构非常简单：
 *    
 *    [Global Header] (24 字节)
 *      magic:        0xa1b2c3d4 — 微秒精度（也有纳秒变体 0xa1b23c4d）
 *      version:      2.4
 *      snaplen:      最大捕获长度
 *      linktype:     1=Ethernet
 *    
 *    [Packet Record] × N
 *      ts_sec:       UNIX 秒时间戳
 *      ts_usec:      微秒偏移
 *      incl_len:     文件中实际存储的数据长度
 *      orig_len:     原始包长度（可能因 snaplen 被截断）
 *      [packet data]: incl_len 字节的原始数据
 *
 *    写入时，我们需要手动构造这些二进制结构。
 *    读取时，可以手动解析，也可以用 libpcap 的 pcap_open_offline。
 *
 * 2. 两种读取方式
 *    ------------------------------------------------
 *    a) pcap_open_replay():    使用 libpcap API。
 *       好处：自动处理各种链路层类型、纳秒格式变体、大端小端
 *       坏处：依赖 libpcap 安装
 *    
 *    b) pcap_parse_raw():     纯文件 I/O 手动解析。
 *       好处：不依赖 libpcap 也能读，适合理解格式
 *       坏处：需要自己处理字节序、格式变体
 *    
 *    我们两种都提供：优先用 libpcap（生产环境），
 *    同时提供手动解析版供学习参考。
 *
 * 3. 文件回放的意义
 *    ------------------------------------------------
 *    PCAP 文件回放 = 用保存的抓包数据"喂"给解析流程，
 *    让解析、显示模块像处理实时流量一样工作。
 *    好处：
 *    - 可复现：用同一份数据反复测试和调试
 *    - 可对比：修改解析代码后，同样的数据看输出差异
 *    - 性能测试：用大文件压测解析吞吐
 *    - 教学演示：用精心构造的 pcap 展示特定协议交互
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "pcap_io.h"

/* ========== 写入实现 ========== */

FILE* pcap_open_write(const char *filename, LinkType linktype)
{
    if (!filename) return NULL;

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        printf("[-] 无法创建文件: %s\n", filename);
        return NULL;
    }

    /*
     * 构造 Global Header
     * - magic: 0xa1b2c3d4 (微秒精度，网络字节序)
     * - version: 2.4 (标准版本)
     * - thiszone: 0 (不修正时区)
     * - snaplen: 65535 (标准最大值)
     * - linktype: 1=Ethernet (多数场景)
     * 
     * 以小端序写入（x86 是小端，直接写结构体即可）
     */
    PcapGlobalHeader gh;
    gh.magic         = 0xa1b2c3d4;
    gh.version_major = 2;
    gh.version_minor = 4;
    gh.thiszone      = 0;
    gh.sigfigs       = 0;
    gh.snaplen       = 65535;

    /* 将 LinkType 枚举映射到 DLT 值 */
    switch (linktype) {
        case LINKTYPE_ETHERNET: gh.linktype = 1;  break;  /* DLT_EN10MB */
        case LINKTYPE_RAW:      gh.linktype = 12; break;  /* DLT_RAW */
        default:                gh.linktype = 1;  break;  /* 默认 Ethernet */
    }

    size_t written = fwrite(&gh, sizeof(PcapGlobalHeader), 1, fp);
    if (written != 1) {
        printf("[-] 写入 Global Header 失败\n");
        fclose(fp);
        return NULL;
    }

    printf("[+] 已创建 PCAP 文件: %s (linktype=%u)\n", filename, gh.linktype);
    return fp;
}

int pcap_write_raw(FILE *fp, const struct pcap_pkthdr *header,
                   const u_char *data)
{
    if (!fp || !header || !data) return -1;

    /*
     * 写入 Packet Record:
     * 1. 先写 16 字节的 Packet Header
     * 2. 再写 incl_len 字节的原始数据
     */
    PcapPacketHeader ph;
    ph.ts_sec   = (unsigned int)header->ts.tv_sec;
    ph.ts_usec  = (unsigned int)header->ts.tv_usec;
    ph.incl_len = header->caplen;  /* 文件中存储的长度 */
    ph.orig_len = header->len;     /* 原始长度 */

    if (fwrite(&ph, sizeof(PcapPacketHeader), 1, fp) != 1) {
        printf("[-] 写入 Packet Header 失败\n");
        return -1;
    }

    if (fwrite(data, 1, ph.incl_len, fp) != ph.incl_len) {
        printf("[-] 写入 Packet Data 失败\n");
        return -1;
    }

    return 0;
}

int pcap_write_packet(FILE *fp, const Packet *pkt)
{
    if (!fp || !pkt) return -1;
    return pcap_write_raw(fp, &pkt->header, pkt->data);
}

int pcap_write_batch(FILE *fp, const Packet *pkts, int count)
{
    if (!fp || !pkts || count <= 0) return -1;

    int success = 0;
    for (int i = 0; i < count; i++) {
        if (pcap_write_packet(fp, &pkts[i]) == 0) {
            success++;
        }
    }
    return success;
}

void pcap_close_write(FILE *fp)
{
    if (fp) {
        fclose(fp);
        printf("[+] PCAP 文件已关闭\n");
    }
}

/* ========== 读取与回放 ========== */

pcap_t* pcap_open_replay(const char *filename, char *errbuf)
{
    if (!filename) return NULL;

    /*
     * pcap_open_offline 是 libpcap 提供的离线文件打开函数。
     * 它返回一个 pcap_t 句柄，之后可以像实时抓包一样使用。
     * 
     * 后续可以使用：
     * - pcap_loop() / pcap_dispatch() — 回调模式
     * - pcap_next_ex() — 轮询模式
     * - pcap_datalink() — 获取链路层类型
     * 
     * pcap_close() 释放
     */
    pcap_t *handle = pcap_open_offline(filename, errbuf);
    if (!handle) {
        printf("[-] 打开 PCAP 文件失败: %s\n  %s\n", filename, errbuf);
        return NULL;
    }

    printf("[+] 成功打开 PCAP 文件: %s\n", filename);

    /* 显示文件中的链路层类型 */
    int linktype = pcap_datalink(handle);
    printf("    链路层类型: %d (%s)\n", linktype,
           linktype == 1 ? "Ethernet" : "其他");

    /* 显示文件中的包数量（通过 pcap_next_ex 遍历统计）*/
    int count = 0;
    struct pcap_pkthdr *hdr;
    const u_char *data;
    while (pcap_next_ex(handle, &hdr, &data) == 1) {
        count++;
    }
    printf("    总包数: %d\n", count);

    /* 重置到文件开头以便重新读取 */
    pcap_close(handle);
    handle = pcap_open_offline(filename, errbuf);
    if (!handle) {
        printf("[-] 重置回放文件失败: %s\n", errbuf);
        return NULL;
    }

    return handle;
}

int pcap_replay(const char *filename, packet_handler_t handler, void *userdata)
{
    if (!filename || !handler) return -1;

    char errbuf[PCAP_ERRBUF_SIZE];

    /*
     * 使用 libpcap API 回放
     * 
     * 步骤：
     * 1. 用 pcap_open_offline 打开 .pcap 文件
     * 2. 获取链路层类型
     * 3. 构造回调上下文（复用 capture.c 中的 CallbackCtx 结构）
     * 4. 用 pcap_loop 逐包读取，通过适配器调用 handler
     * 5. 清理
     *
     * 注意：这里我们不能直接引用 capture.c 内部的 CallbackCtx，
     * 因为它是在 capture.c 内部定义的。所以我们需要重新定义或将其放到头文件。
     * 或者直接使用原始 pcap_handler 回调。
     * 
     * 更干净的做法：我们自己在这里用 pcap_next_ex 循环，
     * 手动构造 Packet 再调用 handler。
     */
    pcap_t *handle = pcap_open_offline(filename, errbuf);
    if (!handle) {
        printf("[-] pcap_replay: 无法打开文件 %s\n  %s\n", filename, errbuf);
        return -1;
    }

    LinkType linktype;
    int dl = pcap_datalink(handle);
    switch (dl) {
        case DLT_EN10MB: linktype = LINKTYPE_ETHERNET; break;
        case DLT_RAW:    linktype = LINKTYPE_RAW;      break;
        default:         linktype = LINKTYPE_UNKNOWN;  break;
    }

    printf("[*] 开始回放: %s", filename);

    struct pcap_pkthdr *header;
    const u_char *data;
    int pkt_count = 0;
    int ret;

    while ((ret = pcap_next_ex(handle, &header, &data)) == 1) {
        Packet pkt;
        packet_wrap(&pkt, header, data, linktype);

        /* 设置时间戳信息 */
        pkt.header.ts = header->ts;
        pkt.header.caplen = header->caplen;
        pkt.header.len = header->len;

        handler(&pkt, userdata);
        pkt_count++;

        /* 每1000包打印进度 */
        if (pkt_count % 1000 == 0) {
            printf(".");
        }
    }

    printf("\n[+] 回放完成，共 %d 个包\n", pkt_count);

    pcap_close(handle);
    return 0;
}

int pcap_parse_raw(const char *filename, packet_handler_t handler, void *userdata)
{
    /*
     * 纯文件 I/O 手动解析 .pcap 文件
     * ---------------------------------
     * 这里展示 .pcap 格式的底层细节。
     *
     * 文件结构（从上到下依次是二进制字节流）:
     *
     * 偏移   内容                  长度
     * ------ -------------------- ----
     * 0      Global Header        24
     * 24     Packet 1 Header      16
     * 40     Packet 1 Data        incl_len[1]
     * 40+    Packet 2 Header      16
     *       ...
     *
     * 我们逐块读取，对每个包构造 Packet 结构并调用 handler。
     *
     * 限制：
     * - 只支持标准微秒格式 (magic=0xa1b2c3d4)
     * - 不处理纳秒变体、大端文件
     * - 仅作为教学演示
     */

    if (!filename || !handler) return -1;

    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        printf("[-] 无法打开文件: %s\n", filename);
        return -1;
    }

    /* 读取 Global Header */
    PcapGlobalHeader gh;
    if (fread(&gh, sizeof(PcapGlobalHeader), 1, fp) != 1) {
        printf("[-] 读取 Global Header 失败\n");
        fclose(fp);
        return -1;
    }

    /* 校验魔数 */
    if (gh.magic != 0xa1b2c3d4) {
        printf("[-] 不支持的 PCAP 格式 (magic=0x%08x)\n", gh.magic);
        printf("    仅支持标准微秒格式 (0xa1b2c3d4)\n");
        fclose(fp);
        return -1;
    }

    printf("[*] 手动解析 PCAP 文件: %s\n", filename);
    printf("    版本: %u.%u, snaplen=%u, linktype=%u\n",
           gh.version_major, gh.version_minor, gh.snaplen, gh.linktype);

    /* 映射链路层类型 */
    LinkType linktype = LINKTYPE_UNKNOWN;
    if (gh.linktype == 1) linktype = LINKTYPE_ETHERNET;

    /* 逐包读取 */
    PcapPacketHeader ph;
    int pkt_count = 0;

    while (fread(&ph, sizeof(PcapPacketHeader), 1, fp) == 1) {
        /* 安全检查：incl_len 不能太大（防恶意文件）*/
        if (ph.incl_len > 100000) {
            printf("[-] 包 #%d 长度异常 (%u)，停止解析\n",
                   pkt_count + 1, ph.incl_len);
            break;
        }

        /* 读取包数据 */
        unsigned char *data_buf = (unsigned char*)malloc(ph.incl_len);
        if (!data_buf) {
            printf("[-] 内存不足\n");
            break;
        }

        if (fread(data_buf, 1, ph.incl_len, fp) != ph.incl_len) {
            printf("[-] 读取包数据失败 (#%d)\n", pkt_count + 1);
            free(data_buf);
            break;
        }

        /* 构造 pcap_pkthdr */
        struct pcap_pkthdr header;
        header.ts.tv_sec  = (time_t)ph.ts_sec;
        header.ts.tv_usec = (int)ph.ts_usec;
        header.caplen     = ph.incl_len;
        header.len        = ph.orig_len;

        /* 构造 Packet 并调用 handler */
        Packet pkt;
        packet_wrap(&pkt, &header, data_buf, linktype);
        handler(&pkt, userdata);

        /*
         * 这里 data_buf 是堆分配的，但 Packet.data 指向它。
         * handler 是同步调用的，所以 handler 返回后数据已被处理完毕。
         * 如果 handler 需要异步使用数据，应该在 handler 内拷贝。
         */
        free(data_buf);
        pkt_count++;
    }

    printf("[+] 手动解析完成，共 %d 个包\n", pkt_count);

    fclose(fp);
    return 0;
}
