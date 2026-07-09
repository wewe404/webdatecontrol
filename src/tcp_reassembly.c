/**
 * tcp_reassembly.c — TCP 流重组实现
 *
 * 算法：
 *   1. 从 ParsedPacket 中提取 4 元组和 TCP 载荷
 *   2. 按 4 元组哈希查找或创建流
 *   3. 按序列号将载荷填入半流缓冲区（相对偏移）
 *   4. 当双向 FIN 或 flush_all 时标记完成
 *   5. 从已完成流的缓冲区中提取 HTTP 请求/响应
 *   6. 写入文件
 */

#include "tcp_reassembly.h"
#include <pcap.h>
#include <winsock2.h>
#include <stdlib.h>
#include <string.h>
#include <direct.h>

#define TR_MAX_DATA (256 * 1024)

/* ===================== 哈希 ===================== */
static unsigned int stream_hash(uint32_t a, uint32_t b, uint16_t c, uint16_t d)
{
    return (unsigned int)(a ^ b ^ ((uint32_t)c << 16) ^ d) % TR_MAX_STREAMS;
}

/* ===================== 半流 ===================== */

static void half_init(tr_half_stream_t *h)
{
    memset(h, 0, sizeof(*h));
}

static void half_free(tr_half_stream_t *h)
{
    free(h->data);
    memset(h, 0, sizeof(*h));
}

static void half_feed(tr_half_stream_t *h, uint32_t seq, const uint8_t *payload,
                      uint16_t len, uint8_t flags)
{
    /* SYN: 记录 base_seq，SYN 占 1 个 seq */
    if (!h->initialized && (flags & 0x02)) {
        h->base_seq = seq;
        h->next_seq = 1;          /* 相对偏移：SYN 占 offset 0，数据从 offset 1 开始 */
        h->initialized = 1;
        h->has_syn = 1;
        if (len == 0) return;
        /* 有载荷：seq 要跳过 SYN 占位 */
        seq = seq + 1;
    }

    if (!h->initialized) return;  /* SYN 还没到，丢弃 */

    uint32_t rel = seq - h->base_seq;       /* 相对偏移 */
    uint32_t end = rel + len;

    /* 已经收到过：重传或纯确认 */
    if (end <= h->next_seq) return;

    /* 有重叠：调整 */
    if (rel < h->next_seq) {
        uint32_t skip = h->next_seq - rel;
        if (skip >= len) return;
        payload += skip;
        len -= (uint16_t)skip;
        rel = h->next_seq;
        end = rel + len;
    }

    /* 扩展缓冲区 */
    uint32_t needed = end;
    if (needed > h->data_cap) {
        uint32_t nc = needed + 65536;
        if (nc > TR_MAX_DATA) nc = TR_MAX_DATA;
        if (nc <= h->data_cap) return;  /* 超限 */
        uint8_t *nd = (uint8_t*)realloc(h->data, nc);
        if (!nd) return;
        if (nc > h->data_cap)
            memset(nd + h->data_cap, 0, nc - h->data_cap);
        h->data = nd;
        h->data_cap = nc;
    }

    memcpy(h->data + rel, payload, len);
    if (needed > h->data_len) h->data_len = needed;
    if (end > h->next_seq) h->next_seq = end;

    if (flags & 0x01) h->has_fin = 1;
}

/* ===================== 流操作 ===================== */

static int match_stream(const tcp_stream_t *s, uint32_t a, uint32_t b,
                        uint16_t c, uint16_t d)
{
    return (s->src_ip == a && s->dst_ip == b && s->src_port == c && s->dst_port == d) ||
           (s->src_ip == b && s->dst_ip == a && s->src_port == d && s->dst_port == c);
}

static int which_dir(const tcp_stream_t *s, uint32_t ip, uint16_t port)
{
    if (s->src_ip == ip && s->src_port == port) return 0;
    return 1;
}

/* ===================== API ===================== */

void tr_init(TcpReassembler *tr)
{
    memset(tr, 0, sizeof(*tr));
}

void tr_feed(TcpReassembler *tr, const ParsedPacket *pkt)
{
    if (pkt->layer4_proto != PROTO_TCP) return;

    /* 空载荷且非 SYN/FIN：忽略 */
    if (pkt->payload_len == 0) {
        uint8_t f = pkt->tcp.flags;
        if (!(f & 0x02) && !(f & 0x01)) return;
    }

    tr->total_packets_fed++;

    uint32_t sip = pkt->ipv4.src_ip;
    uint32_t dip = pkt->ipv4.dst_ip;
    uint16_t sp = pkt->tcp.src_port;
    uint16_t dp = pkt->tcp.dst_port;
    uint32_t seq = ntohl(pkt->tcp.seq_num);
    uint8_t  flg = pkt->tcp.flags;

    int slot = -1, empty = -1;
    for (int i = 0; i < TR_MAX_STREAMS; i++) {
        if (!tr->streams[i].slot_used) { if (empty < 0) empty = i; continue; }
        if (match_stream(&tr->streams[i], sip, dip, sp, dp)) { slot = i; break; }
    }

    if (slot < 0) {
        if (empty < 0) return;
        slot = empty;
        tcp_stream_t *s = &tr->streams[slot];
        memset(s, 0, sizeof(*s));
        s->slot_used = 1;
        s->src_ip = sip; s->dst_ip = dip;
        s->src_port = sp; s->dst_port = dp;
        s->start_ts = pkt->ts;
        half_init(&s->half[0]);
        half_init(&s->half[1]);
        tr->stream_count++;
    }

    tcp_stream_t *s = &tr->streams[slot];
    if (s->complete) return;

    int dir = which_dir(s, sip, sp);
    half_feed(&s->half[dir], seq, pkt->payload, pkt->payload_len, flg);

    if (s->half[0].has_fin && s->half[1].has_fin)
        s->complete = 1;

    tr->total_bytes_reassembled += pkt->payload_len;
}

void tr_flush_all(TcpReassembler *tr)
{
    for (int i = 0; i < TR_MAX_STREAMS; i++)
        if (tr->streams[i].slot_used) tr->streams[i].complete = 1;
}

/* ===================== HTTP 提取 ===================== */

/* 在缓冲区中找 HTTP 请求/响应对。返回 1 找到，0 未找到 */
static int find_http_pair(const uint8_t *cdata, uint32_t clen,
                          const uint8_t *sdata, uint32_t slen,
                          int *rqs, int *rqe, int *rps, int *rpe)
{
    *rqs = *rqe = *rps = *rpe = 0;

    /* 找请求：GET/POST 等 */
    const char *meth[] = {"GET ", "POST ", "PUT ", "DELETE ", "HEAD "};
    int found = -1;
    for (int m = 0; m < 5 && found < 0; m++) {
        int ml = (int)strlen(meth[m]);
        for (unsigned i = 0; i + ml < clen; i++)
            if (memcmp(cdata + i, meth[m], ml) == 0) { found = (int)i; break; }
    }
    if (found < 0) return 0;
    *rqs = found;

    /* 找请求头结束 \r\n\r\n */
    for (unsigned i = *rqs; i + 4 <= clen; i++)
        if (cdata[i]=='\r' && cdata[i+1]=='\n' && cdata[i+2]=='\r' && cdata[i+3]=='\n')
            { *rqe = (int)(i+4); break; }
    if (*rqe == 0) return 0;

    /* 找响应：HTTP/ */
    found = -1;
    for (unsigned i = 0; i + 5 < slen; i++)
        if (memcmp(sdata + i, "HTTP/", 5) == 0) { found = (int)i; break; }
    if (found < 0) return 0;
    *rps = found;

    /* 找响应头结束 */
    for (unsigned i = *rps; i + 4 <= slen; i++)
        if (sdata[i]=='\r' && sdata[i+1]=='\n' && sdata[i+2]=='\r' && sdata[i+3]=='\n')
            { *rpe = (int)(i+4); break; }
    if (*rpe == 0) return 0;

    return 1;
}

int tr_write_http_pairs(TcpReassembler *tr)
{
    _mkdir(TR_OUTPUT_DIR);
    int pair_count = 0;

    for (int i = 0; i < TR_MAX_STREAMS; i++) {
        tcp_stream_t *s = &tr->streams[i];
        if (!s->slot_used || !s->complete) continue;

        int rqs, rqe, rps, rpe;
        int ok = find_http_pair(s->half[0].data, s->half[0].data_len,
                                s->half[1].data, s->half[1].data_len,
                                &rqs, &rqe, &rps, &rpe);
        if (!ok) {
            /* 交换方向再试 */
            ok = find_http_pair(s->half[1].data, s->half[1].data_len,
                                s->half[0].data, s->half[0].data_len,
                                &rqs, &rqe, &rps, &rpe);
        }
        if (!ok) continue;

        pair_count++;
        char req_fn[64], resp_fn[64];
        snprintf(req_fn, sizeof(req_fn), "req_%03d.txt", pair_count);
        snprintf(resp_fn, sizeof(resp_fn), "resp_%03d.txt", pair_count);

        char path[512];
        snprintf(path, sizeof(path), "%s/%s", TR_OUTPUT_DIR, req_fn);
        FILE *fp = fopen(path, "wb");
        if (fp) { fwrite(s->half[0].data + rqs, 1, rqe - rqs, fp); fclose(fp); }

        snprintf(path, sizeof(path), "%s/%s", TR_OUTPUT_DIR, resp_fn);
        fp = fopen(path, "wb");
        if (fp) { fwrite(s->half[1].data + rps, 1, rpe - rps, fp); fclose(fp); }

        printf("  [%d] %s <-> %s:%d  -> %s, %s\n",
               pair_count,
               inet_ntoa(*(struct in_addr*)&s->src_ip),
               inet_ntoa(*(struct in_addr*)&s->dst_ip),
               ntohs(s->dst_port),
               req_fn, resp_fn);
    }
    return pair_count;
}

void tr_print_stats(const TcpReassembler *tr)
{
    int comp = 0, http = 0;
    for (int i = 0; i < TR_MAX_STREAMS; i++) {
        if (!tr->streams[i].slot_used) continue;
        if (tr->streams[i].complete) comp++;
        int a,b,c,d;
        if (find_http_pair(tr->streams[i].half[0].data, tr->streams[i].half[0].data_len,
                           tr->streams[i].half[1].data, tr->streams[i].half[1].data_len,
                           &a,&b,&c,&d) ||
            find_http_pair(tr->streams[i].half[1].data, tr->streams[i].half[1].data_len,
                           tr->streams[i].half[0].data, tr->streams[i].half[0].data_len,
                           &a,&b,&c,&d))
            http++;
    }
    printf("  Packets fed:       %d\n", tr->total_packets_fed);
    printf("  Bytes reassembled: %d\n", tr->total_bytes_reassembled);
    printf("  Streams tracked:   %d\n", tr->stream_count);
    printf("  Completed:         %d\n", comp);
    printf("  HTTP pairs:        %d\n", http);
}

int tcp_reassemble_from_pcap(const char *filename, const char *filter_exp)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename, errbuf);
    if (!handle) {
        printf("Cannot open pcap: %s\n", errbuf);
        return 0;
    }

    if (filter_exp && filter_exp[0]) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_setfilter(handle, &fp);
            printf("  Filter: %s\n", filter_exp);
            pcap_freecode(&fp);
        }
    }

    TcpReassembler tr;
    tr_init(&tr);

    struct pcap_pkthdr *hdr;
    const u_char *data;
    int res, total = 0;

    printf("Processing %s ...\n", filename);
    while ((res = pcap_next_ex(handle, &hdr, &data)) >= 0) {
        if (res == 0) continue;
        total++;
        ParsedPacket pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.ts = hdr->ts;
        pkt.packet_len = hdr->len;
        pkt.captured_len = hdr->caplen;
        if (analyze_packet(data, (uint32_t)hdr->caplen, &pkt) == 0) {
            tr_feed(&tr, &pkt);
        }
    }
    tr_flush_all(&tr);
    pcap_close(handle);

    printf("  Total packets: %d\n", total);
    tr_print_stats(&tr);

    printf("Extracting HTTP pairs...\n");
    int pairs = tr_write_http_pairs(&tr);
    printf("Result: %d HTTP sessions saved to %s/\n", pairs, TR_OUTPUT_DIR);
    return pairs;
}
