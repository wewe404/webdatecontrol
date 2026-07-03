/*
 * bpf_filter.c — BPF 过滤模块实现
 * ================================
 *
 * 实现思路详解：
 *
 * 1. pcap_compile_nopcap 原理
 *    ------------------------------------------------
 *    标准的 pcap_compile() 需要一个已打开的 pcap_t 句柄，
 *    因为它需要从句柄获取 snaplen 和 linktype。
 *    
 *    pcap_compile_nopcap(snaplen, linktype, &bpf, expr, 1, PCAP_NETMASK_UNKNOWN)
 *    是 libpcap 提供的不依赖 pcap_t 的编译接口：
 *    - snaplen: 抓包长度，影响 BPF 能读取的最大偏移
 *    - linktype: 链路层类型，影响 BPF 的链路层解析（如 Ethernet 偏移 12 取 EtherType）
 *    - 第四个参数 output: bpf_program 结构
 *    - 第五个参数: 过滤表达式字符串
 *    - 第六个参数: optimize (1=优化 BPF 字节码)
 *    - 第七个参数: netmask (网络掩码，用于 broadcast 判断)
 *
 *    编译成功后，bpf.bf_len 为指令条数，bpf.bf_insns 为指令数组。
 *
 * 2. pcap_offline_filter 原理
 *    ------------------------------------------------
 *    pcap_offline_filter(&bpf, header, data)
 *    对单个数据包执行 BPF 匹配。
 *    - &bpf: 已编译的 bpf_program
 *    - header: pcap_pkthdr 结构（至少需要 caplen）
 *    - data: 原始数据包
 *    返回值为过滤结果：非 0 = 匹配，0 = 不匹配
 *
 *    内部实现：
 *    libpcap 包含一个 BPF 解释器（bpf_filter.c），
 *    它以包数据为输入，逐条执行 BPF 字节码指令。
 *    每条 BPF 指令从包中加载数据到累加器 A 或索引寄存器 X，
 *    然后进行条件判断（JEQ/JGT/JSET）并可能跳转。
 *    最终 RET 指令返回 0（不匹配）或 snaplen（匹配）。
 *
 * 3. BPF vs 我们在代码中做协议过滤
 *    ------------------------------------------------
 *    其实我们完全可以自己在 parse_packet 之后根据协议字段做过滤，
 *    但 BPF 的优势是：
 *    - 在内核中执行（性能高，不经过用户态）
 *    - 通用语法（和 tcpdump/Wireshark 一致）
 *    - pcap_setfilter 将 BPF 加载到内核
 *    - 不匹配的包内核直接丢弃，不进入用户态
 *
 *    我们的实现同时支持两种过滤：
 *    1. 网卡级别: pcap_setfilter（内核过滤，高性能）
 *    2. 用户级别: bpf_match_packet / bpf_match（脱机/回放过滤）
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include "bpf_filter.h"

/* ========== BPF 过滤器 ========== */

int bpf_compile(BpfContext *ctx, const char *expr,
                int snaplen, int linktype)
{
    if (!ctx || !expr || strlen(expr) == 0) {
        if (ctx) {
            ctx->compiled = 0;
            ctx->expression[0] = '\0';
        }
        return -1;
    }

    /*
     * pcap_compile_nopcap 参数说明：
     *   第 1 参数 snaplen: 通常 65535
     *   第 2 参数 linktype: DLT_EN10MB=1 (Ethernet)
     *   第 3 参数 bpf_program*: 输出，编译后的 BPF 程序
     *   第 4 参数 char*: 过滤表达式
     *   第 5 参数 optimize: 1=优化
     *   第 6 参数 netmask: PCAP_NETMASK_UNKNOWN
     *
     * 常见编译失败原因：
     *   - 表达式语法错误（括号不匹配、误拼写等）
     *   - 相对于偏移量越界（如 snaplen 太小）
     *   - linktype 不支持的链路层（如 LINKTYPE_RAW 不能过滤 MAC 地址）
     */
    int ret = pcap_compile_nopcap(snaplen, linktype,
                                  &ctx->bpf,
                                  (char*)expr,
                                  1,           /* optimize */
                                  PCAP_NETMASK_UNKNOWN);

    if (ret != 0) {
        /*
         * pcap_compile_nopcap 失败时不设置 pcap 错误缓冲区，
         * 但有更老的 API 变体会。
         * 我们至少能知道编译失败并给出合理提示。
         */
        ctx->compiled = 0;
        ctx->expression[0] = '\0';
        printf("[-] BPF 编译失败: \"%s\"\n", expr);
        printf("    提示: 检查语法，确保表达式正确\n");
        return -1;
    }

    ctx->compiled = 1;
    ctx->snaplen = snaplen;
    ctx->linktype = linktype;
    strncpy(ctx->expression, expr, sizeof(ctx->expression) - 1);
    ctx->expression[sizeof(ctx->expression) - 1] = '\0';

    printf("[+] BPF 过滤器编译成功: \"%s\"\n", expr);
    return 0;
}

int bpf_match_packet(BpfContext *ctx, const unsigned char *data,
                     unsigned int len)
{
    if (!ctx || !ctx->compiled || !data || len == 0)
        return 0;  /* 无过滤器时默认匹配所有包 */

    /*
     * pcap_offline_filter 需要 pcap_pkthdr，但只需要 caplen 字段。
     * 我们可以构造一个轻量的 pcap_pkthdr。
     * 注意：不要修改原始数据，只读。
     *
     * 第 1 参数: bpf_program* — 已编译的 BPF 程序
     * 第 2 参数: pcap_pkthdr* — 包头部信息
     * 第 3 参数: u_char* — 包数据
     * 返回: 非 0 = 匹配
     */
    struct pcap_pkthdr hdr;
    hdr.caplen = len;
    hdr.len = len;

    /*
     * pcap_offline_filter 的返回值：
     *   - 返回 caplen 表示匹配
     *   - 返回 0 表示不匹配
     * 实际上因为 BPF RET 返回 snaplen 或 0，
     * 所以返回值就是 snaplen 表示匹配。
     */
    int result = pcap_offline_filter(&ctx->bpf, &hdr, data);
    return result != 0;
}

int bpf_match(BpfContext *ctx, Packet *pkt)
{
    if (!ctx || !pkt || !pkt->data)
        return 0;

    return bpf_match_packet(ctx, pkt->data, pkt->data_len);
}

void bpf_destroy(BpfContext *ctx)
{
    if (!ctx) return;

    if (ctx->compiled) {
        /*
         * pcap_freecode 释放编译后的 BPF 程序内存。
         * 内部释放 bpf.bf_insns 数组。
         */
        pcap_freecode(&ctx->bpf);
        ctx->compiled = 0;
    }

    ctx->expression[0] = '\0';
}

const char* bpf_get_expr(const BpfContext *ctx)
{
    if (!ctx) return "";
    return ctx->expression;
}

void bpf_set_linktype(BpfContext *ctx, int linktype)
{
    if (ctx) {
        ctx->linktype = linktype;
    }
}

/*
 * 注意：关于 pcap_setfilter（网卡级过滤）
 *
 * 如果要在抓包网卡上应用 BPF 过滤器（内核级过滤），
 * 使用流程是：
 *
 *   pcap_t *handle = pcap_open_live(...);
 *   struct bpf_program bpf;
 *   pcap_compile(handle, &bpf, "tcp port 80", 1, PCAP_NETMASK_UNKNOWN);
 *   pcap_setfilter(handle, &bpf);
 *   pcap_loop(handle, -1, callback, NULL);
 *   pcap_freecode(&bpf);
 *   pcap_close(handle);
 *
 * 这种方式在网卡驱动层面过滤，不匹配的包根本不进入用户态，
 * 性能最优。适合高流量场景。
 *
 * 我们的 bpf_compile() + bpf_match_packet() 是脱机/用户态过滤，
 * 适合 PCAP 回放文件过滤和已抓取包的二次过滤。
 * 两种方式可以结合使用：网卡级粗过滤 + 用户态精过滤。
 */
