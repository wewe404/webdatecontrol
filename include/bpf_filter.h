#ifndef BPF_FILTER_H
#define BPF_FILTER_H

/*
 * bpf_filter.h — BPF 过滤模块
 * ==============================
 *
 * 职责：编译 BPF 过滤表达式，对原始数据包执行过滤匹配
 *
 * 实现策略：
 *   利用 libpcap 的 pcap_compile_nopcap() + pcap_offline_filter() 实现，
 * 不需要打开真实网卡也能编译和执行 BPF 过滤规则。
 *
 * 为什么选择这套 API？
 *   1. pcap_compile() 需要 pcap_t 句柄（需要打开网卡）
 *   2. pcap_compile_nopcap() 只需要 snaplen 和 linktype，不需要 pcap_t
 *   3. pcap_offline_filter() 对原始数据包执行已编译的 BPF 匹配
 *   4. 这样过滤器和抓包是解耦的，PCAP 回放也能使用同样的过滤
 *
 * BPF (Berkley Packet Filter) 原理简述：
 *   一种基于虚拟机的数据包过滤机制。
 *   过滤表达式（如 "tcp port 80"）被编译成 BPF 字节码序列，
 *   每个指令对包进行测试（如 "检查 ip->protocol 是否 == 6"）。
 *   内核（或 libpcap 的用户态实现）执行这些字节码来判断包是否匹配。
 *
 *   BPF 虚拟机寄存器：
 *     A — 累加器（32-bit）
 *     X — 索引寄存器（32-bit）
 *     PC — 程序计数器
 *   
 *   常见 BPF 指令：
 *     LD  — 从包中加载数据到 A
 *     LDB — 加载 1 字节
 *     LDH — 加载 2 字节
 *     JEQ — 如果 A == k 则跳转
 *     JGT — 如果 A > k 则跳转
 *     RET — 返回（K=0 不匹配，K=snaplen 匹配）
 */

#include <pcap.h>
#include "packet.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========== BPF 过滤器 ========== */

/*
 * BPF 过滤器上下文
 * 封装了编译后的 BPF 程序及其参数
 */
typedef struct {
    struct bpf_program  bpf;         /* libpcap 编译后的 BPF 程序 */
    int                 compiled;    /* 是否已编译成功 */
    int                 snaplen;     /* 编译时用的 snaplen */
    int                 linktype;    /* 编译时用的链路层类型 */
    char                expression[256]; /* 原始的过滤表达式 */
} BpfContext;

/*
 * 编译 BPF 过滤表达式
 * - expr:     过滤表达式，如 "tcp port 80", "host 192.168.1.1"
 * - snaplen:  snaplen 值（通常 65535）
 * - linktype: 链路层类型（通常 DLT_EN10MB = 1）
 * 返回 0=成功, -1=编译失败
 *
 * 内部使用 pcap_compile_nopcap()，该函数不需要 pcap_t 句柄，
 * 只需要 snaplen 和 linktype 就能编译。这让我们可以在
 * 抓包开始前就准备好过滤器。
 *
 * 示例用法：
 *   BpfContext bpf;
 *   if (bpf_compile(&bpf, "tcp port 80", 65535, 1) == 0) {
 *       // 过滤器就绪
 *   }
 */
int bpf_compile(BpfContext *ctx, const char *expr,
                int snaplen, int linktype);

/*
 * 测试一个原始数据包是否匹配 BPF 过滤器
 * - ctx:  已编译的 BPF 上下文
 * - data: 原始数据包指针
 * - len:  数据包长度
 * 返回 1=匹配（通过过滤）, 0=不匹配, -1=错误
 *
 * 内部使用 pcap_offline_filter() 执行匹配。
 * 注意：这个函数操作的是原始包数据，不是 Packet 结构。
 * 因为 BPF 工作在链路层原始数据上。
 */
int bpf_match_packet(BpfContext *ctx, const unsigned char *data,
                     unsigned int len);

/*
 * 测试一个 Packet 是否匹配 BPF 过滤器
 * 是对 bpf_match_packet 的包装，自动提取 Packet 中的原始数据
 */
int bpf_match(BpfContext *ctx, Packet *pkt);

/*
 * 释放 BPF 过滤器资源
 */
void bpf_destroy(BpfContext *ctx);

/*
 * 获取当前过滤表达式
 */
const char* bpf_get_expr(const BpfContext *ctx);

/*
 * 设置链路层类型（默认 DLT_EN10MB=1）
 */
void bpf_set_linktype(BpfContext *ctx, int linktype);

/* ========== BPF 语法速查 ========== */

/*
 * 常用过滤表达式示例：
 *
 *  基本过滤:
 *    "host 192.168.1.1"           — 来源或目的为 192.168.1.1
 *    "src host 192.168.1.1"       — 来源为 192.168.1.1
 *    "dst host 192.168.1.1"       — 目的为 192.168.1.1
 *    "net 192.168.1.0/24"         — 来源或目的在 192.168.1.0/24 网段
 *
 *  协议过滤:
 *    "tcp"                        — 只抓 TCP 包
 *    "udp"                        — 只抓 UDP 包
 *    "icmp"                       — 只抓 ICMP 包
 *    "arp"                        — 只抓 ARP 包
 *    "ip"                         — 只抓 IPv4 包
 *    "ip6"                        — 只抓 IPv6 包
 *
 *  端口过滤:
 *    "port 80"                    — 源或目的端口为 80
 *    "src port 80"                — 源端口为 80
 *    "dst port 53"                — 目的端口为 53
 *    "tcp port 80"                — TCP 且端口为 80
 *    "udp port 53"                — UDP 且端口为 53
 *    "portrange 8000-8100"        — 端口范围 8000-8100
 *
 *  逻辑组合:
 *    "tcp port 80 and host 192.168.1.1"
 *    "tcp or udp"
 *    "not arp"
 *    "host 192.168.1.1 and (tcp port 80 or tcp port 443)"
 *
 *  高级过滤:
 *    "tcp[tcpflags] & tcp-syn != 0"      — 只抓 SYN 包
 *    "tcp[tcpflags] & tcp-fin != 0"      — 只抓 FIN 包
 *    "ip[8] < 64"                         — TTL < 64
 *    "icmp[icmptype] = 8"               — ICMP Echo Request
 *    "greater 100"                       — 包长 > 100 字节
 *    "less 64"                           — 包长 < 64 字节
 *
 * BPF 表达式通过 pcap_compile() 编译为 BPF 字节码。
 * 底层是一套基于累加器和条件跳转的虚拟机指令集。
 * "tcp port 80" 被编译为类似这样的字节码：
 *
 *   (000) ldh      [12]              // 加载 EtherType (offset 12)
 *   (001) jeq      #0x800, jt=2, jf=8  // 是 IPv4 吗？
 *   (002) ldb      [23]              // 加载 IPv4 Protocol (offset 23)
 *   (003) jeq      #0x6, jt=4, jf=8   // 是 TCP 吗？
 *   (004) ldh      [20]              // 加载 IPv4 src port (offset 20)
 *   (005) jeq      #0x50, jt=7, jf=6  // src port == 80?
 *   (006) ldh      [22]              // 加载 IPv4 dst port (offset 22)
 *   (007) jeq      #0x50, jt=9, jf=8  // dst port == 80?
 *   (008) ret      #0                // 不匹配
 *   (009) ret      #65535            // 匹配
 *
 * 从上可以看出 BPF 的执行效率很高：
 * 平均只需执行 3-5 条指令就能决定一个包是否匹配
 */

#ifdef __cplusplus
}
#endif

#endif /* BPF_FILTER_H */
