/**
 * protocol_analyze.c - 协议分析整合层实现
 *
 * 解析链路：
 *   Ethernet -> IPv4/IPv6/ARP
 *            -> TCP/UDP/ICMP
 *            -> DNS(port 53) / HTTP(port 80,8080,8000,443)
 *
 * 本模块整合了 eth_parser/ip_parser/tcp_parser/udp_parser/icmp_parser
 * 等独立解析器，替换了原有的内联解析代码。
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif
#include <pcap.h>

#include "protocol_analyze.h"
#include "eth_parser.h"
#include "ip_parser.h"
#include "ipv6_parser.h"
#include "tcp_parser.h"
#include "udp_parser.h"
#include "icmp_parser.h"
#include "dns_parser.h"
#include "http_parser.h"
#include "bpf_filter.h"
#include "net_utils.h"

/* ---- 常见应用层端口 ---- */
#define PORT_DNS       53
#define PORT_HTTP      80
#define PORT_HTTP_ALT  8080
#define PORT_HTTP_ALT2 8000
#define PORT_HTTPS     443

/* ---- 内部函数：判断是否HTTP端口 ---- */
static int is_http_port(uint16_t port)
{
    return (port == PORT_HTTP || port == PORT_HTTP_ALT ||
            port == PORT_HTTP_ALT2 || port == PORT_HTTPS);
}

/* ---- 内部函数：判断是否DNS端口 ---- */
static int is_dns_port(uint16_t port)
{
    return (port == PORT_DNS);
}

/* ---- 公开函数实现 ---- */

int analyze_packet(const uint8_t *raw_data, uint32_t len, ParsedPacket *pkt)
{
    if (raw_data == NULL || pkt == NULL || len == 0) {
        return -1;
    }

    memset(pkt, 0, sizeof(ParsedPacket));
    pkt->packet_len = len;
    pkt->captured_len = len;

    /* ---- 第一层：Ethernet (调用独立解析器) ---- */
    int eth_len = parse_ethernet(raw_data, len, pkt);
    if (eth_len < 0) return -1;

    const uint8_t *ip_data = raw_data + eth_len;
    uint32_t ip_len = len - (uint32_t)eth_len;

    /* ---- 第二层：IPv4 / ARP ---- */
    if (pkt->eth.ether_type == 0x0800) {
        int ip_hdr_len = parse_ipv4(ip_data, ip_len, pkt);
        if (ip_hdr_len < 0) return -1;

        const uint8_t *transport_data = ip_data + ip_hdr_len;
        uint32_t transport_len = ip_len - (uint32_t)ip_hdr_len;

        /* ---- 第三层：TCP / UDP / ICMP ---- */
        switch (pkt->ipv4.protocol) {
        case 6: /* TCP */
            {
                int tcp_hdr_len = parse_tcp(transport_data, transport_len, pkt);
                if (tcp_hdr_len < 0) return -1;

                const uint8_t *app_data = transport_data + tcp_hdr_len;
                uint32_t app_len = transport_len - (uint32_t)tcp_hdr_len;

                if (app_len > 0) {
                    /* 尝试HTTP解析 */
                    if (is_http_port(pkt->tcp.dst_port) || is_http_port(pkt->tcp.src_port)) {
                        http_result_t http;
                        if (parse_http(app_data, (int)app_len, &http) == 0) {
                            pkt->app_proto = (http.type == HTTP_TYPE_REQUEST) ?
                                             PROTO_HTTP_REQUEST : PROTO_HTTP_RESPONSE;
                        }
                        free_http_result(&http);
                    }

                    /* DNS over TCP */
                    if (is_dns_port(pkt->tcp.dst_port) || is_dns_port(pkt->tcp.src_port)) {
                        if (app_len > 2) {
                            dns_result_t dns;
                            if (parse_dns(app_data + 2, (uint16_t)(app_len - 2), &dns) == 0) {
                                pkt->app_proto = PROTO_DNS;
                                pkt->dns = dns.header;
                            }
                        }
                    }

                    /* 复制载荷 */
                    uint16_t copy_len = app_len > MAX_PAYLOAD ? MAX_PAYLOAD : (uint16_t)app_len;
                    memcpy(pkt->payload, app_data, copy_len);
                    pkt->payload_len = copy_len;
                }
            }
            break;

        case 17: /* UDP */
            {
                int udp_hdr_len = parse_udp(transport_data, transport_len, pkt);
                if (udp_hdr_len < 0) return -1;

                const uint8_t *app_data = transport_data + udp_hdr_len;
                uint32_t app_len = transport_len - (uint32_t)udp_hdr_len;

                if (app_len > 0) {
                    /* DNS解析 */
                    if (is_dns_port(pkt->udp.dst_port) || is_dns_port(pkt->udp.src_port)) {
                        dns_result_t dns;
                        if (parse_dns(app_data, (uint16_t)app_len, &dns) == 0) {
                            pkt->app_proto = PROTO_DNS;
                            pkt->dns = dns.header;
                        }
                    }

                    /* 复制载荷 */
                    uint16_t copy_len = app_len > MAX_PAYLOAD ? MAX_PAYLOAD : (uint16_t)app_len;
                    memcpy(pkt->payload, app_data, copy_len);
                    pkt->payload_len = copy_len;
                }
            }
            break;

        case 1: /* ICMP */
            if (parse_icmp(transport_data, transport_len, pkt) < 0) return -1;
            break;

        default:
            break;
        }
    } else if (pkt->eth.ether_type == 0x0806) {
        pkt->layer2_proto = PROTO_ARP;
    } else if (pkt->eth.ether_type == 0x86DD) {
        /* IPv6 */
        int ip6_hdr_len = parse_ipv6(ip_data, ip_len, pkt);
        if (ip6_hdr_len < 0) return -1;

        const uint8_t *transport_data = ip_data + ip6_hdr_len;
        uint32_t transport_len = ip_len - (uint32_t)ip6_hdr_len;

        /* 限制传输层长度不超过payload_length */
        uint32_t plen = pkt->ipv6.payload_length;
        if (transport_len > plen) transport_len = plen;

        switch (pkt->ipv6.next_header) {
        case 6: /* TCP over IPv6 */
            {
                int tcp_hdr_len = parse_tcp(transport_data, transport_len, pkt);
                if (tcp_hdr_len < 0) return -1;
                const uint8_t *app_data = transport_data + tcp_hdr_len;
                uint32_t app_len = transport_len - (uint32_t)tcp_hdr_len;
                if (app_len > 0) {
                    if (is_http_port(pkt->tcp.dst_port) || is_http_port(pkt->tcp.src_port)) {
                        http_result_t http;
                        if (parse_http(app_data, (int)app_len, &http) == 0) {
                            pkt->app_proto = (http.type == HTTP_TYPE_REQUEST) ?
                                             PROTO_HTTP_REQUEST : PROTO_HTTP_RESPONSE;
                        }
                        free_http_result(&http);
                    }
                    if (is_dns_port(pkt->tcp.dst_port) || is_dns_port(pkt->tcp.src_port)) {
                        if (app_len > 2) {
                            dns_result_t dns;
                            if (parse_dns(app_data + 2, (uint16_t)(app_len - 2), &dns) == 0) {
                                pkt->app_proto = PROTO_DNS;
                                pkt->dns = dns.header;
                            }
                        }
                    }
                    uint16_t copy_len = app_len > MAX_PAYLOAD ? MAX_PAYLOAD : (uint16_t)app_len;
                    memcpy(pkt->payload, app_data, copy_len);
                    pkt->payload_len = copy_len;
                }
            }
            break;
        case 17: /* UDP over IPv6 */
            {
                int udp_hdr_len = parse_udp(transport_data, transport_len, pkt);
                if (udp_hdr_len < 0) return -1;
                const uint8_t *app_data = transport_data + udp_hdr_len;
                uint32_t app_len = transport_len - (uint32_t)udp_hdr_len;
                if (app_len > 0) {
                    if (is_dns_port(pkt->udp.dst_port) || is_dns_port(pkt->udp.src_port)) {
                        dns_result_t dns;
                        if (parse_dns(app_data, (uint16_t)app_len, &dns) == 0) {
                            pkt->app_proto = PROTO_DNS;
                            pkt->dns = dns.header;
                        }
                    }
                    uint16_t copy_len = app_len > MAX_PAYLOAD ? MAX_PAYLOAD : (uint16_t)app_len;
                    memcpy(pkt->payload, app_data, copy_len);
                    pkt->payload_len = copy_len;
                }
            }
            break;
        case 58: /* ICMPv6 */
            if (parse_icmp(transport_data, transport_len, pkt) < 0) return -1;
            break;
        default:
            break;
        }
    }

    return 0;
}

void print_packet_info(const ParsedPacket *pkt)
{
    char mac_buf[32], ip_buf[32];

    printf("\n========== 数据包详情 ==========\n");
    printf("时间戳    : %ld.%06ld\n",
           (long)pkt->ts.tv_sec, (long)pkt->ts.tv_usec);
    printf("总长度    : %u bytes\n", pkt->packet_len);
    printf("捕获长度  : %u bytes\n", pkt->captured_len);

    /* Ethernet层 */
    mac_ntop(pkt->eth.src_mac, mac_buf, sizeof(mac_buf));
    printf("源MAC     : %s\n", mac_buf);
    mac_ntop(pkt->eth.dst_mac, mac_buf, sizeof(mac_buf));
    printf("目的MAC   : %s\n", mac_buf);
    printf("EtherType : 0x%04X\n", pkt->eth.ether_type);

    /* IP层 */
    if (pkt->layer3_proto == PROTO_IPV4) {
        unsigned char *src = (unsigned char *)&pkt->ipv4.src_ip;
        unsigned char *dst = (unsigned char *)&pkt->ipv4.dst_ip;
        snprintf(ip_buf, sizeof(ip_buf), "%u.%u.%u.%u", src[0], src[1], src[2], src[3]);
        printf("源IP       : %s\n", ip_buf);
        snprintf(ip_buf, sizeof(ip_buf), "%u.%u.%u.%u", dst[0], dst[1], dst[2], dst[3]);
        printf("目的IP     : %s\n", ip_buf);
        printf("TTL        : %u\n", pkt->ipv4.ttl);
        printf("协议号     : %u", pkt->ipv4.protocol);
        switch (pkt->ipv4.protocol) {
        case 6:  printf(" (TCP)\n"); break;
        case 17: printf(" (UDP)\n"); break;
        case 1:  printf(" (ICMP)\n"); break;
        default: printf(" (Other)\n"); break;
        }
    } else if (pkt->layer3_proto == PROTO_IPV6) {
        printf("源IP       : %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
               pkt->ipv6.src_ip[0], pkt->ipv6.src_ip[1],
               pkt->ipv6.src_ip[2], pkt->ipv6.src_ip[3],
               pkt->ipv6.src_ip[4], pkt->ipv6.src_ip[5],
               pkt->ipv6.src_ip[6], pkt->ipv6.src_ip[7],
               pkt->ipv6.src_ip[8], pkt->ipv6.src_ip[9],
               pkt->ipv6.src_ip[10], pkt->ipv6.src_ip[11],
               pkt->ipv6.src_ip[12], pkt->ipv6.src_ip[13],
               pkt->ipv6.src_ip[14], pkt->ipv6.src_ip[15]);
        printf("目的IP     : %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
               pkt->ipv6.dst_ip[0], pkt->ipv6.dst_ip[1],
               pkt->ipv6.dst_ip[2], pkt->ipv6.dst_ip[3],
               pkt->ipv6.dst_ip[4], pkt->ipv6.dst_ip[5],
               pkt->ipv6.dst_ip[6], pkt->ipv6.dst_ip[7],
               pkt->ipv6.dst_ip[8], pkt->ipv6.dst_ip[9],
               pkt->ipv6.dst_ip[10], pkt->ipv6.dst_ip[11],
               pkt->ipv6.dst_ip[12], pkt->ipv6.dst_ip[13],
               pkt->ipv6.dst_ip[14], pkt->ipv6.dst_ip[15]);
        printf("Hop Limit  : %u\n", pkt->ipv6.hop_limit);
        printf("Next Hdr   : %u", pkt->ipv6.next_header);
        switch (pkt->ipv6.next_header) {
        case 6:  printf(" (TCP)\n"); break;
        case 17: printf(" (UDP)\n"); break;
        case 58: printf(" (ICMPv6)\n"); break;
        default: printf(" (Other)\n"); break;
        }
    }

    /* 传输层 */
    if (pkt->layer4_proto == PROTO_TCP) {
        printf("源端口     : %u\n", pkt->tcp.src_port);
        printf("目的端口   : %u\n", pkt->tcp.dst_port);
        printf("序列号     : %u\n", pkt->tcp.seq_num);
        printf("确认号     : %u\n", pkt->tcp.ack_num);
        printf("标志位     : 0x%02X", pkt->tcp.flags);
        if (pkt->tcp.flags & 0x02) printf(" SYN");
        if (pkt->tcp.flags & 0x10) printf(" ACK");
        if (pkt->tcp.flags & 0x01) printf(" FIN");
        if (pkt->tcp.flags & 0x04) printf(" RST");
        if (pkt->tcp.flags & 0x08) printf(" PSH");
        printf("\n");
        printf("窗口大小   : %u\n", pkt->tcp.window_size);
    } else if (pkt->layer4_proto == PROTO_UDP) {
        printf("源端口     : %u\n", pkt->udp.src_port);
        printf("目的端口   : %u\n", pkt->udp.dst_port);
        printf("UDP长度    : %u\n", pkt->udp.length);
    } else if (pkt->layer4_proto == PROTO_ICMP) {
        printf("ICMP类型   : %u\n", pkt->icmp.type);
        printf("ICMP代码   : %u\n", pkt->icmp.code);
    }

    /* 应用层 */
    if (pkt->app_proto == PROTO_DNS) {
        printf("应用协议   : DNS\n");
        printf("DNS事务ID  : 0x%04X\n", pkt->dns.transaction_id);
        printf("DNS标志    : 0x%04X\n", pkt->dns.flags);
    } else if (pkt->app_proto == PROTO_HTTP_REQUEST) {
        printf("应用协议   : HTTP请求\n");
    } else if (pkt->app_proto == PROTO_HTTP_RESPONSE) {
        printf("应用协议   : HTTP响应\n");
    }

    if (pkt->payload_len > 0) {
        printf("载荷长度   : %u bytes\n", pkt->payload_len);
    }

    printf("=================================\n");
}

void print_packet_brief(const ParsedPacket *pkt, int seq)
{
    char src_ip_buf[32] = "?";
    char dst_ip_buf[32] = "?";
    char proto_str[16] = "???";
    uint16_t src_port = 0, dst_port = 0;

    if (pkt->layer3_proto == PROTO_IPV4) {
        unsigned char *src = (unsigned char *)&pkt->ipv4.src_ip;
        unsigned char *dst = (unsigned char *)&pkt->ipv4.dst_ip;
        snprintf(src_ip_buf, sizeof(src_ip_buf), "%u.%u.%u.%u", src[0], src[1], src[2], src[3]);
        snprintf(dst_ip_buf, sizeof(dst_ip_buf), "%u.%u.%u.%u", dst[0], dst[1], dst[2], dst[3]);
    } else if (pkt->layer3_proto == PROTO_IPV6) {
        snprintf(src_ip_buf, sizeof(src_ip_buf),
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 pkt->ipv6.src_ip[0], pkt->ipv6.src_ip[1],
                 pkt->ipv6.src_ip[2], pkt->ipv6.src_ip[3],
                 pkt->ipv6.src_ip[4], pkt->ipv6.src_ip[5],
                 pkt->ipv6.src_ip[6], pkt->ipv6.src_ip[7],
                 pkt->ipv6.src_ip[8], pkt->ipv6.src_ip[9],
                 pkt->ipv6.src_ip[10], pkt->ipv6.src_ip[11],
                 pkt->ipv6.src_ip[12], pkt->ipv6.src_ip[13],
                 pkt->ipv6.src_ip[14], pkt->ipv6.src_ip[15]);
        snprintf(dst_ip_buf, sizeof(dst_ip_buf),
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 pkt->ipv6.dst_ip[0], pkt->ipv6.dst_ip[1],
                 pkt->ipv6.dst_ip[2], pkt->ipv6.dst_ip[3],
                 pkt->ipv6.dst_ip[4], pkt->ipv6.dst_ip[5],
                 pkt->ipv6.dst_ip[6], pkt->ipv6.dst_ip[7],
                 pkt->ipv6.dst_ip[8], pkt->ipv6.dst_ip[9],
                 pkt->ipv6.dst_ip[10], pkt->ipv6.dst_ip[11],
                 pkt->ipv6.dst_ip[12], pkt->ipv6.dst_ip[13],
                 pkt->ipv6.dst_ip[14], pkt->ipv6.dst_ip[15]);
    }

    if (pkt->layer4_proto == PROTO_TCP) {
        strncpy(proto_str, "TCP", sizeof(proto_str) - 1);
        src_port = pkt->tcp.src_port;
        dst_port = pkt->tcp.dst_port;
    } else if (pkt->layer4_proto == PROTO_UDP) {
        strncpy(proto_str, "UDP", sizeof(proto_str) - 1);
        src_port = pkt->udp.src_port;
        dst_port = pkt->udp.dst_port;
    } else if (pkt->layer4_proto == PROTO_ICMP) {
        strncpy(proto_str, "ICMP", sizeof(proto_str) - 1);
    } else if (pkt->layer2_proto == PROTO_ARP) {
        strncpy(proto_str, "ARP", sizeof(proto_str) - 1);
    }

    printf("[%4d] %-5s %-16s:%-5d -> %-16s:%-5d  len=%u",
           seq, proto_str, src_ip_buf, src_port, dst_ip_buf, dst_port,
           pkt->packet_len);

    if (pkt->app_proto == PROTO_DNS)       printf(" [DNS]");
    if (pkt->app_proto == PROTO_HTTP_REQUEST)  printf(" [HTTP-Req]");
    if (pkt->app_proto == PROTO_HTTP_RESPONSE) printf(" [HTTP-Rsp]");
    printf("\n");
}

/* ---- pcap回调函数 ---- */
typedef struct {
    int count;
    int verbose;
} analyze_callback_ctx_t;

static void analyze_callback(unsigned char *user,
                              const struct pcap_pkthdr *header,
                              const u_char *data)
{
    analyze_callback_ctx_t *ctx = (analyze_callback_ctx_t *)user;
    ParsedPacket pkt;

    pkt.ts = header->ts;
    pkt.packet_len = header->len;
    pkt.captured_len = header->caplen;

    if (analyze_packet(data, (uint32_t)header->caplen, &pkt) == 0) {
        ctx->count++;
        if (ctx->verbose) {
            print_packet_brief(&pkt, ctx->count);
        }
    } else {
        ctx->count++;
        if (ctx->verbose) {
            printf("[%4d] <解析失败> len=%u\n", ctx->count, header->caplen);
        }
    }
}

int analyze_pcap_file(const char *filename, int verbose)
{
    return analyze_pcap_file_with_filter(filename, NULL, verbose);
}

int analyze_pcap_file_with_filter(const char *filename, const char *filter_exp,
                                   int verbose)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

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

    if (verbose) {
        printf("\n========== 协议分析 ==========\n");
        printf("文件：%s\n", filename);
        if (filter_exp != NULL && filter_exp[0] != '\0') {
            printf("过滤规则：%s\n", filter_exp);
        }
        printf("------------------------------\n");
    }

    analyze_callback_ctx_t ctx;
    ctx.count = 0;
    ctx.verbose = verbose;

    pcap_loop(handle, 0, analyze_callback, (unsigned char *)&ctx);

    if (verbose) {
        printf("------------------------------\n");
        printf("共解析 %d 个数据包\n", ctx.count);
        printf("==============================\n");
    }

    pcap_close(handle);
    return ctx.count;
}
