/**
 * protocol_analyze.c - 协议分析整合层实现
 *
 * 成员C创建的整合模块
 *
 * 解析链路：
 *   Ethernet -> IPv4/IPv6/ARP
 *            -> TCP/UDP/ICMP
 *            -> DNS(port 53) / HTTP(port 80,8080,8000,443)
 *
 * 网络字节序处理：
 *   所有多字节字段从网络字节序(大端)转换为主机字节序
 *   使用ntohs/ntohl进行转换
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
#include "dns_parser.h"
#include "http_parser.h"
#include "bpf_filter.h"
#include "net_utils.h"

/* ---- EtherType 常量 ---- */
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86DD
#define ETHERTYPE_ARP  0x0806

/* ---- IP 协议号常量 ---- */
#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP  6
#define IP_PROTO_UDP  17

/* ---- 常见应用层端口 ---- */
#define PORT_DNS       53
#define PORT_HTTP      80
#define PORT_HTTP_ALT  8080
#define PORT_HTTP_ALT2 8000
#define PORT_HTTPS     443

/* ---- 内部函数：解析Ethernet帧头 ---- */
static int parse_ethernet(const uint8_t *data, uint32_t len, ParsedPacket *pkt)
{
    if (len < 14) return -1;

    memcpy(pkt->eth.dst_mac, data, 6);
    memcpy(pkt->eth.src_mac, data + 6, 6);
    pkt->eth.ether_type = (data[12] << 8) | data[13];

    /* 设置链路层协议 */
    switch (pkt->eth.ether_type) {
    case ETHERTYPE_IPV4:
        pkt->layer2_proto = PROTO_IPV4;
        break;
    case ETHERTYPE_IPV6:
        pkt->layer2_proto = PROTO_IPV6;
        break;
    case ETHERTYPE_ARP:
        pkt->layer2_proto = PROTO_ARP;
        break;
    default:
        pkt->layer2_proto = PROTO_UNKNOWN;
        break;
    }

    return 14; /* Ethernet头长度 */
}

/* ---- 内部函数：解析IPv4头 ---- */
static int parse_ipv4(const uint8_t *data, uint32_t len, ParsedPacket *pkt)
{
    if (len < 20) return -1;

    pkt->ipv4.version_ihl    = data[0];
    pkt->ipv4.dscp_ecn       = data[1];
    pkt->ipv4.total_length   = (data[2] << 8) | data[3];
    pkt->ipv4.identification = (data[4] << 8) | data[5];
    pkt->ipv4.flags_fragment = (data[6] << 8) | data[7];
    pkt->ipv4.ttl            = data[8];
    pkt->ipv4.protocol       = data[9];
    pkt->ipv4.header_checksum = (data[10] << 8) | data[11];
    memcpy(&pkt->ipv4.src_ip, data + 12, 4);
    memcpy(&pkt->ipv4.dst_ip, data + 16, 4);

    pkt->layer3_proto = PROTO_IPV4;

    /* 计算IP头长度 */
    uint8_t ihl = pkt->ipv4.version_ihl & 0x0F;
    int ip_hdr_len = ihl * 4;

    if (ip_hdr_len < 20 || (uint32_t)ip_hdr_len > len) {
        return -1;
    }

    return ip_hdr_len;
}

/* ---- 内部函数：解析TCP头 ---- */
static int parse_tcp(const uint8_t *data, uint32_t len, ParsedPacket *pkt)
{
    if (len < 20) return -1;

    pkt->tcp.src_port       = (data[0] << 8) | data[1];
    pkt->tcp.dst_port       = (data[2] << 8) | data[3];
    pkt->tcp.seq_num        = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) |
                              ((uint32_t)data[6] << 8) | data[7];
    pkt->tcp.ack_num        = ((uint32_t)data[8] << 24) | ((uint32_t)data[9] << 16) |
                              ((uint32_t)data[10] << 8) | data[11];
    pkt->tcp.data_offset    = data[12];
    pkt->tcp.flags          = data[13];
    pkt->tcp.window_size    = (data[14] << 8) | data[15];
    pkt->tcp.checksum       = (data[16] << 8) | data[17];
    pkt->tcp.urgent_pointer = (data[18] << 8) | data[19];

    pkt->layer4_proto = PROTO_TCP;

    /* 计算TCP头长度 */
    uint8_t data_off = (pkt->tcp.data_offset >> 4) & 0x0F;
    int tcp_hdr_len = data_off * 4;

    if (tcp_hdr_len < 20 || (uint32_t)tcp_hdr_len > len) {
        tcp_hdr_len = 20;
    }

    return tcp_hdr_len;
}

/* ---- 内部函数：解析UDP头 ---- */
static int parse_udp(const uint8_t *data, uint32_t len, ParsedPacket *pkt)
{
    if (len < 8) return -1;

    pkt->udp.src_port = (data[0] << 8) | data[1];
    pkt->udp.dst_port = (data[2] << 8) | data[3];
    pkt->udp.length   = (data[4] << 8) | data[5];
    pkt->udp.checksum = (data[6] << 8) | data[7];

    pkt->layer4_proto = PROTO_UDP;

    return 8; /* UDP头固定8字节 */
}

/* ---- 内部函数：解析ICMP头 ---- */
static int parse_icmp(const uint8_t *data, uint32_t len, ParsedPacket *pkt)
{
    if (len < 4) return -1;

    pkt->icmp.type     = data[0];
    pkt->icmp.code     = data[1];
    pkt->icmp.checksum = (data[2] << 8) | data[3];

    pkt->layer4_proto = PROTO_ICMP;

    return 4; /* ICMP最小头长度 */
}

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

    /* ParsedPacket应已被memset清零，这里确保 */
    pkt->layer2_proto = PROTO_UNKNOWN;
    pkt->layer3_proto = PROTO_UNKNOWN;
    pkt->layer4_proto = PROTO_UNKNOWN;
    pkt->app_proto = PROTO_UNKNOWN;

    /* ---- 第一层：Ethernet ---- */
    int eth_len = parse_ethernet(raw_data, len, pkt);
    if (eth_len < 0) return -1;

    const uint8_t *ip_data = raw_data + eth_len;
    uint32_t ip_len = len - eth_len;

    /* ---- 第二层：IPv4 / ARP ---- */
    if (pkt->eth.ether_type == ETHERTYPE_IPV4) {
        int ip_hdr_len = parse_ipv4(ip_data, ip_len, pkt);
        if (ip_hdr_len < 0) return -1;

        const uint8_t *transport_data = ip_data + ip_hdr_len;
        uint32_t transport_len = ip_len - ip_hdr_len;

        /* ---- 第三层：TCP / UDP / ICMP ---- */
        switch (pkt->ipv4.protocol) {
        case IP_PROTO_TCP:
            {
                int tcp_hdr_len = parse_tcp(transport_data, transport_len, pkt);
                if (tcp_hdr_len < 0) return -1;

                const uint8_t *app_data = transport_data + tcp_hdr_len;
                uint32_t app_len = transport_len - tcp_hdr_len;

                /* ---- 第四层：HTTP ---- */
                if (app_len > 0) {
                    /* 优先检查端口号 */
                    if (is_http_port(pkt->tcp.dst_port) || is_http_port(pkt->tcp.src_port)) {
                        /* 尝试HTTP解析 */
                        http_result_t http;
                        if (parse_http(app_data, (int)app_len, &http) == 0) {
                            pkt->app_proto = (http.type == HTTP_TYPE_REQUEST) ?
                                             PROTO_HTTP_REQUEST : PROTO_HTTP_RESPONSE;
                        }
                        free_http_result(&http);
                    }

                    /* DNS over TCP (不太常见但支持) */
                    if (is_dns_port(pkt->tcp.dst_port) || is_dns_port(pkt->tcp.src_port)) {
                        if (app_len > 2) {
                            /* TCP DNS有2字节长度前缀 */
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

        case IP_PROTO_UDP:
            {
                int udp_hdr_len = parse_udp(transport_data, transport_len, pkt);
                if (udp_hdr_len < 0) return -1;

                const uint8_t *app_data = transport_data + udp_hdr_len;
                uint32_t app_len = transport_len - udp_hdr_len;

                /* ---- 第四层：DNS ---- */
                if (app_len > 0) {
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

        case IP_PROTO_ICMP:
            {
                int icmp_hdr_len = parse_icmp(transport_data, transport_len, pkt);
                if (icmp_hdr_len < 0) return -1;
            }
            break;

        default:
            break;
        }
    } else if (pkt->eth.ether_type == ETHERTYPE_ARP) {
        /* ARP包，只标记协议类型 */
        pkt->layer2_proto = PROTO_ARP;
    } else if (pkt->eth.ether_type == ETHERTYPE_IPV6) {
        pkt->layer3_proto = PROTO_IPV6;
        /* IPv6解析留待成员B实现 */
    }

    return 0;
}

void print_packet_info(const ParsedPacket *pkt)
{
    char mac_buf[32], ip_buf[32];

    printf("\n========== 数据包详情 ==========\n");

    /* 时间戳 */
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

    /* 载荷 */
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

    if (pkt->app_proto == PROTO_DNS) {
        printf(" [DNS]");
    } else if (pkt->app_proto == PROTO_HTTP_REQUEST) {
        printf(" [HTTP-Req]");
    } else if (pkt->app_proto == PROTO_HTTP_RESPONSE) {
        printf(" [HTTP-Rsp]");
    }
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

    memset(&pkt, 0, sizeof(pkt));
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

    /* 应用BPF过滤（如果指定） */
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
