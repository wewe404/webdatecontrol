
#include "eth_parser.h"
#include <arpa/inet.h>   // 用于 ntohs()
#include <stdio.h>       // 用于 printf（后续可替换为日志）

int parse_ethernet(const unsigned char *raw_data) {
    if (raw_data == NULL) {
        return -1;
    }

    // 强制转换为以太网头部结构体指针
    ethernet_header_t *eth = (ethernet_header_t *)raw_data;
    
    // 转换字节序获取上层协议类型
    uint16_t ether_type = ntohs(eth->ether_type);

    // 【调试打印】后面可以和组长对接去掉这部分，或改用日志模块
    printf("【以太网层】\n");
    printf("  目标MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           eth->dst_mac[0], eth->dst_mac[1], eth->dst_mac[2],
           eth->dst_mac[3], eth->dst_mac[4], eth->dst_mac[5]);
    printf("  源MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
           eth->src_mac[3], eth->src_mac[4], eth->src_mac[5]);
    printf("  上层协议: 0x%04x ", ether_type);
    
    // 打印协议名称
    if (ether_type == 0x0800) printf("(IPv4)\n");
    else if (ether_type == 0x86DD) printf("(IPv6)\n");
    else if (ether_type == 0x0806) printf("(ARP)\n");
    else printf("(未知协议)\n");

    return ether_type;  // 返回上层协议类型，供上层调用者判断
}