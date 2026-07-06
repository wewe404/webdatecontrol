#include "ip_parser.h"
#include "net_utils.h"      // 包含 checksum16 校验和函数
#include <arpa/inet.h>      // ntohs, ntohl
#include <stdio.h>
#include <string.h>

int parse_ipv4(const unsigned char *raw_data) {
    if (raw_data == NULL) {
        return -1;
    }

    ipv4_header_t *ip = (ipv4_header_t *)raw_data;

    // 1. 提取头部长度 (IHL) 和总长度
    uint8_t ihl = (ip->version_ihl & 0x0F) * 4;   // 低4位是IHL，单位4字节
    uint16_t total_len = ntohs(ip->total_length);
    
    // 防御性检查：头部长度不能小于20字节，也不能大于总长度
    if (ihl < 20 || ihl > total_len) {
        printf("【IPv4】头部长度异常: IHL=%d, TotalLen=%d\n", ihl, total_len);
        return -1;
    }

    // 2. 校验和验证（验收必考点！）
    // 校验和只覆盖头部（前 ihl 个字节），不包含数据
    uint16_t recv_checksum = ip->header_checksum;
    // 计算校验和时，需要把头部校验和字段置0再计算
    uint16_t calc_checksum = checksum16(raw_data, ihl);
    
    // 因为 checksum16 计算时默认包含所有字节，而头部里的校验和字段是网络字节序，
    // 标准做法：将接收到的校验和转为网络字节序进行比较，或者计算时直接忽略。
    // 简单有效的方法：如果计算出的校验和 + 接收到的校验和 == 0xFFFF，则校验通过。
    // 注意：checksum16 返回的是已取反的校验和，所以相加应为 0xFFFF。
    if ( (calc_checksum + ntohs(recv_checksum)) != 0xFFFF && 
         (calc_checksum + ntohs(recv_checksum)) != 0x0000 ) {
        // 极少情况下校验和为 0x0000 也视为有效（但实际很少见）
        printf("【IPv4】校验和验证失败！Calc: 0x%04X, Recv: 0x%04X\n", 
               calc_checksum, ntohs(recv_checksum));
        return -1;
    }

    // 3. 提取并打印关键信息（调试用）
    uint32_t src_ip = ip->src_ip;
    uint32_t dst_ip = ip->dst_ip;
    
    // 将IP地址转为字符串格式
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = src_ip;
    dst_addr.s_addr = dst_ip;

    printf("【IPv4层】\n");
    printf("  版本: %d, 头部长度: %d 字节\n", (ip->version_ihl >> 4), ihl);
    printf("  总长度: %d 字节\n", total_len);
    printf("  TTL: %d\n", ip->ttl);
    printf("  上层协议: %d %s\n", ip->protocol, 
           ip->protocol == 6 ? "(TCP)" : 
           ip->protocol == 17 ? "(UDP)" : 
           ip->protocol == 1 ? "(ICMP)" : "(Unknown)");
    printf("  源IP: %s\n", inet_ntoa(src_addr));
    printf("  目标IP: %s\n", inet_ntoa(dst_addr));
    printf("  校验和: %s\n", 
           (calc_checksum + ntohs(recv_checksum)) == 0xFFFF ? "验证通过 ✅" : "验证失败 ❌");

    // 4. 返回 IP 载荷的偏移量（即 TCP/UDP 数据的起始位置相对于 raw_data 的偏移）
    // 这样上层解析器可以直接从 raw_data + payload_offset 开始解析 TCP/UDP
    return ihl;
}