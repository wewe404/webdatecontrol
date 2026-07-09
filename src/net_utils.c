/*
 * net_utils.c - 网络工具函数实现
 *
 * 成员A负责模块
 *
 * 主要完成：
 * 1. MAC地址字符串转换
 * 2. IPv4地址字符串转换
 * 3. 16位网络校验和计算
 * 4. 网络工具函数单元自测
 */
#include <stdio.h>
#include "net_utils.h"

/* MAC地址转字符串 */
void mac_ntop(const unsigned char mac[6], char *buf, size_t size)
{
    snprintf(buf, size, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* IPv4地址转字符串 */
void ip_ntop(const unsigned char ip[4], char *buf, size_t size)
{
    snprintf(buf, size, "%u.%u.%u.%u",
             ip[0], ip[1], ip[2], ip[3]);
}

/* 计算16位校验和 */
unsigned short checksum16(const unsigned char *data, int len)
{
    unsigned int sum = 0;

    while (len > 1)
    {
        sum += (data[0] << 8) | data[1];
        data += 2;
        len -= 2;
    }

    if (len == 1)
    {
        sum += data[0] << 8;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (unsigned short)(~sum);
}

/* 工具函数自测 */
void net_utils_self_test(void)
{
    unsigned char mac[6] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    unsigned char ip[4] = {192, 168, 31, 143};
    unsigned char test_data[8] = {0x45, 0x00, 0x00, 0x54, 0x12, 0x34, 0x00, 0x00};

    char mac_buf[32];
    char ip_buf[32];
    unsigned short sum;

    mac_ntop(mac, mac_buf, sizeof(mac_buf));
    ip_ntop(ip, ip_buf, sizeof(ip_buf));
    sum = checksum16(test_data, sizeof(test_data));

    printf("\n========== 工具函数自测 ==========\n");
    printf("MAC 转换结果：%s\n", mac_buf);
    printf("IP 转换结果 ：%s\n", ip_buf);
    printf("校验和结果 ：0x%04X\n", sum);
    printf("工具函数自测完成。\n");
}