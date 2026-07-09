/*
 * net_utils.h - 网络工具函数接口声明
 *
 * 成员A负责模块
 *
 * 提供MAC/IP地址转换和校验和计算接口。
 */
#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <stddef.h>

/* MAC地址转字符串 */
void mac_ntop(const unsigned char mac[6], char *buf, size_t size);

/* IPv4地址转字符串 */
void ip_ntop(const unsigned char ip[4], char *buf, size_t size);

/* 计算16位校验和 */
unsigned short checksum16(const unsigned char *data, int len);

/* 工具函数自测 */
void net_utils_self_test(void);

#endif