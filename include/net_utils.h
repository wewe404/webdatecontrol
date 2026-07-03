#ifndef NET_UTILS_H
#define NET_UTILS_H

/*
 * net_utils.h - 网络工具函数模块
 * ==============================
 * 提供跨模块通用的网络字节序处理、地址转换、校验和计算等工具函数。
 * 所有模块（A/B/C/D）都可以引用此文件。
 *
 * 设计原则：
 * - 纯函数，不依赖全局状态
 * - 线程安全（只操作传入的参数）
 */

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>   /* inet_ntop, socklen_t, in6_addr */
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========== MAC 地址 ========== */

/*
 * MAC 地址转可读字符串
 * 输入: mac — 6字节的MAC地址数组
 * 输出: buf — 输出缓冲区（至少 18 字节: "xx:xx:xx:xx:xx:xx\0"）
 * 返回: buf 指针
 * 
 * 示例:
 *   unsigned char mac[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
 *   char str[18];
 *   mac_ntop(mac, str, sizeof(str));
 *   // str == "aa:bb:cc:dd:ee:ff"
 */
char* mac_ntop(const unsigned char *mac, char *buf, size_t size);

/* MAC 地址从字符串解析为字节数组 ("xx:xx:xx:xx:xx:xx" -> 6字节) */
int mac_pton(const char *str, unsigned char *mac);

/* ========== IP 地址 ========== */

/*
 * IPv4 地址转字符串（in_addr 结构 -> "xxx.xxx.xxx.xxx"）
 * 是对 inet_ntoa 的线程安全封装（使用静态内部缓冲的简单封装）
 */
char* ipv4_ntop(const struct in_addr *addr, char *buf, size_t size);

/* IPv6 地址转字符串 */
char* ipv6_ntop(const struct in6_addr *addr, char *buf, size_t size);

/* ========== 校验和 ========== */

/*
 * 计算 IP/TCP/UDP 校验和（RFC 1071）
 * 
 * 算法：
 *   1. 将数据按 16-bit 一组求和
 *   2. 若长度为奇数，最后补一个 0x00 字节
 *   3. 将高16位进位加到低16位，直到无进位
 *   4. 取反（one's complement）
 *
 * 输入: buf — 数据指针
 *       len — 数据长度（字节）
 * 返回: 16位校验和（网络字节序）
 *
 * 注意：
 * - 计算 TCP/UDP 校验和时，需要包含伪头部（Pseudo Header）
 * - 计算 IP 头部校验和时，checksum 字段本身应置为 0
 */
unsigned short checksum(unsigned short *buf, int len);

/*
 * 计算 TCP 伪头部校验和
 * 包含：源IP(4B) + 目的IP(4B) + 0x00(1B) + protocol(1B) + TCP长度(2B) + TCP段
 */
unsigned short tcp_checksum(const struct in_addr *src, const struct in_addr *dst,
                            unsigned char protocol,
                            const unsigned char *tcp_segment, int segment_len);

/* ========== 便捷宏 ========== */

/* 16/32位网络字节序与主机字节序互换的明确命名 */
#define NET_TO_HOST16(x)  ntohs(x)
#define NET_TO_HOST32(x)  ntohl(x)
#define HOST_TO_NET16(x)  htons(x)
#define HOST_TO_NET32(x)  htonl(x)

#ifdef __cplusplus
}
#endif

#endif /* NET_UTILS_H */
