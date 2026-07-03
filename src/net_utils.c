/*
 * net_utils.c - 网络工具函数实现
 * ==============================
 *
 * 实现思路详解：
 *
 * 1. mac_ntop — MAC地址格式化
 *    ------------------------------------------------
 *    sprintf 逐个字节以 %02x 格式化即可。
 *    注意：MAC地址通常用小写十六进制，冒号分隔。
 *    每个字节占2字符+1冒号（最后一个字节后不跟冒号）。
 *    6字节共 "xx:xx:xx:xx:xx:xx" = 17字符 + 1 null = 18字节。
 *
 * 2. checksum — RFC 1071 校验和
 *    ------------------------------------------------
 *    这是网络协议最经典的算法之一，用于 IP/TCP/UDP 头部完整性验证。
 *    
 *    原理：
 *    a. 把数据看成一系列 16-bit 整数（大端序）
 *    b. 全部累加
 *    c. 每产生一次进位（> 0xFFFF），就加到低位
 *    d. 最后取反码
 *    
 *    为什么取反码？
 *    接收方验证时，把整个头部（含校验和字段）一起求checksum，
 *    结果应为 0xFFFF。取反码使得硬件实现简单。
 *
 * 3. tcp_checksum — TCP伪头部校验和
 *    ------------------------------------------------
 *    TCP校验和不仅覆盖TCP段本身，还要覆盖"伪头部"。
 *    伪头部包含：源IP(4) + 目的IP(4) + 保留(1) + 协议号(1) + TCP长度(2)
 *    这是为了检测IP层的地址或协议字段被篡改。
 *    UDP校验和也使用同样的方式。
 *
 *    实现方式：
 *    - 构造一个12字节的伪头部缓冲区
 *    - 将伪头部和TCP段拼接在一起计算校验和
 *    - 注意TCP段中的 checksum 字段应置为0参与计算
 */

#include <string.h>
#include "net_utils.h"

/* ========== MAC 地址 ========== */

char* mac_ntop(const unsigned char *mac, char *buf, size_t size)
{
    if (!mac || !buf || size < 18) return NULL;

    /*
     * 使用 snprintf 逐个字节格式化。
     * %02x：两位小写十六进制，不足补零。
     * 每次写 "xx:"，到最后一个字节只写 "xx"。
     */
    char *p = buf;
    size_t remaining = size;

    for (int i = 0; i < 6; i++) {
        int written;
        if (i < 5) {
            written = _snprintf(p, remaining, "%02x:", mac[i]);
        } else {
            written = _snprintf(p, remaining, "%02x", mac[i]);
        }
        if (written < 0 || (size_t)written >= remaining) {
            /* 缓冲区不足 */
            buf[0] = '\0';
            return NULL;
        }
        p += written;
        remaining -= written;
    }

    return buf;
}

int mac_pton(const char *str, unsigned char *mac)
{
    /*
     * 从 "xx:xx:xx:xx:xx:xx" 解析为6字节
     * 支持小写/大写十六进制 
     */
    if (!str || !mac) return -1;

    unsigned int bytes[6];
    if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
               &bytes[0], &bytes[1], &bytes[2],
               &bytes[3], &bytes[4], &bytes[5]) != 6) {
        return -1;
    }

    for (int i = 0; i < 6; i++) {
        mac[i] = (unsigned char)bytes[i];
    }
    return 0;
}

/* ========== IP 地址 ========== */

char* ipv4_ntop(const struct in_addr *addr, char *buf, size_t size)
{
    if (!addr || !buf || size < 16) return NULL;

    /*
     * inet_ntop 是 POSIX 标准函数，Windows 下在 <ws2tcpip.h> 中。
     * AF_INET 表示 IPv4，输出格式 "xxx.xxx.xxx.xxx"。
     */
    const char *ret = inet_ntop(AF_INET, addr, buf, (socklen_t)size);
    return (char*)ret;
}

char* ipv6_ntop(const struct in6_addr *addr, char *buf, size_t size)
{
    if (!addr || !buf || size < 46) return NULL;

    const char *ret = inet_ntop(AF_INET6, addr, buf, (socklen_t)size);
    return (char*)ret;
}

/* ========== 校验和 ========== */

unsigned short checksum(unsigned short *buf, int len)
{
    /*
     * RFC 1071 实现
     *
     * 逐段理解：
     * 1. sum 是 32-bit 累加器，因为16-bit加法可能产生进位
     * 2. 每次取 16-bit（注意是网络字节序大端），累加
     * 3. 如果 len 是奇数，最后多出来的一个字节补0当作16-bit处理
     * 4. 循环将高16位进位加到低16位（最多需要2次，因为最大进位值很小）
     * 5. 取反码 (~sum & 0xFFFF)
     */
    unsigned long sum = 0;

    /* 主循环：成对处理16-bit字 */
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    /* 如果还剩1个奇数长度的字节，补0 */
    if (len == 1) {
        unsigned short last = *(unsigned char*)buf;
        sum += last;
    }

    /* 将进位从高16位折叠到低16位 */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    /* 返回反码（取反后转为主机字节序无关，因为 checksum 是16位值）*/
    return (unsigned short)(~sum & 0xFFFF);
}

unsigned short tcp_checksum(const struct in_addr *src, const struct in_addr *dst,
                            unsigned char protocol,
                            const unsigned char *tcp_segment, int segment_len)
{
    /*
     * TCP/UDP 伪头部结构：
     *   0                   16                   31
     *   +-------------------+-------------------+
     *   |        源 IP 地址 (32-bit)            |
     *   +-------------------+-------------------+
     *   |       目的 IP 地址 (32-bit)            |
     *   +-------------------+-------------------+
     *   |  保留(0x00) |协议  |   TCP/UDP 长度   |
     *   +-------------------+-------------------+
     *   |        TCP/UDP 段 (变长)              |
     *   +-------------------+-------------------+
     *
     * 为什么要伪头部？
     * 防止 IP 层篡改地址或协议字段后转发。
     * TCP/UDP 校验和覆盖伪头部，任何改动都导致校验和不匹配。
     */

    /* 构建伪头部（12字节）*/
    unsigned char pseudo_header[12];
    int ph_len = 12;

    /* 拷贝源IP和目的IP（各4字节）*/
    memcpy(pseudo_header, src, 4);
    memcpy(pseudo_header + 4, dst, 4);

    /* 保留字段（1字节 0x00）+ 协议号（1字节）*/
    pseudo_header[8] = 0;
    pseudo_header[9] = protocol;

    /* TCP/UDP 段长度（网络字节序）*/
    unsigned short seg_len_net = htons((unsigned short)segment_len);
    memcpy(pseudo_header + 10, &seg_len_net, 2);

    /*
     * 构建完整缓冲区：伪头部 + TCP/UDP 段
     * 注意：这里的 TCP 段中的 checksum 字段应视为0参与计算
     *       （调用者应确保在传入前已清零，或者在计算时跳过）
     *
     * 由于我们要保持原始 tcp_segment 不变，不能直接修改其 checksum 字段。
     * 但实际计算时如果 tcp_segment 的 checksum 字段非零，
     * 结果会不同（等于做了一次校验收到的结果）。
     * 这里假设调用者已经清零了 checksum 字段，或者我们手动处理。
     *
     * 简便做法：分配临时缓冲区，复制数据，把 checksum 位置0。
     * 但分配大缓冲区有性能问题。这里做一个优化：
     * 伪头部 + 段一起计算，但在累加时跳过 checksum 字段。
     *
     * 更简单的实现：TCP checksum 字段在偏移 16 处（TCP header 第3个32-bit字）。
     * 我们在累加时把那两个字节设为0。
     * 
     * 但为了代码清晰，这里使用临时缓冲区的版本。
     */
    int total_len = ph_len + segment_len;
    unsigned char *buffer = (unsigned char*)malloc(total_len);
    if (!buffer) {
        return 0;  /* 内存不足时返回0（校验和通常不会全0，0是无效校验和）*/
    }

    /* 拷贝伪头部 */
    memcpy(buffer, pseudo_header, ph_len);
    /* 拷贝TCP/UDP段 */
    memcpy(buffer + ph_len, tcp_segment, segment_len);

    /* 
     * 清零 TCP/UDP段中的 checksum 字段（偏移 16）
     * TCP header 中 checksum 在第 16~17 字节（从0计数）
     */
    if (segment_len >= 18) {  /* 至少需要完整的20字节TCP头 */
        buffer[ph_len + 16] = 0;
        buffer[ph_len + 17] = 0;
    }

    unsigned short result = checksum((unsigned short*)buffer, total_len);

    free(buffer);
    return result;
}
