#ifndef CAPTURE_H
#define CAPTURE_H

/*
 * capture.h - 抓包引擎模块
 * ==========================
 * 职责：网卡枚举、打开设备、启动/停止抓包
 * 提供两种抓包模式：
 *   1. pcap_loop 回调模式 — 持续抓包，每抓到一包回调一次（推荐用于 UI 集成）
 *   2. pcap_next_ex 轮询模式 — 每次手动抓一个包（用于简单 CLI 场景）
 */

#include <pcap.h>
#include "packet.h"

/* ========== 抓包回调函数类型 ========== */
/* 当 pcap_loop 抓到数据包后，引擎会构造好 Packet 再调用此回调 */
typedef void (*packet_handler_t)(Packet *packet, void *userdata);

/* ========== 网卡操作 ========== */

/* 列出所有可用网卡，返回数量（-1 表示失败）*/
int list_devices(void);

/* 根据编号获取网卡名称 */
const char* get_device_by_index(int index);

/* 释放网卡列表（list_devices 后调用）*/
void free_device_list(void);

/* ========== 抓包引擎 ========== */

/*
 * 初始化抓包（新版：带参数配置）
 * - device:  网卡名称
 * - snaplen: 最大抓取字节（通常 65535）
 * - timeout: 读取超时(ms)，0 = 不超时
 * - promisc: 是否开启混杂模式（1=开启）
 * 返回 pcap_t* 句柄，失败返回 NULL
 */
pcap_t* capture_init_ex(const char *device, int snaplen, int timeout, int promisc);

/*
 * 初始化抓包（简易版，兼容旧代码）
 * 使用默认参数：snaplen=65535, timeout=1000, promisc=1
 */
pcap_t* capture_init(const char *device);

/*
 * 启动回调式抓包（pcap_loop 模式）
 * - handle:     pcap_t 句柄
 * - handler:    回调函数，每抓到一包调用一次
 * - userdata:   传递给回调的用户数据指针
 * - count:      抓包数量（-1 = 持续抓包直到出错或中断）
 * 返回 0=成功, -1=失败
 */
int start_capture_loop(pcap_t *handle, packet_handler_t handler,
                       void *userdata, int count);

/*
 * 抓取下一个数据包并返回 Packet 结构（pcap_next_ex 轮询模式）
 * - handle: pcap_t 句柄
 * - pkt:    输出参数，抓到的数据包
 * 返回 1=成功, 0=超时, -1=出错
 */
int capture_get_packet(pcap_t *handle, Packet *pkt);

/*
 * 内部回调适配器（将 libpcap 原生回调转换为 Packet 结构）
 * 通常不直接调用，而是通过 start_capture_loop 间接使用
 */
void pcap_callback_adapter(u_char *user, const struct pcap_pkthdr *header,
                           const u_char *packet_data);

/*
 * 旧版 API（向后兼容，保持原签名确保 main.c 无需修改）
 */

/* 准备抓包（旧版，仅打印提示）*/
void start_capture(pcap_t *handle);

/* 旧版抓取一个数据包（仅打印长度）*/
void capture_one_packet(pcap_t *handle);

/* ========== 辅助函数 ========== */

/* 将 libpcap 原始数据包装为统一的 Packet 结构 */
void packet_wrap(Packet *pkt, const struct pcap_pkthdr *header,
                 const u_char *data, LinkType linktype);

/* 获取数据链路层类型（从已打开的 pcap_t 句柄）*/
LinkType get_link_type(pcap_t *handle);

/* 获取网卡描述 */
const char* get_device_desc(int index);

/* ========== 资源管理 ========== */

/* 停止抓包并释放句柄 */
void stop_capture(pcap_t *handle);

/* 获取最后一次错误的描述 */
const char* get_last_error(void);

#endif /* CAPTURE_H */
