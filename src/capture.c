/*
 * capture.c - 抓包引擎模块实现
 * ==============================
 *
 * 实现思路（逐功能说明）：
 *
 * 1. 网卡枚举 (list_devices)
 *    ------------------------------------------------
 *    使用 pcap_findalldevs() 获取系统中所有网卡设备链表。
 *    每个 pcap_if_t 节点包含 name（设备名，如 \Device\NPF_{...}) 
 *    和 description（可读描述）。
 *    打印时同时展示编号、名称和描述，让用户知道在选什么。
 *    最后用 pcap_freealldevs() 释放，避免内存泄漏。
 *
 * 2. 打开设备 (capture_init_ex)
 *    ------------------------------------------------
 *    pcap_open_live() 是核心：传入设备名、snaplen、混杂模式标志、
 *    超时时间和错误缓冲区。
 *    - snaplen=65535：捕获完整帧，不截断
 *    - promisc=1：混杂模式，接收所有经过网卡的数据包
 *    - timeout=1000ms：每1秒返回一次（即使没有包），
 *      让程序有机会处理其他逻辑
 *
 * 3. 回调式抓包 (start_capture_loop)
 *    ------------------------------------------------
 *    pcap_loop() 是 libpcap 的经典抓包模式。传入一个回调函数，
 *    libpcap 内部循环读取网卡 -> 每读到一个包就调用回调。
 *    相比手动 pcap_next_ex 轮询，它的好处是：
 *    - 底层做了缓冲优化，丢包率更低
 *    - 代码更简洁，不需要自己写循环
 *    缺点：回调里不能做耗时操作，否则会影响抓包性能。
 *    
 *    我们实现了一个中间层回调 (pcap_callback_adapter)：
 *    libpcap 原始回调的签名是 (u_char *user, 
 *    const struct pcap_pkthdr *header, const u_char *packet)
 *    我们在适配器里把原始数据包装成统一的 Packet 结构，
 *    再调用用户提供的 packet_handler_t。
 *    这样上层模块（D 的 UI、C 的统计）只需要处理 Packet 即可。
 *
 * 4. 单包轮询 (capture_one_packet)
 *    ------------------------------------------------
 *    pcap_next_ex() 每次调用尝试读取一个包。
 *    返回值：1=读到包，0=超时，-1=出错。
 *    适合简单场景：选择网卡 -> 抓10个包 -> 退出。
 *    性能不如 pcap_loop，因为每次调用都有用户态/内核态切换开销。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "capture.h"

/* ========== 内部全局变量（用于缓存网卡列表）========== */

static pcap_if_t *g_alldevs = NULL;
static int        g_dev_count = 0;
static char       g_errbuf[PCAP_ERRBUF_SIZE];

/* ========== 网卡操作 ========== */

int list_devices(void)
{
    /* 如果已缓存，先释放 */
    if (g_alldevs) {
        pcap_freealldevs(g_alldevs);
        g_alldevs = NULL;
        g_dev_count = 0;
    }

    if (pcap_findalldevs(&g_alldevs, g_errbuf) == -1) {
        printf("[-] 获取网卡列表失败：%s\n", g_errbuf);
        return -1;
    }

    int count = 0;
    pcap_if_t *dev;

    printf("\n========== 可用网卡 ==========\n");
    for (dev = g_alldevs; dev != NULL; dev = dev->next) {
        printf("  %d. %s", ++count, dev->name);
        if (dev->description && strlen(dev->description) > 0) {
            printf("\n     描述: %s", dev->description);
        }
        printf("\n");
    }

    if (count == 0) {
        printf("  (没有找到可用网卡)\n");
        return -1;
    }

    printf("==============================\n");
    g_dev_count = count;
    return count;
}

const char* get_device_by_index(int index)
{
    if (!g_alldevs || index < 1) return NULL;

    pcap_if_t *dev = g_alldevs;
    for (int i = 1; i < index && dev != NULL; i++) {
        dev = dev->next;
    }
    return dev ? dev->name : NULL;
}

const char* get_device_desc(int index)
{
    if (!g_alldevs || index < 1) return NULL;

    pcap_if_t *dev = g_alldevs;
    for (int i = 1; i < index && dev != NULL; i++) {
        dev = dev->next;
    }
    return (dev && dev->description) ? dev->description : "";
}

void free_device_list(void)
{
    if (g_alldevs) {
        pcap_freealldevs(g_alldevs);
        g_alldevs = NULL;
        g_dev_count = 0;
    }
}

/* ========== 抓包引擎 ========== */

pcap_t* capture_init_ex(const char *device, int snaplen, int timeout, int promisc)
{
    if (!device) {
        printf("[-] capture_init_ex: 设备名为空\n");
        return NULL;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_t *handle = pcap_open_live(device, snaplen, promisc, timeout, errbuf);
    
    if (handle == NULL) {
        printf("[-] 打开网卡 \"%s\" 失败：%s\n", device, errbuf);
        return NULL;
    }

    /* 检查链路层类型（目前只支持 Ethernet）*/
    int linktype = pcap_datalink(handle);
    if (linktype != DLT_EN10MB) {
        printf("[!] 警告：网卡链路层类型不是 Ethernet (ft=%d)，"
               "部分解析可能不适用\n", linktype);
    }

    printf("[+] 成功打开网卡：%s\n", device);
    return handle;
}

pcap_t* capture_init(const char *device)
{
    /* 
     * 简易版：使用标准参数
     * snaplen=65535 — 捕获完整以太网帧（最大1514字节通常足够）
     * timeout=1000  — 每秒返回一次，兼顾实时性和CPU
     * promisc=1     — 混杂模式
     */
    return capture_init_ex(device, 65535, 1000, 1);
}

/*
 * pcap_loop 的内部回调适配器
 *
 * 为什么要有这个适配器？
 * libpcap 的回调签名是固定死的：
 *   void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
 * 我们想暴露给上层的接口是：
 *   void handler(Packet *pkt, void *userdata)
 * 所以这个适配器做一件简单的事：
 *   把 (h, p) 包装成 Packet，然后调用 handler。
 * user 指针指向的是一个包含 {packet_handler_t, void*} 的结构体。
 *
 * 这样上层模块只管处理 Packet 就行，不用关心 pcap 细节。
 */
typedef struct {
    packet_handler_t handler;
    void            *userdata;
    LinkType         linktype;
} CallbackCtx;

void pcap_callback_adapter(u_char *user, const struct pcap_pkthdr *header,
                           const u_char *packet_data)
{
    CallbackCtx *ctx = (CallbackCtx*)user;
    if (!ctx || !ctx->handler) return;

    Packet pkt;
    packet_wrap(&pkt, header, packet_data, ctx->linktype);
    ctx->handler(&pkt, ctx->userdata);
}

int start_capture_loop(pcap_t *handle, packet_handler_t handler,
                       void *userdata, int count)
{
    if (!handle || !handler) {
        printf("[-] start_capture_loop: 参数无效\n");
        return -1;
    }

    LinkType linktype = get_link_type(handle);

    /*
     * 构造回调上下文。
     * CallbackCtx 在 pcap_loop 期间必须保持有效，
     * 所以用 malloc 分配堆内存。
     */
    CallbackCtx *ctx = (CallbackCtx*)malloc(sizeof(CallbackCtx));
    if (!ctx) {
        printf("[-] start_capture_loop: 内存分配失败\n");
        return -1;
    }
    ctx->handler  = handler;
    ctx->userdata = userdata;
    ctx->linktype = linktype;

    printf("[*] 开始抓包（回调模式），目标 %d 个包...\n", count);
    
    /*
     * pcap_loop(handle, count, callback, user)
     * - count: 抓 count 个包后返回；-1 表示持续抓直到出错
     * - 返回值：0=成功完成count个, -1=出错, -2=被pcap_breakloop中断
     */
    int ret = pcap_loop(handle, count, pcap_callback_adapter, (u_char*)ctx);
    
    free(ctx);

    if (ret == -1) {
        printf("[-] 抓包出错：%s\n", pcap_geterr(handle));
        return -1;
    } else if (ret == -2) {
        printf("[*] 抓包被中断\n");
        return -2;
    }

    printf("[+] 抓包完成\n");
    return 0;
}

int capture_get_packet(pcap_t *handle, Packet *pkt)
{
    if (!handle || !pkt) return -1;

    struct pcap_pkthdr *header;
    const u_char *data;

    /*
     * pcap_next_ex 的工作原理：
     * 内部维护一个缓冲，从网卡驱动批量读取数据包。
     * 返回值：
     *   1  — 成功，header 和 data 指向内部缓冲区的数据
     *   0  — 超时时间内没有包到达
     *  -1  — 出错
     *  -2  — 被 pcap_breakloop 中断（离线文件回放时出现）
     *
     * 注意：data 指针指向的是 pcap 内部缓冲区，
     *       在下一次调用 pcap_next_ex 前有效。
     *       如果需要长期保存，必须 memcpy 拷贝数据。
     */
    int res = pcap_next_ex(handle, &header, &data);

    if (res == 1) {
        packet_wrap(pkt, header, data, get_link_type(handle));
        return 1;
    } else if (res == 0) {
        /* 超时，没包 */
        return 0;
    } else {
        /* res == -1 或 -2 */
        if (res == -1) {
            printf("[-] pcap_next_ex 出错：%s\n", pcap_geterr(handle));
        }
        return -1;
    }
}

/* ========== 辅助函数 ========== */

void packet_wrap(Packet *pkt, const struct pcap_pkthdr *header,
                 const u_char *data, LinkType linktype)
{
    if (!pkt || !header || !data) return;

    packet_reset(pkt);

    /* 复制包头信息（时间戳、长度）*/
    memcpy(&pkt->header, header, sizeof(struct pcap_pkthdr));

    /*
     * 注意：data 指针指向 libpcap 内部缓冲区。
     * 在回调模式和 pcap_next_ex 模式下，数据存活期不同：
     * - 回调模式：调用回调时有效，回调返回后可能被覆盖
     * - pcap_next_ex：下次调用前有效
     * 
     * 如果要异步处理包（比如放入队列让UI线程显示），
     * 必须 memcpy 拷贝整包数据。
     * 这里只保存指针，假设调用者会在有效期内使用。
     */
    pkt->data     = data;
    pkt->data_len = header->caplen;  /* caplen = 实际捕获长度 */
    pkt->linktype = linktype;

    /* 检查是否被 snaplen 截断 */
    if (header->caplen < header->len) {
        pkt->truncated = 1;
    }

    /* 推入链路层协议 */
    if (linktype == LINKTYPE_ETHERNET) {
        packet_push_proto(pkt, PROTO_ETHERNET);
    }
}

LinkType get_link_type(pcap_t *handle)
{
    if (!handle) return LINKTYPE_UNKNOWN;

    switch (pcap_datalink(handle)) {
        case DLT_EN10MB: return LINKTYPE_ETHERNET;
        case DLT_RAW:    return LINKTYPE_RAW;
        case DLT_NULL:   return LINKTYPE_NULL;
        default:         return LINKTYPE_UNKNOWN;
    }
}

/* ========== 旧版 API（向后兼容）========== */

void start_capture(pcap_t *handle)
{
    if (handle == NULL) {
        printf("抓包句柄为空。\n");
        return;
    }

    printf("抓包模块已准备完成。\n");
}

void capture_one_packet(pcap_t *handle)
{
    struct pcap_pkthdr *header;
    const u_char *data;

    int res;
    int timeout_count = 0;

    /*
     * 等待数据包时不能死循环——用户不知道是在抓包还是卡死了。
     * 每次 pcap_next_ex 超时（返回0，默认1秒），打印一个提示并继续尝试。
     * 这让用户知道程序还在跑，只是网络没流量。
     */
    while ((res = pcap_next_ex(handle, &header, &data)) == 0)
    {
        timeout_count++;
        if (timeout_count <= 5) {
            printf("等待数据包中... (%d)", timeout_count);
        } else if (timeout_count % 10 == 0) {
            printf("仍在等待，已过 %d 秒...", timeout_count);
        } else {
            printf(".");
        }
        fflush(stdout);  /* 立即刷新输出 */
    }

    /* 换行，覆盖掉等待提示 */
    if (timeout_count > 0) printf("\n");

    if (res == 1)
    {
        printf("捕获成功！长度：%u 字节\n", header->len);
    }
    else
    {
        printf("抓包失败！\n");
    }
}

/* ========== 资源管理 ========== */

void stop_capture(pcap_t *handle)
{
    if (handle != NULL) {
        /*
         * pcap_breakloop：安全地中断正在运行中的 pcap_loop/pcap_dispatch。
         * 设置一个内部标志，下次循环时退出。
         */
        pcap_breakloop(handle);
        pcap_close(handle);
        printf("[+] 抓包句柄已关闭\n");
    }
}

const char* get_last_error(void)
{
    return g_errbuf;
}
