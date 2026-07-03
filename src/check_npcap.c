/*
 * check_npcap.c — Npcap 环境诊断工具
 * 用法：在管理员 cmd 中编译运行
 *   cl check_npcap.c /I "C:\Program Files\Npcap\Include" /link /LIBPATH:"C:\Program Files\Npcap\Lib\x64" wpcap.lib
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <pcap.h>

int main()
{
    SetConsoleOutputCP(CP_UTF8);
    printf("========== Npcap 环境诊断 ==========\n\n");

    /* 1. 管理员权限检查 */
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elevation;
    DWORD size = sizeof(TOKEN_ELEVATION);
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken) &&
        GetTokenInformation(hToken, TokenElevation, &elevation, size, &size)) {
        printf("[%s] 以管理员权限运行\n",
               elevation.TokenIsElevated ? " ✅" : " ❌");
    }
    if (hToken) CloseHandle(hToken);

    /* 2. Npcap DLL 检查 */
    HMODULE h = LoadLibraryA("wpcap.dll");
    printf("[%s] wpcap.dll 可加载\n", h ? " ✅" : " ❌");
    if (h) FreeLibrary(h);

    h = LoadLibraryA("Packet.dll");
    printf("[%s] Packet.dll 可加载\n", h ? " ✅" : " ❌");
    if (h) FreeLibrary(h);

    /* 3. 设备列表 */
    printf("\n--- 可用网卡 ---\n");
    pcap_if_t *alldevs, *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("[ ❌] pcap_findalldevs 失败: %s\n", errbuf);
        printf("     → 没有管理员权限？Npcap 没装？\n");
    } else {
        int count = 0;
        for (dev = alldevs; dev; dev = dev->next) {
            count++;
            printf("  %d. %s\n", count, dev->name);
            if (dev->description)
            printf("     描述: %s\n", dev->description);
            if (dev->addresses) {
                struct sockaddr_in *sa = (struct sockaddr_in*)dev->addresses->addr;
                if (sa && sa->sin_family == AF_INET)
                    printf("     IP:   %s\n", inet_ntoa(sa->sin_addr));
            }
        }
        if (count == 0)
            printf("  (无网卡，Npcap 可能没装)\n");
        pcap_freealldevs(alldevs);
    }

    /* 4. 尝试打开第一个网卡抓 1 个包 */
    printf("\n--- 测试抓包 ---\n");
    if (pcap_findalldevs(&alldevs, errbuf) == 0 && alldevs) {
        pcap_t *handle = pcap_open_live(alldevs->name, 65535, 1, 3000, errbuf);
        if (handle) {
            printf("[ ✅] 成功打开: %s\n", alldevs->name);
            printf("     等待 3 秒抓包...\n");

            struct pcap_pkthdr *hdr;
            const u_char *data;
            int res = pcap_next_ex(handle, &hdr, &data);
            if (res == 1)
                printf("[ ✅] 抓到数据包！长度: %u 字节\n", hdr->len);
            else if (res == 0)
                printf("[ ❌] 超时——3 秒内没包\n     → 网卡可能没流量，或者没管理员权限\n");
            else
                printf("[ ❌] pcap_next_ex 错误: %s\n", pcap_geterr(handle));

            pcap_close(handle);
        } else {
            printf("[ ❌] pcap_open_live 失败: %s\n", errbuf);
        }
        pcap_freealldevs(alldevs);
    }

    printf("\n====================================\n");
    return 0;
}
