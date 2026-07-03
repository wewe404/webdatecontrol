#include <stdio.h>
#include <pcap.h>
#pragma comment(lib, "wpcap.lib")

int main() {
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    printf("Testing pcap_findalldevs...\n");
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("FAIL: %s\n", errbuf);
        return 1;
    }
    int n = 0;
    for (d = alldevs; d; d = d->next) {
        n++;
        printf("  [%d] %s", n, d->name);
        if (d->description) printf(" - %s", d->description);
        printf("\n");
    }
    printf("Total: %d devices\n", n);
    pcap_freealldevs(alldevs);
    return 0;
}
