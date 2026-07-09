#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <stddef.h>
#include <stdint.h>

void mac_ntop(const unsigned char mac[6], char *buf, size_t size);
void ip_ntop(const unsigned char ip[4], char *buf, size_t size);
unsigned short checksum16(const unsigned char *data, int len);
void net_utils_self_test(void);

#endif
