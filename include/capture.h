#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

int list_devices(void);
pcap_t* capture_init(const char *device);
void start_capture(pcap_t *handle);
void capture_one_packet(pcap_t *handle);
void capture_packets_with_stats(pcap_t *handle, int packet_count);
void capture_save_to_file(pcap_t *handle, int packet_count, const char *filename);
void read_pcap_file(const char *filename);
void read_pcap_file_with_filter(const char *filename, const char *filter_exp);
void performance_capture_test(pcap_t *handle, int seconds);
int apply_filter(pcap_t *handle, const char *filter_exp);
void stop_capture(pcap_t *handle);

#endif
