#ifndef BPF_FILTER_H
#define BPF_FILTER_H

#include <pcap.h>

int bpf_compile_and_set(pcap_t *handle, const char *filter_exp);
int bpf_validate(const char *filter_exp);
int bpf_validate_detail(const char *filter_exp, char *errbuf, int errbuf_size);
int bpf_filter_offline(const char *filename, const char *filter_exp);
int bpf_filter_offline_with_stats(const char *filename, const char *filter_exp,
                                   int *total_out, int *matched_out);
void bpf_print_common_rules(void);
void bpf_run_test_suite(const char *filename);

#endif
