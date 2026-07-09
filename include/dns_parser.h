#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include "common.h"

#define DNS_TYPE_A      1
#define DNS_TYPE_NS     2
#define DNS_TYPE_CNAME  5
#define DNS_TYPE_SOA    6
#define DNS_TYPE_PTR    12
#define DNS_TYPE_MX     15
#define DNS_TYPE_TXT    16
#define DNS_TYPE_AAAA   28
#define DNS_TYPE_SRV    33

#define DNS_CLASS_IN    1

#define DNS_FLAG_QR         0x8000
#define DNS_FLAG_OPCODE     0x7800
#define DNS_FLAG_AA         0x0400
#define DNS_FLAG_TC         0x0200
#define DNS_FLAG_RD         0x0100
#define DNS_FLAG_RA         0x0080
#define DNS_FLAG_RCODE      0x000F

typedef struct {
    char     qname[MAX_DNS_NAME];
    uint16_t qtype;
    uint16_t qclass;
} dns_question_t;

typedef struct {
    char     name[MAX_DNS_NAME];
    uint16_t type;
    uint16_t rclass;
    uint32_t ttl;
    uint16_t rd_length;
    char     rdata[512];
} dns_rr_t;

#define MAX_DNS_QUESTIONS  16
#define MAX_DNS_RRS        64

typedef struct {
    dns_hdr_t       header;
    dns_question_t  questions[MAX_DNS_QUESTIONS];
    dns_rr_t        answers[MAX_DNS_RRS];
    dns_rr_t        authority[MAX_DNS_RRS];
    dns_rr_t        additional[MAX_DNS_RRS];
    int             question_count;
    int             answer_count;
    int             authority_count;
    int             additional_count;
} dns_result_t;

int parse_dns(const uint8_t *data, uint16_t len, dns_result_t *result);
void print_dns(const dns_result_t *result);
const char *dns_type_str(uint16_t type);
const char *dns_rcode_str(uint16_t rcode);
const char *dns_opcode_str(uint16_t opcode);

#endif
