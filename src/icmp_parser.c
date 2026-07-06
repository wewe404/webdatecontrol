#include "icmp_parser.h"
#include <arpa/inet.h>
#include <stdio.h>

int parse_icmp(const unsigned char *raw_data, uint16_t ip_payload_len) {
    if (raw_data == NULL || ip_payload_len < 8) {
        return -1;
    }

    icmp_header_t *icmp = (icmp_header_t *)raw_data;

    // 提取类型和代码
    uint8_t type = icmp->type;
    uint8_t code = icmp->code;

    const char *type_desc = "";
    switch (type) {
        case 0:  type_desc = "Echo Reply (Ping响应)"; break;
        case 3:  type_desc = "Destination Unreachable"; break;
        case 8:  type_desc = "Echo Request (Ping请求)"; break;
        case 11: type_desc = "Time Exceeded"; break;
        default: type_desc = "Unknown"; break;
    }

    printf("【ICMP层】\n");
    printf("  类型: %d (%s)\n", type, type_desc);
    printf("  代码: %d\n", code);
    printf("  校验和: 0x%04X\n", ntohs(icmp->checksum));

    return 0;
}