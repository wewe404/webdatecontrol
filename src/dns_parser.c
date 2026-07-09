/**
 * dns_parser.c - DNS协议解析模块实现
 *
 * DNS报文结构 (RFC 1035):
 *   +---------------------+
 *   | Header (12 bytes)   |
 *   +---------------------+
 *   | Question section    |
 *   +---------------------+
 *   | Answer/Authority/Additional sections |
 *   +---------------------+
 *
 * 域名压缩指针：当标签长度字节的高2位为11(0xC0)时，
 * 表示这是一个压缩指针，指向DNS报文中的另一个位置。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dns_parser.h"

static int decode_dns_name(const uint8_t *data, uint16_t data_len,
                           uint16_t offset, char *name, size_t name_size)
{
    uint16_t pos = offset;
    size_t name_pos = 0;
    int jumped = 0;
    uint16_t jump_offset = 0;
    int safety_counter = 0;

    name[0] = '\0';

    while (pos < data_len && safety_counter < 128) {
        safety_counter++;

        uint8_t label_len = data[pos];

        if (label_len == 0) {
            if (!jumped) jump_offset = pos + 1;
            break;
        }

        if ((label_len & 0xC0) == 0xC0) {
            if (pos + 1 >= data_len) return -1;
            uint16_t pointer = ((label_len & 0x3F) << 8) | data[pos + 1];
            if (!jumped) jump_offset = pos + 2;
            jumped = 1;
            pos = pointer;
            continue;
        }

        if ((label_len & 0xC0) != 0) return -1;

        if (pos + 1 + label_len > data_len) return -1;

        if (name_pos > 0 && name_pos < name_size - 1) {
            name[name_pos++] = '.';
        }

        for (int i = 0; i < label_len && name_pos < name_size - 1; i++) {
            name[name_pos++] = (char)data[pos + 1 + i];
        }
        name[name_pos] = '\0';

        pos += 1 + label_len;
    }

    if (name_pos == 0) {
        strncpy(name, ".", name_size - 1);
        name[name_size - 1] = '\0';
    }

    return jumped ? (int)jump_offset : (int)(pos + 1);
}

static int parse_dns_rr(const uint8_t *data, uint16_t data_len,
                        uint16_t offset, dns_rr_t *rr)
{
    int consumed = decode_dns_name(data, data_len, offset, rr->name, sizeof(rr->name));
    if (consumed < 0) return -1;

    uint16_t pos = (uint16_t)consumed;

    if (pos + 10 > data_len) return -1;

    rr->type     = (data[pos] << 8) | data[pos + 1];
    rr->rclass   = (data[pos + 2] << 8) | data[pos + 3];
    rr->ttl      = ((uint32_t)data[pos + 4] << 24) | ((uint32_t)data[pos + 5] << 16) |
                   ((uint32_t)data[pos + 6] << 8) | data[pos + 7];
    rr->rd_length = (data[pos + 8] << 8) | data[pos + 9];
    pos += 10;

    uint16_t rdata_offset = pos;

    switch (rr->type) {
    case DNS_TYPE_A:
        if (rr->rd_length == 4 && rdata_offset + 4 <= data_len) {
            snprintf(rr->rdata, sizeof(rr->rdata), "%u.%u.%u.%u",
                     data[rdata_offset], data[rdata_offset + 1],
                     data[rdata_offset + 2], data[rdata_offset + 3]);
        } else {
            strncpy(rr->rdata, "<invalid A>", sizeof(rr->rdata) - 1);
        }
        break;

    case DNS_TYPE_AAAA:
        if (rr->rd_length == 16 && rdata_offset + 16 <= data_len) {
            snprintf(rr->rdata, sizeof(rr->rdata),
                     "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                     data[rdata_offset],     data[rdata_offset + 1],
                     data[rdata_offset + 2], data[rdata_offset + 3],
                     data[rdata_offset + 4], data[rdata_offset + 5],
                     data[rdata_offset + 6], data[rdata_offset + 7],
                     data[rdata_offset + 8], data[rdata_offset + 9],
                     data[rdata_offset + 10], data[rdata_offset + 11],
                     data[rdata_offset + 12], data[rdata_offset + 13],
                     data[rdata_offset + 14], data[rdata_offset + 15]);
        } else {
            strncpy(rr->rdata, "<invalid AAAA>", sizeof(rr->rdata) - 1);
        }
        break;

    case DNS_TYPE_CNAME:
    case DNS_TYPE_PTR:
    case DNS_TYPE_NS:
        {
            char cname[MAX_DNS_NAME];
            int ret = decode_dns_name(data, data_len, rdata_offset, cname, sizeof(cname));
            if (ret >= 0) {
                strncpy(rr->rdata, cname, sizeof(rr->rdata) - 1);
                rr->rdata[sizeof(rr->rdata) - 1] = '\0';
            } else {
                strncpy(rr->rdata, "<decode error>", sizeof(rr->rdata) - 1);
            }
        }
        break;

    case DNS_TYPE_MX:
        if (rdata_offset + 2 <= data_len) {
            uint16_t preference = (data[rdata_offset] << 8) | data[rdata_offset + 1];
            char mx_name[MAX_DNS_NAME];
            int ret = decode_dns_name(data, data_len, rdata_offset + 2, mx_name, sizeof(mx_name));
            if (ret >= 0) {
                snprintf(rr->rdata, sizeof(rr->rdata), "%u %s", preference, mx_name);
            } else {
                snprintf(rr->rdata, sizeof(rr->rdata), "%u <decode error>", preference);
            }
        }
        break;

    case DNS_TYPE_TXT:
        if (rdata_offset < data_len && rr->rd_length > 0) {
            uint8_t txt_len = data[rdata_offset];
            int copy_len = txt_len;
            if (copy_len > (int)sizeof(rr->rdata) - 1)
                copy_len = (int)sizeof(rr->rdata) - 1;
            if (rdata_offset + 1 + txt_len <= data_len) {
                memcpy(rr->rdata, data + rdata_offset + 1, copy_len);
                rr->rdata[copy_len] = '\0';
            }
        }
        break;

    case DNS_TYPE_SOA:
        {
            char soa_mname[MAX_DNS_NAME];
            int ret = decode_dns_name(data, data_len, rdata_offset, soa_mname, sizeof(soa_mname));
            if (ret >= 0) {
                char soa_rname[MAX_DNS_NAME];
                int ret2 = decode_dns_name(data, data_len, (uint16_t)ret, soa_rname, sizeof(soa_rname));
                if (ret2 >= 0 && ret2 + 20 <= (int)data_len) {
                    uint32_t serial  = ((uint32_t)data[ret2] << 24) | ((uint32_t)data[ret2+1] << 16) |
                                       ((uint32_t)data[ret2+2] << 8) | data[ret2+3];
                    uint32_t refresh = ((uint32_t)data[ret2+4] << 24) | ((uint32_t)data[ret2+5] << 16) |
                                       ((uint32_t)data[ret2+6] << 8) | data[ret2+7];
                    uint32_t retry   = ((uint32_t)data[ret2+8] << 24) | ((uint32_t)data[ret2+9] << 16) |
                                       ((uint32_t)data[ret2+10] << 8) | data[ret2+11];
                    uint32_t expire  = ((uint32_t)data[ret2+12] << 24) | ((uint32_t)data[ret2+13] << 16) |
                                       ((uint32_t)data[ret2+14] << 8) | data[ret2+15];
                    uint32_t minimum = ((uint32_t)data[ret2+16] << 24) | ((uint32_t)data[ret2+17] << 16) |
                                       ((uint32_t)data[ret2+18] << 8) | data[ret2+19];
                    snprintf(rr->rdata, sizeof(rr->rdata),
                             "%s %s serial=%u refresh=%u retry=%u expire=%u min=%u",
                             soa_mname, soa_rname, serial, refresh, retry, expire, minimum);
                }
            }
        }
        break;

    default:
        snprintf(rr->rdata, sizeof(rr->rdata), "<type=%u len=%u>", rr->type, rr->rd_length);
        break;
    }

    return rdata_offset + rr->rd_length;
}

int parse_dns(const uint8_t *data, uint16_t len, dns_result_t *result)
{
    if (data == NULL || result == NULL || len < 12) return -1;

    memset(result, 0, sizeof(dns_result_t));

    result->header.transaction_id = (data[0] << 8) | data[1];
    result->header.flags          = (data[2] << 8) | data[3];
    result->header.qd_count       = (data[4] << 8) | data[5];
    result->header.an_count       = (data[6] << 8) | data[7];
    result->header.ns_count       = (data[8] << 8) | data[9];
    result->header.ar_count       = (data[10] << 8) | data[11];

    uint16_t offset = 12;

    for (int i = 0; i < result->header.qd_count && i < MAX_DNS_QUESTIONS; i++) {
        int consumed = decode_dns_name(data, len, offset,
                                       result->questions[i].qname,
                                       sizeof(result->questions[i].qname));
        if (consumed < 0) return -1;
        offset = (uint16_t)consumed;

        if (offset + 4 > len) return -1;
        result->questions[i].qtype  = (data[offset] << 8) | data[offset + 1];
        result->questions[i].qclass = (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;
        result->question_count++;
    }

    for (int i = 0; i < result->header.an_count && i < MAX_DNS_RRS; i++) {
        int consumed = parse_dns_rr(data, len, offset, &result->answers[i]);
        if (consumed < 0) return -1;
        offset = (uint16_t)consumed;
        result->answer_count++;
    }

    for (int i = 0; i < result->header.ns_count && i < MAX_DNS_RRS; i++) {
        int consumed = parse_dns_rr(data, len, offset, &result->authority[i]);
        if (consumed < 0) return -1;
        offset = (uint16_t)consumed;
        result->authority_count++;
    }

    for (int i = 0; i < result->header.ar_count && i < MAX_DNS_RRS; i++) {
        int consumed = parse_dns_rr(data, len, offset, &result->additional[i]);
        if (consumed < 0) return -1;
        offset = (uint16_t)consumed;
        result->additional_count++;
    }

    return 0;
}

const char *dns_type_str(uint16_t type)
{
    switch (type) {
    case DNS_TYPE_A:     return "A";
    case DNS_TYPE_NS:    return "NS";
    case DNS_TYPE_CNAME: return "CNAME";
    case DNS_TYPE_SOA:   return "SOA";
    case DNS_TYPE_PTR:   return "PTR";
    case DNS_TYPE_MX:    return "MX";
    case DNS_TYPE_TXT:   return "TXT";
    case DNS_TYPE_AAAA:  return "AAAA";
    case DNS_TYPE_SRV:   return "SRV";
    default:             return "UNKNOWN";
    }
}

const char *dns_rcode_str(uint16_t rcode)
{
    switch (rcode) {
    case 0: return "NoError";
    case 1: return "FormErr";
    case 2: return "ServFail";
    case 3: return "NXDomain";
    case 4: return "NotImp";
    case 5: return "Refused";
    default: return "Unknown";
    }
}

const char *dns_opcode_str(uint16_t opcode)
{
    switch (opcode) {
    case 0: return "QUERY";
    case 1: return "IQUERY";
    case 2: return "STATUS";
    default: return "Unknown";
    }
}

void print_dns(const dns_result_t *result)
{
    uint16_t flags  = result->header.flags;
    uint16_t qr     = (flags & DNS_FLAG_QR) >> 15;
    uint16_t opcode = (flags & DNS_FLAG_OPCODE) >> 11;
    uint16_t aa     = (flags & DNS_FLAG_AA) >> 10;
    uint16_t tc     = (flags & DNS_FLAG_TC) >> 9;
    uint16_t rd     = (flags & DNS_FLAG_RD) >> 8;
    uint16_t ra     = (flags & DNS_FLAG_RA) >> 7;
    uint16_t rcode  = flags & DNS_FLAG_RCODE;

    printf("\n========== DNS 解析结果 ==========\n");
    printf("Transaction ID : 0x%04X\n", result->header.transaction_id);
    printf("标志位         : 0x%04X\n", flags);
    printf("  QR     : %u (%s)\n", qr, qr ? "响应" : "查询");
    printf("  Opcode : %u (%s)\n", opcode, dns_opcode_str(opcode));
    printf("  AA     : %u (%s)\n", aa, aa ? "权威回答" : "非权威");
    printf("  TC     : %u (%s)\n", tc, tc ? "已截断" : "未截断");
    printf("  RD     : %u (%s)\n", rd, rd ? "期望递归" : "不递归");
    printf("  RA     : %u (%s)\n", ra, ra ? "递归可用" : "递归不可用");
    printf("  RCODE  : %u (%s)\n", rcode, dns_rcode_str(rcode));
    printf("Question数  : %u\n", result->header.qd_count);
    printf("Answer数    : %u\n", result->header.an_count);
    printf("Authority数 : %u\n", result->header.ns_count);
    printf("Additional数: %u\n", result->header.ar_count);

    if (result->question_count > 0) {
        printf("\n--- Question 区 ---\n");
        for (int i = 0; i < result->question_count; i++) {
            printf("  [%d] Name: %s  Type: %s(%u)  Class: %u\n",
                   i + 1, result->questions[i].qname,
                   dns_type_str(result->questions[i].qtype),
                   result->questions[i].qtype,
                   result->questions[i].qclass);
        }
    }

    if (result->answer_count > 0) {
        printf("\n--- Answer 区 ---\n");
        for (int i = 0; i < result->answer_count; i++) {
            printf("  [%d] Name: %s  Type: %s  TTL: %u\n",
                   i + 1, result->answers[i].name,
                   dns_type_str(result->answers[i].type),
                   result->answers[i].ttl);
            printf("       RDATA: %s\n", result->answers[i].rdata);
        }
    }

    if (result->authority_count > 0) {
        printf("\n--- Authority 区 ---\n");
        for (int i = 0; i < result->authority_count; i++) {
            printf("  [%d] Name: %s  Type: %s  TTL: %u\n",
                   i + 1, result->authority[i].name,
                   dns_type_str(result->authority[i].type),
                   result->authority[i].ttl);
            printf("       RDATA: %s\n", result->authority[i].rdata);
        }
    }

    if (result->additional_count > 0) {
        printf("\n--- Additional 区 ---\n");
        for (int i = 0; i < result->additional_count; i++) {
            printf("  [%d] Name: %s  Type: %s  TTL: %u\n",
                   i + 1, result->additional[i].name,
                   dns_type_str(result->additional[i].type),
                   result->additional[i].ttl);
            printf("       RDATA: %s\n", result->additional[i].rdata);
        }
    }

    printf("==================================\n");
}
