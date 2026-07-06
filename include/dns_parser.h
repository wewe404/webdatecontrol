/**
 * dns_parser.h - DNS协议解析模块接口
 *
 * 成员C负责模块
 * 功能：解析DNS报文（Header + Question + Answer/Authority/Additional）
 *       支持域名压缩指针（0xC0前缀）解码
 *       支持常见RR类型（A, AAAA, CNAME, MX, NS, SOA, PTR, TXT, SRV）
 *
 * 对应文档任务：
 *   第1天: 调研DNS报文格式，写parse_dns()骨架
 *   第3天: 实现parse_dns()完整版（Header flags位解析、Question区域名解码）
 *   第7天: DNS应答/授权/附加段解析
 */

#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include "common.h"

/* ---- DNS RR 类型常量 ---- */
#define DNS_TYPE_A      1       /* IPv4地址 */
#define DNS_TYPE_NS     2       /* 名称服务器 */
#define DNS_TYPE_CNAME  5       /* 规范名称 */
#define DNS_TYPE_SOA    6       /* 授权起始 */
#define DNS_TYPE_PTR    12      /* 指针记录 */
#define DNS_TYPE_MX     15      /* 邮件交换 */
#define DNS_TYPE_TXT    16      /* 文本记录 */
#define DNS_TYPE_AAAA   28      /* IPv6地址 */
#define DNS_TYPE_SRV    33      /* 服务定位 */

/* ---- DNS 类别常量 ---- */
#define DNS_CLASS_IN    1       /* Internet */

/* ---- DNS 标志位掩码 ---- */
#define DNS_FLAG_QR         0x8000  /* 查询(0)/响应(1) */
#define DNS_FLAG_OPCODE     0x7800  /* 操作码 */
#define DNS_FLAG_AA         0x0400  /* 权威回答 */
#define DNS_FLAG_TC         0x0200  /* 截断标志 */
#define DNS_FLAG_RD         0x0100  /* 期望递归 */
#define DNS_FLAG_RA         0x0080  /* 递归可用 */
#define DNS_FLAG_RCODE      0x000F  /* 响应码 */

/* ---- DNS Question 记录 ---- */
typedef struct {
    char     qname[MAX_DNS_NAME];   /* 查询域名 */
    uint16_t qtype;                  /* 查询类型 */
    uint16_t qclass;                 /* 查询类别 */
} dns_question_t;

/* ---- DNS RR（资源记录） ---- */
typedef struct {
    char     name[MAX_DNS_NAME];     /* 资源记录名 */
    uint16_t type;                    /* 记录类型 */
    uint16_t rclass;                  /* 记录类别 */
    uint32_t ttl;                     /* 生存时间 */
    uint16_t rd_length;               /* RDATA长度 */
    char     rdata[512];              /* RDATA文本表示 */
} dns_rr_t;

/* ---- DNS 解析结果 ---- */
#define MAX_DNS_QUESTIONS  16
#define MAX_DNS_RRS        64

typedef struct {
    dns_hdr_t       header;                              /* DNS头部 */
    dns_question_t  questions[MAX_DNS_QUESTIONS];        /* Question区 */
    dns_rr_t        answers[MAX_DNS_RRS];                /* Answer区 */
    dns_rr_t        authority[MAX_DNS_RRS];              /* Authority区 */
    dns_rr_t        additional[MAX_DNS_RRS];             /* Additional区 */
    int             question_count;                      /* 实际解析的Question数 */
    int             answer_count;                        /* 实际解析的Answer数 */
    int             authority_count;                     /* 实际解析的Authority数 */
    int             additional_count;                    /* 实际解析的Additional数 */
} dns_result_t;

/**
 * parse_dns - 解析DNS报文
 * @param data   指向DNS报文起始位置的指针（UDP载荷）
 * @param len    DNS报文总长度
 * @param result 输出参数，解析结果
 * @return 0成功, -1失败
 */
int parse_dns(const uint8_t *data, uint16_t len, dns_result_t *result);

/**
 * print_dns - 格式化打印DNS解析结果
 * @param result DNS解析结果
 */
void print_dns(const dns_result_t *result);

/**
 * dns_type_str - 将DNS类型码转为可读字符串
 * @param type 类型码
 * @return 类型字符串
 */
const char *dns_type_str(uint16_t type);

/**
 * dns_rcode_str - 将DNS响应码转为可读字符串
 * @param rcode 响应码
 * @return 响应码字符串
 */
const char *dns_rcode_str(uint16_t rcode);

/**
 * dns_opcode_str - 将DNS操作码转为可读字符串
 * @param opcode 操作码
 * @return 操作码字符串
 */
const char *dns_opcode_str(uint16_t opcode);

#endif /* DNS_PARSER_H */
