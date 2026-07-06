/**
 * http_parser.h - HTTP协议解析模块接口
 *
 * 成员C负责模块
 * 功能：解析HTTP请求/响应
 *       - 请求行解析 (METHOD / URI / VERSION)
 *       - 状态行解析 (VERSION / STATUS_CODE / REASON_PHRASE)
 *       - Header键值对解析
 *       - chunked分块传输编码解码
 *
 * 对应文档任务：
 *   第1天: 调研HTTP请求/响应行格式
 *   第4天: 实现parse_http()（请求行/状态行/Header Key:Value解析）
 *   第7天: HTTP分块传输编码(chunked)支持
 */

#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

#include "common.h"

/* ---- HTTP 报文类型 ---- */
typedef enum {
    HTTP_TYPE_UNKNOWN = 0,
    HTTP_TYPE_REQUEST,       /* HTTP请求 */
    HTTP_TYPE_RESPONSE       /* HTTP响应 */
} http_type_t;

/* ---- HTTP 方法 ---- */
typedef enum {
    HTTP_METHOD_UNKNOWN = 0,
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_OPTIONS,
    HTTP_METHOD_CONNECT,
    HTTP_METHOD_TRACE,
    HTTP_METHOD_PATCH
} http_method_t;

/* ---- HTTP Header键值对 ---- */
#define MAX_HTTP_HEADERS  64
#define MAX_HEADER_KEY    256
#define MAX_HEADER_VALUE  1024

typedef struct {
    char key[MAX_HEADER_KEY];
    char value[MAX_HEADER_VALUE];
} http_header_t;

/* ---- HTTP 解析结果 ---- */
typedef struct {
    http_type_t     type;               /* 请求/响应 */
    /* 请求行字段 */
    http_method_t   method;             /* HTTP方法 */
    char            method_str[16];     /* 方法字符串 */
    char            uri[2048];          /* 请求URI */
    /* 状态行字段 */
    int             status_code;        /* 响应状态码 */
    char            reason_phrase[256]; /* 原因短语 */
    /* 公共字段 */
    char            version[16];        /* HTTP版本 (如 "HTTP/1.1") */

    /* Header列表 */
    http_header_t   headers[MAX_HTTP_HEADERS];
    int             header_count;

    /* Body */
    char           *body;               /* 指向Body数据 */
    int             body_len;           /* Body长度 */
    int             is_chunked;         /* 是否使用chunked编码 */

} http_result_t;

/**
 * parse_http - 解析HTTP报文
 * @param data    指向HTTP报文起始位置（TCP载荷）
 * @param len     HTTP报文总长度
 * @param result  输出参数，解析结果
 * @return 0成功, -1失败
 */
int parse_http(const uint8_t *data, int len, http_result_t *result);

/**
 * print_http - 格式化打印HTTP解析结果
 * @param result HTTP解析结果
 */
void print_http(const http_result_t *result);

/**
 * http_method_str - 将HTTP方法枚举转为字符串
 */
const char *http_method_str(http_method_t method);

/**
 * http_get_header - 从解析结果中查找指定Header
 * @param result  HTTP解析结果
 * @param key     Header名（不区分大小写）
 * @return Header值指针，未找到返回NULL
 */
const char *http_get_header(const http_result_t *result, const char *key);

/**
 * http_decode_chunked - 解码HTTP chunked传输编码
 * @param input     chunked编码的body数据
 * @param input_len 输入数据长度
 * @param output    输出缓冲区
 * @param output_max 输出缓冲区最大长度
 * @return 解码后的数据长度，-1表示失败
 */
int http_decode_chunked(const char *input, int input_len,
                        char *output, int output_max);

/**
 * free_http_result - 释放HTTP解析结果中动态分配的内存
 * @param result HTTP解析结果
 */
void free_http_result(http_result_t *result);

#endif /* HTTP_PARSER_H */
