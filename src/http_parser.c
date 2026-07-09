/**
 * http_parser.c - HTTP协议解析模块实现
 *
 * 支持HTTP请求/响应解析：
 *   - 请求行解析 (METHOD / URI / VERSION)
 *   - 状态行解析 (VERSION / STATUS_CODE / REASON_PHRASE)
 *   - Header键值对解析
 *   - chunked分块传输编码解码
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "http_parser.h"

static int str_icmp(const char *a, const char *b)
{
    while (*a && *b) {
        int ca = tolower((unsigned char)*a);
        int cb = tolower((unsigned char)*b);
        if (ca != cb) return ca - cb;
        a++;
        b++;
    }
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

static http_method_t parse_method(const char *str)
{
    if (strcmp(str, "GET") == 0)     return HTTP_METHOD_GET;
    if (strcmp(str, "POST") == 0)    return HTTP_METHOD_POST;
    if (strcmp(str, "PUT") == 0)     return HTTP_METHOD_PUT;
    if (strcmp(str, "DELETE") == 0)  return HTTP_METHOD_DELETE;
    if (strcmp(str, "HEAD") == 0)    return HTTP_METHOD_HEAD;
    if (strcmp(str, "OPTIONS") == 0) return HTTP_METHOD_OPTIONS;
    if (strcmp(str, "CONNECT") == 0) return HTTP_METHOD_CONNECT;
    if (strcmp(str, "TRACE") == 0)   return HTTP_METHOD_TRACE;
    if (strcmp(str, "PATCH") == 0)   return HTTP_METHOD_PATCH;
    return HTTP_METHOD_UNKNOWN;
}

const char *http_method_str(http_method_t method)
{
    switch (method) {
    case HTTP_METHOD_GET:     return "GET";
    case HTTP_METHOD_POST:    return "POST";
    case HTTP_METHOD_PUT:     return "PUT";
    case HTTP_METHOD_DELETE:  return "DELETE";
    case HTTP_METHOD_HEAD:    return "HEAD";
    case HTTP_METHOD_OPTIONS: return "OPTIONS";
    case HTTP_METHOD_CONNECT: return "CONNECT";
    case HTTP_METHOD_TRACE:   return "TRACE";
    case HTTP_METHOD_PATCH:   return "PATCH";
    default:                  return "UNKNOWN";
    }
}

static const char *find_crlf(const char *data, int len)
{
    for (int i = 0; i < len - 1; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n') {
            return data + i;
        }
    }
    return NULL;
}

const char *http_get_header(const http_result_t *result, const char *key)
{
    for (int i = 0; i < result->header_count; i++) {
        if (str_icmp(result->headers[i].key, key) == 0) {
            return result->headers[i].value;
        }
    }
    return NULL;
}

int http_decode_chunked(const char *input, int input_len,
                        char *output, int output_max)
{
    const char *pos = input;
    const char *end = input + input_len;
    int out_pos = 0;

    while (pos < end) {
        const char *crlf = find_crlf(pos, (int)(end - pos));
        if (crlf == NULL) break;

        char size_buf[32];
        int line_len = (int)(crlf - pos);
        if (line_len >= (int)sizeof(size_buf))
            line_len = (int)sizeof(size_buf) - 1;
        memcpy(size_buf, pos, line_len);
        size_buf[line_len] = '\0';

        char *semi = strchr(size_buf, ';');
        if (semi) *semi = '\0';

        long chunk_size = strtol(size_buf, NULL, 16);
        if (chunk_size <= 0) break;

        pos = crlf + 2;

        if (pos + chunk_size > end)
            chunk_size = (long)(end - pos);

        int copy_len = (int)chunk_size;
        if (out_pos + copy_len >= output_max)
            copy_len = output_max - out_pos - 1;

        if (copy_len > 0) {
            memcpy(output + out_pos, pos, copy_len);
            out_pos += copy_len;
        }

        pos += chunk_size;

        if (pos + 1 < end && pos[0] == '\r' && pos[1] == '\n') {
            pos += 2;
        }
    }

    output[out_pos] = '\0';
    return out_pos;
}

int parse_http(const uint8_t *data, int len, http_result_t *result)
{
    if (data == NULL || result == NULL || len <= 0) return -1;

    memset(result, 0, sizeof(http_result_t));

    const char *str = (const char *)data;
    const char *end = str + len;
    const char *pos = str;

    /* ---- 解析第一行 ---- */
    const char *line_end = find_crlf(pos, (int)(end - pos));
    if (line_end == NULL) return -1;

    int first_line_len = (int)(line_end - pos);
    char first_line[4096];
    if (first_line_len >= (int)sizeof(first_line))
        first_line_len = (int)sizeof(first_line) - 1;
    memcpy(first_line, pos, first_line_len);
    first_line[first_line_len] = '\0';

    if (strncmp(first_line, "HTTP/", 5) == 0) {
        result->type = HTTP_TYPE_RESPONSE;
        char *space1 = strchr(first_line, ' ');
        if (space1 == NULL) return -1;
        *space1 = '\0';
        strncpy(result->version, first_line, sizeof(result->version) - 1);

        char *space2 = strchr(space1 + 1, ' ');
        if (space2 == NULL) return -1;
        *space2 = '\0';
        result->status_code = atoi(space1 + 1);
        strncpy(result->reason_phrase, space2 + 1, sizeof(result->reason_phrase) - 1);
    } else {
        result->type = HTTP_TYPE_REQUEST;
        char *space1 = strchr(first_line, ' ');
        if (space1 == NULL) return -1;
        *space1 = '\0';
        strncpy(result->method_str, first_line, sizeof(result->method_str) - 1);
        result->method = parse_method(result->method_str);

        char *space2 = strchr(space1 + 1, ' ');
        if (space2 == NULL) return -1;
        *space2 = '\0';
        strncpy(result->uri, space1 + 1, sizeof(result->uri) - 1);
        strncpy(result->version, space2 + 1, sizeof(result->version) - 1);
    }

    pos = line_end + 2;

    /* ---- 解析Header ---- */
    while (pos < end) {
        line_end = find_crlf(pos, (int)(end - pos));
        if (line_end == NULL) break;

        int hdr_line_len = (int)(line_end - pos);

        if (hdr_line_len == 0) {
            pos = line_end + 2;
            break;
        }

        if (result->header_count < MAX_HTTP_HEADERS) {
            char hdr_line[4096];
            if (hdr_line_len >= (int)sizeof(hdr_line))
                hdr_line_len = (int)sizeof(hdr_line) - 1;
            memcpy(hdr_line, pos, hdr_line_len);
            hdr_line[hdr_line_len] = '\0';

            char *colon = strchr(hdr_line, ':');
            if (colon != NULL) {
                *colon = '\0';
                char *value = colon + 1;
                while (*value == ' ' || *value == '\t') value++;

                strncpy(result->headers[result->header_count].key,
                        hdr_line, MAX_HEADER_KEY - 1);
                result->headers[result->header_count].key[MAX_HEADER_KEY - 1] = '\0';

                strncpy(result->headers[result->header_count].value,
                        value, MAX_HEADER_VALUE - 1);
                result->headers[result->header_count].value[MAX_HEADER_VALUE - 1] = '\0';

                result->header_count++;
            }
        }

        pos = line_end + 2;
    }

    /* ---- Body ---- */
    const char *te = http_get_header(result, "Transfer-Encoding");
    if (te != NULL && str_icmp(te, "chunked") == 0) {
        result->is_chunked = 1;
        int body_len = (int)(end - pos);
        if (body_len > 0) {
            char *decoded = (char *)malloc(body_len + 1);
            if (decoded != NULL) {
                int decoded_len = http_decode_chunked(pos, body_len, decoded, body_len + 1);
                if (decoded_len >= 0) {
                    result->body = decoded;
                    result->body_len = decoded_len;
                } else {
                    free(decoded);
                }
            }
        }
    } else {
        int body_len = (int)(end - pos);
        if (body_len > 0) {
            result->body = (char *)malloc(body_len + 1);
            if (result->body != NULL) {
                memcpy(result->body, pos, body_len);
                result->body[body_len] = '\0';
                result->body_len = body_len;
            }
        }
    }

    return 0;
}

void print_http(const http_result_t *result)
{
    printf("\n========== HTTP 解析结果 ==========\n");
    printf("类型   : %s\n", result->type == HTTP_TYPE_REQUEST ? "请求" :
                             result->type == HTTP_TYPE_RESPONSE ? "响应" : "未知");
    printf("版本   : %s\n", result->version);

    if (result->type == HTTP_TYPE_REQUEST) {
        printf("方法   : %s\n", http_method_str(result->method));
        printf("URI    : %s\n", result->uri);
    } else if (result->type == HTTP_TYPE_RESPONSE) {
        printf("状态码 : %d\n", result->status_code);
        printf("原因   : %s\n", result->reason_phrase);
    }

    printf("\n--- Headers (%d) ---\n", result->header_count);
    for (int i = 0; i < result->header_count; i++) {
        printf("  %s: %s\n", result->headers[i].key, result->headers[i].value);
    }

    if (result->is_chunked) {
        printf("\n[使用chunked传输编码，已解码]\n");
    }

    if (result->body != NULL && result->body_len > 0) {
        printf("\n--- Body (%d bytes) ---\n", result->body_len);
        int show_len = result->body_len > 512 ? 512 : result->body_len;
        for (int j = 0; j < show_len; j++) {
            char c = result->body[j];
            if (isprint((unsigned char)c) || c == '\n' || c == '\r' || c == '\t') {
                putchar(c);
            } else {
                printf("\\x%02X", (unsigned char)c);
            }
        }
        if (result->body_len > 512) {
            printf("\n... (省略 %d 字节)\n", result->body_len - 512);
        }
        printf("\n");
    }

    printf("===================================\n");
}

void free_http_result(http_result_t *result)
{
    if (result != NULL && result->body != NULL) {
        free(result->body);
        result->body = NULL;
        result->body_len = 0;
    }
}
