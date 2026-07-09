#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

#include "common.h"

typedef enum {
    HTTP_TYPE_UNKNOWN = 0,
    HTTP_TYPE_REQUEST,
    HTTP_TYPE_RESPONSE
} http_type_t;

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

#define MAX_HTTP_HEADERS  64
#define MAX_HEADER_KEY    256
#define MAX_HEADER_VALUE  1024

typedef struct {
    char key[MAX_HEADER_KEY];
    char value[MAX_HEADER_VALUE];
} http_header_t;

typedef struct {
    http_type_t     type;
    http_method_t   method;
    char            method_str[16];
    char            uri[2048];
    int             status_code;
    char            reason_phrase[256];
    char            version[16];

    http_header_t   headers[MAX_HTTP_HEADERS];
    int             header_count;

    char           *body;
    int             body_len;
    int             is_chunked;
} http_result_t;

int parse_http(const uint8_t *data, int len, http_result_t *result);
void print_http(const http_result_t *result);
const char *http_method_str(http_method_t method);
const char *http_get_header(const http_result_t *result, const char *key);
int http_decode_chunked(const char *input, int input_len,
                        char *output, int output_max);
void free_http_result(http_result_t *result);

#endif
