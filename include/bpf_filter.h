/**
 * bpf_filter.h - BPF过滤规则封装模块接口
 *
 * 成员C负责模块
 * 功能：
 *   - 封装pcap_compile/pcap_setfilter的完整流程
 *   - BPF规则表达式语法校验
 *   - 支持实时抓包和离线pcap文件过滤
 *   - 常见过滤规则组合测试支持
 *
 * 对应文档任务：
 *   第5天: 实现BPF过滤对接（pcap_compile编译规则、pcap_setfilter挂载）
 *   第9天: BPF过滤规则全覆盖测试（AND/OR/port/host组合、空规则/畸形规则处理）
 *
 * BPF过滤原理：
 *   pcap_compile() 将文本规则编译为BPF虚拟机字节码
 *   pcap_setfilter() 将字节码注入内核/驱动层进行包过滤
 *   过滤在内核层完成，减少用户态开销，提高抓包性能
 *
 * 常见过滤规则示例：
 *   tcp                          - 只抓TCP流量
 *   udp                          - 只抓UDP流量
 *   port 80                      - 源或目的端口为80
 *   host 192.168.1.1             - 源或目的IP为指定地址
 *   tcp port 80 and host 1.2.3.4 - TCP且端口80且指定IP
 *   src host 192.168.1.1         - 源IP为指定地址
 *   dst port 53                  - 目的端口为53
 *   not arp                      - 排除ARP流量
 */

#ifndef BPF_FILTER_H
#define BPF_FILTER_H

#include <pcap.h>

/**
 * bpf_compile_and_set - 编译并设置BPF过滤规则到pcap句柄
 * @param handle     pcap句柄（实时抓包或离线文件）
 * @param filter_exp 过滤规则表达式字符串
 * @return 0成功, -1失败
 */
int bpf_compile_and_set(pcap_t *handle, const char *filter_exp);

/**
 * bpf_validate - 验证BPF规则表达式语法是否合法
 * @param filter_exp 过滤规则表达式字符串
 * @return 1合法, 0不合法
 */
int bpf_validate(const char *filter_exp);

/**
 * bpf_validate_detail - 验证BPF规则并返回详细错误信息
 * @param filter_exp  过滤规则表达式
 * @param errbuf      错误信息缓冲区
 * @param errbuf_size 错误缓冲区大小
 * @return 1合法, 0不合法
 */
int bpf_validate_detail(const char *filter_exp, char *errbuf, int errbuf_size);

/**
 * bpf_filter_offline - 对离线pcap文件应用BPF过滤并显示结果
 * @param filename   pcap文件名
 * @param filter_exp 过滤规则表达式
 * @return 0成功, -1失败
 */
int bpf_filter_offline(const char *filename, const char *filter_exp);

/**
 * bpf_filter_offline_with_stats - 对离线pcap文件应用BPF过滤并统计
 * @param filename   pcap文件名
 * @param filter_exp 过滤规则表达式
 * @param total_out  输出：文件中总包数
 * @param matched_out 输出：匹配的包数
 * @return 0成功, -1失败
 */
int bpf_filter_offline_with_stats(const char *filename, const char *filter_exp,
                                   int *total_out, int *matched_out);

/**
 * bpf_print_common_rules - 打印常见BPF过滤规则示例
 */
void bpf_print_common_rules(void);

/**
 * bpf_run_test_suite - 运行BPF过滤规则测试套件
 * @param filename pcap测试文件
 */
void bpf_run_test_suite(const char *filename);

#endif /* BPF_FILTER_H */
