/**
 * ncurses_ui.c — shell-out 模式 TUI（含 TCP 流重组）
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>
#include <pcap.h>
#include <curses.h>

#include "capture.h"
#include "net_utils.h"
#include "common.h"
#include "dns_parser.h"
#include "http_parser.h"
#include "bpf_filter.h"
#include "stats.h"
#include "protocol_analyze.h"
#include "tcp_reassembly.h"

/* 颜色 */
#define CP_TITLE      1
#define CP_MENU_NORM  2
#define CP_MENU_HL    3
#define CP_MENU_CAT   4
#define CP_STATUSBAR  5
#define CP_HELPBAR    6

static void init_colors(void)
{
    if (!has_colors()) return;
    start_color();
    init_pair(CP_TITLE,     COLOR_WHITE, COLOR_BLUE);
    init_pair(CP_MENU_NORM, COLOR_WHITE, COLOR_BLACK);
    init_pair(CP_MENU_HL,   COLOR_BLACK, COLOR_CYAN);
    init_pair(CP_MENU_CAT,  COLOR_YELLOW, COLOR_BLACK);
    init_pair(CP_STATUSBAR, COLOR_WHITE, COLOR_BLUE);
    init_pair(CP_HELPBAR,   COLOR_BLACK, COLOR_WHITE);
}

/* 菜单 */
#define MENU_COUNT  17

static const char *menu_items[MENU_COUNT] = {
    "1. \u67E5\u770B\u7F51\u5361\u5217\u8868",
    "2. \u8FDE\u7EED\u6293\u5305\u5E76\u663E\u793A\u7EDF\u8BA1\u4FE1\u606F",
    "3. \u6293\u5305\u5E76\u4FDD\u5B58\u4E3A pcap \u6587\u4EF6",
    "4. \u8BFB\u53D6 pcap \u6587\u4EF6\u56DE\u653E",
    "5. \u4F7F\u7528 BPF \u8FC7\u6EE4\u89C4\u5219\u6293\u5305",
    "6. \u6309 BPF \u89C4\u5219\u8BFB\u53D6 pcap \u6587\u4EF6",
    "7. \u5DE5\u5177\u51FD\u6570\u81EA\u6D4B",
    "8. \u6293\u5305\u6027\u80FD\u6D4B\u8BD5",
    "9. \u534F\u8BAE\u5206\u6790\uFF08\u89E3\u6790 pcap \u5404\u5C42\u534F\u8BAE\uFF09",
    "10. DNS \u62A5\u6587\u89E3\u6790\u6F14\u793A",
    "11. HTTP \u62A5\u6587\u89E3\u6790\u6F14\u793A",
    "12. BPF \u8FC7\u6EE4\u6D4B\u8BD5\u5957\u4EF6",
    "13. BPF \u5E38\u89C1\u89C4\u5219\u793A\u4F8B",
    "14. \u6D41\u91CF\u7EDF\u8BA1\uFF08\u5B9E\u65F6\u6293\u5305\u7EDF\u8BA1\uFF09",
    "15. \u6D41\u91CF\u7EDF\u8BA1\uFF08pcap \u6587\u4EF6\u7EDF\u8BA1\uFF09",
    "16. \u6D41\u91CF\u7EDF\u8BA1\uFF08pcap \u6587\u4EF6 + BPF \u8FC7\u6EE4\uFF09",
    "17. TCP \u6D41\u91CD\u7EC4 + HTTP \u63D0\u53D6\uFF08\u8FDB\u9636\uFF09",
};

static const int layout[] = {
    -2, 0,1,2,3,4,5,6,7,
    -1,
    -3, 8,9,10,11,12,13,14,15,16,
    -1
};
#define LAYOUT_LEN (sizeof(layout)/sizeof(layout[0]))

/* 绘制 */
static void draw_title(void)
{
    int w = getmaxx(stdscr);
    attron(COLOR_PAIR(CP_TITLE) | A_BOLD);
    for (int x = 0; x < w; x++) mvaddch(0, x, ' ');
    mvprintw(0, (w - 24) / 2, " \u7F51\u7EDC\u6570\u636E\u5305\u6355\u83B7\u4E0E\u534F\u8BAE\u89E3\u6790\u5DE5\u5177 ");
    attroff(COLOR_PAIR(CP_TITLE) | A_BOLD);
}

static void draw_helpbar(void)
{
    int w = getmaxx(stdscr);
    int h = getmaxy(stdscr);
    attron(COLOR_PAIR(CP_HELPBAR) | A_BOLD);
    for (int x = 0; x < w; x++) mvaddch(h - 1, x, ' ');
    mvprintw(h - 1, 2, " \u65B9\u5411\u952E\u79FB\u52A8 | Enter\u9009\u62E9 | 1-9 0 !@#$%%^& \u5FEB\u6377\u952E | q \u9000\u51FA");
    attroff(COLOR_PAIR(CP_HELPBAR) | A_BOLD);
}

static void draw_statusbar(const char *msg)
{
    int w = getmaxx(stdscr);
    int h = getmaxy(stdscr);
    attron(COLOR_PAIR(CP_STATUSBAR));
    for (int x = 0; x < w; x++) mvaddch(h - 2, x, ' ');
    if (msg) mvprintw(h - 2, 2, " %s", msg);
    attroff(COLOR_PAIR(CP_STATUSBAR));
}

static void draw_item(int y, int x, const char *text, int hl)
{
    int cols = getmaxx(stdscr);
    int pair = hl ? CP_MENU_HL : CP_MENU_NORM;
    int attr = hl ? (A_BOLD | COLOR_PAIR(pair)) : COLOR_PAIR(pair);
    attron(attr);
    for (int c = x; c < cols - 1; c++) mvaddch(y, c, ' ');
    mvprintw(y, x, " %s", text);
    attroff(attr);
}

static void draw_menu(int hl_idx)
{
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    int x = 4, y = 2;

    for (int i = 0; i < LAYOUT_LEN && y < rows - 2; i++) {
        int item = layout[i];
        if (item == -1) {
            for (int c = x; c < cols - 2; c++) mvaddch(y, c, '-');
            y++;
        } else if (item == -2) {
            attron(COLOR_PAIR(CP_MENU_CAT) | A_BOLD);
            mvprintw(y++, x, "-- \u6293\u5305\u4E0E\u6587\u4EF6\u64CD\u4F5C --");
            attroff(COLOR_PAIR(CP_MENU_CAT) | A_BOLD);
        } else if (item == -3) {
            attron(COLOR_PAIR(CP_MENU_CAT) | A_BOLD);
            mvprintw(y++, x, "-- \u534F\u8BAE\u89E3\u6790\u4E0E\u7EDF\u8BA1 --");
            attroff(COLOR_PAIR(CP_MENU_CAT) | A_BOLD);
        } else {
            draw_item(y, x, menu_items[item], item == hl_idx);
            y++;
        }
    }
}

/* 确认对话框 */
static int yesno_dialog(const char *msg)
{
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    int dw = strlen(msg) + 12, dh = 5;
    if (dw > cols - 4) dw = cols - 4;
    int dx = (cols - dw) / 2, dy = (rows - dh) / 2;
    WINDOW *dlg = newwin(dh, dw, dy, dx);
    if (!dlg) return 0;
    keypad(dlg, TRUE);
    box(dlg, 0, 0);
    mvwprintw(dlg, 2, 2, "%s (y/n)", msg);
    wrefresh(dlg);
    int ch = wgetch(dlg);
    delwin(dlg);
    touchwin(stdscr);
    refresh();
    return (ch == 'y' || ch == 'Y');
}

/* Shell-out */
typedef void (*func_t)(void);

static void shell_out(func_t func, const char *title)
{
    def_prog_mode();
    endwin();
    /* ensure console is in line-buffered mode for scanf/getchar */
    HANDLE hCon = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hCon, &mode);
    SetConsoleMode(hCon, mode | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
    if (title) printf("===== %s =====\n\n", title);
    func();
    printf("\n----- \u6309\u4EFB\u610F\u952E\u8FD4\u56DE\u83DC\u5355 -----");
    _getch();
    flushinp();
    reset_prog_mode();
    refresh();
}

/* 网卡选择 */
static int select_device_terminal(char *dev, int size)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;
    int count = 0, choice;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("\u83B7\u53D6\u7F51\u5361\u5217\u8868\u5931\u8D25: %s\n", errbuf);
        return -1;
    }
    for (d = alldevs; d; d = d->next) {
        count++;
        printf("%d. %s", count, d->name);
        if (d->description) printf(" - %s", d->description);
        printf("\n");
    }
    if (count == 0) { printf("\u65E0\u53EF\u7528\u7F51\u5361\u3002\n"); pcap_freealldevs(alldevs); return -1; }
    printf("\n\u8BF7\u9009\u62E9\u7F51\u5361\u7F16\u53F7: ");
    if (scanf("%d", &choice) != 1) choice = -1;
    while (getchar() != '\n');
    if (choice < 1 || choice > count) { printf("\u65E0\u6548\u7F16\u53F7\u3002\n"); pcap_freealldevs(alldevs); return -1; }
    d = alldevs;
    for (int i = 1; i < choice; i++) d = d->next;
    strncpy(dev, d->name, size - 1);
    dev[size - 1] = '\0';
    pcap_freealldevs(alldevs);
    return 0;
}

/* ===== 菜单函数 ===== */

static void fn_list(void)         { list_devices(); }
static void fn_self_test(void)    { net_utils_self_test(); }

static void fn_capture(void)
{
    char dev[512]; int count = 10;
    if (select_device_terminal(dev, sizeof(dev)) != 0) return;
    printf("\u6293\u5305\u6570\u91CF (默\u8BA4 10): ");
    if (scanf("%d", &count) != 1) count = 10;
    while (getchar() != '\n');
    if (count <= 0) count = 10;
    pcap_t *h = capture_init(dev);
    if (h) { start_capture(h); capture_packets_with_stats(h, count); stop_capture(h); }
}

static void fn_save_pcap(void)
{
    char dev[512], fn[256]; int count = 10;
    if (select_device_terminal(dev, sizeof(dev)) != 0) return;
    printf("\u6293\u5305\u6570\u91CF (默\u8BA4 10): ");
    if (scanf("%d", &count) != 1) count = 10;
    while (getchar() != '\n');
    if (count <= 0) count = 10;
    printf("pcap \u6587\u4EF6\u540D: ");
    scanf("%255s", fn); while (getchar() != '\n');
    pcap_t *h = capture_init(dev);
    if (h) { start_capture(h); capture_save_to_file(h, count, fn); stop_capture(h); }
}

static void fn_read_pcap(void)
{
    char fn[256];
    printf("pcap \u6587\u4EF6\u540D: ");
    scanf("%255s", fn); while (getchar() != '\n');
    read_pcap_file(fn);
}

static void fn_filter_cap(void)
{
    char dev[512], filter[256]; int count = 10;
    if (select_device_terminal(dev, sizeof(dev)) != 0) return;
    printf("\u6293\u5305\u6570\u91CF (默\u8BA4 10): ");
    if (scanf("%d", &count) != 1) count = 10;
    while (getchar() != '\n');
    if (count <= 0) count = 10;
    printf("BPF \u8FC7\u6EE4\u89C4\u5219 (\u5982 tcp port 80): ");
    fgets(filter, sizeof(filter), stdin);
    filter[strcspn(filter, "\n")] = '\0';
    pcap_t *h = capture_init(dev);
    if (h) {
        if (apply_filter(h, filter) == 0) { start_capture(h); capture_packets_with_stats(h, count); }
        stop_capture(h);
    }
}

static void fn_read_bpf(void)
{
    char fn[256], filter[256];
    printf("pcap \u6587\u4EF6\u540D: ");
    scanf("%255s", fn); while (getchar() != '\n');
    printf("BPF \u8FC7\u6EE4\u89C4\u5219: ");
    fgets(filter, sizeof(filter), stdin);
    filter[strcspn(filter, "\n")] = '\0';
    read_pcap_file_with_filter(fn, filter);
}

static void fn_perf(void)
{
    char dev[512]; int sec = 5;
    if (select_device_terminal(dev, sizeof(dev)) != 0) return;
    printf("\u6D4B\u8BD5\u65F6\u957F (\u79D2, 默\u8BA4 5): ");
    if (scanf("%d", &sec) != 1) sec = 5;
    while (getchar() != '\n');
    if (sec <= 0) sec = 5;
    pcap_t *h = capture_init(dev);
    if (h) { performance_capture_test(h, sec); stop_capture(h); }
}

static void fn_proto(void)
{
    char fn[256], filter[256]; int hasf = 0;
    printf("pcap \u6587\u4EF6\u540D: ");
    scanf("%255s", fn); while (getchar() != '\n');
    printf("使用 BPF \u8FC7\u6EE4\uFF1F(y/n): ");
    int c = _getch(); printf("%c\n", c);
    while (_kbhit()) _getch();
    if (c == 'y' || c == 'Y') {
        printf("\u8FC7\u6EE4\u89C4\u5219: ");
        fgets(filter, sizeof(filter), stdin);
        filter[strcspn(filter, "\n")] = '\0';
        hasf = 1;
    }
    if (hasf) analyze_pcap_file_with_filter(fn, filter, 1);
    else analyze_pcap_file(fn, 1);
}

static void fn_dns(void)
{
    char fn[256];
    printf("pcap \u6587\u4EF6\u540D: ");
    scanf("%255s", fn); while (getchar() != '\n');
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *h = pcap_open_offline(fn, errbuf);
    if (!h) { printf("\u6253\u5F00\u5931\u8D25: %s\n", errbuf); return; }
    struct pcap_pkthdr *hdr; const u_char *data; int res, dc = 0, tot = 0;
    printf("\u6587\u4EF6: %s\n", fn);
    while ((res = pcap_next_ex(h, &hdr, &data)) >= 0) {
        if (res == 0) continue; tot++;
        ParsedPacket pkt; memset(&pkt, 0, sizeof(pkt));
        pkt.ts = hdr->ts; pkt.packet_len = hdr->len; pkt.captured_len = hdr->caplen;
        if (analyze_packet(data, (uint32_t)hdr->caplen, &pkt) == 0 && pkt.app_proto == PROTO_DNS && pkt.payload_len > 0) {
            dc++; printf("\n--- DNS #%d ---\n", dc);
            dns_result_t dns;
            if (parse_dns(pkt.payload, pkt.payload_len, &dns) == 0) print_dns(&dns);
            if (dc >= 20) { printf("\n(20 \u4E2A\u4E0A\u9650)\n"); break; }
        }
    }
    printf("\n\u603B\u5305 %d, DNS %d\n", tot, dc);
    pcap_close(h);
}

static void fn_http(void)
{
    char fn[256];
    printf("pcap \u6587\u4EF6\u540D: ");
    scanf("%255s", fn); while (getchar() != '\n');
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *h = pcap_open_offline(fn, errbuf);
    if (!h) { printf("\u6253\u5F00\u5931\u8D25: %s\n", errbuf); return; }
    struct pcap_pkthdr *hdr; const u_char *data; int res, hc = 0, tot = 0;
    printf("\u6587\u4EF6: %s\n", fn);
    while ((res = pcap_next_ex(h, &hdr, &data)) >= 0) {
        if (res == 0) continue; tot++;
        ParsedPacket pkt; memset(&pkt, 0, sizeof(pkt));
        pkt.ts = hdr->ts; pkt.packet_len = hdr->len; pkt.captured_len = hdr->caplen;
        if (analyze_packet(data, (uint32_t)hdr->caplen, &pkt) == 0 &&
            (pkt.app_proto == PROTO_HTTP_REQUEST || pkt.app_proto == PROTO_HTTP_RESPONSE) && pkt.payload_len > 0) {
            hc++; printf("\n--- HTTP #%d ---\n", hc);
            http_result_t http;
            if (parse_http(pkt.payload, pkt.payload_len, &http) == 0) print_http(&http);
            free_http_result(&http);
            if (hc >= 20) { printf("\n(20 \u4E2A\u4E0A\u9650)\n"); break; }
        }
    }
    printf("\n\u603B\u5305 %d, HTTP %d\n", tot, hc);
    pcap_close(h);
}

static void fn_bpf_test(void)
{
    char fn[256];
    printf("pcap \u6587\u4EF6\u540D: ");
    scanf("%255s", fn); while (getchar() != '\n');
    bpf_run_test_suite(fn);
}

static void fn_bpf_rules(void)
{
    bpf_print_common_rules();
    printf("\n\u6D4B\u8BD5\u89C4\u5219? (y/n): ");
    int c = _getch(); printf("%c\n", c);
    while (_kbhit()) _getch();
    if (c == 'y' || c == 'Y') {
        char fn[256], filter[256];
        printf("pcap \u6587\u4EF6\u540D: ");
        scanf("%255s", fn); while (getchar() != '\n');
        printf("\u8FC7\u6EE4\u89C4\u5219: ");
        fgets(filter, sizeof(filter), stdin);
        filter[strcspn(filter, "\n")] = '\0';
        bpf_filter_offline(fn, filter);
    }
}

static void fn_stats_live(void)
{
    char dev[512]; int sec = 0;
    if (select_device_terminal(dev, sizeof(dev)) != 0) return;
    printf("\u7EDF\u8BA1\u65F6\u957F (\u79D2, 0=\u6301\u7EED): ");
    if (scanf("%d", &sec) != 1) sec = 0;
    while (getchar() != '\n');
    pcap_t *h = capture_init(dev);
    if (h) { stats_t stats; stats_capture(h, sec, &stats); stop_capture(h); }
}

static void fn_stats_pcap(void)
{
    char fn[256];
    printf("pcap \u6587\u4EF6\u540D: ");
    scanf("%255s", fn); while (getchar() != '\n');
    stats_t stats;
    if (stats_from_pcap(fn, &stats) == 0) stats_print(&stats);
}

static void fn_stats_pcap_f(void)
{
    char fn[256], filter[256];
    printf("pcap \u6587\u4EF6\u540D: ");
    scanf("%255s", fn); while (getchar() != '\n');
    printf("BPF \u8FC7\u6EE4\u89C4\u5219: ");
    fgets(filter, sizeof(filter), stdin);
    filter[strcspn(filter, "\n")] = '\0';
    stats_t stats;
    if (stats_from_pcap_with_filter(fn, filter, &stats) == 0) stats_print(&stats);
}

/* ---- 17. TCP \u6D41\u91CD\u7EC4 ---- */
static void fn_tcp_reassemble(void)
{
    char fn[256], filter[256];
    printf("pcap \u6587\u4EF6\u540D: ");
    scanf("%255s", fn); while (getchar() != '\n');
    printf("BPF \u8FC7\u6EE4\u89C4\u5219\uFF08\u76F4\u63A5\u56DE\u8F66\u8DF3\u8FC7\uFF09: ");
    fgets(filter, sizeof(filter), stdin);
    filter[strcspn(filter, "\n")] = '\0';
    int pairs = tcp_reassemble_from_pcap(fn, filter[0] ? filter : NULL);
    if (pairs > 0) {
        printf("\n\u6210\u529F\uFF01%d \u4E2A HTTP \u4F1A\u8BDD\u5DF2\u4FDD\u5B58\u5230 reassembly_output/ \u76EE\u5F55\u3002\n", pairs);
        printf("\u8BF7\u6253\u5F00\u8BE5\u76EE\u5F55\u9A8C\u8BC1\u8BF7\u6C42/\u54CD\u5E94\u5BF9\u662F\u5426\u5B8C\u6574\u3002\n");
    } else {
        printf("\n\u672A\u63D0\u53D6\u5230 HTTP \u4F1A\u8BDD\u3002\n");
    }
}

/* ===== \u51FD\u6570\u8868 ===== */
static func_t menu_funcs[MENU_COUNT] = {
    fn_list, fn_capture, fn_save_pcap, fn_read_pcap,
    fn_filter_cap, fn_read_bpf, fn_self_test, fn_perf,
    fn_proto, fn_dns, fn_http, fn_bpf_test,
    fn_bpf_rules, fn_stats_live, fn_stats_pcap, fn_stats_pcap_f,
    fn_tcp_reassemble
};

static const char *menu_titles[MENU_COUNT] = {
    "\u7F51\u5361\u5217\u8868", "\u5B9E\u65F6\u6293\u5305", "\u4FDD\u5B58 pcap", "\u8BFB\u53D6 pcap",
    "BPF \u8FC7\u6EE4\u6293\u5305", "BPF \u8BFB\u53D6 pcap", "\u81EA\u6D4B", "\u6027\u80FD\u6D4B\u8BD5",
    "\u534F\u8BAE\u5206\u6790", "DNS \u89E3\u6790", "HTTP \u89E3\u6790", "BPF \u6D4B\u8BD5\u5957\u4EF6",
    "BPF \u89C4\u5219", "\u5B9E\u65F6\u6D41\u91CF\u7EDF\u8BA1", "pcap \u7EDF\u8BA1", "pcap+BPF \u7EDF\u8BA1",
    "TCP \u6D41\u91CD\u7EC4"
};

/* ===== \u4E3B\u5FAA\u73AF ===== */
int main(void)
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    timeout(-1);

    if (has_colors()) init_colors();

    int hl = 0;
    int running = 1;

    while (running) {
        erase();
        draw_title();
        draw_menu(hl);
        draw_statusbar("\u5C31\u7EEA");
        draw_helpbar();
        wnoutrefresh(stdscr);
        doupdate();

        int ch = getch();
        int exec = -1;

        switch (ch) {
        case KEY_UP:    if (--hl < 0) hl = MENU_COUNT - 1; break;
        case KEY_DOWN:  if (++hl >= MENU_COUNT) hl = 0; break;
        case '\n': case '\r': case ' ': exec = hl; break;
        case 'q': case 'Q': case 27: if (yesno_dialog("\u786E\u8BA4\u9000\u51FA")) running = 0; break;
        case '1': exec = 0;  break; case '2': exec = 1;  break;
        case '3': exec = 2;  break; case '4': exec = 3;  break;
        case '5': exec = 4;  break; case '6': exec = 5;  break;
        case '7': exec = 6;  break; case '8': exec = 7;  break;
        case '9': exec = 8;  break; case '0': exec = 9;  break;
        case '!': exec = 10; break; case '@': exec = 11; break;
        case '#': exec = 12; break; case '$': exec = 13; break;
        case '%': exec = 14; break; case '^': exec = 15; break;
        case '&': exec = 16; break;
        default: break;
        }

        if (exec >= 0 && exec < MENU_COUNT) {
            shell_out(menu_funcs[exec], menu_titles[exec]);
            cbreak(); noecho(); keypad(stdscr, TRUE); curs_set(0);
        }
    }

    clear();
    refresh();
    endwin();
    printf("\u7A0B\u5E8F\u5DF2\u9000\u51FA\u3002\n");
    return 0;
}
