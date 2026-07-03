/**
 * ncurses 双窗口布局示例
 * 上方：列表区（可滚动）
 * 下方：详情区（显示选中项详情）
 *
 * 编译: gcc -o ncurses_dual_pane ncurses_dual_pane.c -lncurses
 * 或 (Windows/MSYS2): gcc -o ncurses_dual_pane.exe ncurses_dual_pane.c -lncurses
 */

#include <ncurses.h>
#include <string.h>
#include <stdlib.h>

/* ==================== 数据 ==================== */

#define ITEM_COUNT 8

static const char *items[ITEM_COUNT] = {
    "apple.txt",
    "books/",
    "config.yaml",
    "main.c",
    "notes.md",
    "photos/",
    "script.py",
    "tmp/"
};

static const char *details[ITEM_COUNT] = {
    "Type: file\nSize: 1.2 KB\nModified: 2026-06-30 14:22\nDesc: 随便记的购物清单",
    "Type: directory\nSize: 4.1 KB (12 files)\nModified: 2026-06-28 09:15\nDesc: 电子书合集",
    "Type: file\nSize: 3.5 KB\nModified: 2026-06-30 10:00\nDesc: OpenClaw 配置",
    "Type: file\nSize: 8.7 KB\nModified: 2026-06-30 16:45\nDesc: 主程序源代码",
    "Type: file\nSize: 2.1 KB\nModified: 2026-06-29 21:30\nDesc: 开发笔记",
    "Type: directory\nSize: 18.2 MB (43 files)\nModified: 2026-06-25 11:10\nDesc: 2026 旅行照片",
    "Type: file\nSize: 5.3 KB\nModified: 2026-06-30 12:00\nDesc: Python 脚本 helper",
    "Type: directory\nSize: 205 KB (7 files)\nModified: 2026-06-27 08:50\nDesc: 临时下载文件"
};

/* ==================== 辅助函数 ==================== */

/* 安全地在窗口内画边框（不使用默认边框，节省一行） */
static void draw_separator(WINDOW *win, int y, int x, int w, chtype ch) {
    int i;
    for (i = 0; i < w; i++)
        mvwaddch(win, y, x + i, ch);
}

/* 在窗口内用属性画文字，自动截断 */
static void mvwprint_trunc(WINDOW *win, int y, int x, int maxw, const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    int len = (int)strlen(buf);
    if (len > maxw) {
        /* 截断 + "…" */
        memcpy(buf + maxw - 1, "…", 3);   /* UTF-8 省略号 3 字节 */
        buf[maxw + 2] = '\0';
        len = maxw + 2;
    }
    mvwaddstr(win, y, x, buf);
}

/* 获取显示多行详情的实际行数 */
static int detail_line_count(const char *detail, int maxw) {
    int lines = 0;
    const char *p = detail;
    while (*p) {
        const char *nl = strchr(p, '\n');
        int linelen = nl ? (int)(nl - p) : (int)strlen(p);
        /* 需要折行的行数 */
        lines += (linelen + maxw - 1) / maxw;
        if (nl)
            p = nl + 1;
        else
            break;
    }
    return lines;
}

/* ==================== 绘制 ==================== */

static void draw_list(WINDOW *win, int highlight, int top, int h, int w) {
    werase(win);

    int y;
    for (y = 0; y < h; y++) {
        int idx = top + y;
        if (idx >= ITEM_COUNT)
            break;

        if (idx == highlight) {
            wattron(win, A_REVERSE);
            mvwprint_trunc(win, y, 1, w - 2, " %s", items[idx]);
            wattroff(win, A_REVERSE);
        } else {
            /* 目录加粗/高亮 */
            if (details[idx][0] == 'T' && strstr(details[idx], "directory")) {
                wattron(win, A_BOLD | COLOR_PAIR(2));
            }
            mvwprint_trunc(win, y, 1, w - 2, " %s", items[idx]);
            wattroff(win, A_BOLD | COLOR_PAIR(2));
        }
    }

    box(win, 0, 0);
    mvwprintw(win, 0, 2, " 文件列表 ");
    wnoutrefresh(win);
}

static void draw_detail(WINDOW *win, int idx, int h, int w) {
    werase(win);

    if (idx < 0 || idx >= ITEM_COUNT) {
        box(win, 0, 0);
        mvwprintw(win, 0, 2, " 详情 ");
        mvwprintw(win, h / 2, 2, "(无选中项)");
        wnoutrefresh(win);
        return;
    }

    const char *detail = details[idx];
    int maxw = w - 4;                 /* 左右留 2 格边距 */
    if (maxw < 1) maxw = 1;

    /* 第一行: 文件名 + 指示器 */
    wattron(win, A_BOLD);
    mvwprint_trunc(win, 1, 2, maxw, "%s", items[idx]);
    wattroff(win, A_BOLD);

    int y = 3;   /* 从第 3 行开始显示详情内容 */
    const char *p = detail;
    while (*p && y < h - 1) {
        const char *nl = strchr(p, '\n');
        int linelen = nl ? (int)(nl - p) : (int)strlen(p);

        /* 需要进行软折行显示 */
        int offset = 0;
        while (offset < linelen && y < h - 1) {
            int chunk = linelen - offset;
            if (chunk > maxw) chunk = maxw;
            char buf[512];
            memcpy(buf, p + offset, chunk);
            buf[chunk] = '\0';
            mvwprintw(win, y, 2, "%s", buf);
            offset += chunk;
            y++;
        }

        if (nl)
            p = nl + 1;
        else
            break;
    }

    /* 如果有更多内容塞不下 */
    while (*p) {
        const char *nl = strchr(p, '\n');
        int linelen = nl ? (int)(nl - p) : (int)strlen(p);
        if ((linelen + maxw - 1) / maxw + y >= h - 1) {
            mvwprintw(win, h - 2, 2, "(... 更多内容)");
            break;
        }
        break;
    }

    box(win, 0, 0);
    mvwprintw(win, 0, 2, " 详情 ");
    wnoutrefresh(win);
}

/* ==================== 主程序 ==================== */

int main(void) {
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);                     /* 隐藏光标 */

    if (has_colors()) {
        start_color();
        init_pair(1, COLOR_CYAN, COLOR_BLACK);
        init_pair(2, COLOR_YELLOW, COLOR_BLACK);
        init_pair(3, COLOR_WHITE, COLOR_BLUE);
    }

    int highlight = 0;               /* 当前高亮项索引 */
    int top = 0;                     /* 列表顶部可见项 */

    int ch;
    int running = 1;

    while (running) {
        /* ----- 获取尺寸并创建子窗口 ----- */
        int max_y, max_x;
        getmaxyx(stdscr, max_y, max_x);

        /* 上 60% 列表区，下 40% 详情区，最少给详情区 5 行 */
        int sep_y = max_y * 60 / 100;
        if (sep_y < 3) sep_y = 3;
        if (max_y - sep_y < 5) sep_y = max_y - 5;
        if (sep_y < 1) sep_y = 1;

        int list_h  = sep_y;
        int detail_h = max_y - sep_y;

        WINDOW *list_win   = newwin(list_h,   max_x, 0, 0);
        WINDOW *detail_win = newwin(detail_h, max_x, sep_y, 0);

        /* 计算列表内容可用行数（去掉边框上下） */
        int list_content_h = list_h - 2;      /* 上/下边框占一行 */
        if (list_content_h < 0) list_content_h = 0;

        /* 如果高亮项超出可视范围，滚动 */
        if (highlight < top)
            top = highlight;
        else if (highlight >= top + list_content_h)
            top = highlight - list_content_h + 1;

        /* 限制 top 范围 */
        if (top > ITEM_COUNT - list_content_h)
            top = ITEM_COUNT - list_content_h;
        if (top < 0) top = 0;

        /* ----- 绘制 ----- */
        draw_list(list_win, highlight, top, list_content_h, max_x);
        draw_detail(detail_win, highlight, detail_h, max_x);

        /* 底部操作提示（直接写到 stdscr） */
        attron(COLOR_PAIR(3));
        mvprintw(max_y - 1, 0, " ↑↓ 选择 | q 退出 ");
        attroff(COLOR_PAIR(3));
        clrtoeol();

        /* 一次 doupdate 刷新所有窗口 */
        doupdate();

        /* ----- 输入 ----- */
        ch = getch();
        switch (ch) {
            case KEY_UP:
                if (highlight > 0) highlight--;
                break;
            case KEY_DOWN:
                if (highlight < ITEM_COUNT - 1) highlight++;
                break;
            case KEY_PPAGE:    /* Page Up */
                highlight -= list_content_h;
                if (highlight < 0) highlight = 0;
                break;
            case KEY_NPAGE:    /* Page Down */
                highlight += list_content_h;
                if (highlight >= ITEM_COUNT) highlight = ITEM_COUNT - 1;
                break;
            case KEY_HOME:
                highlight = 0;
                break;
            case KEY_END:
                highlight = ITEM_COUNT - 1;
                break;
            case 'q':
            case 'Q':
                running = 0;
                break;
            case KEY_RESIZE:
                /* 窗口尺寸自动在下一轮循环处理 */
                break;
            default:
                break;
        }

        delwin(list_win);
        delwin(detail_win);
    }

    endwin();
    return 0;
}
