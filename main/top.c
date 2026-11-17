/* top: a full-screen, htop-style live view of the device - CPU per task,
 * memory, the file area, the network and who is logged in. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "c3shell.h"

#define TOP_TASKS 40
#define OUT_CAP   2048

enum { K_UP = 1000, K_DOWN, K_PGUP, K_PGDN, K_HOME, K_END, K_F10, K_OTHER };
enum { SORT_CPU, SORT_STACK, SORT_NAME, SORT_PRIO, SORT_N };
static const char *const sort_name[SORT_N] = { "CPU%", "STACK", "NAME", "PRI" };

typedef struct {
    port_task_t t;
    float       cpu;          /* percent of one core over the last interval, -1 = not known yet */
} row_t;

typedef struct {
    session_t  *s;
    char        out[OUT_CAP];
    int         n;
    int         cols, rows, row, col;
    /* the previous sample, for CPU deltas */
    struct { uint32_t id, runtime; } prev[TOP_TASKS];
    int         nprev;
    uint32_t    prev_us;
    bool        have_prev, measured;
    port_task_t cur[TOP_TASKS];
    row_t       task[TOP_TASKS];
    int         ntask, running;
    float       cpu_total;    /* -1 = not known yet */
    int         sort, scroll, delay_s;
} top_t;

/* ---------------- output: clipped, coloured segments ---------------- */

static void flush(top_t *t)
{
    if (t->n)
        tn_write(t->s, t->out, (size_t)t->n);
    t->n = 0;
}

static void put(top_t *t, const char *p, int len)
{
    while (len > 0) {
        int room = OUT_CAP - t->n;
        if (room == 0) {
            flush(t);
            continue;
        }
        int k = len < room ? len : room;
        memcpy(t->out + t->n, p, (size_t)k);
        t->n += k;
        p += k;
        len -= k;
    }
}

static void puts_(top_t *t, const char *p) { put(t, p, (int)strlen(p)); }

/* Text at the cursor in SGR colour sgr (NULL = plain), cut at the right edge. */
static void seg(top_t *t, const char *sgr, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void seg(top_t *t, const char *sgr, const char *fmt, ...)
{
    char tmp[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    int room = t->cols - t->col, k = (int)strlen(tmp);
    if (room <= 0 || k == 0)
        return;
    if (k > room)
        k = room;
    if (sgr) {
        puts_(t, "\x1b[");
        puts_(t, sgr);
        puts_(t, "m");
    }
    put(t, tmp, k);
    if (sgr)
        puts_(t, "\x1b[0m");
    t->col += k;
}

/* Start screen line t->row (0-based); false once the screen is full. */
static bool line(top_t *t)
{
    char go[24];
    if (t->row >= t->rows)
        return false;
    snprintf(go, sizeof go, "\x1b[%d;1H", t->row + 1);
    puts_(t, go);
    t->col = 0;
    return true;
}

static void endline(top_t *t)
{
    if (t->col < t->cols)
        puts_(t, "\x1b[K");
    t->row++;
}

static void human(char *out, size_t cap, long long bytes)
{
    if (bytes < 0)
        snprintf(out, cap, "?");
    else if (bytes < 10 * 1024)
        snprintf(out, cap, "%.1fK", (double)bytes / 1024);
    else if (bytes < 1024 * 1024)
        snprintf(out, cap, "%lldK", bytes / 1024);
    else
        snprintf(out, cap, "%.1fM", (double)bytes / (1024 * 1024));
}

static void duration(char *out, size_t cap, uint32_t s)
{
    if (s >= 86400)
        snprintf(out, cap, "%ud %02u:%02u:%02u", (unsigned)(s / 86400), (unsigned)(s / 3600 % 24),
                 (unsigned)(s / 60 % 60), (unsigned)(s % 60));
    else
        snprintf(out, cap, "%02u:%02u:%02u", (unsigned)(s / 3600), (unsigned)(s / 60 % 60), (unsigned)(s % 60));
}

/* "Label[||||||        text]" across the whole line, like htop's meters */
static void meter(top_t *t, const char *label, double frac, const char *text)
{
    int w = t->cols - (int)strlen(label) - 2, tl = (int)strlen(text);
    char bar[256];
    if (w > (int)sizeof bar - 1)
        w = (int)sizeof bar - 1;
    if (w < tl)
        w = tl;
    if (frac < 0)
        frac = 0;
    if (frac > 1)
        frac = 1;
    int fill = (int)(frac * w + 0.5), room = w - tl;
    if (fill > room)
        fill = room;
    const char *col = frac < 0.6 ? "32" : frac < 0.85 ? "33" : "31";
    seg(t, "1;36", "%s", label);
    seg(t, "1", "[");
    memset(bar, '|', (size_t)fill);
    bar[fill] = 0;
    seg(t, col, "%s", bar);
    memset(bar, ' ', (size_t)(room - fill));
    bar[room - fill] = 0;
    seg(t, NULL, "%s", bar);
    seg(t, "2", "%s", text);
    seg(t, "1", "]");
}

/* ---------------- sampling ---------------- */

static bool idle_task(const char *name) { return strncmp(name, "IDLE", 4) == 0; }

static bool before(const top_t *t, const row_t *a, const row_t *b)
{
    switch (t->sort) {
    case SORT_STACK:
        return a->t.stack_free < b->t.stack_free;     /* tightest stack first */
    case SORT_NAME:
        return strcmp(a->t.name, b->t.name) < 0;
    case SORT_PRIO:
        return a->t.prio > b->t.prio;
    default:
        if (a->cpu != b->cpu)
            return a->cpu > b->cpu;
        return a->t.runtime > b->t.runtime;
    }
}

static void sort_tasks(top_t *t)
{
    for (int i = 1; i < t->ntask; i++) {
        row_t r = t->task[i];
        int j = i;
        for (; j > 0 && before(t, &r, &t->task[j - 1]); j--)
            t->task[j] = t->task[j - 1];
        t->task[j] = r;
    }
}

static void sample(top_t *t)
{
    uint32_t now = 0;
    int n = port_tasks(t->cur, TOP_TASKS, &now);
    uint32_t dt = now - t->prev_us;
    float idle = 0, busy = 0;
    bool have_idle = false;

    if (n < 0)
        n = 0;
    t->ntask = n;
    t->running = 0;
    t->measured = false;
    for (int i = 0; i < n; i++) {
        row_t *r = &t->task[i];
        r->t = t->cur[i];
        r->cpu = -1;
        if (r->t.state == 'R')
            t->running++;
        if (r->t.runtime)
            t->measured = true;
        for (int j = 0; t->have_prev && dt > 0 && j < t->nprev; j++) {
            if (t->prev[j].id == r->t.id) {
                r->cpu = (float)(r->t.runtime - t->prev[j].runtime) * 100.0f / (float)dt;
                break;
            }
        }
        if (r->cpu >= 0) {
            if (idle_task(r->t.name)) {
                idle += r->cpu;
                have_idle = true;
            } else {
                busy += r->cpu;
            }
        }
    }
    /* On the chip everything that is not the idle task is work; the simulator has no idle task. */
    if (!t->have_prev || !t->measured)
        t->cpu_total = -1;
    else
        t->cpu_total = have_idle ? 100.0f - idle : busy;
    if (t->cpu_total < -0.5f)
        t->cpu_total = 0;

    t->nprev = n;
    for (int i = 0; i < n; i++) {
        t->prev[i].id = t->cur[i].id;
        t->prev[i].runtime = t->cur[i].runtime;
    }
    t->prev_us = now;
    t->have_prev = true;
    sort_tasks(t);
}

/* ---------------- drawing ---------------- */

static void header_row(top_t *t, const char *text)
{
    if (!line(t))
        return;
    seg(t, "30;46", "%-*s", t->cols < 255 ? t->cols : 255, text);
    endline(t);
}

static void draw(top_t *t)
{
    session_t *s = t->s;
    char a[24], b[24], c[24], txt[96], id[5];
    net_status_t st;
    vpn_status_t vs;
    port_sysinfo_t si;
    sess_info_t ss[C3_MAX_SESSIONS];
    long total = 0, used = 0, heap, minfree, largest;
    uint32_t up = port_uptime_s();

    t->cols = s->cols > 0 ? s->cols : 80;
    t->rows = s->rows > 0 ? s->rows : 24;
    t->row = 0;
    port_device_id(id);
    port_sysinfo(&si);
    port_heap(&heap, &minfree, &largest);
    netmgr_status(&st);
    vpn_status(&vs);
    int nss = server_sessions(ss, C3_MAX_SESSIONS);

    puts_(t, "\x1b[?25l");

    /* title */
    line(t);
    duration(a, sizeof a, up);
    seg(t, "1", "%s-%s", C3_NAME, id);
    seg(t, NULL, "  up %s   tasks %d, %d running   sessions %d/%d", a, t->ntask, t->running, nss, C3_MAX_SESSIONS);
    endline(t);

    /* meters */
    if (line(t)) {
        if (t->cpu_total >= 0)
            snprintf(txt, sizeof txt, "%.1f%%", (double)t->cpu_total);
        else
            snprintf(txt, sizeof txt, "%s", t->ntask && !t->measured && t->have_prev ? "n/a" : "...");
        meter(t, "CPU ", t->cpu_total / 100.0, txt);
        endline(t);
    }
    if (line(t)) {
        if (heap >= 0 && si.heap_total > 0) {
            human(a, sizeof a, si.heap_total - heap);
            human(b, sizeof b, si.heap_total);
            snprintf(txt, sizeof txt, "%s/%s", a, b);
            meter(t, "Mem ", (double)(si.heap_total - heap) / (double)si.heap_total, txt);
        } else {
            meter(t, "Mem ", 0, "n/a");
        }
        endline(t);
    }
    if (line(t)) {
        if (port_fs_usage(&total, &used) == 0 && total > 0) {
            human(a, sizeof a, used);
            human(b, sizeof b, total);
            snprintf(txt, sizeof txt, "%s/%s", a, b);
            meter(t, "Disk", (double)used / (double)total, txt);
        } else {
            meter(t, "Disk", 0, "n/a");
        }
        endline(t);
    }
    if (minfree >= 0 && line(t)) {
        human(a, sizeof a, heap);
        human(b, sizeof b, minfree);
        human(c, sizeof c, largest);
        seg(t, "1;36", "Heap ");
        seg(t, NULL, "free %s   lowest ever %s   largest block %s", a, b, c);
        endline(t);
    }
    if (line(t)) {
        seg(t, "1;36", "WiFi ");
        if (st.sta_up)
            seg(t, NULL, "%s  %s  %d dBm", st.sta_ssid, st.sta_ip, st.rssi);
        else if (st.have_saved)
            seg(t, NULL, "'%s' not reachable", st.sta_ssid);
        else
            seg(t, NULL, "not joined");
        if (st.ap_up)
            seg(t, NULL, "   hosting %s (%s)", st.ap_ssid, st.ap_ip);
        endline(t);
    }
    if (line(t)) {
        seg(t, "1;36", "VPN  ");
        if (vs.running) {
            human(a, sizeof a, (long long)vs.rx);
            human(b, sizeof b, (long long)vs.tx);
            seg(t, NULL, "%s%s%s   rx %s  tx %s", vs.state, vs.ip[0] ? "  " : "", vs.ip, a, b);
        } else {
            seg(t, NULL, "off");
        }
        endline(t);
    }

    /* sessions */
    if (line(t))
        endline(t);
    header_row(t, "  #  USER            FROM                  TIME  DOING");
    for (int i = 0; i < nss && line(t); i++) {
        duration(a, sizeof a, up - ss[i].since_s);
        const char *doing = ss[i].doing[0] ? ss[i].doing : "shell";
        seg(t, ss[i].id == s->id ? "1" : NULL, "%c%2d  %-15.15s %-15.15s %10s  %s%s", ss[i].id == s->id ? '*' : ' ',
            ss[i].id + 1, ss[i].user[0] ? ss[i].user : "-", ss[i].peer, a, doing, ss[i].via_ap ? " (setup net)" : "");
        endline(t);
    }

    /* tasks, scrollable, above the key bar */
    if (line(t))
        endline(t);
    snprintf(txt, sizeof txt, " %-15s ST  PRI   %s   %s", sort_name[SORT_NAME], sort_name[SORT_CPU],
             "STACK FREE");
    header_row(t, txt);
    int vis = t->rows - 1 - t->row;
    if (vis < 0)
        vis = 0;
    int maxscroll = t->ntask > vis ? t->ntask - vis : 0;
    if (t->scroll > maxscroll)
        t->scroll = maxscroll;
    if (t->scroll < 0)
        t->scroll = 0;
    for (int i = t->scroll; i < t->ntask && t->row < t->rows - 1; i++) {
        row_t *r = &t->task[i];
        line(t);
        if (r->cpu >= 0)
            snprintf(a, sizeof a, "%5.1f", (double)r->cpu);
        else
            snprintf(a, sizeof a, "    -");
        if (r->t.stack_free >= 0)
            snprintf(b, sizeof b, "%6ld", r->t.stack_free);
        else
            snprintf(b, sizeof b, "     -");
        const char *col = r->t.state == 'R' ? "1;32" : NULL;
        seg(t, col, " %-15.15s %c  %3u  %s %9s", r->t.name, r->t.state, (unsigned)r->t.prio, a, b);
        if (r->t.stack_free >= 0 && r->t.stack_free < 512)
            seg(t, "1;31", "  low!");
        endline(t);
    }
    while (t->row < t->rows - 1) {
        line(t);
        endline(t);
    }

    /* key bar */
    t->row = t->rows - 1;
    line(t);
    seg(t, "1", "q");
    seg(t, "30;46", "Quit  ");
    seg(t, "1", "s");
    snprintf(txt, sizeof txt, "Sort:%-6s", sort_name[t->sort]);
    seg(t, "30;46", "%s", txt);
    seg(t, "1", "+-");
    snprintf(txt, sizeof txt, "Every %ds ", t->delay_s);
    seg(t, "30;46", "%s", txt);
    seg(t, "1", "Up/Dn");
    seg(t, "30;46", "Scroll ");
    endline(t);
    flush(t);
}

/* ---------------- input ---------------- */

static int key(top_t *t, int timeout_ms)
{
    int c = tn_getc(t->s, timeout_ms);
    if (c != 0x1B)
        return c;
    int c2 = tn_getc(t->s, 40);
    if (c2 < 0)
        return 0x1B;                /* Esc on its own */
    if (c2 != '[' && c2 != 'O')
        return K_OTHER;
    int c3 = tn_getc(t->s, 40);
    switch (c3) {
    case 'A': return K_UP;
    case 'B': return K_DOWN;
    case 'H': return K_HOME;
    case 'F': return K_END;
    }
    if (c3 >= '0' && c3 <= '9') {   /* Esc [ number ~ */
        int num = c3 - '0', c4;
        while ((c4 = tn_getc(t->s, 40)) >= '0' && c4 <= '9')
            num = num * 10 + c4 - '0';
        while (c4 >= 0 && c4 < 0x40)            /* ";modifier" parameters */
            c4 = tn_getc(t->s, 40);
        switch (num) {
        case 1: case 7: return K_HOME;
        case 4: case 8: return K_END;
        case 5: return K_PGUP;
        case 6: return K_PGDN;
        case 21: return K_F10;
        }
    }
    return K_OTHER;
}

int cmd_top(session_t *s, int argc, char **argv)
{
    int delay = 2;
    if (argc == 3 && strcmp(argv[1], "-d") == 0 && atoi(argv[2]) >= 1 && atoi(argv[2]) <= 60) {
        delay = atoi(argv[2]);
    } else if (argc != 1) {
        tn_puts(s, "usage: top [-d seconds]   (1-60, default 2)\n");
        return 0;
    }
    top_t *t = calloc(1, sizeof *t);
    if (!t) {
        tn_puts(s, "top: out of memory\n");
        return 0;
    }
    t->s = s;
    t->delay_s = delay;

    tn_write(s, "\x1b[?1049h\x1b[2J", 12);     /* alternate screen, like a full-screen program */
    s->winch = false;
    sample(t);
    bool first = true, quit = false;
    while (!quit && !s->closed) {
        if (!first)
            sample(t);
        draw(t);
        int limit = first ? 700 : t->delay_s * 1000;    /* first CPU figures come quickly */
        first = false;
        for (int waited = 0; waited < limit && !quit;) {
            int k = key(t, 250);
            if (k == TN_TIMEOUT) {
                waited += 250;
                if (s->winch) {
                    s->winch = false;
                    puts_(t, "\x1b[2J");
                    draw(t);
                }
                continue;
            }
            int page = t->rows > 16 ? t->rows - 16 : 1;
            switch (k) {
            case TN_CLOSED: case 'q': case 'Q': case 0x03: case 0x04: case 0x1B: case K_F10:
                quit = true;
                continue;
            case 's': case 'S': case '>': case '<':
                t->sort = (t->sort + 1) % SORT_N;
                sort_tasks(t);
                break;
            case '+': case '=':
                if (t->delay_s < 60)
                    t->delay_s++;
                break;
            case '-': case '_':
                if (t->delay_s > 1)
                    t->delay_s--;
                break;
            case K_UP: case 'k':   t->scroll--; break;
            case K_DOWN: case 'j': t->scroll++; break;
            case K_PGUP:           t->scroll -= page; break;
            case K_PGDN: case ' ': t->scroll += page; break;
            case K_HOME: case 'g': t->scroll = 0; break;
            case K_END: case 'G':  t->scroll = TOP_TASKS; break;
            case 0x0C:             puts_(t, "\x1b[2J"); break;    /* Ctrl-L */
            default:               continue;
            }
            draw(t);
        }
    }
    if (!s->closed)
        tn_puts(s, "\x1b[0m\x1b[?25h\x1b[?1049l");
    free(t);
    return 0;
}
