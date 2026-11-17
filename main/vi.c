/* A small vi.
 *
 * Normal mode:  h j k l / arrows, w b, 0 ^ $, gg G, Ctrl-F Ctrl-B, counts (5j, 3dd, 12G)
 *               i a I A o O        enter insert mode
 *               x r<c> J D dd dw d$ yy p P u   edit (u toggles the last change)
 *               /text n N           search
 *               ZZ, Ctrl-L, Ctrl-G
 * Ex commands:  :w [file]  :q  :q!  :wq  :x  :<line>
 * Insert mode:  typing, Enter, Backspace (joins lines at column 0), Tab, arrows, Esc
 *
 * The whole file lives in RAM (C3_VI_MAX bytes at most), one heap block per
 * line. Saving writes a temporary file and renames it over the original. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "c3shell.h"

enum { K_UP = 0x100, K_DOWN, K_LEFT, K_RIGHT, K_HOME, K_END, K_DEL, K_PGUP, K_PGDN };

typedef struct {
    char *t;
    int len;
} line_t;

typedef struct {
    session_t *s;
    line_t *ln;
    int n, cap;
    int cy, cx;          /* cursor: line, byte offset */
    int top, left;       /* first line / first display column on screen */
    int want;            /* display column vertical moves try to keep */
    bool insert, dirty, quit;
    size_t bytes;
    char vpath[C3_PATH_MAX];
    char msg[200];
    char search[64];
    /* one level of undo: the whole buffer as it was before the last change */
    char *undo;
    size_t undolen;
    int ucy, ucx;
    bool undo_dirty;
    /* yank register (whole lines) */
    char *yank;
    size_t yanklen;
    /* keys read ahead while decoding escape sequences */
    int back[4], nback;
} vi_t;

/* ---------------- buffer ---------------- */

static bool cont(char c) { return ((unsigned char)c & 0xC0) == 0x80; }

static int ins_line(vi_t *v, int at, const char *t, int len)
{
    if (v->n == v->cap) {
        int nc = v->cap ? v->cap * 2 : 64;
        line_t *nl = realloc(v->ln, sizeof *nl * (size_t)nc);
        if (!nl)
            return -1;
        v->ln = nl;
        v->cap = nc;
    }
    char *b = malloc((size_t)len + 1);
    if (!b)
        return -1;
    memcpy(b, t, (size_t)len);
    b[len] = 0;
    memmove(&v->ln[at + 1], &v->ln[at], sizeof *v->ln * (size_t)(v->n - at));
    v->ln[at].t = b;
    v->ln[at].len = len;
    v->n++;
    v->bytes += (size_t)len + 1;
    return 0;
}

static void del_line(vi_t *v, int at)
{
    v->bytes -= (size_t)v->ln[at].len + 1;
    free(v->ln[at].t);
    memmove(&v->ln[at], &v->ln[at + 1], sizeof *v->ln * (size_t)(v->n - at - 1));
    v->n--;
    if (v->n == 0)
        ins_line(v, 0, "", 0);
}

static void free_lines(vi_t *v)
{
    for (int i = 0; i < v->n; i++)
        free(v->ln[i].t);
    v->n = 0;
    v->bytes = 0;
}

/* Replace bytes [a, b) of line y with ins. */
static int splice(vi_t *v, int y, int a, int b, const char *ins, int ilen)
{
    line_t *l = &v->ln[y];
    int nlen = l->len - (b - a) + ilen;
    if (nlen > l->len && v->bytes + (size_t)(nlen - l->len) > C3_VI_MAX) {
        snprintf(v->msg, sizeof v->msg, "File too large (vi holds at most %d KB)", C3_VI_MAX / 1024);
        return -1;
    }
    char *t = realloc(l->t, (size_t)nlen + 1);
    if (!t)
        return -1;
    memmove(t + a + ilen, t + b, (size_t)(l->len - b) + 1);
    memcpy(t + a, ins, (size_t)ilen);
    v->bytes += (size_t)(nlen - l->len);
    l->t = t;
    l->len = nlen;
    v->dirty = true;
    return 0;
}

static char *join_all(vi_t *v, size_t *len)
{
    size_t total = 0;
    for (int i = 0; i < v->n; i++)
        total += (size_t)v->ln[i].len + 1;
    char *b = malloc(total + 1), *p = b;
    if (!b)
        return NULL;
    for (int i = 0; i < v->n; i++) {
        memcpy(p, v->ln[i].t, (size_t)v->ln[i].len);
        p += v->ln[i].len;
        *p++ = '\n';
    }
    *len = total;
    return b;
}

static void load_text(vi_t *v, const char *data, size_t len)
{
    free_lines(v);
    size_t i = 0;
    while (i < len) {
        const char *nl = memchr(data + i, '\n', len - i);
        size_t e = nl ? (size_t)(nl - data) : len;
        ins_line(v, v->n, data + i, (int)(e - i));
        i = e + 1;
    }
    if (v->n == 0)
        ins_line(v, 0, "", 0);
}

static void snapshot(vi_t *v)
{
    free(v->undo);
    v->undo = join_all(v, &v->undolen);
    v->ucy = v->cy;
    v->ucx = v->cx;
    v->undo_dirty = v->dirty;
}

static void undo(vi_t *v)
{
    if (!v->undo) {
        snprintf(v->msg, sizeof v->msg, "Already at oldest change");
        return;
    }
    size_t curlen;
    char *cur = join_all(v, &curlen);
    if (!cur)
        return;
    int cy = v->cy, cx = v->cx;
    bool d = v->dirty;
    load_text(v, v->undo, v->undolen);
    v->cy = v->ucy < v->n ? v->ucy : v->n - 1;
    v->cx = v->ucx;
    v->dirty = v->undo_dirty;
    free(v->undo);
    v->undo = cur;          /* so u again redoes, like classic vi */
    v->undolen = curlen;
    v->ucy = cy;
    v->ucx = cx;
    v->undo_dirty = d;
}

/* ---------------- display geometry ---------------- */

static int width_at(const char *t, int i, int col)
{
    unsigned char c = (unsigned char)t[i];
    if (c == '\t')
        return 8 - col % 8;
    if (cont((char)c))
        return 0;
    if (c < 0x20 || c == 0x7F)
        return 2;
    return 1;
}

static int dcol(const line_t *l, int idx)
{
    int col = 0;
    for (int i = 0; i < idx && i < l->len; i++)
        col += width_at(l->t, i, col);
    return col;
}

static int idx_for_col(const line_t *l, int want, bool insert)
{
    int col = 0, i = 0;
    int last = insert ? l->len : (l->len > 0 ? l->len - 1 : 0);
    while (i < last) {
        int w = width_at(l->t, i, col);
        if (col + w > want)
            break;
        col += w;
        i++;
        while (i < l->len && cont(l->t[i]))
            i++;
    }
    while (i > 0 && i < l->len && cont(l->t[i]))
        i--;
    return i > last ? last : i;
}

static void clamp(vi_t *v)
{
    if (v->cy >= v->n)
        v->cy = v->n - 1;
    if (v->cy < 0)
        v->cy = 0;
    line_t *l = &v->ln[v->cy];
    int max = v->insert ? l->len : (l->len > 0 ? l->len - 1 : 0);
    if (v->cx > max)
        v->cx = max;
    if (v->cx < 0)
        v->cx = 0;
    while (v->cx > 0 && cont(l->t[v->cx]))
        v->cx--;
}

static int text_rows(vi_t *v)
{
    return v->s->rows > 2 ? v->s->rows - 1 : 1;
}

/* ---------------- drawing ---------------- */

typedef struct {
    session_t *s;
    char b[1024];
    int n;
} out_t;

static void put(out_t *o, const char *p, int n)
{
    while (n > 0) {
        int k = (int)sizeof o->b - o->n;
        if (k > n)
            k = n;
        memcpy(o->b + o->n, p, (size_t)k);
        o->n += k;
        p += k;
        n -= k;
        if (o->n == (int)sizeof o->b) {
            tn_write(o->s, o->b, (size_t)o->n);
            o->n = 0;
        }
    }
}

static void puts_(out_t *o, const char *p) { put(o, p, (int)strlen(p)); }

static void draw_line(out_t *o, const line_t *l, int left, int cols)
{
    int col = 0;
    bool vis = false;
    for (int i = 0; i < l->len; i++) {
        unsigned char c = (unsigned char)l->t[i];
        int w = width_at(l->t, i, col);
        if (cont((char)c)) {
            if (vis)
                put(o, (const char *)&c, 1);
            continue;
        }
        vis = col >= left && col + w <= left + cols;
        if (col >= left + cols)
            break;
        if (vis) {
            if (c == '\t') {
                put(o, "        ", w);
            } else if (c < 0x20 || c == 0x7F) {
                char ctl[2] = { '^', (char)(c ^ 0x40) };
                put(o, ctl, 2);
            } else {
                put(o, (const char *)&c, 1);
            }
        }
        col += w;
    }
}

static void render(vi_t *v)
{
    session_t *s = v->s;
    int rows = text_rows(v), cols = s->cols > 0 ? s->cols : 80;
    out_t o = { .s = s };
    line_t *cur = &v->ln[v->cy];
    int cc = dcol(cur, v->cx);

    if (v->cy < v->top)
        v->top = v->cy;
    if (v->cy >= v->top + rows)
        v->top = v->cy - rows + 1;
    if (cc < v->left)
        v->left = cc;
    if (cc >= v->left + cols)
        v->left = cc - cols + 1;

    puts_(&o, "\x1b[?25l\x1b[H");
    for (int r = 0; r < rows; r++) {
        int y = v->top + r;
        if (y < v->n)
            draw_line(&o, &v->ln[y], v->left, cols);
        else
            puts_(&o, "~");
        puts_(&o, "\x1b[K\r\n");
    }
    /* status line */
    char st[200], pos[32];
    snprintf(pos, sizeof pos, "%d,%d", v->cy + 1, cc + 1);
    if (v->msg[0])
        snprintf(st, sizeof st, "%s", v->msg);
    else if (v->insert)
        snprintf(st, sizeof st, "-- INSERT --");
    else
        snprintf(st, sizeof st, "%s%s", v->vpath[0] ? v->vpath : "[No Name]", v->dirty ? " [+]" : "");
    int sl = (int)strlen(st), pl = (int)strlen(pos);
    if (sl > cols - pl - 2)
        sl = cols - pl - 2 > 0 ? cols - pl - 2 : 0;
    put(&o, st, sl);
    for (int i = sl; i < cols - pl - 1; i++)
        put(&o, " ", 1);
    puts_(&o, pos);
    puts_(&o, "\x1b[K");

    char go[48];
    snprintf(go, sizeof go, "\x1b[%d;%dH\x1b[?25h", v->cy - v->top + 1, cc - v->left + 1);
    puts_(&o, go);
    if (o.n)
        tn_write(s, o.b, (size_t)o.n);
}

/* ---------------- input ---------------- */

static int raw_key(vi_t *v, int timeout_ms)
{
    if (v->nback)
        return v->back[--v->nback];
    return tn_getc(v->s, timeout_ms);
}

static void unget(vi_t *v, int c)
{
    if (v->nback < 4)
        v->back[v->nback++] = c;
}

/* Next key, with arrow keys etc. decoded. Returns TN_CLOSED when the session ends. */
static int key(vi_t *v)
{
    int c;
    for (;;) {
        c = raw_key(v, 500);
        if (c != TN_TIMEOUT)
            break;
        if (v->s->winch) {          /* terminal resized while idle */
            v->s->winch = false;
            render(v);
        }
    }
    if (c != 0x1B)
        return c;
    int c2 = raw_key(v, 40);
    if (c2 < 0)
        return 0x1B;
    if (c2 != '[' && c2 != 'O') {
        unget(v, c2);
        return 0x1B;
    }
    int c3 = raw_key(v, 40);
    if (c3 < 0) {
        unget(v, c2);
        return 0x1B;
    }
    switch (c3) {
    case 'A': return K_UP;
    case 'B': return K_DOWN;
    case 'C': return K_RIGHT;
    case 'D': return K_LEFT;
    case 'H': return K_HOME;
    case 'F': return K_END;
    }
    if (c2 == '[' && c3 >= '0' && c3 <= '9') {       /* ESC [ n ~ */
        int c4 = raw_key(v, 40);
        while (c4 >= '0' && c4 <= ';')
            c4 = raw_key(v, 40);
        switch (c3) {
        case '1': case '7': return K_HOME;
        case '4': case '8': return K_END;
        case '3': return K_DEL;
        case '5': return K_PGUP;
        case '6': return K_PGDN;
        }
        return -10;                                  /* unknown sequence: ignore */
    }
    if (c2 == 'O') {               /* "Esc O" followed by something else: the O command */
        unget(v, c3);
        unget(v, 'O');
        return 0x1B;
    }
    return -10;
}

/* Read a line on the status line (after ':' or '/'). false if cancelled. */
static bool prompt_line(vi_t *v, char lead, char *buf, size_t cap)
{
    int len = 0;
    buf[0] = 0;
    for (;;) {
        char line[200];
        snprintf(line, sizeof line, "\x1b[%d;1H%c%s\x1b[K", v->s->rows > 0 ? v->s->rows : 24, lead, buf);
        tn_write(v->s, line, strlen(line));
        int c = key(v);
        if (c == TN_CLOSED) {
            v->quit = true;
            return false;
        }
        if (c == '\r' || c == '\n')
            return true;
        if (c == 0x1B || c == 3)
            return false;
        if (c == 0x7F || c == 8) {
            if (len == 0)
                return false;
            buf[--len] = 0;
            continue;
        }
        if (c >= 0x20 && c < 0x100 && len < (int)cap - 1) {
            buf[len++] = (char)c;
            buf[len] = 0;
        }
    }
}

/* ---------------- motions ---------------- */

static void left(vi_t *v)
{
    if (v->cx > 0) {
        v->cx--;
        while (v->cx > 0 && cont(v->ln[v->cy].t[v->cx]))
            v->cx--;
    }
    v->want = dcol(&v->ln[v->cy], v->cx);
}

static void right(vi_t *v)
{
    line_t *l = &v->ln[v->cy];
    int max = v->insert ? l->len : l->len - 1;
    int nx = v->cx + 1;
    while (nx < l->len && cont(l->t[nx]))
        nx++;
    if (nx <= max)
        v->cx = nx;
    v->want = dcol(l, v->cx);
}

static void vert(vi_t *v, int dy)
{
    v->cy += dy;
    if (v->cy < 0)
        v->cy = 0;
    if (v->cy >= v->n)
        v->cy = v->n - 1;
    v->cx = idx_for_col(&v->ln[v->cy], v->want, v->insert);
}

static int cls(char c)
{
    if (c == ' ' || c == '\t')
        return 0;
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || (c & 0x80))
        return 1;
    return 2;
}

static void word_fwd(vi_t *v)
{
    line_t *l = &v->ln[v->cy];
    int x = v->cx;
    if (x < l->len) {
        int k = cls(l->t[x]);
        while (x < l->len && cls(l->t[x]) == k && k != 0)
            x++;
    }
    while (x < l->len && cls(l->t[x]) == 0)
        x++;
    if (x >= l->len && v->cy + 1 < v->n) {
        v->cy++;
        l = &v->ln[v->cy];
        x = 0;
        while (x < l->len && cls(l->t[x]) == 0)
            x++;
    }
    v->cx = x;
    clamp(v);
    v->want = dcol(&v->ln[v->cy], v->cx);
}

static void word_back(vi_t *v)
{
    int x = v->cx;
    if (x == 0 && v->cy > 0) {
        v->cy--;
        x = v->ln[v->cy].len;
    }
    line_t *l = &v->ln[v->cy];
    while (x > 0 && cls(l->t[x - 1]) == 0)
        x--;
    if (x > 0) {
        int k = cls(l->t[x - 1]);
        while (x > 0 && cls(l->t[x - 1]) == k)
            x--;
    }
    v->cx = x;
    clamp(v);
    v->want = dcol(l, v->cx);
}

static void first_nonblank(vi_t *v)
{
    line_t *l = &v->ln[v->cy];
    v->cx = 0;
    while (v->cx < l->len && (l->t[v->cx] == ' ' || l->t[v->cx] == '\t'))
        v->cx++;
    clamp(v);
    v->want = dcol(l, v->cx);
}

static void find(vi_t *v, bool fwd)
{
    if (!v->search[0]) {
        snprintf(v->msg, sizeof v->msg, "No previous search");
        return;
    }
    int y = v->cy, x = v->cx;
    for (int step = 0; step <= v->n; step++) {
        line_t *l = &v->ln[y];
        const char *hit = NULL;
        if (fwd) {
            int from = step == 0 ? x + 1 : 0;
            if (from <= l->len)
                hit = strstr(l->t + from, v->search);
        } else {
            int limit = step == 0 ? x : l->len + 1;
            for (const char *p = strstr(l->t, v->search); p && p - l->t < limit; p = strstr(p + 1, v->search))
                hit = p;
        }
        if (hit) {
            if ((fwd && (y < v->cy || (y == v->cy && hit - l->t <= x))) ||
                (!fwd && (y > v->cy || (y == v->cy && hit - l->t >= x))))
                snprintf(v->msg, sizeof v->msg, fwd ? "search hit BOTTOM, continuing at TOP"
                                                    : "search hit TOP, continuing at BOTTOM");
            v->cy = y;
            v->cx = (int)(hit - l->t);
            clamp(v);
            v->want = dcol(&v->ln[v->cy], v->cx);
            return;
        }
        y = fwd ? (y + 1) % v->n : (y + v->n - 1) % v->n;
    }
    snprintf(v->msg, sizeof v->msg, "Pattern not found: %s", v->search);
}

/* ---------------- files ---------------- */

static int open_file(vi_t *v, const char *vpath)
{
    char host[C3_HOST_MAX], *data = NULL;
    size_t len = 0;
    snprintf(v->vpath, sizeof v->vpath, "%s", vpath);
    if (fs_host(vpath, host, sizeof host) != 0) {
        tn_printf(v->s, "vi: %s: %s\n", vpath, strerror(ENAMETOOLONG));
        return -1;
    }
    int r = fs_read_file(host, &data, &len, C3_VI_MAX);
    if (r == -ENOENT) {
        load_text(v, "", 0);
        snprintf(v->msg, sizeof v->msg, "\"%s\" [New File]", vpath);
        return 0;
    }
    if (r == -EFBIG) {
        tn_printf(v->s, "vi: %s: too large for vi (at most %d KB)\n", vpath, C3_VI_MAX / 1024);
        return -1;
    }
    if (r < 0) {
        tn_printf(v->s, "vi: %s: %s\n", vpath, strerror(-r));
        return -1;
    }
    load_text(v, data, len);
    free(data);
    snprintf(v->msg, sizeof v->msg, "\"%s\" %dL, %luB", vpath, v->n, (unsigned long)len);
    return 0;
}

static bool write_file(vi_t *v, const char *as)
{
    char vp[C3_PATH_MAX], host[C3_HOST_MAX];
    if (as && *as) {
        if (fs_resolve(v->s, as, vp, sizeof vp) != 0) {
            snprintf(v->msg, sizeof v->msg, "E212: Can't open file for writing");
            return false;
        }
    } else if (v->vpath[0]) {
        snprintf(vp, sizeof vp, "%s", v->vpath);
    } else {
        snprintf(v->msg, sizeof v->msg, "E32: No file name");
        return false;
    }
    if (fs_host(vp, host, sizeof host) != 0) {
        snprintf(v->msg, sizeof v->msg, "E212: Can't open file for writing (name too long)");
        return false;
    }
    struct stat st;
    if (stat(host, &st) == 0 && S_ISDIR(st.st_mode)) {
        snprintf(v->msg, sizeof v->msg, "\"%.80s\" is a directory", vp);
        return false;
    }
    size_t len;
    char *data = join_all(v, &len);
    if (!data) {
        snprintf(v->msg, sizeof v->msg, "E342: Out of memory");
        return false;
    }
    int r = fs_write_file(host, data, len);
    free(data);
    if (r < 0) {
        snprintf(v->msg, sizeof v->msg, "\"%s\" E514: write error: %s", vp, strerror(-r));
        return false;
    }
    snprintf(v->msg, sizeof v->msg, "\"%s\" %dL, %luB written", vp, v->n, (unsigned long)len);
    if (!v->vpath[0])
        snprintf(v->vpath, sizeof v->vpath, "%s", vp);
    if (strcmp(vp, v->vpath) == 0)
        v->dirty = false;
    return true;
}

static void ex(vi_t *v, char *cmd)
{
    while (*cmd == ' ')
        cmd++;
    char *arg = strchr(cmd, ' ');
    if (arg) {
        *arg++ = 0;
        while (*arg == ' ')
            arg++;
    }
    if (*cmd >= '0' && *cmd <= '9') {
        v->cy = atoi(cmd) - 1;
        clamp(v);
        first_nonblank(v);
    } else if (strcmp(cmd, "w") == 0) {
        write_file(v, arg);
    } else if (strcmp(cmd, "wq") == 0 || (strcmp(cmd, "x") == 0 && v->dirty)) {
        if (write_file(v, arg))
            v->quit = true;
    } else if (strcmp(cmd, "x") == 0) {
        v->quit = true;
    } else if (strcmp(cmd, "q") == 0) {
        if (v->dirty)
            snprintf(v->msg, sizeof v->msg, "E37: No write since last change (add ! to override)");
        else
            v->quit = true;
    } else if (strcmp(cmd, "q!") == 0) {
        v->quit = true;
    } else if (*cmd) {
        snprintf(v->msg, sizeof v->msg, "E492: Not an editor command: %.80s", cmd);
    }
}

/* ---------------- editing ---------------- */

static void yank_lines(vi_t *v, int from, int count)
{
    size_t total = 0;
    for (int i = 0; i < count; i++)
        total += (size_t)v->ln[from + i].len + 1;
    char *b = malloc(total + 1), *p = b;
    if (!b)
        return;
    for (int i = 0; i < count; i++) {
        memcpy(p, v->ln[from + i].t, (size_t)v->ln[from + i].len);
        p += v->ln[from + i].len;
        *p++ = '\n';
    }
    free(v->yank);
    v->yank = b;
    v->yanklen = total;
}

static void put_lines(vi_t *v, bool below)
{
    if (!v->yank)
        return;
    if (v->bytes + v->yanklen > C3_VI_MAX) {
        snprintf(v->msg, sizeof v->msg, "File too large (vi holds at most %d KB)", C3_VI_MAX / 1024);
        return;
    }
    int at = below ? v->cy + 1 : v->cy, y = at;
    size_t i = 0;
    while (i < v->yanklen) {
        const char *nl = memchr(v->yank + i, '\n', v->yanklen - i);
        size_t e = nl ? (size_t)(nl - v->yank) : v->yanklen;
        ins_line(v, y++, v->yank + i, (int)(e - i));
        i = e + 1;
    }
    v->dirty = true;
    v->cy = at;
    first_nonblank(v);
}

static void insert_bytes(vi_t *v, const char *b, int n)
{
    if (splice(v, v->cy, v->cx, v->cx, b, n) == 0)
        v->cx += n;
}

static void newline(vi_t *v)
{
    line_t *l = &v->ln[v->cy];
    if (v->bytes + 1 > C3_VI_MAX) {
        snprintf(v->msg, sizeof v->msg, "File too large (vi holds at most %d KB)", C3_VI_MAX / 1024);
        return;
    }
    if (ins_line(v, v->cy + 1, l->t + v->cx, l->len - v->cx) != 0)
        return;
    l = &v->ln[v->cy];
    v->bytes -= (size_t)(l->len - v->cx);
    l->len = v->cx;
    l->t[l->len] = 0;
    v->cy++;
    v->cx = 0;
    v->dirty = true;
}

static void join_next(vi_t *v)
{
    if (v->cy + 1 >= v->n)
        return;
    line_t *a = &v->ln[v->cy];
    line_t *b = &v->ln[v->cy + 1];
    int pos = a->len, skip = 0;
    while (skip < b->len && (b->t[skip] == ' ' || b->t[skip] == '\t'))
        skip++;
    bool space = a->len > 0 && skip < b->len;
    char *nt = realloc(a->t, (size_t)a->len + (space ? 1 : 0) + (size_t)(b->len - skip) + 1);
    if (!nt)
        return;
    a->t = nt;
    if (space)
        a->t[a->len++] = ' ';
    memcpy(a->t + a->len, b->t + skip, (size_t)(b->len - skip) + 1);
    a->len += b->len - skip;
    v->bytes -= (size_t)(1 + skip) - (space ? 1 : 0);   /* the newline becomes the space, or goes */
    free(b->t);
    memmove(&v->ln[v->cy + 1], &v->ln[v->cy + 2], sizeof *v->ln * (size_t)(v->n - v->cy - 2));
    v->n--;
    v->cx = pos;
    v->dirty = true;
}

static void backspace(vi_t *v)
{
    if (v->cx > 0) {
        int a = v->cx - 1;
        while (a > 0 && cont(v->ln[v->cy].t[a]))
            a--;
        splice(v, v->cy, a, v->cx, "", 0);
        v->cx = a;
    } else if (v->cy > 0) {
        v->cy--;
        v->cx = v->ln[v->cy].len;
        int keep = v->cx;
        line_t *a = &v->ln[v->cy], *b = &v->ln[v->cy + 1];
        char *nt = realloc(a->t, (size_t)(a->len + b->len) + 1);
        if (!nt)
            return;
        a->t = nt;
        memcpy(a->t + a->len, b->t, (size_t)b->len + 1);
        a->len += b->len;
        v->bytes -= 1;
        free(b->t);
        memmove(&v->ln[v->cy + 1], &v->ln[v->cy + 2], sizeof *v->ln * (size_t)(v->n - v->cy - 2));
        v->n--;
        v->cx = keep;
        v->dirty = true;
    }
}

static void insert_mode(vi_t *v)
{
    v->insert = true;
    v->msg[0] = 0;
    for (;;) {
        clamp(v);
        if (!tn_input_ready(v->s))      /* skip redraws while a paste is streaming in */
            render(v);
        int c = key(v);
        if (c == TN_CLOSED) {
            v->quit = true;
            break;
        }
        v->msg[0] = 0;
        if (c == 0x1B || c == 3) {
            break;
        } else if (c == '\r' || c == '\n') {
            newline(v);
        } else if (c == 0x7F || c == 8) {
            backspace(v);
        } else if (c == K_DEL) {
            line_t *l = &v->ln[v->cy];
            if (v->cx < l->len) {
                int b = v->cx + 1;
                while (b < l->len && cont(l->t[b]))
                    b++;
                splice(v, v->cy, v->cx, b, "", 0);
            }
        } else if (c == K_LEFT) {
            left(v);
        } else if (c == K_RIGHT) {
            right(v);
        } else if (c == K_UP) {
            vert(v, -1);
        } else if (c == K_DOWN) {
            vert(v, 1);
        } else if (c == K_HOME) {
            v->cx = 0;
        } else if (c == K_END) {
            v->cx = v->ln[v->cy].len;
        } else if (c == '\t' || (c >= 0x20 && c < 0x100 && c != 0x7F)) {
            char ch = (char)c;
            insert_bytes(v, &ch, 1);
        }
        v->want = dcol(&v->ln[v->cy], v->cx);
    }
    v->insert = false;
    if (v->cx > 0)
        left(v);              /* vi steps back onto the last inserted character */
    clamp(v);
}

static void normal(vi_t *v)
{
    int count = 0;
    for (;;) {
        clamp(v);
        if (!tn_input_ready(v->s))
            render(v);
        if (v->quit)
            return;
        int c = key(v);
        if (c == TN_CLOSED) {
            v->quit = true;
            return;
        }
        if (c != 0x1B)
            v->msg[0] = 0;
        if ((c >= '1' && c <= '9') || (c == '0' && count > 0)) {
            count = count * 10 + (c - '0');
            if (count > 100000)
                count = 100000;
            continue;
        }
        int n = count ? count : 1;
        bool had = count > 0;
        count = 0;
        line_t *l = &v->ln[v->cy];

        switch (c) {
        case 'h': case K_LEFT: case 0x7F: case 8:
            while (n--)
                left(v);
            break;
        case 'l': case K_RIGHT: case ' ':
            while (n--)
                right(v);
            break;
        case 'j': case K_DOWN:
            vert(v, n);
            break;
        case 'k': case K_UP:
            vert(v, -n);
            break;
        case '\r': case '+':
            vert(v, n);
            first_nonblank(v);
            break;
        case '-':
            vert(v, -n);
            first_nonblank(v);
            break;
        case '0': case K_HOME:
            v->cx = 0;
            v->want = 0;
            break;
        case '^':
            first_nonblank(v);
            break;
        case '$': case K_END:
            v->cx = l->len;
            clamp(v);
            v->want = 1 << 30;
            break;
        case 'w':
            while (n--)
                word_fwd(v);
            break;
        case 'b':
            while (n--)
                word_back(v);
            break;
        case 'G':
            v->cy = had ? n - 1 : v->n - 1;
            clamp(v);
            first_nonblank(v);
            break;
        case 'g':
            if (key(v) == 'g') {
                v->cy = had ? n - 1 : 0;
                clamp(v);
                first_nonblank(v);
            }
            break;
        case 6: case K_PGDN:              /* Ctrl-F */
            vert(v, n * (text_rows(v) - 2 > 1 ? text_rows(v) - 2 : 1));
            v->top = v->cy;
            break;
        case 2: case K_PGUP:              /* Ctrl-B */
            vert(v, -n * (text_rows(v) - 2 > 1 ? text_rows(v) - 2 : 1));
            break;
        case 12:                          /* Ctrl-L */
            tn_write(v->s, "\x1b[2J", 4);
            break;
        case 7:                           /* Ctrl-G */
            snprintf(v->msg, sizeof v->msg, "\"%s\"%s %d lines --%d%%--", v->vpath[0] ? v->vpath : "[No Name]",
                     v->dirty ? " [Modified]" : "", v->n, (v->cy + 1) * 100 / v->n);
            break;

        case 'i':
            snapshot(v);
            insert_mode(v);
            break;
        case 'a':
            snapshot(v);
            v->insert = true;       /* lets the cursor step past the last character */
            right(v);
            insert_mode(v);
            break;
        case 'I':
            snapshot(v);
            first_nonblank(v);
            insert_mode(v);
            break;
        case 'A':
            snapshot(v);
            v->insert = true;
            v->cx = l->len;
            insert_mode(v);
            break;
        case 'o': case 'O':
            snapshot(v);
            if (v->bytes + 1 > C3_VI_MAX) {
                snprintf(v->msg, sizeof v->msg, "File too large (vi holds at most %d KB)", C3_VI_MAX / 1024);
                break;
            }
            if (c == 'o')
                v->cy++;
            ins_line(v, v->cy, "", 0);
            v->cx = 0;
            v->dirty = true;
            insert_mode(v);
            break;
        case 'x': case K_DEL:
            if (l->len == 0)
                break;
            snapshot(v);
            while (n-- && v->ln[v->cy].len > 0) {
                l = &v->ln[v->cy];
                int b = v->cx + 1;
                while (b < l->len && cont(l->t[b]))
                    b++;
                splice(v, v->cy, v->cx, b, "", 0);
                clamp(v);
            }
            break;
        case 'r': {
            int r = key(v);
            if (r < 0x20 || r >= 0x100 || l->len == 0)
                break;
            snapshot(v);
            char ch = (char)r;
            int b = v->cx + 1;
            while (b < l->len && cont(l->t[b]))
                b++;
            splice(v, v->cy, v->cx, b, &ch, 1);
            break;
        }
        case 'J':
            snapshot(v);
            while (n-- && v->cy + 1 < v->n)
                join_next(v);
            break;
        case 'D':
            snapshot(v);
            splice(v, v->cy, v->cx, l->len, "", 0);
            break;
        case 'd': {
            int m = key(v);
            snapshot(v);
            if (m == 'd') {
                if (n > v->n - v->cy)
                    n = v->n - v->cy;
                yank_lines(v, v->cy, n);
                while (n--)
                    del_line(v, v->cy);
                v->dirty = true;
                first_nonblank(v);
            } else if (m == '$') {
                splice(v, v->cy, v->cx, l->len, "", 0);
            } else if (m == 'w') {
                int x0 = v->cx, y0 = v->cy;
                while (n--)
                    word_fwd(v);
                int end = v->cy == y0 ? v->cx : v->ln[y0].len;
                if (v->cy == y0 && v->cx == x0)
                    end = v->ln[y0].len;
                v->cy = y0;
                splice(v, y0, x0, end, "", 0);
                v->cx = x0;
            }
            break;
        }
        case 'y':
            if (key(v) == 'y') {
                if (n > v->n - v->cy)
                    n = v->n - v->cy;
                yank_lines(v, v->cy, n);
                snprintf(v->msg, sizeof v->msg, "%d line%s yanked", n, n == 1 ? "" : "s");
            }
            break;
        case 'Y':
            yank_lines(v, v->cy, 1);
            break;
        case 'p': case 'P':
            snapshot(v);
            while (n--)
                put_lines(v, c == 'p');
            break;
        case 'u':
            undo(v);
            break;

        case '/':
            if (prompt_line(v, '/', v->search, sizeof v->search))
                find(v, true);
            break;
        case 'n':
            find(v, true);
            break;
        case 'N':
            find(v, false);
            break;
        case ':': {
            char cmd[96];
            if (prompt_line(v, ':', cmd, sizeof cmd))
                ex(v, cmd);
            break;
        }
        case 'Z':
            if (key(v) == 'Z') {
                if (!v->dirty || write_file(v, NULL))
                    v->quit = true;
            }
            break;
        case 0x1B:
            break;
        }
    }
}

int cmd_vi(session_t *s, int argc, char **argv)
{
    vi_t *v = calloc(1, sizeof *v);
    char vp[C3_PATH_MAX];
    if (!v) {
        tn_puts(s, "vi: out of memory\n");
        return 1;
    }
    v->s = s;
    if (argc > 2) {
        tn_puts(s, "usage: vi [file]\n");
        free(v);
        return 2;
    }
    if (argc == 2) {
        int r = fs_resolve(s, argv[1], vp, sizeof vp);
        char host[C3_HOST_MAX];
        struct stat st;
        if (r < 0) {
            tn_printf(s, "vi: %s: %s\n", argv[1], strerror(-r));
            free(v);
            return 1;
        }
        if (fs_host(vp, host, sizeof host) != 0) {
            tn_printf(s, "vi: %s: %s\n", argv[1], strerror(ENAMETOOLONG));
            free(v);
            return 1;
        }
        if (stat(host, &st) == 0 && S_ISDIR(st.st_mode)) {
            tn_printf(s, "vi: %s: Is a directory\n", argv[1]);
            free(v);
            return 1;
        }
        if (open_file(v, vp) != 0) {
            free(v);
            return 1;
        }
    } else {
        load_text(v, "", 0);
    }

    tn_write(s, "\x1b[?1049h\x1b[2J", 12);     /* alternate screen, like a full-screen program */
    s->winch = false;
    normal(v);
    if (!s->closed)
        tn_write(s, "\x1b[?1049l", 8);

    free_lines(v);
    free(v->ln);
    free(v->undo);
    free(v->yank);
    free(v);
    return 0;
}
