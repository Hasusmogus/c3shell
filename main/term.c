/* Terminal layer: the shell's view of the user's SSH channel (or of the local
 * console), plus a small line editor with history. The user's SSH client puts
 * their terminal in raw mode, so echoing and line editing happen here. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include "c3shell.h"

/* The console is a plain non-blocking fd. It never "closes": with nobody
 * attached, reads find nothing and writes are dropped. */
static int console_read(session_t *s)
{
    ssize_t n = read(s->io.fd, s->ibuf, sizeof s->ibuf);
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
        port_sleep_ms(100);             /* e.g. USB unplugged: don't spin */
    return n > 0 ? (int)n : 0;
}

static void console_write(session_t *s, const uint8_t *p, size_t len)
{
    int stalls = 0;
    while (len > 0) {
        ssize_t n = write(s->io.fd, p, len);
        if (n > 0) {
            p += n;
            len -= (size_t)n;
            stalls = 0;
        } else if (++stalls > 20) {
            return;                     /* nobody is reading: drop it */
        } else {
            port_sleep_ms(5);
        }
    }
}

/* Fetch whatever the user has sent. >0 = bytes now in ibuf, 0 = nothing yet,
 * TN_CLOSED = the connection is gone. */
static int poll_input(session_t *s)
{
    if (s->kick)
        s->closed = true;
    if (s->closed)
        return TN_CLOSED;
    if (s->console) {
        s->ipos = 0;
        s->ilen = (uint16_t)console_read(s);
        return s->ilen;
    }
    s->io.nonblock = true;
    int n = sshio_read(s->ssh, s->ibuf, sizeof s->ibuf);
    if (n < 0) {
        s->closed = true;
        return TN_CLOSED;
    }
    s->ipos = 0;
    s->ilen = (uint16_t)n;
    return n;
}

static void wait_readable(session_t *s, int ms)
{
    fd_set rd;
    struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
    FD_ZERO(&rd);
    FD_SET(s->io.fd, &rd);
    select(s->io.fd + 1, &rd, NULL, NULL, &tv);
}

int tn_getc(session_t *s, int timeout_ms)
{
    int waited = 0;
    while (s->ipos >= s->ilen) {
        int r = poll_input(s);
        if (r == TN_CLOSED)
            return TN_CLOSED;
        if (r > 0)
            break;
        int step = timeout_ms - waited > 500 ? 500 : timeout_ms - waited;
        if (step <= 0)
            return TN_TIMEOUT;
        wait_readable(s, step);
        waited += step;
    }
    return s->ibuf[s->ipos++];
}

bool tn_input_ready(session_t *s)
{
    return s->ipos < s->ilen || poll_input(s) > 0;
}

int tn_read_avail(session_t *s, uint8_t *buf, int cap)
{
    if (s->ipos >= s->ilen && poll_input(s) == TN_CLOSED)
        return TN_CLOSED;
    int n = s->ilen - s->ipos;
    if (n > cap)
        n = cap;
    memcpy(buf, s->ibuf + s->ipos, (size_t)n);
    s->ipos = (uint16_t)(s->ipos + n);
    return n;
}

int tn_write(session_t *s, const void *data, size_t len)
{
    if (s->kick)
        s->closed = true;
    if (s->closed)
        return -1;
    if (s->console) {
        console_write(s, data, len);
        return 0;
    }
    s->io.nonblock = true;
    if (sshio_write(s->ssh, &s->io, data, (int)len) < 0) {
        s->closed = true;
        return -1;
    }
    return 0;
}

void tn_puts(session_t *s, const char *str)
{
    uint8_t out[256];
    size_t o = 0;
    char prev = 0;
    for (; *str; prev = *str++) {
        if (o > sizeof out - 3) {
            tn_write(s, out, o);
            o = 0;
        }
        if (*str == '\n' && prev != '\r')
            out[o++] = '\r';
        out[o++] = (uint8_t)*str;
    }
    if (o)
        tn_write(s, out, o);
}

void tn_printf(session_t *s, const char *fmt, ...)
{
    char buf[384];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    tn_puts(s, buf);
}

/* Number of display cells in a (possibly UTF-8) buffer. */
static int cells(const char *b, int len)
{
    int n = 0;
    for (int i = 0; i < len; i++)
        if (((uint8_t)b[i] & 0xC0) != 0x80)
            n++;
    return n;
}

/* ---------------- line editor ---------------- */

typedef struct {
    session_t  *s;
    const char *prompt;      /* the part of the prompt on the input's own line */
    char       *buf;
    int         len, cur, cap;
    int         crow;        /* screen row of the cursor, counted from the prompt's row */
    bool        echo;
} ed_t;

static int ed_cols(const ed_t *e) { return e->s->cols > 0 ? e->s->cols : 80; }

static int ed_plen(const ed_t *e) { return cells(e->prompt, (int)strlen(e->prompt)); }

/* Redraw prompt and line and put the cursor in place; copes with lines that
 * wrap onto several screen rows. */
static void ed_refresh(ed_t *e)
{
    char o[640];
    int n = 0, cols = ed_cols(e), plen = ed_plen(e);
    if (!e->echo)
        return;
    if (e->crow > 0)
        n += snprintf(o + n, sizeof o - (size_t)n, "\x1b[%dA", e->crow);
    o[n++] = '\r';
    n += snprintf(o + n, sizeof o - (size_t)n, "%.200s%.*s\x1b[J", e->prompt, e->len, e->buf);
    int end = plen + cells(e->buf, e->len), pos = plen + cells(e->buf, e->cur);
    if (end > 0 && end % cols == 0)
        n += snprintf(o + n, sizeof o - (size_t)n, "\r\n");   /* leave the "pending wrap" state */
    if (end / cols > pos / cols)
        n += snprintf(o + n, sizeof o - (size_t)n, "\x1b[%dA", end / cols - pos / cols);
    o[n++] = '\r';
    if (pos % cols)
        n += snprintf(o + n, sizeof o - (size_t)n, "\x1b[%dC", pos % cols);
    e->crow = pos / cols;
    tn_write(e->s, o, (size_t)n);
}

static void ed_insert(ed_t *e, const char *text, int tl)
{
    if (tl > e->cap - 1 - e->len)
        tl = e->cap - 1 - e->len;
    if (tl <= 0)
        return;
    bool at_end = e->cur == e->len;
    memmove(e->buf + e->cur + tl, e->buf + e->cur, (size_t)(e->len - e->cur));
    memcpy(e->buf + e->cur, text, (size_t)tl);
    e->len += tl;
    e->cur += tl;
    if (!e->echo)
        return;
    if (!at_end || tl > 1) {
        ed_refresh(e);
        return;
    }
    tn_write(e->s, text, 1);                       /* typing at the end: just echo */
    int pos = ed_plen(e) + cells(e->buf, e->cur), cols = ed_cols(e);
    if ((uint8_t)text[0] < 0x80 && pos % cols == 0)
        tn_puts(e->s, "\r\n");
    e->crow = pos / cols;
}

static void ed_delete(ed_t *e, int from, int to)   /* remove buf[from, to) */
{
    if (from < 0)
        from = 0;
    if (to > e->len)
        to = e->len;
    if (from >= to)
        return;
    memmove(e->buf + from, e->buf + to, (size_t)(e->len - to));
    e->len -= to - from;
    if (e->cur > to)
        e->cur -= to - from;
    else if (e->cur > from)
        e->cur = from;
    ed_refresh(e);
}

static void ed_replace(ed_t *e, int from, int to, const char *text, int tl)   /* buf[from, to) := text */
{
    if (tl > e->cap - 1 - (e->len - (to - from)))
        tl = e->cap - 1 - (e->len - (to - from));
    if (tl < 0)
        return;
    memmove(e->buf + from + tl, e->buf + to, (size_t)(e->len - to));
    memcpy(e->buf + from, text, (size_t)tl);
    e->len += tl - (to - from);
    e->cur = from + tl;
    ed_refresh(e);
}

static int prev_char(const ed_t *e, int i)
{
    if (i > 0)
        i--;
    while (i > 0 && ((uint8_t)e->buf[i] & 0xC0) == 0x80)
        i--;
    return i;
}

static int next_char(const ed_t *e, int i)
{
    if (i < e->len)
        i++;
    while (i < e->len && ((uint8_t)e->buf[i] & 0xC0) == 0x80)
        i++;
    return i;
}

static void ed_move(ed_t *e, int to)
{
    if (to == e->cur)
        return;
    e->cur = to;
    ed_refresh(e);
}

static void ed_set(ed_t *e, const char *text)
{
    e->len = (int)strlen(text);
    if (e->len > e->cap - 1)
        e->len = e->cap - 1;
    memcpy(e->buf, text, (size_t)e->len);
    e->cur = e->len;
    ed_refresh(e);
}

/* ---- Tab completion ---- */

static const char *display_name(const char *c)   /* "notes/a.txt" -> "a.txt", "notes/" stays "notes/" */
{
    size_t l = strlen(c);
    const char *p = c + l;
    if (l && c[l - 1] == '/')
        p--;
    while (p > c && p[-1] != '/')
        p--;
    return p;
}

static void ed_list(ed_t *e, const tn_cands_t *cd)
{
    int cols = ed_cols(e), w = 0;
    for (int i = 0; i < cd->n; i++) {
        int l = (int)strlen(display_name(cd->c[i]));
        if (l > w)
            w = l;
    }
    w += 2;
    int per = cols / w > 0 ? cols / w : 1, rows = (cd->n + per - 1) / per;
    e->cur = e->len;
    ed_refresh(e);                                 /* cursor to the end, then list below */
    tn_puts(e->s, "\n");
    for (int r = 0; r < rows; r++) {
        for (int k = 0; k < per; k++) {
            int i = k * rows + r;
            if (i < cd->n)
                tn_printf(e->s, "%-*s", k == per - 1 ? 0 : w, display_name(cd->c[i]));
        }
        tn_puts(e->s, "\n");
    }
    if (cd->more)
        tn_puts(e->s, "(more not shown)\n");
    e->crow = 0;
    ed_refresh(e);
}

static void ed_complete(ed_t *e, bool again)
{
    /* the word under completion: from after the last unquoted space up to the cursor */
    int start = 0;
    char q = 0;
    for (int i = 0; i < e->cur; i++) {
        char c = e->buf[i];
        if (q) {
            if (c == q)
                q = 0;
        } else if (c == '"' || c == '\'') {
            q = c;
        } else if (c == ' ') {
            start = i + 1;
        }
    }
    char word[C3_PATH_MAX], line[LINE_MAX_];
    int wl = 0;
    for (int i = start; i < e->cur && wl < (int)sizeof word - 1; i++)
        if (e->buf[i] != '"' && e->buf[i] != '\'')
            word[wl++] = e->buf[i];
    word[wl] = 0;
    snprintf(line, sizeof line, "%.*s", start, e->buf);

    tn_cands_t *cd = calloc(1, sizeof *cd);
    if (!cd)
        return;
    shell_complete(e->s, line, word, cd);
    for (int i = 1; i < cd->n; i++) {              /* sorted, for the listing */
        char t[C3_PATH_MAX];
        int j = i;
        memcpy(t, cd->c[i], sizeof t);
        for (; j > 0 && strcmp(t, cd->c[j - 1]) < 0; j--)
            memcpy(cd->c[j], cd->c[j - 1], sizeof t);
        memcpy(cd->c[j], t, sizeof t);
    }
    if (cd->n == 0) {
        tn_write(e->s, "\a", 1);
        free(cd);
        return;
    }
    size_t lcp = strlen(cd->c[0]);                 /* longest common prefix */
    for (int i = 1; i < cd->n; i++) {
        size_t k = 0;
        while (k < lcp && cd->c[i][k] == cd->c[0][k])
            k++;
        lcp = k;
    }
    bool unique = cd->n == 1 && !cd->more;
    if (lcp > (size_t)wl || unique) {
        char tok[C3_PATH_MAX + 8];
        int tl = 0;
        bool dir = unique && lcp && cd->c[0][lcp - 1] == '/';
        if (!q && memchr(cd->c[0], ' ', lcp))
            q = '"';                               /* a name with spaces needs quotes */
        if (q)
            tok[tl++] = q;
        memcpy(tok + tl, cd->c[0], lcp);
        tl += (int)lcp;
        if (unique && !dir) {
            if (q)
                tok[tl++] = q;
            tok[tl++] = ' ';
        }
        ed_replace(e, start, e->cur, tok, tl);    /* the typed word becomes the completed one */
        free(cd);
        return;
    }
    if (again)
        ed_list(e, cd);
    else
        tn_write(e->s, "\a", 1);
    free(cd);
}

int tn_readline(session_t *s, const char *prompt, char *buf, size_t cap, int flags, int timeout_s)
{
    ed_t ed = { .s = s, .buf = buf, .echo = (flags & RL_ECHO) != 0 };
    ed_t *e = &ed;
    int hpos = s->hist_n;            /* index into history; hist_n = the fresh line */
    char fresh[LINE_MAX_] = "";      /* what was typed before browsing the history */
    bool tabbed = false;

    if (cap > LINE_MAX_)
        cap = LINE_MAX_;
    e->cap = (int)cap;
    if (!prompt)
        prompt = "";
    tn_puts(s, prompt);
    e->prompt = strrchr(prompt, '\n') ? strrchr(prompt, '\n') + 1 : prompt;

    for (;;) {
        int c = tn_getc(s, timeout_s * 1000);
        if (c == TN_CLOSED || c == TN_TIMEOUT)
            return c;
        bool was_tab = tabbed;
        tabbed = false;

        if (c == 0x1B) {                            /* escape sequence -> a key */
            int c2 = tn_getc(s, 100), num = 0, fin;
            if (c2 != '[' && c2 != 'O')
                continue;
            while ((fin = tn_getc(s, 100)) >= '0' && fin <= '9')
                num = num * 10 + fin - '0';
            while (fin >= 0x20 && fin < 0x40)       /* ";modifier" */
                fin = tn_getc(s, 100);
            switch (fin) {
            case 'A': c = 0x10; break;              /* up = Ctrl-P */
            case 'B': c = 0x0E; break;              /* down = Ctrl-N */
            case 'C': c = 0x06; break;              /* right = Ctrl-F */
            case 'D': c = 0x02; break;              /* left = Ctrl-B */
            case 'H': c = 0x01; break;              /* Home = Ctrl-A */
            case 'F': c = 0x05; break;              /* End = Ctrl-E */
            case '~':
                c = num == 1 || num == 7 ? 0x01 : num == 4 || num == 8 ? 0x05 : num == 3 ? 0x7E7F : 0;
                break;
            default:
                c = 0;
            }
            if (!c)
                continue;
        }

        switch (c) {
        case '\r':
        case '\n':
            ed_move(e, e->len);
            tn_puts(s, "\n");
            buf[e->len] = 0;
            if ((flags & RL_HISTORY) && e->len > 0 &&
                (s->hist_n == 0 || strcmp(s->hist[s->hist_n - 1], buf) != 0)) {
                if (s->hist_n == HIST_N) {
                    memmove(s->hist[0], s->hist[1], sizeof s->hist[0] * (HIST_N - 1));
                    s->hist_n--;
                }
                snprintf(s->hist[s->hist_n++], LINE_MAX_, "%s", buf);
            }
            return e->len;
        case 0x03:                                  /* Ctrl-C */
            ed_move(e, e->len);
            tn_puts(s, "^C\n");
            buf[0] = 0;
            return TN_INTR;
        case 0x04:                                  /* Ctrl-D: end on an empty line, else delete */
            if (e->len == 0) {
                tn_puts(s, "\n");
                return TN_EOF;
            }
            ed_delete(e, e->cur, next_char(e, e->cur));
            break;
        case 0x7E7F:                                /* Delete key */
            ed_delete(e, e->cur, next_char(e, e->cur));
            break;
        case 0x7F:
        case 0x08:                                  /* backspace */
            ed_delete(e, prev_char(e, e->cur), e->cur);
            break;
        case 0x01: ed_move(e, 0); break;                        /* Ctrl-A */
        case 0x05: ed_move(e, e->len); break;                   /* Ctrl-E */
        case 0x02: ed_move(e, prev_char(e, e->cur)); break;     /* Ctrl-B */
        case 0x06: ed_move(e, next_char(e, e->cur)); break;     /* Ctrl-F */
        case 0x15: ed_delete(e, 0, e->cur); break;              /* Ctrl-U: kill to the start */
        case 0x0B: ed_delete(e, e->cur, e->len); break;         /* Ctrl-K: kill to the end */
        case 0x17: {                                            /* Ctrl-W: previous word */
            int i = e->cur;
            while (i > 0 && e->buf[i - 1] == ' ')
                i--;
            while (i > 0 && e->buf[i - 1] != ' ')
                i--;
            ed_delete(e, i, e->cur);
            break;
        }
        case 0x0C:                                  /* Ctrl-L: clear the screen, keep the line */
            tn_puts(s, "\x1b[H\x1b[2J");
            e->crow = 0;
            if (e->echo)
                ed_refresh(e);
            else
                tn_puts(s, e->prompt);
            break;
        case '\t':
            if ((flags & RL_COMPLETE) && e->echo) {
                ed_complete(e, was_tab);
                tabbed = true;
            }
            break;
        case 0x10:                                  /* history: up */
        case 0x0E:                                  /* history: down */
            if (flags & RL_HISTORY) {
                int np = hpos + (c == 0x10 ? -1 : 1);
                if (np < 0 || np > s->hist_n)
                    break;
                if (hpos == s->hist_n)
                    snprintf(fresh, sizeof fresh, "%.*s", e->len, buf);
                hpos = np;
                ed_set(e, hpos == s->hist_n ? fresh : s->hist[hpos]);
            }
            break;
        default:
            if (c >= 0x20 && c <= 0xFF) {
                char ch = (char)c;
                ed_insert(e, &ch, 1);
            }
        }
    }
}

bool tn_confirm(session_t *s, const char *question)
{
    char ans[8];
    tn_puts(s, question);
    int n = tn_readline(s, " Type 'yes' to confirm: ", ans, sizeof ans, RL_ECHO, 60);
    return n == 3 && strcmp(ans, "yes") == 0;
}
