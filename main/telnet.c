/* Telnet protocol layer: option negotiation, NAWS (window size), IAC
 * escaping, and a small line editor with history. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "c3shell.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

enum { IAC = 255, DONT = 254, DO = 253, WONT = 252, WILL = 251, SB = 250, SE = 240 };
enum { OPT_BINARY = 0, OPT_ECHO = 1, OPT_SGA = 3, OPT_NAWS = 31 };
enum { ST_DATA, ST_CR, ST_IAC, ST_OPT, ST_SB, ST_SB_IAC };

static int raw_send(session_t *s, const uint8_t *p, size_t n)
{
    while (n > 0 && !s->closed) {
        ssize_t w = send(s->fd, p, n, MSG_NOSIGNAL);
        if (w <= 0) {
            if (w < 0 && errno == EINTR)
                continue;
            s->closed = true;   /* includes SO_SNDTIMEO expiry: the client is gone */
            return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return s->closed ? -1 : 0;
}

void tn_init(session_t *s)
{
    static const uint8_t hello[] = {
        IAC, WILL, OPT_ECHO,   IAC, WILL, OPT_SGA,    IAC, DO, OPT_SGA,
        IAC, WILL, OPT_BINARY, IAC, DO,   OPT_BINARY, IAC, DO, OPT_NAWS,
    };
    s->cols = 80;
    s->rows = 24;
    raw_send(s, hello, sizeof hello);
}

static void negotiate(session_t *s, uint8_t cmd, uint8_t opt)
{
    /* Options we asked for ourselves need no answer; refuse everything else. */
    bool ours = false;
    if (cmd == WILL || cmd == WONT)
        ours = (opt == OPT_SGA || opt == OPT_NAWS || opt == OPT_BINARY);
    else
        ours = (opt == OPT_ECHO || opt == OPT_SGA || opt == OPT_BINARY);
    if (opt == OPT_BINARY && (cmd == WILL || cmd == WONT))
        s->in_binary = (cmd == WILL);
    if (ours || cmd == WONT || cmd == DONT)
        return;
    uint8_t reply[3] = { IAC, cmd == WILL ? DONT : WONT, opt };
    raw_send(s, reply, 3);
}

static void subneg(session_t *s)
{
    if (s->sblen == 5 && s->sb[0] == OPT_NAWS) {
        uint16_t c = (uint16_t)(s->sb[1] << 8 | s->sb[2]);
        uint16_t r = (uint16_t)(s->sb[3] << 8 | s->sb[4]);
        if (c && r && (c != s->cols || r != s->rows)) {
            s->cols = c;
            s->rows = r;
            s->winch = true;
        }
    }
}

/* Strip telnet protocol from raw bytes; returns the number of data bytes. */
static int decode(session_t *s, const uint8_t *in, int n, uint8_t *out)
{
    int m = 0;
    for (int i = 0; i < n; i++) {
        uint8_t c = in[i];
        switch (s->tstate) {
        case ST_CR:
            s->tstate = ST_DATA;
            if (c == '\n' || c == 0)   /* NVT end of line is CR LF or CR NUL */
                break;
            /* fall through */
        case ST_DATA:
            if (c == IAC) {
                s->tstate = ST_IAC;
            } else {
                out[m++] = c;
                if (c == '\r' && !s->in_binary)
                    s->tstate = ST_CR;
            }
            break;
        case ST_IAC:
            if (c == IAC) {
                out[m++] = 0xFF;
                s->tstate = ST_DATA;
            } else if (c == SB) {
                s->sblen = 0;
                s->tstate = ST_SB;
            } else if (c >= WILL) {
                s->tcmd = c;
                s->tstate = ST_OPT;
            } else {
                s->tstate = ST_DATA;
            }
            break;
        case ST_OPT:
            negotiate(s, s->tcmd, c);
            s->tstate = ST_DATA;
            break;
        case ST_SB:
            if (c == IAC)
                s->tstate = ST_SB_IAC;
            else if (s->sblen < sizeof s->sb)
                s->sb[s->sblen++] = c;
            break;
        case ST_SB_IAC:
            if (c == SE) {
                subneg(s);
                s->tstate = ST_DATA;
            } else {
                if (s->sblen < sizeof s->sb)
                    s->sb[s->sblen++] = c;
                s->tstate = ST_SB;
            }
            break;
        }
    }
    return m;
}

/* Pull whatever the socket has into ibuf. 1 = got bytes (maybe only protocol),
 * 0 = nothing within the timeout, TN_CLOSED = connection gone. */
static int fill(session_t *s, int timeout_ms)
{
    uint8_t raw[sizeof s->ibuf];
    fd_set rd;
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };

    if (s->kick)
        s->closed = true;
    if (s->closed)
        return TN_CLOSED;
    FD_ZERO(&rd);
    FD_SET(s->fd, &rd);
    int r = select(s->fd + 1, &rd, NULL, NULL, &tv);
    if (r == 0 || (r < 0 && errno == EINTR))
        return 0;
    if (r < 0) {
        s->closed = true;
        return TN_CLOSED;
    }
    ssize_t n = recv(s->fd, raw, sizeof raw, 0);
    if (n <= 0) {
        s->closed = true;
        return TN_CLOSED;
    }
    s->ipos = 0;
    s->ilen = (uint16_t)decode(s, raw, (int)n, s->ibuf);
    return 1;
}

bool tn_pending(session_t *s)
{
    return s->ipos < s->ilen;
}

int tn_getc(session_t *s, int timeout_ms)
{
    int waited = 0;
    while (s->ipos >= s->ilen) {
        int step = timeout_ms - waited > 1000 ? 1000 : timeout_ms - waited;
        if (step <= 0)
            return TN_TIMEOUT;
        int r = fill(s, step);
        if (r == TN_CLOSED)
            return TN_CLOSED;
        if (r == 0)
            waited += step;
    }
    return s->ibuf[s->ipos++];
}

int tn_read_avail(session_t *s, uint8_t *buf, int cap)
{
    if (s->ipos >= s->ilen) {
        int r = fill(s, 0);
        if (r == TN_CLOSED)
            return TN_CLOSED;
    }
    int n = s->ilen - s->ipos;
    if (n > cap)
        n = cap;
    memcpy(buf, s->ibuf + s->ipos, (size_t)n);
    s->ipos = (uint16_t)(s->ipos + n);
    return n;
}

int tn_write(session_t *s, const void *data, size_t len)
{
    const uint8_t *p = data;
    uint8_t out[512];
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        if (o > sizeof out - 2) {
            if (raw_send(s, out, o) < 0)
                return -1;
            o = 0;
        }
        out[o++] = p[i];
        if (p[i] == IAC)
            out[o++] = IAC;
    }
    return o ? raw_send(s, out, o) : 0;
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

static void erase_chars(session_t *s, int n)
{
    while (n-- > 0)
        tn_puts(s, "\b \b");
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

int tn_readline(session_t *s, const char *prompt, char *buf, size_t cap, int flags, int timeout_s)
{
    int len = 0;
    int hpos = s->hist_n;            /* index into history; hist_n = the fresh line */
    bool echo = flags & RL_ECHO;

    if (cap > LINE_MAX_)
        cap = LINE_MAX_;
    if (prompt)
        tn_puts(s, prompt);

    for (;;) {
        int c = tn_getc(s, timeout_s * 1000);
        if (c == TN_CLOSED || c == TN_TIMEOUT)
            return c;

        if (c == '\r' || c == '\n') {
            tn_puts(s, "\n");
            buf[len] = 0;
            if ((flags & RL_HISTORY) && len > 0 &&
                (s->hist_n == 0 || strcmp(s->hist[s->hist_n - 1], buf) != 0)) {
                if (s->hist_n == HIST_N) {
                    memmove(s->hist[0], s->hist[1], sizeof s->hist[0] * (HIST_N - 1));
                    s->hist_n--;
                }
                snprintf(s->hist[s->hist_n++], LINE_MAX_, "%s", buf);
            }
            return len;
        }
        if (c == 3) {                               /* Ctrl-C */
            tn_puts(s, "^C\n");
            buf[0] = 0;
            return TN_INTR;
        }
        if (c == 4) {                               /* Ctrl-D */
            if (len == 0) {
                tn_puts(s, "\n");
                return TN_EOF;
            }
            continue;
        }
        if (c == 0x7F || c == 0x08) {               /* backspace */
            if (len > 0) {
                while (len > 0 && ((uint8_t)buf[len - 1] & 0xC0) == 0x80)
                    len--;                          /* UTF-8 continuation bytes */
                len--;
                if (echo)
                    erase_chars(s, 1);
            }
            continue;
        }
        if (c == 0x15) {                            /* Ctrl-U: kill line */
            if (echo)
                erase_chars(s, cells(buf, len));
            len = 0;
            continue;
        }
        if (c == 0x1B) {                            /* escape sequence */
            int c2 = tn_getc(s, 100);
            if (c2 != '[' && c2 != 'O')
                continue;
            int fin;
            do {
                fin = tn_getc(s, 100);
            } while (fin >= 0x20 && fin < 0x40);
            if (!(flags & RL_HISTORY) || (fin != 'A' && fin != 'B'))
                continue;
            int np = hpos + (fin == 'A' ? -1 : 1);
            if (np < 0 || np > s->hist_n)
                continue;
            hpos = np;
            erase_chars(s, cells(buf, len));
            if (hpos == s->hist_n)
                len = 0;
            else {
                len = (int)strlen(s->hist[hpos]);
                if (len > (int)cap - 1)
                    len = (int)cap - 1;
                memcpy(buf, s->hist[hpos], (size_t)len);
            }
            tn_write(s, buf, (size_t)len);
            continue;
        }
        if (c < 0x20 || c == 0xFF)
            continue;
        if (len < (int)cap - 1) {
            buf[len++] = (char)c;
            if (echo)
                tn_write(s, &buf[len - 1], 1);
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
