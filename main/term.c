/* Terminal layer: the shell's view of the user's SSH channel, plus a small
 * line editor with history. The user's SSH client puts their terminal in raw
 * mode, so echoing and line editing happen here. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include "c3shell.h"

/* Fetch whatever the user has sent. >0 = bytes now in ibuf, 0 = nothing yet,
 * TN_CLOSED = the connection is gone. */
static int poll_input(session_t *s)
{
    if (s->kick)
        s->closed = true;
    if (s->closed)
        return TN_CLOSED;
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
        if (c < 0x20)
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
