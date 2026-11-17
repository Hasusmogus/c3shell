/* File transfers between the file area and other machines.
 *
 *   inbound   SFTP (what OpenSSH's scp and sftp use by default) and the
 *             classic scp protocol ("scp -O"), served on exec / subsystem
 *             channels of the device's own SSH server
 *   outbound  the shell's scp command, which runs "scp -t" / "scp -f" on the
 *             other machine over an ordinary SSH connection
 *
 * Every path goes through fs_resolve(), so transfers reach exactly what the
 * file commands reach: the file area and nothing else.
 *
 * The scp protocol is symmetric, so one sender and one receiver serve both
 * directions: the receiver acknowledges every step with a zero byte, the
 * sender announces each file with "C<mode> <size> <name>\n" (directories with
 * "D...", "E" to leave them), and errors travel as "\1msg\n" / "\2msg\n". */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "c3shell.h"

#define CHUNK 2048

/* ---------------- a byte stream: the user's own channel, or a remote command ---------------- */

typedef struct {
    session_t *s;
    sshc_t    *c;            /* outbound: the remote scp; NULL = the session's own channel */
    bool       show;         /* progress and errors to the user's terminal (outbound) */
    bool       recursive;
    bool       failed;       /* some file did not make it (exit status 1) */
    uint8_t    rb[512];
    int        rpos, rlen;
} xs_t;

static int xs_fill(xs_t *x, int timeout_ms)
{
    if (x->c) {
        for (;;) {
            bool err = false;
            int n = sshc_read(x->c, x->rb, sizeof x->rb, timeout_ms, &err);
            if (n <= 0)
                return -1;
            if (err) {                       /* the remote's stderr: show it, it is not protocol */
                tn_write(x->s, x->rb, (size_t)n);
                continue;
            }
            x->rpos = 0;
            x->rlen = n;
            return n;
        }
    }
    int ch = tn_getc(x->s, timeout_ms);
    if (ch < 0)
        return -1;
    x->rb[0] = (uint8_t)ch;
    int n = tn_read_avail(x->s, x->rb + 1, (int)sizeof x->rb - 1);
    x->rpos = 0;
    x->rlen = 1 + (n > 0 ? n : 0);
    return x->rlen;
}

static int xs_getc(xs_t *x, int timeout_ms)
{
    if (x->rpos >= x->rlen && xs_fill(x, timeout_ms) < 0)
        return -1;
    return x->rb[x->rpos++];
}

/* Exactly len bytes, or -1. With out == NULL, hand them to sink() in pieces. */
static int xs_read(xs_t *x, void *out, size_t len)
{
    uint8_t *o = out;
    while (len) {
        if (x->rpos >= x->rlen && xs_fill(x, C3_SSH_IO_MS) < 0)
            return -1;
        size_t n = (size_t)(x->rlen - x->rpos);
        if (n > len)
            n = len;
        memcpy(o, x->rb + x->rpos, n);
        x->rpos += (int)n;
        o += n;
        len -= n;
    }
    return 0;
}

/* One line up to '\n' (not stored); -1 on EOF or overlong. */
static int xs_line(xs_t *x, char *buf, size_t cap)
{
    size_t n = 0;
    for (;;) {
        int ch = xs_getc(x, C3_SSH_IO_MS);
        if (ch < 0)
            return -1;
        if (ch == '\n')
            break;
        if (n + 1 >= cap)
            return -1;
        buf[n++] = (char)ch;
    }
    buf[n] = 0;
    return (int)n;
}

static int xs_write(xs_t *x, const void *data, size_t len)
{
    if (x->c)
        return sshc_write(x->c, data, (int)len);
    return tn_write(x->s, data, len);
}

/* ---------------- scp protocol ---------------- */

static int scp_ack(xs_t *x)
{
    return xs_write(x, "", 1);
}

/* Tell the other side about a failure (it shows the message); also show it
 * here when this end has a user watching. */
static void scp_err(xs_t *x, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void scp_err(xs_t *x, const char *fmt, ...)
{
    char msg[200];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg + 1, sizeof msg - 2, fmt, ap);
    va_end(ap);
    x->failed = true;
    if (x->show)
        tn_printf(x->s, "scp: %s\n", msg + 1);
    msg[0] = 1;
    size_t n = strlen(msg);
    msg[n] = '\n';
    xs_write(x, msg, n + 1);
}

/* Wait for the receiver's verdict: 0 = go on, 1 = it refused this file, -1 = over. */
static int scp_wait(xs_t *x)
{
    char msg[200];
    int ch = xs_getc(x, C3_SSH_IO_MS);
    if (ch == 0)
        return 0;
    if (ch == 1 || ch == 2) {
        if (xs_line(x, msg, sizeof msg) >= 0 && x->show)
            tn_printf(x->s, "%s\n", msg);
        x->failed = true;
        return ch == 1 ? 1 : -1;
    }
    if (x->show)
        tn_puts(x->s, "scp: lost the connection\n");
    x->failed = true;
    return -1;
}

static void progress(xs_t *x, const char *name, long done, long total, bool final)
{
    if (!x->show)
        return;
    int pct = total > 0 ? (int)(done * 100 / total) : 100;
    tn_printf(x->s, "\r%-40.40s %3d%% %8ld KB%s", name, pct, (done + 1023) / 1024, final ? "\n" : "");
}

static bool join(char *out, const char *dir, const char *name)
{
    int n = snprintf(out, C3_PATH_MAX, "%s%s%s", dir, strcmp(dir, "/") == 0 ? "" : "/", name);
    return n > 0 && n < C3_PATH_MAX;
}

static bool safe_name(const char *n)
{
    return n[0] && strcmp(n, ".") != 0 && strcmp(n, "..") != 0 && !strchr(n, '/') &&
           strlen(n) < C3_NAME_MAX;
}

/* Send one file or (recursive) directory, named by its path in the file area. */
static int scp_send(xs_t *x, const char *vpath, int depth)
{
    char host[C3_HOST_MAX], line[C3_NAME_MAX + 40];
    const char *name = strrchr(vpath, '/') ? strrchr(vpath, '/') + 1 : vpath;
    struct stat st;

    if (strcmp(vpath, "/") == 0)
        name = "files";
    if (fs_host(vpath, host, sizeof host) != 0 || stat(host, &st) != 0) {
        scp_err(x, "%s: %s", vpath, strerror(errno ? errno : ENOENT));
        return 0;
    }
    if (S_ISDIR(st.st_mode)) {
        if (!x->recursive || depth > 8) {
            scp_err(x, "%s: is a directory%s", vpath, x->recursive ? " nested too deep" : " (use -r)");
            return 0;
        }
        snprintf(line, sizeof line, "D0755 0 %s\n", name);
        if (xs_write(x, line, strlen(line)) < 0)
            return -1;
        int r = scp_wait(x);
        if (r)
            return r < 0 ? -1 : 0;
        DIR *d = opendir(host);
        struct dirent *e;
        char child[C3_PATH_MAX];
        while (d && (e = readdir(d))) {
            if (!safe_name(e->d_name))
                continue;
            if (!join(child, vpath, e->d_name)) {
                scp_err(x, "%s/%s: name too long", vpath, e->d_name);
                continue;
            }
            if (scp_send(x, child, depth + 1) < 0) {
                closedir(d);
                return -1;
            }
        }
        if (d)
            closedir(d);
        if (xs_write(x, "E\n", 2) < 0)
            return -1;
        return scp_wait(x) < 0 ? -1 : 0;
    }

    FILE *f = fopen(host, "rb");
    if (!f) {
        scp_err(x, "%s: %s", vpath, strerror(errno));
        return 0;
    }
    snprintf(line, sizeof line, "C0644 %ld %s\n", (long)st.st_size, name);
    int r = xs_write(x, line, strlen(line)) < 0 ? -1 : scp_wait(x);
    if (r) {
        fclose(f);
        return r < 0 ? -1 : 0;
    }
    uint8_t *buf = malloc(CHUNK);
    long done = 0;
    bool readerr = false;
    while (buf && done < (long)st.st_size) {
        size_t want = (size_t)((long)st.st_size - done) > CHUNK ? CHUNK : (size_t)((long)st.st_size - done);
        size_t got = fread(buf, 1, want, f);
        if (got < want) {                     /* keep the stream in step: pad, then report */
            memset(buf + got, 0, want - got);
            readerr = true;
        }
        if (xs_write(x, buf, want) < 0) {
            free(buf);
            fclose(f);
            return -1;
        }
        done += (long)want;
        if ((done & 0xFFFF) < CHUNK && done < (long)st.st_size)
            progress(x, name, done, (long)st.st_size, false);
    }
    free(buf);
    fclose(f);
    if (!buf)
        return -1;
    if (readerr)
        scp_err(x, "%s: read error", vpath);
    else if (xs_write(x, "", 1) < 0)
        return -1;
    progress(x, name, done, (long)st.st_size, true);
    return scp_wait(x) < 0 ? -1 : 0;
}

/* Receive into target (a path in the file area). If target is a directory the
 * incoming names go inside it, otherwise the one incoming file becomes target. */
static int scp_receive(xs_t *x, const char *target, int depth)
{
    char line[C3_NAME_MAX + 64], vpath[C3_PATH_MAX], host[C3_HOST_MAX];
    struct stat st;

    if (scp_ack(x) < 0)
        return -1;
    for (;;) {
        int ch = xs_getc(x, C3_SSH_IO_MS);
        if (ch < 0)
            return depth == 0 ? 0 : -1;       /* the sender is done */
        if (xs_line(x, line, sizeof line) < 0)
            return -1;
        if (ch == 1 || ch == 2) {
            if (x->show)
                tn_printf(x->s, "%s\n", line);
            x->failed = true;
            if (ch == 2)
                return -1;
            continue;
        }
        if (ch == 'E') {
            if (depth == 0)
                return -1;
            return scp_ack(x);
        }
        if (ch == 'T') {                      /* times (scp -p): accepted, not kept */
            if (scp_ack(x) < 0)
                return -1;
            continue;
        }
        if (ch != 'C' && ch != 'D') {
            scp_err(x, "protocol error");
            return -1;
        }

        unsigned mode;
        long long size;
        int off = 0;
        if (sscanf(line, "%o %lld %n", &mode, &size, &off) < 2 || off == 0 || size < 0) {
            scp_err(x, "protocol error");
            return -1;
        }
        const char *name = line + off;
        bool into = fs_host(target, host, sizeof host) == 0 && stat(host, &st) == 0 && S_ISDIR(st.st_mode);
        if (!safe_name(name)) {
            scp_err(x, "%s: unexpected file name", name);
            return -1;
        }
        if (into ? !join(vpath, target, name) : snprintf(vpath, sizeof vpath, "%s", target) >= (int)sizeof vpath) {
            scp_err(x, "%s: name too long", name);
            return -1;
        }
        if (fs_host(vpath, host, sizeof host) != 0) {
            scp_err(x, "%s: name too long", name);
            return -1;
        }

        if (ch == 'D') {
            if (!x->recursive || depth > 8) {
                scp_err(x, "%s: received a directory%s", name, x->recursive ? " nested too deep" : "");
                return -1;
            }
            if (mkdir(host, 0755) != 0 && errno != EEXIST) {
                scp_err(x, "%s: %s", vpath, strerror(errno));
                return -1;
            }
            if (scp_receive(x, vpath, depth + 1) < 0)
                return -1;
            continue;
        }

        /* 'C': a file of size bytes follows our go-ahead */
        long free_b = -1, total, used;
        if (port_fs_usage(&total, &used) == 0)
            free_b = total - used;
        FILE *f = NULL;
        if (free_b >= 0 && size > free_b)
            errno = ENOSPC;
        else
            f = fopen(host, "wb");
        if (!f) {
            scp_err(x, "%s: %s", vpath, strerror(errno));
            continue;                         /* the sender skips this file */
        }
        if (scp_ack(x) < 0) {
            fclose(f);
            return -1;
        }
        long long done = 0;
        bool werr = false;
        while (done < size) {
            if (x->rpos >= x->rlen && xs_fill(x, C3_SSH_IO_MS) < 0) {
                fclose(f);
                remove(host);
                return -1;
            }
            size_t n = (size_t)(x->rlen - x->rpos);
            if ((long long)n > size - done)
                n = (size_t)(size - done);
            if (!werr && fwrite(x->rb + x->rpos, 1, n, f) != n)
                werr = true;
            x->rpos += (int)n;
            done += (long long)n;
            if ((done & 0xFFFF) < (long long)n && done < size)
                progress(x, name, (long)done, (long)size, false);
        }
        if (fclose(f) != 0)
            werr = true;
        progress(x, name, (long)done, (long)size, true);
        int end = xs_getc(x, C3_SSH_IO_MS);   /* the sender's own verdict on the file */
        if (end < 0)
            return -1;
        if (end != 0) {
            char msg[160];
            xs_line(x, msg, sizeof msg);
            if (x->show)
                tn_printf(x->s, "%s\n", msg);
            remove(host);
            x->failed = true;
            if (end == 2)
                return -1;
            continue;
        }
        if (werr) {
            remove(host);
            scp_err(x, "%s: write failed (file area full?)", vpath);
        } else if (scp_ack(x) < 0) {
            return -1;
        }
    }
}

/* ---------------- inbound: "scp -t/-f path" on our exec channel ---------------- */

/* Split a command line into words: quotes and backslashes as a POSIX shell
 * would treat them, which is what scp clients expect on the far end. */
static int words(char *line, char **argv, int max)
{
    int argc = 0;
    char *r = line, *w = line;
    while (*r) {
        while (*r == ' ' || *r == '\t')
            r++;
        if (!*r)
            break;
        if (argc == max)
            return -1;
        argv[argc++] = w;
        char q = 0;
        while (*r && (q || (*r != ' ' && *r != '\t'))) {
            if (!q && (*r == '"' || *r == '\'')) {
                q = *r++;
            } else if (q && *r == q) {
                q = 0;
                r++;
            } else if (*r == '\\' && q != '\'' && r[1]) {
                r++;
                *w++ = *r++;
            } else {
                *w++ = *r++;
            }
        }
        if (*r)
            r++;
        *w++ = 0;
    }
    return argc;
}

static int scp_server(session_t *s, const char *command)
{
    char *line = strdup(command), *argv[12];
    char vpath[C3_PATH_MAX];
    bool to = false, from = false;
    xs_t *x = calloc(1, sizeof *x);
    int argc = line ? words(line, argv, 12) : -1, i, ret = 1;

    if (!x || argc < 2)
        goto out;
    x->s = s;
    for (i = 1; i < argc && argv[i][0] == '-'; i++) {
        if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        }
        for (const char *p = argv[i] + 1; *p; p++) {
            if (*p == 't')
                to = true;
            else if (*p == 'f')
                from = true;
            else if (*p == 'r')
                x->recursive = true;
            /* -d (target must be a directory), -p (times), -v: nothing to do */
        }
    }
    if (to == from || i >= argc) {
        tn_puts(s, "scp: unsupported request\n");
        goto out;
    }
    if (to) {
        int r = fs_resolve(s, argv[i], vpath, sizeof vpath);
        if (r < 0 || i + 1 != argc) {
            scp_err(x, "%s: %s", argv[i], r < 0 ? strerror(-r) : "one target only");
            goto out;
        }
        port_log("session %d: scp upload to %s", s->id, vpath);
        ret = scp_receive(x, vpath, 0) < 0 || x->failed;
    } else {
        if (scp_wait(x) < 0)
            goto out;
        port_log("session %d: scp download", s->id);
        ret = 0;
        for (; i < argc; i++) {
            int r = fs_resolve(s, argv[i], vpath, sizeof vpath);
            if (r < 0)
                scp_err(x, "%s: %s", argv[i], strerror(-r));
            else if (scp_send(x, vpath, 0) < 0) {
                ret = 1;
                break;
            }
        }
        ret = ret || x->failed;
    }
out:
    free(line);
    free(x);
    return ret;
}

/* ---------------- inbound: SFTP version 3 ---------------- */

enum {
    FX_INIT = 1, FX_VERSION = 2, FX_OPEN = 3, FX_CLOSE = 4, FX_READ = 5, FX_WRITE = 6, FX_LSTAT = 7,
    FX_FSTAT = 8, FX_SETSTAT = 9, FX_FSETSTAT = 10, FX_OPENDIR = 11, FX_READDIR = 12, FX_REMOVE = 13,
    FX_MKDIR = 14, FX_RMDIR = 15, FX_REALPATH = 16, FX_STAT = 17, FX_RENAME = 18,
    FX_STATUS = 101, FX_HANDLE = 102, FX_DATA = 103, FX_NAME = 104, FX_ATTRS = 105,
};
enum { ST_OK, ST_EOF, ST_NO_FILE, ST_DENIED, ST_FAILURE, ST_BAD_MSG, ST_NO_CONN, ST_LOST, ST_UNSUPPORTED };
#define A_SIZE  0x1
#define A_UIDGID 0x2
#define A_PERM  0x4
#define A_TIME  0x8
#define A_EXT   0x80000000u

#define SFTP_IN   4096          /* largest request kept whole; WRITE data is streamed */
#define SFTP_OUT  (8 * 1024 + 512)
#define SFTP_READ (8 * 1024)    /* a READ is answered with at most this much (short reads are allowed) */
#define HANDLES   4

typedef struct {
    xs_t     x;
    uint8_t *in, *out;
    uint32_t ilen, ipos, olen;
    bool     bad;
    struct {
        bool used, dir;
        int  fd;
        DIR *d;
        char vpath[C3_PATH_MAX];
    } h[HANDLES];
} sftp_t;

/* request parsing */
static uint32_t g32(sftp_t *f)
{
    if (f->ipos + 4 > f->ilen) {
        f->bad = true;
        return 0;
    }
    const uint8_t *p = f->in + f->ipos;
    f->ipos += 4;
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static uint64_t g64(sftp_t *f)
{
    uint64_t hi = g32(f);
    return hi << 32 | g32(f);
}

/* a string, NUL-terminated in place (the byte after it is consumed by the
 * next field's parse, so terminate a copy instead when that matters) */
static const char *gstr(sftp_t *f, char *buf, size_t cap)
{
    uint32_t n = g32(f);
    if (f->bad || n > f->ilen - f->ipos || n >= cap) {
        f->bad = true;
        return "";
    }
    memcpy(buf, f->in + f->ipos, n);
    buf[n] = 0;
    f->ipos += n;
    return buf;
}

static void gattrs(sftp_t *f)
{
    uint32_t fl = g32(f);
    if (fl & A_SIZE)
        g64(f);
    if (fl & A_UIDGID)
        g64(f);
    if (fl & A_PERM)
        g32(f);
    if (fl & A_TIME)
        g64(f);
    if (fl & A_EXT) {
        uint32_t n = g32(f);
        char tmp[256];
        for (uint32_t i = 0; i < n && !f->bad; i++) {
            gstr(f, tmp, sizeof tmp);
            gstr(f, tmp, sizeof tmp);
        }
    }
}

/* reply building */
static void p8(sftp_t *f, uint8_t v)
{
    if (f->olen < SFTP_OUT)
        f->out[f->olen++] = v;
}
static void p32(sftp_t *f, uint32_t v)
{
    p8(f, (uint8_t)(v >> 24));
    p8(f, (uint8_t)(v >> 16));
    p8(f, (uint8_t)(v >> 8));
    p8(f, (uint8_t)v);
}
static void p64(sftp_t *f, uint64_t v)
{
    p32(f, (uint32_t)(v >> 32));
    p32(f, (uint32_t)v);
}
static void pbytes(sftp_t *f, const void *d, uint32_t n)
{
    p32(f, n);
    if (f->olen + n <= SFTP_OUT) {
        memcpy(f->out + f->olen, d, n);
        f->olen += n;
    }
}
static void pstr(sftp_t *f, const char *str)
{
    pbytes(f, str, (uint32_t)strlen(str));
}
static void pattrs(sftp_t *f, const struct stat *st)
{
    p32(f, A_SIZE | A_PERM | A_TIME);
    p64(f, (uint64_t)st->st_size);
    /* the same permissions as the long listing shows: LittleFS keeps none
     * (st_mode is just the file type), and clients apply what they are sent */
    p32(f, (uint32_t)((st->st_mode & S_IFMT) | (S_ISDIR(st->st_mode) ? 0755 : 0644)));
    p32(f, (uint32_t)st->st_mtime);
    p32(f, (uint32_t)st->st_mtime);
}

static void begin(sftp_t *f, uint8_t type, uint32_t id)
{
    f->olen = 4;
    p8(f, type);
    p32(f, id);
}

static int finish(sftp_t *f)
{
    uint32_t n = f->olen - 4;
    f->out[0] = (uint8_t)(n >> 24);
    f->out[1] = (uint8_t)(n >> 16);
    f->out[2] = (uint8_t)(n >> 8);
    f->out[3] = (uint8_t)n;
    return xs_write(&f->x, f->out, f->olen);
}

static int status(sftp_t *f, uint32_t id, uint32_t code, const char *msg)
{
    begin(f, FX_STATUS, id);
    p32(f, code);
    pstr(f, msg ? msg : code == ST_OK ? "Success" : "Failure");
    pstr(f, "");
    return finish(f);
}

static int status_errno(sftp_t *f, uint32_t id, int e)
{
    uint32_t code = e == ENOENT || e == ENOTDIR ? ST_NO_FILE : e == EACCES || e == EPERM ? ST_DENIED : ST_FAILURE;
    return status(f, id, code, strerror(e));
}

/* a path from the request, resolved into the file area */
static int gpath(sftp_t *f, char *vpath, char *host)
{
    char raw[C3_PATH_MAX + 1];
    gstr(f, raw, sizeof raw);
    if (f->bad)
        return -ENAMETOOLONG;
    int r = fs_resolve(f->x.s, raw, vpath, C3_PATH_MAX);
    if (r == 0 && fs_host(vpath, host, C3_HOST_MAX) != 0)
        r = -ENAMETOOLONG;
    return r;
}

static int ghandle(sftp_t *f, bool dir)
{
    char h[8];
    gstr(f, h, sizeof h);
    int i = h[0] - '0';
    if (f->bad || strlen(h) != 1 || i < 0 || i >= HANDLES || !f->h[i].used || f->h[i].dir != dir)
        return -1;
    return i;
}

static int new_handle(sftp_t *f)
{
    for (int i = 0; i < HANDLES; i++)
        if (!f->h[i].used)
            return i;
    return -1;
}

static int reply_handle(sftp_t *f, uint32_t id, int i)
{
    char h[2] = { (char)('0' + i), 0 };
    begin(f, FX_HANDLE, id);
    pstr(f, h);
    return finish(f);
}

static void longname(char *out, size_t cap, const char *name, const struct stat *st)
{
    snprintf(out, cap, "%crw%cr-%cr-%c    1 c3       c3     %10ld Jan  1  1970 %s", S_ISDIR(st->st_mode) ? 'd' : '-',
             S_ISDIR(st->st_mode) ? 'x' : '-', S_ISDIR(st->st_mode) ? 'x' : '-', S_ISDIR(st->st_mode) ? 'x' : '-',
             (long)st->st_size, name);
}

/* WRITE: the data is copied straight from the channel into the file. */
static int do_write(sftp_t *f, uint32_t total)
{
    uint8_t hdr[4 + 4 + 8 + 8 + 4];   /* id, handle (len + up to 8), offset, data length */
    uint32_t id, hl, dl;
    uint64_t off;

    if (total < 4 + 4 + 8 + 4 || xs_read(&f->x, hdr, 8) < 0)
        return -1;
    id = (uint32_t)hdr[0] << 24 | (uint32_t)hdr[1] << 16 | (uint32_t)hdr[2] << 8 | hdr[3];
    hl = (uint32_t)hdr[4] << 24 | (uint32_t)hdr[5] << 16 | (uint32_t)hdr[6] << 8 | hdr[7];
    if (hl > 8 || total < 4 + 4 + hl + 8 + 4)
        return -1;
    char h[9] = { 0 };
    uint8_t rest[12];
    if (xs_read(&f->x, h, hl) < 0 || xs_read(&f->x, rest, 12) < 0)
        return -1;
    off = (uint64_t)rest[0] << 56 | (uint64_t)rest[1] << 48 | (uint64_t)rest[2] << 40 | (uint64_t)rest[3] << 32 |
          (uint64_t)rest[4] << 24 | (uint64_t)rest[5] << 16 | (uint64_t)rest[6] << 8 | rest[7];
    dl = (uint32_t)rest[8] << 24 | (uint32_t)rest[9] << 16 | (uint32_t)rest[10] << 8 | rest[11];
    if (dl != total - (4 + 4 + hl + 8 + 4))
        return -1;

    int i = h[0] - '0';
    bool ok = hl == 1 && i >= 0 && i < HANDLES && f->h[i].used && !f->h[i].dir;
    int err = ok ? 0 : EBADF;
    if (ok && lseek(f->h[i].fd, (off_t)off, SEEK_SET) == (off_t)-1)
        err = errno;
    while (dl) {                       /* always drain the data, even after a failure */
        if (f->x.rpos >= f->x.rlen && xs_fill(&f->x, C3_SSH_IO_MS) < 0)
            return -1;
        uint32_t n = (uint32_t)(f->x.rlen - f->x.rpos);
        if (n > dl)
            n = dl;
        if (!err && write(f->h[i].fd, f->x.rb + f->x.rpos, n) != (ssize_t)n)
            err = errno ? errno : ENOSPC;
        f->x.rpos += (int)n;
        dl -= n;
    }
    return err ? status_errno(f, id, err) : status(f, id, ST_OK, NULL);
}

static int sftp_one(sftp_t *f, uint8_t type)
{
    char vpath[C3_PATH_MAX], host[C3_HOST_MAX], v2[C3_PATH_MAX], h2[C3_HOST_MAX];
    struct stat st;
    uint32_t id = type == FX_INIT ? 0 : g32(f);
    int i, r;

    switch (type) {
    case FX_INIT:
        f->olen = 4;
        p8(f, FX_VERSION);
        p32(f, 3);
        return finish(f);

    case FX_REALPATH:
        if ((r = gpath(f, vpath, host)) < 0)
            return status_errno(f, id, -r);
        begin(f, FX_NAME, id);
        p32(f, 1);
        pstr(f, vpath);
        pstr(f, vpath);
        p32(f, 0);
        return finish(f);

    case FX_STAT:
    case FX_LSTAT:
        if ((r = gpath(f, vpath, host)) < 0)
            return status_errno(f, id, -r);
        if (stat(host, &st) != 0)
            return status_errno(f, id, errno);
        begin(f, FX_ATTRS, id);
        pattrs(f, &st);
        return finish(f);

    case FX_FSTAT:
        if ((i = ghandle(f, false)) < 0)
            return status(f, id, ST_FAILURE, "bad handle");
        if (fstat(f->h[i].fd, &st) != 0)
            return status_errno(f, id, errno);
        begin(f, FX_ATTRS, id);
        pattrs(f, &st);
        return finish(f);

    case FX_SETSTAT:
    case FX_FSETSTAT:                  /* no owners, modes or times to set here: accept and ignore */
        return status(f, id, ST_OK, NULL);

    case FX_OPEN: {
        if ((r = gpath(f, vpath, host)) < 0)
            return status_errno(f, id, -r);
        uint32_t pf = g32(f), fl;
        gattrs(f);
        fl = (pf & 3) == 3 ? O_RDWR : (pf & 2) ? O_WRONLY : O_RDONLY;
        if (pf & 0x04)
            fl |= O_APPEND;
        if (pf & 0x08)
            fl |= O_CREAT;
        if (pf & 0x10)
            fl |= O_TRUNC;
        if (pf & 0x20)
            fl |= O_EXCL;
        if ((i = new_handle(f)) < 0)
            return status(f, id, ST_FAILURE, "too many open files");
        if (stat(host, &st) == 0 && S_ISDIR(st.st_mode))
            return status(f, id, ST_FAILURE, "is a directory");
        int fd = open(host, (int)fl, 0644);
        if (fd < 0)
            return status_errno(f, id, errno);
        f->h[i].used = true;
        f->h[i].dir = false;
        f->h[i].fd = fd;
        return reply_handle(f, id, i);
    }

    case FX_OPENDIR: {
        if ((r = gpath(f, vpath, host)) < 0)
            return status_errno(f, id, -r);
        if ((i = new_handle(f)) < 0)
            return status(f, id, ST_FAILURE, "too many open directories");
        DIR *d = opendir(host);
        if (!d)
            return status_errno(f, id, errno);
        f->h[i].used = true;
        f->h[i].dir = true;
        f->h[i].d = d;
        snprintf(f->h[i].vpath, sizeof f->h[i].vpath, "%s", vpath);
        return reply_handle(f, id, i);
    }

    case FX_CLOSE: {
        char h[8];
        gstr(f, h, sizeof h);
        i = h[0] - '0';
        if (f->bad || i < 0 || i >= HANDLES || !f->h[i].used)
            return status(f, id, ST_FAILURE, "bad handle");
        r = f->h[i].dir ? closedir(f->h[i].d) : close(f->h[i].fd);
        f->h[i].used = false;
        return r == 0 ? status(f, id, ST_OK, NULL) : status_errno(f, id, errno);
    }

    case FX_READ: {
        if ((i = ghandle(f, false)) < 0)
            return status(f, id, ST_FAILURE, "bad handle");
        uint64_t off = g64(f);
        uint32_t len = g32(f);
        if (len > SFTP_READ)
            len = SFTP_READ;
        if (lseek(f->h[i].fd, (off_t)off, SEEK_SET) == (off_t)-1)
            return status_errno(f, id, errno);
        begin(f, FX_DATA, id);
        uint32_t at = f->olen;
        p32(f, 0);
        ssize_t n = read(f->h[i].fd, f->out + f->olen, len);
        if (n < 0)
            return status_errno(f, id, errno);
        if (n == 0)
            return status(f, id, ST_EOF, "End of file");
        f->olen += (uint32_t)n;
        f->out[at] = (uint8_t)(n >> 24);
        f->out[at + 1] = (uint8_t)(n >> 16);
        f->out[at + 2] = (uint8_t)(n >> 8);
        f->out[at + 3] = (uint8_t)n;
        return finish(f);
    }

    case FX_READDIR: {
        if ((i = ghandle(f, true)) < 0)
            return status(f, id, ST_FAILURE, "bad handle");
        begin(f, FX_NAME, id);
        uint32_t at = f->olen, count = 0;
        p32(f, 0);
        struct dirent *e;
        char ln[C3_NAME_MAX + 340];
        while (f->olen < SFTP_OUT - 512 && count < 32 && (e = readdir(f->h[i].d))) {
            if (!join(v2, f->h[i].vpath, e->d_name) || fs_host(v2, h2, sizeof h2) != 0 || stat(h2, &st) != 0)
                continue;
            longname(ln, sizeof ln, e->d_name, &st);
            pstr(f, e->d_name);
            pstr(f, ln);
            pattrs(f, &st);
            count++;
        }
        if (count == 0)
            return status(f, id, ST_EOF, "End of directory");
        f->out[at] = (uint8_t)(count >> 24);
        f->out[at + 1] = (uint8_t)(count >> 16);
        f->out[at + 2] = (uint8_t)(count >> 8);
        f->out[at + 3] = (uint8_t)count;
        return finish(f);
    }

    case FX_REMOVE:
        if ((r = gpath(f, vpath, host)) < 0)
            return status_errno(f, id, -r);
        if (stat(host, &st) == 0 && S_ISDIR(st.st_mode))
            return status(f, id, ST_FAILURE, "is a directory");
        return unlink(host) == 0 ? status(f, id, ST_OK, NULL) : status_errno(f, id, errno);

    case FX_MKDIR:
        if ((r = gpath(f, vpath, host)) < 0)
            return status_errno(f, id, -r);
        gattrs(f);
        return mkdir(host, 0755) == 0 ? status(f, id, ST_OK, NULL) : status_errno(f, id, errno);

    case FX_RMDIR:
        if ((r = gpath(f, vpath, host)) < 0)
            return status_errno(f, id, -r);
        if (strcmp(vpath, "/") == 0)
            return status(f, id, ST_DENIED, "cannot remove the root");
        return rmdir(host) == 0 ? status(f, id, ST_OK, NULL) : status_errno(f, id, errno);

    case FX_RENAME:
        if ((r = gpath(f, vpath, host)) < 0 || (r = gpath(f, v2, h2)) < 0)
            return status_errno(f, id, -r);
        if (strcmp(vpath, "/") == 0)
            return status(f, id, ST_DENIED, "cannot rename the root");
        if (stat(h2, &st) == 0)        /* SFTP v3: renaming onto an existing name fails */
            return status(f, id, ST_FAILURE, "target exists");
        return rename(host, h2) == 0 ? status(f, id, ST_OK, NULL) : status_errno(f, id, errno);

    default:
        return status(f, id, ST_UNSUPPORTED, "not supported");
    }
}

static int sftp_server(session_t *s)
{
    sftp_t *f = calloc(1, sizeof *f);
    int ret = 1;

    if (!f || !(f->in = malloc(SFTP_IN)) || !(f->out = malloc(SFTP_OUT)))
        goto out;
    f->x.s = s;
    port_log("session %d: sftp started", s->id);
    for (;;) {
        uint8_t hdr[5];
        /* between requests the client may sit idle for a long time */
        if (f->x.rpos >= f->x.rlen && xs_fill(&f->x, C3_IDLE_TIMEOUT_S * 1000) < 0) {
            ret = 0;
            break;
        }
        if (xs_read(&f->x, hdr, 5) < 0)
            break;
        uint32_t len = (uint32_t)hdr[0] << 24 | (uint32_t)hdr[1] << 16 | (uint32_t)hdr[2] << 8 | hdr[3];
        if (len < 1)
            break;
        if (hdr[4] == FX_WRITE) {
            if (do_write(f, len - 1) < 0)
                break;
            continue;
        }
        if (len - 1 > SFTP_IN)
            break;
        f->ilen = len - 1;
        f->ipos = 0;
        f->bad = false;
        if (xs_read(&f->x, f->in, f->ilen) < 0)
            break;
        int r = sftp_one(f, hdr[4]);
        if (f->bad && r == 0 && hdr[4] != FX_INIT)
            port_log("session %d: sftp: malformed request %u", s->id, hdr[4]);
        if (r < 0)
            break;
    }
    for (int i = 0; i < HANDLES; i++) {
        if (f->h[i].used && f->h[i].dir)
            closedir(f->h[i].d);
        else if (f->h[i].used)
            close(f->h[i].fd);
    }
    port_log("session %d: sftp ended", s->id);
out:
    if (f) {
        free(f->in);
        free(f->out);
        free(f);
    }
    return ret;
}

/* Entry point for a non-interactive channel; returns the exit status. */
int xfer_serve(session_t *s, bool subsystem, const char *command)
{
    int st = 127;
    snprintf(s->cwd, sizeof s->cwd, "/");
    if (subsystem && strcmp(command, "sftp") == 0)
        st = sftp_server(s);
    else if (!subsystem && strncmp(command, "scp ", 4) == 0)
        st = scp_server(s, command);
    else
        tn_printf(s, C3_NAME ": only interactive logins, scp and sftp are available (not '%.40s')\n", command);
    /* The client signals "no more data" with an EOF, which the terminal layer
     * reads as a closed session. The connection is normally still up and
     * waiting for our exit status, so let the regular shutdown send it. */
    if (!s->kick)
        s->closed = false;
    return st;
}

/* ---------------- outbound: the scp command ---------------- */

/* "[user@]host:path" -> parts; false if arg names a local file. */
static bool remote_spec(char *arg, char **user, char **host, char **path)
{
    char *colon = strchr(arg, ':');
    char *slash = strchr(arg, '/');
    if (!colon || colon == arg || (slash && slash < colon))
        return false;
    *colon = 0;
    *path = colon + 1;
    char *at = strrchr(arg, '@');
    if (at) {
        *at = 0;
        *user = arg;
        *host = at + 1;
    } else {
        *user = NULL;
        *host = arg;
    }
    return **host != 0;
}

/* Single-quote a path for the remote shell. */
static bool shell_quote(char *out, size_t cap, const char *in)
{
    size_t o = 0;
    if (!*in)
        in = ".";
    if (o + 1 >= cap)
        return false;
    out[o++] = '\'';
    for (; *in; in++) {
        if (*in == '\'') {
            if (o + 4 >= cap)
                return false;
            memcpy(out + o, "'\\''", 4);
            o += 4;
        } else {
            if (o + 1 >= cap)
                return false;
            out[o++] = *in;
        }
    }
    if (o + 2 > cap)
        return false;
    out[o++] = '\'';
    out[o] = 0;
    return true;
}

int cmd_scp(session_t *s, int argc, char **argv)
{
    int port = 22, first = 1;
    bool recursive = false;
    char *ruser = NULL, *rhost = NULL, *rpath = NULL;
    char cmd[C3_PATH_MAX * 3 + 64], q[C3_PATH_MAX * 2 + 16], user[32];

    for (; first < argc && argv[first][0] == '-'; first++) {
        if (strcmp(argv[first], "-P") == 0 && first + 1 < argc)
            port = atoi(argv[++first]);
        else if (strcmp(argv[first], "-r") == 0)
            recursive = true;
        else
            break;
    }
    int nops = argc - first;
    if (nops < 2 || port < 1 || port > 65535) {
        tn_puts(s, "usage: scp [-r] [-P port] file... [user@]host:[path]   (upload)\n"
                   "       scp [-r] [-P port] [user@]host:path [local]    (download)\n");
        return 0;
    }
    bool up = remote_spec(argv[argc - 1], &ruser, &rhost, &rpath);
    if (!up) {
        if (nops != 2 || !remote_spec(argv[first], &ruser, &rhost, &rpath)) {
            tn_puts(s, "scp: one side must be remote ([user@]host:path), the other local\n");
            return 0;
        }
    } else {
        for (int i = first; i < argc - 1; i++) {
            if (strchr(argv[i], ':') && !strchr(argv[i], '/')) {
                tn_puts(s, "scp: copying between two remote machines is not supported\n");
                return 0;
            }
        }
    }
    if (strlen(rpath) > C3_PATH_MAX * 2 || !shell_quote(q, sizeof q, rpath)) {
        tn_puts(s, "scp: remote path too long\n");
        return 0;
    }
    if (ruser)
        snprintf(user, sizeof user, "%s", ruser);
    else
        snprintf(user, sizeof user, "%s", s->user);

    /* local side first, so a typo is caught before connecting */
    char local[C3_PATH_MAX];
    if (!up) {
        int r = fs_resolve(s, nops == 2 ? argv[argc - 1] : ".", local, sizeof local);
        if (r < 0) {
            tn_printf(s, "scp: %s: %s\n", argv[argc - 1], strerror(-r));
            return 0;
        }
    }

    if (up)
        snprintf(cmd, sizeof cmd, "scp %s%s-t -- %s", recursive ? "-r " : "", nops > 2 ? "-d " : "", q);
    else
        snprintf(cmd, sizeof cmd, "scp %s-f -- %s", recursive ? "-r " : "", q);

    sshc_t *c = sshc_open(s, user, rhost, port, cmd);
    if (!c)
        return s->closed;
    xs_t *x = calloc(1, sizeof *x);
    if (!x) {
        sshc_close(c);
        tn_puts(s, "scp: out of memory\n");
        return 0;
    }
    x->s = s;
    x->c = c;
    x->show = true;
    x->recursive = recursive;

    if (up) {
        int r = scp_wait(x);
        for (int i = first; r == 0 && i < argc - 1; i++) {
            char vpath[C3_PATH_MAX];
            int e = fs_resolve(s, argv[i], vpath, sizeof vpath);
            if (e < 0) {
                tn_printf(s, "scp: %s: %s\n", argv[i], strerror(-e));
                x->failed = true;
                continue;
            }
            if (scp_send(x, vpath, 0) < 0)
                r = -1;
        }
        sshc_send_eof(c);
    } else {
        scp_receive(x, local, 0);
    }
    /* drain until the remote scp exits, showing anything it still says */
    uint8_t tmp[256];
    bool err;
    for (int n; (n = sshc_read(c, tmp, sizeof tmp, 3000, &err)) > 0;)
        if (err)
            tn_write(s, tmp, (size_t)n);
    int st = sshc_exit_status(c);
    if (st != 0 && !x->failed)
        tn_printf(s, "scp: the remote scp exited with status %d\n", st);
    sshc_close(c);
    free(x);
    return s->closed;
}
