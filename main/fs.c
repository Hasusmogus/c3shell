/* The user's file area and the basic Unix-style commands that work on it.
 *
 * Every path the user types is resolved here, against the session's current
 * directory, into a normalized path inside the file area's root ("/" to the
 * user). ".." stops at that root and there is no way to name anything outside
 * it - the firmware, the account and the keys live in other flash partitions
 * that this code cannot address at all. */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "c3shell.h"

/* ---------------- paths ---------------- */

int fs_resolve(session_t *s, const char *arg, char *vpath, size_t vcap)
{
    char tmp[C3_PATH_MAX * 2];
    char out[C3_PATH_MAX];
    size_t olen = 0;

    if (!arg || !*arg)
        arg = ".";
    if (strlen(arg) >= C3_PATH_MAX)
        return -ENAMETOOLONG;
    if (arg[0] == '/')
        snprintf(tmp, sizeof tmp, "%s", arg);
    else
        snprintf(tmp, sizeof tmp, "%s/%s", s->cwd, arg);

    out[0] = 0;
    for (char *save = NULL, *c = strtok_r(tmp, "/", &save); c; c = strtok_r(NULL, "/", &save)) {
        if (strcmp(c, ".") == 0)
            continue;
        if (strcmp(c, "..") == 0) {         /* up one level, but never above the root */
            char *slash = strrchr(out, '/');
            olen = slash ? (size_t)(slash - out) : 0;
            out[olen] = 0;
            continue;
        }
        size_t n = strlen(c);
        if (n >= C3_NAME_MAX)
            return -ENAMETOOLONG;
        for (const char *p = c; *p; p++)
            if ((unsigned char)*p < 0x20 || *p == 0x7F)
                return -EINVAL;
        if (olen + 1 + n >= sizeof out)
            return -ENAMETOOLONG;
        out[olen++] = '/';
        memcpy(out + olen, c, n + 1);
        olen += n;
    }
    snprintf(vpath, vcap, "%s", olen ? out : "/");
    return 0;
}

int fs_host(const char *vpath, char *host, size_t cap)
{
    int n = snprintf(host, cap, "%s%s", port_fs_root(), strcmp(vpath, "/") == 0 ? "" : vpath);
    return n < 0 || (size_t)n >= cap ? -ENAMETOOLONG : 0;
}

/* resolve + map in one go; prints "cmd: arg: error" on failure */
static int path_of(session_t *s, const char *cmd, const char *arg, char *vpath, char *host)
{
    int r = fs_resolve(s, arg, vpath, C3_PATH_MAX);
    if (r < 0) {
        tn_printf(s, "%s: %s: %s\n", cmd, arg, strerror(-r));
        return r;
    }
    if (fs_host(vpath, host, C3_HOST_MAX) != 0) {
        tn_printf(s, "%s: %s: %s\n", cmd, arg, strerror(ENAMETOOLONG));
        return -ENAMETOOLONG;
    }
    return 0;
}

static const char *base(const char *vpath)
{
    const char *b = strrchr(vpath, '/');
    return b ? b + 1 : vpath;
}

static bool is_dir(const char *host)
{
    struct stat st;
    return stat(host, &st) == 0 && S_ISDIR(st.st_mode);
}

static bool exists(const char *host)
{
    struct stat st;
    return stat(host, &st) == 0;
}

/* split "-xyz" style options off the front of argv; returns the first operand index */
static int opts(int argc, char **argv, const char *allowed, bool flag[128], session_t *s)
{
    int i = 1;
    memset(flag, 0, 128);
    for (; i < argc && argv[i][0] == '-' && argv[i][1]; i++) {
        if (strcmp(argv[i], "--") == 0)
            return i + 1;
        for (const char *p = argv[i] + 1; *p; p++) {
            if (!strchr(allowed, *p)) {
                tn_printf(s, "%s: unknown option -%c\n", argv[0], *p);
                return -1;
            }
            flag[(unsigned char)*p] = true;
        }
    }
    return i;
}

/* ---------------- file I/O helpers (shared with vi) ---------------- */

int fs_read_file(const char *host, char **data, size_t *len, size_t max)
{
    struct stat st;
    int fd = open(host, O_RDONLY);
    if (fd < 0)
        return -errno;
    if (fstat(fd, &st) != 0 || S_ISDIR(st.st_mode)) {
        close(fd);
        return -EISDIR;
    }
    if ((size_t)st.st_size > max) {
        close(fd);
        return -EFBIG;
    }
    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf) {
        close(fd);
        return -ENOMEM;
    }
    size_t got = 0;
    while (got < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + got, (size_t)st.st_size - got);
        if (n <= 0)
            break;
        got += (size_t)n;
    }
    close(fd);
    buf[got] = 0;
    *data = buf;
    *len = got;
    return 0;
}

/* Replace a file's contents without ever leaving it half-written: write a
 * temporary file next to it, then rename it over the original. */
int fs_write_file(const char *host, const char *data, size_t len)
{
    char tmp[C3_PATH_MAX + 24];
    snprintf(tmp, sizeof tmp, "%s.~tmp", host);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -errno;
    size_t done = 0;
    int err = 0;
    while (done < len) {
        ssize_t n = write(fd, data + done, len - done);
        if (n <= 0) {
            err = n < 0 ? errno : ENOSPC;
            break;
        }
        done += (size_t)n;
    }
    if (close(fd) != 0 && !err)
        err = errno;
    if (!err && rename(tmp, host) != 0) {
        /* some file systems will not rename over an existing file */
        if (unlink(host) != 0 || rename(tmp, host) != 0)
            err = errno ? errno : EIO;
    }
    if (err) {
        unlink(tmp);
        return -err;
    }
    return 0;
}

/* ---------------- commands ---------------- */

typedef struct {
    char name[C3_NAME_MAX];
    bool dir;
    long size;
} ent_t;

static int ent_cmp(const void *a, const void *b)
{
    return strcmp(((const ent_t *)a)->name, ((const ent_t *)b)->name);
}

static void ls_one(session_t *s, const char *vpath, const char *host, bool lng, bool all, bool header)
{
    struct stat st;
    if (stat(host, &st) != 0) {
        tn_printf(s, "ls: %s: %s\n", vpath, strerror(errno));
        return;
    }
    if (!S_ISDIR(st.st_mode)) {
        if (lng)
            tn_printf(s, "-  %8ld  %s\n", (long)st.st_size, base(vpath));
        else
            tn_printf(s, "%s\n", base(vpath));
        return;
    }

    DIR *d = opendir(host);
    if (!d) {
        tn_printf(s, "ls: %s: %s\n", vpath, strerror(errno));
        return;
    }
    int cap = 32, n = 0;
    ent_t *e = malloc(sizeof *e * (size_t)cap);
    struct dirent *de;
    while (e && (de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (de->d_name[0] == '.' && !all)
            continue;
        if (n == cap) {
            ent_t *ne = realloc(e, sizeof *e * (size_t)(cap *= 2));
            if (!ne)
                break;
            e = ne;
        }
        char p[C3_HOST_MAX + C3_NAME_MAX];
        struct stat es;
        snprintf(e[n].name, sizeof e[n].name, "%.*s", C3_NAME_MAX - 1, de->d_name);
        snprintf(p, sizeof p, "%s/%.*s", host, C3_NAME_MAX - 1, de->d_name);
        e[n].dir = stat(p, &es) == 0 && S_ISDIR(es.st_mode);
        e[n].size = e[n].dir ? 0 : (long)es.st_size;
        n++;
    }
    closedir(d);
    if (!e)
        return;
    qsort(e, (size_t)n, sizeof *e, ent_cmp);

    if (header)
        tn_printf(s, "%s:\n", vpath);
    if (lng) {
        for (int i = 0; i < n; i++)
            if (e[i].dir)
                tn_printf(s, "d  %8s  %s/\n", "-", e[i].name);
            else
                tn_printf(s, "-  %8ld  %s\n", e[i].size, e[i].name);
    } else if (n > 0) {
        /* columns, like ls on a terminal */
        int w = 0;
        for (int i = 0; i < n; i++) {
            int l = (int)strlen(e[i].name) + (e[i].dir ? 1 : 0);
            if (l > w)
                w = l;
        }
        w += 2;
        int per = s->cols / w;
        if (per < 1)
            per = 1;
        int rows = (n + per - 1) / per;
        for (int r = 0; r < rows; r++) {
            for (int c = 0; c < per; c++) {
                int i = c * rows + r;
                if (i >= n)
                    break;
                char cell[C3_NAME_MAX + 2];
                snprintf(cell, sizeof cell, "%s%s", e[i].name, e[i].dir ? "/" : "");
                bool last = c == per - 1 || (c + 1) * rows + r >= n;
                if (last)
                    tn_printf(s, "%s", cell);
                else
                    tn_printf(s, "%-*s", w, cell);
            }
            tn_puts(s, "\n");
        }
    }
    free(e);
}

int cmd_ls(session_t *s, int argc, char **argv)
{
    bool f[128];
    char v[C3_PATH_MAX], h[C3_HOST_MAX];
    int i = opts(argc, argv, "la", f, s);
    if (i < 0)
        return 0;
    if (i == argc) {
        if (path_of(s, "ls", ".", v, h) == 0)
            ls_one(s, v, h, f['l'], f['a'], false);
        return 0;
    }
    for (int j = i; j < argc; j++) {
        if (path_of(s, "ls", argv[j], v, h) == 0) {
            ls_one(s, v, h, f['l'], f['a'], argc - i > 1 && is_dir(h));
            if (j + 1 < argc && argc - i > 1 && is_dir(h))
                tn_puts(s, "\n");
        }
    }
    return 0;
}

int cmd_cd(session_t *s, int argc, char **argv)
{
    char v[C3_PATH_MAX], h[C3_HOST_MAX];
    if (argc > 2) {
        tn_puts(s, "usage: cd [directory]\n");
        return 0;
    }
    if (path_of(s, "cd", argc > 1 ? argv[1] : "/", v, h) != 0)
        return 0;
    if (!exists(h))
        tn_printf(s, "cd: %s: No such file or directory\n", argv[1]);
    else if (!is_dir(h))
        tn_printf(s, "cd: %s: Not a directory\n", argv[1]);
    else
        snprintf(s->cwd, sizeof s->cwd, "%s", v);
    return 0;
}

int cmd_pwd(session_t *s, int argc, char **argv)
{
    (void)argc;
    (void)argv;
    tn_printf(s, "%s\n", s->cwd);
    return 0;
}

static int mkdir_p(const char *host)
{
    char p[C3_HOST_MAX];
    size_t root = strlen(port_fs_root());
    snprintf(p, sizeof p, "%s", host);
    for (char *c = p + root + 1; *c; c++) {
        if (*c != '/')
            continue;
        *c = 0;
        if (!is_dir(p) && mkdir(p, 0755) != 0)
            return -errno;
        *c = '/';
    }
    if (is_dir(p))
        return 0;
    return mkdir(p, 0755) == 0 ? 0 : -errno;
}

int cmd_mkdir(session_t *s, int argc, char **argv)
{
    bool f[128];
    char v[C3_PATH_MAX], h[C3_HOST_MAX];
    int i = opts(argc, argv, "p", f, s);
    if (i < 0)
        return 0;
    if (i == argc)
        tn_puts(s, "usage: mkdir [-p] directory...\n");
    for (; i < argc; i++) {
        if (path_of(s, "mkdir", argv[i], v, h) != 0)
            continue;
        int r = f['p'] ? mkdir_p(h) : (mkdir(h, 0755) == 0 ? 0 : -errno);
        if (r < 0)
            tn_printf(s, "mkdir: %s: %s\n", argv[i], strcmp(v, "/") == 0 ? "File exists" : strerror(-r));
    }
    return 0;
}

int cmd_rmdir(session_t *s, int argc, char **argv)
{
    char v[C3_PATH_MAX], h[C3_HOST_MAX];
    if (argc < 2)
        tn_puts(s, "usage: rmdir directory...\n");
    for (int i = 1; i < argc; i++) {
        if (path_of(s, "rmdir", argv[i], v, h) != 0)
            continue;
        if (strcmp(v, "/") == 0)
            tn_printf(s, "rmdir: %s: cannot remove the root directory\n", argv[i]);
        else if (!is_dir(h))
            tn_printf(s, "rmdir: %s: %s\n", argv[i], exists(h) ? "Not a directory" : "No such file or directory");
        else if (rmdir(h) != 0)
            tn_printf(s, "rmdir: %s: %s\n", argv[i], errno == EEXIST ? "Directory not empty" : strerror(errno));
    }
    return 0;
}

/* Remove a directory tree. Names are gathered before deleting anything, so
 * the directory is never modified while it is being read. */
static int rm_tree(const char *host, int depth)
{
    if (depth > 32)
        return -ELOOP;
    if (!is_dir(host))
        return unlink(host) == 0 ? 0 : -errno;

    for (;;) {
        char names[8][C3_NAME_MAX];
        int n = 0;
        DIR *d = opendir(host);
        struct dirent *de;
        if (!d)
            return -errno;
        while (n < 8 && (de = readdir(d)))
            if (strcmp(de->d_name, ".") && strcmp(de->d_name, ".."))
                snprintf(names[n++], C3_NAME_MAX, "%.*s", C3_NAME_MAX - 1, de->d_name);
        closedir(d);
        if (n == 0)
            break;
        for (int i = 0; i < n; i++) {
            char p[C3_HOST_MAX + C3_NAME_MAX];
            snprintf(p, sizeof p, "%s/%.*s", host, C3_NAME_MAX - 1, names[i]);
            int r = rm_tree(p, depth + 1);
            if (r < 0)
                return r;
        }
    }
    return rmdir(host) == 0 ? 0 : -errno;
}

int cmd_rm(session_t *s, int argc, char **argv)
{
    bool f[128];
    char v[C3_PATH_MAX], h[C3_HOST_MAX];
    int i = opts(argc, argv, "rRf", f, s);
    bool rec = f['r'] || f['R'];
    if (i < 0)
        return 0;
    if (i == argc && !f['f'])
        tn_puts(s, "usage: rm [-r] [-f] file...\n");
    for (; i < argc; i++) {
        if (path_of(s, "rm", argv[i], v, h) != 0)
            continue;
        if (strcmp(v, "/") == 0) {
            tn_puts(s, "rm: refusing to remove '/'\n");
            continue;
        }
        if (strncmp(s->cwd, v, strlen(v)) == 0 && (s->cwd[strlen(v)] == 0 || s->cwd[strlen(v)] == '/')) {
            tn_printf(s, "rm: %s: you are inside it - cd somewhere else first\n", argv[i]);
            continue;
        }
        if (!exists(h)) {
            if (!f['f'])
                tn_printf(s, "rm: %s: No such file or directory\n", argv[i]);
            continue;
        }
        if (is_dir(h) && !rec) {
            tn_printf(s, "rm: %s: is a directory (use rm -r)\n", argv[i]);
            continue;
        }
        int r = rm_tree(h, 0);
        if (r < 0)
            tn_printf(s, "rm: %s: %s\n", argv[i], strerror(-r));
    }
    return 0;
}

int cmd_touch(session_t *s, int argc, char **argv)
{
    char v[C3_PATH_MAX], h[C3_HOST_MAX];
    if (argc < 2)
        tn_puts(s, "usage: touch file...\n");
    for (int i = 1; i < argc; i++) {
        if (path_of(s, "touch", argv[i], v, h) != 0 || exists(h))
            continue;
        int fd = open(h, O_WRONLY | O_CREAT, 0644);
        if (fd < 0)
            tn_printf(s, "touch: %s: %s\n", argv[i], strerror(errno));
        else
            close(fd);
    }
    return 0;
}

int cmd_cat(session_t *s, int argc, char **argv)
{
    char v[C3_PATH_MAX], h[C3_HOST_MAX];
    uint8_t in[256], out[512];
    if (argc < 2)
        tn_puts(s, "usage: cat file...\n");
    for (int i = 1; i < argc && !s->closed; i++) {
        if (path_of(s, "cat", argv[i], v, h) != 0)
            continue;
        if (is_dir(h)) {
            tn_printf(s, "cat: %s: Is a directory\n", argv[i]);
            continue;
        }
        int fd = open(h, O_RDONLY);
        if (fd < 0) {
            tn_printf(s, "cat: %s: %s\n", argv[i], strerror(errno));
            continue;
        }
        ssize_t n;
        uint8_t last = '\n';
        while ((n = read(fd, in, sizeof in)) > 0 && !s->closed) {
            int o = 0;
            for (ssize_t k = 0; k < n; k++) {
                if (in[k] == '\n' && last != '\r')
                    out[o++] = '\r';
                out[o++] = last = in[k];
            }
            tn_write(s, out, (size_t)o);
        }
        close(fd);
    }
    return 0;
}

static int copy_file(const char *from, const char *to)
{
    char *data;
    size_t len;
    int r = fs_read_file(from, &data, &len, (size_t)-1 / 2);
    if (r < 0)
        return r;
    r = fs_write_file(to, data, len);
    free(data);
    return r;
}

/* For cp/mv: if the destination is a directory, the source goes inside it. */
static void target_in(session_t *s, const char *src_v, char *dst_v, char *dst_h)
{
    (void)s;
    if (is_dir(dst_h)) {
        size_t l = strlen(dst_v);
        if (snprintf(dst_v + l, C3_PATH_MAX - l, "%s%s", l > 1 ? "/" : "", base(src_v)) >= (int)(C3_PATH_MAX - l) ||
            fs_host(dst_v, dst_h, C3_HOST_MAX) != 0)
            dst_v[C3_PATH_MAX - 1] = 1;     /* flag "too long" for the caller's length check */
    }
}

int cmd_cp(session_t *s, int argc, char **argv)
{
    char sv[C3_PATH_MAX], sh[C3_HOST_MAX], dv[C3_PATH_MAX], dh[C3_HOST_MAX];
    if (argc != 3) {
        tn_puts(s, "usage: cp source destination\n");
        return 0;
    }
    if (path_of(s, "cp", argv[1], sv, sh) || path_of(s, "cp", argv[2], dv, dh))
        return 0;
    if (!exists(sh)) {
        tn_printf(s, "cp: %s: No such file or directory\n", argv[1]);
        return 0;
    }
    if (is_dir(sh)) {
        tn_printf(s, "cp: %s: is a directory (not supported)\n", argv[1]);
        return 0;
    }
    target_in(s, sv, dv, dh);
    if (strlen(dv) >= C3_PATH_MAX - 1) {
        tn_puts(s, "cp: destination path too long\n");
        return 0;
    }
    if (strcmp(sv, dv) == 0) {
        tn_printf(s, "cp: %s and %s are the same file\n", argv[1], argv[2]);
        return 0;
    }
    int r = copy_file(sh, dh);
    if (r < 0)
        tn_printf(s, "cp: %s: %s\n", argv[2], strerror(-r));
    return 0;
}

int cmd_mv(session_t *s, int argc, char **argv)
{
    char sv[C3_PATH_MAX], sh[C3_HOST_MAX], dv[C3_PATH_MAX], dh[C3_HOST_MAX];
    if (argc != 3) {
        tn_puts(s, "usage: mv source destination\n");
        return 0;
    }
    if (path_of(s, "mv", argv[1], sv, sh) || path_of(s, "mv", argv[2], dv, dh))
        return 0;
    if (strcmp(sv, "/") == 0 || !exists(sh)) {
        tn_printf(s, "mv: %s: %s\n", argv[1], exists(sh) ? "cannot move the root directory" : "No such file or directory");
        return 0;
    }
    target_in(s, sv, dv, dh);
    if (strlen(dv) >= C3_PATH_MAX - 1) {
        tn_puts(s, "mv: destination path too long\n");
        return 0;
    }
    size_t sl = strlen(sv);
    if (strncmp(dv, sv, sl) == 0 && (dv[sl] == '/' || dv[sl] == 0)) {
        if (dv[sl] == 0)
            return 0;                       /* moved onto itself */
        tn_printf(s, "mv: cannot move %s into itself\n", argv[1]);
        return 0;
    }
    if (exists(dh)) {
        if (is_dir(dh)) {
            tn_printf(s, "mv: %s: a directory with that name exists\n", dv);
            return 0;
        }
        if (is_dir(sh)) {
            tn_printf(s, "mv: %s: a file with that name exists\n", dv);
            return 0;
        }
        unlink(dh);                         /* replacing a file, like mv does */
    }
    if (rename(sh, dh) != 0)
        tn_printf(s, "mv: %s: %s\n", argv[1], strerror(errno));
    return 0;
}

int cmd_df(session_t *s, int argc, char **argv)
{
    long total = 0, used = 0;
    (void)argc;
    (void)argv;
    if (port_fs_usage(&total, &used) != 0 || total <= 0) {
        tn_puts(s, "df: file area not available\n");
        return 0;
    }
    tn_printf(s, "%ld KB used of %ld KB (%ld%%), %ld KB free\n", used / 1024, total / 1024, used * 100 / total,
              (total - used) / 1024);
    return 0;
}
