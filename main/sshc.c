/* Outbound SSH client: bridges the user's session to an interactive shell on
 * another machine. Host keys are trusted on first use and pinned afterwards; login
 * tries the device's own key first, then password / keyboard-interactive. */
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>   /* supportedAuth: lets us order the auth methods */

#include "c3shell.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define KBD_MAX 4

typedef struct {
    session_t *s;
    WOLFSSH   *ssh;
    sshio_t    io;
    char       target[80];           /* user@host, for prompts */
    char       khname[64];           /* known-hosts key */
    /* auth state */
    bool       use_key, key_offered, prompted, aborted, hostkey_bad;
    int        pw_tries;
    char       pw[128];
    uint8_t    der[128];
    int        derlen;
    uint8_t    pubblob[51];
    char       kb_resp[KBD_MAX][128];
    byte      *kb_ptr[KBD_MAX];
    word32     kb_len[KBD_MAX];
} sshc_t;

/* ---------------- transport ---------------- */

static int dial(session_t *s, const char *host, int port)
{
    struct addrinfo hints = { 0 }, *res = NULL;
    char portstr[8];
    int fd = -1;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof portstr, "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) {
        tn_printf(s, "ssh: could not resolve hostname %s\n", host);
        return -1;
    }
    fd = socket(res->ai_family, res->ai_socktype, 0);
    if (fd >= 0) {
        int fl = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        int r = connect(fd, res->ai_addr, res->ai_addrlen);
        if (r < 0 && errno == EINPROGRESS) {
            fd_set wr;
            struct timeval tv = { C3_SSH_CONNECT_MS / 1000, (C3_SSH_CONNECT_MS % 1000) * 1000 };
            int err = 0;
            socklen_t len = sizeof err;
            FD_ZERO(&wr);
            FD_SET(fd, &wr);
            r = -1;
            if (select(fd + 1, NULL, &wr, NULL, &tv) > 0 &&
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0) {
                if (err == 0)
                    r = 0;
                else
                    errno = err;
            } else {
                errno = ETIMEDOUT;
            }
        }
        if (r < 0) {
            tn_printf(s, "ssh: connect to %s port %d: %s\n", host, port, strerror(errno));
            close(fd);
            fd = -1;
        } else {
            int on = 1;
            struct timeval tv = { 10, 0 };
            fcntl(fd, F_SETFL, fl);
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
            setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on);
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        }
    }
    freeaddrinfo(res);
    return fd;
}

/* ---------------- callbacks ---------------- */

static int hostkey_cb(const byte *key, word32 sz, void *vctx)
{
    sshc_t *c = vctx;
    session_t *s = c->s;
    uint8_t fp[32];
    char fptxt[64], type[24] = "unknown";

    if (wc_Sha256Hash(key, sz, fp) != 0)
        return -1;
    sshstore_fp_text(fp, fptxt, sizeof fptxt);
    if (sz > 4) {
        word32 tl = (word32)key[0] << 24 | (word32)key[1] << 16 | (word32)key[2] << 8 | key[3];
        if (tl < sizeof type && tl + 4 <= sz) {
            memcpy(type, key + 4, tl);
            type[tl] = 0;
        }
    }

    switch (sshstore_host_check(c->khname, fp)) {
    case KH_MATCH:
        return 0;
    case KH_CHANGED:
        tn_printf(s,
                  "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
                  "@  WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!       @\n"
                  "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
                  "The %s host key for %s does not match the one saved earlier.\n"
                  "Someone could be intercepting the connection, or the host was reinstalled.\n"
                  "Offered fingerprint: %s\n"
                  "If this is expected, run 'hosts forget %s' and connect again.\n",
                  type, c->khname, fptxt, c->khname);
        c->hostkey_bad = true;
        return -1;
    default: {
        char ans[8];
        tn_printf(s, "The authenticity of host '%s' can't be established.\n%s key fingerprint is %s\n",
                  c->khname, type, fptxt);
        int n = tn_readline(s, "Trust this host and continue (yes/no)? ", ans, sizeof ans, RL_ECHO, 60);
        if (n == 3 && strcmp(ans, "yes") == 0) {
            sshstore_host_add(c->khname, fp);
            tn_printf(s, "Host '%s' added to the list of known hosts.\n", c->khname);
            return 0;
        }
        c->hostkey_bad = true;
        return -1;
    }
    }
}

static int auth_cb(byte type, WS_UserAuthData *d, void *vctx)
{
    sshc_t *c = vctx;
    session_t *s = c->s;

    if (type == WOLFSSH_USERAUTH_PUBLICKEY) {
        if (!c->use_key || c->derlen <= 0)
            return WOLFSSH_USERAUTH_FAILURE;
        d->sf.publicKey.publicKeyType = (const byte *)"ssh-ed25519";
        d->sf.publicKey.publicKeyTypeSz = 11;
        d->sf.publicKey.publicKey = c->pubblob;
        d->sf.publicKey.publicKeySz = sizeof c->pubblob;
        d->sf.publicKey.privateKey = c->der;
        d->sf.publicKey.privateKeySz = (word32)c->derlen;
        c->key_offered = true;
        /* If the server turns the key down, fall back to the interactive methods. */
        c->ssh->supportedAuth[0] = ID_USERAUTH_PASSWORD;
        c->ssh->supportedAuth[1] = ID_USERAUTH_KEYBOARD;
        c->ssh->supportedAuth[2] = ID_NONE;
        c->ssh->supportedAuth[3] = ID_NONE;
        return WOLFSSH_USERAUTH_SUCCESS;
    }

    if (type == WOLFSSH_USERAUTH_PASSWORD) {
        char prompt[112];
        /* Let the key go first when the server would accept one. */
        if (c->use_key && !c->key_offered && (d->type & WOLFSSH_USERAUTH_PUBLICKEY))
            return WOLFSSH_USERAUTH_FAILURE;
        if (c->aborted || c->pw_tries >= 3)
            return WOLFSSH_USERAUTH_FAILURE;
        if (c->pw_tries > 0)
            tn_puts(s, "Permission denied, please try again.\n");
        snprintf(prompt, sizeof prompt, "%s's password: ", c->target);
        int n = tn_readline(s, prompt, c->pw, sizeof c->pw, 0, 120);
        c->prompted = true;
        if (n < 0) {
            c->aborted = true;
            return WOLFSSH_USERAUTH_FAILURE;
        }
        c->pw_tries++;
        d->sf.password.password = (const byte *)c->pw;
        d->sf.password.passwordSz = (word32)n;
        return WOLFSSH_USERAUTH_SUCCESS;
    }

    if (type == WOLFSSH_USERAUTH_KEYBOARD) {
        WS_UserAuthData_Keyboard *kb = &d->sf.keyboard;
        if (c->aborted || kb->promptCount > KBD_MAX)
            return WOLFSSH_USERAUTH_FAILURE;
        if (kb->promptName && kb->promptName[0])
            tn_printf(s, "%s\n", (const char *)kb->promptName);
        if (kb->promptInstruction && kb->promptInstruction[0])
            tn_printf(s, "%s\n", (const char *)kb->promptInstruction);
        for (word32 i = 0; i < kb->promptCount; i++) {
            const char *p = kb->prompts && kb->prompts[i] ? (const char *)kb->prompts[i] : "Response: ";
            int echo = kb->promptEcho && kb->promptEcho[i] ? RL_ECHO : 0;
            int n = tn_readline(s, p, c->kb_resp[i], sizeof c->kb_resp[i], echo, 120);
            c->prompted = true;
            if (n < 0) {
                c->aborted = true;
                return WOLFSSH_USERAUTH_FAILURE;
            }
            c->kb_ptr[i] = (byte *)c->kb_resp[i];
            c->kb_len[i] = (word32)n;
        }
        kb->responseCount = kb->promptCount;
        kb->responses = c->kb_ptr;
        kb->responseLengths = c->kb_len;
        return WOLFSSH_USERAUTH_SUCCESS;
    }
    return WOLFSSH_USERAUTH_FAILURE;
}

/* ---------------- interactive bridge ---------------- */

static void bridge(sshc_t *c)
{
    session_t *s = c->s;
    uint8_t *buf = malloc(1024 + 256 + 512);
    uint8_t *in = buf ? buf + 1024 : NULL, *out = buf ? buf + 1280 : NULL;
    enum { E_LINE_START, E_TILDE, E_MID } esc = E_LINE_START;

    if (!buf)
        return;
    c->io.nonblock = true;

    while (!s->closed && !s->kick) {
        bool busy = false;

        /* user -> remote */
        int n = tn_read_avail(s, in, 256);
        if (n == TN_CLOSED)
            break;
        if (s->winch) {
            s->winch = false;
            wolfSSH_ChangeTerminalSize(c->ssh, s->cols, s->rows, 0, 0);
        }
        if (n > 0) {
            int o = 0;
            busy = true;
            for (int i = 0; i < n; i++) {           /* "~." at the start of a line hangs up */
                uint8_t ch = in[i];
                if (esc == E_TILDE) {
                    if (ch == '.') {
                        tn_puts(s, "\n");
                        goto done;
                    }
                    if (ch != '~')
                        out[o++] = '~';
                    out[o++] = ch;
                    esc = E_MID;
                } else if (esc == E_LINE_START && ch == '~') {
                    esc = E_TILDE;
                } else {
                    out[o++] = ch;
                    esc = (ch == '\r' || ch == '\n') ? E_LINE_START : E_MID;
                }
            }
            if (o > 0 && sshio_write(c->ssh, &c->io, out, o) < 0)
                break;
        }

        /* remote -> user (a bounded burst, so typing stays responsive during floods) */
        for (int i = 0; i < 16; i++) {
            n = sshio_read(c->ssh, buf, 1024);
            if (n < 0)
                goto done;
            if (n == 0)
                break;
            busy = true;
            if (tn_write(s, buf, (size_t)n) < 0)
                goto done;
        }

        if (!busy) {
            fd_set rd;
            struct timeval tv = { 1, 0 };
            int maxfd = s->io.fd > c->io.fd ? s->io.fd : c->io.fd;
            FD_ZERO(&rd);
            FD_SET(s->io.fd, &rd);
            FD_SET(c->io.fd, &rd);
            if (select(maxfd + 1, &rd, NULL, NULL, &tv) < 0 && errno != EINTR)
                break;
        }
    }
done:
    free(buf);
}

/* ---------------- entry point ---------------- */

static int attempt(sshc_t *c, const char *user, const char *host, int port, int *err)
{
    session_t *s = c->s;
    WOLFSSH_CTX *ctx = NULL;
    int ret = -1;

    *err = 0;
    c->io.fd = dial(s, host, port);
    if (c->io.fd < 0)
        return -1;
    c->io.kick = &s->kick;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx) {
        sshio_ctx_setup(ctx);
        wolfSSH_SetUserAuth(ctx, auth_cb);
        wolfSSH_CTX_SetPublicKeyCheck(ctx, hostkey_cb);
        c->ssh = wolfSSH_new(ctx);
    }
    if (!c->ssh) {
        tn_puts(s, "ssh: out of memory\n");
        goto out;
    }
    sshio_attach(c->ssh, &c->io);
    wolfSSH_SetUserAuthCtx(c->ssh, c);
    wolfSSH_SetPublicKeyCheckCtx(c->ssh, c);
    wolfSSH_SetUsername(c->ssh, user);
    wolfSSH_SetChannelType(c->ssh, WOLFSSH_SESSION_TERMINAL, NULL, 0);
    if (c->use_key) {
        /* Hold keyboard-interactive back until the key has had its turn. */
        c->ssh->supportedAuth[0] = ID_USERAUTH_PUBLICKEY;
        c->ssh->supportedAuth[1] = ID_USERAUTH_PASSWORD;
        c->ssh->supportedAuth[2] = ID_NONE;
        c->ssh->supportedAuth[3] = ID_NONE;
    }

    c->io.nonblock = false;
    c->io.io_ms = C3_SSH_IO_MS;
    if (wolfSSH_connect(c->ssh) != WS_SUCCESS) {
        *err = wolfSSH_get_error(c->ssh);
        goto out;
    }
    ret = 0;
    if (s->cols != 80 || s->rows != 24)
        wolfSSH_ChangeTerminalSize(c->ssh, s->cols, s->rows, 0, 0);
    s->winch = false;
    bridge(c);
    c->io.nonblock = false;
    c->io.io_ms = 1500;
    wolfSSH_shutdown(c->ssh);
out:
    if (c->ssh)
        wolfSSH_free(c->ssh);
    if (ctx)
        wolfSSH_CTX_free(ctx);
    c->ssh = NULL;
    close(c->io.fd);
    return ret;
}

int ssh_run(session_t *s, const char *user, const char *host, int port)
{
    static const uint8_t head[] = { 0, 0, 0, 11, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9', 0, 0, 0, 32 };
    sshc_t *c = calloc(1, sizeof *c);
    int err = 0, ret;

    if (!c) {
        tn_puts(s, "ssh: out of memory\n");
        return -1;
    }
    c->s = s;
    snprintf(c->target, sizeof c->target, "%.31s@%.40s", user, host);
    if (port == 22)
        snprintf(c->khname, sizeof c->khname, "%.60s", host);
    else
        snprintf(c->khname, sizeof c->khname, "[%.50s]:%d", host, port);

    memcpy(c->pubblob, head, sizeof head);
    c->derlen = sshstore_identity(c->der, sizeof c->der, c->pubblob + sizeof head);
    c->use_key = c->derlen > 0;

    ret = attempt(c, user, host, port, &err);
    if (ret < 0 && c->use_key && !c->key_offered && !c->prompted && !c->hostkey_bad &&
        !s->closed && err == WS_USER_AUTH_E) {
        /* The server offers neither public-key nor password logins (only
         * keyboard-interactive): go again without holding that method back. */
        c->use_key = false;
        ret = attempt(c, user, host, port, &err);
    }

    if (ret == 0) {
        tn_printf(s, "\nConnection to %s closed.\n", host);
    } else if (err != 0 && !s->closed) {
        if (c->hostkey_bad)
            tn_puts(s, "Host key verification failed.\n");
        else if (c->aborted)
            tn_puts(s, "ssh: cancelled.\n");
        else if (err == WS_USER_AUTH_E || c->prompted || c->key_offered) {
            tn_printf(s, "%s: Permission denied.\n", c->target);
            if (!c->prompted)
                tn_puts(s, "The server only accepts keys: run 'sshkey' and add the line it prints to\n"
                           "~/.ssh/authorized_keys on that machine.\n");
        } else
            tn_printf(s, "ssh: connection to %s failed (%s)\n", host, wolfSSH_ErrorToName(err));
    }
    memset(c, 0, sizeof *c);
    free(c);
    return ret;
}
