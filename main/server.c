/* SSH server: listener, login (password against the device account), and
 * the session table. One thread per connection. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssh/ssh.h>

#include "c3shell.h"

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static session_t *slots[C3_MAX_SESSIONS];
static session_t *console_s;
static WOLFSSH_CTX *srv_ctx;

/* ---------------- brute-force guard ---------------- */

#define GUARD_N 8
int guard_block_s = C3_GUARD_BLOCK_S;
static struct { uint32_t ip, until_s, last_s; uint8_t fails; } guard[GUARD_N];

static bool guard_blocked(uint32_t ip)
{
    bool b = false;
    pthread_mutex_lock(&lock);
    for (int i = 0; i < GUARD_N; i++)
        if (guard[i].ip == ip && guard[i].until_s > port_uptime_s())
            b = true;
    pthread_mutex_unlock(&lock);
    return b;
}

/* Record a wrong password; true if the address is now blocked. */
static bool guard_fail(uint32_t ip)
{
    int slot = 0;
    bool blocked = false;
    uint32_t now = port_uptime_s();
    pthread_mutex_lock(&lock);
    for (int i = 0; i < GUARD_N; i++) {
        if (guard[i].ip == ip) {
            slot = i;
            break;
        }
        if (guard[i].last_s < guard[slot].last_s)   /* otherwise reuse the stalest entry */
            slot = i;
    }
    if (guard[slot].ip != ip) {
        guard[slot].ip = ip;
        guard[slot].fails = 0;
        guard[slot].until_s = 0;
    }
    guard[slot].last_s = now ? now : 1;
    if (++guard[slot].fails >= C3_GUARD_FAILS) {
        guard[slot].fails = 0;
        guard[slot].until_s = now + (uint32_t)guard_block_s;
        blocked = true;
    }
    pthread_mutex_unlock(&lock);
    return blocked;
}

static void guard_ok(uint32_t ip)
{
    pthread_mutex_lock(&lock);
    for (int i = 0; i < GUARD_N; i++)
        if (guard[i].ip == ip)
            guard[i].fails = 0;
    pthread_mutex_unlock(&lock);
}

/* ---------------- login ---------------- */

static int auth_types(WOLFSSH *ssh, void *ctx)
{
    (void)ssh;
    (void)ctx;
    return WOLFSSH_USERAUTH_PASSWORD;
}

/* NOTE: WOLFSSH_USERAUTH_SUCCESS is 0 - every path must return explicitly. */
static int auth_cb(byte type, WS_UserAuthData *d, void *vctx)
{
    session_t *s = vctx;
    char user[32], pass[128];

    if (!d || !d->username || d->usernameSz == 0 || d->usernameSz >= sizeof user)
        return WOLFSSH_USERAUTH_FAILURE;
    memcpy(user, d->username, d->usernameSz);
    user[d->usernameSz] = 0;

    if (type != WOLFSSH_USERAUTH_NONE && type != WOLFSSH_USERAUTH_PASSWORD)
        return WOLFSSH_USERAUTH_FAILURE;

    if (!account_exists()) {
        /* Factory-new device: let the connection in so the shell can run the
         * account-creation dialogue. It gets nothing else until that succeeds. */
        s->setup = true;
        snprintf(s->user, sizeof s->user, "%s", user);
        return WOLFSSH_USERAUTH_SUCCESS;
    }
    if (type != WOLFSSH_USERAUTH_PASSWORD || !d->sf.password.password ||
        d->sf.password.passwordSz >= sizeof pass)
        return WOLFSSH_USERAUTH_FAILURE;

    memcpy(pass, d->sf.password.password, d->sf.password.passwordSz);
    pass[d->sf.password.passwordSz] = 0;
    bool ok = account_check(user, pass);
    memset(pass, 0, sizeof pass);
    if (ok) {
        guard_ok(s->peer_ip);
        s->setup = false;
        snprintf(s->user, sizeof s->user, "%s", user);
        return WOLFSSH_USERAUTH_SUCCESS;
    }
    port_log("session %d: wrong password from %s", s->id, s->peer);
    if (guard_fail(s->peer_ip)) {
        port_log("blocking %s for %d s after repeated wrong passwords", s->peer, guard_block_s);
        return WOLFSSH_USERAUTH_REJECTED;
    }
    port_sleep_ms(1000);
    return WOLFSSH_USERAUTH_FAILURE;
}

static int on_resize(WOLFSSH *ssh, word32 cols, word32 rows, word32 wpx, word32 hpx, void *vctx)
{
    session_t *s = vctx;
    (void)ssh;
    (void)wpx;
    (void)hpx;
    if (cols && rows) {
        s->cols = (uint16_t)cols;
        s->rows = (uint16_t)rows;
        s->winch = true;
    }
    return WS_SUCCESS;
}

/* ---------------- sessions ---------------- */

int server_session_count(void)
{
    int n = 0;
    pthread_mutex_lock(&lock);
    for (int i = 0; i < C3_MAX_SESSIONS; i++)
        n += slots[i] != NULL;
    pthread_mutex_unlock(&lock);
    return n;
}

void server_console_attach(session_t *s)
{
    pthread_mutex_lock(&lock);
    console_s = s;
    pthread_mutex_unlock(&lock);
}

int server_sessions(sess_info_t *out, int max)
{
    int n = 0;
    pthread_mutex_lock(&lock);
    for (int i = 0; i <= C3_MAX_SESSIONS && n < max; i++) {
        session_t *s = i < C3_MAX_SESSIONS ? slots[i] : console_s;
        if (!s)
            continue;
        out[n].id = s->id;
        out[n].via_ap = s->via_ap;
        out[n].since_s = s->since_s;
        snprintf(out[n].user, sizeof out[n].user, "%s", s->user);
        snprintf(out[n].peer, sizeof out[n].peer, "%s", s->peer);
        snprintf(out[n].doing, sizeof out[n].doing, "%s", s->doing);
        n++;
    }
    pthread_mutex_unlock(&lock);
    return n;
}

void server_kick_ap_sessions(void)
{
    pthread_mutex_lock(&lock);
    for (int i = 0; i < C3_MAX_SESSIONS; i++)
        if (slots[i] && slots[i]->via_ap)
            slots[i]->kick = true;      /* its own thread notices within a second and cleans up */
    pthread_mutex_unlock(&lock);
}

static void session_thread(void *arg)
{
    session_t *s = arg;

    port_log("session %d: %s connected%s", s->id, s->peer, s->via_ap ? " (setup network)" : "");
    s->cols = 80;
    s->rows = 24;
    s->since_s = port_uptime_s();
    snprintf(s->doing, sizeof s->doing, "login");
    s->ssh = wolfSSH_new(srv_ctx);
    if (s->ssh) {
        sshio_attach(s->ssh, &s->io);
        wolfSSH_SetUserAuthCtx(s->ssh, s);
        wolfSSH_SetTerminalResizeCb(s->ssh, on_resize);
        wolfSSH_SetTerminalResizeCtx(s->ssh, s);
        s->io.nonblock = false;
        s->io.io_ms = C3_LOGIN_GRACE_S * 1000;
        s->io.deadline_s = port_uptime_s() + C3_LOGIN_GRACE_S;

        if (wolfSSH_accept(s->ssh) == WS_SUCCESS) {
            s->io.deadline_s = 0;
            WS_SessionType t = wolfSSH_GetSessionType(s->ssh);
            if (t == WOLFSSH_SESSION_SHELL || t == WOLFSSH_SESSION_TERMINAL) {
                session_main(s);
            } else if (s->setup) {
                tn_puts(s, C3_NAME ": this device has no account yet - log in interactively first\n");
                wolfSSH_SetExitStatus(s->ssh, 1);
            } else {
                const char *cmd = wolfSSH_GetSessionCommand(s->ssh);
                snprintf(s->doing, sizeof s->doing, "%s", t == WOLFSSH_SESSION_SUBSYSTEM ? "sftp" : "scp");
                int st = xfer_serve(s, t == WOLFSSH_SESSION_SUBSYSTEM, cmd ? cmd : "");
                wolfSSH_SetExitStatus(s->ssh, (word32)st);
            }
            if (!s->closed && !s->kick) {
                s->io.nonblock = false;
                s->io.io_ms = 1500;
                wolfSSH_shutdown(s->ssh);
            }
        } else {
            port_log("session %d: login not completed (%s)", s->id, wolfSSH_get_error_name(s->ssh));
        }
        wolfSSH_free(s->ssh);
    }

    long room = port_stack_headroom();
    if (room >= 0)
        port_log("session %d: closed (stack headroom was %ld of %d bytes)", s->id, room, C3_SESSION_STACK);
    else
        port_log("session %d: closed", s->id);

    pthread_mutex_lock(&lock);
    slots[s->id] = NULL;
    pthread_mutex_unlock(&lock);
    close(s->io.fd);
    free(s);
}

static void tune_socket(int fd)
{
    int on = 1;
    struct timeval tv = { 10, 0 };
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on);
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
#ifdef TCP_KEEPIDLE
    int idle = 60, intvl = 10, cnt = 3;     /* notice a vanished client in ~90 s */
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof idle);
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof intvl);
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof cnt);
#endif
}

static void server_run(void)
{
    struct sockaddr_in addr = { 0 };
    int on = 1;
    int lfd = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port_listen_port());
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    if (lfd < 0 || bind(lfd, (struct sockaddr *)&addr, sizeof addr) < 0 || listen(lfd, 2) < 0) {
        port_log("ssh: cannot listen on port %d", port_listen_port());
        for (;;)
            port_sleep_ms(1000);
    }
    port_log("ssh: listening on port %d", port_listen_port());

    for (;;) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof peer;
        int fd = accept(lfd, (struct sockaddr *)&peer, &plen);
        if (fd < 0) {
            port_sleep_ms(200);
            continue;
        }
        if (guard_blocked(peer.sin_addr.s_addr)) {
            close(fd);
            continue;
        }
        tune_socket(fd);

        session_t *s = calloc(1, sizeof *s);
        int id = -1;
        pthread_mutex_lock(&lock);
        for (int i = 0; s && i < C3_MAX_SESSIONS; i++)
            if (!slots[i]) {
                slots[id = i] = s;
                break;
            }
        pthread_mutex_unlock(&lock);
        if (id < 0) {
            port_log("ssh: connection refused, all %d session slots are in use", C3_MAX_SESSIONS);
            close(fd);
            free(s);
            continue;
        }
        s->io.fd = fd;
        s->io.kick = &s->kick;
        s->id = id;
        s->peer_ip = peer.sin_addr.s_addr;
        s->via_ap = port_sock_via_ap(fd);
        inet_ntop(AF_INET, &peer.sin_addr, s->peer, sizeof s->peer);

        if (port_thread_start("session", C3_SESSION_STACK, session_thread, s) != 0) {
            port_log("ssh: out of memory for a session thread");
            pthread_mutex_lock(&lock);
            slots[id] = NULL;
            pthread_mutex_unlock(&lock);
            close(fd);
            free(s);
        }
    }
}

/* wolfCrypt's seed source (CUSTOM_RAND_GENERATE_SEED in config/user_settings.h) */
int c3shell_rand_seed(unsigned char *out, unsigned int sz)
{
    port_random(out, sz);
    return 0;
}

void c3shell_main(void)
{
    uint8_t der[128];
    char fp[64];

    port_log(C3_NAME " " C3_VERSION " starting");
    port_crypto_init();
    wolfSSH_Init();

    /* The server's identity: made once, kept until a factory reset. */
    int derlen = sshstore_hostkey(der, sizeof der, fp, sizeof fp);
    srv_ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (derlen <= 0 || !srv_ctx ||
        wolfSSH_CTX_UsePrivateKey_buffer(srv_ctx, der, (word32)derlen, WOLFSSH_FORMAT_ASN1) != WS_SUCCESS) {
        port_log("ssh: cannot set up the host key - not starting");
        for (;;)
            port_sleep_ms(1000);
    }
    memset(der, 0, sizeof der);
    sshio_ctx_setup(srv_ctx);
    wolfSSH_SetUserAuth(srv_ctx, auth_cb);
    wolfSSH_SetUserAuthTypes(srv_ctx, auth_types);
    port_log("ssh: host key fingerprint is %s (ED25519)", fp);

    netmgr_start();
    console_start();
    server_run();
}
