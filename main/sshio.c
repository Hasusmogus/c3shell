/* Socket I/O for wolfSSH (which is built with WOLFSSH_USER_IO), shared by the
 * server side (the user's login) and the client side (outbound ssh), plus
 * read/write helpers that hide wolfSSH's "try again" conditions. */
#include <errno.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssh/ssh.h>

#include "c3shell.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static int io_recv(WOLFSSH *ssh, void *buf, word32 sz, void *vctx)
{
    sshio_t *io = vctx;
    (void)ssh;
    if (io->kick && *io->kick)
        return WS_CBIO_ERR_CONN_CLOSE;
    if (io->deadline_s && port_uptime_s() >= io->deadline_s)
        return WS_CBIO_ERR_TIMEOUT;
    if (!io->nonblock) {
        /* Wait in short steps so a session that is being ended lets go promptly. */
        for (int waited = 0;; waited += 500) {
            fd_set rd;
            struct timeval tv = { 0, 500000 };
            if (waited >= io->io_ms || (io->kick && *io->kick) ||
                (io->deadline_s && port_uptime_s() >= io->deadline_s))
                return WS_CBIO_ERR_TIMEOUT;
            FD_ZERO(&rd);
            FD_SET(io->fd, &rd);
            if (select(io->fd + 1, &rd, NULL, NULL, &tv) > 0)
                break;
        }
    }
    ssize_t n = recv(io->fd, buf, sz, MSG_DONTWAIT);
    if (n > 0)
        return (int)n;
    if (n == 0)
        return WS_CBIO_ERR_CONN_CLOSE;
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return WS_CBIO_ERR_WANT_READ;
    return errno == ECONNRESET ? WS_CBIO_ERR_CONN_RST : WS_CBIO_ERR_GENERAL;
}

static int io_send(WOLFSSH *ssh, void *buf, word32 sz, void *vctx)
{
    sshio_t *io = vctx;
    (void)ssh;
    ssize_t n;
    do {
        n = send(io->fd, buf, sz, MSG_NOSIGNAL);   /* bounded by the socket's SO_SNDTIMEO */
    } while (n < 0 && errno == EINTR);
    if (n > 0)
        return (int)n;
    return (errno == EPIPE || errno == ECONNRESET) ? WS_CBIO_ERR_CONN_CLOSE : WS_CBIO_ERR_GENERAL;
}

void sshio_ctx_setup(void *ctx)
{
    wolfSSH_SetIORecv(ctx, io_recv);
    wolfSSH_SetIOSend(ctx, io_send);
}

void sshio_attach(WOLFSSH *ssh, sshio_t *io)
{
    wolfSSH_SetIOReadCtx(ssh, io);
    wolfSSH_SetIOWriteCtx(ssh, io);
}

static bool soft(int e)
{
    return e == WS_WANT_READ || e == WS_WANT_WRITE || e == WS_REKEYING || e == WS_CHAN_RXD ||
           e == WS_WINDOW_FULL;
}

/* Non-blocking read of channel data (io->nonblock must be set). The peer's
 * stderr stream is mixed in, or flagged through is_stderr when that is given. */
int sshio_read(WOLFSSH *ssh, uint8_t *buf, int cap)
{
    return sshio_read_ext(ssh, buf, cap, NULL);
}

int sshio_read_ext(WOLFSSH *ssh, uint8_t *buf, int cap, bool *is_stderr)
{
    if (is_stderr)
        *is_stderr = false;
    for (int guard = 0; guard < 16; guard++) {
        int n = wolfSSH_stream_read(ssh, buf, (word32)cap);
        if (n > 0)
            return n;
        if (n == WS_EXTDATA) {                      /* the peer's stderr stream */
            n = wolfSSH_extended_data_read(ssh, buf, (word32)cap);
            if (n > 0) {
                if (is_stderr)
                    *is_stderr = true;
                return n;
            }
            continue;
        }
        if (n == WS_EOF)
            return -1;
        int e = wolfSSH_get_error(ssh);
        if (e == WS_WANT_READ || e == WS_WANT_WRITE)
            return 0;
        if (e == WS_REKEYING) {                     /* key re-exchange in progress */
            if (wolfSSH_worker(ssh, NULL) < 0) {
                e = wolfSSH_get_error(ssh);
                if (e == WS_WANT_READ || e == WS_WANT_WRITE)
                    return 0;
                if (!soft(e))
                    return -1;
            }
            continue;
        }
        if (e == WS_CHAN_RXD || e == WS_WINDOW_FULL)
            continue;
        return -1;
    }
    return 0;
}

/* Send all of data, waiting out a full window or a key re-exchange. Anything
 * the peer sends meanwhile stays queued inside wolfSSH for the next read. */
int sshio_write(WOLFSSH *ssh, sshio_t *io, const uint8_t *data, int len)
{
    int off = 0, stalls = 0;
    while (off < len) {
        int n = wolfSSH_stream_send(ssh, (byte *)data + off, (word32)(len - off));
        if (n > 0) {
            off += n;
            stalls = 0;
            continue;
        }
        int e = wolfSSH_get_error(ssh);
        if ((!soft(n) && !soft(e)) || ++stalls > 80 || (io->kick && *io->kick))
            return -1;
        fd_set rd;
        struct timeval tv = { 0, 250000 };
        FD_ZERO(&rd);
        FD_SET(io->fd, &rd);
        select(io->fd + 1, &rd, NULL, NULL, &tv);
        if (wolfSSH_worker(ssh, NULL) < 0 && !soft(wolfSSH_get_error(ssh)))
            return -1;
    }
    return 0;
}
