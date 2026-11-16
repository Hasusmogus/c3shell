/* Simulator only: TCP connections through the VPN tunnel.
 *
 * On the chip every socket is an lwIP socket and lwIP itself routes into the
 * tunnel. The simulator's sockets are the host's, so a connection to an
 * address behind the VPN is made with the simulator's own lwIP (whose only
 * interface is the tunnel) and handed to the caller as one end of a
 * socketpair; two small threads copy between the two. */
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "lwip/api.h"
#include "lwip/tcpip.h"

#include "c3shell.h"

typedef struct {
    struct netconn *nc;
    int  fd;
    int  refs;
    pthread_mutex_t lock;
} bridge_t;

static void unref(bridge_t *b)
{
    pthread_mutex_lock(&b->lock);
    int left = --b->refs;
    pthread_mutex_unlock(&b->lock);
    if (left)
        return;
    netconn_close(b->nc);
    netconn_delete(b->nc);
    close(b->fd);
    free(b);
}

static void *to_tunnel(void *arg)            /* caller -> remote */
{
    bridge_t *b = arg;
    char buf[4096];
    for (;;) {
        ssize_t n = read(b->fd, buf, sizeof buf);
        if (n <= 0 || netconn_write(b->nc, buf, (size_t)n, NETCONN_COPY) != ERR_OK)
            break;
    }
    netconn_shutdown(b->nc, 0, 1);
    unref(b);
    return NULL;
}

static void *from_tunnel(void *arg)          /* remote -> caller */
{
    bridge_t *b = arg;
    for (;;) {
        struct netbuf *nb;
        if (netconn_recv(b->nc, &nb) != ERR_OK)
            break;
        void *data;
        u16_t len;
        bool ok = true;
        do {
            netbuf_data(nb, &data, &len);
            for (u16_t off = 0; ok && off < len;) {
                ssize_t w = write(b->fd, (char *)data + off, len - off);
                ok = w > 0;
                off = (u16_t)(off + (ok ? w : 0));
            }
        } while (ok && netbuf_next(nb) >= 0);
        netbuf_delete(nb);
        if (!ok)
            break;
    }
    shutdown(b->fd, SHUT_WR);
    unref(b);
    return NULL;
}

int port_vpn_dial(uint32_t ip_be, uint16_t port, int timeout_ms)
{
    int sv[2];
    ip_addr_t dst;
    (void)timeout_ms;                         /* lwIP gives up on its own (SYN retries) */

    struct netconn *nc = netconn_new(NETCONN_TCP);
    if (!nc)
        return -1;
    ip_addr_set_ip4_u32(&dst, ip_be);
    if (netconn_connect(nc, &dst, port) != ERR_OK || socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        netconn_delete(nc);
        return -1;
    }
    bridge_t *b = calloc(1, sizeof *b);
    b->nc = nc;
    b->fd = sv[1];
    b->refs = 2;
    pthread_mutex_init(&b->lock, NULL);
    pthread_t t1, t2;
    pthread_create(&t1, NULL, to_tunnel, b);
    pthread_create(&t2, NULL, from_tunnel, b);
    pthread_detach(t1);
    pthread_detach(t2);
    return sv[0];
}

void sim_lwip_start(void)
{
    tcpip_init(NULL, NULL);
}
