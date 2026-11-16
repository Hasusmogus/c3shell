/* The VPN tunnel as an lwIP network interface.
 *
 * Packets lwIP routes into the tunnel are handed to the OpenVPN client
 * (ovpn.c), which encrypts and sends them; packets it decrypts come back in
 * through vpnif_input(). Routing: the tunnel's own subnet (or point-to-point
 * peer) is matched by lwIP itself; pushed routes and redirect-gateway are
 * matched by vpnif_route(), which lwIP consults after its own interfaces
 * (a hook on the chip, LWIP_HOOK_IP4_ROUTE in the simulator). The local
 * WiFi network always wins over a pushed route, and the VPN server itself is
 * never sent into the tunnel.
 *
 * The same file runs on the chip (ESP-IDF's lwIP, next to WiFi) and in the
 * simulator (its own lwIP whose only interface is this one). */
#include <stdlib.h>
#include <string.h>

#include "lwip/ip4_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcpip.h"
#include "lwip/priv/tcpip_priv.h"
#if LWIP_DNS
#include "lwip/dns.h"
#endif

#include "c3shell.h"
#include "vpnif.h"

static struct netif vnif;
static bool added;
static vpnif_cfg_t cfg;               /* changed only inside the TCP/IP thread */
static void (*out_fn)(const uint8_t *pkt, size_t len);
#if LWIP_DNS
static ip_addr_t saved_dns;
static bool dns_changed;
#endif

static bool cfg_match(const vpnif_cfg_t *c, uint32_t ip)
{
    if (ip == c->server)
        return false;
    if (c->ip && ((ip ^ c->ip) & c->mask) == 0)
        return true;
    if (c->peer && ip == c->peer)
        return true;
    for (int i = 0; i < c->nroutes; i++)
        if (((ip ^ c->routes[i].net) & c->routes[i].mask) == 0)
            return true;
    return c->redirect;
}

struct netif *vpnif_route(const ip4_addr_t *dest)
{
    if (!added || !netif_is_up(&vnif))
        return NULL;
    return cfg_match(&cfg, ip4_addr_get_u32(dest)) ? &vnif : NULL;
}

bool vpn_routes_ip(uint32_t ip)
{
    /* a racy read is fine here: it only picks which stack dials */
    return added && cfg_match(&cfg, ip);
}

/* Runs on lwIP's TCP/IP thread, whose stack is small on the chip: no big
 * buffers here, and nothing that could block on a socket. */
static err_t vnif_output(struct netif *n, struct pbuf *p, const ip4_addr_t *ip)
{
    (void)n;
    (void)ip;
    if (p->tot_len > VPN_MTU || !out_fn)
        return ERR_OK;                   /* dropped, as a full link would */
    uint8_t *buf = malloc(p->tot_len);
    if (!buf)
        return ERR_OK;
    pbuf_copy_partial(p, buf, p->tot_len, 0);
    out_fn(buf, p->tot_len);
    free(buf);
    return ERR_OK;
}

static err_t vnif_init(struct netif *n)
{
    n->name[0] = 'v';
    n->name[1] = 'p';
    n->output = vnif_output;
    n->mtu = VPN_MTU;
    n->flags = 0;                        /* point to point: no ARP, no broadcast */
    return ERR_OK;
}

struct call {
    struct tcpip_api_call_data base;
    const vpnif_cfg_t *c;
    int up;
};

static void addrs(const vpnif_cfg_t *c, ip4_addr_t *ip, ip4_addr_t *mask, ip4_addr_t *gw)
{
    ip4_addr_set_u32(ip, c->ip);
    ip4_addr_set_u32(mask, c->peer ? 0xFFFFFFFFu : c->mask);
    ip4_addr_set_u32(gw, c->peer);
}

static err_t do_call(struct tcpip_api_call_data *d)
{
    struct call *k = (struct call *)d;
    if (k->up) {
        ip4_addr_t ip, mask, gw;
        bool same = added && cfg.ip == k->c->ip && cfg.mask == k->c->mask && cfg.peer == k->c->peer;
        if (added && !same) {
            netif_remove(&vnif);
            added = false;
        }
        cfg = *k->c;
        if (!added) {
            addrs(&cfg, &ip, &mask, &gw);
            if (!netif_add(&vnif, &ip, &mask, &gw, NULL, vnif_init, tcpip_input))
                return ERR_IF;
            added = true;
        }
        netif_set_up(&vnif);
        netif_set_link_up(&vnif);
#if LWIP_DNS
        if (cfg.dns) {
            ip_addr_t a = IPADDR4_INIT(cfg.dns);
            if (!dns_changed)
                saved_dns = *dns_getserver(0);
            dns_setserver(0, &a);
            dns_changed = true;
        }
#endif
    } else if (added) {
        netif_set_down(&vnif);
        netif_remove(&vnif);
        added = false;
        memset(&cfg, 0, sizeof cfg);
#if LWIP_DNS
        if (dns_changed)
            dns_setserver(0, &saved_dns);
        dns_changed = false;
#endif
    }
    return ERR_OK;
}

int vpnif_up(const vpnif_cfg_t *c, void (*out)(const uint8_t *pkt, size_t len))
{
    struct call k = { .c = c, .up = 1 };
    out_fn = out;
    return tcpip_api_call(do_call, &k.base) == ERR_OK ? 0 : -1;
}

void vpnif_down(void)
{
    struct call k = { .up = 0 };
    tcpip_api_call(do_call, &k.base);
}

void vpnif_input(const uint8_t *pkt, size_t len)
{
    if (!added || len < 20 || (pkt[0] >> 4) != 4)
        return;                          /* IPv4 only */
    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_POOL);
    if (!p)
        return;
    pbuf_take(p, pkt, (u16_t)len);
    if (vnif.input(p, &vnif) != ERR_OK)
        pbuf_free(p);
}

int vpn_dial(uint32_t ip_be, uint16_t port, int timeout_ms)
{
    if (!vpn_routes_ip(ip_be))
        return -2;
    return port_vpn_dial(ip_be, port, timeout_ms);
}
