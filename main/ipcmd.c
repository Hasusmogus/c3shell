/* ip: the device's network interfaces and routes, in the style of Linux's
 * ip(8):  ip addr | ip route | ip link  (each with -s for traffic counters). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "c3shell.h"

static void ipstr(char *out, size_t cap, uint32_t be)
{
    const uint8_t *b = (const uint8_t *)&be;
    snprintf(out, cap, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

static int prefix(uint32_t mask_be)
{
    const uint8_t *b = (const uint8_t *)&mask_be;
    uint32_t m = (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3];
    int n = 0;
    while (m & 0x80000000u) {
        n++;
        m <<= 1;
    }
    return n;
}

static void show_link(session_t *s, int idx, const port_netif_t *n, bool addr, bool stats, const net_status_t *st)
{
    char a[16], b[16];
    tn_printf(s, "%d: %s: <%s> mtu 1500 state %s\n", idx, n->name,
              n->up ? "BROADCAST,MULTICAST,UP,LOWER_UP" : "BROADCAST,MULTICAST", n->up ? "UP" : "DOWN");
    tn_printf(s, "    link/ether %02x:%02x:%02x:%02x:%02x:%02x\n", n->mac[0], n->mac[1], n->mac[2], n->mac[3],
              n->mac[4], n->mac[5]);
    if (strcmp(n->name, "wlan0") == 0 && st->sta_up)
        tn_printf(s, "    wifi '%s' signal %d dBm\n", st->sta_ssid, st->rssi);
    else if (strcmp(n->name, "wlan0") == 0 && st->have_saved)
        tn_printf(s, "    wifi '%s' (not reachable right now)\n", st->sta_ssid);
    else if (strcmp(n->name, "ap0") == 0)
        tn_printf(s, "    wifi '%s' (the setup network%s)\n", st->ap_ssid, st->ap_up ? "" : ", off");
    if (addr && n->ip) {
        uint32_t brd = n->ip | ~n->mask;
        ipstr(a, sizeof a, n->ip);
        ipstr(b, sizeof b, brd);
        tn_printf(s, "    inet %s/%d brd %s scope global %s\n", a, prefix(n->mask), b, n->name);
    }
    if (stats && (n->rx_pkts || n->tx_pkts))
        tn_printf(s, "    RX: packets %lu  bytes %llu\n    TX: packets %lu  bytes %llu\n", (unsigned long)n->rx_pkts,
                  (unsigned long long)n->rx_bytes, (unsigned long)n->tx_pkts, (unsigned long long)n->tx_bytes);
}

static void show_tun(session_t *s, int idx, const vpnif_cfg_t *c, bool addr, bool stats)
{
    vpn_status_t vs;
    char a[16], p[16];
    vpn_status(&vs);
    tn_printf(s, "%d: tun0: <POINTOPOINT,UP,LOWER_UP> mtu %d state UNKNOWN\n    link/none\n", idx, VPN_MTU);
    if (vs.server[0])
        tn_printf(s, "    openvpn to %s\n", vs.server);
    if (addr) {
        ipstr(a, sizeof a, c->ip);
        if (c->peer) {
            ipstr(p, sizeof p, c->peer);
            tn_printf(s, "    inet %s peer %s scope global tun0\n", a, p);
        } else {
            tn_printf(s, "    inet %s/%d scope global tun0\n", a, prefix(c->mask));
        }
    }
    if (stats)
        tn_printf(s, "    RX: bytes %llu\n    TX: bytes %llu\n", (unsigned long long)vs.rx, (unsigned long long)vs.tx);
}

static void show_routes(session_t *s, const port_netif_t *nifs, int n, const vpnif_cfg_t *vpn)
{
    char a[16], b[16];
    const port_netif_t *wl = NULL;
    for (int i = 0; i < n; i++)
        if (strcmp(nifs[i].name, "wlan0") == 0 && nifs[i].up && nifs[i].ip)
            wl = &nifs[i];

    /* default route: the tunnel with redirect-gateway (the VPN server itself
     * still goes out over WiFi), else the WiFi gateway */
    if (vpn && vpn->redirect) {
        tn_puts(s, "default dev tun0\n");
        if (wl && wl->gw && vpn->server) {
            ipstr(a, sizeof a, vpn->server);
            ipstr(b, sizeof b, wl->gw);
            tn_printf(s, "%s via %s dev wlan0\n", a, b);
        }
    }
    if (wl && wl->gw) {                        /* behind the tunnel's default, if there is one */
        ipstr(b, sizeof b, wl->gw);
        tn_printf(s, "default via %s dev wlan0%s\n", b, vpn && vpn->redirect ? " metric 100" : "");
    }
    for (int i = 0; i < n; i++) {                /* the networks the interfaces are on */
        if (!nifs[i].up || !nifs[i].ip)
            continue;
        ipstr(a, sizeof a, nifs[i].ip & nifs[i].mask);
        ipstr(b, sizeof b, nifs[i].ip);
        tn_printf(s, "%s/%d dev %s scope link src %s\n", a, prefix(nifs[i].mask), nifs[i].name, b);
    }
    if (vpn) {
        ipstr(b, sizeof b, vpn->ip);
        if (vpn->peer) {
            ipstr(a, sizeof a, vpn->peer);
            tn_printf(s, "%s dev tun0 scope link src %s\n", a, b);
        } else {
            ipstr(a, sizeof a, vpn->ip & vpn->mask);
            tn_printf(s, "%s/%d dev tun0 scope link src %s\n", a, prefix(vpn->mask), b);
        }
        for (int i = 0; i < vpn->nroutes; i++) {   /* pushed by the server */
            ipstr(a, sizeof a, vpn->routes[i].net);
            tn_printf(s, "%s/%d dev tun0\n", a, prefix(vpn->routes[i].mask));
        }
    }
}

static int usage(session_t *s)
{
    tn_puts(s, "usage: ip [-s] addr | route | link\n"
               "       (a, r and l will do; -s adds traffic counters)\n");
    return 2;
}

int cmd_ip(session_t *s, int argc, char **argv)
{
    bool stats = false;
    const char *obj = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "-stats") == 0)
            stats = true;
        else if (!obj)
            obj = argv[i];
        else if (strcmp(argv[i], "show") != 0 && strcmp(argv[i], "list") != 0 && strcmp(argv[i], "ls") != 0)
            return usage(s);
    }
    if (!obj)
        return usage(s);
    size_t l = strlen(obj);
    bool addr = strncmp(obj, "address", l) == 0, route = strncmp(obj, "route", l) == 0,
         link = strncmp(obj, "link", l) == 0;
    if (addr + route + link != 1)              /* "a" is addr (as in Linux), not ambiguous with anything */
        return usage(s);

    port_netif_t nifs[2];
    vpnif_cfg_t vpn;
    net_status_t st;
    int n = port_netifs(nifs, 2);
    bool tun = vpnif_config(&vpn);
    netmgr_status(&st);

    if (route) {
        show_routes(s, nifs, n, tun ? &vpn : NULL);
        return 0;
    }
    for (int i = 0; i < n; i++)
        show_link(s, i + 1, &nifs[i], addr, stats, &st);
    if (tun)
        show_tun(s, n + 1, &vpn, addr, stats);
    return 0;
}
