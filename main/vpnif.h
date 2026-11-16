/* lwIP's routing hook for the VPN tunnel (vpnif.c). Kept apart from
 * c3shell.h so lwIP's own build can include it. */
#ifndef C3_VPNIF_H
#define C3_VPNIF_H
struct netif;
struct ip4_addr;
struct netif *vpnif_route(const struct ip4_addr *dest);
#endif
