/* lwIP settings for the simulator's VPN stack: its only interface is the
 * tunnel (main/vpnif.c), and connections through it are bridged to ordinary
 * sockets by sim/vpn_proxy.c using the netconn API. */
#ifndef C3_SIM_LWIPOPTS_H
#define C3_SIM_LWIPOPTS_H

#define NO_SYS                     0
#define SYS_LIGHTWEIGHT_PROT       1
#define LWIP_TCPIP_CORE_LOCKING    1
#define LWIP_NETCONN               1
#define LWIP_SOCKET                0
#define LWIP_NETIF_API             0
#define LWIP_COMPAT_SOCKETS        0

#define LWIP_IPV4                  1
#define LWIP_IPV6                  0
#define LWIP_ARP                   0
#define LWIP_ETHERNET              0
#define LWIP_DHCP                  0
#define LWIP_AUTOIP                0
#define LWIP_DNS                   0
#define LWIP_IGMP                  0
#define LWIP_ICMP                  1
#define LWIP_RAW                   0
#define LWIP_UDP                   1
#define LWIP_TCP                   1
#define IP_REASSEMBLY              1
#define IP_FRAG                    1

#define MEM_LIBC_MALLOC            1
#define MEMP_MEM_MALLOC            1
#define MEM_ALIGNMENT              8
#define PBUF_POOL_SIZE             64
#define MEMP_NUM_NETCONN           16
#define MEMP_NUM_TCP_PCB           16

#define TCP_MSS                    1360    /* VPN_MTU (1400) - 40 */
#define TCP_WND                    (8 * TCP_MSS)
#define TCP_SND_BUF                (8 * TCP_MSS)
#define TCP_SND_QUEUELEN           32
#define LWIP_TCP_KEEPALIVE         1
#define LWIP_SO_RCVTIMEO           1
#define LWIP_SO_SNDTIMEO           1

#define TCPIP_MBOX_SIZE            64
#define DEFAULT_TCP_RECVMBOX_SIZE  64
#define DEFAULT_UDP_RECVMBOX_SIZE  8
#define DEFAULT_RAW_RECVMBOX_SIZE  8
#define DEFAULT_ACCEPTMBOX_SIZE    4
#define TCPIP_THREAD_STACKSIZE     0
#define DEFAULT_THREAD_STACKSIZE   0

#define LWIP_NETIF_LOOPBACK        0
#define LWIP_HAVE_LOOPIF           0
#define LWIP_STATS                 0
#define LWIP_NOASSERT_ON_ERROR     1

/* routes pushed by the VPN server (see main/vpnif.c) */
#define LWIP_HOOK_FILENAME         "vpnif.h"
#define LWIP_HOOK_IP4_ROUTE(dest)  vpnif_route(dest)

#endif
