/* ping and traceroute: ICMP echo requests, reported like the usual tools. */
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "c3shell.h"

#define PING_DATA  56
#define TRACE_DATA 32

/* ---------------- shared ---------------- */

static double now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1000.0 + (double)t.tv_nsec / 1e6;
}

static uint16_t checksum(const uint8_t *p, size_t n)
{
    uint32_t sum = 0;
    for (; n > 1; p += 2, n -= 2)
        sum += (uint32_t)(p[0] << 8 | p[1]);
    if (n)
        sum += (uint32_t)p[0] << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/* Ctrl-C (or q) typed? Also true once the session is gone. */
static bool interrupted(session_t *s)
{
    uint8_t b[32];
    int n;
    while ((n = tn_read_avail(s, b, sizeof b)) > 0)
        for (int i = 0; i < n; i++)
            if (b[i] == 0x03 || b[i] == 'q') {
                s->intr = b[i] == 0x03;     /* Ctrl-C also stops a script or loop around it */
                return true;
            }
    return n == TN_CLOSED;
}

typedef struct {
    int      fd;
    uint16_t id;
    struct sockaddr_in dst;
    char     ip[INET_ADDRSTRLEN];
} icmp_t;

/* resolve and open; 0, or 2 after saying why not */
static int icmp_open(session_t *s, const char *cmd, const char *host, icmp_t *ic)
{
    struct addrinfo hints = { 0 }, *res = NULL;
    hints.ai_family = AF_INET;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) {
        tn_printf(s, "%s: could not resolve hostname %s\n", cmd, host);
        return 2;
    }
    ic->dst = *(struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);
    inet_ntop(AF_INET, &ic->dst.sin_addr, ic->ip, sizeof ic->ip);
    ic->fd = port_icmp_socket();
    if (ic->fd < 0) {
        tn_printf(s, "%s: cannot open an ICMP socket (%s)\n", cmd, strerror(errno));
        return 2;
    }
    port_random(&ic->id, sizeof ic->id);
    return 0;
}

static int icmp_send(icmp_t *ic, uint16_t seq, int datalen)
{
    uint8_t pkt[8 + PING_DATA];
    if (datalen > PING_DATA)
        datalen = PING_DATA;
    memset(pkt, 0, sizeof pkt);
    pkt[0] = 8;                                  /* echo request */
    pkt[4] = (uint8_t)(ic->id >> 8);
    pkt[5] = (uint8_t)ic->id;
    pkt[6] = (uint8_t)(seq >> 8);
    pkt[7] = (uint8_t)seq;
    for (int i = 0; i < datalen; i++)
        pkt[8 + i] = (uint8_t)i;
    uint16_t c = checksum(pkt, (size_t)(8 + datalen));
    pkt[2] = (uint8_t)(c >> 8);
    pkt[3] = (uint8_t)c;
    return sendto(ic->fd, pkt, (size_t)(8 + datalen), 0, (struct sockaddr *)&ic->dst, sizeof ic->dst) < 0 ? -1 : 0;
}

/* an answer (or an error) to our request number seq? */
static bool answers(const icmp_t *ic, const port_icmp_t *r, uint16_t seq)
{
    if (r->seq != seq || (r->id_known && r->id != ic->id))
        return false;
    return r->type == 0 ? r->from == ic->dst.sin_addr.s_addr : r->type == 3 || r->type == 11;
}

/* Wait up to ms for what answers request seq; 1 = *r is it, 0 = nothing, -1 = interrupted */
static int icmp_wait(session_t *s, icmp_t *ic, uint16_t seq, double deadline, port_icmp_t *r)
{
    for (;;) {
        double left = deadline - now_ms();
        if (left <= 0)
            return 0;
        int k = port_icmp_recv(ic->fd, left > 100 ? 100 : (int)left + 1, r);
        if (k == 1 && answers(ic, r, seq))
            return 1;
        if (interrupted(s))
            return -1;
    }
}

static const char *unreach(uint8_t code)
{
    switch (code) {
    case 0:  return "Net";
    case 1:  return "Host";
    case 2:  return "Protocol";
    case 13: return "Communication administratively prohibited -";
    default: return "";
    }
}

/* ---------------- ping ---------------- */

static int ping_usage(session_t *s)
{
    tn_puts(s, "usage: ping [-c count] [-i seconds] [-W timeout] host   (-c 0: until Ctrl-C)\n");
    return 2;
}

int cmd_ping(session_t *s, int argc, char **argv)
{
    int count = 4, timeout_s = 2;
    double interval = 1.0;
    const char *host = NULL;
    icmp_t ic;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            count = atoi(argv[++i]);
            if (count < 0)
                return ping_usage(s);
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            interval = atof(argv[++i]);
            if (interval < 0.2 || interval > 60)
                return ping_usage(s);
        } else if (strcmp(argv[i], "-W") == 0 && i + 1 < argc) {
            timeout_s = atoi(argv[++i]);
            if (timeout_s < 1 || timeout_s > 30)
                return ping_usage(s);
        } else if (argv[i][0] != '-' && !host) {
            host = argv[i];
        } else {
            return ping_usage(s);
        }
    }
    if (!host)
        return ping_usage(s);
    int r0 = icmp_open(s, "ping", host, &ic);
    if (r0)
        return r0;

    tn_printf(s, "PING %s (%s): %d data bytes\n", host, ic.ip, PING_DATA);
    int sent = 0, got = 0;
    double rmin = 0, rmax = 0, rsum = 0;
    bool stop = false;

    for (int seq = 1; !stop && (count == 0 || seq <= count); seq++) {
        port_icmp_t r;
        double t0 = now_ms();
        sent++;
        if (icmp_send(&ic, (uint16_t)seq, PING_DATA) < 0) {
            tn_printf(s, "ping: sending icmp_seq=%d: %s\n", seq, strerror(errno));
        } else {
            int k = icmp_wait(s, &ic, (uint16_t)seq, t0 + timeout_s * 1000.0, &r);
            char from[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &r.from, from, sizeof from);
            if (k < 0) {
                stop = true;
            } else if (k == 0) {
                tn_printf(s, "Request timeout for icmp_seq %d\n", seq);
            } else if (r.type == 3) {
                tn_printf(s, "From %s icmp_seq=%d Destination %s Unreachable\n", from, seq, unreach(r.code));
            } else if (r.type == 11) {
                tn_printf(s, "From %s icmp_seq=%d Time to live exceeded\n", from, seq);
            } else {
                double rtt = now_ms() - t0;
                if (r.ttl >= 0)
                    tn_printf(s, "%d bytes from %s: icmp_seq=%d ttl=%d time=%.1f ms\n", r.len, ic.ip, seq, r.ttl, rtt);
                else
                    tn_printf(s, "%d bytes from %s: icmp_seq=%d time=%.1f ms\n", r.len, ic.ip, seq, rtt);
                if (got == 0 || rtt < rmin)
                    rmin = rtt;
                if (rtt > rmax)
                    rmax = rtt;
                rsum += rtt;
                got++;
            }
        }
        /* the rest of the interval, unless that was the last one */
        while (!stop && (count == 0 || seq < count)) {
            double left = t0 + interval * 1000.0 - now_ms();
            if (left <= 0)
                break;
            port_sleep_ms(left > 100 ? 100 : (uint32_t)left + 1);
            if (interrupted(s))
                stop = true;
        }
    }
    close(ic.fd);

    tn_printf(s, "\n--- %s ping statistics ---\n", host);
    tn_printf(s, "%d packets transmitted, %d received, %d%% packet loss\n", sent, got,
              sent ? (sent - got) * 100 / sent : 0);
    if (got)
        tn_printf(s, "round-trip min/avg/max = %.1f/%.1f/%.1f ms\n", rmin, rsum / got, rmax);
    return got ? 0 : 1;                    /* like ping: 1 when nothing answered */
}

/* ---------------- traceroute ---------------- */

static int trace_usage(session_t *s, const char *cmd)
{
    tn_printf(s, "usage: %s [-m max_hops] [-q probes] [-w seconds] host\n", cmd);
    return 2;
}

/* Echo requests with TTL 1, 2, 3 ...: each router on the way answers "time
 * exceeded", the destination with an echo reply (like Windows' tracert). */
int cmd_traceroute(session_t *s, int argc, char **argv)
{
    int max = 30, probes = 3, wait_s = 2;
    const char *host = NULL;
    icmp_t ic;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            max = atoi(argv[++i]);
            if (max < 1 || max > 64)
                return trace_usage(s, argv[0]);
        } else if (strcmp(argv[i], "-q") == 0 && i + 1 < argc) {
            probes = atoi(argv[++i]);
            if (probes < 1 || probes > 5)
                return trace_usage(s, argv[0]);
        } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            wait_s = atoi(argv[++i]);
            if (wait_s < 1 || wait_s > 10)
                return trace_usage(s, argv[0]);
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "-I") == 0) {
            /* numeric addresses and ICMP probes are what it does anyway */
        } else if (argv[i][0] != '-' && !host) {
            host = argv[i];
        } else {
            return trace_usage(s, argv[0]);
        }
    }
    if (!host)
        return trace_usage(s, argv[0]);
    int r0 = icmp_open(s, argv[0], host, &ic);
    if (r0)
        return r0;

    tn_printf(s, "traceroute to %s (%s), %d hops max, %d byte packets\n", host, ic.ip, max, 20 + 8 + TRACE_DATA);
    uint16_t seq = 0;
    bool done = false, reached = false, stop = false;
    for (int ttl = 1; ttl <= max && !done && !stop; ttl++) {
        uint32_t last = 0;
        if (port_icmp_ttl(ic.fd, ttl) != 0) {
            tn_printf(s, "%s: cannot set the TTL (%s)\n", argv[0], strerror(errno));
            break;
        }
        tn_printf(s, "%2d ", ttl);
        for (int q = 0; q < probes && !stop; q++) {
            port_icmp_t r;
            double t0 = now_ms();
            if (icmp_send(&ic, ++seq, TRACE_DATA) < 0) {
                tn_printf(s, " !(%s)", strerror(errno));
                continue;
            }
            int k = icmp_wait(s, &ic, seq, t0 + wait_s * 1000.0, &r);
            if (k < 0) {
                stop = true;
                break;
            }
            if (k == 0) {
                tn_puts(s, " *");
                continue;
            }
            if (r.from != last) {                /* a new address on this hop (or the first) */
                char from[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &r.from, from, sizeof from);
                tn_printf(s, " %s", from);
                last = r.from;
            }
            tn_printf(s, "  %.1f ms", now_ms() - t0);
            if (r.type == 0) {
                done = reached = true;
            } else if (r.type == 3) {             /* unreachable: the path ends here */
                tn_printf(s, " !%c", r.code == 0 ? 'N' : r.code == 1 ? 'H' : r.code == 2 ? 'P' : r.code == 13 ? 'X' : '?');
                done = true;
            }
        }
        tn_puts(s, "\n");
    }
    close(ic.fd);
    return reached ? 0 : 1;
}
