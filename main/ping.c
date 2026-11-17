/* ping: ICMP echo requests, reported like the usual ping. */
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "c3shell.h"

#define PING_DATA 56

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
            if (b[i] == 0x03 || b[i] == 'q')
                return true;
    return n == TN_CLOSED;
}

static int usage(session_t *s)
{
    tn_puts(s, "usage: ping [-c count] [-i seconds] [-W timeout] host   (-c 0: until Ctrl-C)\n");
    return 0;
}

int cmd_ping(session_t *s, int argc, char **argv)
{
    int count = 4, timeout_s = 2;
    double interval = 1.0;
    const char *host = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            count = atoi(argv[++i]);
            if (count < 0)
                return usage(s);
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            interval = atof(argv[++i]);
            if (interval < 0.2 || interval > 60)
                return usage(s);
        } else if (strcmp(argv[i], "-W") == 0 && i + 1 < argc) {
            timeout_s = atoi(argv[++i]);
            if (timeout_s < 1 || timeout_s > 30)
                return usage(s);
        } else if (argv[i][0] != '-' && !host) {
            host = argv[i];
        } else {
            return usage(s);
        }
    }
    if (!host)
        return usage(s);

    struct addrinfo hints = { 0 }, *res = NULL;
    hints.ai_family = AF_INET;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) {
        tn_printf(s, "ping: could not resolve hostname %s\n", host);
        return 0;
    }
    struct sockaddr_in dst = *(struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dst.sin_addr, ip, sizeof ip);

    bool with_ip = false;
    int fd = port_icmp_socket(&with_ip);
    if (fd < 0) {
        tn_printf(s, "ping: cannot open an ICMP socket (%s)\n", strerror(errno));
        return 0;
    }
    uint16_t id;
    port_random(&id, sizeof id);

    tn_printf(s, "PING %s (%s): %d data bytes\n", host, ip, PING_DATA);
    int sent = 0, got = 0;
    double rmin = 0, rmax = 0, rsum = 0;
    bool stop = false;

    for (int seq = 1; !stop && (count == 0 || seq <= count); seq++) {
        uint8_t pkt[8 + PING_DATA];
        memset(pkt, 0, sizeof pkt);
        pkt[0] = 8;                                  /* echo request */
        pkt[4] = (uint8_t)(id >> 8);
        pkt[5] = (uint8_t)id;
        pkt[6] = (uint8_t)(seq >> 8);
        pkt[7] = (uint8_t)seq;
        for (int i = 0; i < PING_DATA; i++)
            pkt[8 + i] = (uint8_t)i;
        uint16_t c = checksum(pkt, sizeof pkt);
        pkt[2] = (uint8_t)(c >> 8);
        pkt[3] = (uint8_t)c;

        double t0 = now_ms();
        sent++;
        bool answered = false;
        if (sendto(fd, pkt, sizeof pkt, 0, (struct sockaddr *)&dst, sizeof dst) < 0) {
            tn_printf(s, "ping: sending icmp_seq=%d: %s\n", seq, strerror(errno));
        } else {
            double deadline = t0 + timeout_s * 1000.0;
            while (!answered && !stop) {
                double left = deadline - now_ms();
                if (left <= 0)
                    break;
                int slice = left > 100 ? 100 : (int)left + 1;
                struct timeval tv = { 0, slice * 1000 };
                fd_set rd;
                FD_ZERO(&rd);
                FD_SET(fd, &rd);
                if (select(fd + 1, &rd, NULL, NULL, &tv) > 0) {
                    uint8_t buf[256];
                    struct sockaddr_in from;
                    socklen_t fl = sizeof from;
                    ssize_t n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
                    const uint8_t *ic = buf;
                    int ttl = -1;
                    if (n > 0 && with_ip) {          /* raw socket: the IP header comes first */
                        int ihl = (buf[0] & 0x0F) * 4;
                        if (n < ihl + 8)
                            continue;
                        ttl = buf[8];
                        ic = buf + ihl;
                        n -= ihl;
                    }
                    if (n < 8 || ic[0] != 0 || from.sin_addr.s_addr != dst.sin_addr.s_addr)
                        continue;                    /* not an echo reply from our target */
                    uint16_t rid = (uint16_t)(ic[4] << 8 | ic[5]), rseq = (uint16_t)(ic[6] << 8 | ic[7]);
                    if ((with_ip && rid != id) || rseq != (uint16_t)seq)
                        continue;                    /* someone else's, or a late one */
                    double rtt = now_ms() - t0;
                    if (ttl >= 0)
                        tn_printf(s, "%d bytes from %s: icmp_seq=%d ttl=%d time=%.1f ms\n", (int)n, ip, seq, ttl,
                                  rtt);
                    else
                        tn_printf(s, "%d bytes from %s: icmp_seq=%d time=%.1f ms\n", (int)n, ip, seq, rtt);
                    if (got == 0 || rtt < rmin)
                        rmin = rtt;
                    if (rtt > rmax)
                        rmax = rtt;
                    rsum += rtt;
                    got++;
                    answered = true;
                }
                if (interrupted(s))
                    stop = true;
            }
            if (!answered && !stop)
                tn_printf(s, "Request timeout for icmp_seq %d\n", seq);
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
    close(fd);

    tn_printf(s, "\n--- %s ping statistics ---\n", host);
    tn_printf(s, "%d packets transmitted, %d received, %d%% packet loss\n", sent, got,
              sent ? (sent - got) * 100 / sent : 0);
    if (got)
        tn_printf(s, "round-trip min/avg/max = %.1f/%.1f/%.1f ms\n", rmin, rsum / got, rmax);
    return 0;
}
