/* Telnet listener and session table. One thread per login. */
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
#include "c3shell.h"

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static session_t *slots[C3_MAX_SESSIONS];

int server_session_count(void)
{
    int n = 0;
    pthread_mutex_lock(&lock);
    for (int i = 0; i < C3_MAX_SESSIONS; i++)
        n += slots[i] != NULL;
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
    session_main(s);
    long room = port_stack_headroom();
    if (room >= 0)
        port_log("session %d: closed (stack headroom was %ld of %d bytes)", s->id, room, C3_SESSION_STACK);
    else
        port_log("session %d: closed", s->id);

    pthread_mutex_lock(&lock);
    slots[s->id] = NULL;
    pthread_mutex_unlock(&lock);
    close(s->fd);
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
    addr.sin_port = htons((uint16_t)port_telnet_port());
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    if (lfd < 0 || bind(lfd, (struct sockaddr *)&addr, sizeof addr) < 0 || listen(lfd, 2) < 0) {
        port_log("telnet: cannot listen on port %d", port_telnet_port());
        for (;;)
            port_sleep_ms(1000);
    }
    port_log("telnet: listening on port %d", port_telnet_port());

    for (;;) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof peer;
        int fd = accept(lfd, (struct sockaddr *)&peer, &plen);
        if (fd < 0) {
            port_sleep_ms(200);
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
            static const char busy[] = "c3shell: too many sessions, try again later\r\n";
            send(fd, busy, sizeof busy - 1, 0);
            close(fd);
            free(s);
            continue;
        }
        s->fd = fd;
        s->id = id;
        s->via_ap = port_sock_via_ap(fd);
        inet_ntop(AF_INET, &peer.sin_addr, s->peer, sizeof s->peer);

        if (port_thread_start("session", C3_SESSION_STACK, session_thread, s) != 0) {
            port_log("telnet: out of memory for a session thread");
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
    port_log(C3_NAME " " C3_VERSION " starting");
    ssh_global_init();
    netmgr_start();
    server_run();
}
