/* Host (Linux) implementation of port.h: the "virtual ESP32-C3".
 *
 * Real:      SSH server, shell, account store, SSH client (same code and
 *            same crypto as the firmware), reaching real machines.
 * Simulated: the radio. WiFi networks come from sim/networks.txt, the setup
 *            network is a flag, and flash storage is a directory of files.
 *
 * Type commands on the simulator's stdin to play the outside world; see
 * console() below or type "help". */
#define _GNU_SOURCE
#include <dirent.h>
#include <ftw.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include "c3shell.h"

void sim_lwip_start(void);

#define NETS_MAX 16

typedef struct {
    char ssid[33];
    char pass[65];
    int  rssi;
    bool visible;
} simnet_t;

static simnet_t nets[NETS_MAX];
static int nnets;
static const char *state_dir = "sim/state";
static const char *nets_file = "sim/networks.txt";
static int listen_port = 2222;
static int delay_scale = 100;          /* percent; --fast sets 3 */
static char **saved_argv;
static struct timespec t0;

static pthread_mutex_t wlock = PTHREAD_MUTEX_INITIALIZER;
static bool ap_up, sta_up;
static char ap_name[33], sta_ssid[33];

/* ---------------- system ---------------- */

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)(t.tv_sec - t0.tv_sec) + (double)(t.tv_nsec - t0.tv_nsec) / 1e9;
}

uint32_t port_uptime_s(void) { return (uint32_t)now_s(); }
void port_sleep_ms(uint32_t ms) { usleep(ms * 1000u); }
long port_free_heap(void) { return -1; }
int  port_listen_port(void) { return listen_port; }
void port_device_id(char out[5]) { memcpy(out, "51M0", 5); }

void port_sysinfo(port_sysinfo_t *o)
{
    struct utsname u;
    char line[256], model[80] = "unknown CPU";
    FILE *f = fopen("/proc/cpuinfo", "r");
    while (f && fgets(line, sizeof line, f)) {
        char *v = strchr(line, ':');
        if (v && strncmp(line, "model name", 10) == 0) {
            snprintf(model, sizeof model, "%s", v + 2);
            model[strcspn(model, "\n")] = 0;
            break;
        }
    }
    if (f)
        fclose(f);
    if (uname(&u) == 0)
        snprintf(o->host, sizeof o->host, "virtual ESP32-C3 (%.20s %.20s)", u.sysname, u.machine);
    else
        snprintf(o->host, sizeof o->host, "virtual ESP32-C3");
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    snprintf(o->cpu, sizeof o->cpu, "%s (%ld thread%s, host)", model, n, n == 1 ? "" : "s");
    o->flash_kb = -1;
    o->heap_total = -1;
}

void port_log(const char *fmt, ...)
{
    static pthread_mutex_t l = PTHREAD_MUTEX_INITIALIZER;
    va_list ap;
    pthread_mutex_lock(&l);
    printf("[%8.3f] ", now_s());
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
    fflush(stdout);
    pthread_mutex_unlock(&l);
}

void port_random(void *buf, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(buf, 1, len, f) != len)
        abort();
    fclose(f);
}

void port_reboot(void)
{
    port_log("[sim] *** reboot ***");
    for (int fd = 3; fd < 1024; fd++)
        close(fd);
    execv("/proc/self/exe", saved_argv);
    _exit(1);
}

/* Threads get exactly the stack the firmware would give them, pre-filled with
 * a pattern so the deepest use can be measured (shown by 'status' and when a
 * session closes). x86-64 frames are larger than RISC-V ones, so if a stack
 * size is enough here it is comfortably enough on the chip. Use --big-stacks
 * if you ever need to take the stack size out of the picture. */
#define STACK_GUARD (64 * 1024)
struct tramp { void (*fn)(void *); void *arg; uint8_t *stack; size_t size; };
static __thread struct tramp *self;
static bool big_stacks;

long port_stack_headroom(void)
{
    if (!self)
        return -1;
    size_t i = 0;
    while (i < self->size && self->stack[i] == 0xA5)
        i++;
    return (long)i;
}

static void *trampoline(void *p)
{
    self = p;
    self->fn(self->arg);
    return NULL;            /* stack and descriptor are leaked: fine for a test tool */
}

int port_thread_start(const char *name, size_t stack, void (*fn)(void *), void *arg)
{
    pthread_t th;
    pthread_attr_t at;
    struct tramp *t = malloc(sizeof *t);
    (void)name;
    if (!t)
        return -1;
    t->fn = fn;
    t->arg = arg;
    if (big_stacks)
        stack = 1024 * 1024;
    /* a guard region below the measured stack turns an overflow into a clear
     * "headroom 0" report instead of a crash somewhere else */
    t->size = stack;
    uint8_t *mem = malloc(STACK_GUARD + stack);
    if (!mem) {
        free(t);
        return -1;
    }
    memset(mem, 0xA5, STACK_GUARD + stack);
    t->stack = mem + STACK_GUARD;
    pthread_attr_init(&at);
    pthread_attr_setstack(&at, mem, STACK_GUARD + stack);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    int r = pthread_create(&th, &at, trampoline, t);
    pthread_attr_destroy(&at);
    if (r != 0)
        free(t);
    return r == 0 ? 0 : -1;
}

/* ---------------- storage: one file per key ---------------- */

static void kv_path(const char *key, char *out, size_t cap)
{
    snprintf(out, cap, "%s/%s.bin", state_dir, key);
}

int port_kv_get(const char *key, void *buf, size_t cap)
{
    char p[512];
    kv_path(key, p, sizeof p);
    FILE *f = fopen(p, "rb");
    if (!f)
        return -1;
    size_t n = fread(buf, 1, cap, f);
    fclose(f);
    return (int)n;
}

int port_kv_set(const char *key, const void *buf, size_t len)
{
    char p[512], tmp[520];
    kv_path(key, p, sizeof p);
    snprintf(tmp, sizeof tmp, "%s.tmp", p);
    FILE *f = fopen(tmp, "wb");
    if (!f)
        return -1;
    size_t n = fwrite(buf, 1, len, f);
    fclose(f);
    if (n != len || rename(tmp, p) != 0)
        return -1;
    return 0;
}

void port_kv_del(const char *key)
{
    char p[512];
    kv_path(key, p, sizeof p);
    unlink(p);
}

void port_kv_wipe(void)
{
    DIR *d = opendir(state_dir);
    struct dirent *e;
    while (d && (e = readdir(d))) {
        size_t n = strlen(e->d_name);
        if (n > 4 && strcmp(e->d_name + n - 4, ".bin") == 0) {
            char p[512];
            snprintf(p, sizeof p, "%s/%s", state_dir, e->d_name);
            unlink(p);
        }
    }
    if (d)
        closedir(d);
}

/* ---------------- file area: a plain directory ---------------- */

#define SIM_FS_TOTAL (0x1F0000L)      /* same size as the chip's storage partition */
static char fs_root[512];
static long fs_used_acc;

const char *port_fs_root(void) { return fs_root; }

static int add_size(const char *p, const struct stat *st, int flag, struct FTW *f)
{
    (void)p;
    (void)f;
    if (flag == FTW_F)
        fs_used_acc += (st->st_size + 4095) / 4096 * 4096;   /* whole 4 KB blocks, like LittleFS */
    else
        fs_used_acc += 4096;
    return 0;
}

int port_fs_usage(long *total, long *used)
{
    fs_used_acc = 0;
    nftw(fs_root, add_size, 16, FTW_PHYS);
    *total = SIM_FS_TOTAL;
    *used = fs_used_acc < SIM_FS_TOTAL ? fs_used_acc : SIM_FS_TOTAL;
    return 0;
}

static int rm_entry(const char *p, const struct stat *st, int flag, struct FTW *f)
{
    (void)st;
    (void)flag;
    if (f->level > 0)
        remove(p);
    return 0;
}

void port_fs_wipe(void)
{
    nftw(fs_root, rm_entry, 16, FTW_DEPTH | FTW_PHYS);
}

/* ---------------- simulated radio ---------------- */

static void sim_delay(int ms)
{
    usleep((useconds_t)(ms * delay_scale / 100) * 1000u);
}

static simnet_t *find_net(const char *ssid)
{
    for (int i = 0; i < nnets; i++)
        if (strcmp(nets[i].ssid, ssid) == 0)
            return &nets[i];
    return NULL;
}

static void load_nets(void)
{
    static const simnet_t defaults[] = {
        { "HomeNet", "homepass123", -48, true },
        { "Workshop-2.4", "soldering-iron", -66, true },
        { "CoffeeShop Free", "", -72, true },
        { "Neighbour_5F", "you-do-not-know-this", -86, true },
    };
    FILE *f = fopen(nets_file, "r");
    char line[256];
    if (!f) {
        memcpy(nets, defaults, sizeof defaults);
        nnets = (int)(sizeof defaults / sizeof defaults[0]);
        return;
    }
    while (nnets < NETS_MAX && fgets(line, sizeof line, f)) {
        char *ssid = line, *pass, *rssi;
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == '#' || line[0] == 0)
            continue;
        if (!(pass = strchr(ssid, '|')))
            continue;
        *pass++ = 0;
        if ((rssi = strchr(pass, '|')))
            *rssi++ = 0;
        simnet_t *n = &nets[nnets++];
        snprintf(n->ssid, sizeof n->ssid, "%.32s", ssid);
        snprintf(n->pass, sizeof n->pass, "%.64s", pass);
        n->rssi = rssi ? atoi(rssi) : -60;
        n->visible = true;
    }
    fclose(f);
}

int port_wifi_scan(port_ap_t *out, int max)
{
    int n = 0;
    sim_delay(1200);
    pthread_mutex_lock(&wlock);
    for (int i = 0; i < nnets && n < max; i++) {
        if (!nets[i].visible)
            continue;
        memset(&out[n], 0, sizeof out[n]);
        snprintf(out[n].ssid, sizeof out[n].ssid, "%.32s", nets[i].ssid);
        out[n].rssi = (int8_t)nets[i].rssi;
        out[n].channel = (uint8_t)(1 + (i * 5) % 11);
        out[n].secure = nets[i].pass[0] != 0;
        n++;
    }
    pthread_mutex_unlock(&wlock);
    for (int i = 1; i < n; i++)                 /* strongest first, like the real driver */
        for (int j = i; j > 0 && out[j].rssi > out[j - 1].rssi; j--) {
            port_ap_t t = out[j];
            out[j] = out[j - 1];
            out[j - 1] = t;
        }
    return n;
}

int port_wifi_ap_start(const char *ssid, const char *pass)
{
    pthread_mutex_lock(&wlock);
    ap_up = true;
    snprintf(ap_name, sizeof ap_name, "%s", ssid);
    pthread_mutex_unlock(&wlock);
    port_log("[sim] radio: hosting '%s' (%s) - reach it with: ssh -p %d localhost", ssid,
             pass[0] ? "WPA2" : "open", listen_port);
    return 0;
}

void port_wifi_ap_stop(void)
{
    pthread_mutex_lock(&wlock);
    ap_up = false;
    pthread_mutex_unlock(&wlock);
    port_log("[sim] radio: stopped hosting '%s'", ap_name);
}

int port_wifi_sta_connect(const char *ssid, const char *pass, uint32_t timeout_ms)
{
    int r;
    (void)timeout_ms;
    pthread_mutex_lock(&wlock);
    sta_up = false;
    simnet_t *n = find_net(ssid);
    if (!n || !n->visible)
        r = PORT_WIFI_NOT_FOUND;
    else if (strcmp(n->pass, pass) != 0)
        r = PORT_WIFI_AUTH;
    else
        r = PORT_WIFI_OK;
    pthread_mutex_unlock(&wlock);

    sim_delay(r == PORT_WIFI_OK ? 1500 : 3000);

    pthread_mutex_lock(&wlock);
    if (r == PORT_WIFI_OK) {
        sta_up = true;
        snprintf(sta_ssid, sizeof sta_ssid, "%s", ssid);
    }
    pthread_mutex_unlock(&wlock);
    port_log("[sim] radio: join '%s' -> %s", ssid,
             r == PORT_WIFI_OK ? "connected, got 192.168.0.77" : r == PORT_WIFI_AUTH ? "wrong password" : "not found");
    return r;
}

void port_wifi_sta_disconnect(void)
{
    pthread_mutex_lock(&wlock);
    sta_up = false;
    pthread_mutex_unlock(&wlock);
}

bool port_wifi_sta_up(void) { return sta_up; }
int  port_wifi_sta_rssi(void)
{
    simnet_t *n = find_net(sta_ssid);
    return n ? n->rssi : 0;
}
void port_wifi_sta_ip(char *out, size_t cap) { snprintf(out, cap, "%s", sta_up ? "192.168.0.77" : ""); }
void port_wifi_ap_ip(char *out, size_t cap) { snprintf(out, cap, "192.168.4.1"); }

/* Everything arrives on localhost here, so approximate: a client that
 * connected while the setup network was up is treated as being on it. */
bool port_sock_via_ap(int fd)
{
    (void)fd;
    return ap_up;
}

/* ---------------- operator console (stdin) ---------------- */

static void *console(void *arg)
{
    char line[128];
    (void)arg;
    while (fgets(line, sizeof line, stdin)) {
        char *cmd = strtok(line, " \t\r\n"), *rest = strtok(NULL, "\r\n");
        if (!cmd)
            continue;
        if (strcmp(cmd, "down") == 0 || strcmp(cmd, "up") == 0) {
            bool vis = cmd[0] == 'u';
            pthread_mutex_lock(&wlock);
            simnet_t *n = find_net(rest ? rest : sta_ssid);
            if (n) {
                n->visible = vis;
                if (!vis && sta_up && strcmp(n->ssid, sta_ssid) == 0)
                    sta_up = false;
            }
            pthread_mutex_unlock(&wlock);
            if (n)
                port_log("[sim] network '%s' is now %s", n->ssid, vis ? "in range" : "out of range");
            else
                port_log("[sim] no such network");
        } else if (strcmp(cmd, "nets") == 0) {
            for (int i = 0; i < nnets; i++)
                port_log("[sim]   %-24s %4d dBm  %s  password: %s", nets[i].ssid, nets[i].rssi,
                         nets[i].visible ? "in range " : "out of range", nets[i].pass[0] ? nets[i].pass : "(open)");
        } else if (strcmp(cmd, "status") == 0) {
            port_log("[sim] hosting: %s   joined: %s   sessions: %d", ap_up ? ap_name : "no",
                     sta_up ? sta_ssid : "no", server_session_count());
        } else if (strcmp(cmd, "reboot") == 0) {
            port_reboot();
        } else if (strcmp(cmd, "quit") == 0) {
            exit(0);
        } else {
            port_log("[sim] commands: nets | down [ssid] | up [ssid] | status | reboot | quit");
        }
    }
    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t th;
    bool fresh = false;

    saved_argv = argv;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    signal(SIGPIPE, SIG_IGN);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--fresh") == 0)
            fresh = true;
        else if (strcmp(argv[i], "--kept") == 0)
            ;
        else if (strcmp(argv[i], "--big-stacks") == 0)
            big_stacks = true;
        else if (strcmp(argv[i], "--fast") == 0)
            delay_scale = 3;
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            listen_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--state") == 0 && i + 1 < argc)
            state_dir = argv[++i];
        else if (strcmp(argv[i], "--networks") == 0 && i + 1 < argc)
            nets_file = argv[++i];
        else if (strcmp(argv[i], "--fallback") == 0 && i + 1 < argc)
            netmgr_fallback_s = atoi(argv[++i]);
        else if (strcmp(argv[i], "--retry") == 0 && i + 1 < argc)
            netmgr_retry_s = atoi(argv[++i]);
        else if (strcmp(argv[i], "--block") == 0 && i + 1 < argc)
            guard_block_s = atoi(argv[++i]);
        else {
            fprintf(stderr,
                    "usage: %s [--fresh] [--fast] [--big-stacks] [--port N] [--state DIR] [--networks FILE]\n"
                    "          [--fallback SECONDS] [--retry SECONDS] [--block SECONDS]\n", argv[0]);
            return 2;
        }
    }
    mkdir(state_dir, 0700);
    snprintf(fs_root, sizeof fs_root, "%s/fs", state_dir);
    mkdir(fs_root, 0700);
    if (fresh) {
        port_kv_wipe();
        port_fs_wipe();
        for (int i = 1; i < argc; i++)          /* a simulated reboot must not wipe again */
            if (strcmp(argv[i], "--fresh") == 0)
                argv[i] = "--kept";
    }
    load_nets();
    port_log("[sim] virtual ESP32-C3, state in %s/, %d simulated networks", state_dir, nnets);
    pthread_create(&th, NULL, console, NULL);
    sim_lwip_start();      /* the VPN tunnel's TCP/IP stack (sim/vpn_proxy.c) */
    c3shell_main();
    return 0;
}
