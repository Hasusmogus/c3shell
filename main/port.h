/* Platform abstraction. Everything in main/ *.c is portable C on top of this
 * header plus BSD sockets and pthreads; main/esp/ implements it for the
 * ESP32-C3 and sim/ implements it for a Linux host. */
#ifndef C3_PORT_H
#define C3_PORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---- persistent key/value store (keys <= 15 chars) ---- */
int  port_kv_get(const char *key, void *buf, size_t cap);   /* bytes read, or -1 */
int  port_kv_set(const char *key, const void *buf, size_t len);
void port_kv_del(const char *key);
void port_kv_wipe(void);

/* ---- the user's file area: a directory tree reached with ordinary POSIX
 *      calls under this prefix (its own flash partition on the chip) ---- */
const char *port_fs_root(void);
int  port_fs_usage(long *total, long *used);
void port_fs_wipe(void);

/* ---- system ---- */
uint32_t port_uptime_s(void);
void     port_sleep_ms(uint32_t ms);
void     port_random(void *buf, size_t len);
void     port_reboot(void);
void     port_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
int      port_thread_start(const char *name, size_t stack, void (*fn)(void *), void *arg);
long     port_free_heap(void);        /* -1 if unknown */
long     port_stack_headroom(void);   /* bytes never used on the calling thread's stack, -1 if unknown */
void     port_device_id(char out[5]); /* 4 hex chars, unique per board */
int      port_listen_port(void);      /* where the SSH server listens */
typedef struct {
    char host[64];                    /* the hardware, e.g. "ESP32-C3 rev v0.4" */
    char cpu[96];                     /* e.g. "RISC-V, 1 core @ 160 MHz" */
    long flash_kb;                    /* -1 if unknown */
    long heap_total;                  /* bytes, -1 if unknown */
} port_sysinfo_t;
void     port_sysinfo(port_sysinfo_t *out);  /* for 'fetch' */

/* ---- what 'top' shows ---- */
typedef struct {
    char     name[16];
    char     state;                   /* like ps: R runnable, S sleeping/waiting, other letters rare */
    uint8_t  prio;
    uint32_t id;                      /* stable while the task lives */
    uint32_t runtime;                 /* CPU time used so far, microseconds, wraps; 0 = not measured */
    long     stack_free;              /* bytes of stack never used, -1 if unknown */
} port_task_t;
int  port_tasks(port_task_t *out, int max, uint32_t *now_us); /* count or -1; now_us on runtime's clock */
void port_heap(long *free_now, long *min_free, long *largest); /* bytes, -1 where unknown */
bool     port_sock_via_ap(int fd);    /* did this client arrive over the setup network? */
/* A TCP connection through the VPN tunnel as an ordinary socket fd. On the chip
 * lwIP routes into the tunnel by itself, so this returns -2 ("use socket()");
 * the simulator bridges to its own lwIP. -1 = failed. */
int      port_vpn_dial(uint32_t ip_be, uint16_t port, int timeout_ms);

/* ---- local console: the USB serial port on the chip, a pseudo-terminal in
 *      the simulator (--console) ---- */
int  port_console_open(void);          /* non-blocking fd for reading and writing, -1 if there is none */
void port_console_quiet(bool quiet);   /* keep log lines off the console while someone is logged in */

/* ---- ping ---- */
/* A socket for ICMP echo. *with_ip_header: replies arrive with their IP
 * header in front (a raw socket, as on the chip). -1 if there is none. */
int  port_icmp_socket(bool *with_ip_header);

/* ---- WiFi ---- */
typedef struct {
    char    ssid[33];
    int8_t  rssi;
    uint8_t channel;
    uint8_t secure;
} port_ap_t;

enum { PORT_WIFI_OK = 0, PORT_WIFI_AUTH = -1, PORT_WIFI_NOT_FOUND = -2, PORT_WIFI_TIMEOUT = -3,
       PORT_WIFI_ERR = -4 };

int  port_wifi_scan(port_ap_t *out, int max);            /* count, strongest first */
int  port_wifi_ap_start(const char *ssid, const char *pass);
void port_wifi_ap_stop(void);
int  port_wifi_sta_connect(const char *ssid, const char *pass, uint32_t timeout_ms);
void port_wifi_sta_disconnect(void);                     /* stop trying / leave */
bool port_wifi_sta_up(void);                             /* associated and has an IP */
void port_wifi_sta_ip(char *out, size_t cap);
int  port_wifi_sta_rssi(void);
void port_wifi_ap_ip(char *out, size_t cap);

#endif
