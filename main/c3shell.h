#ifndef C3SHELL_H
#define C3SHELL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "config.h"
#include "port.h"

struct WOLFSSH;

/* ---------- SSH transport glue (sshio.c) ---------- */
typedef struct {
    int      fd;
    bool     nonblock;        /* reads return "try again" instead of waiting */
    int      io_ms;           /* how long a blocking read may wait */
    uint32_t deadline_s;      /* uptime after which reads fail; 0 = none */
    volatile bool *kick;      /* owner is being told to stop */
} sshio_t;

void sshio_attach(struct WOLFSSH *ssh, sshio_t *io);     /* use io for this connection */
void sshio_ctx_setup(void *wolfssh_ctx);
int  sshio_read(struct WOLFSSH *ssh, uint8_t *buf, int cap);   /* >0 bytes, 0 nothing yet, -1 over */
int  sshio_write(struct WOLFSSH *ssh, sshio_t *io, const uint8_t *data, int len);  /* 0 or -1 */

/* ---------- terminal session ---------- */
#define TN_CLOSED  (-1)
#define TN_TIMEOUT (-2)
#define TN_INTR    (-3)   /* Ctrl-C */
#define TN_EOF     (-4)   /* Ctrl-D on an empty line */

#define RL_ECHO    1
#define RL_HISTORY 2

#define HIST_N   8
#define LINE_MAX_ 160

typedef struct session {
    int      id;
    bool     via_ap;
    bool     closed;
    volatile bool kick;      /* set by another thread: end this session */
    bool     setup;          /* let in without a password because no account exists yet */
    uint32_t peer_ip;
    struct WOLFSSH *ssh;     /* the user's connection to us */
    sshio_t  io;
    uint16_t cols, rows;
    bool     winch;
    /* input waiting to be consumed */
    uint8_t  ibuf[256];
    uint16_t ipos, ilen;
    /* shell */
    char     user[32];
    char     peer[24];
    char     hist[HIST_N][LINE_MAX_];
    int      hist_n;
} session_t;

int  tn_getc(session_t *s, int timeout_ms);
int  tn_read_avail(session_t *s, uint8_t *buf, int cap);  /* non-blocking: n, 0, or TN_CLOSED */
int  tn_write(session_t *s, const void *data, size_t len); /* raw bytes */
void tn_puts(session_t *s, const char *str);               /* text, \n -> \r\n */
void tn_printf(session_t *s, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
int  tn_readline(session_t *s, const char *prompt, char *buf, size_t cap, int flags, int timeout_s);
bool tn_confirm(session_t *s, const char *question);       /* requires typing "yes" */

/* ---------- server ---------- */
extern int guard_block_s;
void c3shell_main(void);               /* start everything; never returns */
int  server_session_count(void);
void server_kick_ap_sessions(void);
void session_main(session_t *s);       /* shell.c */

/* ---------- account ---------- */
bool account_exists(void);
int  account_create(const char *user, const char *pass);   /* 0, or -1 if one already exists */
bool account_check(const char *user, const char *pass);
int  account_set_password(const char *pass);
void account_name(char *out, size_t cap);
bool account_valid_username(const char *user);

/* ---------- network manager ---------- */
typedef struct {
    bool ap_up, sta_up, have_saved;
    char ap_ssid[33], sta_ssid[33], sta_ip[20], ap_ip[20];
    int  rssi;
} net_status_t;

extern int netmgr_fallback_s, netmgr_retry_s;
void netmgr_start(void);
void netmgr_status(net_status_t *st);
int  netmgr_scan(port_ap_t *out, int max);
int  netmgr_join(const char *ssid, const char *pass);
void netmgr_drop_ap(void);
void netmgr_forget(void);

/* ---------- outbound ssh + stored keys ---------- */
int  ssh_run(session_t *s, const char *user, const char *host, int port);
int  sshstore_pubkey_line(char *out, size_t cap, bool regen);          /* device identity (outbound logins) */
int  sshstore_identity(uint8_t *der, size_t dercap, uint8_t pub[32]);  /* DER length or -1 */
int  sshstore_hostkey(uint8_t *der, size_t dercap, char *fp, size_t fpcap); /* this device's server key */
enum { KH_NEW, KH_MATCH, KH_CHANGED };
int  sshstore_host_check(const char *name, const uint8_t fp[32]);
void sshstore_host_add(const char *name, const uint8_t fp[32]);
int  sshstore_host_list(session_t *s);
bool sshstore_host_forget(const char *name_or_index);
void sshstore_fp_text(const uint8_t fp[32], char *out, size_t cap);

#endif
