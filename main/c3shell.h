#ifndef C3SHELL_H
#define C3SHELL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "config.h"
#include "port.h"

struct WOLFSSH;
struct shstate;

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
int  sshio_read_ext(struct WOLFSSH *ssh, uint8_t *buf, int cap, bool *is_stderr);
int  sshio_write(struct WOLFSSH *ssh, sshio_t *io, const uint8_t *data, int len);  /* 0 or -1 */

/* ---------- terminal session ---------- */
#define TN_CLOSED  (-1)
#define TN_TIMEOUT (-2)
#define TN_INTR    (-3)   /* Ctrl-C */
#define TN_EOF     (-4)   /* Ctrl-D on an empty line */

#define RL_ECHO    1
#define RL_HISTORY 2
#define RL_COMPLETE 4     /* Tab completes commands and file names */

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
    char     cwd[C3_PATH_MAX];   /* in the file area */
    char     hist[HIST_N][LINE_MAX_];
    int      hist_n;
    /* shown by 'top' */
    uint32_t since_s;        /* uptime when the connection arrived */
    char     doing[16];      /* "login", the running command, "" at the prompt */
    /* local console (USB serial) instead of SSH: io.fd is the console */
    bool     console;
    int8_t   size_probe;     /* console: does the terminal answer size queries? 0 untried, 1 yes, -1 no */
    /* shell language */
    bool     logout;         /* a command ended the session (exit, reboot, joining another network ...) */
    volatile bool intr;      /* Ctrl-C seen: a running script or loop stops */
    void    *redir;          /* FILE* that output goes to instead of the terminal (cmd > file) */
    struct shstate *sh;      /* variables and $? */
} session_t;

int  tn_getc(session_t *s, int timeout_ms);
bool tn_input_ready(session_t *s);                         /* typed bytes waiting? (non-blocking) */
int  tn_read_avail(session_t *s, uint8_t *buf, int cap);  /* non-blocking: n, 0, or TN_CLOSED */
int  tn_write(session_t *s, const void *data, size_t len); /* raw bytes */
void tn_puts(session_t *s, const char *str);               /* text, \n -> \r\n */
void tn_printf(session_t *s, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
int  tn_readline(session_t *s, const char *prompt, char *buf, size_t cap, int flags, int timeout_s);
bool tn_confirm(session_t *s, const char *question);       /* requires typing "yes" */
bool tn_peek_intr(session_t *s);                           /* Ctrl-C among the typed-ahead input? (sets s->intr) */

/* Tab completion: every way to finish the word being typed */
#define TN_CANDS 48
typedef struct {
    int  n;
    bool more;                       /* there were more than TN_CANDS */
    char c[TN_CANDS][C3_PATH_MAX];   /* full replacements for the word; directories end in '/' */
} tn_cands_t;
void shell_complete(session_t *s, const char *line, const char *word, tn_cands_t *out); /* line = text before the word */
void fs_complete(session_t *s, const char *word, bool dirs_only, tn_cands_t *out);

/* ---------- server ---------- */
extern int guard_block_s;
void c3shell_main(void);               /* start everything; never returns */
int  server_session_count(void);
typedef struct {
    int      id;
    bool     via_ap;
    uint32_t since_s;
    char     user[32], peer[24], doing[16];
} sess_info_t;
int  server_sessions(sess_info_t *out, int max);   /* snapshot of the session table */
int  cmd_top(session_t *s, int argc, char **argv); /* top.c */
int  cmd_ping(session_t *s, int argc, char **argv); /* ping.c */
int  cmd_traceroute(session_t *s, int argc, char **argv);
int  cmd_ip(session_t *s, int argc, char **argv);   /* ipcmd.c */
void server_console_attach(session_t *s);          /* show a console session in 'top' (NULL = none) */

/* ---------- local console (console.c) ---------- */
void console_start(void);                  /* login prompt on the USB serial port, if there is one */
void console_sync_size(session_t *s);      /* ask the terminal its size (there is no SSH to tell us) */
void server_kick_ap_sessions(void);
void session_main(session_t *s);       /* shell.c */
int  shell_command(session_t *s, int argc, char **argv); /* run a command by name: exit status, -1 if there is none */

/* ---------- shell language (script.c) ---------- */
int  sh_run(session_t *s, const char *text);     /* what was typed at the prompt: exit status */
bool sh_incomplete(const char *text);             /* an if/while/for or a quote is still open: read more */
void sh_free(session_t *s);
extern const char *const sh_builtins[];           /* names, for Tab completion (NULL-terminated) */

/* ---------- file area (fs.c, vi.c) ---------- */
int  fs_resolve(session_t *s, const char *arg, char *vpath, size_t vcap);  /* 0 or -errno */
int  fs_host(const char *vpath, char *host, size_t cap);              /* 0, or -ENAMETOOLONG */
int  fs_read_file(const char *host, char **data, size_t *len, size_t max);
int  fs_write_file(const char *host, const char *data, size_t len);
int  cmd_ls(session_t *s, int argc, char **argv);
int  cmd_cd(session_t *s, int argc, char **argv);
int  cmd_pwd(session_t *s, int argc, char **argv);
int  cmd_mkdir(session_t *s, int argc, char **argv);
int  cmd_rmdir(session_t *s, int argc, char **argv);
int  cmd_rm(session_t *s, int argc, char **argv);
int  cmd_touch(session_t *s, int argc, char **argv);
int  cmd_cat(session_t *s, int argc, char **argv);
int  cmd_cp(session_t *s, int argc, char **argv);
int  cmd_mv(session_t *s, int argc, char **argv);
int  cmd_df(session_t *s, int argc, char **argv);
int  cmd_vi(session_t *s, int argc, char **argv);

/* ---------- file transfers (xfer.c) ---------- */
int  xfer_serve(session_t *s, bool subsystem, const char *command);  /* sftp / scp -t / scp -f; exit status */
int  cmd_scp(session_t *s, int argc, char **argv);

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
typedef struct sshc sshc_t;
/* An authenticated connection running cmd on the far end (NULL = a terminal shell).
 * Prompts, host-key questions and errors go to the user's session. */
sshc_t *sshc_open(session_t *s, const char *user, const char *host, int port, const char *cmd);
int  sshc_read(sshc_t *c, uint8_t *buf, int cap, int timeout_ms, bool *is_stderr); /* >0, 0 timeout, -1 closed */
int  sshc_write(sshc_t *c, const void *data, int len);                             /* 0 or -1 */
int  sshc_send_eof(sshc_t *c);
int  sshc_exit_status(sshc_t *c);
void sshc_close(sshc_t *c);
int  sshstore_pubkey_line(char *out, size_t cap, bool regen);          /* device identity (outbound logins) */
int  sshstore_identity(uint8_t *der, size_t dercap, uint8_t pub[32]);  /* DER length or -1 */
int  sshstore_hostkey(uint8_t *der, size_t dercap, char *fp, size_t fpcap); /* this device's server key */
enum { KH_NEW, KH_MATCH, KH_CHANGED };
int  sshstore_host_check(const char *name, const uint8_t fp[32]);
void sshstore_host_add(const char *name, const uint8_t fp[32]);
int  sshstore_host_list(session_t *s);
bool sshstore_host_forget(const char *name_or_index);
void sshstore_fp_text(const uint8_t fp[32], char *out, size_t cap);

/* ---------- OpenVPN client (ovpn.c) and its tunnel interface (vpnif.c) ---------- */
#define VPN_MTU    1400   /* inner packets; keeps the encrypted ones under a WiFi frame */
#define VPN_ROUTES 16

typedef struct {
    bool     running;
    char     state[24];      /* off, connecting, configuring, connected, reconnecting, failed */
    char     error[160];     /* why the last attempt ended */
    char     ip[20], server[80], file[C3_PATH_MAX];
    uint32_t since_s;
    int      routes;
    bool     redirect;
    uint64_t rx, tx;
} vpn_status_t;

int  vpn_start(session_t *s, const char *ovpn_path);   /* parse, ask for credentials, start in the background */
void vpn_stop(void);
void vpn_status(vpn_status_t *st);

/* addresses in network byte order */
typedef struct {
    uint32_t ip, mask, peer;  /* peer: the far end of a point-to-point link (net30), else 0 */
    uint32_t server;          /* the VPN server: never routed into the tunnel */
    struct { uint32_t net, mask; } routes[VPN_ROUTES];
    int      nroutes;
    bool     redirect;        /* redirect-gateway: everything not local goes into the tunnel */
    uint32_t dns;
} vpnif_cfg_t;

int  vpnif_up(const vpnif_cfg_t *c, void (*out)(const uint8_t *pkt, size_t len));
bool vpnif_config(vpnif_cfg_t *out);  /* the tunnel's addresses and routes, if it is up */
void vpnif_down(void);
void vpnif_input(const uint8_t *pkt, size_t len);
bool vpn_routes_ip(uint32_t ip_be);
/* fd connected to ip:port through the VPN's own TCP/IP stack (simulator only),
 * -2 when the destination is not for that stack (use an ordinary socket), -1 on failure */
int  vpn_dial(uint32_t ip_be, uint16_t port, int timeout_ms);

#endif
