/* A small OpenVPN client (protocol version 2, as spoken by OpenVPN 2.4 - 2.7
 * servers and compatible ones).
 *
 *   transport      UDP or TCP, IPv4
 *   control        reliable layer + TLS 1.2/1.3 (wolfSSL), certificate login,
 *                  optional auth-user-pass; tls-auth or tls-crypt wrapping
 *   keys           key-method 2; "tls-ekm" exporter, or the classic PRF
 *   data channel   AES-128/256-GCM, DATA_V1 or DATA_V2 (peer-id),
 *                  "compress"/"comp-lzo" stubs (no actual compression)
 *   tunnel         dev tun only, delivered to lwIP through vpnif.c
 *
 * One thread runs the protocol; a second only waits for packets from the
 * server. Packets lwIP sends into the tunnel are queued from the TCP/IP
 * thread (which must never block on a socket) and sent by the protocol
 * thread. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/sha.h>

#include "c3shell.h"

/* ---------------- protocol constants ---------------- */

enum {
    P_CONTROL_SOFT_RESET_V1 = 3, P_CONTROL_V1 = 4, P_ACK_V1 = 5, P_DATA_V1 = 6,
    P_CONTROL_HARD_RESET_CLIENT_V2 = 7, P_CONTROL_HARD_RESET_SERVER_V2 = 8, P_DATA_V2 = 9,
};
#define IV_PROTO_DATA_V2        (1 << 1)
#define IV_PROTO_TLS_KEY_EXPORT (1 << 3)

static const uint8_t PING_MAGIC[16] = { 0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
                                        0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48 };
static const uint8_t OCC_MAGIC[16] = { 0x28, 0x7f, 0x34, 0x6f, 0x81, 0x32, 0x4c, 0x8d,
                                       0x41, 0xcd, 0x52, 0x72, 0x79, 0x27, 0x3a, 0xe3 };
#define OCC_EXIT 6

#define MAX_PKT      2048            /* largest packet on the wire we accept */
#define CTL_CHUNK    1000            /* TLS bytes per control packet */
#define REL_SEND     4               /* control packets in flight (the server's window) */
#define REL_RECV     8
#define ACK_MAX      4
#define QMAX         32              /* packets waiting in each direction */
#define HAND_WINDOW  60              /* seconds to finish a (re)negotiation */
#define LAME_DUCK_S  60              /* an old key keeps decrypting this long after a new one */

enum { WRAP_NONE, WRAP_AUTH, WRAP_CRYPT };
enum { COMP_NONE, COMP_STUB, COMP_STUB_V2 };
enum { KS_FREE, KS_RESET, KS_TLS, KS_KM2, KS_PUSH, KS_ACTIVE };

/* ---------------- configuration (.ovpn) ---------------- */

typedef struct {
    char     host[4][64];
    uint16_t port[4];
    int8_t   tcp[4];                 /* 1 tcp, 0 udp, -1 whatever 'proto' says */
    int      nremote;
    char    *ca, *cert, *key;        /* PEM text */
    int      wrap;
    uint8_t  wrapkey[256];
    int      key_dir;                /* -1 bidirectional, 0 or 1 */
    int      auth_hash;              /* tls-auth HMAC: WC_SHA, WC_SHA256, WC_SHA512 */
    bool     auth_user_pass;
    char     authfile[C3_PATH_MAX];
    bool     remote_cert_tls;
    char     x509_name[64];          /* verify-x509-name: the server certificate's CN ... */
    bool     x509_prefix;            /* ... or its start */
    int      ping, ping_restart;
    char     ciphers[64];            /* advertised, ours first */
    char     ignored[160];
} ovcfg_t;

/* ---------------- state ---------------- */

typedef struct {
    uint32_t id;
    uint16_t len;
    uint8_t  op;
    uint8_t  tries;
    uint32_t sent_ms;
    uint8_t *data;                   /* the control body after the wrap: msgid + payload */
} relout_t;

typedef struct {
    int      state;
    uint8_t  key_id;
    uint32_t started_s, retired_s;
    /* reliability layer */
    uint32_t send_id, recv_id;
    relout_t out[REL_SEND];
    struct { bool used; uint32_t id; uint16_t len; uint8_t op; uint8_t *data; } in[REL_RECV];
    uint32_t acks[ACK_MAX * 2];
    int      nacks;
    /* TLS over it */
    WOLFSSL *ssl;
    uint8_t *tin, *tout, *pt;        /* received TLS, TLS to send, decrypted plaintext */
    size_t   tin_len, tout_len, pt_len, tin_cap, tout_cap, pt_cap;
    bool     km2_got, km2_tail;
    uint8_t  pre_master[48], c_r1[32], c_r2[32], s_r1[32], s_r2[32];
    /* data channel */
    bool     keys;
    Aes      enc, dec;
    uint8_t  iv_enc[8], iv_dec[8];
    uint32_t pid_send, replay_top;
    uint64_t replay_bits;
} kstate_t;

typedef struct qpkt { struct qpkt *next; uint16_t len; uint8_t data[]; } qpkt_t;

typedef struct {
    ovcfg_t  cfg;
    char     path[C3_PATH_MAX];
    char     user[64], pass[128], token[256];
    /* transport */
    int      fd;
    bool     tcp;
    struct sockaddr_in srv;
    char     srvname[80];
    /* session */
    uint8_t  sid[8], psid[8];
    bool     have_psid;
    uint8_t  hk_out[64], hk_in[64], ck_out[32], ck_in[32];
    int      hlen;
    uint32_t wrap_pid, wrap_time, wrap_rx_top;
    uint64_t wrap_rx_bits;
    WOLFSSL_CTX *ctx;
    kstate_t ks[2];
    int      cur;                    /* ks[] index that sends data */
    uint8_t  next_key_id;
    /* pushed */
    char     push[1536];
    size_t   push_len;
    bool     ekm, subnet, pushed;
    int      peer_id, keylen, comp;
    int      ping, ping_restart;
    vpnif_cfg_t net;
    /* timers (seconds of uptime) */
    uint32_t last_rx_s, last_tx_s;
    /* queues */
    qpkt_t  *inq, *outq;
    int      ninq, noutq;
    /* stats */
    uint64_t rx_bytes, tx_bytes;
    /* scratch space for the protocol thread (kept off its stack, which the
     * TLS handshake needs): one per call path, none of them nest */
    uint8_t  rx_body[MAX_PKT];                       /* control_recv */
    uint8_t  tx_body[CTL_CHUNK + 64], tx_pkt[CTL_CHUNK + 160];   /* ctl_emit */
    uint8_t  d_pkt[MAX_PKT], d_pt[MAX_PKT];          /* data_send / data_recv */
} vpn_t;

static pthread_mutex_t qlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  qcond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t slock = PTHREAD_MUTEX_INITIALIZER;   /* status fields below */
static vpn_t *V;
static volatile bool want_stop, running, rx_run, rx_alive;
static char st_state[24] = "off", st_error[160], st_ip[20], st_server[80], st_file[C3_PATH_MAX];
static uint32_t st_since;
static int st_routes;
static bool st_redirect;

static void set_state(const char *state, const char *err)
{
    pthread_mutex_lock(&slock);
    if (strcmp(st_state, state) != 0)
        st_since = port_uptime_s();
    snprintf(st_state, sizeof st_state, "%s", state);
    if (err)
        snprintf(st_error, sizeof st_error, "%s", err);
    pthread_mutex_unlock(&slock);
}

static uint32_t now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint32_t)((uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u);
}

static void put16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static uint32_t get16(const uint8_t *p) { return (uint32_t)p[0] << 8 | p[1]; }
static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

/* ================================================================
 * configuration file
 * ================================================================ */

static void note_ignored(ovcfg_t *c, const char *what)
{
    size_t n = strlen(c->ignored);
    if (strstr(c->ignored, what))
        return;
    snprintf(c->ignored + n, sizeof c->ignored - n, "%s%s", n ? ", " : "", what);
}

/* "-----BEGIN OpenVPN Static key V1-----" hex block -> 256 bytes */
static int static_key(const char *text, uint8_t out[256])
{
    const char *p = strstr(text, "-----BEGIN OpenVPN Static key V1-----");
    int n = 0, half = -1;
    if (!p)
        return -1;
    p = strchr(p, '\n');
    for (; p && *p && n < 256; p++) {
        if (*p == '-')
            break;
        int v = *p >= '0' && *p <= '9' ? *p - '0' : *p >= 'a' && *p <= 'f' ? *p - 'a' + 10
              : *p >= 'A' && *p <= 'F' ? *p - 'A' + 10 : -1;
        if (v < 0)
            continue;
        if (half < 0) {
            half = v;
        } else {
            out[n++] = (uint8_t)(half << 4 | v);
            half = -1;
        }
    }
    return n == 256 ? 0 : -1;
}

/* A file the config names, relative to the config's own directory. */
static char *side_file(session_t *s, const char *cfgpath, const char *name, char *err, size_t ecap)
{
    char dir[C3_PATH_MAX], vpath[C3_PATH_MAX], host[C3_HOST_MAX], *data = NULL;
    size_t len;
    snprintf(dir, sizeof dir, "%s", cfgpath);
    char *slash = strrchr(dir, '/');
    if (slash)
        slash[slash == dir ? 1 : 0] = 0;
    session_t tmp = *s;                   /* resolve against the config's directory */
    snprintf(tmp.cwd, sizeof tmp.cwd, "%s", dir[0] ? dir : "/");
    if (fs_resolve(&tmp, name, vpath, sizeof vpath) < 0 || fs_host(vpath, host, sizeof host) < 0 ||
        fs_read_file(host, &data, &len, 64 * 1024) != 0) {
        snprintf(err, ecap, "cannot read '%s'", name);
        return NULL;
    }
    return data;
}

static int parse_config(session_t *s, const char *vpath, char *text, ovcfg_t *c, char *err, size_t ecap)
{
    char *save = NULL, *block = NULL, *bstart = NULL;
    bool is_client = false, def_tcp = false;
    uint16_t def_port = 1194;
    char tlsauth_file[C3_PATH_MAX] = "", tlscrypt_file[C3_PATH_MAX] = "";

    memset(c, 0, sizeof *c);
    c->key_dir = -1;
    c->auth_hash = WC_SHA;
    snprintf(c->ciphers, sizeof c->ciphers, "AES-256-GCM:AES-128-GCM");

    char *text_end = text + strlen(text);
    for (char *line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        if (block) {                     /* inside <ca> ... </ca> and friends */
            char close[24];
            const char *p = line + strspn(line, " \t");
            int cl = snprintf(close, sizeof close, "</%s>", block);
            if (strncmp(p, close, (size_t)cl) == 0 && p[cl + strspn(p + cl, " \t\r")] == 0) {
                if (line > bstart)
                    line[-1] = 0;        /* bstart .. here is the block's text */
                else
                    *bstart = 0;
                char *dup = strdup(bstart);
                if (!dup) {
                    snprintf(err, ecap, "out of memory");
                    return -1;
                }
                if (strcmp(block, "ca") == 0)
                    c->ca = dup;
                else if (strcmp(block, "cert") == 0)
                    c->cert = dup;
                else if (strcmp(block, "key") == 0)
                    c->key = dup;
                else {
                    int r = static_key(dup, c->wrapkey);
                    free(dup);
                    if (r < 0) {
                        snprintf(err, ecap, "<%s> is not an OpenVPN static key", block);
                        return -1;
                    }
                    c->wrap = strcmp(block, "tls-crypt") == 0 ? WRAP_CRYPT : WRAP_AUTH;
                }
                block = NULL;
            } else if (line + strlen(line) < text_end) {
                line[strlen(line)] = '\n';  /* undo strtok: keep the block's lines together */
            }
            continue;
        }
        size_t L = strlen(line);
        while (L && (line[L - 1] == '\r' || line[L - 1] == ' ' || line[L - 1] == '\t'))
            line[--L] = 0;
        while (*line == ' ' || *line == '\t')
            line++;
        if (!*line || *line == '#' || *line == ';')
            continue;

        char *argv[6] = { 0 };
        int argc = 0;
        for (char *sv = NULL, *w = strtok_r(line, " \t", &sv); w && argc < 6; w = strtok_r(NULL, " \t", &sv))
            argv[argc++] = w;
        const char *k = argv[0];

        if (k[0] == '<') {
            static const char *names[] = { "ca", "cert", "key", "tls-auth", "tls-crypt" };
            char name[24];
            snprintf(name, sizeof name, "%.*s", (int)strcspn(k + 1, ">"), k + 1);
            if (strcmp(name, "tls-crypt-v2") == 0 || strcmp(name, "pkcs12") == 0 || strcmp(name, "secret") == 0) {
                snprintf(err, ecap, "<%s> is not supported", name);
                return -1;
            }
            block = NULL;
            for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
                if (strcmp(name, names[i]) == 0)
                    block = (char *)names[i];
            if (!block) {
                snprintf(err, ecap, "unknown block <%s>", name);
                return -1;
            }
            /* the block's text starts on the next line */
            bstart = save;
            continue;
        }

        if (strcmp(k, "client") == 0 || strcmp(k, "tls-client") == 0) {
            is_client = true;
        } else if (strcmp(k, "dev") == 0 || strcmp(k, "dev-type") == 0) {
            if (argc < 2 || strncmp(argv[1], "tun", 3) != 0) {
                snprintf(err, ecap, "only 'dev tun' is supported (not '%s')", argc > 1 ? argv[1] : "");
                return -1;
            }
        } else if (strcmp(k, "proto") == 0 && argc > 1) {
            if (strncmp(argv[1], "tcp", 3) == 0)
                def_tcp = true;
            else if (strncmp(argv[1], "udp", 3) == 0)
                def_tcp = false;
            if (strstr(argv[1], "6")) {
                snprintf(err, ecap, "IPv6 transport is not supported");
                return -1;
            }
        } else if (strcmp(k, "port") == 0 && argc > 1) {
            def_port = (uint16_t)atoi(argv[1]);
        } else if (strcmp(k, "remote") == 0 && argc > 1) {
            if (c->nremote < 4) {
                int i = c->nremote++;
                snprintf(c->host[i], sizeof c->host[i], "%s", argv[1]);
                c->port[i] = argc > 2 ? (uint16_t)atoi(argv[2]) : 0;
                c->tcp[i] = argc > 3 ? strncmp(argv[3], "tcp", 3) == 0 : -1;
            }
        } else if ((strcmp(k, "ca") == 0 || strcmp(k, "cert") == 0 || strcmp(k, "key") == 0) && argc > 1) {
            char *data = side_file(s, vpath, argv[1], err, ecap);
            if (!data)
                return -1;
            char **slot = k[0] == 'c' && k[1] == 'a' ? &c->ca : k[1] == 'e' ? &c->cert : &c->key;
            free(*slot);
            *slot = data;
        } else if (strcmp(k, "tls-auth") == 0) {
            if (argc > 1 && strcmp(argv[1], "[inline]") != 0)
                snprintf(tlsauth_file, sizeof tlsauth_file, "%s", argv[1]);
            if (argc > 2)
                c->key_dir = atoi(argv[2]);
            c->wrap = WRAP_AUTH;
        } else if (strcmp(k, "tls-crypt") == 0) {
            if (argc > 1 && strcmp(argv[1], "[inline]") != 0)
                snprintf(tlscrypt_file, sizeof tlscrypt_file, "%s", argv[1]);
            c->wrap = WRAP_CRYPT;
        } else if (strcmp(k, "tls-crypt-v2") == 0 || strcmp(k, "pkcs12") == 0 || strcmp(k, "secret") == 0) {
            snprintf(err, ecap, "'%s' is not supported", k);
            return -1;
        } else if (strcmp(k, "key-direction") == 0 && argc > 1) {
            c->key_dir = atoi(argv[1]);
        } else if (strcmp(k, "auth") == 0 && argc > 1) {
            if (strcasecmp(argv[1], "SHA1") == 0)
                c->auth_hash = WC_SHA;
            else if (strcasecmp(argv[1], "SHA256") == 0)
                c->auth_hash = WC_SHA256;
            else if (strcasecmp(argv[1], "SHA512") == 0)
                c->auth_hash = WC_SHA512;
            else {
                snprintf(err, ecap, "auth %s is not supported (SHA1, SHA256, SHA512)", argv[1]);
                return -1;
            }
        } else if (strcmp(k, "auth-user-pass") == 0) {
            c->auth_user_pass = true;
            if (argc > 1)
                snprintf(c->authfile, sizeof c->authfile, "%s", argv[1]);
        } else if (strcmp(k, "verify-x509-name") == 0 && argc > 1) {
            const char *type = argc > 2 ? argv[2] : "subject";
            if (strcmp(type, "name") != 0 && strcmp(type, "name-prefix") != 0) {
                snprintf(err, ecap, "verify-x509-name: only the 'name' and 'name-prefix' forms are supported");
                return -1;
            }
            snprintf(c->x509_name, sizeof c->x509_name, "%s", argv[1]);
            c->x509_prefix = strcmp(type, "name-prefix") == 0;
        } else if (strcmp(k, "remote-cert-tls") == 0) {
            c->remote_cert_tls = argc > 1 && strcmp(argv[1], "server") == 0;
        } else if (strcmp(k, "keepalive") == 0 && argc > 2) {
            c->ping = atoi(argv[1]);
            c->ping_restart = atoi(argv[2]);
        } else if (strcmp(k, "ping") == 0 && argc > 1) {
            c->ping = atoi(argv[1]);
        } else if (strcmp(k, "ping-restart") == 0 && argc > 1) {
            c->ping_restart = atoi(argv[1]);
        } else if ((strcmp(k, "cipher") == 0 || strcmp(k, "data-ciphers") == 0 || strcmp(k, "ncp-ciphers") == 0) &&
                   argc > 1) {
            /* advertise the GCM ciphers this list allows, in its order */
            char list[64] = "", tmp[128];
            snprintf(tmp, sizeof tmp, "%s", argv[1]);
            for (char *sv = NULL, *ci = strtok_r(tmp, ":", &sv); ci; ci = strtok_r(NULL, ":", &sv)) {
                if (strcasecmp(ci, "AES-256-GCM") == 0 || strcasecmp(ci, "AES-128-GCM") == 0) {
                    size_t n = strlen(list);
                    snprintf(list + n, sizeof list - n, "%s%s", n ? ":" : "", ci);
                }
            }
            if (list[0])
                snprintf(c->ciphers, sizeof c->ciphers, "%s", list);
            else if (strcmp(k, "data-ciphers") == 0) {
                snprintf(err, ecap, "none of the data-ciphers is supported (AES-256-GCM, AES-128-GCM)");
                return -1;
            }
        } else if (strcmp(k, "nobind") == 0 || strcmp(k, "persist-key") == 0 || strcmp(k, "persist-tun") == 0 ||
                   strcmp(k, "resolv-retry") == 0 || strcmp(k, "verb") == 0 || strcmp(k, "mute") == 0 ||
                   strcmp(k, "remote-random") == 0 || strcmp(k, "float") == 0 || strcmp(k, "auth-nocache") == 0 ||
                   strcmp(k, "tls-version-min") == 0 || strcmp(k, "reneg-sec") == 0 ||
                   strcmp(k, "explicit-exit-notify") == 0 || strcmp(k, "mute-replay-warnings") == 0 ||
                   strcmp(k, "pull") == 0 || strcmp(k, "comp-lzo") == 0 || strcmp(k, "compress") == 0 ||
                   strcmp(k, "allow-compression") == 0 || strcmp(k, "setenv") == 0 || strcmp(k, "user") == 0 ||
                   strcmp(k, "group") == 0 || strcmp(k, "connect-retry") == 0 || strcmp(k, "server-poll-timeout") == 0 ||
                   strcmp(k, "tun-mtu") == 0 || strcmp(k, "mssfix") == 0 || strcmp(k, "route-delay") == 0 ||
                   strcmp(k, "remote-cert-eku") == 0 || strcmp(k, "ns-cert-type") == 0 || strcmp(k, "tls-cipher") == 0 ||
                   strcmp(k, "ignore-unknown-option") == 0 || strcmp(k, "block-outside-dns") == 0 ||
                   strcmp(k, "script-security") == 0 || strcmp(k, "up") == 0 || strcmp(k, "down") == 0 ||
                   strcmp(k, "route-nopull") == 0 || strcmp(k, "pull-filter") == 0 || strcmp(k, "dhcp-option") == 0) {
            if (strcmp(k, "route-nopull") == 0 || strcmp(k, "pull-filter") == 0 ||
                strcmp(k, "remote-cert-eku") == 0 || strcmp(k, "ns-cert-type") == 0)
                note_ignored(c, k);
        } else {
            note_ignored(c, k);
        }
    }
    if (block) {
        snprintf(err, ecap, "<%s> is never closed", block);
        return -1;
    }
    if (!is_client) {
        snprintf(err, ecap, "not a client configuration (no 'client' line)");
        return -1;
    }
    if (c->nremote == 0) {
        snprintf(err, ecap, "no 'remote' line");
        return -1;
    }
    for (int i = 0; i < c->nremote; i++) {
        if (!c->port[i])
            c->port[i] = def_port;
        if (c->tcp[i] < 0)
            c->tcp[i] = def_tcp;
    }
    if (tlsauth_file[0] || tlscrypt_file[0]) {
        char *data = side_file(s, vpath, tlsauth_file[0] ? tlsauth_file : tlscrypt_file, err, ecap);
        if (!data)
            return -1;
        int r = static_key(data, c->wrapkey);
        free(data);
        if (r < 0) {
            snprintf(err, ecap, "the tls-auth/tls-crypt file is not an OpenVPN static key");
            return -1;
        }
    }
    if (!c->ca) {
        snprintf(err, ecap, "no CA certificate (ca / <ca>)");
        return -1;
    }
    if (!c->cert != !c->key) {
        snprintf(err, ecap, "a client certificate needs its key, and the other way round");
        return -1;
    }
    if (!c->cert && !c->auth_user_pass) {
        snprintf(err, ecap, "no way to log in: neither a client certificate nor auth-user-pass");
        return -1;
    }
    if (c->key && strstr(c->key, "ENCRYPTED")) {
        snprintf(err, ecap, "the private key is password-protected; store it without a passphrase");
        return -1;
    }
    return 0;
}

static void free_config(ovcfg_t *c)
{
    free(c->ca);
    free(c->cert);
    free(c->key);
    memset(c, 0, sizeof *c);
}

/* ================================================================
 * queues between the threads
 * ================================================================ */

static bool q_push(qpkt_t **q, int *n, const uint8_t *data, size_t len)
{
    if (*n >= QMAX)
        return false;
    qpkt_t *p = malloc(sizeof *p + len);
    if (!p)
        return false;
    p->next = NULL;
    p->len = (uint16_t)len;
    memcpy(p->data, data, len);
    while (*q)
        q = &(*q)->next;
    *q = p;
    (*n)++;
    return true;
}

static qpkt_t *q_pop(qpkt_t **q, int *n)
{
    qpkt_t *p = *q;
    if (p) {
        *q = p->next;
        (*n)--;
    }
    return p;
}

static void q_clear(qpkt_t **q, int *n)
{
    for (qpkt_t *p; (p = q_pop(q, n));)
        free(p);
}

/* from lwIP's TCP/IP thread: never block here */
static void tun_out(const uint8_t *pkt, size_t len)
{
    pthread_mutex_lock(&qlock);
    if (V && running && V->ks[V->cur].keys)
        q_push(&V->outq, &V->noutq, pkt, len);
    pthread_cond_signal(&qcond);
    pthread_mutex_unlock(&qlock);
}

/* ================================================================
 * transport
 * ================================================================ */

static void rx_thread(void *arg)
{
    vpn_t *v = arg;
    uint8_t *buf = malloc(MAX_PKT + 2);
    size_t have = 0;

    while (buf && rx_run) {
        ssize_t n;
        if (!v->tcp) {
            n = recv(v->fd, buf, MAX_PKT, 0);
            if (n <= 0) {
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
                    continue;
                port_sleep_ms(100);     /* ICMP unreachable and the like: keep listening */
                continue;
            }
            pthread_mutex_lock(&qlock);
            q_push(&v->inq, &v->ninq, buf, (size_t)n);
            pthread_cond_signal(&qcond);
            pthread_mutex_unlock(&qlock);
            continue;
        }
        /* TCP: 16-bit length, then the packet */
        n = recv(v->fd, buf + have, MAX_PKT + 2 - have, 0);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
            continue;
        if (n <= 0) {
            pthread_mutex_lock(&qlock);
            q_push(&v->inq, &v->ninq, (const uint8_t *)"", 0);   /* empty = connection lost */
            pthread_cond_signal(&qcond);
            pthread_mutex_unlock(&qlock);
            break;
        }
        have += (size_t)n;
        while (have >= 2) {
            size_t plen = get16(buf);
            if (plen == 0 || plen > MAX_PKT) {
                have = 0;
                break;
            }
            if (have < plen + 2)
                break;
            pthread_mutex_lock(&qlock);
            q_push(&v->inq, &v->ninq, buf + 2, plen);
            pthread_cond_signal(&qcond);
            pthread_mutex_unlock(&qlock);
            memmove(buf, buf + 2 + plen, have - plen - 2);
            have -= plen + 2;
        }
    }
    free(buf);
    rx_alive = false;
}

static int wire_send(vpn_t *v, const uint8_t *pkt, size_t len)
{
    ssize_t n;
    if (v->tcp) {
        uint8_t hdr[2];
        put16(hdr, (uint32_t)len);
        /* one buffer so the length and the packet leave together */
        uint8_t *b = malloc(len + 2);
        if (!b)
            return -1;
        memcpy(b, hdr, 2);
        memcpy(b + 2, pkt, len);
        size_t off = 0;
        while (off < len + 2) {
            n = send(v->fd, b + off, len + 2 - off, 0);
            if (n <= 0) {
                free(b);
                return -1;
            }
            off += (size_t)n;
        }
        free(b);
    } else {
        n = send(v->fd, pkt, len, 0);
        if (n < 0)
            return -1;
    }
    v->tx_bytes += len;
    v->last_tx_s = port_uptime_s();
    return 0;
}

static int transport_open(vpn_t *v, int idx, char *err, size_t ecap)
{
    struct addrinfo hints = { 0 }, *res = NULL;
    char portstr[8];
    ovcfg_t *c = &v->cfg;

    hints.ai_family = AF_INET;
    hints.ai_socktype = c->tcp[idx] == 1 ? SOCK_STREAM : SOCK_DGRAM;
    snprintf(portstr, sizeof portstr, "%u", c->port[idx]);
    if (getaddrinfo(c->host[idx], portstr, &hints, &res) != 0 || !res) {
        snprintf(err, ecap, "cannot resolve %s", c->host[idx]);
        return -1;
    }
    v->srv = *(struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);
    v->tcp = c->tcp[idx] == 1;
    snprintf(v->srvname, sizeof v->srvname, "%s:%u/%s", c->host[idx], c->port[idx], v->tcp ? "tcp" : "udp");
    v->fd = socket(AF_INET, v->tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (v->fd < 0) {
        snprintf(err, ecap, "socket: %s", strerror(errno));
        return -1;
    }
    struct timeval tv = { 0, 500000 };   /* the receive thread looks up twice a second */
    setsockopt(v->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    struct timeval stv = { 10, 0 };
    setsockopt(v->fd, SOL_SOCKET, SO_SNDTIMEO, &stv, sizeof stv);
    if (v->tcp) {
        int fl = fcntl(v->fd, F_GETFL, 0);
        fcntl(v->fd, F_SETFL, fl | O_NONBLOCK);
        int r = connect(v->fd, (struct sockaddr *)&v->srv, sizeof v->srv);
        if (r < 0 && errno == EINPROGRESS) {
            fd_set wr;
            struct timeval ct = { 10, 0 };
            int e = 0;
            socklen_t el = sizeof e;
            FD_ZERO(&wr);
            FD_SET(v->fd, &wr);
            r = select(v->fd + 1, NULL, &wr, NULL, &ct) > 0 &&
                getsockopt(v->fd, SOL_SOCKET, SO_ERROR, &e, &el) == 0 && e == 0 ? 0 : -1;
            if (r < 0)
                errno = e ? e : ETIMEDOUT;
        }
        fcntl(v->fd, F_SETFL, fl);
        if (r < 0) {
            snprintf(err, ecap, "connect to %s: %s", v->srvname, strerror(errno));
            close(v->fd);
            v->fd = -1;
            return -1;
        }
    } else if (connect(v->fd, (struct sockaddr *)&v->srv, sizeof v->srv) < 0) {
        snprintf(err, ecap, "connect to %s: %s", v->srvname, strerror(errno));
        close(v->fd);
        v->fd = -1;
        return -1;
    }
    return 0;
}

/* ================================================================
 * control channel: tls-auth / tls-crypt wrapping
 * ================================================================ */

static int hmac(int type, const uint8_t *key, int klen, const uint8_t *a, size_t alen, const uint8_t *b, size_t blen,
                const uint8_t *c, size_t clen, uint8_t *out)
{
    Hmac h;
    int r = wc_HmacInit(&h, NULL, INVALID_DEVID);
    if (r == 0)
        r = wc_HmacSetKey(&h, type, key, (word32)klen);
    if (r == 0 && alen)
        r = wc_HmacUpdate(&h, a, (word32)alen);
    if (r == 0 && blen)
        r = wc_HmacUpdate(&h, b, (word32)blen);
    if (r == 0 && clen)
        r = wc_HmacUpdate(&h, c, (word32)clen);
    if (r == 0)
        r = wc_HmacFinal(&h, out);
    wc_HmacFree(&h);
    return r;
}

static int ctr(const uint8_t key[32], const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len)
{
    Aes a;
    int r = wc_AesInit(&a, NULL, INVALID_DEVID);
    if (r == 0)
        r = wc_AesSetKeyDirect(&a, key, 32, iv, AES_ENCRYPTION);
    if (r == 0)
        r = wc_AesCtrEncrypt(&a, out, in, (word32)len);
    wc_AesFree(&a);
    return r;
}

static void wrap_keys(vpn_t *v)
{
    const ovcfg_t *c = &v->cfg;
    /* the static key is two halves of { cipher[64], hmac[64] } */
    int out = 0, in = 0;
    if (c->wrap == WRAP_CRYPT) {
        out = 1;                          /* the client always uses the "inverse" direction */
        in = 0;
    } else if (c->key_dir >= 0) {
        out = c->key_dir;
        in = 1 - c->key_dir;
    }
    if (c->wrap == WRAP_CRYPT) {
        v->hlen = 32;
        memcpy(v->ck_out, c->wrapkey + out * 128, 32);
        memcpy(v->ck_in, c->wrapkey + in * 128, 32);
        memcpy(v->hk_out, c->wrapkey + out * 128 + 64, 32);
        memcpy(v->hk_in, c->wrapkey + in * 128 + 64, 32);
    } else if (c->wrap == WRAP_AUTH) {
        v->hlen = c->auth_hash == WC_SHA ? 20 : c->auth_hash == WC_SHA256 ? 32 : 64;
        memcpy(v->hk_out, c->wrapkey + out * 128 + 64, (size_t)v->hlen);
        memcpy(v->hk_in, c->wrapkey + in * 128 + 64, (size_t)v->hlen);
    }
}

/* body = acks + msgid + payload; out = the packet on the wire */
static int wrap(vpn_t *v, uint8_t opkey, const uint8_t *body, size_t blen, uint8_t *out, size_t cap)
{
    size_t o = 0;
    uint8_t hdr[9 + 8];
    out[o++] = opkey;
    memcpy(out + o, v->sid, 8);
    o += 8;
    if (v->cfg.wrap == WRAP_NONE) {
        if (o + blen > cap)
            return -1;
        memcpy(out + o, body, blen);
        return (int)(o + blen);
    }
    uint8_t pidt[8];
    put32(pidt, ++v->wrap_pid);
    put32(pidt + 4, v->wrap_time);
    if (v->cfg.wrap == WRAP_AUTH) {
        /* [op][sid][hmac][pid][time][body]; HMAC over [pid][time][op][sid][body] */
        if (o + (size_t)v->hlen + 8 + blen > cap)
            return -1;
        uint8_t mac[64];
        memcpy(hdr, out, 9);
        if (hmac(v->cfg.auth_hash, v->hk_out, v->hlen, pidt, 8, hdr, 9, body, blen, mac) != 0)
            return -1;
        memcpy(out + o, mac, (size_t)v->hlen);
        o += (size_t)v->hlen;
        memcpy(out + o, pidt, 8);
        o += 8;
        memcpy(out + o, body, blen);
        return (int)(o + blen);
    }
    /* tls-crypt: [op][sid][pid][time][tag][AES-CTR(body)]; tag = HMAC over everything before it + body */
    if (o + 8 + 32 + blen > cap)
        return -1;
    memcpy(out + o, pidt, 8);
    o += 8;
    uint8_t tag[32];
    if (hmac(WC_SHA256, v->hk_out, 32, out, o, body, blen, NULL, 0, tag) != 0)
        return -1;
    memcpy(out + o, tag, 32);
    o += 32;
    if (ctr(v->ck_out, tag, body, out + o, blen) != 0)
        return -1;
    return (int)(o + blen);
}

static int ct_diff(const uint8_t *a, const uint8_t *b, int n)
{
    uint8_t d = 0;
    for (int i = 0; i < n; i++)
        d |= a[i] ^ b[i];
    return d;
}

static bool replay_ok(uint32_t *top, uint64_t *bits, uint32_t id)
{
    if (id == 0)
        return false;
    if (id > *top) {
        uint32_t shift = id - *top;
        *bits = shift >= 64 ? 0 : *bits << shift;
        *bits |= 1;
        *top = id;
        return true;
    }
    uint32_t back = *top - id;
    if (back >= 64 || (*bits >> back & 1))
        return false;
    *bits |= (uint64_t)1 << back;
    return true;
}

/* Check and strip the wrap of a received control packet. Returns the body
 * length (body written to out), or -1 to drop it. */
static int unwrap(vpn_t *v, const uint8_t *pkt, size_t len, uint8_t *out, size_t cap)
{
    size_t o = 9;
    if (len < 9)
        return -1;
    if (v->cfg.wrap == WRAP_NONE) {
        if (len - o > cap)
            return -1;
        memcpy(out, pkt + o, len - o);
        return (int)(len - o);
    }
    if (v->cfg.wrap == WRAP_AUTH) {
        if (len < o + (size_t)v->hlen + 8)
            return -1;
        const uint8_t *mac = pkt + o, *pidt = pkt + o + v->hlen, *body = pidt + 8;
        size_t blen = len - o - (size_t)v->hlen - 8;
        uint8_t want[64];
        if (blen > cap || hmac(v->cfg.auth_hash, v->hk_in, v->hlen, pidt, 8, pkt, 9, body, blen, want) != 0 ||
            ct_diff(mac, want, v->hlen) != 0)
            return -1;
        if (!replay_ok(&v->wrap_rx_top, &v->wrap_rx_bits, get32(pidt)))
            return -1;
        memcpy(out, body, blen);
        return (int)blen;
    }
    if (len < o + 8 + 32)
        return -1;
    const uint8_t *tag = pkt + o + 8, *enc = tag + 32;
    size_t blen = len - o - 8 - 32;
    uint8_t want[32];
    if (blen > cap || ctr(v->ck_in, tag, enc, out, blen) != 0 ||
        hmac(WC_SHA256, v->hk_in, 32, pkt, o + 8, out, blen, NULL, 0, want) != 0 || ct_diff(tag, want, 32) != 0)
        return -1;
    if (!replay_ok(&v->wrap_rx_top, &v->wrap_rx_bits, get32(pkt + o)))
        return -1;
    return (int)blen;
}

/* ================================================================
 * control channel: reliability layer
 * ================================================================ */

static kstate_t *ks_by_id(vpn_t *v, uint8_t key_id)
{
    for (int i = 0; i < 2; i++)
        if (v->ks[i].state != KS_FREE && v->ks[i].key_id == key_id)
            return &v->ks[i];
    return NULL;
}

/* Send one control packet: acks we owe, then (unless a bare ACK) msgid + payload. */
static int ctl_emit(vpn_t *v, kstate_t *k, uint8_t op, const uint8_t *msg, size_t mlen)
{
    uint8_t *body = v->tx_body, *pkt = v->tx_pkt;
    size_t b = 0;
    int n = k->nacks > ACK_MAX ? ACK_MAX : k->nacks;
    body[b++] = (uint8_t)n;
    for (int i = 0; i < n; i++) {
        put32(body + b, k->acks[i]);
        b += 4;
    }
    if (n) {
        memcpy(body + b, v->psid, 8);
        b += 8;
        memmove(k->acks, k->acks + n, (size_t)(k->nacks - n) * sizeof k->acks[0]);
        k->nacks -= n;
    }
    if (mlen > sizeof v->tx_body - b)
        return -1;
    memcpy(body + b, msg, mlen);
    b += mlen;
    int len = wrap(v, (uint8_t)(op << 3 | k->key_id), body, b, pkt, sizeof v->tx_pkt);
    return len < 0 ? -1 : wire_send(v, pkt, (size_t)len);
}

/* Queue a reliable control message (reset or TLS bytes) and send it. */
static int ctl_send(vpn_t *v, kstate_t *k, uint8_t op, const uint8_t *payload, size_t plen)
{
    int slot = -1;
    for (int i = 0; i < REL_SEND; i++)
        if (!k->out[i].data) {
            slot = i;
            break;
        }
    if (slot < 0)
        return 1;                         /* window full: try again after an ack */
    relout_t *r = &k->out[slot];
    r->data = malloc(4 + plen);
    if (!r->data)
        return -1;
    r->id = k->send_id++;
    put32(r->data, r->id);
    memcpy(r->data + 4, payload, plen);
    r->len = (uint16_t)(4 + plen);
    r->op = op;
    r->tries = 1;
    r->sent_ms = now_ms();
    return ctl_emit(v, k, op, r->data, r->len);
}

static bool window_free(kstate_t *k)
{
    for (int i = 0; i < REL_SEND; i++)
        if (!k->out[i].data)
            return true;
    return false;
}

/* Push queued TLS output into control packets as the window allows. */
static int ctl_flush(vpn_t *v, kstate_t *k)
{
    while (k->tout_len && window_free(k)) {
        size_t n = k->tout_len > CTL_CHUNK ? CTL_CHUNK : k->tout_len;
        if (ctl_send(v, k, P_CONTROL_V1, k->tout, n) < 0)
            return -1;
        memmove(k->tout, k->tout + n, k->tout_len - n);
        k->tout_len -= n;
    }
    if (k->nacks && ctl_emit(v, k, P_ACK_V1, NULL, 0) < 0)
        return -1;
    return 0;
}

static void ack_add(kstate_t *k, uint32_t id)
{
    for (int i = 0; i < k->nacks; i++)
        if (k->acks[i] == id)
            return;
    if (k->nacks < (int)(sizeof k->acks / sizeof k->acks[0]))
        k->acks[k->nacks++] = id;
}

static bool grow(uint8_t **buf, size_t *cap, size_t need)
{
    if (need <= *cap)
        return true;
    size_t n = *cap ? *cap : 2048;
    while (n < need)
        n *= 2;
    if (n > 64 * 1024)
        return false;
    uint8_t *p = realloc(*buf, n);
    if (!p)
        return false;
    *buf = p;
    *cap = n;
    return true;
}

static int deliver(vpn_t *v, kstate_t *k, uint8_t op, const uint8_t *data, size_t len);

/* ================================================================
 * TLS on top
 * ================================================================ */

static int tls_recv_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    kstate_t *k = ctx;
    (void)ssl;
    if (!k->tin_len)
        return WOLFSSL_CBIO_ERR_WANT_READ;
    size_t n = (size_t)sz < k->tin_len ? (size_t)sz : k->tin_len;
    memcpy(buf, k->tin, n);
    memmove(k->tin, k->tin + n, k->tin_len - n);
    k->tin_len -= n;
    return (int)n;
}

static int tls_send_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    kstate_t *k = ctx;
    (void)ssl;
    if (!grow(&k->tout, &k->tout_cap, k->tout_len + (size_t)sz))
        return WOLFSSL_CBIO_ERR_GENERAL;
    memcpy(k->tout + k->tout_len, buf, (size_t)sz);
    k->tout_len += (size_t)sz;
    return sz;
}

/* what verify_cb checks beyond the CA signature (one VPN at a time) */
static bool want_remote_cert_tls, want_prefix;
static char want_name[64];

static int verify_cb(int ok, WOLFSSL_X509_STORE_CTX *store)
{
    if (!ok)
        return 0;
    if (store->error_depth != 0 || (!want_remote_cert_tls && !want_name[0]))
        return 1;
    if (!store->certs || store->totalCerts < 1)
        return 0;
    DecodedCert dc;
    int good = 0;
    wc_InitDecodedCert(&dc, store->certs[0].buffer, store->certs[0].length, NULL);
    if (wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL) == 0) {
        good = 1;
        /* remote-cert-tls server: the leaf must be marked for TLS server use */
        if (want_remote_cert_tls && !(dc.extExtKeyUsage & EXTKEYUSE_SERVER_AUTH)) {
            port_log("vpn: the server's certificate is not a TLS server certificate (remote-cert-tls server)");
            good = 0;
        }
        if (want_name[0]) {
            size_t n = strlen(want_name);
            bool match = dc.subjectCN && (want_prefix ? (size_t)dc.subjectCNLen >= n && memcmp(dc.subjectCN, want_name, n) == 0
                                                      : (size_t)dc.subjectCNLen == n && memcmp(dc.subjectCN, want_name, n) == 0);
            if (!match) {
                port_log("vpn: the server's certificate is for '%.*s', not '%s' (verify-x509-name)",
                         dc.subjectCN ? dc.subjectCNLen : 0, dc.subjectCN ? dc.subjectCN : "", want_name);
                good = 0;
            }
        }
    }
    wc_FreeDecodedCert(&dc);
    return good;
}

static int make_ctx(vpn_t *v, char *err, size_t ecap)
{
    ovcfg_t *c = &v->cfg;
    v->ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (!v->ctx) {
        snprintf(err, ecap, "out of memory (TLS)");
        return -1;
    }
    wolfSSL_CTX_SetIORecv(v->ctx, tls_recv_cb);
    wolfSSL_CTX_SetIOSend(v->ctx, tls_send_cb);
    if (wolfSSL_CTX_load_verify_buffer(v->ctx, (const unsigned char *)c->ca, (long)strlen(c->ca),
                                       WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        snprintf(err, ecap, "the CA certificate could not be loaded");
        return -1;
    }
    if (c->cert) {
        if (wolfSSL_CTX_use_certificate_chain_buffer(v->ctx, (const unsigned char *)c->cert, (long)strlen(c->cert)) !=
            WOLFSSL_SUCCESS) {
            snprintf(err, ecap, "the client certificate could not be loaded");
            return -1;
        }
        if (wolfSSL_CTX_use_PrivateKey_buffer(v->ctx, (const unsigned char *)c->key, (long)strlen(c->key),
                                              WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
            snprintf(err, ecap, "the private key could not be loaded (RSA or EC, PEM, no passphrase)");
            return -1;
        }
    }
    want_remote_cert_tls = c->remote_cert_tls;
    want_prefix = c->x509_prefix;
    snprintf(want_name, sizeof want_name, "%s", c->x509_name);
    wolfSSL_CTX_set_verify(v->ctx, WOLFSSL_VERIFY_PEER, verify_cb);
    return 0;
}

static void ks_free(kstate_t *k)
{
    if (k->ssl)
        wolfSSL_free(k->ssl);
    for (int i = 0; i < REL_SEND; i++)
        free(k->out[i].data);
    for (int i = 0; i < REL_RECV; i++)
        free(k->in[i].data);
    free(k->tin);
    free(k->tout);
    free(k->pt);
    if (k->keys) {
        wc_AesFree(&k->enc);
        wc_AesFree(&k->dec);
    }
    memset(k, 0, sizeof *k);
}

static int ks_start(vpn_t *v, kstate_t *k, uint8_t key_id, uint8_t reset_op)
{
    ks_free(k);
    k->key_id = key_id;
    k->state = KS_RESET;
    k->started_s = port_uptime_s();
    k->ssl = wolfSSL_new(v->ctx);
    if (!k->ssl)
        return -1;
    wolfSSL_SetIOReadCtx(k->ssl, k);
    wolfSSL_SetIOWriteCtx(k->ssl, k);
    wolfSSL_KeepArrays(k->ssl);          /* the tls-ekm exporter needs the handshake secrets */
    port_random(k->pre_master, sizeof k->pre_master);
    port_random(k->c_r1, sizeof k->c_r1);
    port_random(k->c_r2, sizeof k->c_r2);
    return ctl_send(v, k, reset_op, NULL, 0) < 0 ? -1 : 0;
}

static size_t wstr(uint8_t *p, const char *s)
{
    size_t n = strlen(s) + 1;
    put16(p, (uint32_t)n);
    memcpy(p + 2, s, n);
    return 2 + n;
}

static int send_km2(vpn_t *v, kstate_t *k)
{
    char opts[200], info[256];
    uint8_t *m = malloc(1024);
    size_t o = 0;
    if (!m)
        return -1;
    snprintf(opts, sizeof opts, "V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto %s,cipher %.*s,auth [null-digest],"
             "keysize %d,key-method 2,tls-client", v->tcp ? "TCPv4_CLIENT" : "UDPv4",
             (int)strcspn(v->cfg.ciphers, ":"), v->cfg.ciphers, strncmp(v->cfg.ciphers, "AES-128", 7) == 0 ? 128 : 256);
    snprintf(info, sizeof info, "IV_VER=2.6.0\nIV_PLAT=" C3_NAME "\nIV_PROTO=%d\nIV_NCP=2\nIV_CIPHERS=%s\n"
             "IV_LZO_STUB=1\nIV_COMP_STUB=1\nIV_COMP_STUBv2=1\nIV_GUI_VER=" C3_NAME "_" C3_VERSION "\n",
             IV_PROTO_DATA_V2 | IV_PROTO_TLS_KEY_EXPORT, v->cfg.ciphers);
    memset(m, 0, 4);
    o = 4;
    m[o++] = 2;                          /* key method 2 */
    memcpy(m + o, k->pre_master, 48);
    o += 48;
    memcpy(m + o, k->c_r1, 32);
    o += 32;
    memcpy(m + o, k->c_r2, 32);
    o += 32;
    o += wstr(m + o, opts);
    if (v->cfg.auth_user_pass) {
        o += wstr(m + o, v->user);
        o += wstr(m + o, v->token[0] ? v->token : v->pass);
    } else {
        put16(m + o, 0);
        put16(m + o + 2, 0);
        o += 4;
    }
    o += wstr(m + o, info);
    int r = wolfSSL_write(k->ssl, m, (int)o);
    memset(m, 0, 1024);
    free(m);
    return r == (int)o ? 0 : -1;
}

/* ---------------- key derivation ---------------- */

static void p_hash(int type, const uint8_t *sec, size_t slen, const uint8_t *seed, size_t seedlen, uint8_t *out,
                   size_t olen)
{
    int hl = type == WC_MD5 ? 16 : 20;
    uint8_t a[20], t[20];
    hmac(type, sec, (int)slen, seed, seedlen, NULL, 0, NULL, 0, a);       /* A(1) */
    for (size_t done = 0; done < olen;) {
        hmac(type, sec, (int)slen, a, (size_t)hl, seed, seedlen, NULL, 0, t);
        for (int i = 0; i < hl && done < olen; i++)
            out[done++] ^= t[i];
        hmac(type, sec, (int)slen, a, (size_t)hl, NULL, 0, NULL, 0, a);
    }
}

/* TLS 1.0 PRF, as OpenVPN uses it: P_MD5(first half) XOR P_SHA1(second half) */
static void prf(const uint8_t *sec, size_t slen, const char *label, const uint8_t *c_seed, const uint8_t *s_seed,
                const uint8_t *c_sid, const uint8_t *s_sid, uint8_t *out, size_t olen)
{
    uint8_t seed[64 + 32 + 32 + 16];
    size_t n = strlen(label), half = (slen + 1) / 2;
    memcpy(seed, label, n);
    memcpy(seed + n, c_seed, 32);
    memcpy(seed + n + 32, s_seed, 32);
    n += 64;
    if (c_sid) {
        memcpy(seed + n, c_sid, 8);
        memcpy(seed + n + 8, s_sid, 8);
        n += 16;
    }
    memset(out, 0, olen);
    p_hash(WC_MD5, sec, half, seed, n, out, olen);
    p_hash(WC_SHA, sec + slen - half, half, seed, n, out, olen);
}

static int derive_keys(vpn_t *v, kstate_t *k)
{
    uint8_t key2[256];
    if (v->ekm) {
        if (wolfSSL_export_keying_material(k->ssl, key2, sizeof key2, "EXPORTER-OpenVPN-datakeys", 25, NULL, 0, 0) !=
            WOLFSSL_SUCCESS)
            return -1;
    } else {
        uint8_t master[48];
        prf(k->pre_master, 48, "OpenVPN master secret", k->c_r1, k->s_r1, NULL, NULL, master, 48);
        prf(master, 48, "OpenVPN key expansion", k->c_r2, k->s_r2, v->sid, v->psid, key2, sizeof key2);
        memset(master, 0, sizeof master);
    }
    /* key2 = { {cipher[64], hmac[64]} x 2 }; the client sends with the first
     * (OpenVPN's KEY_DIRECTION_NORMAL - the reverse of tls-crypt's choice) */
    const uint8_t *out = key2, *in = key2 + 128;
    if (k->keys) {
        wc_AesFree(&k->enc);
        wc_AesFree(&k->dec);
    }
    int r = wc_AesInit(&k->enc, NULL, INVALID_DEVID) || wc_AesInit(&k->dec, NULL, INVALID_DEVID) ||
            wc_AesGcmSetKey(&k->enc, out, (word32)v->keylen) || wc_AesGcmSetKey(&k->dec, in, (word32)v->keylen);
    memcpy(k->iv_enc, out + 64, 8);
    memcpy(k->iv_dec, in + 64, 8);
    memset(key2, 0, sizeof key2);
    memset(k->pre_master, 0, sizeof k->pre_master);
    wolfSSL_FreeArrays(k->ssl);
    if (r)
        return -1;
    k->keys = true;
    k->pid_send = 0;
    k->replay_top = 0;
    k->replay_bits = 0;
    return 0;
}

/* ================================================================
 * pushed options -> the tunnel
 * ================================================================ */

static uint32_t ip_of(const char *s)
{
    struct in_addr a;
    return inet_pton(AF_INET, s, &a) == 1 ? a.s_addr : 0;
}

static int apply_push(vpn_t *v, char *err, size_t ecap)
{
    char *save = NULL;
    char cipher[32] = "";
    char ifc_a[20] = "", ifc_b[20] = "";
    vpnif_cfg_t *n = &v->net;

    memset(n, 0, sizeof *n);
    v->ekm = false;
    v->subnet = false;
    v->peer_id = -1;
    v->comp = COMP_NONE;
    v->ping = v->cfg.ping;
    v->ping_restart = v->cfg.ping_restart;
    v->push[v->push_len] = 0;
    for (char *o = strtok_r(v->push, ",", &save); o; o = strtok_r(NULL, ",", &save)) {
        char *a[6] = { 0 };
        int ac = 0;
        for (char *sv = NULL, *w = strtok_r(o, " ", &sv); w && ac < 6; w = strtok_r(NULL, " ", &sv))
            a[ac++] = w;
        if (!ac)
            continue;
        if (strcmp(a[0], "ifconfig") == 0 && ac >= 3) {
            snprintf(ifc_a, sizeof ifc_a, "%s", a[1]);
            snprintf(ifc_b, sizeof ifc_b, "%s", a[2]);
        } else if (strcmp(a[0], "topology") == 0 && ac >= 2) {
            v->subnet = strcmp(a[1], "subnet") == 0;
        } else if (strcmp(a[0], "route") == 0 && ac >= 2) {
            if (ac >= 4 && strcmp(a[3], "net_gateway") == 0)
                continue;
            if (n->nroutes < VPN_ROUTES) {
                n->routes[n->nroutes].net = ip_of(a[1]);
                n->routes[n->nroutes].mask = ac >= 3 ? ip_of(a[2]) : 0xFFFFFFFFu;
                if (strcmp(a[1], "vpn_gateway") != 0)
                    n->nroutes++;
            }
        } else if (strcmp(a[0], "redirect-gateway") == 0) {
            n->redirect = true;
        } else if (strcmp(a[0], "dhcp-option") == 0 && ac >= 3 && strcmp(a[1], "DNS") == 0) {
            if (!n->dns)
                n->dns = ip_of(a[2]);
        } else if (strcmp(a[0], "ping") == 0 && ac >= 2) {
            v->ping = atoi(a[1]);
        } else if (strcmp(a[0], "ping-restart") == 0 && ac >= 2) {
            v->ping_restart = atoi(a[1]);
        } else if (strcmp(a[0], "peer-id") == 0 && ac >= 2) {
            v->peer_id = atoi(a[1]);
        } else if (strcmp(a[0], "cipher") == 0 && ac >= 2) {
            snprintf(cipher, sizeof cipher, "%s", a[1]);
        } else if (strcmp(a[0], "key-derivation") == 0 && ac >= 2 && strcmp(a[1], "tls-ekm") == 0) {
            v->ekm = true;
        } else if (strcmp(a[0], "protocol-flags") == 0) {
            for (int i = 1; i < ac; i++)
                if (strcmp(a[i], "tls-ekm") == 0)
                    v->ekm = true;
        } else if (strcmp(a[0], "auth-token") == 0 && ac >= 2) {
            snprintf(v->token, sizeof v->token, "%s", a[1]);
        } else if (strcmp(a[0], "comp-lzo") == 0) {
            v->comp = COMP_STUB;           /* "comp-lzo [no|yes|adaptive]": one framing byte, never compressed */
        } else if (strcmp(a[0], "compress") == 0) {
            v->comp = ac >= 2 && (strcmp(a[1], "stub-v2") == 0 || strcmp(a[1], "lz4-v2") == 0) ? COMP_STUB_V2 : COMP_STUB;
        }
    }
    if (!ifc_a[0]) {
        snprintf(err, ecap, "the server did not assign an IPv4 address (no 'ifconfig' pushed)");
        return -1;
    }
    if (!cipher[0])                       /* an old server without negotiation: the config's first */
        snprintf(cipher, sizeof cipher, "%.*s", (int)strcspn(v->cfg.ciphers, ":"), v->cfg.ciphers);
    if (strcasecmp(cipher, "AES-256-GCM") == 0)
        v->keylen = 32;
    else if (strcasecmp(cipher, "AES-128-GCM") == 0)
        v->keylen = 16;
    else {
        snprintf(err, ecap, "the server wants cipher %s; only AES-256-GCM and AES-128-GCM are supported", cipher);
        return -1;
    }
    n->ip = ip_of(ifc_a);
    if (v->subnet) {
        n->mask = ip_of(ifc_b);
    } else {
        n->peer = ip_of(ifc_b);           /* net30 / p2p: the other end of the link */
        n->mask = 0xFFFFFFFFu;
    }
    n->server = v->srv.sin_addr.s_addr;
    return 0;
}

/* ================================================================
 * data channel
 * ================================================================ */

static int data_send(vpn_t *v, const uint8_t *payload, size_t plen)
{
    kstate_t *k = &v->ks[v->cur];
    uint8_t *pkt = v->d_pkt, *pt = v->d_pt;
    size_t h = 0, ptlen = 0;

    if (!k->keys || plen > VPN_MTU)
        return -1;
    if (v->comp == COMP_STUB)
        pt[ptlen++] = 0xFA;               /* "not compressed" */
    else if (v->comp == COMP_STUB_V2 && plen && payload[0] == 0x50) {
        pt[ptlen++] = 0x50;               /* escape a payload that looks like a v2 header */
        pt[ptlen++] = 0x00;
    }
    memcpy(pt + ptlen, payload, plen);
    ptlen += plen;

    if (v->peer_id >= 0) {
        put32(pkt, (uint32_t)(P_DATA_V2 << 3 | k->key_id) << 24 | ((uint32_t)v->peer_id & 0xFFFFFF));
        h = 4;
    } else {
        pkt[0] = (uint8_t)(P_DATA_V1 << 3 | k->key_id);
        h = 1;
    }
    if (++k->pid_send == 0xFFFFFFFFu)     /* would wrap: the key must be replaced first */
        return -1;
    put32(pkt + h, k->pid_send);
    uint8_t iv[12];
    memcpy(iv, pkt + h, 4);
    memcpy(iv + 4, k->iv_enc, 8);
    const uint8_t *aad = v->peer_id >= 0 ? pkt : pkt + h;
    word32 aadlen = v->peer_id >= 0 ? (word32)(h + 4) : 4;
    if (wc_AesGcmEncrypt(&k->enc, pkt + h + 4 + 16, pt, (word32)ptlen, iv, 12, pkt + h + 4, 16, aad, aadlen) != 0)
        return -1;
    return wire_send(v, pkt, h + 4 + 16 + ptlen);
}

static void data_recv(vpn_t *v, const uint8_t *pkt, size_t len)
{
    uint8_t op = pkt[0] >> 3;
    size_t h = op == P_DATA_V2 ? 4 : 1;
    kstate_t *k = ks_by_id(v, pkt[0] & 7);
    uint8_t *pt = v->d_pt;

    if (!k || !k->keys || len < h + 4 + 16)
        return;
    size_t clen = len - h - 4 - 16;
    uint8_t iv[12];
    memcpy(iv, pkt + h, 4);
    memcpy(iv + 4, k->iv_dec, 8);
    const uint8_t *aad = op == P_DATA_V2 ? pkt : pkt + h;
    word32 aadlen = op == P_DATA_V2 ? (word32)(h + 4) : 4;
    if (wc_AesGcmDecrypt(&k->dec, pt, pkt + h + 4 + 16, (word32)clen, iv, 12, pkt + h + 4, 16, aad, aadlen) != 0)
        return;
    if (!replay_ok(&k->replay_top, &k->replay_bits, get32(pkt + h)))
        return;
    v->last_rx_s = port_uptime_s();

    const uint8_t *p = pt;
    size_t n = clen;
    if (v->comp == COMP_STUB && n && p[0] == 0xFA) {
        p++;
        n--;
    } else if (v->comp == COMP_STUB_V2 && n >= 2 && p[0] == 0x50) {
        if (p[1] != 0)
            return;                       /* actually compressed: we cannot unpack it */
        p += 2;
        n -= 2;
    }
    if (n == sizeof PING_MAGIC && memcmp(p, PING_MAGIC, n) == 0)
        return;
    if (n > sizeof OCC_MAGIC && memcmp(p, OCC_MAGIC, sizeof OCC_MAGIC) == 0) {
        if (p[sizeof OCC_MAGIC] == OCC_EXIT) {
            port_log("vpn: the server is shutting down or restarting");
            v->last_rx_s = 0;             /* reconnect */
        }
        return;
    }
    v->rx_bytes += n;
    vpnif_input(p, n);
}

/* ================================================================
 * the protocol thread
 * ================================================================ */

static char fail_msg[160];
static bool fatal;                       /* do not retry (e.g. AUTH_FAILED) */

static void fail(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void fail(const char *fmt, ...)
{
    va_list ap;
    if (fail_msg[0])
        return;
    va_start(ap, fmt);
    vsnprintf(fail_msg, sizeof fail_msg, fmt, ap);
    va_end(ap);
}

static void control_message(vpn_t *v, kstate_t *k, char *msg)
{
    if (strncmp(msg, "PUSH_REPLY", 10) == 0) {
        if (k->state != KS_PUSH)
            return;                       /* an update after the fact: nothing to apply */
        const char *body = msg[10] == ',' ? msg + 11 : msg + 10;
        size_t bl = strlen(body);
        if (v->push_len + bl + 2 >= sizeof v->push) {
            fail("the server's pushed options are too long");
            return;
        }
        if (v->push_len)
            v->push[v->push_len++] = ',';
        memcpy(v->push + v->push_len, body, bl);
        v->push_len += bl;
        v->push[v->push_len] = 0;
        if (strstr(body, "push-continuation 2"))
            return;                       /* more to come */
        char err[160] = "";
        if (apply_push(v, err, sizeof err) < 0 || derive_keys(v, k) < 0) {
            fail("%s", err[0] ? err : "deriving the data channel keys failed");
            fatal = true;
            return;
        }
        v->push_len = 0;
        if (vpnif_up(&v->net, tun_out) < 0) {
            fail("cannot set up the tunnel interface");
            return;
        }
        k->state = KS_ACTIVE;
        v->cur = (int)(k - v->ks);
        v->pushed = true;
        v->last_rx_s = port_uptime_s();
        char ip[20];
        struct in_addr a = { v->net.ip };
        inet_ntop(AF_INET, &a, ip, sizeof ip);
        pthread_mutex_lock(&slock);
        snprintf(st_ip, sizeof st_ip, "%s", ip);
        st_routes = v->net.nroutes;
        st_redirect = v->net.redirect;
        pthread_mutex_unlock(&slock);
        port_log("vpn: connected to %s, tunnel address %s, %d route%s%s, %s, %s keys", v->srvname, ip,
                 v->net.nroutes, v->net.nroutes == 1 ? "" : "s", v->net.redirect ? " + default route" : "",
                 v->keylen == 32 ? "AES-256-GCM" : "AES-128-GCM", v->ekm ? "tls-ekm" : "PRF");
        set_state("connected", "");
    } else if (strncmp(msg, "AUTH_FAILED", 11) == 0) {
        fail("the server refused the login%s%s", msg[11] == ',' ? ": " : "", msg[11] == ',' ? msg + 12 : "");
        v->token[0] = 0;
        fatal = true;
    } else if (strncmp(msg, "RESTART", 7) == 0) {
        fail("the server asked for a reconnect%s", msg + 7);
    } else if (strncmp(msg, "HALT", 4) == 0) {
        fail("the server told this client to stop%s", msg + 4);
        fatal = true;
    } else if (strncmp(msg, "INFO", 4) == 0 || strncmp(msg, "AUTH_PENDING", 12) == 0) {
        port_log("vpn: server says: %.120s", msg);
    }
}

/* Feed TLS with what arrived; run the handshake / read plaintext. */
static int tls_pump(vpn_t *v, kstate_t *k)
{
    if (k->state == KS_TLS) {
        int r = wolfSSL_connect(k->ssl);
        if (r != WOLFSSL_SUCCESS) {
            int e = wolfSSL_get_error(k->ssl, r);
            if (e == WOLFSSL_ERROR_WANT_READ || e == WOLFSSL_ERROR_WANT_WRITE)
                return 0;
            char es[80];
            wolfSSL_ERR_error_string_n((unsigned long)e, es, sizeof es);
            fail("TLS handshake failed: %s", es);
            if (e == ASN_NO_SIGNER_E || e == ASN_SIG_CONFIRM_E || e == VERIFY_CERT_ERROR || e == ASN_PARSE_E)
                fatal = true;
            return -1;
        }
        if (send_km2(v, k) < 0) {
            fail("sending the key exchange failed");
            return -1;
        }
        k->state = KS_KM2;
    }
    if (k->state < KS_KM2)
        return 0;
    for (;;) {
        if (!grow(&k->pt, &k->pt_cap, k->pt_len + 2048)) {
            fail("control channel overflow");
            return -1;
        }
        int r = wolfSSL_read(k->ssl, k->pt + k->pt_len, 2048);
        if (r <= 0) {
            int e = wolfSSL_get_error(k->ssl, r);
            if (e == WOLFSSL_ERROR_WANT_READ || e == WOLFSSL_ERROR_WANT_WRITE)
                break;
            fail("the server closed the control channel");
            return -1;
        }
        k->pt_len += (size_t)r;
    }
    /* the server's key-method-2 reply first, then NUL-terminated messages */
    size_t pos = 0;
    if (!k->km2_got) {
        if (k->pt_len < 5 + 64 + 2)
            return 0;
        if (get32(k->pt) != 0 || (k->pt[4] & 0x0F) != 2) {
            fail("unexpected key exchange from the server");
            fatal = true;
            return -1;
        }
        size_t ol = get16(k->pt + 69);
        if (k->pt_len < 71 + ol)
            return 0;
        memcpy(k->s_r1, k->pt + 5, 32);
        memcpy(k->s_r2, k->pt + 37, 32);
        pos = 71 + ol;
        k->km2_got = true;
        k->km2_tail = true;
        if (!v->pushed) {
            static const char req[] = "PUSH_REQUEST";
            wolfSSL_write(k->ssl, req, sizeof req);   /* with its NUL */
            k->state = KS_PUSH;
            set_state("configuring", NULL);
        } else {                          /* renegotiation: same settings, new keys */
            if (derive_keys(v, k) < 0) {
                fail("deriving the new data channel keys failed");
                return -1;
            }
            k->state = KS_ACTIVE;
            int old = 1 - (int)(k - v->ks);
            v->ks[old].retired_s = port_uptime_s();
            v->cur = (int)(k - v->ks);
            port_log("vpn: data channel keys renewed (key %u)", k->key_id);
        }
    }
    /* empty strings (username, password, peer info) may trail the reply */
    while (k->km2_tail && k->pt_len - pos >= 2 && k->pt[pos] == 0) {
        size_t l = get16(k->pt + pos);
        if (k->pt_len - pos < 2 + l)
            break;
        pos += 2 + l;
    }
    while (pos < k->pt_len) {
        uint8_t *end = memchr(k->pt + pos, 0, k->pt_len - pos);
        if (!end)
            break;
        k->km2_tail = false;
        if (end > k->pt + pos)
            control_message(v, k, (char *)k->pt + pos);
        pos = (size_t)(end - k->pt) + 1;
    }
    memmove(k->pt, k->pt + pos, k->pt_len - pos);
    k->pt_len -= pos;
    return 0;
}

/* One in-order reliable message for key state k. */
static int deliver(vpn_t *v, kstate_t *k, uint8_t op, const uint8_t *data, size_t len)
{
    if (op == P_CONTROL_HARD_RESET_SERVER_V2 || op == P_CONTROL_SOFT_RESET_V1) {
        if (k->state == KS_RESET)
            k->state = KS_TLS;
        return tls_pump(v, k);
    }
    if (op != P_CONTROL_V1)
        return 0;
    if (!grow(&k->tin, &k->tin_cap, k->tin_len + len)) {
        fail("control channel overflow");
        return -1;
    }
    memcpy(k->tin + k->tin_len, data, len);
    k->tin_len += len;
    return tls_pump(v, k);
}

static void control_recv(vpn_t *v, const uint8_t *pkt, size_t len)
{
    uint8_t *body = v->rx_body;
    uint8_t op = pkt[0] >> 3, key_id = pkt[0] & 7;

    if (len < 9)
        return;
    if (v->have_psid && memcmp(pkt + 1, v->psid, 8) != 0)
        return;                           /* another session's packet */
    int blen = unwrap(v, pkt, len, body, sizeof v->rx_body);
    if (blen < 1)
        return;
    if (op == P_CONTROL_HARD_RESET_SERVER_V2 && !v->have_psid) {
        memcpy(v->psid, pkt + 1, 8);
        v->have_psid = true;
    }
    if (!v->have_psid)
        return;

    kstate_t *k = ks_by_id(v, key_id);
    if (!k && op == P_CONTROL_SOFT_RESET_V1) {
        /* the server renegotiates: a new key state next to the current one */
        int slot = 1 - v->cur;
        port_log("vpn: the server renegotiates (key %u)", key_id);
        if (ks_start(v, &v->ks[slot], key_id, P_CONTROL_SOFT_RESET_V1) < 0) {
            fail("renegotiation failed to start");
            return;
        }
        k = &v->ks[slot];
    }
    if (!k)
        return;

    size_t b = 0;
    int nack = body[b++];
    if (nack > 8 || (size_t)blen < b + (size_t)nack * 4 + (nack ? 8u : 0u))
        return;
    for (int i = 0; i < nack; i++) {
        uint32_t id = get32(body + b + i * 4);
        for (int j = 0; j < REL_SEND; j++)
            if (k->out[j].data && k->out[j].id == id) {
                free(k->out[j].data);
                k->out[j].data = NULL;
            }
    }
    b += (size_t)nack * 4;
    if (nack) {
        if (memcmp(body + b, v->sid, 8) != 0)
            return;
        b += 8;
    }
    if (op == P_ACK_V1) {
        ctl_flush(v, k);                  /* the window may have opened */
        return;
    }
    if ((size_t)blen < b + 4)
        return;
    uint32_t id = get32(body + b);
    b += 4;
    ack_add(k, id);
    if (id < k->recv_id) {                /* a repeat: our ack got lost */
        ctl_flush(v, k);
        return;
    }
    if (id >= k->recv_id + REL_RECV)
        return;
    int slot = (int)(id % REL_RECV);
    if (!k->in[slot].used) {
        k->in[slot].data = malloc((size_t)blen - b + 1);
        if (!k->in[slot].data)
            return;
        memcpy(k->in[slot].data, body + b, (size_t)blen - b);
        k->in[slot].len = (uint16_t)((size_t)blen - b);
        k->in[slot].op = op;
        k->in[slot].id = id;
        k->in[slot].used = true;
    }
    for (;;) {
        int s = (int)(k->recv_id % REL_RECV);
        if (!k->in[s].used || k->in[s].id != k->recv_id)
            break;
        k->in[s].used = false;
        k->recv_id++;
        int r = deliver(v, k, k->in[s].op, k->in[s].data, k->in[s].len);
        free(k->in[s].data);
        k->in[s].data = NULL;
        if (r < 0 || fail_msg[0])
            return;
    }
    ctl_flush(v, k);
}

static void retransmit(vpn_t *v, kstate_t *k)
{
    uint32_t t = now_ms();
    for (int i = 0; i < REL_SEND; i++) {
        relout_t *r = &k->out[i];
        uint32_t rto = 2000u << (r->tries > 3 ? 3 : r->tries - 1);
        if (!r->data || t - r->sent_ms < rto)
            continue;
        if (r->tries >= 8) {
            fail("no answer from %s", v->srvname);
            return;
        }
        r->tries++;
        r->sent_ms = t;
        ctl_emit(v, k, r->op, r->data, r->len);
    }
}

/* One connection attempt to one remote, until it fails or we are told to stop. */
static void session(vpn_t *v, int idx)
{
    char err[160];
    fail_msg[0] = 0;
    fatal = false;
    v->have_psid = false;
    v->pushed = false;
    v->push_len = 0;
    v->wrap_pid = 0;
    v->wrap_rx_top = 0;
    v->wrap_rx_bits = 0;
    v->wrap_time = (uint32_t)time(NULL) > 1000000000u ? (uint32_t)time(NULL) : 1700000000u + port_uptime_s();
    v->next_key_id = 1;
    port_random(v->sid, 8);

    set_state("connecting", NULL);
    if (transport_open(v, idx, err, sizeof err) < 0) {
        fail("%s", err);
        return;
    }
    pthread_mutex_lock(&slock);
    snprintf(st_server, sizeof st_server, "%s", v->srvname);
    pthread_mutex_unlock(&slock);
    port_log("vpn: connecting to %s", v->srvname);

    rx_run = rx_alive = true;
    if (port_thread_start("vpn-rx", 4096, rx_thread, v) != 0) {
        rx_run = rx_alive = false;
        fail("out of memory (receive thread)");
        goto out;
    }
    v->cur = 0;
    if (ks_start(v, &v->ks[0], 0, P_CONTROL_HARD_RESET_CLIENT_V2) < 0) {
        fail("out of memory (TLS)");
        goto out;
    }
    v->last_rx_s = v->last_tx_s = port_uptime_s();

    while (!want_stop && !fail_msg[0]) {
        /* wait for a packet either way, or for the next timer (at most 0.5 s) */
        pthread_mutex_lock(&qlock);
        if (!v->inq && !v->outq) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_nsec += 500 * 1000000L;
            if (ts.tv_nsec >= 1000000000L) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000L;
            }
            pthread_cond_timedwait(&qcond, &qlock, &ts);
        }
        qpkt_t *in = v->inq, *out = v->outq;
        v->inq = v->outq = NULL;
        v->ninq = v->noutq = 0;
        pthread_mutex_unlock(&qlock);

        for (qpkt_t *p = in, *nx; p; p = nx) {
            nx = p->next;
            if (p->len == 0)
                fail("%s closed the connection", v->srvname);
            else if (!fail_msg[0]) {
                uint8_t op = p->data[0] >> 3;
                if (op == P_DATA_V1 || op == P_DATA_V2)
                    data_recv(v, p->data, p->len);
                else
                    control_recv(v, p->data, p->len);
            }
            free(p);
        }
        for (qpkt_t *p = out, *nx; p; p = nx) {
            nx = p->next;
            if (!fail_msg[0])
                data_send(v, p->data, p->len);
            free(p);
        }
        if (fail_msg[0])
            break;

        uint32_t now = port_uptime_s();
        for (int i = 0; i < 2; i++) {
            kstate_t *k = &v->ks[i];
            if (k->state == KS_FREE)
                continue;
            retransmit(v, k);
            if (k->state != KS_ACTIVE && now - k->started_s > HAND_WINDOW)
                fail("%s did not complete the %s in %d s", v->srvname,
                     k->key_id == 0 ? "handshake" : "renegotiation", HAND_WINDOW);
            if (k->tout_len && window_free(k))
                ctl_flush(v, k);
            if (k->retired_s && now - k->retired_s > LAME_DUCK_S && i != v->cur)
                ks_free(k);
        }
        if (v->ks[v->cur].keys) {
            if (v->ping > 0 && now - v->last_tx_s >= (uint32_t)v->ping)
                data_send(v, PING_MAGIC, sizeof PING_MAGIC);
            if (v->ping_restart > 0 && now - v->last_rx_s > (uint32_t)v->ping_restart)
                fail("no traffic from %s for %d s", v->srvname, v->ping_restart);
        }
    }
out:
    rx_run = false;                      /* the receive thread looks every 0.5 s */
    if (v->fd >= 0 && v->tcp)
        shutdown(v->fd, SHUT_RDWR);
    for (int i = 0; i < 30 && rx_alive; i++)
        port_sleep_ms(100);
    if (v->fd >= 0)
        close(v->fd);
    v->fd = -1;
    for (int i = 0; i < 2; i++)
        ks_free(&v->ks[i]);
    pthread_mutex_lock(&qlock);
    q_clear(&v->inq, &v->ninq);
    q_clear(&v->outq, &v->noutq);
    pthread_mutex_unlock(&qlock);
}

static void vpn_thread(void *arg)
{
    vpn_t *v = arg;
    char err[160];
    int backoff = 5;

    if (make_ctx(v, err, sizeof err) < 0) {
        port_log("vpn: %s", err);
        set_state("failed", err);
        goto done;
    }
    wrap_keys(v);
    for (int attempt = 0; !want_stop; attempt++) {
        session(v, attempt % v->cfg.nremote);
        if (want_stop)
            break;
        port_log("vpn: %s", fail_msg);
        if (fatal) {
            set_state("failed", fail_msg);
            break;
        }
        set_state("reconnecting", fail_msg);
        for (int i = 0; i < backoff * 10 && !want_stop; i++)
            port_sleep_ms(100);
        if (v->pushed || backoff >= 60)
            backoff = 5;
        else
            backoff *= 2;
        if (backoff > 60)
            backoff = 60;
    }
done:
    vpnif_down();
    if (v->ctx)
        wolfSSL_CTX_free(v->ctx);
    pthread_mutex_lock(&qlock);
    V = NULL;
    pthread_mutex_unlock(&qlock);
    free_config(&v->cfg);
    memset(v, 0, sizeof *v);
    free(v);
    pthread_mutex_lock(&slock);
    st_ip[0] = 0;
    if (want_stop || strcmp(st_state, "failed") != 0) {
        snprintf(st_state, sizeof st_state, "off");
        st_since = port_uptime_s();
    }
    pthread_mutex_unlock(&slock);
    long room = port_stack_headroom();
    if (room >= 0)
        port_log("vpn: stopped (stack headroom was %ld of %d bytes)", room, C3_VPN_STACK);
    else
        port_log("vpn: stopped");
    running = false;
}

/* ================================================================
 * shell interface
 * ================================================================ */

void vpn_status(vpn_status_t *st)
{
    pthread_mutex_lock(&slock);
    memset(st, 0, sizeof *st);
    st->running = running;
    snprintf(st->state, sizeof st->state, "%s", st_state);
    snprintf(st->error, sizeof st->error, "%s", st_error);
    snprintf(st->ip, sizeof st->ip, "%s", st_ip);
    snprintf(st->server, sizeof st->server, "%s", st_server);
    snprintf(st->file, sizeof st->file, "%s", st_file);
    st->since_s = port_uptime_s() - st_since;
    st->routes = st_routes;
    st->redirect = st_redirect;
    pthread_mutex_unlock(&slock);
    pthread_mutex_lock(&qlock);
    if (V) {
        st->rx = V->rx_bytes;
        st->tx = V->tx_bytes;
    }
    pthread_mutex_unlock(&qlock);
}

void vpn_stop(void)
{
    if (!running)
        return;
    want_stop = true;
    pthread_cond_signal(&qcond);
    for (int i = 0; i < 100 && running; i++)
        port_sleep_ms(100);
}

/* Read user / password from a two-line file in the file area. */
static int read_authfile(session_t *s, const char *cfgpath, const char *name, vpn_t *v)
{
    char err[80];
    char *data = side_file(s, cfgpath, name, err, sizeof err);
    if (!data) {
        tn_printf(s, "vpn: auth-user-pass: %s\n", err);
        return -1;
    }
    char *nl = strpbrk(data, "\r\n");
    if (!nl) {
        free(data);
        tn_puts(s, "vpn: the auth-user-pass file needs the username and the password on two lines\n");
        return -1;
    }
    *nl++ = 0;
    nl += strspn(nl, "\r\n");
    nl[strcspn(nl, "\r\n")] = 0;
    snprintf(v->user, sizeof v->user, "%s", data);
    snprintf(v->pass, sizeof v->pass, "%s", nl);
    memset(data, 0, strlen(data));
    free(data);
    return 0;
}

int vpn_start(session_t *s, const char *arg)
{
    char vpath[C3_PATH_MAX], host[C3_HOST_MAX], err[160] = "";
    char *text = NULL;
    size_t len;

    if (running) {
        tn_puts(s, "vpn: already running - 'vpn down' first\n");
        return -1;
    }
    if (fs_resolve(s, arg, vpath, sizeof vpath) < 0 || fs_host(vpath, host, sizeof host) < 0 ||
        fs_read_file(host, &text, &len, 64 * 1024) != 0) {
        tn_printf(s, "vpn: cannot read %s\n", arg);
        return -1;
    }
    vpn_t *v = calloc(1, sizeof *v);
    if (!v) {
        free(text);
        tn_puts(s, "vpn: out of memory\n");
        return -1;
    }
    v->fd = -1;
    int r = parse_config(s, vpath, text, &v->cfg, err, sizeof err);
    free(text);
    if (r < 0) {
        tn_printf(s, "vpn: %s: %s\n", vpath, err);
        free_config(&v->cfg);
        free(v);
        return -1;
    }
    if (v->cfg.ignored[0])
        tn_printf(s, "vpn: not used by this client: %s\n", v->cfg.ignored);
    if (v->cfg.auth_user_pass) {
        if (v->cfg.authfile[0]) {
            if (read_authfile(s, vpath, v->cfg.authfile, v) < 0)
                goto bad;
        } else {
            if (tn_readline(s, "VPN username: ", v->user, sizeof v->user, RL_ECHO, 120) < 0 ||
                tn_readline(s, "VPN password: ", v->pass, sizeof v->pass, 0, 120) < 0)
                goto bad;
        }
    }
    snprintf(v->path, sizeof v->path, "%s", vpath);

    pthread_mutex_lock(&slock);
    snprintf(st_file, sizeof st_file, "%s", vpath);
    snprintf(st_state, sizeof st_state, "starting");
    st_since = port_uptime_s();
    st_error[0] = 0;
    st_server[0] = 0;
    pthread_mutex_unlock(&slock);
    want_stop = false;
    running = true;
    pthread_mutex_lock(&qlock);
    V = v;
    pthread_mutex_unlock(&qlock);
    if (port_thread_start("vpn", C3_VPN_STACK, vpn_thread, v) != 0) {
        running = false;
        pthread_mutex_lock(&qlock);
        V = NULL;
        pthread_mutex_unlock(&qlock);
        tn_puts(s, "vpn: out of memory for the VPN thread\n");
        goto bad;
    }
    return 0;
bad:
    free_config(&v->cfg);
    memset(v, 0, sizeof *v);
    free(v);
    return -1;
}
