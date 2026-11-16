/* Network manager: decides when the device hosts its own setup network and
 * when it lives on a joined WiFi network.
 *
 *   no saved network ........................ host setup network
 *   saved network joins ..................... station only (setup network gone)
 *   saved network unreachable for a while ... host setup network again, and
 *                                             keep retrying the saved one while
 *                                             nobody is logged in
 */
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include "c3shell.h"

typedef struct {
    char ssid[33];
    char pass[65];
} creds_t;

int netmgr_fallback_s = C3_FALLBACK_S;
int netmgr_retry_s = C3_RETRY_S;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;   /* serialises radio operations */
static creds_t saved;
static bool have_saved;
static bool ap_up;
static char ap_ssid[33];

static void ap_start(void)
{
    if (ap_up)
        return;
    if (port_wifi_ap_start(ap_ssid, C3_AP_PASSWORD) == 0) {
        ap_up = true;
        port_log("setup network '%s' is up", ap_ssid);
    } else {
        port_log("could not start setup network");
    }
}

static void ap_stop(void)
{
    if (!ap_up)
        return;
    ap_up = false;
    /* Their link is about to vanish: close those logins cleanly first. */
    server_kick_ap_sessions();
    port_wifi_ap_stop();
    port_log("setup network '%s' is down", ap_ssid);
}

static void monitor(void *arg)
{
    int down_s = 0, retry_in = netmgr_retry_s;
    (void)arg;
    for (;;) {
        port_sleep_ms(1000);
        pthread_mutex_lock(&lock);
        if (!have_saved || port_wifi_sta_up()) {
            down_s = 0;
        } else if (!ap_up) {
            if (++down_s >= netmgr_fallback_s) {
                port_log("'%s' unreachable for %d s, falling back to setup network", saved.ssid, down_s);
                port_wifi_sta_disconnect();
                ap_start();
                down_s = 0;
                retry_in = netmgr_retry_s;
            }
        } else if (--retry_in <= 0) {
            retry_in = netmgr_retry_s;
            /* A join attempt disturbs the setup network, so leave it alone
             * while someone is using it. */
            if (server_session_count() == 0) {
                if (port_wifi_sta_connect(saved.ssid, saved.pass, C3_JOIN_TIMEOUT_MS) == PORT_WIFI_OK) {
                    port_log("rejoined '%s'", saved.ssid);
                    ap_stop();
                } else {
                    port_wifi_sta_disconnect();
                }
            }
        }
        pthread_mutex_unlock(&lock);
    }
}

void netmgr_start(void)
{
    char id[5];
    port_device_id(id);
    snprintf(ap_ssid, sizeof ap_ssid, "%s%s", C3_AP_SSID_PREFIX, id);

    have_saved = port_kv_get("wifi", &saved, sizeof saved) == (int)sizeof saved && saved.ssid[0];
    if (have_saved) {
        port_log("joining saved network '%s'", saved.ssid);
        if (port_wifi_sta_connect(saved.ssid, saved.pass, C3_JOIN_TIMEOUT_MS) == PORT_WIFI_OK) {
            char ip[20];
            port_wifi_sta_ip(ip, sizeof ip);
            port_log("joined '%s', address %s", saved.ssid, ip);
        } else {
            port_log("could not join '%s'", saved.ssid);
            port_wifi_sta_disconnect();
            ap_start();
        }
    } else {
        port_log("no saved network");
        ap_start();
    }
    port_thread_start("netmgr", 6144, monitor, NULL);
}

void netmgr_status(net_status_t *st)
{
    memset(st, 0, sizeof *st);
    st->ap_up = ap_up;
    st->have_saved = have_saved;
    st->sta_up = port_wifi_sta_up();
    snprintf(st->ap_ssid, sizeof st->ap_ssid, "%s", ap_ssid);
    snprintf(st->sta_ssid, sizeof st->sta_ssid, "%s", have_saved ? saved.ssid : "");
    port_wifi_ap_ip(st->ap_ip, sizeof st->ap_ip);
    if (st->sta_up) {
        port_wifi_sta_ip(st->sta_ip, sizeof st->sta_ip);
        st->rssi = port_wifi_sta_rssi();
    }
}

int netmgr_scan(port_ap_t *out, int max)
{
    pthread_mutex_lock(&lock);
    int n = port_wifi_scan(out, max);
    pthread_mutex_unlock(&lock);
    return n;
}

/* Join a network. On success it becomes the saved network; the setup network
 * stays up until netmgr_drop_ap() so the caller can tell the user first.
 * On failure the previous state is restored. */
int netmgr_join(const char *ssid, const char *pass)
{
    pthread_mutex_lock(&lock);
    int r = port_wifi_sta_connect(ssid, pass, C3_JOIN_TIMEOUT_MS);
    if (r == PORT_WIFI_OK) {
        memset(&saved, 0, sizeof saved);
        snprintf(saved.ssid, sizeof saved.ssid, "%s", ssid);
        snprintf(saved.pass, sizeof saved.pass, "%s", pass);
        have_saved = true;
        port_kv_set("wifi", &saved, sizeof saved);
        char ip[20];
        port_wifi_sta_ip(ip, sizeof ip);
        port_log("joined '%s', address %s", ssid, ip);
    } else {
        port_wifi_sta_disconnect();
        if (!ap_up && have_saved) {
            /* We left a working network for this attempt: go back to it. */
            if (port_wifi_sta_connect(saved.ssid, saved.pass, C3_JOIN_TIMEOUT_MS) != PORT_WIFI_OK) {
                port_wifi_sta_disconnect();
                ap_start();
            }
        } else if (!ap_up) {
            ap_start();
        }
    }
    pthread_mutex_unlock(&lock);
    return r;
}

void netmgr_drop_ap(void)
{
    pthread_mutex_lock(&lock);
    if (port_wifi_sta_up())
        ap_stop();
    pthread_mutex_unlock(&lock);
}

void netmgr_forget(void)
{
    pthread_mutex_lock(&lock);
    port_kv_del("wifi");
    have_saved = false;
    memset(&saved, 0, sizeof saved);
    ap_start();
    port_wifi_sta_disconnect();
    pthread_mutex_unlock(&lock);
}
