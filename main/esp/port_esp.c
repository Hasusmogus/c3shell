/* ESP32-C3 implementation of port.h (ESP-IDF): NVS storage, WiFi in
 * station / access-point mode, and the firmware entry point. */
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

#include "esp_chip_info.h"
#include "esp_event.h"
#include "esp_flash.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_pthread.h"
#include "esp_random.h"
#include "esp_rom_sys.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_littlefs.h"
#include "lwip/sockets.h"
#include "lwip/netif.h"
#include "nvs.h"
#include "nvs_flash.h"

#include "c3shell.h"
#include "vpnif.h"

static const char *TAG = C3_NAME;
#define NVS_NS "c3shell"

/* ---------------- storage ---------------- */

int port_kv_get(const char *key, void *buf, size_t cap)
{
    nvs_handle_t h;
    size_t len = cap;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK)
        return -1;
    esp_err_t e = nvs_get_blob(h, key, buf, &len);
    nvs_close(h);
    return e == ESP_OK ? (int)len : -1;
}

int port_kv_set(const char *key, const void *buf, size_t len)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK)
        return -1;
    esp_err_t e = nvs_set_blob(h, key, buf, len);
    if (e == ESP_OK)
        e = nvs_commit(h);
    nvs_close(h);
    return e == ESP_OK ? 0 : -1;
}

void port_kv_del(const char *key)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK)
        return;
    nvs_erase_key(h, key);
    nvs_commit(h);
    nvs_close(h);
}

void port_kv_wipe(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK)
        return;
    nvs_erase_all(h);
    nvs_commit(h);
    nvs_close(h);
}

/* ---------------- file area ---------------- */

#define FS_LABEL "storage"
#define FS_ROOT  "/files"

const char *port_fs_root(void) { return FS_ROOT; }

int port_fs_usage(long *total, long *used)
{
    size_t t = 0, u = 0;
    if (esp_littlefs_info(FS_LABEL, &t, &u) != ESP_OK)
        return -1;
    *total = (long)t;
    *used = (long)u;
    return 0;
}

void port_fs_wipe(void)
{
    esp_littlefs_format(FS_LABEL);
}

static void fs_mount(void)
{
    esp_vfs_littlefs_conf_t conf = {
        .base_path = FS_ROOT,
        .partition_label = FS_LABEL,
        .format_if_mount_failed = true,     /* first boot: the partition is blank */
    };
    esp_err_t e = esp_vfs_littlefs_register(&conf);
    if (e != ESP_OK)
        ESP_LOGE(TAG, "file area could not be mounted (%s)", esp_err_to_name(e));
}

/* ---------------- system ---------------- */

uint32_t port_uptime_s(void) { return (uint32_t)(esp_timer_get_time() / 1000000); }
void port_sleep_ms(uint32_t ms) { vTaskDelay(pdMS_TO_TICKS(ms)); }
void port_random(void *buf, size_t len) { esp_fill_random(buf, len); }
long port_free_heap(void) { return (long)esp_get_free_heap_size(); }
long port_stack_headroom(void) { return (long)uxTaskGetStackHighWaterMark(NULL); }
int  port_listen_port(void) { return 22; }

int port_tasks(port_task_t *out, int max, uint32_t *now_us)
{
#if CONFIG_FREERTOS_USE_TRACE_FACILITY
    UBaseType_t cap = uxTaskGetNumberOfTasks() + 4;
    TaskStatus_t *ts = malloc(cap * sizeof *ts);
    configRUN_TIME_COUNTER_TYPE total = 0;
    if (!ts)
        return -1;
    UBaseType_t n = uxTaskGetSystemState(ts, cap, &total);
    int k = 0;
    for (UBaseType_t i = 0; i < n && k < max; i++, k++) {
        port_task_t *t = &out[k];
        snprintf(t->name, sizeof t->name, "%s", ts[i].pcTaskName);
        /* FreeRTOS reports a task waiting without a timeout as "suspended" */
        switch (ts[i].eCurrentState) {
        case eRunning: case eReady:     t->state = 'R'; break;
        case eBlocked: case eSuspended: t->state = 'S'; break;
        case eDeleted:                  t->state = 'Z'; break;
        default:                        t->state = '?'; break;
        }
        t->prio = (uint8_t)ts[i].uxCurrentPriority;
        t->id = (uint32_t)ts[i].xTaskNumber;
#if CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS
        t->runtime = (uint32_t)ts[i].ulRunTimeCounter;
#else
        t->runtime = 0;
#endif
        t->stack_free = (long)ts[i].usStackHighWaterMark;   /* bytes: ESP-IDF stacks count in bytes */
    }
    free(ts);
#if CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS
    *now_us = (uint32_t)total;          /* the run-time clock is esp_timer, in microseconds */
#else
    *now_us = (uint32_t)esp_timer_get_time();
#endif
    return k;
#else
    (void)out;
    (void)max;
    (void)now_us;
    return -1;
#endif
}

void port_heap(long *free_now, long *min_free, long *largest)
{
    *free_now = (long)heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
    *min_free = (long)heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT);
    *largest = (long)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT);
}

void port_sysinfo(port_sysinfo_t *o)
{
    esp_chip_info_t ci;
    uint32_t flash = 0;
    esp_chip_info(&ci);
    snprintf(o->host, sizeof o->host, "ESP32-C3 rev v%d.%d", ci.revision / 100, ci.revision % 100);
    snprintf(o->cpu, sizeof o->cpu, "RISC-V, %d core%s @ %u MHz", ci.cores, ci.cores == 1 ? "" : "s",
             (unsigned)esp_rom_get_cpu_ticks_per_us());
    o->flash_kb = esp_flash_get_size(NULL, &flash) == ESP_OK ? (long)(flash / 1024) : -1;
    o->heap_total = (long)heap_caps_get_total_size(MALLOC_CAP_DEFAULT);
}

void port_reboot(void)
{
    esp_restart();
}

void port_log(const char *fmt, ...)
{
    char buf[160];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    ESP_LOGI(TAG, "%s", buf);
}

void port_device_id(char out[5])
{
    uint8_t mac[6] = { 0 };
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(out, 5, "%02X%02X", mac[4], mac[5]);
}

struct tramp { void (*fn)(void *); void *arg; };

static void *trampoline(void *p)
{
    struct tramp t = *(struct tramp *)p;
    free(p);
    t.fn(t.arg);
    return NULL;
}

int port_thread_start(const char *name, size_t stack, void (*fn)(void *), void *arg)
{
    pthread_t th;
    struct tramp *t = malloc(sizeof *t);
    esp_pthread_cfg_t cfg = esp_pthread_get_default_config();

    if (!t)
        return -1;
    t->fn = fn;
    t->arg = arg;
    cfg.stack_size = stack;
    cfg.thread_name = name;
    cfg.prio = 5;
    esp_pthread_set_cfg(&cfg);
    if (pthread_create(&th, NULL, trampoline, t) != 0) {
        free(t);
        return -1;
    }
    pthread_detach(th);
    return 0;
}

/* ---------------- WiFi ---------------- */

#define BIT_GOT_IP BIT0
#define BIT_FAILED BIT1

static esp_netif_t *sta_if, *ap_if;
static EventGroupHandle_t wifi_ev;
static volatile bool sta_want;      /* we want to be associated */
static volatile bool sta_joining;   /* inside port_wifi_sta_connect() */
static volatile bool sta_has_ip;
static volatile int  join_tries;
static volatile uint8_t last_reason;

static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        sta_has_ip = false;
        last_reason = ((wifi_event_sta_disconnected_t *)data)->reason;
        if (!sta_want)
            return;
        if (sta_joining && ++join_tries >= 3)
            xEventGroupSetBits(wifi_ev, BIT_FAILED);
        else
            esp_wifi_connect();     /* an established link that dropped: keep trying */
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        sta_has_ip = true;
        xEventGroupSetBits(wifi_ev, BIT_GOT_IP);
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_AP_STACONNECTED) {
        ESP_LOGI(TAG, "a client joined the setup network");
    }
}

static void wifi_init(void)
{
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    char id[5], host[24];

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    sta_if = esp_netif_create_default_wifi_sta();
    ap_if = esp_netif_create_default_wifi_ap();
    port_device_id(id);
    snprintf(host, sizeof host, "%s-%s", C3_NAME, id);
    esp_netif_set_hostname(sta_if, host);

    wifi_ev = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_event, NULL));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));    /* credentials live in our own NVS keys */
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    esp_wifi_set_ps(WIFI_PS_NONE);                              /* snappy interactive sessions */
}

int port_wifi_scan(port_ap_t *out, int max)
{
    wifi_scan_config_t sc = { 0 };
    uint16_t n = (uint16_t)max;
    wifi_ap_record_t *rec;

    if (esp_wifi_scan_start(&sc, true) != ESP_OK)
        return 0;
    rec = calloc((size_t)max, sizeof *rec);
    if (!rec || esp_wifi_scan_get_ap_records(&n, rec) != ESP_OK) {
        esp_wifi_clear_ap_list();
        free(rec);
        return 0;
    }
    for (int i = 0; i < n; i++) {       /* the driver returns them strongest first */
        memset(&out[i], 0, sizeof out[i]);
        snprintf(out[i].ssid, sizeof out[i].ssid, "%s", (const char *)rec[i].ssid);
        out[i].rssi = rec[i].rssi;
        out[i].channel = rec[i].primary;
        out[i].secure = rec[i].authmode != WIFI_AUTH_OPEN;
    }
    free(rec);
    return n;
}

int port_wifi_ap_start(const char *ssid, const char *pass)
{
    wifi_config_t wc = { 0 };
    size_t plen = strlen(pass);

    snprintf((char *)wc.ap.ssid, sizeof wc.ap.ssid, "%s", ssid);
    wc.ap.ssid_len = (uint8_t)strlen(ssid);
    wc.ap.channel = 1;
    wc.ap.max_connection = 2;
    if (plen >= 8) {
        snprintf((char *)wc.ap.password, sizeof wc.ap.password, "%s", pass);
        wc.ap.authmode = WIFI_AUTH_WPA2_PSK;
    } else {
        wc.ap.authmode = WIFI_AUTH_OPEN;
    }
    /* AP+STA: the station side stays available for scanning and joining. */
    if (esp_wifi_set_mode(WIFI_MODE_APSTA) != ESP_OK || esp_wifi_set_config(WIFI_IF_AP, &wc) != ESP_OK)
        return -1;
    return 0;
}

void port_wifi_ap_stop(void)
{
    esp_wifi_set_mode(WIFI_MODE_STA);
}

int port_wifi_sta_connect(const char *ssid, const char *pass, uint32_t timeout_ms)
{
    wifi_config_t wc = { 0 };

    sta_want = false;
    esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(200));     /* let a pending disconnect event drain */

    snprintf((char *)wc.sta.ssid, sizeof wc.sta.ssid, "%s", ssid);
    snprintf((char *)wc.sta.password, sizeof wc.sta.password, "%s", pass);
    wc.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    wc.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
    wc.sta.pmf_cfg.capable = true;
    if (esp_wifi_set_config(WIFI_IF_STA, &wc) != ESP_OK)
        return PORT_WIFI_ERR;

    xEventGroupClearBits(wifi_ev, BIT_GOT_IP | BIT_FAILED);
    join_tries = 0;
    last_reason = 0;
    sta_joining = true;
    sta_want = true;
    if (esp_wifi_connect() != ESP_OK) {
        sta_joining = sta_want = false;
        return PORT_WIFI_ERR;
    }
    EventBits_t bits = xEventGroupWaitBits(wifi_ev, BIT_GOT_IP | BIT_FAILED, pdTRUE, pdFALSE,
                                           pdMS_TO_TICKS(timeout_ms));
    sta_joining = false;
    if (bits & BIT_GOT_IP)
        return PORT_WIFI_OK;

    sta_want = false;
    esp_wifi_disconnect();
    switch (last_reason) {
    case WIFI_REASON_AUTH_FAIL:
    case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
    case WIFI_REASON_HANDSHAKE_TIMEOUT:
    case WIFI_REASON_MIC_FAILURE:
    case WIFI_REASON_AUTH_EXPIRE:
        return PORT_WIFI_AUTH;
    case WIFI_REASON_NO_AP_FOUND:
        return PORT_WIFI_NOT_FOUND;
    default:
        return (bits & BIT_FAILED) ? PORT_WIFI_ERR : PORT_WIFI_TIMEOUT;
    }
}

void port_wifi_sta_disconnect(void)
{
    sta_want = false;
    esp_wifi_disconnect();
}

bool port_wifi_sta_up(void)
{
    return sta_has_ip;
}

static void netif_ip(esp_netif_t *nif, char *out, size_t cap)
{
    esp_netif_ip_info_t info;
    out[0] = 0;
    if (nif && esp_netif_get_ip_info(nif, &info) == ESP_OK)
        snprintf(out, cap, IPSTR, IP2STR(&info.ip));
}

void port_wifi_sta_ip(char *out, size_t cap) { netif_ip(sta_if, out, cap); }
void port_wifi_ap_ip(char *out, size_t cap) { netif_ip(ap_if, out, cap); }

int port_wifi_sta_rssi(void)
{
    wifi_ap_record_t ap;
    return esp_wifi_sta_get_ap_info(&ap) == ESP_OK ? ap.rssi : 0;
}

bool port_sock_via_ap(int fd)
{
    struct sockaddr_in local;
    socklen_t len = sizeof local;
    esp_netif_ip_info_t info;

    if (getsockname(fd, (struct sockaddr *)&local, &len) != 0)
        return false;
    return esp_netif_get_ip_info(ap_if, &info) == ESP_OK && local.sin_addr.s_addr == info.ip.addr;
}

/* ---------------- entry point ---------------- */

void app_main(void)
{
    esp_err_t e = nvs_flash_init();
    if (e == ESP_ERR_NVS_NO_FREE_PAGES || e == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        e = nvs_flash_init();
    }
    ESP_ERROR_CHECK(e);
    fs_mount();
    wifi_init();
    c3shell_main();
}

/* ---------------- VPN tunnel routing ---------------- */

/* lwIP routes into the tunnel by itself: every socket here is an lwIP socket. */
int port_vpn_dial(uint32_t ip_be, uint16_t port, int timeout_ms)
{
    (void)ip_be;
    (void)port;
    (void)timeout_ms;
    return -2;
}

/* ESP-IDF's lwIP asks this hook for a route after matching its own interfaces'
 * subnets (src == NULL), and for source-based routing (src set). The link
 * option --wrap=ip4_route_src_hook (main/CMakeLists.txt) puts this in front:
 * destinations the VPN pushed routes for go into the tunnel. */
struct netif *__real_ip4_route_src_hook(const ip4_addr_t *src, const ip4_addr_t *dest);
struct netif *__wrap_ip4_route_src_hook(const ip4_addr_t *src, const ip4_addr_t *dest)
{
    if (src == NULL) {
        struct netif *n = vpnif_route(dest);
        if (n)
            return n;
    }
    return __real_ip4_route_src_hook(src, dest);
}
