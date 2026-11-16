/* Persistent SSH state: known host keys of other machines (trust on first
 * use), the device's Ed25519 identity for outbound public-key logins, and the
 * host key of the device's own SSH server. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/hash.h>
#include "c3shell.h"

typedef struct {
    char    name[64];
    uint8_t fp[32];
} khost_t;

typedef struct {
    uint16_t derlen;
    uint8_t  der[126];
    uint8_t  pub[32];
} ident_t;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

/* ---------------- known hosts ---------------- */

static int kh_load(khost_t *t)
{
    int n = port_kv_get("khosts", t, sizeof(khost_t) * C3_KNOWN_HOSTS);
    return n < 0 ? 0 : n / (int)sizeof(khost_t);
}

static void kh_save(const khost_t *t, int n)
{
    if (n == 0)
        port_kv_del("khosts");
    else
        port_kv_set("khosts", t, sizeof(khost_t) * (size_t)n);
}

void sshstore_fp_text(const uint8_t fp[32], char *out, size_t cap)
{
    byte b64[64];
    word32 len = sizeof b64;
    if (Base64_Encode_NoNl(fp, 32, b64, &len) != 0)
        len = 0;
    while (len > 0 && b64[len - 1] == '=')
        len--;
    snprintf(out, cap, "SHA256:%.*s", (int)len, (const char *)b64);
}

int sshstore_host_check(const char *name, const uint8_t fp[32])
{
    khost_t *t = malloc(sizeof(khost_t) * C3_KNOWN_HOSTS);
    int r = KH_NEW;
    if (!t)
        return KH_CHANGED;       /* fail closed */
    pthread_mutex_lock(&lock);
    int n = kh_load(t);
    for (int i = 0; i < n; i++)
        if (strcmp(t[i].name, name) == 0) {
            r = memcmp(t[i].fp, fp, 32) == 0 ? KH_MATCH : KH_CHANGED;
            break;
        }
    pthread_mutex_unlock(&lock);
    free(t);
    return r;
}

void sshstore_host_add(const char *name, const uint8_t fp[32])
{
    khost_t *t = malloc(sizeof(khost_t) * C3_KNOWN_HOSTS);
    if (!t)
        return;
    pthread_mutex_lock(&lock);
    int n = kh_load(t), i;
    for (i = 0; i < n; i++)
        if (strcmp(t[i].name, name) == 0)
            break;
    if (i == C3_KNOWN_HOSTS) {   /* full: drop the oldest entry */
        memmove(&t[0], &t[1], sizeof(khost_t) * (C3_KNOWN_HOSTS - 1));
        i = n = C3_KNOWN_HOSTS - 1;
    }
    memset(&t[i], 0, sizeof t[i]);
    snprintf(t[i].name, sizeof t[i].name, "%s", name);
    memcpy(t[i].fp, fp, 32);
    kh_save(t, i == n ? n + 1 : n);
    pthread_mutex_unlock(&lock);
    free(t);
}

int sshstore_host_list(session_t *s)
{
    khost_t *t = malloc(sizeof(khost_t) * C3_KNOWN_HOSTS);
    if (!t)
        return 0;
    pthread_mutex_lock(&lock);
    int n = kh_load(t);
    pthread_mutex_unlock(&lock);
    for (int i = 0; i < n; i++) {
        char fp[64];
        sshstore_fp_text(t[i].fp, fp, sizeof fp);
        tn_printf(s, "  %2d  %-28s %s\n", i + 1, t[i].name, fp);
    }
    free(t);
    return n;
}

bool sshstore_host_forget(const char *what)
{
    khost_t *t = malloc(sizeof(khost_t) * C3_KNOWN_HOSTS);
    bool done = false;
    if (!t)
        return false;
    pthread_mutex_lock(&lock);
    int n = kh_load(t);
    char *end;
    long idx = strtol(what, &end, 10);
    for (int i = 0; i < n; i++)
        if ((*end == 0 && idx == i + 1) || strcmp(t[i].name, what) == 0) {
            memmove(&t[i], &t[i + 1], sizeof(khost_t) * (size_t)(n - i - 1));
            kh_save(t, n - 1);
            done = true;
            break;
        }
    pthread_mutex_unlock(&lock);
    free(t);
    return done;
}

/* ---------------- device identity ---------------- */

static int ident_make(ident_t *id)
{
    WC_RNG rng;
    ed25519_key key;
    word32 publen = 32;
    int r = -1;

    if (wc_InitRng(&rng) != 0)
        return -1;
    if (wc_ed25519_init(&key) == 0) {
        if (wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key) == 0 &&
            wc_ed25519_export_public(&key, id->pub, &publen) == 0) {
            int n = wc_Ed25519KeyToDer(&key, id->der, sizeof id->der);
            if (n > 0) {
                id->derlen = (uint16_t)n;
                r = 0;
            }
        }
        wc_ed25519_free(&key);
    }
    wc_FreeRng(&rng);
    return r;
}

static int ident_get(const char *slot, ident_t *id, bool regen)
{
    int r = 0;
    pthread_mutex_lock(&lock);
    if (regen || port_kv_get(slot, id, sizeof *id) != (int)sizeof *id || id->derlen == 0 ||
        id->derlen > sizeof id->der) {
        memset(id, 0, sizeof *id);
        r = ident_make(id);
        if (r == 0 && port_kv_set(slot, id, sizeof *id) != 0)
            r = -1;
    }
    pthread_mutex_unlock(&lock);
    return r;
}

static const uint8_t blob_head[] = { 0, 0, 0, 11, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9', 0, 0, 0, 32 };

int sshstore_identity(uint8_t *der, size_t dercap, uint8_t pub[32])
{
    ident_t id;
    int n = -1;
    if (ident_get("sshkey", &id, false) == 0 && id.derlen <= dercap) {
        n = id.derlen;
        memcpy(der, id.der, id.derlen);
        memcpy(pub, id.pub, 32);
    }
    memset(&id, 0, sizeof id);
    return n;
}

int sshstore_hostkey(uint8_t *der, size_t dercap, char *fp, size_t fpcap)
{
    ident_t id;
    uint8_t blob[sizeof blob_head + 32], hash[32];
    int n = -1;
    if (ident_get("hostkey", &id, false) == 0 && id.derlen <= dercap) {
        memcpy(blob, blob_head, sizeof blob_head);
        memcpy(blob + sizeof blob_head, id.pub, 32);
        if (wc_Sha256Hash(blob, sizeof blob, hash) == 0) {
            sshstore_fp_text(hash, fp, fpcap);
            memcpy(der, id.der, id.derlen);
            n = id.derlen;
        }
    }
    memset(&id, 0, sizeof id);
    return n;
}

int sshstore_pubkey_line(char *out, size_t cap, bool regen)
{
    ident_t id;
    uint8_t blob[sizeof blob_head + 32];
    byte b64[96];
    word32 len = sizeof b64;
    char dev[5];

    if (ident_get("sshkey", &id, regen) != 0)
        return -1;
    memcpy(blob, blob_head, sizeof blob_head);
    memcpy(blob + sizeof blob_head, id.pub, 32);
    memset(&id, 0, sizeof id);
    if (Base64_Encode_NoNl(blob, sizeof blob, b64, &len) != 0)
        return -1;
    port_device_id(dev);
    snprintf(out, cap, "ssh-ed25519 %.*s %s-%s", (int)len, (const char *)b64, C3_NAME, dev);
    return 0;
}
