/* The single login account. Only a salted PBKDF2-HMAC-SHA256 hash is stored. */
#include <pthread.h>
#include <string.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include "c3shell.h"

typedef struct {
    char     user[32];
    uint8_t  salt[16];
    uint8_t  hash[32];
    uint32_t iters;
} account_t;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static bool load(account_t *a)
{
    return port_kv_get("account", a, sizeof *a) == (int)sizeof *a && a->user[0];
}

static int derive(const char *pass, const account_t *a, uint8_t out[32])
{
    return wc_PBKDF2(out, (const byte *)pass, (int)strlen(pass), a->salt, sizeof a->salt,
                     (int)a->iters, 32, WC_SHA256);
}

bool account_valid_username(const char *u)
{
    size_t n = strlen(u);
    if (n < 1 || n > 31)
        return false;
    for (; *u; u++)
        if (!((*u >= 'a' && *u <= 'z') || (*u >= 'A' && *u <= 'Z') || (*u >= '0' && *u <= '9') ||
              *u == '_' || *u == '-' || *u == '.'))
            return false;
    return true;
}

bool account_exists(void)
{
    account_t a;
    return load(&a);
}

void account_name(char *out, size_t cap)
{
    account_t a;
    out[0] = 0;
    if (load(&a)) {
        strncpy(out, a.user, cap - 1);
        out[cap - 1] = 0;
    }
}

static int store(account_t *a, const char *pass)
{
    port_random(a->salt, sizeof a->salt);
    a->iters = C3_PBKDF2_ITERS;
    if (derive(pass, a, a->hash) != 0)
        return -1;
    return port_kv_set("account", a, sizeof *a);
}

int account_create(const char *user, const char *pass)
{
    account_t a;
    int r = -1;
    pthread_mutex_lock(&lock);
    if (!load(&a)) {                 /* never overwrite: first-boot setup only */
        memset(&a, 0, sizeof a);
        strncpy(a.user, user, sizeof a.user - 1);
        r = store(&a, pass);
    }
    pthread_mutex_unlock(&lock);
    return r;
}

int account_set_password(const char *pass)
{
    account_t a;
    int r = -1;
    pthread_mutex_lock(&lock);
    if (load(&a))
        r = store(&a, pass);
    pthread_mutex_unlock(&lock);
    return r;
}

bool account_check(const char *user, const char *pass)
{
    account_t a;
    uint8_t h[32];
    if (!load(&a))
        return false;
    /* Always run the KDF so a wrong username costs the same as a wrong password. */
    if (derive(pass, &a, h) != 0)
        return false;
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++)
        diff |= h[i] ^ a.hash[i];
    return diff == 0 && strcmp(user, a.user) == 0;
}
