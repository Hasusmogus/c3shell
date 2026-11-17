/* Shared wolfCrypt + wolfSSH build configuration.
 * Used unchanged by both the ESP32-C3 firmware and the host simulator, so the
 * SSH client that runs in the simulator is the same code that runs on the chip. */
#ifndef C3SHELL_USER_SETTINGS_H
#define C3SHELL_USER_SETTINGS_H

/* wolfSSL turns on its own Espressif port (hardware crypto, FreeRTOS
 * allocator hooks) as soon as it sees PlatformIO. We want plain portable
 * wolfCrypt instead - exactly the code the simulator exercises. */
#undef WOLFSSL_ESPIDF
#undef PLATFORMIO

/* ---- wolfCrypt: the primitives SSH and the OpenVPN client need ---- */
#define WOLFSSL_WOLFSSH
#define WOLFSSL_PUBLIC_MP
#define SINGLE_THREADED          /* every SSH session owns all of its crypto state */
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define NO_ASN_TIME
#define WOLFSSL_SMALL_STACK
/* ...but a hash keeps its working buffer for its lifetime instead of a
 * malloc/free per block: password hashing alone is ~12,000 blocks a login */
#define WOLFSSL_SMALL_STACK_CACHE
#define WOLFSSL_IGNORE_FILE_WARN

#define NO_DH
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_DES3
#define NO_PSK
#define NO_OLD_TLS

#define WOLFSSL_SP_MATH_ALL
#define SP_WORD_SIZE 32
#define SP_INT_BITS 4096         /* RSA host keys up to 4096 bit */
#define WOLFSSL_SP_SMALL

#define HAVE_ECC
#define HAVE_ECC384
#define HAVE_ECC521
#define ECC_TIMING_RESISTANT
#define HAVE_CURVE25519
#define HAVE_ED25519
#define WOLFSSL_ED25519_STREAMING_VERIFY
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WC_RSA_BLINDING
#define WOLFSSL_KEY_GEN          /* Ed25519 key -> DER for the device identity */

#define HAVE_AESGCM
#define GCM_TABLE_4BIT
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_DIRECT

#define HAVE_HASHDRBG
#define WOLFSSL_BASE64_ENCODE
#define HAVE_PBKDF2

/* ---- TLS client, for the OpenVPN control channel (ovpn.c) ---- */
#define NO_WOLFSSL_SERVER        /* the SSH server is wolfSSH; TLS is only ever a client */
#define WOLFSSL_USER_IO          /* TLS records travel inside OpenVPN control packets */
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_EXTENDED_MASTER
#define HAVE_HKDF
#define WC_RSA_PSS
#define HAVE_KEYING_MATERIAL     /* RFC 5705 exporter: OpenVPN's "tls-ekm" data-channel keys */
#define WOLFSSL_ALWAYS_VERIFY_CB /* remote-cert-tls server looks at the peer's certificate */
#define NO_SESSION_CACHE
/* MD5 stays in for OpenVPN's original key derivation (TLS 1.0 PRF) used by
 * servers older than 2.6; TLS itself is limited to 1.2 and 1.3. */

/* Entropy comes from the platform layer: the hardware RNG on the chip,
 * /dev/urandom in the simulator (see port_random()). */
extern int c3shell_rand_seed(unsigned char *out, unsigned int sz);
#define CUSTOM_RAND_GENERATE_SEED c3shell_rand_seed
#define NO_DEV_RANDOM

/* ---- wolfSSH: server (the login shell) and client (outbound ssh);
 *      we supply the socket I/O ---- */
#define WOLFSSH_SHELL            /* window-change requests from the user's terminal */
#define WOLFSSH_ALLOW_USERAUTH_NONE /* only granted while no account exists (first boot) */
#define WOLFSSH_SMALL_STACK
#define WOLFSSH_USER_IO
#define WOLFSSH_TERM
#define NO_TERMIOS               /* the terminal is at the far end of an SSH channel */
#define WOLFSSH_KEYBOARD_INTERACTIVE
#define DEFAULT_WINDOW_SZ      (16 * 1024)
#define DEFAULT_MAX_PACKET_SZ  (4 * 1024)

#endif
