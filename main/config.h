/* c3shell tunables */
#ifndef C3_CONFIG_H
#define C3_CONFIG_H

#define C3_NAME            "c3shell"
#define C3_VERSION         "0.2"

/* Setup network hosted while the device has no WiFi to join.
 * SSID is this prefix + the last two MAC bytes, e.g. "c3shell-2D90".
 * Password must be >= 8 chars (WPA2); set to "" for an open network. */
#define C3_AP_SSID_PREFIX  "c3shell-"
#define C3_AP_PASSWORD     "c3shell-setup"

#define C3_MAX_SESSIONS    3          /* simultaneous SSH connections, including ones still logging in */
#define C3_SESSION_STACK   (24 * 1024)
#define C3_IDLE_TIMEOUT_S  900        /* at the prompt; not during ssh */
#define C3_LOGIN_GRACE_S   60         /* a connection must finish logging in within this */
#define C3_GUARD_FAILS     5          /* wrong passwords from one address before it is blocked ... */
#define C3_GUARD_BLOCK_S   300        /* ... for this long */
#define C3_PW_MIN          6
#define C3_PBKDF2_ITERS    3000

#define C3_JOIN_TIMEOUT_MS 15000
#define C3_FALLBACK_S      30         /* WiFi lost this long -> host setup network again */
#define C3_RETRY_S         60         /* while hosting, retry the saved network this often */
#define C3_AP_LINGER_MS    3000       /* after a successful join, before the setup network vanishes */

#define C3_KNOWN_HOSTS     16

#define C3_PATH_MAX        128        /* longest path in the file area, e.g. "/notes/todo.txt" */
#define C3_NAME_MAX        64         /* longest single name + 1 (LittleFS limit) */
#define C3_HOST_MAX        (C3_PATH_MAX + 64) /* the same path with the file area's mount point in front */
#define C3_VI_MAX          (32 * 1024) /* largest file vi will load */
#define C3_SSH_CONNECT_MS  8000
#define C3_SSH_IO_MS       20000

#endif
