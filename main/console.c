/* The shell on the local console: the ESP32-C3's USB serial port (the same
 * one that carries the log), so the board can be used with nothing but a USB
 * cable - also before it has WiFi. A getty-style login prompt, then the
 * ordinary shell; 'exit' brings the prompt back. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "c3shell.h"

/* A serial line has no way to report the window size, so ask the terminal:
 * park the cursor far bottom-right and request its position ("ESC[6n"). */
void console_sync_size(session_t *s)
{
    static const char ask[] = "\x1b" "7\x1b[999;999H\x1b[6n\x1b" "8";
    int rows = 0, cols = 0, c, *num = &rows;

    if (s->size_probe < 0)
        return;
    tn_write(s, ask, sizeof ask - 1);
    /* the answer is ESC [ rows ; cols R - skip anything typed before it */
    while ((c = tn_getc(s, 400)) >= 0 && c != 0x1B)
        ;
    if (c == 0x1B && tn_getc(s, 100) == '[') {
        while ((c = tn_getc(s, 100)) >= 0) {
            if (c >= '0' && c <= '9')
                *num = *num * 10 + (c - '0');
            else if (c == ';')
                num = &cols;
            else
                break;
        }
    }
    if (c == 'R' && rows >= 5 && cols >= 20 && rows < 1000 && cols < 1000) {
        s->size_probe = 1;
        if (rows != s->rows || cols != s->cols) {
            s->rows = (uint16_t)rows;
            s->cols = (uint16_t)cols;
            s->winch = true;
        }
    } else if (s->size_probe == 0) {
        s->size_probe = -1;             /* this terminal does not answer: keep 80x24 */
    }
}

/* true = logged in (or let through to create the first account) */
static bool login(session_t *s)
{
    char id[5], user[40], pass[64];

    port_device_id(id);
    tn_printf(s, "\n%s %s (device %s) - USB console\n", C3_NAME, C3_VERSION, id);
    if (!account_exists()) {
        tn_puts(s, "This device has no account yet. Press Enter to create one.\n");
        int n = tn_readline(s, "", user, sizeof user, RL_ECHO, 3600);
        if (n < 0 || account_exists())
            return false;
        s->setup = true;
        return true;
    }
    int n = tn_readline(s, "login: ", user, sizeof user, RL_ECHO, 3600);
    if (n <= 0)
        return false;
    n = tn_readline(s, "Password: ", pass, sizeof pass, 0, 120);
    if (n < 0)
        return false;
    bool ok = account_check(user, pass);
    memset(pass, 0, sizeof pass);
    if (!ok) {
        port_sleep_ms(2000);
        tn_puts(s, "Login incorrect\n");
        port_log("console: wrong password");
        return false;
    }
    snprintf(s->user, sizeof s->user, "%.31s", user);
    return true;
}

static void console_thread(void *arg)
{
    int fd = (int)(intptr_t)arg;
    for (;;) {
        session_t *s = calloc(1, sizeof *s);
        if (!s) {
            port_sleep_ms(1000);
            continue;
        }
        s->console = true;
        s->io.fd = fd;
        s->id = C3_MAX_SESSIONS;        /* after the SSH slots; it does not take one */
        s->cols = 80;
        s->rows = 24;
        s->since_s = port_uptime_s();
        snprintf(s->peer, sizeof s->peer, "USB console");
        snprintf(s->doing, sizeof s->doing, "login");
        if (login(s)) {
            port_log("console: %s logged in", s->setup ? "(first-time setup)" : s->user);
            s->since_s = port_uptime_s();
            console_sync_size(s);
            server_console_attach(s);
            port_console_quiet(true);
            session_main(s);
            port_console_quiet(false);
            server_console_attach(NULL);
            port_log("console: logged out");
        }
        free(s);
    }
}

void console_start(void)
{
    int fd = port_console_open();
    if (fd < 0)
        return;
    if (port_thread_start("console", C3_SESSION_STACK, console_thread, (void *)(intptr_t)fd) != 0)
        port_log("console: cannot start");
}
