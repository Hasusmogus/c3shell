/* The shell on the local console: the ESP32-C3's USB serial port (the same
 * one that carries the log), so the board can be used with nothing but a USB
 * cable - also before it has WiFi. A getty-style login prompt, then the
 * ordinary shell; 'exit' brings the prompt back. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
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

enum { LOGIN_OK, LOGIN_AGAIN, LOGIN_IDLE };

#define CONSOLE_IDLE_S 60    /* at the login prompt, before the shell's stack is given back */

static int login(session_t *s)
{
    char id[5], user[40], pass[64];

    port_device_id(id);
    tn_printf(s, "\n%s %s (device %s) - USB console\n", C3_NAME, C3_VERSION, id);
    if (!account_exists()) {
        tn_puts(s, "This device has no account yet. Press Enter to create one.\n");
        int n = tn_readline(s, "", user, sizeof user, RL_ECHO, CONSOLE_IDLE_S);
        if (n < 0 || account_exists())
            return n == TN_TIMEOUT ? LOGIN_IDLE : LOGIN_AGAIN;
        s->setup = true;
        return LOGIN_OK;
    }
    int n = tn_readline(s, "login: ", user, sizeof user, RL_ECHO, CONSOLE_IDLE_S);
    if (n == TN_TIMEOUT)
        return LOGIN_IDLE;
    if (n <= 0)
        return LOGIN_AGAIN;
    n = tn_readline(s, "Password: ", pass, sizeof pass, 0, CONSOLE_IDLE_S);
    if (n < 0)
        return n == TN_TIMEOUT ? LOGIN_IDLE : LOGIN_AGAIN;
    bool ok = account_check(user, pass);
    memset(pass, 0, sizeof pass);
    if (!ok) {
        port_sleep_ms(2000);
        tn_puts(s, "Login incorrect\n");
        port_log("console: wrong password");
        return LOGIN_AGAIN;
    }
    snprintf(s->user, sizeof s->user, "%.31s", user);
    return LOGIN_OK;
}

/* The console's shell runs on a full session stack, but only from the first
 * key pressed until logout (or a minute of nobody at the login prompt); the
 * rest of the time a small thread just waits for that key. */
static int console_fd = -1;
static volatile bool console_busy;

static void console_session(void *arg)
{
    session_t *s = calloc(1, sizeof *s);
    (void)arg;
    if (s) {
        s->console = true;
        s->io.fd = console_fd;
        s->id = C3_MAX_SESSIONS;        /* after the SSH slots; it does not take one */
        s->cols = 80;
        s->rows = 24;
        s->since_s = port_uptime_s();
        snprintf(s->peer, sizeof s->peer, "USB console");
        snprintf(s->doing, sizeof s->doing, "login");
        /* the key that woke us is usually Enter: it asks for the prompt, it is not an empty login */
        while (tn_input_ready(s) && (s->ibuf[s->ipos] == '\r' || s->ibuf[s->ipos] == '\n'))
            s->ipos++;
        int r = LOGIN_AGAIN;
        for (int tries = 0; tries < 5 && r == LOGIN_AGAIN; tries++)
            r = login(s);
        if (r == LOGIN_OK) {
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
    console_busy = false;
}

static void console_getty(void *arg)
{
    (void)arg;
    for (;;) {
        fd_set rd;
        struct timeval tv = { 1, 0 };
        FD_ZERO(&rd);
        FD_SET(console_fd, &rd);
        if (select(console_fd + 1, &rd, NULL, NULL, &tv) <= 0)
            continue;
        console_busy = true;
        if (port_thread_start("console", C3_SESSION_STACK, console_session, NULL) != 0) {
            console_busy = false;
            port_sleep_ms(1000);        /* not enough memory right now: try again on the next key */
            continue;
        }
        while (console_busy)
            port_sleep_ms(200);
    }
}

void console_start(void)
{
    console_fd = port_console_open();
    if (console_fd < 0)
        return;
    if (port_thread_start("console-wait", 3072, console_getty, NULL) != 0)
        port_log("console: cannot start");
}
