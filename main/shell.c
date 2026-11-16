/* Per-connection flow: first-boot account creation if needed, then the command shell. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "c3shell.h"

#define SCAN_MAX 20
enum { CMD_OK = 0, CMD_EXIT = 1 };

/* ---------------- account setup / login ---------------- */

static int read_new_password(session_t *s, char *out, size_t cap)
{
    char again[64];
    for (;;) {
        int n = tn_readline(s, "New password: ", out, cap, 0, 120);
        if (n < 0)
            return n;
        if (n < C3_PW_MIN) {
            tn_printf(s, "Too short - use at least %d characters.\n", C3_PW_MIN);
            continue;
        }
        n = tn_readline(s, "Retype new password: ", again, sizeof again, 0, 120);
        if (n < 0)
            return n;
        if (strcmp(out, again) != 0) {
            tn_puts(s, "The passwords do not match, try again.\n");
            continue;
        }
        memset(again, 0, sizeof again);
        return 0;
    }
}

/* Runs for a connection that was let in because no account existed.
 * 0 = account created, anything else = hang up. */
static int first_boot_setup(session_t *s)
{
    char user[40], pass[64], prompt[80];
    bool suggest = account_valid_username(s->user);

    tn_puts(s, "\n*** First-time setup ***\n"
               "This device has no account yet. Create the one you will log in with.\n\n");
    if (suggest)
        snprintf(prompt, sizeof prompt, "New username [%s]: ", s->user);
    else
        snprintf(prompt, sizeof prompt, "New username: ");
    for (;;) {
        int n = tn_readline(s, prompt, user, sizeof user, RL_ECHO, 120);
        if (n < 0)
            return -1;
        if (n == 0 && suggest)
            snprintf(user, sizeof user, "%s", s->user);
        if (account_valid_username(user))
            break;
        tn_puts(s, "Use 1-31 characters: letters, digits, '.', '_' or '-'.\n");
    }
    if (read_new_password(s, pass, sizeof pass) < 0)
        return -1;
    int r = account_create(user, pass);
    memset(pass, 0, sizeof pass);
    if (r != 0) {
        tn_puts(s, "An account was created from another connection in the meantime.\n"
                   "Connect again and log in with it.\n");
        return -1;
    }
    snprintf(s->user, sizeof s->user, "%.31s", user);
    port_log("account '%s' created", user);
    tn_printf(s, "\nAccount '%s' created. From now on, log in with:  ssh %s@<this device>\n", user, user);
    return 0;
}

/* ---------------- commands ---------------- */

static int cmd_help(session_t *s, int argc, char **argv)
{
    (void)argc;
    (void)argv;
    tn_puts(s,
            "  wifi                      pick a WiFi network to join (scan + select)\n"
            "  wifi forget               forget the saved network, host the setup network\n"
            "  ssh [user@]host [-p port] open a shell on another machine\n"
            "                            (hang up a stuck one with ~. on a new line; ~~. from OpenSSH)\n"
            "  sshkey [new]              show (or regenerate) this device's public key\n"
            "  hosts                     list remembered SSH host keys\n"
            "  hosts forget <n|name>     forget one\n"
            "  status                    network, sessions, memory\n"
            "  passwd                    change your password\n"
            "  reboot                    restart the device\n"
            "  factory-reset             erase account, WiFi and SSH data\n"
            "  exit                      log out\n");
    return CMD_OK;
}

static int cmd_status(session_t *s, int argc, char **argv)
{
    net_status_t st;
    char id[5];
    uint32_t up = port_uptime_s();
    (void)argc;
    (void)argv;

    netmgr_status(&st);
    port_device_id(id);
    tn_printf(s, "%s %s, device %s, up %ud %02u:%02u:%02u\n", C3_NAME, C3_VERSION, id,
              (unsigned)(up / 86400), (unsigned)(up / 3600 % 24), (unsigned)(up / 60 % 60), (unsigned)(up % 60));
    if (st.sta_up)
        tn_printf(s, "WiFi:          joined '%s', address %s, signal %d dBm\n", st.sta_ssid, st.sta_ip, st.rssi);
    else if (st.have_saved)
        tn_printf(s, "WiFi:          '%s' saved but not reachable right now\n", st.sta_ssid);
    else
        tn_puts(s, "WiFi:          no network chosen yet (run 'wifi')\n");
    if (st.ap_up)
        tn_printf(s, "Setup network: '%s' is up, address %s\n", st.ap_ssid, st.ap_ip);
    else
        tn_puts(s, "Setup network: off\n");
    tn_printf(s, "Sessions:      %d of %d, you are %s from %s\n", server_session_count(), C3_MAX_SESSIONS,
              s->user, s->peer);
    if (port_free_heap() >= 0)
        tn_printf(s, "Memory:        %ld bytes free, session stack headroom %ld bytes\n", port_free_heap(),
                  port_stack_headroom());
    return CMD_OK;
}

static const char *bars(int rssi)
{
    return rssi >= -55 ? "[####]" : rssi >= -67 ? "[### ]" : rssi >= -78 ? "[##  ]" : "[#   ]";
}

static int wifi_join(session_t *s, const port_ap_t *ap)
{
    char pass[65] = "";
    net_status_t st;

    if (ap->secure) {
        char prompt[64];
        snprintf(prompt, sizeof prompt, "Password for '%s': ", ap->ssid);
        int n = tn_readline(s, prompt, pass, sizeof pass, 0, 120);
        if (n < 0)
            return n == TN_CLOSED ? CMD_EXIT : CMD_OK;
        if (n < 8) {
            tn_puts(s, "WiFi passwords have at least 8 characters.\n");
            return CMD_OK;
        }
    }
    tn_printf(s, "Joining '%s' ...\n", ap->ssid);
    int r = netmgr_join(ap->ssid, pass);
    memset(pass, 0, sizeof pass);
    if (r != PORT_WIFI_OK) {
        tn_printf(s, "Could not join '%s': %s.\n", ap->ssid,
                  r == PORT_WIFI_AUTH        ? "wrong password"
                  : r == PORT_WIFI_NOT_FOUND ? "network not found"
                  : r == PORT_WIFI_TIMEOUT   ? "no answer (timed out)"
                                             : "radio error");
        return CMD_OK;
    }
    netmgr_status(&st);
    tn_printf(s, "\nJoined '%s'. This device is now at %s.\n", ap->ssid, st.sta_ip);
    if (st.ap_up)
        tn_printf(s, "The setup network '%s' is shutting down now.\n", st.ap_ssid);
    tn_printf(s, "Join '%s' yourself and reconnect with:  ssh %s@%s\n\n", ap->ssid, s->user, st.sta_ip);
    port_sleep_ms(C3_AP_LINGER_MS);
    netmgr_drop_ap();
    return CMD_EXIT;        /* this connection does not survive the switch */
}

static int cmd_wifi(session_t *s, int argc, char **argv)
{
    port_ap_t aps[SCAN_MAX];
    net_status_t st;
    char line[40];

    netmgr_status(&st);
    if (argc > 1 && strcmp(argv[1], "forget") == 0) {
        if (!st.have_saved) {
            tn_puts(s, "No network is saved.\n");
            return CMD_OK;
        }
        tn_printf(s, "Forget '%s' and go back to hosting '%s'?", st.sta_ssid, st.ap_ssid);
        if (!tn_confirm(s, ""))
            return CMD_OK;
        tn_printf(s, "Done. Find this device on the WiFi network '%s' (ssh %s@%s).\n", st.ap_ssid, s->user, st.ap_ip);
        port_sleep_ms(500);
        netmgr_forget();
        return s->via_ap ? CMD_OK : CMD_EXIT;
    }
    if (argc > 1) {
        tn_puts(s, "usage: wifi | wifi forget\n");
        return CMD_OK;
    }
    if (st.sta_up && !s->via_ap) {
        tn_printf(s, "You are connected through '%s'. Switching networks ends this session", st.sta_ssid);
        if (!tn_confirm(s, ".\n"))
            return CMD_OK;
    }

    for (;;) {
        tn_puts(s, "Scanning ...\n");
        int raw = netmgr_scan(aps, SCAN_MAX), n = 0;
        for (int i = 0; i < raw; i++) {         /* drop hidden networks and repeats of one name */
            bool dup = aps[i].ssid[0] == 0;
            for (int j = 0; j < n && !dup; j++)
                dup = strcmp(aps[j].ssid, aps[i].ssid) == 0;
            if (!dup)
                aps[n++] = aps[i];
        }
        if (n == 0)
            tn_puts(s, "No networks found.\n");
        else
            tn_puts(s, "\n   #  Signal           Security  Network\n");
        for (int i = 0; i < n; i++)
            tn_printf(s, "  %2d  %s %4d dBm  %-8s  %s%s\n", i + 1, bars(aps[i].rssi), aps[i].rssi,
                      aps[i].secure ? "password" : "open", aps[i].ssid,
                      st.sta_up && strcmp(aps[i].ssid, st.sta_ssid) == 0 ? "  (current)" : "");

        int len = tn_readline(s, "\nNetwork number, r = rescan, m = type a name, q = cancel: ", line, sizeof line,
                              RL_ECHO, 180);
        if (len == TN_CLOSED || len == TN_TIMEOUT)
            return CMD_EXIT;
        if (len < 0 || line[0] == 'q' || line[0] == 0)
            return CMD_OK;
        if (line[0] == 'r')
            continue;
        if (line[0] == 'm') {
            port_ap_t manual = { .secure = 1 };
            len = tn_readline(s, "Network name (SSID): ", manual.ssid, sizeof manual.ssid, RL_ECHO, 120);
            if (len <= 0)
                return len == TN_CLOSED ? CMD_EXIT : CMD_OK;
            for (int i = 0; i < n; i++)
                if (strcmp(aps[i].ssid, manual.ssid) == 0)
                    manual.secure = aps[i].secure;
            return wifi_join(s, &manual);
        }
        char *end;
        long pick = strtol(line, &end, 10);
        if (*end != 0 || pick < 1 || pick > n) {
            tn_puts(s, "Not one of the listed numbers.\n");
            continue;
        }
        return wifi_join(s, &aps[pick - 1]);
    }
}

static int cmd_ssh(session_t *s, int argc, char **argv)
{
    char user[32] = "", host[64] = "";
    int port = 22;
    net_status_t st;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            snprintf(user, sizeof user, "%s", argv[++i]);
        } else if (argv[i][0] != '-' && host[0] == 0) {
            char *at = strrchr(argv[i], '@');
            if (at) {
                *at = 0;
                snprintf(user, sizeof user, "%s", argv[i]);
                snprintf(host, sizeof host, "%s", at + 1);
            } else {
                snprintf(host, sizeof host, "%s", argv[i]);
            }
        } else {
            host[0] = 0;
            break;
        }
    }
    if (host[0] == 0 || port < 1 || port > 65535) {
        tn_puts(s, "usage: ssh [user@]host [-p port]\n");
        return CMD_OK;
    }
    if (user[0] == 0) {
        char prompt[64];
        snprintf(prompt, sizeof prompt, "login as [%s]: ", s->user);
        int n = tn_readline(s, prompt, user, sizeof user, RL_ECHO, 60);
        if (n < 0)
            return n == TN_CLOSED ? CMD_EXIT : CMD_OK;
        if (n == 0)
            snprintf(user, sizeof user, "%s", s->user);
    }
    netmgr_status(&st);
    if (!st.sta_up)
        tn_puts(s, "Note: no WiFi network joined - only machines on the setup network are reachable.\n");
    ssh_run(s, user, host, port);
    return s->closed ? CMD_EXIT : CMD_OK;
}

static int cmd_sshkey(session_t *s, int argc, char **argv)
{
    char line[160];
    bool regen = argc > 1 && strcmp(argv[1], "new") == 0;
    if (regen && !tn_confirm(s, "Replace this device's SSH key? Servers that trust the old one will stop accepting it."))
        return CMD_OK;
    if (sshstore_pubkey_line(line, sizeof line, regen) != 0) {
        tn_puts(s, "Could not create a key.\n");
        return CMD_OK;
    }
    tn_printf(s, "This device's public key. To log in without a password, add this line to\n"
                 "~/.ssh/authorized_keys on the machine you connect to:\n\n%s\n\n", line);
    return CMD_OK;
}

static int cmd_hosts(session_t *s, int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "forget") == 0) {
        tn_puts(s, sshstore_host_forget(argv[2]) ? "Forgotten.\n" : "No such entry.\n");
    } else if (argc == 1) {
        if (sshstore_host_list(s) == 0)
            tn_puts(s, "No hosts remembered yet.\n");
    } else {
        tn_puts(s, "usage: hosts | hosts forget <number|name>\n");
    }
    return CMD_OK;
}

static int cmd_passwd(session_t *s, int argc, char **argv)
{
    char cur[64], pass[64];
    (void)argc;
    (void)argv;
    if (tn_readline(s, "Current password: ", cur, sizeof cur, 0, 60) < 0)
        return CMD_OK;
    bool ok = account_check(s->user, cur);
    memset(cur, 0, sizeof cur);
    if (!ok) {
        port_sleep_ms(1500);
        tn_puts(s, "Wrong password.\n");
        return CMD_OK;
    }
    if (read_new_password(s, pass, sizeof pass) == 0)
        tn_puts(s, account_set_password(pass) == 0 ? "Password changed.\n" : "Could not save the password.\n");
    memset(pass, 0, sizeof pass);
    return CMD_OK;
}

static int cmd_reboot(session_t *s, int argc, char **argv)
{
    (void)argc;
    (void)argv;
    tn_puts(s, "Rebooting ...\n");
    port_sleep_ms(500);
    port_reboot();
    return CMD_EXIT;
}

static int cmd_factory_reset(session_t *s, int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (!tn_confirm(s, "This erases the account, the saved WiFi network, known hosts and both SSH keys\n(your SSH client will warn that this device's host key changed)."))
        return CMD_OK;
    tn_puts(s, "Erasing and rebooting ...\n");
    port_log("factory reset requested by %s", s->user);
    port_sleep_ms(500);
    port_kv_wipe();
    port_reboot();
    return CMD_EXIT;
}

static int cmd_exit(session_t *s, int argc, char **argv)
{
    (void)s;
    (void)argc;
    (void)argv;
    return CMD_EXIT;
}

static const struct {
    const char *name;
    int (*fn)(session_t *, int, char **);
} commands[] = {
    { "help", cmd_help },     { "?", cmd_help },         { "wifi", cmd_wifi },
    { "ssh", cmd_ssh },       { "sshkey", cmd_sshkey },  { "hosts", cmd_hosts },
    { "status", cmd_status }, { "passwd", cmd_passwd },  { "reboot", cmd_reboot },
    { "factory-reset", cmd_factory_reset },              { "exit", cmd_exit },
    { "logout", cmd_exit },   { "quit", cmd_exit },
};

static int run_line(session_t *s, char *line)
{
    char *argv[8];
    int argc = 0;
    for (char *tok = strtok(line, " \t"); tok && argc < 8; tok = strtok(NULL, " \t"))
        argv[argc++] = tok;
    if (argc == 0)
        return CMD_OK;
    for (size_t i = 0; i < sizeof commands / sizeof commands[0]; i++)
        if (strcmp(argv[0], commands[i].name) == 0)
            return commands[i].fn(s, argc, argv);
    tn_printf(s, "%s: unknown command - type 'help'\n", argv[0]);
    return CMD_OK;
}

void session_main(session_t *s)
{
    char id[5], prompt[64], line[LINE_MAX_];
    net_status_t st;

    port_device_id(id);
    tn_printf(s, "%s %s (device %s)\n", C3_NAME, C3_VERSION, id);

    /* The SSH layer already checked the password - unless there was no
     * account to check against, in which case one has to be created now. */
    if (s->setup && first_boot_setup(s) != 0)
        return;
    port_log("session %d: %s logged in", s->id, s->user);

    netmgr_status(&st);
    tn_puts(s, "\n");
    if (st.sta_up)
        tn_printf(s, "Joined to '%s' as %s.\n", st.sta_ssid, st.sta_ip);
    else if (st.have_saved)
        tn_printf(s, "The saved network '%s' is not reachable; hosting '%s' meanwhile.\n", st.sta_ssid, st.ap_ssid);
    else
        tn_puts(s, "No WiFi network chosen yet - run 'wifi' to pick one.\n");
    tn_puts(s, "Type 'help' for the list of commands.\n\n");

    snprintf(prompt, sizeof prompt, "%s@%s-%s> ", s->user, C3_NAME, id);
    while (!s->closed) {
        int n = tn_readline(s, prompt, line, sizeof line, RL_ECHO | RL_HISTORY, C3_IDLE_TIMEOUT_S);
        if (n == TN_INTR)
            continue;
        if (n == TN_TIMEOUT)
            tn_puts(s, "\nIdle for too long, logging out.\n");
        if (n < 0)
            break;
        if (run_line(s, line) == CMD_EXIT)
            break;
    }
    if (!s->closed)
        tn_puts(s, "Goodbye.\n");
}
