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
            "  scp [-r] [-P port] from... to   copy files to/from another machine,\n"
            "                            e.g. scp notes.txt me@pc:  or  scp me@pc:work.ovpn .\n"
            "  vpn up [file.ovpn]        connect to an OpenVPN server (default /vpn.ovpn)\n"
            "  vpn [status] | vpn down   show the tunnel / disconnect\n"
            "  sshkey [new]              show (or regenerate) this device's public key\n"
            "  hosts                     list remembered SSH host keys\n"
            "  hosts forget <n|name>     forget one\n"
            "  ls [-l] [-a] [path]       list files            cd [dir]   pwd\n"
            "  mkdir [-p] dir            make a directory      rmdir dir\n"
            "  touch file                create an empty file  rm [-r] [-f] path\n"
            "  cat file   cp from to   mv from to             df (space left)\n"
            "  vi [file]                 edit a file (:wq saves and quits, :q! discards)\n"
            "  status                    network, sessions, memory\n"
            "  fetch [--plain]           system summary with a logo, fastfetch-style\n"
            "  top [-d secs]             live view of tasks, CPU, memory, sessions (q quits)\n"
            "  passwd                    change your password\n"
            "  reboot                    restart the device\n"
            "  factory-reset             erase account, WiFi, SSH data and all files\n"
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
    vpn_status_t vs;
    vpn_status(&vs);
    if (vs.running)
        tn_printf(s, "VPN:           %s%s%s\n", vs.state, vs.ip[0] ? ", address " : "", vs.ip);
    if (port_free_heap() >= 0)
        tn_printf(s, "Memory:        %ld bytes free, session stack headroom %ld bytes\n", port_free_heap(),
                  port_stack_headroom());
    return CMD_OK;
}

/* fastfetch-style summary: a chip on the left, facts on the right */
static int cmd_fetch(session_t *s, int argc, char **argv)
{
    static const char *const logo[] = {   /* the Espressif mark, in half blocks */
        "      ▄▄▄ ▀▀██▄▄    ",
        "  █ ▄██████▄▄▀▀██▄  ",
        " █ ▄▄▄▄ ▀▀████▄ ▀██ ",
        "█ ████████▄ ▀███▄▀██",
        "█ ███▄ ▀▀███▄ ███▄ █",
        "█ ▀█████▄ ▀███ ███  ",
        "▀▄    ▀███ ▀██▄ ███ ",
        " ▀▄ ██  ███ ███ ▀▀  ",
        "   ▀▄   ██▀ ██▀ ▄▄  ",
        "     ▀▀▄▄▄▄▄▄▄▄▀▀   ",
    };
    enum { NLOGO = sizeof logo / sizeof logo[0], NINFO = 16 };
    bool color = !(argc > 1 && strcmp(argv[1], "--plain") == 0);
    const char *c1 = color ? "\033[1;31m" : "", *c0 = color ? "\033[0m" : "";
    char info[NINFO][112], id[5];
    int n = 0;
    net_status_t st;
    vpn_status_t vs;
    port_sysinfo_t si;
    uint32_t up = port_uptime_s();
    long total, used, heap = port_free_heap();

    if (argc > 1 && color) {
        tn_puts(s, "usage: fetch [--plain]\n");
        return CMD_OK;
    }
    port_device_id(id);
    port_sysinfo(&si);
    netmgr_status(&st);
    vpn_status(&vs);

#define ADD(label, ...)                                                                       \
    do {                                                                                      \
        int k_ = snprintf(info[n], sizeof info[n], "%s%-9s%s ", c1, label, c0);               \
        snprintf(info[n] + k_, sizeof info[n] - (size_t)k_, __VA_ARGS__);                     \
        n++;                                                                                  \
    } while (0)

    snprintf(info[n++], sizeof info[0], "%s%s%s@%s%s-%s%s", c1, s->user, c0, c1, C3_NAME, id, c0);
    snprintf(info[n++], sizeof info[0], "%.*s", (int)(strlen(s->user) + strlen(C3_NAME) + 6),
             "----------------------------------------------------------------");
    ADD("OS", "%s %s", C3_NAME, C3_VERSION);
    ADD("Host", "%s", si.host);
    ADD("CPU", "%s", si.cpu);
    if (up >= 86400)
        ADD("Uptime", "%ud %uh %um", (unsigned)(up / 86400), (unsigned)(up / 3600 % 24), (unsigned)(up / 60 % 60));
    else if (up >= 3600)
        ADD("Uptime", "%uh %um", (unsigned)(up / 3600), (unsigned)(up / 60 % 60));
    else
        ADD("Uptime", "%um %us", (unsigned)(up / 60), (unsigned)(up % 60));
    ADD("Shell", "%s sh", C3_NAME);
    ADD("Terminal", "%ux%u, from %s", (unsigned)s->cols, (unsigned)s->rows, s->peer);
    if (heap >= 0 && si.heap_total > 0)
        ADD("Memory", "%ld KB / %ld KB (%ld%%)", (si.heap_total - heap) / 1024, si.heap_total / 1024,
            (si.heap_total - heap) * 100 / si.heap_total);
    else if (heap >= 0)
        ADD("Memory", "%ld KB free", heap / 1024);
    if (si.flash_kb > 0)
        ADD("Flash", "%ld MB", si.flash_kb / 1024);
    if (port_fs_usage(&total, &used) == 0 && total > 0)
        ADD("Disk (/)", "%ld KB / %ld KB (%ld%%)", used / 1024, total / 1024, used * 100 / total);
    if (st.sta_up)
        ADD("WiFi", "%s (%s, %d dBm)", st.sta_ssid, st.sta_ip, st.rssi);
    else if (st.ap_up)
        ADD("WiFi", "hosting %s (%s)", st.ap_ssid, st.ap_ip);
    if (vs.running)
        ADD("VPN", "%s%s%s", vs.state, vs.ip[0] ? ", " : "", vs.ip);
    ADD("Sessions", "%d of %d", server_session_count(), C3_MAX_SESSIONS);
#undef ADD

    tn_puts(s, "\n");
    for (int i = 0; i < (n > NLOGO ? n : NLOGO) + (color ? 2 : 0); i++) {
        const char *art = i < NLOGO ? logo[i] : "                    ";
        tn_printf(s, "%s%s%s  ", c1, art, c0);
        if (i < n) {
            tn_puts(s, info[i]);
        } else if (color && i == n + 1) {      /* palette strip, as fastfetch/neofetch do */
            for (int c = 0; c < 8; c++)
                tn_printf(s, "\033[4%dm   ", c);
            tn_puts(s, "\033[0m");
        }
        tn_puts(s, "\n");
    }
    tn_puts(s, "\n");
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

static void fmt_bytes(char *out, size_t cap, uint64_t n)
{
    if (n < 10 * 1024)
        snprintf(out, cap, "%u B", (unsigned)n);
    else if (n < 10 * 1024 * 1024)
        snprintf(out, cap, "%u KB", (unsigned)(n / 1024));
    else
        snprintf(out, cap, "%u MB", (unsigned)(n / (1024 * 1024)));
}

static void vpn_show(session_t *s)
{
    vpn_status_t st;
    char rx[16], tx[16];
    vpn_status(&st);
    if (!st.running && strcmp(st.state, "failed") != 0) {
        tn_puts(s, "VPN: off\n");
        return;
    }
    tn_printf(s, "VPN: %s for %us (%s)\n", st.state, (unsigned)st.since_s, st.file);
    if (st.server[0])
        tn_printf(s, "  server   %s\n", st.server);
    if (st.ip[0]) {
        fmt_bytes(rx, sizeof rx, st.rx);
        fmt_bytes(tx, sizeof tx, st.tx);
        tn_printf(s, "  address  %s, %d pushed route%s%s\n  traffic  %s in, %s out\n", st.ip, st.routes,
                  st.routes == 1 ? "" : "s", st.redirect ? " + all other traffic" : "", rx, tx);
    }
    if (st.error[0] && strcmp(st.state, "connected") != 0)
        tn_printf(s, "  %s     %s\n", strcmp(st.state, "failed") == 0 ? "error" : "last ", st.error);
}

static int cmd_vpn(session_t *s, int argc, char **argv)
{
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "status") == 0)) {
        vpn_show(s);
        return CMD_OK;
    }
    if (argc == 2 && strcmp(argv[1], "down") == 0) {
        vpn_status_t st;
        vpn_status(&st);
        if (!st.running) {
            tn_puts(s, "The VPN is not running.\n");
            return CMD_OK;
        }
        tn_puts(s, "Disconnecting ...\n");
        vpn_stop();
        tn_puts(s, "VPN off. Connections through it are closed.\n");
        return CMD_OK;
    }
    if ((argc == 2 || argc == 3) && strcmp(argv[1], "up") == 0) {
        if (vpn_start(s, argc == 3 ? argv[2] : "/vpn.ovpn") != 0)
            return s->closed ? CMD_EXIT : CMD_OK;
        /* follow the first attempt, so mistakes show up right here */
        vpn_status_t st;
        char last[24] = "";
        for (int i = 0; i < 150; i++) {    /* 30 s */
            vpn_status(&st);
            if (strcmp(st.state, last) != 0) {
                snprintf(last, sizeof last, "%s", st.state);
                if (strcmp(st.state, "connecting") == 0 && st.server[0])
                    tn_printf(s, "Connecting to %s ...\n", st.server);
                else if (strcmp(st.state, "configuring") == 0)
                    tn_puts(s, "Logged in, getting the network settings ...\n");
            }
            if (strcmp(st.state, "connected") == 0) {
                tn_printf(s, "VPN up: this device is %s on the remote network. ssh and scp to its\n"
                             "addresses now go through the tunnel. It reconnects by itself; 'vpn down' ends it.\n",
                          st.ip);
                return CMD_OK;
            }
            if (strcmp(st.state, "failed") == 0 || strcmp(st.state, "reconnecting") == 0 || !st.running) {
                tn_printf(s, "VPN: %s\n", st.error[0] ? st.error : "stopped");
                if (strcmp(st.state, "reconnecting") == 0)
                    tn_puts(s, "Still trying in the background ('vpn' shows progress, 'vpn down' stops it).\n");
                return CMD_OK;
            }
            if (tn_input_ready(s) && tn_getc(s, 0) == 3) {      /* Ctrl-C: stop watching */
                tn_puts(s, "^C\nStill connecting in the background ('vpn' shows progress).\n");
                return CMD_OK;
            }
            port_sleep_ms(200);
        }
        tn_puts(s, "Still connecting in the background ('vpn' shows progress).\n");
        return CMD_OK;
    }
    tn_puts(s, "usage: vpn [status] | vpn up [file.ovpn] | vpn down\n");
    return CMD_OK;
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
    if (!tn_confirm(s, "This erases the account, the saved WiFi network, known hosts, both SSH keys and\nevery file (your SSH client will warn that this device's host key changed)."))
        return CMD_OK;
    tn_puts(s, "Erasing and rebooting ...\n");
    port_log("factory reset requested by %s", s->user);
    port_sleep_ms(500);
    port_fs_wipe();
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
    { "scp", cmd_scp },       { "vpn", cmd_vpn },
    { "status", cmd_status }, { "fetch", cmd_fetch },    { "neofetch", cmd_fetch },
    { "top", cmd_top },       { "htop", cmd_top },
    { "passwd", cmd_passwd },  { "reboot", cmd_reboot },
    { "factory-reset", cmd_factory_reset },              { "exit", cmd_exit },
    { "ls", cmd_ls },         { "cd", cmd_cd },          { "pwd", cmd_pwd },
    { "mkdir", cmd_mkdir },   { "rmdir", cmd_rmdir },    { "rm", cmd_rm },
    { "touch", cmd_touch },   { "cat", cmd_cat },        { "cp", cmd_cp },
    { "mv", cmd_mv },         { "df", cmd_df },          { "vi", cmd_vi },
    { "logout", cmd_exit },   { "quit", cmd_exit },
};

/* Split a command line into words. "double" or 'single' quotes keep spaces
 * inside one word. Splits in place. */
static int split(char *line, char **argv, int max)
{
    int argc = 0;
    char *r = line, *w = line;
    while (*r) {
        while (*r == ' ' || *r == '\t')
            r++;
        if (!*r)
            break;
        if (argc == max)
            return -1;
        argv[argc++] = w;
        char q = 0;
        while (*r && (q || (*r != ' ' && *r != '\t'))) {
            if (!q && (*r == '"' || *r == '\'')) {
                q = *r++;
            } else if (q && *r == q) {
                q = 0;
                r++;
            } else {
                *w++ = *r++;
            }
        }
        if (q)
            return -2;
        if (*r)
            r++;
        *w++ = 0;
    }
    return argc;
}

static int run_line(session_t *s, char *line)
{
    char *argv[16];
    int argc = split(line, argv, 16);
    if (argc == -1) {
        tn_puts(s, "too many arguments\n");
        return CMD_OK;
    }
    if (argc == -2) {
        tn_puts(s, "missing closing quote\n");
        return CMD_OK;
    }
    if (argc == 0)
        return CMD_OK;
    for (size_t i = 0; i < sizeof commands / sizeof commands[0]; i++)
        if (strcmp(argv[0], commands[i].name) == 0) {
            snprintf(s->doing, sizeof s->doing, "%s", argv[0]);
            int r = commands[i].fn(s, argc, argv);
            s->doing[0] = 0;
            return r;
        }
    tn_printf(s, "%s: unknown command - type 'help'\n", argv[0]);
    return CMD_OK;
}

void session_main(session_t *s)
{
    char id[5], prompt[C3_PATH_MAX + 64], line[LINE_MAX_];
    net_status_t st;

    port_device_id(id);
    tn_printf(s, "%s %s (device %s)\n", C3_NAME, C3_VERSION, id);

    /* The SSH layer already checked the password - unless there was no
     * account to check against, in which case one has to be created now. */
    snprintf(s->doing, sizeof s->doing, "%s", s->setup ? "setup" : "");
    if (s->setup && first_boot_setup(s) != 0)
        return;
    s->doing[0] = 0;
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

    snprintf(s->cwd, sizeof s->cwd, "/");
    while (!s->closed) {
        snprintf(prompt, sizeof prompt, "%s@%s-%s:%s> ", s->user, C3_NAME, id, s->cwd);
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
