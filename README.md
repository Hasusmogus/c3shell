# c3shell

A telnet-accessible jump shell for the ESP32-C3, written in C (ESP-IDF).

- **Telnet in, SSH out.** Log in to the board with any telnet client, then
  `ssh user@host` to open a real interactive shell on another machine
  (full-screen programs, window resizing, Ctrl-C all work).
- **First boot asks you to create an account.** Nothing is preconfigured; the
  first person to connect picks the username and password.
- **Hosts its own WiFi network until it has one to join.** Connect to the
  setup network, telnet in, run `wifi`, pick your network from the list. The
  setup network then disappears and the board lives on your network.
- **A virtual ESP32-C3** (`make run`) runs the same code on your PC so you can
  develop and test without flashing.

## Try it without hardware

    make run-fresh            # a factory-new virtual device
    telnet localhost 2323     # in another terminal

You get the first-boot account prompt, then the shell. Run `wifi` and join
`HomeNet` (password `homepass123`; the simulated networks are in
`sim/networks.txt`). Your telnet session is closed, just as it would be when
the real setup network vanishes; reconnect and you get a login prompt.
`ssh you@some-machine` from there reaches real machines on your network.

`make run` starts it again with its saved state (`sim/state/`), like a power
cycle. While it runs you can type into the simulator's own terminal to play
the outside world:

| type            | effect                                                   |
|-----------------|----------------------------------------------------------|
| `nets`          | list the simulated networks and their passwords          |
| `down [ssid]`   | network goes out of range (default: the joined one)      |
| `up [ssid]`     | it comes back                                            |
| `status`        | radio state and session count                            |
| `reboot`        | power-cycle the virtual device                           |

`make test` runs the automated end-to-end suite: a scripted telnet client
walks through first boot, the WiFi selector, WiFi loss and recovery, reboot,
factory reset, and SSH against both a mock server and a real OpenSSH `sshd`
started on a spare local port. It needs `uv` (for the mock server's Python
dependency) and the usual `telnet`/`sshd`/`ssh-keygen` programs.

### What the simulator does and does not cover

The simulator compiles everything in `main/*.c` unchanged: telnet protocol,
line editor, shell, account store, network state machine, and the SSH client
with the same wolfSSH/wolfCrypt sources and the same `config/user_settings.h`
as the firmware. Session threads even get the firmware's stack size and report
how much of it they used.

Only `port.h` is implemented differently (`sim/port_sim.c` instead of
`main/esp/port_esp.c`): the radio is faked and flash storage is a directory.
So the ESP-IDF WiFi calls, NVS, and real-world radio behaviour (the setup
network changing channel while joining, weak signal) are the part that still
needs the board.

## On the board

    make firmware     # compile only
    make flash        # compile, flash over /dev/ttyACM0, start
    make monitor      # serial log

1. Power it up. It hosts a WiFi network called `c3shell-XXXX` (XXXX = last
   two bytes of its MAC), password `c3shell-setup`.
2. Join that network and `telnet 192.168.4.1`.
3. Create your account at the prompt.
4. Run `wifi`, choose your network, enter its password. The board prints the
   address it received, and the setup network shuts down a few seconds later.
5. Rejoin your normal network and `telnet <that address>`. The board also
   registers the DHCP hostname `c3shell-XXXX`, and prints its address on the
   serial log.

If the saved network is unreachable for 30 s (router off, password changed),
the board hosts the setup network again so you are never locked out, and keeps
retrying the saved network once a minute while nobody is logged in.

## Shell commands

    wifi                      pick a WiFi network to join (scan + select)
    wifi forget               forget the saved network, host the setup network
    ssh [user@]host [-p port] open a shell on another machine  (~. hangs up)
    sshkey [new]              show (or regenerate) this device's public key
    hosts                     list remembered SSH host keys
    hosts forget <n|name>     forget one
    status                    network, sessions, memory
    passwd                    change your password
    reboot                    restart the device
    factory-reset             erase account, WiFi and SSH data
    exit                      log out

SSH logins try the board's own Ed25519 key first (add the line printed by
`sshkey` to `~/.ssh/authorized_keys` on a server for password-less login),
then fall back to password or keyboard-interactive prompts. Host keys are
remembered on first connection and a changed key is refused.

## Security notes

- Telnet is not encrypted. Your c3shell password, and any SSH password you
  type through it, cross the WiFi link protected only by the WiFi encryption.
  Use it on networks you trust, and prefer `sshkey` logins so no server
  password is typed at all.
- Change `C3_AP_PASSWORD` in `main/config.h` before relying on it: with the
  default, anyone in radio range of a factory-fresh board can create the
  account.
- The account password is stored as a salted PBKDF2-SHA256 hash; the WiFi
  password and the board's SSH private key are stored in flash unencrypted.

## Layout

    main/            portable application code + config.h (tunables)
    main/esp/        ESP32-C3 backend (WiFi, NVS, app_main)
    sim/             Linux backend: the virtual device
    config/          wolfCrypt/wolfSSH build settings shared by both builds
    components/      ESP-IDF wrappers for the two libraries
    third_party/     wolfSSL + wolfSSH checkouts (scripts/fetch-deps.sh)
    test/            end-to-end tests

wolfSSL and wolfSSH are GPL-3.0 licensed, which matters if you distribute
firmware built from this.
