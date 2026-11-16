# c3shell

An SSH jump shell for the ESP32-C3, written in C (ESP-IDF).

- **SSH in, SSH out.** Log in to the board with any SSH client, then
  `ssh user@host` from its shell to open a real interactive shell on another
  machine (full-screen programs, window resizing, Ctrl-C all work).
- **First boot asks you to create an account.** Nothing is preconfigured; the
  first person to connect picks the username and password.
- **Hosts its own WiFi network until it has one to join.** Connect to the
  setup network, ssh in, run `wifi`, pick your network from the list. The
  setup network then disappears and the board lives on your network.
- **Files on the device.** A small Unix-style file area with `ls`, `cd`,
  `mkdir`, `touch`, `rm`, `cp`, `mv`, `cat` and a built-in `vi`.
- **A virtual ESP32-C3** (`make run`) runs the same code on your PC so you can
  develop and test without flashing.

## Try it without hardware

    make run-fresh                # a factory-new virtual device
    ssh -p 2222 you@localhost     # in another terminal

No password is asked while the device has no account: you land in the
first-boot dialogue, then the shell. Run `wifi` and join `HomeNet` (password
`homepass123`; the simulated networks are in `sim/networks.txt`). Your session
is closed, just as it would be when the real setup network vanishes; reconnect
and this time your password is required. `ssh you@some-machine` from the
device's shell reaches real machines on your network.

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

`make test` runs the automated end-to-end suite: the real OpenSSH client on a
pseudo-terminal, scripted, walks through first boot, the WiFi selector, WiFi
loss and recovery, the wrong-password lockout, reboot, factory reset, and
outbound SSH against both a mock server and a real OpenSSH `sshd` started on a
spare local port. It needs `uv` (for the mock server's Python dependency) and
the usual `ssh`/`sshd`/`ssh-keygen` programs.

### What the simulator does and does not cover

The simulator compiles everything in `main/*.c` unchanged: SSH server, line
editor, shell, account store, network state machine, and the outbound SSH
client, with the same wolfSSH/wolfCrypt sources and the same `config/user_settings.h`
as the firmware. Session threads even get the firmware's stack size and report
how much of it they used.

Only `port.h` is implemented differently (`sim/port_sim.c` instead of
`main/esp/port_esp.c`): the radio is faked and flash storage is a directory.
So the ESP-IDF WiFi calls, NVS, and real-world radio behaviour (the setup
network changing channel while joining, weak signal) are the part that still
needs the board.

## On the board

    make firmware     # compile only
    make flash        # compile, flash over USB, start
    make monitor      # serial log

1. Power it up. It hosts a WiFi network called `c3shell-XXXX` (XXXX = last
   two bytes of its MAC), password `c3shell-setup`.
2. Join that network and `ssh you@192.168.4.1` (any username; no password yet).
   Compare the host key fingerprint your client shows with the one on the
   serial log (`make monitor`) if you want to be sure it is your board.
3. Create your account at the prompt.
4. Run `wifi`, choose your network, enter its password. The board prints the
   address it received, and the setup network shuts down a few seconds later.
5. Rejoin your normal network and `ssh you@<that address>`. The board also
   registers the DHCP hostname `c3shell-XXXX`, and prints its address on the
   serial log.

If the saved network is unreachable for 30 s (router off, password changed),
the board hosts the setup network again so you are never locked out, and keeps
retrying the saved network once a minute while nobody is logged in.

## Shell commands

    wifi                      pick a WiFi network to join (scan + select)
    wifi forget               forget the saved network, host the setup network
    ssh [user@]host [-p port] open a shell on another machine
    sshkey [new]              show (or regenerate) this device's public key
    hosts                     list remembered SSH host keys
    hosts forget <n|name>     forget one
    ls [-l] [-a] [path]       list files               cd [dir]   pwd
    mkdir [-p] dir            make a directory         rmdir dir
    touch file                create an empty file     rm [-r] [-f] path
    cat file   cp from to   mv from to                df (space left)
    vi [file]                 edit a file
    status                    network, sessions, memory
    passwd                    change your password
    reboot                    restart the device
    factory-reset             erase account, WiFi, SSH data and all files
    exit                      log out

### Files

The file area is a 1.9 MB LittleFS partition of its own (power-loss safe,
wear levelled), shown to you as `/`. Paths work as usual: relative to the
current directory, `..` to go up (never above `/`), quotes around names with
spaces. Names can be up to 63 characters, paths up to 127.

`vi` is a deliberately small vi: `h j k l`/arrows, `w b 0 ^ $ gg G`,
`Ctrl-F`/`Ctrl-B`, counts (`5j`, `3dd`, `12G`), `i a I A o O` to insert,
`x r J D dd dw d$ yy p P`, `u` (one level, pressing it again redoes),
`/text n N`, and `:w [file] :q :q! :wq :x :<line> ZZ`. It edits files up to
32 KB, held in RAM, and saves by writing a new copy and renaming it over the
old one, so a crash or power cut mid-save never leaves a half-written file.

The firmware cannot be changed from the shell. The file commands can only
name things inside the file area; the firmware, the account and the SSH keys
live in other flash partitions that no command can address. In addition the
flash driver refuses, at run time, any write to the bootloader, the partition
table or the running firmware. Re-flashing still works over USB, which needs
physical access to the board.

Outbound logins try the board's own Ed25519 key first (add the line printed
by `sshkey` to `~/.ssh/authorized_keys` on a server for password-less login),
then fall back to password or keyboard-interactive prompts. Host keys are
remembered on first connection and a changed key is refused. To hang up a
stuck outbound connection type `~.` at the start of a line; from OpenSSH type
`~~.`, because your own client swallows the first `~`.

## Security notes

- Everything between you and the board is encrypted and the board proves its
  identity with a host key generated on first boot. A factory reset makes a
  new one, so your client will warn about the change once.
- Logging in to the board is by password only. Five wrong passwords from one
  address block that address for five minutes, and a connection that has not
  logged in within a minute is dropped. That slows guessing; it does not make
  a weak password safe, and three connection slots are easy to tie up, so
  think before forwarding port 22 from the internet.
- A factory-new board lets the first visitor in without a password to create
  the account. Change `C3_AP_PASSWORD` in `main/config.h` before relying on
  it: with the default, that first visitor could be anyone in radio range.
- The account password is stored as a salted PBKDF2-SHA256 hash; the WiFi
  password, the board's SSH private keys and your files are stored in flash
  unencrypted, so anyone holding the board can read them out over USB.

## Layout

    main/            portable application code + config.h (tunables)
                     fs.c = file commands and path sandbox, vi.c = the editor
    main/esp/        ESP32-C3 backend (WiFi, NVS, app_main)
    sim/             Linux backend: the virtual device
    config/          wolfCrypt/wolfSSH build settings shared by both builds
    components/      ESP-IDF wrappers for the two libraries
    third_party/     wolfSSL + wolfSSH checkouts (scripts/fetch-deps.sh)
    test/            end-to-end tests

## License

Copyright (C) 2026 Hasusmogus

c3shell is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. See [LICENSE](LICENSE).

The firmware links wolfSSL and wolfSSH, which are themselves GPL-3.0-or-later,
so anyone who distributes a built firmware image must also offer its source
under the same terms.
