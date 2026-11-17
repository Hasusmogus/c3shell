# Host-side targets. The firmware itself is built with PlatformIO (see README).
#
#   make sim        build the virtual ESP32-C3      -> build-sim/c3shell-sim
#   make run        build and start it (ssh -p 2222 localhost)
#   make run-fresh  same, but as a factory-new device (first-boot setup)
#   make test       automated end-to-end test against the simulator
#   make test-vpn   just the OpenVPN part (real openvpn server in a network namespace)
#   make firmware   compile the real firmware (no flashing)
#   make flash      compile, flash the board (first /dev/ttyACM*, or PORT=...), and start it
#   make monitor    watch the board's serial log (shows the IP address it got)

WOLFSSL := third_party/wolfssl
WOLFSSH := third_party/wolfssh
LWIP    := third_party/lwip
B       := build-sim
PIO     ?= $(HOME)/esp/pio-venv/bin/pio
PORT    ?= $(firstword $(wildcard /dev/ttyACM*))
ESPTOOL ?= $(HOME)/.platformio/packages/tool-esptool/esptool

CFLAGS  ?= -O1 -g
CFLAGS  += -std=gnu11 -Wall -Wextra -pthread -DWOLFSSL_USER_SETTINGS \
           -Iconfig -Imain -I$(WOLFSSL) -I$(WOLFSSH)
ifdef ASAN
CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer
endif

WC  := aes asn coding curve25519 ed25519 ecc error fe_operations ge_operations hash hmac \
       kdf logging md5 memory pwdbased random rsa sha sha256 sha512 signature sp_int wc_port \
       wc_encrypt wolfmath
TLS := internal keys ssl tls tls13 wolfio
SSH := internal io log port ssh keygen ossh misc
APP := term sshio fs vi top account netmgr server shell sshstore sshc xfer ovpn vpnif
# lwIP: the VPN tunnel's TCP/IP stack in the simulator (the chip has its own)
LWIP_SRC := $(wildcard $(LWIP)/src/core/*.c $(LWIP)/src/core/ipv4/*.c $(LWIP)/src/api/*.c) \
            $(LWIP)/contrib/ports/unix/port/sys_arch.c
LWIP_INC := -Isim -I$(LWIP)/src/include -I$(LWIP)/contrib/ports/unix/port/include

OBJS := $(APP:%=$(B)/app/%.o) $(B)/app/port_sim.o $(B)/app/vpn_proxy.o \
        $(patsubst $(LWIP)/%.c,$(B)/lwip/%.o,$(LWIP_SRC)) \
        $(WC:%=$(B)/wolfcrypt/%.o) $(TLS:%=$(B)/wolfssl/%.o) $(SSH:%=$(B)/wolfssh/%.o)

.PHONY: sim run run-fresh test test-vpn firmware flash monitor clean deps
sim: $(B)/c3shell-sim

deps: $(WOLFSSL)/README.md $(LWIP)/README
$(WOLFSSL)/README.md $(LWIP)/README:
	./scripts/fetch-deps.sh

$(B)/c3shell-sim: $(OBJS)
	@echo "  LINK $@"
	@$(CC) $(CFLAGS) -o $@ $(OBJS)

$(B)/app/%.o: main/%.c main/c3shell.h main/port.h main/config.h config/user_settings.h | deps
	@mkdir -p $(@D)
	@echo "  CC   $<"
	@$(CC) $(CFLAGS) -c -o $@ $<
$(B)/app/vpnif.o: main/vpnif.c main/vpnif.h main/c3shell.h main/port.h main/config.h sim/lwipopts.h | deps
	@mkdir -p $(@D)
	@echo "  CC   $<"
	@$(CC) $(CFLAGS) $(LWIP_INC) -c -o $@ $<
$(B)/app/vpn_proxy.o: sim/vpn_proxy.c main/c3shell.h main/port.h sim/lwipopts.h | deps
	@mkdir -p $(@D)
	@echo "  CC   $<"
	@$(CC) $(CFLAGS) $(LWIP_INC) -c -o $@ $<
$(B)/lwip/%.o: $(LWIP)/%.c sim/lwipopts.h | deps
	@mkdir -p $(@D)
	@echo "  CC   $<"
	@$(CC) $(CFLAGS) $(LWIP_INC) -Imain -w -c -o $@ $<
$(B)/app/port_sim.o: sim/port_sim.c main/c3shell.h main/port.h main/config.h
	@mkdir -p $(@D)
	@echo "  CC   $<"
	@$(CC) $(CFLAGS) -c -o $@ $<
$(B)/wolfcrypt/%.o: $(WOLFSSL)/wolfcrypt/src/%.c config/user_settings.h | deps
	@mkdir -p $(@D)
	@echo "  CC   $<"
	@$(CC) $(CFLAGS) -w -c -o $@ $<
$(B)/wolfssl/%.o: $(WOLFSSL)/src/%.c config/user_settings.h | deps
	@mkdir -p $(@D)
	@echo "  CC   $<"
	@$(CC) $(CFLAGS) -w -c -o $@ $<
$(B)/wolfssh/%.o: $(WOLFSSH)/src/%.c config/user_settings.h | deps
	@mkdir -p $(@D)
	@echo "  CC   $<"
	@$(CC) $(CFLAGS) -w -c -o $@ $<

run: sim
	./$(B)/c3shell-sim
run-fresh: sim
	./$(B)/c3shell-sim --fresh

test: sim
	uv run --quiet test/run_tests.py
	uv run --quiet test/vpn_test.py

test-vpn: sim
	uv run --quiet test/vpn_test.py

firmware:
	$(PIO) run
flash:
	$(PIO) run -t upload --upload-port $(PORT)
	@# this board stays in the ROM downloader after a flash; kick it into the firmware
	$(ESPTOOL) --port $(PORT) --after watchdog-reset chip-id
monitor:
	$(PIO) device monitor --port $(firstword $(wildcard /dev/ttyACM*))

clean:
	rm -rf $(B)
