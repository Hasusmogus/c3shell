# Host-side targets. The firmware itself is built with PlatformIO (see README).
#
#   make sim        build the virtual ESP32-C3      -> build-sim/c3shell-sim
#   make run        build and start it (telnet localhost 2323)
#   make run-fresh  same, but as a factory-new device (first-boot setup)
#   make test       automated end-to-end test against the simulator
#   make firmware   compile the real firmware (no flashing)
#   make flash      compile, flash the board on /dev/ttyACM0, and start it
#   make monitor    watch the board's serial log (shows the IP address it got)

WOLFSSL := third_party/wolfssl
WOLFSSH := third_party/wolfssh
B       := build-sim
PIO     ?= $(HOME)/esp/pio-venv/bin/pio
ESPTOOL ?= $(HOME)/.platformio/packages/tool-esptool/esptool

CFLAGS  ?= -O1 -g
CFLAGS  += -std=gnu11 -Wall -Wextra -pthread -DWOLFSSL_USER_SETTINGS \
           -Iconfig -Imain -I$(WOLFSSL) -I$(WOLFSSH)
ifdef ASAN
CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer
endif

WC  := aes asn coding curve25519 ed25519 ecc error fe_operations ge_operations hash hmac \
       logging memory pwdbased random rsa sha sha256 sha512 signature sp_int wc_port \
       wc_encrypt wolfmath
SSH := internal io log port ssh keygen ossh misc
APP := telnet account netmgr server shell sshstore sshc

OBJS := $(APP:%=$(B)/app/%.o) $(B)/app/port_sim.o \
        $(WC:%=$(B)/wolfcrypt/%.o) $(SSH:%=$(B)/wolfssh/%.o)

.PHONY: sim run run-fresh test firmware flash monitor clean deps
sim: $(B)/c3shell-sim

deps: $(WOLFSSL)/README.md
$(WOLFSSL)/README.md:
	./scripts/fetch-deps.sh

$(B)/c3shell-sim: $(OBJS)
	@echo "  LINK $@"
	@$(CC) $(CFLAGS) -o $@ $(OBJS)

$(B)/app/%.o: main/%.c main/c3shell.h main/port.h main/config.h config/user_settings.h | deps
	@mkdir -p $(@D)
	@echo "  CC   $<"
	@$(CC) $(CFLAGS) -c -o $@ $<
$(B)/app/port_sim.o: sim/port_sim.c main/c3shell.h main/port.h main/config.h
	@mkdir -p $(@D)
	@echo "  CC   $<"
	@$(CC) $(CFLAGS) -c -o $@ $<
$(B)/wolfcrypt/%.o: $(WOLFSSL)/wolfcrypt/src/%.c config/user_settings.h | deps
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

firmware:
	$(PIO) run
flash:
	$(PIO) run -t upload
	@# this board stays in the ROM downloader after a flash; kick it into the firmware
	$(ESPTOOL) --port /dev/ttyACM0 --after watchdog-reset chip-id
monitor:
	$(PIO) device monitor

clean:
	rm -rf $(B)
