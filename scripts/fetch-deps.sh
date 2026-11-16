#!/bin/sh
# Fetch the third-party libraries (pinned release tags) into third_party/.
set -e
cd "$(dirname "$0")/../third_party" 2>/dev/null || { mkdir -p "$(dirname "$0")/../third_party"; cd "$(dirname "$0")/../third_party"; }
[ -d wolfssl ] || git clone -q --depth 1 -b v5.9.4-stable https://github.com/wolfSSL/wolfssl
[ -d wolfssh ] || git clone -q --depth 1 -b v1.6.0-stable https://github.com/wolfSSL/wolfssh
# lwIP, for the simulator only (the firmware uses the copy inside ESP-IDF): the
# VPN tunnel's own TCP/IP stack, as on the chip
[ -d lwip ] || git clone -q --depth 1 -b STABLE-2_2_1_RELEASE https://github.com/lwip-tcpip/lwip
echo "third_party ready"
