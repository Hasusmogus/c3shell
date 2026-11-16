#!/bin/sh
# Fetch the two third-party libraries (pinned release tags) into third_party/.
set -e
cd "$(dirname "$0")/../third_party" 2>/dev/null || { mkdir -p "$(dirname "$0")/../third_party"; cd "$(dirname "$0")/../third_party"; }
[ -d wolfssl ] || git clone -q --depth 1 -b v5.9.4-stable https://github.com/wolfSSL/wolfssl
[ -d wolfssh ] || git clone -q --depth 1 -b v1.6.0-stable https://github.com/wolfSSL/wolfssh
echo "third_party ready"
