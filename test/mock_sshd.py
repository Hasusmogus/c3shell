"""Tiny SSH server for the tests (asyncssh).

usage: mock_sshd.py PORT HOSTKEY_FILE MODE [AUTHORIZED_KEYS_FILE]
MODE: password | kbdint | pubkey
"""
import asyncio
import sys

import asyncssh

PORT, HOSTKEY, MODE = int(sys.argv[1]), sys.argv[2], sys.argv[3]
AUTH_KEYS = sys.argv[4] if len(sys.argv) > 4 else None
USER, PASSWORD, TOKEN = "tester", "pw-123456", "letmein"


class Server(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return MODE == "password"

    def validate_password(self, username, password):
        return username == USER and password == PASSWORD

    def kbdint_auth_supported(self):
        return MODE == "kbdint"

    def get_kbdint_challenge(self, username, lang, submethods):
        return "Mock login", "Enter the one-time token", "en", [("Token: ", True)]

    def validate_kbdint_response(self, username, responses):
        return username == USER and list(responses) == [TOKEN]

    def public_key_auth_supported(self):
        return MODE == "pubkey"

    def validate_public_key(self, username, key):
        mine = key.export_public_key("openssh").decode().split()[1]
        with open(AUTH_KEYS) as f:
            return username == USER and any(mine in line for line in f)


async def shell(process):
    w, h, _, _ = process.term_size
    process.stdout.write(f"mock shell term={process.term_type} size={w}x{h}\n$ ")
    while True:
        try:
            line = await process.stdin.readline()
        except asyncssh.TerminalSizeChanged as e:
            process.stdout.write(f"\nresized {e.width}x{e.height}\n$ ")
            continue
        except asyncssh.BreakReceived:
            continue
        if not line:
            break
        cmd = line.strip()
        if cmd == "exit":
            process.stdout.write("bye\n")
            break
        if cmd == "stderr":
            process.stderr.write("this went to stderr\n")
        elif cmd.startswith("flood "):
            n = int(cmd.split()[1])
            for i in range(n):
                process.stdout.write(f"line {i:06d} " + "x" * 60 + "\n")
            process.stdout.write("flood done\n")
        elif cmd:
            process.stdout.write(f"echo: {cmd}\n")
        process.stdout.write("$ ")
    process.exit(0)


async def main():
    await asyncssh.create_server(Server, "127.0.0.1", PORT, server_host_keys=[HOSTKEY], process_factory=shell)
    print("mock sshd ready", flush=True)
    await asyncio.Event().wait()


asyncio.run(main())
