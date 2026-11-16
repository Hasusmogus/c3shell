# /// script
# requires-python = ">=3.10"
# dependencies = ["asyncssh"]
# ///
"""End-to-end test of c3shell against the simulator (build-sim/c3shell-sim).

Drives the device exactly like a person would: a telnet client that types.
Covers first-boot account creation, login, the WiFi selector and the
disappearing setup network, fallback when WiFi is lost, persistence across a
reboot, and SSH (password, keyboard-interactive, public key, host-key
pinning) against a mock server and a real OpenSSH sshd.

Run with:  make test
"""
import getpass
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIM = os.path.join(ROOT, "build-sim", "c3shell-sim")
IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
NAWS, BINARY, ECHO, SGA = 31, 0, 1, 3


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Telnet:
    """Just enough of a telnet client: answers negotiation, reports a window size."""

    def __init__(self, port, cols=100, rows=30):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.cols, self.rows = cols, rows
        self.text = b""
        self.raw = b""
        self.eof = False

    def _naws(self):
        self.sock.sendall(bytes([IAC, SB, NAWS, self.cols >> 8, self.cols & 255, self.rows >> 8, self.rows & 255, IAC, SE]))

    def resize(self, cols, rows):
        self.cols, self.rows = cols, rows
        self._naws()

    def _pump(self, timeout):
        self.sock.settimeout(timeout)
        try:
            data = self.sock.recv(65536)
        except socket.timeout:
            return
        except OSError:
            data = b""
        if not data:
            self.eof = True
            return
        self.raw += data
        while self.raw:
            i = self.raw.find(bytes([IAC]))
            if i < 0:
                self.text += self.raw
                self.raw = b""
                break
            self.text += self.raw[:i]
            self.raw = self.raw[i:]
            if len(self.raw) < 2:
                break
            cmd = self.raw[1]
            if cmd == IAC:
                self.text += b"\xff"
                self.raw = self.raw[2:]
            elif cmd in (DO, DONT, WILL, WONT):
                if len(self.raw) < 3:
                    break
                opt = self.raw[2]
                self.raw = self.raw[3:]
                if cmd == DO and opt == NAWS:
                    self.sock.sendall(bytes([IAC, WILL, NAWS]))
                    self._naws()
                elif cmd == DO and opt in (BINARY, SGA):
                    self.sock.sendall(bytes([IAC, WILL, opt]))
                elif cmd == DO:
                    self.sock.sendall(bytes([IAC, WONT, opt]))
                elif cmd == WILL and opt in (BINARY, SGA, ECHO):
                    self.sock.sendall(bytes([IAC, DO, opt]))
                elif cmd == WILL:
                    self.sock.sendall(bytes([IAC, DONT, opt]))
            else:
                self.raw = self.raw[2:]

    def expect(self, pattern, timeout=15):
        """Wait for a regex; returns everything up to and including the match."""
        rx = re.compile(pattern.encode() if isinstance(pattern, str) else pattern, re.S)
        end = time.time() + timeout
        while True:
            m = rx.search(self.text)
            if m:
                out = self.text[: m.end()]
                self.text = self.text[m.end():]
                return out.decode(errors="replace")
            if self.eof or time.time() > end:
                why = "connection closed" if self.eof else "timeout"
                raise AssertionError(f"{why} waiting for {pattern!r}; got:\n{self.text.decode(errors='replace')}")
            self._pump(0.2)

    def expect_closed(self, timeout=15):
        end = time.time() + timeout
        while not self.eof:
            if time.time() > end:
                raise AssertionError("connection was not closed by the device")
            self._pump(0.2)
        out, self.text = self.text.decode(errors="replace"), b""
        return out

    def send(self, s):
        self.sock.sendall(s.encode() if isinstance(s, str) else s)

    def line(self, s):
        self.send(s + "\r")

    def close(self):
        self.sock.close()


class Sim:
    def __init__(self, state, port, extra=()):
        self.port = port
        self.log = []
        self.proc = subprocess.Popen(
            [os.environ.get("C3SIM", SIM), "--fast", "--port", str(port), "--state", state, "--networks", os.path.join(ROOT, "sim", "networks.txt"), *extra],
            cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        threading.Thread(target=self._reader, daemon=True).start()
        self.wait_log("telnet: listening")

    def _reader(self):
        for line in self.proc.stdout:
            self.log.append(line.rstrip())

    def wait_log(self, needle, timeout=20, start=0):
        end = time.time() + timeout
        while time.time() < end:
            for i in range(start, len(self.log)):
                if needle in self.log[i]:
                    return i
            time.sleep(0.05)
        raise AssertionError(f"simulator never logged {needle!r}; log:\n" + "\n".join(self.log[-30:]))

    def console(self, cmd):
        self.proc.stdin.write(cmd + "\n")
        self.proc.stdin.flush()

    def telnet(self, **kw):
        end = time.time() + 10
        while True:
            try:
                return Telnet(self.port, **kw)
            except OSError:
                if time.time() > end:
                    raise
                time.sleep(0.1)

    def stop(self):
        self.proc.kill()
        self.proc.wait()


def login(sim, user="admin", password="secret-123", **kw):
    t = sim.telnet(**kw)
    t.expect("login: ")
    t.line(user)
    t.expect("Password: ")
    t.line(password)
    t.expect(PROMPT)
    return t


PROMPT = r"admin@c3shell-51M0> "
results = []


def step(name):
    def deco(fn):
        results.append((name, fn))
        return fn
    return deco


# --------------------------------------------------------------------------

@step("first boot: hosts setup network, asks to create an account")
def t_first_boot(c):
    sim = c["sim"]
    sim.wait_log("hosting 'c3shell-51M0'")
    t = sim.telnet()
    t.expect("First-time setup")
    t.expect("New username: ")
    t.line("bad name!")
    t.expect("Use 1-31 characters")
    t.expect("New username: ")
    t.line("admin")
    t.expect("New password: ")
    t.line("abc")
    t.expect("Too short")
    t.expect("New password: ")
    t.line("secret-123")
    t.expect("Retype new password: ")
    t.line("different")
    t.expect("do not match")
    t.expect("New password: ")
    t.line("secret-123")
    out = t.expect("Retype new password: ")
    assert "secret-123" not in out, "password was echoed"
    t.line("secret-123")
    t.expect("Account 'admin' created")
    t.expect("No WiFi network chosen yet")
    t.expect(PROMPT)
    c["t"] = t


@step("a second connection now gets a login prompt, not the setup wizard")
def t_second_conn(c):
    t2 = c["sim"].telnet()
    t2.expect("login: ")
    t2.line("admin")
    t2.expect("Password: ")
    t2.line("wrong")
    t2.expect("Login incorrect", timeout=10)
    t2.expect("login: ")
    t2.line("admin")
    t2.expect("Password: ")
    t2.line("secret-123")
    t2.expect(PROMPT)
    t3 = c["sim"].telnet()
    t3.expect("too many sessions")
    t3.close()
    t2.line("exit")
    t2.expect("Goodbye")
    t2.expect_closed()


@step("shell basics: help, status, unknown command, line editing, history")
def t_shell(c):
    t = c["t"]
    t.line("help")
    t.expect("wifi forget")
    t.expect(PROMPT)
    t.line("status")
    out = t.expect(PROMPT)
    assert "Setup network: 'c3shell-51M0' is up" in out and "no network chosen" in out, out
    t.line("frobnicate")
    t.expect("unknown command")
    t.expect(PROMPT)
    t.send("statuz\x7fs\r")                # backspace
    t.expect("Sessions:")
    t.expect(PROMPT)
    t.send("garbage\x15")                  # Ctrl-U
    t.send("\x1b[A\r")                     # up-arrow recalls "status"
    t.expect("Sessions:")
    t.expect(PROMPT)
    t.send("half a line\x03")              # Ctrl-C
    t.expect(PROMPT)


@step("wifi selector: scan, wrong password, cancel")
def t_wifi_fail(c):
    t = c["t"]
    t.line("wifi")
    out = t.expect("q = cancel: ")
    rows = re.findall(r"^\s+(\d+)\s+\[[# ]+\]\s+(-\d+) dBm\s+(\w+)\s+(.+?)\s*$", out, re.M)
    names = [r[3] for r in rows]
    assert names == ["HomeNet", "Workshop-2.4", "CoffeeShop Free", "Neighbour_5F"], out
    assert rows[2][2] == "open" and rows[0][2] == "password", out
    c["home_idx"] = names.index("HomeNet") + 1
    t.line("9")
    t.expect("Not one of the listed numbers")
    t.expect("q = cancel: ")
    t.line(str(c["home_idx"]))
    t.expect("Password for 'HomeNet': ")
    t.line("not-the-password")
    t.expect("Could not join 'HomeNet': wrong password")
    t.expect(PROMPT)
    t.line("status")
    out = t.expect(PROMPT)
    assert "Setup network: 'c3shell-51M0' is up" in out, "setup network must survive a failed join"
    t.line("wifi")
    t.expect("q = cancel: ")
    t.line("q")
    t.expect(PROMPT)


@step("wifi selector: joining a network makes the setup network disappear")
def t_wifi_join(c):
    sim, t = c["sim"], c["t"]
    t.line("wifi")
    t.expect("q = cancel: ")
    t.line(str(c["home_idx"]))
    t.expect("Password for 'HomeNet': ")
    t.line("homepass123")
    t.expect("Joined 'HomeNet'. This device is now at 192.168.0.77")
    t.expect("setup network 'c3shell-51M0' is shutting down")
    t.expect("telnet 192.168.0.77")
    t.expect_closed()                      # we were on the setup network: it is gone
    sim.wait_log("stopped hosting 'c3shell-51M0'")
    t = login(sim)
    t.line("status")
    out = t.expect(PROMPT)
    assert "joined 'HomeNet'" in out and "Setup network: off" in out, out
    c["t"] = t


@step("ssh (mock server): host key prompt, wrong then right password, window size, resize")
def t_ssh_password(c):
    t = c["t"]
    port = c["mock"]("password")
    t.line(f"ssh tester@127.0.0.1 -p {port}")
    t.expect("authenticity of host '\\[127.0.0.1\\]:%d' can't be established" % port)
    t.expect("ssh-ed25519 key fingerprint is SHA256:")
    t.expect(r"\(yes/no\)\? ")
    t.line("no")
    t.expect("Host key verification failed")
    t.expect(PROMPT)

    t.line(f"ssh tester@127.0.0.1 -p {port}")
    t.expect(r"\(yes/no\)\? ")
    t.line("yes")
    t.expect("added to the list of known hosts")
    t.expect("tester@127.0.0.1's password: ")
    t.line("nope")
    t.expect("Permission denied, please try again")
    t.expect("tester@127.0.0.1's password: ")
    t.line("pw-123456")
    t.expect(r"mock shell term=xterm")
    t.expect("resized 100x30")             # the telnet window size is passed on right after login
    t.expect(r"\$ ")
    t.line("hello there")
    t.expect("echo: hello there")
    t.resize(132, 43)
    t.expect("resized 132x43")
    t.line("stderr")
    t.expect("this went to stderr")
    t.line("flood 3000")                   # ~220 kB through the bridge
    out = t.expect("flood done", timeout=60)
    assert out.count("line 00") == 3000 and "line 002999" in out
    t.line("exit")
    t.expect("Connection to 127.0.0.1 closed")
    t.expect(PROMPT)

    t.line(f"ssh -p {port} -l tester 127.0.0.1")   # known now: no question asked
    out = t.expect("password: ")
    assert "authenticity" not in out, out
    t.line("pw-123456")
    t.expect(r"\$ ")
    t.send("\r~.")                         # escape sequence hangs up
    t.expect("Connection to 127.0.0.1 closed")
    t.expect(PROMPT)

    t.line(f"ssh tester@127.0.0.1 -p {port}")
    for _ in range(3):
        t.expect("password: ")
        t.line("still-wrong")
    t.expect("Permission denied\\.")
    t.expect(PROMPT)
    c["pw_port"] = port


@step("ssh: a changed host key is refused until 'hosts forget'")
def t_ssh_hostkey_changed(c):
    t = c["t"]
    port = c["mock"]("password", port=c["pw_port"], newkey=True)
    t.line(f"ssh tester@127.0.0.1 -p {port}")
    t.expect("REMOTE HOST IDENTIFICATION HAS CHANGED")
    t.expect("Host key verification failed")
    t.expect(PROMPT)
    t.line("hosts")
    out = t.expect(PROMPT)
    assert f"[127.0.0.1]:{port}" in out and "SHA256:" in out, out
    t.line(f"hosts forget [127.0.0.1]:{port}")
    t.expect("Forgotten")
    t.expect(PROMPT)
    t.line("hosts")
    t.expect("No hosts remembered yet")
    t.expect(PROMPT)


@step("ssh: keyboard-interactive only server")
def t_ssh_kbdint(c):
    t = c["t"]
    port = c["mock"]("kbdint")
    t.line(f"ssh tester@127.0.0.1 -p {port}")
    t.expect(r"\(yes/no\)\? ")
    t.line("yes")
    t.expect("Enter the one-time token")
    t.expect("Token: ")
    t.line("letmein")
    t.expect(r"mock shell")
    t.expect(r"\$ ")
    t.line("exit")
    t.expect(PROMPT)


@step("ssh: device public key is offered first, no password asked")
def t_ssh_pubkey(c):
    t = c["t"]
    t.line("sshkey")
    out = t.expect(PROMPT)
    m = re.search(r"^(ssh-ed25519 \S+ c3shell-51M0)\s*$", out, re.M)
    assert m, out
    c["pubkey"] = m.group(1)
    ak = os.path.join(c["tmp"], "authorized_keys")
    with open(ak, "w") as f:
        f.write(c["pubkey"] + "\n")
    os.chmod(ak, 0o600)
    c["ak"] = ak
    port = c["mock"]("pubkey", ak=ak)
    t.line(f"ssh tester@127.0.0.1 -p {port}")
    t.expect(r"\(yes/no\)\? ")
    t.line("yes")
    out = t.expect(r"\$ ")
    assert "mock shell" in out and "assword" not in out, out
    t.line("exit")
    t.expect(PROMPT)

    with open(ak, "w") as f:               # server no longer trusts us
        f.write("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake nobody\n")
    t.line(f"ssh tester@127.0.0.1 -p {port}")
    t.expect("Permission denied")
    t.expect("run 'sshkey'")
    t.expect(PROMPT)
    with open(ak, "w") as f:
        f.write(c["pubkey"] + "\n")


@step("ssh: real OpenSSH sshd - shell, pty size, 8-bit data, 1 MB with re-keying")
def t_ssh_openssh(c):
    t = c["t"]
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    if not os.path.exists(sshd):
        return "skipped (no sshd binary)"
    d, port = c["tmp"], free_port()
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", f"{d}/hostkey"], check=True)
    with open(f"{d}/sshd_config", "w") as f:
        f.write(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {d}/hostkey\nPidFile {d}/sshd.pid\n"
                f"AuthorizedKeysFile {c['ak']}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\n"
                "KbdInteractiveAuthentication no\nRekeyLimit 256K\nPrintMotd no\nPrintLastLog no\nLogLevel DEBUG1\n")
    proc = subprocess.Popen([sshd, "-D", "-e", "-f", f"{d}/sshd_config"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    c["procs"].append(proc)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    me = getpass.getuser()
    t.line(f"ssh {me}@127.0.0.1 -p {port}")
    t.expect(r"\(yes/no\)\? ")
    t.line("yes")
    try:
        t.expect("added to the list of known hosts")
        t.line("PS1='READY> '; echo started-$((6*7))")
        t.expect("started-42")
    except AssertionError:
        proc.terminate()
        print("---- sshd log ----\n" + proc.stdout.read().decode(errors="replace"))
        raise
    t.expect("READY> ")
    t.line("stty size")
    t.expect("43 132")                     # the size set by the earlier resize test
    t.expect("READY> ")
    t.resize(120, 40)
    time.sleep(0.3)
    t.line("stty size")
    t.expect("40 120")
    t.expect("READY> ")
    t.line("printf 'A\\377B\\303\\251C\\n' | od -An -c; printf 'raw:\\377\\303\\251:end\\n'")
    out = t.expect("READY> ")
    assert "raw:" in out
    assert b"raw:\xff\xc3\xa9:end" in out.encode("utf-8", "replace") or "raw:�é:end" in out, out
    t.line("seq 1 150000 | tee /dev/null; echo all-$((100+23))-done")   # ~1 MB, crosses several re-keys
    out = t.expect("all-123-done", timeout=120)
    body = out[out.index("\r\n2\r\n") + 2:out.index("all-123-done")]
    want = "".join(f"{i}\r\n" for i in range(2, 150001))
    assert body == want, f"stream corrupted: {len(body)} bytes, expected {len(want)}"
    t.expect("READY> ")
    t.line("head -c 200000 /dev/urandom | base64 -w0 | sha256sum; echo sum-done")
    t.expect("sum-done")
    t.expect("READY> ")
    t.line("exit")
    t.expect("Connection to 127.0.0.1 closed")
    t.expect(PROMPT)
    proc.terminate()
    log = proc.stdout.read().decode(errors="replace")
    rekeys = log.count("rekey in after") + log.count("rekey out after")
    assert rekeys >= 4, f"expected the session to be re-keyed, sshd log shows {rekeys}"
    return f"{rekeys // 2} key re-exchanges survived"


@step("ssh: real OpenSSH sshd with RSA and ECDSA host keys")
def t_ssh_other_hostkeys(c):
    t = c["t"]
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    if not os.path.exists(sshd):
        return "skipped (no sshd binary)"
    me = getpass.getuser()
    for ktype, bits in (("rsa", "4096"), ("ecdsa", "256"), ("ecdsa", "521")):
        d, port = c["tmp"], free_port()
        key = f"{d}/hostkey-{ktype}-{bits}"
        subprocess.run(["ssh-keygen", "-q", "-t", ktype, "-b", bits, "-N", "", "-f", key], check=True)
        cfg = f"{d}/sshd_config-{ktype}-{bits}"
        with open(cfg, "w") as f:
            f.write(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {key}\nPidFile none\n"
                    f"AuthorizedKeysFile {c['ak']}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\n"
                    "KbdInteractiveAuthentication no\nPrintMotd no\nPrintLastLog no\n")
        proc = subprocess.Popen([sshd, "-D", "-e", "-f", cfg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        c["procs"].append(proc)
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        t.line(f"ssh {me}@127.0.0.1 -p {port}")
        out = t.expect(r"\(yes/no\)\? ")
        want = "rsa-sha2-" if ktype == "rsa" else f"ecdsa-sha2-nistp{bits}"
        assert want in out or (ktype == "rsa" and "ssh-rsa" in out), out
        t.line("yes")
        t.expect("added to the list of known hosts")
        t.line(f"echo {ktype}-$((40+2))-ok; exit")
        t.expect(f"{ktype}-42-ok")
        t.expect("Connection to 127.0.0.1 closed")
        t.expect(PROMPT)
        proc.terminate()


@step("the real telnet program: character mode, remote echo, hidden password")
def t_real_telnet(c):
    import pty
    import select as sel
    if not shutil.which("telnet"):
        return "skipped (no telnet program installed)"
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("telnet", ["telnet", "127.0.0.1", str(c["sim"].port)])
    buf = b""

    def until(pat, timeout=10):
        nonlocal buf
        end = time.time() + timeout
        while not re.search(pat, buf):
            if time.time() > end:
                raise AssertionError(f"telnet program: no {pat!r} in:\n{buf.decode(errors='replace')}")
            if sel.select([fd], [], [], 0.2)[0]:
                try:
                    buf += os.read(fd, 4096)
                except OSError:
                    raise AssertionError(f"telnet program exited; output:\n{buf.decode(errors='replace')}")
        out, buf = buf, b""
        return out.decode(errors="replace")

    try:
        until(rb"login: ")
        os.write(fd, b"admin\r")
        out = until(rb"Password: ")
        assert out.count("admin") == 1, f"username echoed {out.count('admin')} times (expected once):\n{out}"
        os.write(fd, b"secret-123\r")
        out = until(PROMPT.encode())
        assert "secret-123" not in out, "password was echoed by the telnet program"
        os.write(fd, b"status\r")
        out = until(PROMPT.encode())
        assert out.count("status") == 1 and "Sessions:" in out, out
        assert "\r\r\n" not in out and "\n\n\n" not in out, f"line endings look doubled: {out!r}"
        os.write(fd, b"exit\r")
        until(rb"Goodbye")
    finally:
        try:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
        except OSError:
            pass
        os.close(fd)


@step("WiFi lost: falls back to the setup network, rejoins when it returns")
def t_fallback(c):
    sim, t = c["sim"], c["t"]
    t.line("exit")
    t.expect_closed()
    mark = len(sim.log)
    sim.console("down HomeNet")
    sim.wait_log("falling back to setup network", start=mark)
    sim.wait_log("hosting 'c3shell-51M0'", start=mark)
    t = login(sim)
    t.line("status")
    out = t.expect(PROMPT)
    assert "'HomeNet' saved but not reachable" in out and "is up" in out, out
    mark = len(sim.log)
    sim.console("up HomeNet")
    time.sleep(4)                          # someone is logged in: it must not retry under them
    assert not any("rejoined" in l for l in sim.log[mark:]), "retried while a session was active"
    t.line("exit")
    t.expect_closed()
    sim.wait_log("rejoined 'HomeNet'", start=mark)
    sim.wait_log("stopped hosting", start=mark)


@step("reboot: account and network survive, device rejoins by itself")
def t_reboot(c):
    sim = c["sim"]
    t = login(sim)
    t.line("passwd")
    t.expect("Current password: ")
    t.line("secret-123")
    t.expect("New password: ")
    t.line("new-secret-456")
    t.expect("Retype new password: ")
    t.line("new-secret-456")
    t.expect("Password changed")
    t.expect(PROMPT)
    mark = len(sim.log)
    t.line("reboot")
    t.expect_closed()
    sim.wait_log("joined 'HomeNet', address 192.168.0.77", start=mark)
    sim.wait_log("telnet: listening", start=mark)
    assert not any("hosting" in l for l in sim.log[mark:]), "setup network must stay off after reboot"
    t = sim.telnet()
    t.expect("login: ")
    t.line("admin")
    t.expect("Password: ")
    t.line("secret-123")                   # old password no longer works
    t.expect("Login incorrect")
    t.close()
    t = login(sim, password="new-secret-456")
    c["t"] = t


@step("wifi forget and factory-reset return the device to first-boot state")
def t_reset(c):
    sim, t = c["sim"], c["t"]
    mark = len(sim.log)
    t.line("wifi forget")
    t.expect("Type 'yes' to confirm: ")
    t.line("yes")
    t.expect("Find this device on the WiFi network 'c3shell-51M0'")
    sim.wait_log("hosting 'c3shell-51M0'", start=mark)
    t.close()
    t = login(sim, password="new-secret-456")
    mark = len(sim.log)
    t.line("factory-reset")
    t.expect("Type 'yes' to confirm: ")
    t.line("no")
    t.expect(PROMPT)
    t.line("factory-reset")
    t.expect("Type 'yes' to confirm: ")
    t.line("yes")
    t.expect("Erasing and rebooting")
    t.expect_closed()
    sim.wait_log("no saved network", start=mark)
    sim.wait_log("telnet: listening", start=mark)
    t = sim.telnet()
    t.expect("First-time setup")
    t.close()


def main():
    if not os.path.exists(SIM):
        sys.exit("build the simulator first: make sim")
    tmp = tempfile.mkdtemp(prefix="c3shell-test-")
    procs = []
    mock_keys = {}

    def mock(mode, port=None, newkey=False, ak=None):
        port = port or free_port()
        old = mock_keys.get(port)
        if old:
            old.kill()
            old.wait()
        key = os.path.join(tmp, f"mockkey-{port}-{'b' if newkey else 'a'}")
        if not os.path.exists(key):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], check=True)
        args = [sys.executable, os.path.join(ROOT, "test", "mock_sshd.py"), str(port), key, mode]
        if ak:
            args.append(ak)
        p = subprocess.Popen(args, stdout=subprocess.PIPE, text=True)
        assert "ready" in p.stdout.readline()
        procs.append(p)
        mock_keys[port] = p
        return port

    sim = Sim(os.path.join(tmp, "state"), free_port(), extra=("--fresh", "--fallback", "2", "--retry", "2"))
    ctx = {"sim": sim, "tmp": tmp, "mock": mock, "procs": procs}
    failed = 0
    try:
        for name, fn in results:
            t0 = time.time()
            try:
                note = fn(ctx)
                print(f"  ok    {name}{' - ' + note if note else ''}  ({time.time() - t0:.1f}s)", flush=True)
            except AssertionError as e:
                failed += 1
                time.sleep(0.3)
                print(f"  FAIL  {name}\n        {str(e).replace(chr(10), chr(10) + '        ')}", flush=True)
                print("        ---- simulator log (tail) ----\n        " + "\n        ".join(sim.log[-40:]))
                break                      # later steps depend on earlier ones
    finally:
        room = [int(m.group(1)) for l in sim.log for m in [re.search(r"stack headroom was (\d+)", l)] if m]
        if room:
            print(f"\n  smallest session stack headroom seen: {min(room)} bytes (x86-64 build)")
        sim.stop()
        for p in procs:
            p.kill()
        shutil.rmtree(tmp, ignore_errors=True)
    print("\nALL TESTS PASSED" if not failed else "\nTESTS FAILED")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
