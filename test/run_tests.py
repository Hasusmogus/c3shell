# /// script
# requires-python = ">=3.10"
# dependencies = ["asyncssh"]
# ///
"""End-to-end test of c3shell against the simulator (build-sim/c3shell-sim).

Drives the device exactly like a person would: the real OpenSSH client on a
pseudo-terminal, with a script doing the typing.
Covers first-boot account creation, login, the WiFi selector and the
disappearing setup network, fallback when WiFi is lost, persistence across a
reboot, and SSH (password, keyboard-interactive, public key, host-key
pinning) against a mock server and a real OpenSSH sshd.

Run with:  make test
"""
import fcntl
import getpass
import os
import pty
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIM = os.path.join(ROOT, "build-sim", "c3shell-sim")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Client:
    """The real OpenSSH client on a pseudo-terminal, driven like a person typing."""

    def __init__(self, port, user, known_hosts, cols=100, rows=30, command=None):
        self.cols, self.rows = cols, rows
        self.text = b""
        self.eof = False
        args = ["ssh", "-F", "/dev/null", "-p", str(port), "-o", f"UserKnownHostsFile={known_hosts}",
                "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR", "-o", "PubkeyAuthentication=no",
                "-o", "NumberOfPasswordPrompts=3", "-o", "ConnectTimeout=5", f"{user}@127.0.0.1"]
        if command:
            args += ["-tt", command]
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
            os.execvp("ssh", args)

    def resize(self, cols, rows):
        self.cols, self.rows = cols, rows
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def _pump(self, timeout):
        if self.eof or not select.select([self.fd], [], [], timeout)[0]:
            return
        try:
            data = os.read(self.fd, 65536)
        except OSError:
            data = b""
        if not data:
            self.eof = True
            return
        self.text += data

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
                raise AssertionError(f"connection was not closed by the device; got:\n{self.text.decode(errors='replace')}")
            self._pump(0.2)
        out, self.text = self.text.decode(errors="replace"), b""
        return out

    def send(self, s):
        data = s.encode() if isinstance(s, str) else s
        while data:                        # a pty takes only so much at once
            try:
                n = os.write(self.fd, data)
            except BlockingIOError:
                n = 0
            data = data[n:]
            if data:
                self._pump(0.05)           # keep draining output so ssh never stalls

    def line(self, s):
        self.send(s + "\r")

    def close(self):
        try:
            os.kill(self.pid, 9)
            os.waitpid(self.pid, 0)
        except OSError:
            pass
        try:
            os.close(self.fd)
        except OSError:
            pass
        self.eof = True


class Sim:
    def __init__(self, state, port, extra=()):
        self.port = port
        self.known_hosts = os.path.join(os.path.dirname(state), "known_hosts")
        self.log = []
        self.proc = subprocess.Popen(
            [os.environ.get("C3SIM", SIM), "--fast", "--port", str(port), "--state", state, "--networks", os.path.join(ROOT, "sim", "networks.txt"), *extra],
            cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        threading.Thread(target=self._reader, daemon=True).start()
        self.wait_log("ssh: listening")

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

    def connect(self, user="admin", **kw):
        return Client(self.port, user, self.known_hosts, **kw)

    def stop(self):
        self.proc.kill()
        self.proc.wait()


def login(sim, user="admin", password="secret-123", **kw):
    t = sim.connect(user, **kw)
    t.expect("password: ")
    t.line(password)
    t.expect(PROMPT)
    return t


PROMPT = r"admin@c3shell-51M0:/\S*> "


def prompt_in(d):
    return re.escape(f"admin@c3shell-51M0:{d}> ")
results = []


def step(name):
    def deco(fn):
        results.append((name, fn))
        return fn
    return deco


# --------------------------------------------------------------------------

@step("first boot: hosts setup network, lets you in to create an account")
def t_first_boot(c):
    sim = c["sim"]
    sim.wait_log("hosting 'c3shell-51M0'")
    assert any("host key fingerprint is SHA256:" in l for l in sim.log), "host key fingerprint not logged"
    t = sim.connect("admin")                # no password asked: there is no account yet
    t.expect("First-time setup")
    eve = sim.connect("eve")                # a second visitor arrives during setup
    eve.expect(r"New username \[eve\]: ")
    t.expect(r"New username \[admin\]: ")
    t.line("bad name!")
    t.expect("Use 1-31 characters")
    t.expect(r"New username \[admin\]: ")
    t.line("")                             # accept the suggested name
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
    eve.line("")                           # the account now exists: eve must not get a shell
    eve.expect("New password: ")
    eve.line("eve-password")
    eve.expect("Retype new password: ")
    eve.line("eve-password")
    eve.expect("created from another connection")
    out = eve.expect_closed()
    assert "c3shell-51M0>" not in out, out


@step("once an account exists a password is required; session slots are limited")
def t_second_conn(c):
    sim = c["sim"]
    t2 = sim.connect("admin")
    t2.expect("password: ")
    t2.line("wrong")
    t2.expect("Permission denied, please try again")
    t2.expect("password: ")
    t2.line("secret-123")
    out = t2.expect(PROMPT)
    assert "First-time setup" not in out
    tx = sim.connect("somebody-else")
    tx.expect("password: ")
    tx.line("secret-123")                  # right password, wrong user
    tx.expect("Permission denied, please try again")
    tx.close()
    time.sleep(0.5)
    t3 = login(sim)
    t4 = sim.connect("admin")              # c["t"], t2, t3 hold all three slots
    t4.expect_closed(timeout=10)
    sim.wait_log("all 3 session slots are in use")
    t3.line("exit")
    t3.expect("Goodbye")
    t3.expect_closed()
    t2.line("exit")
    t2.expect_closed()
    tc = sim.connect("admin", command="status")   # running a command instead of a shell
    tc.expect("password: ")
    tc.line("secret-123")
    tc.expect("only interactive logins, scp and sftp")
    tc.expect_closed()


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
    t.expect("ssh admin@192.168.0.77")
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
    t.expect("resized 100x30")             # your terminal size is passed on right after login
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
    t.send("\r~~.")                        # "~." for the inner connection; OpenSSH itself eats one "~"
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


@step("files: mkdir, cd, touch, ls, cp, mv, cat, rm, rmdir, quoting, df")
def t_files(c):
    t = c["t"]

    def run(cmd, where="/"):
        t.line(cmd)
        return t.expect(prompt_in(where))

    out = run("ls")
    assert out.strip().endswith(">") and "\n" in out          # empty root lists nothing
    run("mkdir docs")
    run("mkdir -p docs/deep/er")
    out = run("mkdir docs")
    assert "File exists" in out, out
    run("cd docs/deep", "/docs/deep")
    out = run("pwd", "/docs/deep")
    assert "\n/docs/deep\r\n" in out, out
    run("touch a.txt 'two words.txt'", "/docs/deep")
    out = run("ls -l", "/docs/deep")
    assert "a.txt" in out and "two words.txt" in out and "er/" in out, out
    run("cd ..", "/docs")
    run("cd ../../../..")                   # can't climb above the root
    out = run("ls docs")
    assert "deep/" in out, out
    out = run("cd nowhere")
    assert "No such file or directory" in out, out
    out = run("cd docs/deep/a.txt")
    assert "Not a directory" in out, out
    out = run("rmdir docs")
    assert "not empty" in out, out
    out = run("rm docs")
    assert "is a directory" in out, out

    # contents come in through vi; cp/mv/cat work on them
    t.line("vi docs/hello.txt")
    t.expect(r"\[New File\]")
    t.send("iline one\rline two\x1b")
    time.sleep(0.2)
    t.send(":wq\r")
    t.expect(prompt_in("/"))
    out = run("cat docs/hello.txt")
    assert "line one\r\nline two\r\n" in out, repr(out)
    run("cp docs/hello.txt docs/deep")
    run("mv docs/deep/hello.txt /docs/deep/renamed.txt")
    out = run("cat docs/deep/renamed.txt")
    assert "line two" in out, out
    out = run("ls -l docs/deep")
    assert "renamed.txt" in out and "hello.txt" not in out and re.search(r"-\s+18\s+renamed\.txt", out), out
    out = run("mv docs docs/deep")
    assert "into itself" in out, out
    out = run("cat 'docs/deep/two words.txt'")
    out = run("rm /")
    assert "refusing" in out, out
    out = run('echo "unclosed')
    assert "missing closing quote" in out, out
    out = run("df")
    assert re.search(r"\d+ KB used of 1984 KB", out), out
    run("cd docs/deep", "/docs/deep")
    out = run("rm -r /docs", "/docs/deep")
    assert "you are inside it" in out, out
    run("cd /")
    run("rm -r docs")
    out = run("ls")
    assert "docs" not in out, out


@step("files: no way out of the file area")
def t_sandbox(c):
    t, sim = c["t"], c["sim"]
    state = os.path.dirname(sim.known_hosts) + "/state"
    assert os.path.exists(f"{state}/account.bin"), os.listdir(state)
    for probe in ["../account.bin", "/../account.bin", "../../state/account.bin", "..//../account.bin",
                  "./../../../../etc/passwd"]:
        t.line(f"cat {probe}")
        out = t.expect(PROMPT)
        assert "No such file" in out, (probe, out)
    t.line("ls ..")
    out = t.expect(PROMPT)
    assert "account" not in out and "fs" not in out.split("\n", 1)[1], out
    t.line("vi ../escape.txt")
    t.expect(r"\[New File\]")
    t.send("ix\x1b")
    time.sleep(0.2)
    t.send(":wq\r")
    t.expect(PROMPT)
    assert not os.path.exists(f"{state}/escape.txt"), "a write escaped the file area"
    assert os.path.exists(f"{state}/fs/escape.txt"), "the write should have landed at /escape.txt"
    t.line("rm escape.txt")
    t.expect(PROMPT)
    t.line("ls " + "x" * 70)
    out = t.expect(PROMPT)
    assert "too long" in out, out


@step("vi: editing commands, undo, search, yank/put, quit protection")
def t_vi(c):
    t, sim = c["t"], c["sim"]
    path = os.path.dirname(sim.known_hosts) + "/state/fs/edit.txt"
    with open(path, "w") as f:
        f.write("alpha beta\ngamma\ndelta\n\tindented\nüñí ok\n")

    def keys(k):
        t.send(k)
        time.sleep(0.15)

    def content():
        with open(path) as f:
            return f.read()

    t.line("vi edit.txt")
    t.expect(r'"/edit.txt" 5L, 4\dB')
    keys("dd")                                 # delete "alpha beta"
    keys("p")                                  # put it back below "gamma"
    keys(":w\r")
    t.expect("written")
    assert content() == "gamma\nalpha beta\ndelta\n\tindented\nüñí ok\n", repr(content())
    keys("u")                                  # undo the put
    keys("gg")
    keys("wwx")                                # w crosses onto the next line
    keys("u")
    keys("G$")
    keys("x")                                  # delete the last character of "üñí ok"
    keys("0x")                                 # delete the multi-byte ü as one character
    keys(":w\r")
    t.expect("written")
    assert content().endswith("ñí o\n"), repr(content())
    keys("/delta\r")
    keys("Aine\x1b")                          # append at end of the found line
    keys("ggOtop\x1b")
    keys("3G")
    keys("J")
    keys(":w\r")
    t.expect("written")
    lines = content().split("\n")
    assert lines[0] == "top", lines
    assert "deltaine" in content(), repr(content())
    keys("ggdw")
    keys(":w\r")
    t.expect("written")
    keys("ihello\x1b")
    keys(":q\r")
    t.expect("No write since last change")
    keys(":q!\r")
    t.expect(PROMPT)
    assert "hello" not in content(), repr(content())
    t.line("vi edit.txt")
    t.expect("edit.txt")
    keys("yyP:x\r")                            # :x saves when changed
    t.expect(PROMPT)
    assert content().split("\n")[0] == content().split("\n")[1], repr(content())
    t.line("vi edit.txt")
    t.expect("edit.txt")
    keys("ZZ")                                 # unchanged: just quits
    t.expect(PROMPT)
    t.line("vi")
    t.expect("No Name")
    keys("iscratch\x1b:w\r")
    t.expect("E32: No file name")
    keys(":w scratch.txt\r")
    t.expect("written")
    keys(":q\r")
    t.expect(PROMPT)
    t.line("cat scratch.txt")
    t.expect("scratch")
    t.expect(PROMPT)
    t.line("rm scratch.txt edit.txt")
    t.expect(PROMPT)

    # a big paste streams in without a redraw per character, and size is capped
    t.line("vi big.txt")
    t.expect("New File")
    t.send("i" + ("0123456789abcdef" * 4 + "\r") * 300 + "\x1b")
    keys(":wq\r")
    t.expect(PROMPT, timeout=60)
    with open(path.replace("edit.txt", "big.txt")) as f:
        got = f.read()
    assert got == ("0123456789abcdef" * 4 + "\n") * 300 + "\n", f"paste: {len(got)} bytes, {got.count(chr(10))} lines"
    with open(path.replace("edit.txt", "huge.txt"), "w") as f:
        f.write("x" * 40000)
    t.line("vi huge.txt")
    t.expect("too large for vi")
    t.expect(PROMPT)
    t.line("rm big.txt huge.txt")
    t.expect(PROMPT)


def _pc_tools(c):
    """scp/sftp from 'a PC' (this machine) into the device, logging in by password."""
    sim, d = c["sim"], c["tmp"]
    ap = os.path.join(d, "askpass")
    with open(ap, "w") as f:
        f.write("#!/bin/sh\necho secret-123\n")
    os.chmod(ap, 0o755)
    env = dict(os.environ, SSH_ASKPASS=ap, SSH_ASKPASS_REQUIRE="force", DISPLAY="none")
    opts = ["-F", "/dev/null", "-o", f"UserKnownHostsFile={sim.known_hosts}", "-o", "StrictHostKeyChecking=accept-new",
            "-o", "PubkeyAuthentication=no", "-o", "LogLevel=ERROR", "-P", str(sim.port)]

    def run(prog, *args, stdin=None):
        o = [x if not (prog == "ssh" and x == "-P") else "-p" for x in opts]
        r = subprocess.run([prog, *o, *args], env=env, input=stdin, capture_output=True, text=True, timeout=120)
        return r.returncode, r.stdout + r.stderr
    return run


@step("files: scp and sftp from a PC (SFTP and classic scp), sandboxed")
def t_xfer_in(c):
    t, d = c["t"], c["tmp"]
    run = _pc_tools(c)
    blob = os.urandom(300_000)
    with open(f"{d}/blob.bin", "wb") as f:
        f.write(blob)
    os.makedirs(f"{d}/tree/sub", exist_ok=True)
    for name, text in (("tree/a.txt", "alpha\n"), ("tree/sub/b.txt", "beta\n")):
        with open(f"{d}/{name}", "w") as f:
            f.write(text)
    rc, out = run("scp", f"{d}/blob.bin", "admin@127.0.0.1:/")                     # SFTP (OpenSSH default)
    assert rc == 0, out
    rc, out = run("scp", "-O", f"{d}/blob.bin", "admin@127.0.0.1:/classic.bin")    # classic scp protocol
    assert rc == 0, out
    rc, out = run("scp", "-r", f"{d}/tree", "admin@127.0.0.1:/")
    assert rc == 0, out
    rc, out = run("scp", "admin@127.0.0.1:/classic.bin", f"{d}/back1")
    assert rc == 0, out
    rc, out = run("scp", "-O", "-r", "admin@127.0.0.1:/tree", f"{d}/tree2")
    assert rc == 0, out
    assert open(f"{d}/back1", "rb").read() == blob, "download corrupted"
    assert open(f"{d}/tree2/sub/b.txt").read() == "beta\n"
    t.line("ls -l / tree/sub")
    out = t.expect(PROMPT)
    assert re.search(r"300000\s+blob\.bin", out) and "classic.bin" in out and "b.txt" in out, out
    rc, out = run("sftp", "admin@127.0.0.1", stdin="ls -l /\nmkdir /d\nrename /blob.bin /d/x.bin\nls /d\n"
                  "get /../../../etc/hostname " + d + "/escaped\nrm /d/x.bin\nrmdir /d\n")
    assert rc == 0, out
    assert "/d/x.bin" in out and "classic.bin" in out, out
    assert "not found" in out and not os.path.exists(f"{d}/escaped"), out
    rc, out = run("scp", "-O", "admin@127.0.0.1:/../../../etc/hostname", f"{d}/escaped2")
    assert rc != 0 and not os.path.exists(f"{d}/escaped2"), out
    rc, out = run("ssh", "admin@127.0.0.1", "ls")                                    # no shell commands
    assert rc != 0 and "only interactive logins" in out, out
    t.line("rm -r tree classic.bin")
    t.expect(PROMPT)


@step("scp command: upload and download against a real OpenSSH sshd, through the device")
def t_xfer_out(c):
    t, d = c["t"], c["tmp"]
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    if not os.path.exists(sshd):
        return "skipped (no sshd binary)"
    port = free_port()
    with open(f"{d}/sshd_scp_config", "w") as f:
        f.write(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {d}/hostkey\nPidFile {d}/sshd2.pid\n"
                f"AuthorizedKeysFile {c['ak']}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\n"
                "KbdInteractiveAuthentication no\nLogLevel ERROR\n")
    proc = subprocess.Popen([sshd, "-D", "-e", "-f", f"{d}/sshd_scp_config"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    c["procs"].append(proc)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    me = getpass.getuser()
    blob = open(f"{d}/blob.bin", "rb").read()
    rc, out = _pc_tools(c)("scp", f"{d}/blob.bin", "admin@127.0.0.1:/")
    assert rc == 0, out
    t.line(f"scp -P {port} blob.bin {me}@127.0.0.1:{d}/landed.bin")
    t.expect(r"\(yes/no\)\? ")
    t.line("yes")
    out = t.expect(PROMPT, timeout=60)
    assert "100%" in out and open(f"{d}/landed.bin", "rb").read() == blob, out
    t.line(f"scp -P {port} -r {me}@127.0.0.1:{d}/tree fetched")
    out = t.expect(PROMPT, timeout=60)
    t.line("cat fetched/sub/b.txt")
    out = t.expect(PROMPT)
    assert "beta" in out, out
    t.line(f"scp -P {port} {me}@127.0.0.1:{d}/no-such-file .")
    out = t.expect(PROMPT, timeout=30)
    assert "No such file" in out, out
    t.line("scp blob.bin")
    out = t.expect(PROMPT)
    assert "usage: scp" in out, out
    t.line("rm -r fetched blob.bin")
    t.expect(PROMPT)
    proc.terminate()


@step("repeated wrong passwords get the address blocked for a while")
def t_lockout(c):
    sim = c["sim"]
    mark = len(sim.log)
    a = sim.connect("admin")
    for _ in range(3):
        a.expect("password: ")
        a.line("guess")
    a.expect_closed()
    b = sim.connect("admin")
    b.expect("password: ")
    b.line("guess")
    b.expect("password: ")
    b.line("guess")                        # fifth wrong one: the device hangs up
    sim.wait_log("blocking 127.0.0.1", start=mark)
    b.expect("password: ")                 # ssh only notices once it tries to send again
    b.line("secret-123")
    out = b.expect_closed()
    assert "c3shell" not in out, out
    d = sim.connect("admin")               # even the right password gets no chance now
    out = d.expect_closed(timeout=10)
    assert "password:" not in out, out
    time.sleep(3.5)                        # the simulator runs with a 3 s block
    d = login(sim)
    d.line("exit")
    d.expect_closed()


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


@step("reboot: account, network and files survive, device rejoins by itself")
def t_reboot(c):
    sim = c["sim"]
    t = login(sim)
    t.line("touch keep.txt")
    t.expect(PROMPT)
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
    sim.wait_log("ssh: listening", start=mark)
    assert not any("hosting" in l for l in sim.log[mark:]), "setup network must stay off after reboot"
    t = sim.connect("admin")               # same host key as before, or ssh would refuse here
    t.expect("password: ")
    t.line("secret-123")                   # old password no longer works
    t.expect("Permission denied, please try again")
    t.close()
    t = login(sim, password="new-secret-456")
    t.line("ls")
    out = t.expect(PROMPT)
    assert "keep.txt" in out, "files must survive a reboot: " + out
    c["t"] = t


@step("wifi forget and factory-reset return the device to first-boot state")
def t_reset(c):
    sim, t = c["sim"], c["t"]
    mark = len(sim.log)
    t.line("wifi forget")
    t.expect("Type 'yes' to confirm: ")
    t.line("yes")
    t.expect("Find this device on the WiFi network 'c3shell-51M0' \\(ssh admin@192.168.4.1\\)")
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
    sim.wait_log("ssh: listening", start=mark)
    t = sim.connect("admin")               # a reset device has a new identity; ssh must notice
    out = t.expect_closed()
    assert "REMOTE HOST IDENTIFICATION HAS CHANGED" in out, out
    os.unlink(sim.known_hosts)
    t = sim.connect("admin")
    t.expect("First-time setup")
    t.close()
    state = os.path.dirname(sim.known_hosts) + "/state/fs"
    assert os.listdir(state) == [], f"factory reset left files behind: {os.listdir(state)}"


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

    sim = Sim(os.path.join(tmp, "state"), free_port(), extra=("--fresh", "--fallback", "2", "--retry", "2", "--block", "3"))
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
