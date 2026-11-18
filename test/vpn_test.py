# /// script
# requires-python = ">=3.10"
# dependencies = ["asyncssh"]
# ///
"""End-to-end test of the OpenVPN client against a real OpenVPN server.

Runs itself inside a fresh, unprivileged user + network namespace
(unshare --user --map-current-user --net --keep-caps), where it may create
tun devices without root. In there: an OpenVPN server on 127.0.0.1 with its
tunnel at 10.8.0.1, an OpenSSH sshd listening on all addresses, and the
simulator. The device connects to the VPN and copies files with scp to
10.8.0.1; sshd must see the connection come from the device's tunnel
address, which proves the bytes went through the VPN (and so through the
simulator's lwIP, the same stack the chip uses).

Interactive ssh is not tried here: sshd cannot hand out a pty inside an
unprivileged namespace. Classic-scp exec channels need none.

Run with:  make test-vpn   (also part of make test)
"""
import getpass
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_tests as R  # noqa: E402


def sh(cmd):
    subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def make_pki(d):
    ext = f"{d}/ext"
    with open(f"{ext}-srv", "w") as f:
        f.write("basicConstraints=CA:false\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    with open(f"{ext}-cli", "w") as f:
        f.write("basicConstraints=CA:false\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n")
    ec = "-newkey ec -pkeyopt ec_paramgen_curve:prime256v1"
    sh(f"openssl req -x509 {ec} -nodes -keyout {d}/ca.key -out {d}/ca.crt -days 30 -subj /CN=TestCA "
       f"-addext basicConstraints=critical,CA:true -addext keyUsage=keyCertSign,cRLSign")
    sh(f"openssl req -newkey rsa:2048 -nodes -keyout {d}/server.key -out {d}/server.csr -subj /CN=vpn-server")
    sh(f"openssl x509 -req -in {d}/server.csr -CA {d}/ca.crt -CAkey {d}/ca.key -CAcreateserial "
       f"-out {d}/server.crt -days 30 -extfile {ext}-srv")
    sh(f"openssl req {ec} -nodes -keyout {d}/client.key -out {d}/client.csr -subj /CN=c3client")
    sh(f"openssl x509 -req -in {d}/client.csr -CA {d}/ca.crt -CAkey {d}/ca.key -CAcreateserial "
       f"-out {d}/client.crt -days 30 -extfile {ext}-cli")
    sh(f"openssl req -x509 {ec} -nodes -keyout {d}/other.key -out {d}/other.crt -days 30 -subj /CN=OtherCA")
    sh(f"openvpn --genkey secret {d}/ta.key")


class Server:
    def __init__(self, d, args):
        self.log = f"{d}/openvpn.log"
        f = open(self.log, "w")
        self.p = subprocess.Popen(
            f"openvpn --dev tun0 --server 10.8.0.0 255.255.255.0 --port 1194 --local 127.0.0.1 "
            f"--ca {d}/ca.crt --cert {d}/server.crt --key {d}/server.key --dh none "
            f"--push 'route 10.9.0.0 255.255.255.0' --keepalive 10 60 --disable-dco --verb 3 {args}",
            shell=True, stdout=f, stderr=subprocess.STDOUT)
        for _ in range(100):
            if "Initialization Sequence Completed" in open(self.log).read():
                return
            time.sleep(0.1)
        raise AssertionError("openvpn server did not start:\n" + open(self.log).read()[-2000:])

    def stop(self):
        self.p.terminate()
        self.p.wait()


def ovpn(d, proto="udp", extra=""):
    pem = lambda n: open(f"{d}/{n}").read()
    return (f"client\ndev tun\nproto {proto}\nremote 127.0.0.1 1194\nremote-cert-tls server\nnobind\n{extra}"
            f"<ca>\n{pem('ca.crt')}</ca>\n<cert>\n{pem('client.crt')}</cert>\n<key>\n{pem('client.key')}</key>\n")


def main_inside():
    if not (shutil.which("openvpn") and shutil.which("openssl")):
        print("  skipped: needs openvpn and openssl")
        return 0
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    d = tempfile.mkdtemp(prefix="c3shell-vpn-")
    make_pki(d)
    sh(f"ssh-keygen -q -t ed25519 -N '' -f {d}/hostkey")
    ak = f"{d}/authorized_keys"
    open(ak, "w").close()
    with open(f"{d}/sshd_config", "w") as f:
        f.write(f"Port 2223\nListenAddress 0.0.0.0\nHostKey {d}/hostkey\nPidFile {d}/sshd.pid\nAuthorizedKeysFile {ak}\n"
                "StrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nLogLevel VERBOSE\n")
    sshd_log = open(f"{d}/sshd.log", "w")
    sshd_p = subprocess.Popen([sshd, "-D", "-e", "-f", f"{d}/sshd_config"], stdout=sshd_log, stderr=subprocess.STDOUT)
    fs = f"{d}/state/fs"
    sim = R.Sim(f"{d}/state", R.free_port(), extra=("--fresh",))
    me = getpass.getuser()
    blob = os.urandom(400_000)
    failed = 0
    srv = None
    t = None

    def put(name, text):
        os.makedirs(fs, exist_ok=True)
        with open(f"{fs}/{name}", "w") as f:
            f.write(text)

    def roundtrip(tag):
        """scp up and back down through the tunnel; sshd must see the tunnel address"""
        with open(f"{fs}/up.bin", "wb") as f:
            f.write(blob)
        t.line(f"scp -P 2223 up.bin {me}@10.8.0.1:{d}/landed-{tag}.bin")
        out = t.expect(R.PROMPT + "|" + r"\(yes/no\)\? ", timeout=60)
        if "yes/no" in out:
            t.line("yes")
            out = t.expect(R.PROMPT, timeout=60)
        assert open(f"{d}/landed-{tag}.bin", "rb").read() == blob, out
        t.line(f"scp -P 2223 {me}@10.8.0.1:{d}/landed-{tag}.bin back.bin")
        out = t.expect(R.PROMPT, timeout=60)
        assert open(f"{fs}/back.bin", "rb").read() == blob, out
        sshd_log.flush()
        froms = [l for l in open(f"{d}/sshd.log") if "Accepted publickey" in l]
        assert froms and all("from 10.8.0." in l and "from 10.8.0.1 " not in l for l in froms), froms

    def vpn_up(name, want="VPN up"):
        t.line(f"vpn up {name}")
        out = t.expect(R.PROMPT, timeout=45)
        assert want in out, out
        return out

    def vpn_down():
        t.line("vpn down")
        t.expect("VPN off", timeout=20)
        t.expect(R.PROMPT)

    steps = []

    def step(name):
        def deco(fn):
            steps.append((name, fn))
            return fn
        return deco

    @step("setup: account and the device key on the remote sshd")
    def _():
        nonlocal t
        t = sim.connect("admin")
        t.expect(r"New username \[admin\]: ")
        t.line("")
        t.expect("New password: ")
        t.line("secret-123")
        t.expect("Retype new password: ")
        t.line("secret-123")
        t.expect(R.PROMPT)
        t.line("sshkey")
        out = t.expect(R.PROMPT)
        with open(ak, "w") as f:
            f.write([l for l in out.splitlines() if l.startswith("ssh-ed25519")][0] + "\n")

    @step("UDP, tls-crypt, certificate: connect, scp both ways through the tunnel, status, disconnect")
    def _():
        nonlocal srv
        srv = Server(d, f"--proto udp --topology subnet --tls-crypt {d}/ta.key")
        put("vpn.ovpn", ovpn(d, "udp", f"<tls-crypt>\n{open(d + '/ta.key').read()}</tls-crypt>\n"))
        out = vpn_up("")
        assert "10.8.0.2" in out, out
        roundtrip("udp")
        t.line("vpn")
        out = t.expect(R.PROMPT)
        assert "connected" in out and "1 pushed route" in out and "KB in" in out, out
        t.line("status")
        out = t.expect(R.PROMPT)
        assert "VPN:           connected, address 10.8.0.2" in out, out
        t.line("ip -s addr")
        out = t.expect(R.PROMPT)
        assert "tun0: <POINTOPOINT,UP,LOWER_UP> mtu 1400" in out and "inet 10.8.0.2/24 scope global tun0" in out, out
        assert "openvpn to 127.0.0.1:1194/udp" in out and re.search(r"RX: bytes [1-9]", out), out
        t.line("ip route")
        out = t.expect(R.PROMPT)
        assert "10.8.0.0/24 dev tun0 scope link src 10.8.0.2" in out, out
        assert re.search(r"\d+\.\d+\.\d+\.\d+/\d+ dev tun0\r\n", out), out     # the route the server pushed
        vpn_down()
        t.line("ip addr")
        out = t.expect(R.PROMPT)
        assert "tun0" not in out, out
        t.line("vpn")
        out = t.expect(R.PROMPT)
        assert "VPN: off" in out, out
        srv.stop()

    @step("TCP, tls-auth with key-direction, net30 topology, AES-128-GCM")
    def _():
        nonlocal srv
        srv = Server(d, f"--proto tcp-server --topology net30 --tls-auth {d}/ta.key 0 --data-ciphers AES-128-GCM")
        put("tcp.ovpn", ovpn(d, "tcp", f"key-direction 1\n<tls-auth>\n{open(d + '/ta.key').read()}</tls-auth>\n"))
        vpn_up("tcp.ovpn")
        roundtrip("tcp")
        t.line("ip a")
        out = t.expect(R.PROMPT)
        assert re.search(r"inet 10\.8\.0\.6 peer 10\.8\.0\.5 scope global tun0", out), out   # net30
        t.line("ip r")
        out = t.expect(R.PROMPT)
        assert "10.8.0.5 dev tun0 scope link src 10.8.0.6" in out, out
        assert any("AES-128-GCM" in l and "tunnel address 10.8.0.6" in l for l in sim.log), sim.log[-5:]
        vpn_down()
        srv.stop()

    @step("username/password: refused, then accepted; verify-x509-name; wrong CA; unsupported options")
    def _():
        nonlocal srv
        chk = f"{d}/check.sh"
        with open(chk, "w") as f:
            f.write('#!/bin/sh\n[ "$username" = alice ] && [ "$password" = wonderland ]\n')
        os.chmod(chk, 0o755)
        srv = Server(d, f"--proto udp --topology subnet --verify-client-cert none --username-as-common-name "
                        f"--script-security 3 --auth-user-pass-verify {chk} via-env --auth-gen-token 3600")
        ca = open(f"{d}/ca.crt").read()
        put("pw.ovpn", f"client\ndev tun\nremote 127.0.0.1 1194 udp\nauth-user-pass\nverify-x509-name vpn- name-prefix\n"
                       f"<ca>\n{ca}</ca>\n")
        t.line("vpn up pw.ovpn")
        t.expect("VPN username: ")
        t.line("alice")
        t.expect("VPN password: ")
        t.line("wrong")
        out = t.expect(R.PROMPT, timeout=45)
        assert "refused the login" in out, out
        t.line("vpn up pw.ovpn")
        t.expect("VPN username: ")
        t.line("alice")
        t.expect("VPN password: ")
        t.line("wonderland")
        out = t.expect(R.PROMPT, timeout=45)
        assert "VPN up" in out and "wonderland" not in out, out
        vpn_down()
        put("creds.txt", "alice\nwonderland\n")
        put("name.ovpn", f"client\ndev tun\nremote 127.0.0.1 1194 udp\nauth-user-pass creds.txt\n"
                         f"verify-x509-name other-server name\n<ca>\n{ca}</ca>\n")
        vpn_up("name.ovpn", "TLS handshake failed")
        assert any("not 'other-server'" in l for l in sim.log), sim.log[-5:]
        put("ca.ovpn", f"client\ndev tun\nremote 127.0.0.1 1194 udp\nauth-user-pass creds.txt\n"
                       f"<ca>\n{open(d + '/other.crt').read()}</ca>\n")
        vpn_up("ca.ovpn", "TLS handshake failed")
        put("tap.ovpn", "client\ndev tap\nremote 127.0.0.1\n")
        vpn_up("tap.ovpn", "only 'dev tun' is supported")
        put("v2.ovpn", "client\ndev tun\nremote 127.0.0.1\n<tls-crypt-v2>\nx\n</tls-crypt-v2>\n")
        vpn_up("v2.ovpn", "<tls-crypt-v2> is not supported")
        srv.stop()

    @step("the server renegotiates the keys (reneg-sec 15): the tunnel keeps working")
    def _():
        nonlocal srv
        srv = Server(d, f"--proto udp --topology subnet --tls-crypt {d}/ta.key --reneg-sec 15")
        vpn_up("vpn.ovpn")
        time.sleep(33)
        roundtrip("reneg")
        renewed = sum("keys renewed" in l for l in sim.log)
        assert renewed >= 2, sim.log[-10:]
        vpn_down()
        srv.stop()
        return f"{renewed} key renewals"

    try:
        for name, fn in steps:
            t0 = time.time()
            try:
                note = fn()
                print(f"  ok    {name}{' - ' + note if note else ''}  ({time.time() - t0:.1f}s)", flush=True)
            except AssertionError as e:
                failed += 1
                print(f"  FAIL  {name}\n        {str(e).replace(chr(10), chr(10) + '        ')}", flush=True)
                print("        ---- simulator log (tail) ----\n        " + "\n        ".join(sim.log[-25:]))
                if srv:
                    print("        ---- openvpn log (tail) ----\n        " +
                          "\n        ".join(open(srv.log).read().splitlines()[-25:]))
                break
    finally:
        room = [int(m.group(1)) for l in sim.log for m in [re.search(r"vpn: stopped \(stack headroom was (\d+)", l)] if m]
        if room:
            print(f"\n  smallest VPN thread stack headroom seen: {min(room)} bytes (x86-64 build)")
        if srv:
            srv.stop()
        sim.stop()
        sshd_p.terminate()
        shutil.rmtree(d, ignore_errors=True)
    print("\nVPN TESTS PASSED" if not failed else "\nVPN TESTS FAILED")
    return 1 if failed else 0


def main():
    if os.environ.get("C3_IN_NETNS"):
        sh("ip link set lo up")
        sys.exit(main_inside())
    if not shutil.which("openvpn"):
        print("  skipped: openvpn is not installed")
        return
    probe = subprocess.run(["unshare", "--user", "--map-current-user", "--net", "--keep-caps", "true"],
                           capture_output=True)
    if probe.returncode != 0:
        print("  skipped: unprivileged user namespaces are not available")
        return
    env = dict(os.environ, C3_IN_NETNS="1")
    r = subprocess.run(["unshare", "--user", "--map-current-user", "--net", "--keep-caps",
                        sys.executable, os.path.abspath(__file__)], env=env)
    sys.exit(r.returncode)


if __name__ == "__main__":
    main()
