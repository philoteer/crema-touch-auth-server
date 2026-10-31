#!/usr/bin/env python3
"""Temporary, isolated hostapd hotspot for Crema Touch offline activation."""

import argparse
import fcntl
import grp
import http.client
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shlex
import shutil
import signal
import socket
import stat
import string
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
from activation_server import SHOPCODES, crypt


RUNTIME = Path("/run/crema-revive")
TABLE = "crema_revive"
TOOLS = ("hostapd", "dnsmasq", "iw", "ip", "nmcli", "nft", "openssl")
ENV = dict(os.environ, LC_ALL="C", LANG="C", PATH="/usr/sbin:/usr/bin:/sbin:/bin")
PRIVATE = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


class SetupError(RuntimeError):
    pass


class Interrupted(Exception):
    def __init__(self, signum):
        self.signum = signum


def invocation(*arguments):
    # Diagnostics must work regardless of the caller's working directory.
    return shlex.join(["sudo", "python3", str(Path(__file__).resolve()), *arguments])


def daemon_account(name=None):
    """Use an existing unprivileged account without creating/modifying users."""
    candidates = (name,) if name else ("dnsmasq", "_dnsmasq", "nobody")
    for candidate in candidates:
        try:
            account = pwd.getpwnam(candidate)
        except KeyError:
            continue
        if account.pw_uid == 0:
            if name:
                raise SetupError("--dnsmasq-user must name an unprivileged account, not root")
            continue
        return account
    if name:
        raise SetupError(f"unprivileged account {name!r} was not found")
    raise SetupError(
        "no unprivileged daemon account found; use --dnsmasq-user with an existing "
        "non-root account (normally supplied by your distribution's dnsmasq package)"
    )


def http_account(fallback):
    """Prefer the sudo caller; direct root runs use the selected daemon account."""
    try:
        uid = int(os.environ.get("SUDO_UID", "0"))
    except ValueError as exc:
        raise SetupError("SUDO_UID is not a valid numeric user ID") from exc
    if uid < 0:
        raise SetupError("SUDO_UID must not be negative")
    if uid == 0:
        return fallback
    try:
        return pwd.getpwuid(uid)
    except KeyError as exc:
        raise SetupError(f"sudo caller UID {uid} has no local account") from exc


def radio_handoff_failure(log):
    return "Could not configure driver mode" in log and "AP-ENABLED" not in log


def say(message):
    print(message, flush=True)


def command(args, check=True, **kwargs):
    result = subprocess.run(
        [str(x) for x in args], capture_output=True, text=True, env=ENV,
        timeout=20, **kwargs,
    )
    if check and result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise SetupError(f"{' '.join(str(x) for x in args)} failed: {detail}")
    return result


def json_command(args):
    return json.loads(command(args).stdout)


def interface_name(value):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", value) or value == "lo":
        raise argparse.ArgumentTypeError("invalid Wi-Fi interface name")
    return value


def subnet_value(value):
    try:
        net = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    if net.version != 4 or net.prefixlen != 24 or not any(net.subnet_of(n) for n in PRIVATE):
        raise argparse.ArgumentTypeError("choose an RFC1918 private IPv4 /24, e.g. 10.77.0.0/24")
    return net


def network_values(subnet):
    return str(subnet.network_address + 1), f"{subnet.network_address + 1}/24"


def hostapd_config(iface, ssid, password, channel):
    return f"""interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
ieee80211n=0
wmm_enabled=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase={password}
rsn_pairwise=CCMP
ieee80211w=0
ap_isolate=1
max_num_sta=2
logger_stdout=-1
logger_stdout_level=2
"""


def dnsmasq_config(iface, subnet, runtime, user, group):
    gateway, _ = network_values(subnet)
    return f"""interface={iface}
except-interface=lo
listen-address={gateway}
bind-interfaces
no-resolv
no-hosts
local=/#/
address=/mng.k-epub.co.kr/{gateway}
address=/mng2.k-epub.co.kr/{gateway}
dhcp-authoritative
dhcp-range={subnet.network_address + 20},{subnet.network_address + 50},255.255.255.0,1h
dhcp-option=option:router,{gateway}
dhcp-option=option:dns-server,{gateway}
dhcp-leasefile={runtime}/dnsmasq/leases
pid-file={runtime}/dnsmasq/pid
user={user}
group={group}
log-facility=-
log-dhcp
log-queries
"""


def firewall_rules(iface, subnet):
    gateway, _ = network_values(subnet)
    interface = json.dumps(iface)
    # No masquerading, global forwarding toggle, or changes to existing tables.
    # Accepts here intentionally do not override another firewall's drops.
    return f"""table inet {TABLE} {{
    chain prerouting {{
        type nat hook prerouting priority -110; policy accept;
        iifname {interface} ip saddr {subnet} udp dport 53 redirect to :53
        iifname {interface} ip saddr {subnet} tcp dport 53 redirect to :53
        iifname {interface} ip saddr {subnet} tcp dport 80 redirect to :8080
    }}
    chain input {{
        type filter hook input priority -10; policy accept;
        iifname {interface} udp sport 68 udp dport 67 accept
        iifname {interface} ip saddr {subnet} ip daddr {gateway} udp dport 53 accept
        iifname {interface} ip saddr {subnet} ip daddr {gateway} tcp dport {{ 53, 8080 }} accept
        iifname {interface} drop
        iifname != "lo" ip daddr {gateway} udp dport {{ 53, 67 }} drop
        iifname != "lo" ip daddr {gateway} tcp dport {{ 53, 8080 }} drop
    }}
    chain output {{
        type filter hook output priority -10; policy accept;
        oifname {interface} ip saddr {gateway} udp sport {{ 53, 67 }} accept
        oifname {interface} ip saddr {gateway} tcp sport {{ 53, 8080 }} accept
        oifname {interface} drop
    }}
    chain forward {{
        type filter hook forward priority -10; policy accept;
        iifname {interface} drop
        oifname {interface} drop
    }}
}}
"""


def process_start(pid):
    try:
        # /proc stat field 22; comm in parentheses can contain spaces.
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def stop_child(child):
    pid, started = child["pid"], child["start"]
    if started is None or process_start(pid) != started:
        return
    try:
        if os.getpgid(pid) != pid:
            raise SetupError(f"will not signal unexpected process group for PID {pid}")
        os.killpg(pid, signal.SIGTERM)
        deadline = time.monotonic() + 4
        while process_start(pid) == started and time.monotonic() < deadline:
            # Reap our own child if possible; recovery may not be its parent.
            try:
                if os.waitpid(pid, os.WNOHANG)[0]:
                    return
            except ChildProcessError:
                pass
            status = Path(f"/proc/{pid}/stat")
            try:
                if status.read_text().rsplit(")", 1)[1].split()[0] == "Z":
                    return
            except FileNotFoundError:
                return
            time.sleep(0.05)
        if process_start(pid) == started:
            os.killpg(pid, signal.SIGKILL)
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
    except ProcessLookupError:
        pass


def write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(text)


def save_state(state, runtime=None):
    runtime = RUNTIME if runtime is None else runtime
    temporary = runtime / "state.new"
    write_private(temporary, json.dumps(state, indent=2) + "\n")
    os.replace(temporary, runtime / "state.json")


def validate_runtime(runtime=None):
    runtime = RUNTIME if runtime is None else runtime
    info = runtime.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise SetupError(f"unsafe runtime directory: {runtime}")


def runtime_lock(runtime=None):
    runtime = RUNTIME if runtime is None else runtime
    fd = os.open(runtime / "lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(fd)
        raise SetupError("another hotspot/cleanup process is still running; stop it first") from exc
    return fd


def preflight(args):
    missing = [tool for tool in TOOLS if not shutil.which(tool, path=ENV["PATH"])]
    if missing:
        raise SetupError(
            "Missing tools: " + ", ".join(missing) + "\n"
            "Debian/Ubuntu: sudo apt install --no-install-recommends "
            "python3 openssl hostapd dnsmasq-base iw nftables iproute2 network-manager\n"
            "Other distributions: install equivalent packages; see README.md."
        )
    if not args.interface:
        candidates = [p.name for p in Path("/sys/class/net").iterdir() if (p / "wireless").exists()]
        if len(candidates) != 1:
            raise SetupError("specify --interface; could not identify exactly one Wi-Fi interface")
        args.interface = interface_name(candidates[0])
    iface = args.interface
    if not (Path("/sys/class/net") / iface / "wireless").exists():
        raise SetupError(f"{iface} is not a wireless interface")
    defaults = json_command(["ip", "-j", "-4", "route", "show", "default"])
    if any(r.get("dev") == iface for r in defaults):
        raise SetupError("Wi-Fi has a default route; move to Ethernet and disconnect Wi-Fi first")
    address = json_command(["ip", "-j", "address", "show", "dev", iface])[0]
    if address.get("addr_info"):
        raise SetupError(f"{iface} still has IP addresses; disconnect it first with nmcli device disconnect {iface}")
    routes = json_command(["ip", "-j", "-4", "route", "show", "table", "all"])
    for route in routes:
        dst = route.get("dst", "default")
        if dst == "default":
            continue
        try:
            existing = ipaddress.ip_network(dst, strict=False)
        except ValueError:
            continue
        if existing.overlaps(args.subnet):
            raise SetupError(f"AP subnet overlaps existing route {dst}; choose another --subnet")
    nm = command(["nmcli", "-g", "GENERAL.NM-MANAGED,GENERAL.AUTOCONNECT,GENERAL.CON-UUID", "device", "show", iface]).stdout.splitlines()
    if len(nm) != 3 or nm[0] not in ("yes", "no") or nm[1] not in ("yes", "no"):
        raise SetupError("could not read NetworkManager's original device settings")
    if nm[2] not in ("", "--"):
        raise SetupError("Wi-Fi has an active NetworkManager connection; disconnect it first")
    info = command(["iw", "dev", iface, "info"]).stdout
    mode = re.search(r"^\s*type (\S+)", info, re.M)
    phy = re.search(r"^\s*wiphy (\d+)", info, re.M)
    if not mode or mode[1] != "managed" or not phy:
        raise SetupError("Wi-Fi must initially be in ordinary managed/station mode")
    capabilities = command(["iw", "phy", "phy" + phy[1], "info"]).stdout
    if not re.search(r"^\s*\* AP\s*$", capabilities, re.M):
        raise SetupError("wireless driver does not advertise AP support")
    frequency = next((line for line in capabilities.splitlines() if re.search(rf"MHz \[{args.channel}\]", line)), "")
    if not frequency or "disabled" in frequency or "no IR" in frequency:
        raise SetupError(f"channel {args.channel} cannot start an AP under the current regulatory settings")
    phy_path = (Path("/sys/class/net") / iface / "phy80211").resolve()
    peers = [p.name for p in Path("/sys/class/net").iterdir()
             if p.name != iface and (p / "phy80211").exists() and (p / "phy80211").resolve() == phy_path]
    if peers:
        raise SetupError("other interfaces share this radio: " + ", ".join(peers))
    if crypt(crypt(b"crema self-test"), decrypt=True) != b"crema self-test":
        raise SetupError("OpenSSL 3DES self-test failed")
    dns_user = daemon_account(args.dnsmasq_user)
    ipv6_path = Path(f"/proc/sys/net/ipv6/conf/{iface}/disable_ipv6")
    snapshot = {
        "managed": nm[0], "autoconnect": nm[1], "type": mode[1],
        "mac": address["address"], "link_up": "UP" in address.get("flags", []),
        "ipv6_disabled": ipv6_path.read_text().strip() if ipv6_path.exists() else None,
    }
    return snapshot, dns_user


def cleanup(state, runtime=None):
    """Best-effort rollback, retaining the journal if any operation fails."""
    runtime = RUNTIME if runtime is None else runtime
    errors = []

    def attempt(label, operation):
        try:
            operation()
            save_state(state, runtime)
        except Exception as exc:
            errors.append(f"{label}: {exc}")

    for child in list(reversed(state["children"])):
        def stop(child=child):
            stop_child(child)
            state["children"].remove(child)
        attempt(f"stop {child['name']}", stop)

    if state["firewall_added"]:
        def remove_firewall():
            rules = json_command(["nft", "-j", "list", "tables"])
            exists = any(item.get("table", {}).get("family") == "inet" and
                         item.get("table", {}).get("name") == TABLE for item in rules["nftables"])
            if exists:
                command(["nft", "delete", "table", "inet", TABLE])
            state["firewall_added"] = False
        attempt("remove private firewall table", remove_firewall)

    iface = state["interface"]
    if state["address_added"]:
        def remove_address():
            addresses = json_command(["ip", "-j", "-4", "address", "show", "dev", iface])
            gateway, prefix = state["address"].split("/")
            if any(a.get("local") == gateway and a.get("prefixlen") == int(prefix)
                   for device in addresses for a in device.get("addr_info", [])):
                command(["ip", "address", "del", state["address"], "dev", iface])
            state["address_added"] = False
        attempt("remove AP address", remove_address)

    if state["interface_changed"]:
        def restore_interface():
            old = state["snapshot"]
            command(["ip", "link", "set", "dev", iface, "down"])
            command(["iw", "dev", iface, "set", "type", old["type"]])
            command(["ip", "link", "set", "dev", iface, "address", old["mac"]])
            if old["ipv6_disabled"] is not None:
                Path(f"/proc/sys/net/ipv6/conf/{iface}/disable_ipv6").write_text(old["ipv6_disabled"] + "\n")
            if old["link_up"]:
                command(["ip", "link", "set", "dev", iface, "up"])
            if old["managed"] == "yes":
                command(["nmcli", "device", "set", iface, "managed", "yes"])
                command(["nmcli", "device", "set", iface, "autoconnect", old["autoconnect"]])
            state["interface_changed"] = False
        attempt("restore Wi-Fi/NetworkManager", restore_interface)
    return errors


class Hotspot:
    def __init__(self, args, snapshot, dns_user):
        self.args = args
        self.dns_user = dns_user
        self.gateway, address = network_values(args.subnet)
        self.state = {
            "version": 1, "interface": args.interface, "address": address,
            "snapshot": snapshot, "children": [], "interface_changed": False,
            "address_added": False, "firewall_added": False,
        }
        self.processes = {}
        self.log_positions = {}
        self.stop_signal = None

    def check_stop(self):
        if self.stop_signal is not None:
            raise Interrupted(self.stop_signal)

    def run(self, args, **kwargs):
        self.check_stop()
        result = command(args, **kwargs)
        self.check_stop()
        return result

    def mark(self, flag):
        self.state[flag] = True
        save_state(self.state)

    def prepare_files(self):
        password = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
        user = self.dns_user
        leases = RUNTIME / "dnsmasq"
        leases.mkdir(mode=0o700)
        os.chown(leases, user.pw_uid, user.pw_gid)
        write_private(RUNTIME / "hostapd.conf", hostapd_config(self.args.interface, self.args.ssid, password, self.args.channel))
        write_private(RUNTIME / "dnsmasq.conf", dnsmasq_config(
            self.args.interface, self.args.subnet, RUNTIME, user.pw_name,
            grp.getgrgid(user.pw_gid).gr_name,
        ))
        write_private(RUNTIME / "firewall.nft", firewall_rules(self.args.interface, self.args.subnet))
        # The unprivileged HTTP process must not need access to the user's home.
        shutil.copyfile(Path(__file__).with_name("activation_server.py"), RUNTIME / "activation_server.py")
        os.chmod(RUNTIME / "activation_server.py", 0o644)
        self.run(["dnsmasq", "--test", f"--conf-file={RUNTIME / 'dnsmasq.conf'}"])
        self.run(["nft", "--check", "--file", RUNTIME / "firewall.nft"])
        return password

    def start_child(self, name, args, **kwargs):
        self.check_stop()
        with open(RUNTIME / f"{name}.log", "xb", buffering=0) as log:
            os.chmod(log.name, 0o600)
            process = subprocess.Popen(
                [str(x) for x in args], stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                env=ENV, start_new_session=True, umask=0o077, **kwargs,
            )
        self.processes[name] = process
        self.state["children"].append({"name": name, "pid": process.pid, "start": process_start(process.pid)})
        save_state(self.state)
        self.check_stop()

    def assert_children(self, exclude=()):
        for name, process in self.processes.items():
            if name in exclude:
                continue
            code = process.poll()
            if code is not None:
                raise SetupError(f"{name} exited unexpectedly (status {code}); see log below")

    def wait_for_unmanaged(self, timeout=10):
        """nmcli's setter may return before its Wi-Fi/supplicant teardown ends."""
        if self.state["snapshot"]["managed"] != "yes":
            return
        deadline = time.monotonic() + timeout
        while True:
            result = self.run([
                "nmcli", "-g", "GENERAL.NM-MANAGED,GENERAL.STATE",
                "device", "show", self.args.interface,
            ], check=False)
            values = result.stdout.splitlines()
            if (result.returncode == 0 and len(values) == 2 and values[0] == "no"
                    and values[1].split()[0:1] == ["10"]):
                return
            if time.monotonic() >= deadline:
                raise SetupError(f"NetworkManager did not release the Wi-Fi device within {timeout:g} seconds")
            time.sleep(0.25)

    def prepare_radio(self, timeout=10):
        """Wait for the kernel to accept AP mode, not just an NM acknowledgement."""
        iface = self.args.interface
        deadline = time.monotonic() + timeout
        announced = False
        while True:
            self.run(["ip", "link", "set", "dev", iface, "down"])
            result = self.run(["iw", "dev", iface, "set", "type", "__ap"], check=False)
            detail = result.stderr.strip() or result.stdout.strip()
            if result.returncode == 0:
                info = self.run(["iw", "dev", iface, "info"]).stdout
                if re.search(r"^\s*type AP\s*$", info, re.M):
                    return
                detail = "interface did not stay in AP mode"
            elif not any(error in detail.lower() for error in (
                    "device or resource busy", "resource temporarily unavailable",
                    "operation already in progress", "(-16)", "(-11)", "(-114)")):
                raise SetupError(f"could not put {iface} in AP mode: {detail}")
            if time.monotonic() >= deadline:
                raise SetupError(f"radio did not become available for AP mode within {timeout:g} seconds: {detail}")
            if not announced:
                say(f"Waiting for {iface}'s previous radio owner to release AP mode...")
                announced = True
            time.sleep(0.25)

    def retire_child(self, name):
        """Retire only our recorded process before reusing its name on a retry."""
        process = self.processes[name]
        child = next(child for child in self.state["children"] if child["pid"] == process.pid)
        stop_child(child)
        self.state["children"].remove(child)
        del self.processes[name]
        save_state(self.state)

    def start_access_point(self, attempts=3):
        for attempt in range(1, attempts + 1):
            self.start_child("hostapd", ["hostapd", RUNTIME / "hostapd.conf"])
            deadline = time.monotonic() + 30
            while True:
                self.check_stop()
                # An HTTP/DHCP failure must never be hidden by a radio retry.
                self.assert_children(exclude=("hostapd",))
                code = self.processes["hostapd"].poll()
                log = (RUNTIME / "hostapd.log").read_text(errors="replace")
                if code is not None:
                    if attempt < attempts and radio_handoff_failure(log):
                        say(f"hostapd hit a radio-mode handoff error; retrying ({attempt + 1}/{attempts})...")
                        self.retire_child("hostapd")
                        (RUNTIME / "hostapd.log").rename(RUNTIME / f"hostapd-attempt-{attempt}.log")
                        self.wait_for_unmanaged()
                        self.prepare_radio()
                        self.check_stop()
                        time.sleep(0.5)
                        break
                    raise SetupError(f"hostapd exited unexpectedly (status {code}); see log below")
                if "AP-ENABLED" in log and self.http_ready() and self.dns_ready():
                    return
                if time.monotonic() >= deadline:
                    raise SetupError("AP/DNS/HTTP did not become ready within 30 seconds")
                time.sleep(0.25)

    def setup(self):
        password = self.prepare_files()
        iface = self.args.interface
        say(f"Taking temporary ownership of {iface}; Ethernet and existing firewall tables are untouched.")
        self.mark("interface_changed")
        if self.state["snapshot"]["managed"] == "yes":
            self.run(["nmcli", "device", "set", iface, "autoconnect", "no"])
            self.run(["nmcli", "device", "set", iface, "managed", "no"])
        self.wait_for_unmanaged()
        self.prepare_radio()
        ipv6 = self.state["snapshot"]["ipv6_disabled"]
        if ipv6 is not None:
            Path(f"/proc/sys/net/ipv6/conf/{iface}/disable_ipv6").write_text("1\n")
        self.mark("address_added")
        self.run(["ip", "address", "add", self.state["address"], "dev", iface])
        self.run(["ip", "link", "set", "dev", iface, "up"])
        self.mark("firewall_added")
        self.run(["nft", "--file", RUNTIME / "firewall.nft"])
        http_user = http_account(self.dns_user)
        self.start_child("http", [
            sys.executable, "-I", "-u", RUNTIME / "activation_server.py",
            "--bind", self.gateway, "--port", "8080",
            "--client-subnet", str(self.args.subnet), "--shopcode", self.args.shopcode,
        ], user=http_user.pw_uid, group=http_user.pw_gid, extra_groups=[], cwd="/")
        self.start_child("dnsmasq", ["dnsmasq", "--keep-in-foreground", f"--conf-file={RUNTIME / 'dnsmasq.conf'}"])
        self.start_access_point()
        say(f"\nAP READY\n  SSID:     {self.args.ssid}\n  Password: {password}\n"
            f"  Address:  {self.gateway}\n  Branding: {self.args.shopcode}\n\n"
            "Connect ONLY the Crema Touch and press its registration/continue button.\n"
            "The AP intentionally has no Internet. Keep this terminal open.\n"
            "After success, test a local book. Ctrl+C stops the AP and restores Wi-Fi.\n")

    def http_ready(self):
        connection = http.client.HTTPConnection(self.gateway, 8080, timeout=0.4)
        try:
            connection.request("GET", "/healthz")
            reply = connection.getresponse()
            return reply.status == 200 and reply.read() == b"ready\n"
        except (OSError, http.client.HTTPException):
            return False
        finally:
            connection.close()

    def dns_ready(self):
        transaction = secrets.token_bytes(2)
        question = b"\x04mng2\x06k-epub\x02co\x02kr\x00\x00\x01\x00\x01"
        packet = transaction + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.4)
                sock.sendto(packet, (self.gateway, 53))
                reply = sock.recv(2048)
            return (len(reply) > 12 and reply[:2] == transaction and reply[3] & 15 == 0
                    and int.from_bytes(reply[6:8], "big") > 0
                    and reply[-4:] == socket.inet_aton(self.gateway))
        except OSError:
            return False

    def monitor(self):
        while True:
            self.check_stop()
            self.assert_children()
            for name in ("http", "hostapd", "dnsmasq"):
                path = RUNTIME / f"{name}.log"
                with path.open(errors="replace") as stream:
                    stream.seek(self.log_positions.get(name, 0))
                    for line in stream:
                        if name == "http" or any(word in line for word in ("AP-STA-", "DHCPACK", "DHCPDISCOVER")):
                            say(f"[{name}] {line.rstrip()}")
                    self.log_positions[name] = stream.tell()
            time.sleep(0.5)


def print_logs():
    for name in ("hostapd", "dnsmasq", "http"):
        path = RUNTIME / f"{name}.log"
        if path.exists():
            say(f"\n--- {name}: last 15 log lines ---")
            say("\n".join(path.read_text(errors="replace").splitlines()[-15:]))


def keep_logs():
    destination = Path(tempfile.mkdtemp(prefix="crema-revive-logs-"))
    uid = int(os.environ.get("SUDO_UID", os.getuid()))
    gid = pwd.getpwuid(uid).pw_gid
    for path in RUNTIME.glob("*.log"):
        target = destination / path.name
        shutil.copyfile(path, target)
        os.chmod(target, 0o600)
        os.chown(target, uid, gid)
    os.chown(destination, uid, gid)
    say(f"Diagnostic logs saved to {destination} (may include client MAC/DNS data).")


def recover():
    if not RUNTIME.exists():
        say("No saved hotspot state; nothing to clean up.")
        return 0
    validate_runtime()
    lock = runtime_lock()
    try:
        journal = RUNTIME / "state.json"
        if not journal.exists() and {p.name for p in RUNTIME.iterdir()} <= {"lock", "state.new"}:
            # Initialization was interrupted before any network change could run.
            shutil.rmtree(RUNTIME)
            say("Removed an interrupted initialization; no network changes had started.")
            return 0
        state = json.loads(journal.read_text())
        if state.get("version") != 1:
            raise SetupError("unrecognized recovery-state version; do not remove it manually")
        interface_name(state["interface"])
        errors = cleanup(state)
        if errors:
            raise SetupError("Cleanup incomplete; state retained:\n" + "\n".join(errors))
        shutil.rmtree(RUNTIME)
        say("Recovered: private AP processes, address, firewall, and Wi-Fi settings cleaned up.")
        return 0
    finally:
        os.close(lock)


def parser():
    result = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    result.add_argument("--interface", type=interface_name, help="Wi-Fi device; autodetect if exactly one")
    result.add_argument("--ssid", default="Crema-Revive")
    result.add_argument("--channel", type=int, choices=(1, 6, 11), default=1)
    result.add_argument("--subnet", type=subnet_value, default=subnet_value("10.77.0.0/24"))
    result.add_argument("--shopcode", choices=SHOPCODES, default="keph_yes24")
    result.add_argument("--dnsmasq-user", help="existing non-root daemon account; autodetect dnsmasq, _dnsmasq, or nobody")
    mode = result.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="read-only preflight, no root or network changes")
    mode.add_argument("--cleanup", action="store_true", help="recover a previous run after forced termination; needs root")
    result.add_argument("--keep-logs", action="store_true", help="retain diagnostic logs, but not password/config/leases")
    return result


def main(argv=None):
    os.umask(0o077)
    if sys.version_info < (3, 9):
        raise SetupError("Python 3.9 or newer is required")
    args = parser().parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9 _.-]{1,32}", args.ssid):
        raise SetupError("SSID must be 1-32 ASCII letters, digits, spaces, _, ., or -")
    if not args.check and os.geteuid() != 0:
        raise SetupError(f"network setup needs root. Use {invocation('--interface', args.interface or 'YOUR_WIFI')}; no permanent permissions are needed")
    if args.cleanup:
        previous = {s: signal.signal(s, signal.SIG_IGN)
                    for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
        try:
            return recover()
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
    snapshot, dns_user = preflight(args)
    say(f"Preflight OK: {args.interface} supports AP mode; subnet {args.subnet}; OpenSSL 3DES works.")
    if args.check:
        say("Read-only check complete. Privileged firewall/daemon startup still needs a real run.")
        return 0
    if RUNTIME.exists():
        raise SetupError(f"{RUNTIME} already exists. Stop the previous run or use {invocation('--cleanup')} first.")
    tables = json_command(["nft", "-j", "list", "tables"])
    if any(item.get("table", {}).get("family") == "inet" and item.get("table", {}).get("name") == TABLE
           for item in tables["nftables"]):
        raise SetupError(f"firewall table inet {TABLE} already exists without our runtime state; refusing to overwrite it")
    hotspot = Hotspot(args, snapshot, dns_user)
    lock = None
    runtime_created = False
    exit_code = 0
    previous = {}

    def interrupted(signum, frame):
        # Do not raise between Popen() and journaling its PID, or halfway through
        # an atomic state update. Stop at the next explicit safe checkpoint.
        hotspot.stop_signal = signum

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        previous[signum] = signal.signal(signum, interrupted)
    try:
        RUNTIME.mkdir(mode=0o711)
        runtime_created = True
        # umask protects all files; dropped daemon users need directory traversal.
        RUNTIME.chmod(0o711)
        lock = runtime_lock()
        save_state(hotspot.state)
        hotspot.check_stop()
        hotspot.setup()
        hotspot.monitor()
    except Interrupted as exc:
        say("\nStopping hotspot and restoring the original Wi-Fi state...")
        exit_code = 0 if exc.signum == signal.SIGINT else 128 + exc.signum
    except Exception as exc:
        if hotspot.stop_signal is not None:
            say("\nStop requested; restoring the original Wi-Fi state...")
            exit_code = 0 if hotspot.stop_signal == signal.SIGINT else 128 + hotspot.stop_signal
        else:
            say(f"\nERROR: {exc}")
            if runtime_created:
                print_logs()
            exit_code = 1
    finally:
        # A second Ctrl+C must not interrupt the rollback halfway through.
        for signum in previous:
            signal.signal(signum, signal.SIG_IGN)
        try:
            errors = cleanup(hotspot.state) if runtime_created else []
            if args.keep_logs and runtime_created:
                try:
                    keep_logs()
                except Exception as exc:
                    say(f"Could not preserve logs: {exc}")
            if errors:
                say("CLEANUP INCOMPLETE; recovery state retained:\n" + "\n".join(errors))
                say(f"Retry: {invocation('--cleanup')}")
                exit_code = 1
            elif runtime_created:
                shutil.rmtree(RUNTIME)
                say("Cleanup complete: AP stopped, original Wi-Fi settings restored. Ethernet untouched.")
        finally:
            if lock is not None:
                os.close(lock)
            for signum, handler in previous.items():
                signal.signal(signum, handler)
    return exit_code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (SetupError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
