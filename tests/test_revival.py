"""Unprivileged tests: real localhost HTTP/3DES; mocked network rollback."""

import copy
import http.client
import json
import logging
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import urlencode
import xml.etree.ElementTree as ET
import base64


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import activation_server as activation
import hotspot


def request_body(action="1", serial="LAB_SERIAL", **overrides):
    root = ET.Element("data", version="1")
    ET.SubElement(root, "actcode").text = action
    ET.SubElement(root, "sn").text = serial
    ciphertext = activation.crypt(ET.tostring(root))
    # Android's DEFAULT Base64 contains line breaks, which the form URL-encodes.
    encoded = base64.encodebytes(ciphertext).decode()
    form = {"key": activation.KEY.decode(), "iv": activation.IV.decode(), "data": encoded}
    form.update(overrides)
    return urlencode(form).encode()


class ProtocolTests(unittest.TestCase):
    def test_3des_round_trip(self):
        plaintext = b'<data version="1"><retcode>0</retcode></data>'
        self.assertEqual(activation.crypt(activation.crypt(plaintext), True), plaintext)

    def test_android_form_and_base64_newlines(self):
        self.assertEqual(activation.decode_request(request_body()), ("1", "LAB_SERIAL"))

    def test_missing_duplicate_and_unknown_fields(self):
        for body in (b"key=x", request_body() + b"&key=duplicate", request_body() + b"&extra=x"):
            with self.subTest(body_length=len(body)), self.assertRaises(activation.BadRequest):
                activation.decode_request(body)

    def test_bad_key_base64_action_and_serial(self):
        bodies = [request_body(key="wrong"), request_body(data="!not_base64!"),
                  request_body("99"), request_body(serial=""), request_body(serial="x" * 129)]
        for body in bodies:
            with self.subTest(body_length=len(body)), self.assertRaises(activation.BadRequest):
                activation.decode_request(body)

    def test_success_fields_and_xml_escaping(self):
        serial = "LAB<&SERIAL"
        body = activation.encode_response("1", serial, "keph_aladin")
        root = ET.fromstring(activation.crypt(base64.b64decode(body), True))
        self.assertEqual(root.findtext("retcode"), "0")
        self.assertEqual(root.findtext("sn"), serial)
        self.assertEqual(root.findtext("shopcode"), "keph_aladin")

    def test_update_response_never_offers_firmware(self):
        body = activation.encode_response("2", "LAB_SERIAL", "keph_yes24")
        root = ET.fromstring(activation.crypt(base64.b64decode(body), True))
        self.assertLess(int(root.findtext("retcode")), 0)
        self.assertEqual(root.findall("app"), [])

    def test_xml_entity_declaration_rejected(self):
        xml = b'<!DOCTYPE data [<!ENTITY x "hello">]><data version="1"><actcode>1</actcode><sn>&x;</sn></data>'
        body = urlencode({"key": activation.KEY.decode(), "iv": activation.IV.decode(),
                          "data": base64.b64encode(activation.crypt(xml)).decode()}).encode()
        with self.assertRaises(activation.BadRequest):
            activation.decode_request(body)


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = activation.ActivationServer(("127.0.0.1", 0), "keph_aladin", "127.0.0.0/8")
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.old_logging = logging.root.manager.disable
        logging.disable(logging.CRITICAL)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)
        logging.disable(cls.old_logging)

    def request(self, method, path, body=None, host="mng2.k-epub.co.kr", **headers):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        headers = {"Host": host, "Content-Type": "application/x-www-form-urlencoded", **headers}
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            result = response.status, response.read(), dict(response.getheaders())
            self.assertEqual(int(result[2]["Content-Length"]), len(result[1]))
            self.assertEqual(result[2]["Connection"], "close")
            return result
        finally:
            connection.close()

    def test_both_connectivity_checks(self):
        for host, path in (("mng.k-epub.co.kr", "/"), ("mng2.k-epub.co.kr", activation.SERVICE)):
            self.assertEqual(self.request("GET", path, host=host)[0], 200)

    def test_health(self):
        self.assertEqual(self.request("GET", "/healthz")[0:2], (200, b"ready\n"))

    def test_activation_http(self):
        status, body, _ = self.request("POST", activation.SERVICE, request_body())
        self.assertEqual(status, 200)
        root = ET.fromstring(activation.crypt(base64.b64decode(body), True))
        self.assertEqual(root.findtext("retcode"), "0")
        self.assertEqual(root.findtext("sn"), "LAB_SERIAL")
        self.assertEqual(root.findtext("shopcode"), "keph_aladin")

    def test_ota_http(self):
        status, body, _ = self.request("POST", activation.SERVICE, request_body("2"))
        self.assertEqual(status, 200)
        root = ET.fromstring(activation.crypt(base64.b64decode(body), True))
        self.assertEqual(root.findtext("retcode"), "-1")

    def test_unknown_hosts_and_paths(self):
        self.assertEqual(self.request("GET", "/", host="unrelated.example")[0], 404)
        self.assertEqual(self.request("POST", "/unrelated", b"x")[0], 404)

    def test_bad_and_oversized_requests(self):
        self.assertEqual(self.request("POST", activation.SERVICE, b"invalid")[0], 400)
        self.assertEqual(self.request("POST", activation.SERVICE, b"",
                                      **{"Content-Length": str(activation.MAX_BODY + 1)})[0], 413)

    def test_wrong_content_type(self):
        self.assertEqual(self.request("POST", activation.SERVICE, request_body(),
                                      **{"Content-Type": "text/plain"})[0], 400)

    def test_other_network_cannot_access(self):
        self.assertFalse(self.server.verify_request(None, ("192.0.2.1", 1234)))


class ConfigurationTests(unittest.TestCase):
    def test_subnet_validation(self):
        self.assertEqual(str(hotspot.subnet_value("10.77.0.0/24")), "10.77.0.0/24")
        for value in ("0.0.0.0/0", "8.8.8.0/24", "10.77.0.1/24", "::/0", "10.0.0.0/8"):
            with self.subTest(value=value), self.assertRaises(Exception):
                hotspot.subnet_value(value)

    def test_interface_validation(self):
        self.assertEqual(hotspot.interface_name("wlan_test0"), "wlan_test0")
        for value in ("lo", "x\nflush ruleset", "wlan0;evil", "a" * 16):
            with self.subTest(value=value), self.assertRaises(Exception):
                hotspot.interface_name(value)

    def test_hostapd_legacy_wpa2(self):
        config = hotspot.hostapd_config("wlan_test0", "Crema-Revive", "temporary123", 1)
        for setting in ("hw_mode=g", "channel=1", "wpa=2", "rsn_pairwise=CCMP", "ieee80211w=0"):
            self.assertIn(setting + "\n", config)
        self.assertNotIn("country_code", config)
        self.assertNotIn("wpa=3", config)

    def test_dns_is_interface_local_and_without_upstream(self):
        config = hotspot.dnsmasq_config("wlan_test0", hotspot.subnet_value("10.77.0.0/24"),
                                        Path("/run/crema-revive"), "dnsmasq", "nogroup")
        for setting in ("interface=wlan_test0", "bind-interfaces", "no-resolv", "no-hosts",
                        "address=/mng.k-epub.co.kr/10.77.0.1",
                        "address=/mng2.k-epub.co.kr/10.77.0.1"):
            self.assertIn(setting + "\n", config)
        self.assertNotIn("server=", config)

    def test_firewall_does_not_flush_or_share_internet(self):
        rules = hotspot.firewall_rules("wlan_test0", hotspot.subnet_value("10.77.0.0/24"))
        self.assertIn("table inet crema_revive", rules)
        self.assertIn('iifname "wlan_test0" ip saddr 10.77.0.0/24 tcp dport 80 redirect to :8080', rules)
        self.assertIn('iifname "wlan_test0" ip saddr 10.77.0.0/24 udp dport 53 redirect to :53', rules)
        self.assertIn('iifname "wlan_test0" drop', rules)
        self.assertIn('oifname "wlan_test0" drop', rules)
        for forbidden in ("flush", "masquerade", "eth_test0", "policy drop"):
            self.assertNotIn(forbidden, rules)

    def test_diagnostic_command_is_independent_of_current_directory(self):
        result = shlex.split(hotspot.invocation("--cleanup"))
        self.assertEqual(result[:2], ["sudo", "python3"])
        self.assertEqual(Path(result[2]), Path(hotspot.__file__).resolve())
        self.assertEqual(result[3:], ["--cleanup"])

    def test_daemon_user_can_be_selected_without_source_edits(self):
        self.assertIsNone(hotspot.parser().parse_args([]).dnsmasq_user)
        args = hotspot.parser().parse_args(["--dnsmasq-user", "daemon_test"])
        self.assertEqual(args.dnsmasq_user, "daemon_test")

    def test_python_version_checked_before_network_setup(self):
        with patch.object(hotspot.sys, "version_info", (3, 8)), \
             patch.object(hotspot, "preflight") as preflight:
            with self.assertRaisesRegex(hotspot.SetupError, "Python 3.9"):
                hotspot.main([])
            preflight.assert_not_called()

    def test_log_preservation_uses_standard_tempdir_and_only_copies_logs(self):
        with tempfile.TemporaryDirectory(prefix="crema-log-test-") as directory:
            root = Path(directory)
            runtime, destination = root / "runtime", root / "logs"
            runtime.mkdir()
            destination.mkdir()
            (runtime / "http.log").write_text("test log\n")
            (runtime / "hostapd.conf").write_text("wpa_passphrase=NOT_FOR_SHARING\n")
            with patch.object(hotspot, "RUNTIME", runtime), \
                 patch.object(hotspot.tempfile, "mkdtemp", return_value=str(destination)) as create, \
                 patch.object(hotspot.os, "chown"), patch.object(hotspot, "say"), \
                 patch.dict(os.environ, {"SUDO_UID": str(os.getuid())}):
                hotspot.keep_logs()
            create.assert_called_once_with(prefix="crema-revive-logs-")
            self.assertEqual({p.name for p in destination.iterdir()}, {"http.log"})
            self.assertEqual((destination / "http.log").read_text(), "test log\n")
            self.assertEqual((destination / "http.log").stat().st_mode & 0o777, 0o600)


class AccountTests(unittest.TestCase):
    def setUp(self):
        self.account = SimpleNamespace(pw_name="daemon_test", pw_uid=12345, pw_gid=12345)

    def test_autodetection_does_not_depend_on_debian_account_name(self):
        for available in ("dnsmasq", "_dnsmasq", "nobody"):
            def lookup(name):
                if name != available:
                    raise KeyError(name)
                return self.account

            with self.subTest(available=available), \
                 patch.object(hotspot.pwd, "getpwnam", side_effect=lookup):
                self.assertIs(hotspot.daemon_account(), self.account)

    def test_explicit_existing_account(self):
        with patch.object(hotspot.pwd, "getpwnam", return_value=self.account) as lookup:
            self.assertIs(hotspot.daemon_account("daemon_test"), self.account)
            lookup.assert_called_once_with("daemon_test")

    def test_root_account_is_rejected(self):
        root = SimpleNamespace(pw_uid=0)
        with patch.object(hotspot.pwd, "getpwnam", return_value=root):
            with self.assertRaisesRegex(hotspot.SetupError, "not root"):
                hotspot.daemon_account("root")

    def test_missing_explicit_account_does_not_silently_fall_back(self):
        with patch.object(hotspot.pwd, "getpwnam", side_effect=KeyError) as lookup:
            with self.assertRaisesRegex(hotspot.SetupError, "was not found"):
                hotspot.daemon_account("missing_test")
            lookup.assert_called_once_with("missing_test")

    def test_missing_all_default_accounts_explains_override(self):
        with patch.object(hotspot.pwd, "getpwnam", side_effect=KeyError):
            with self.assertRaisesRegex(hotspot.SetupError, "--dnsmasq-user"):
                hotspot.daemon_account()

    def test_http_runs_as_sudo_caller(self):
        with patch.dict(os.environ, {"SUDO_UID": "12345"}), \
             patch.object(hotspot.pwd, "getpwuid", return_value=self.account) as lookup:
            self.assertIs(hotspot.http_account(None), self.account)
            lookup.assert_called_once_with(12345)

    def test_direct_root_http_uses_selected_daemon_account(self):
        with patch.dict(os.environ, {"SUDO_UID": "0"}), \
             patch.object(hotspot.pwd, "getpwuid") as lookup:
            self.assertIs(hotspot.http_account(self.account), self.account)
            lookup.assert_not_called()

    def test_invalid_sudo_uid_is_rejected(self):
        for value in ("invalid", "-1"):
            with self.subTest(value=value), patch.dict(os.environ, {"SUDO_UID": value}):
                with self.assertRaises(hotspot.SetupError):
                    hotspot.http_account(self.account)


class RadioStartupTests(unittest.TestCase):
    failure = "nl80211: Could not configure driver mode\nnl80211 driver initialization failed.\n"

    def setUp(self):
        args = hotspot.parser().parse_args(["--interface", "wlan_test0"])
        self.instance = hotspot.Hotspot(args, {"managed": "yes"}, None)

    @staticmethod
    def result(stdout="", stderr="", returncode=0):
        return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)

    def test_waits_for_networkmanager_state_not_just_the_setter(self):
        replies = [self.result("yes\n30 (disconnected)\n"),
                   self.result("no\n20 (unavailable)\n"), self.result("no\n10 (unmanaged)\n")]
        with patch.object(self.instance, "run", side_effect=replies) as run, \
             patch.object(hotspot.time, "sleep") as sleep:
            self.instance.wait_for_unmanaged()
        self.assertEqual(run.call_count, 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertTrue(all(call.args[0][-1] == "wlan_test0" for call in run.call_args_list))

    def test_networkmanager_handoff_has_a_deadline(self):
        with patch.object(self.instance, "run", return_value=self.result("yes\n30 (disconnected)\n")), \
             patch.object(hotspot.time, "monotonic", side_effect=[0, 11]):
            with self.assertRaisesRegex(hotspot.SetupError, "NetworkManager did not release"):
                self.instance.wait_for_unmanaged()

    def test_already_unmanaged_radio_does_not_wait_on_networkmanager(self):
        self.instance.state["snapshot"]["managed"] = "no"
        with patch.object(self.instance, "run") as run:
            self.instance.wait_for_unmanaged()
            run.assert_not_called()

    def test_busy_radio_retried_until_kernel_accepts_ap_mode(self):
        replies = [self.result(), self.result(stderr="command failed: Device or resource busy (-16)", returncode=240),
                   self.result(), self.result(), self.result("Interface wlan_test0\n\ttype AP\n")]
        with patch.object(self.instance, "run", side_effect=replies) as run, \
             patch.object(hotspot.time, "sleep") as sleep, patch.object(hotspot, "say"):
            self.instance.prepare_radio()
        self.assertEqual(run.call_count, 5)
        self.assertEqual(sleep.call_count, 1)
        self.assertEqual(run.call_args_list[1].args[0], ["iw", "dev", "wlan_test0", "set", "type", "__ap"])
        self.assertNotIn("eth_test0", str(run.call_args_list))
        self.assertNotIn("systemctl", str(run.call_args_list))

    def test_permanent_mode_error_is_not_retried(self):
        replies = [self.result(), self.result(stderr="Operation not supported (-95)", returncode=161)]
        with patch.object(self.instance, "run", side_effect=replies) as run, \
             patch.object(hotspot.time, "sleep") as sleep:
            with self.assertRaisesRegex(hotspot.SetupError, "Operation not supported"):
                self.instance.prepare_radio()
            self.assertEqual(run.call_count, 2)
            sleep.assert_not_called()

    def test_busy_radio_has_a_deadline(self):
        replies = [self.result(), self.result(stderr="Device or resource busy (-16)", returncode=240)]
        with patch.object(self.instance, "run", side_effect=replies), \
             patch.object(hotspot.time, "monotonic", side_effect=[0, 11]):
            with self.assertRaisesRegex(hotspot.SetupError, "radio did not become available"):
                self.instance.prepare_radio()

    def exercise_startup(self, logs, failure=None, http_failed=False, interrupt_retry=False):
        instance = self.instance
        started = []
        instance.processes = {
            "http": SimpleNamespace(poll=lambda: 1 if http_failed else None),
            "dnsmasq": SimpleNamespace(poll=lambda: None),
        }
        with tempfile.TemporaryDirectory(prefix="crema-radio-") as directory:
            runtime = Path(directory)

            def start(name, command):
                number = len(started)
                log, status = logs[number]
                started.append(name)
                (runtime / "hostapd.log").write_text(log)
                pid = 900000 + number
                instance.processes[name] = SimpleNamespace(pid=pid, poll=lambda: status)
                instance.state["children"].append({"name": name, "pid": pid, "start": "123"})
                hotspot.save_state(instance.state)

            def prepare():
                if interrupt_retry:
                    instance.stop_signal = signal.SIGINT

            with patch.object(hotspot, "RUNTIME", runtime), \
                 patch.object(instance, "start_child", side_effect=start), \
                 patch.object(instance, "wait_for_unmanaged") as wait, \
                 patch.object(instance, "prepare_radio", side_effect=prepare) as prepare_mock, \
                 patch.object(instance, "http_ready", return_value=True), \
                 patch.object(instance, "dns_ready", return_value=True), \
                 patch.object(hotspot, "stop_child") as stop, \
                 patch.object(hotspot.time, "sleep"), patch.object(hotspot, "say"):
                if failure:
                    with self.assertRaises(failure):
                        instance.start_access_point()
                else:
                    instance.start_access_point()
                archives = {p.name: p.read_text() for p in runtime.glob("hostapd*.log")}
                saved = json.loads((runtime / "state.json").read_text())
                return started, wait.call_count, prepare_mock.call_count, stop.call_count, archives, saved

    def test_transient_hostapd_error_restarts_only_our_hostapd(self):
        result = self.exercise_startup([(self.failure, 1), ("wlan_test0: AP-ENABLED\n", None)])
        started, waits, prepares, stops, logs, saved = result
        self.assertEqual(started, ["hostapd", "hostapd"])
        self.assertEqual((waits, prepares, stops), (1, 1, 1))
        self.assertEqual(logs["hostapd-attempt-1.log"], self.failure)
        self.assertIn("AP-ENABLED", logs["hostapd.log"])
        self.assertEqual(saved["children"], [{"name": "hostapd", "pid": 900001, "start": "123"}])
        self.assertEqual(set(self.instance.processes), {"http", "dnsmasq", "hostapd"})

    def test_retry_limit_retains_last_child_for_normal_cleanup(self):
        result = self.exercise_startup([(self.failure, 1)] * 3, failure=hotspot.SetupError)
        started, waits, prepares, stops, logs, saved = result
        self.assertEqual(len(started), 3)
        self.assertEqual((waits, prepares, stops), (2, 2, 2))
        self.assertEqual(set(logs), {"hostapd-attempt-1.log", "hostapd-attempt-2.log", "hostapd.log"})
        self.assertEqual(saved["children"][0]["pid"], 900002)

    def test_unrelated_hostapd_error_is_not_retried(self):
        result = self.exercise_startup([("Line 1: invalid configuration\n", 1)], failure=hotspot.SetupError)
        self.assertEqual(len(result[0]), 1)
        self.assertEqual(result[1:4], (0, 0, 0))

    def test_error_after_ap_was_enabled_is_not_retried(self):
        result = self.exercise_startup([("AP-ENABLED\n" + self.failure, 1)], failure=hotspot.SetupError)
        self.assertEqual(len(result[0]), 1)
        self.assertEqual(result[1:4], (0, 0, 0))

    def test_http_failure_is_not_hidden_by_hostapd_retry(self):
        result = self.exercise_startup([(self.failure, 1)], failure=hotspot.SetupError, http_failed=True)
        self.assertEqual(len(result[0]), 1)
        self.assertEqual(result[1:4], (0, 0, 0))

    def test_interrupt_during_retry_keeps_journal_consistent(self):
        result = self.exercise_startup([(self.failure, 1)], failure=hotspot.Interrupted, interrupt_retry=True)
        self.assertEqual(len(result[0]), 1)
        self.assertEqual(result[5]["children"], [])


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.state = {
            "version": 1, "interface": "wlan_test0", "address": "10.77.0.1/24",
            "snapshot": {"managed": "yes", "autoconnect": "no", "type": "managed",
                         "mac": "02:00:00:00:00:01", "link_up": True, "ipv6_disabled": None},
            "children": [{"name": "http", "pid": 999999, "start": "123"}],
            "firewall_added": True, "address_added": True, "interface_changed": True,
        }

    def json_result(self, args):
        if args[0] == "nft":
            return {"nftables": [{"table": {"family": "inet", "name": hotspot.TABLE}},
                                  {"table": {"family": "inet", "name": "unrelated"}}]}
        return [{"addr_info": [{"local": "10.77.0.1", "prefixlen": 24}]}]

    def test_cleanup_and_idempotence(self):
        with tempfile.TemporaryDirectory(prefix="crema-tests-") as directory:
            with patch.object(hotspot, "command") as run, \
                 patch.object(hotspot, "json_command", side_effect=self.json_result), \
                 patch.object(hotspot, "stop_child") as stop:
                self.assertEqual(hotspot.cleanup(self.state, Path(directory)), [])
                stop.assert_called_once()
                calls = [call.args[0] for call in run.call_args_list]
                self.assertIn(["nft", "delete", "table", "inet", "crema_revive"], calls)
                self.assertIn(["ip", "address", "del", "10.77.0.1/24", "dev", "wlan_test0"], calls)
                self.assertIn(["iw", "dev", "wlan_test0", "set", "type", "managed"], calls)
                self.assertIn(["nmcli", "device", "set", "wlan_test0", "autoconnect", "no"], calls)
                self.assertNotIn("unrelated", str(calls))
                self.assertNotIn("eth_test0", str(calls))
                self.assertNotIn("flush", str(calls))
                self.assertFalse(self.state["interface_changed"])
                self.assertFalse(self.state["firewall_added"])
                self.assertFalse(self.state["address_added"])
                self.assertEqual(self.state["children"], [])
                saved = json.loads((Path(directory) / "state.json").read_text())
                self.assertEqual(saved, self.state)
                run.reset_mock()
                self.assertEqual(hotspot.cleanup(self.state, Path(directory)), [])
                run.assert_not_called()

    def test_cleanup_continues_and_retains_failed_step(self):
        def run(args):
            if args[0] == "nft":
                raise hotspot.SetupError("simulated firewall cleanup error")

        with tempfile.TemporaryDirectory(prefix="crema-tests-") as directory:
            with patch.object(hotspot, "command", side_effect=run), \
                 patch.object(hotspot, "json_command", side_effect=self.json_result), \
                 patch.object(hotspot, "stop_child"):
                errors = hotspot.cleanup(self.state, Path(directory))
                self.assertEqual(len(errors), 1)
                self.assertTrue(self.state["firewall_added"])
                self.assertFalse(self.state["interface_changed"])
                self.assertFalse(self.state["address_added"])
                saved = json.loads((Path(directory) / "state.json").read_text())
                self.assertTrue(saved["firewall_added"])

    def test_cleanup_with_nothing_started(self):
        state = copy.deepcopy(self.state)
        state.update(children=[], firewall_added=False, address_added=False, interface_changed=False)
        with patch.object(hotspot, "command") as run, patch.object(hotspot, "save_state"):
            self.assertEqual(hotspot.cleanup(state), [])
            run.assert_not_called()

    def test_stop_child_checks_process_identity(self):
        with patch.object(hotspot.os, "killpg") as kill:
            hotspot.stop_child({"pid": os.getpid(), "start": "not-the-real-start-time"})
            kill.assert_not_called()

    def test_actual_child_process_is_stopped(self):
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
        try:
            hotspot.stop_child({"pid": process.pid, "start": hotspot.process_start(process.pid)})
            self.assertIsNotNone(process.poll())
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


class LifecycleTests(unittest.TestCase):
    def test_startup_failure_and_termination_both_roll_back(self):
        snapshot = {"managed": "yes", "autoconnect": "no", "type": "managed",
                    "mac": "02:00:00:00:00:01", "link_up": True, "ipv6_disabled": None}
        for signum in (None, signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signum=signum), tempfile.TemporaryDirectory(
                    prefix="crema-lifecycle-") as directory:
                runtime = Path(directory) / "runtime"
                previous = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}

                def setup(instance):
                    instance.state["interface_changed"] = True
                    if signum is None:
                        raise RuntimeError("simulated setup failure")
                    os.kill(os.getpid(), signum)
                    instance.check_stop()

                with patch.object(hotspot, "RUNTIME", runtime), \
                     patch.object(hotspot.os, "geteuid", return_value=0), \
                     patch.object(hotspot, "preflight", return_value=(snapshot, None)), \
                     patch.object(hotspot, "json_command", return_value={"nftables": []}), \
                     patch.object(hotspot.Hotspot, "setup", autospec=True, side_effect=setup), \
                     patch.object(hotspot, "cleanup", return_value=[]) as rollback, \
                     patch.object(hotspot, "say"), patch.object(hotspot, "print_logs"):
                    result = hotspot.main(["--interface", "wlan_test0"])
                    expected = 1 if signum is None else (0 if signum == signal.SIGINT else 128 + signum)
                    self.assertEqual(result, expected)
                    rollback.assert_called_once()
                    self.assertTrue(rollback.call_args.args[0]["interface_changed"])
                    self.assertFalse(runtime.exists())
                for s in previous:
                    self.assertEqual(signal.getsignal(s), previous[s])

    def test_child_is_journaled_before_pending_interrupt_is_raised(self):
        args = hotspot.parser().parse_args(["--interface", "wlan_test0"])
        instance = hotspot.Hotspot(args, {}, None)

        def start(*args, **kwargs):
            instance.stop_signal = signal.SIGINT
            return SimpleNamespace(pid=999999)

        with tempfile.TemporaryDirectory(prefix="crema-child-") as directory:
            runtime = Path(directory)
            with patch.object(hotspot, "RUNTIME", runtime), \
                 patch.object(hotspot.subprocess, "Popen", side_effect=start), \
                 patch.object(hotspot, "process_start", return_value="123"):
                with self.assertRaises(hotspot.Interrupted):
                    instance.start_child("http", ["not-a-real-command"])
                saved = json.loads((runtime / "state.json").read_text())
                self.assertEqual(saved["children"], [{"name": "http", "pid": 999999, "start": "123"}])


if __name__ == "__main__":
    unittest.main()
