#!/usr/bin/env python3
"""Offline Crema Touch activation emulator. Python stdlib + OpenSSL only."""

import argparse
import base64
import binascii
import ipaddress
import logging
import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
import xml.etree.ElementTree as ET


KEY = b"1234567890abcdef12345678"
IV = b"12345678"
SHOPCODES = ("keph_yes24", "keph_aladin", "keph_bandi", "offline")
HOSTS = frozenset(("mng.k-epub.co.kr", "mng2.k-epub.co.kr"))
SERVICE = "/OTA/service.ashx"
MAX_BODY = 16384
LOG = logging.getLogger("crema.http")


class BadRequest(ValueError):
    pass


def crypt(data, decrypt=False):
    command = ["openssl", "enc", "-des-ede3-cbc", "-K", KEY.hex(), "-iv", IV.hex()]
    if decrypt:
        command.append("-d")
    result = subprocess.run(command, input=data, capture_output=True, timeout=5)
    if result.returncode:
        raise BadRequest("3DES operation failed; check ciphertext and padding")
    return result.stdout


def decode_request(body):
    try:
        form = parse_qs(
            body.decode("ascii"), keep_blank_values=True, strict_parsing=True,
            encoding="utf-8", errors="strict", max_num_fields=8,
        )
        if set(form) != {"key", "iv", "data"} or any(len(v) != 1 for v in form.values()):
            raise BadRequest("expected one key, iv, and data field")
        if form["key"][0] != KEY.decode() or form["iv"][0] != IV.decode():
            raise BadRequest("unexpected device key/IV; capture firmware details")
        ciphertext = base64.b64decode("".join(form["data"][0].split()), validate=True)
        if not ciphertext or len(ciphertext) % 8:
            raise BadRequest("invalid ciphertext length")
        plaintext = crypt(ciphertext, decrypt=True)
        if b"<!DOCTYPE" in plaintext.upper() or b"<!ENTITY" in plaintext.upper():
            raise BadRequest("XML document declarations are not supported")
        root = ET.fromstring(plaintext)
        if root.tag != "data" or root.get("version") != "1":
            raise BadRequest("expected data XML version 1")
        action = (root.findtext("actcode") or "").strip()
        serial = (root.findtext("sn") or "").strip()
        if action not in ("1", "2"):
            raise BadRequest("unsupported actcode")
        if not serial or len(serial) > 128 or any(ord(c) < 32 for c in serial):
            raise BadRequest("missing or invalid device serial")
        return action, serial
    except (UnicodeError, binascii.Error, ET.ParseError, ValueError) as exc:
        if isinstance(exc, BadRequest):
            raise
        raise BadRequest("malformed form, Base64, or XML") from exc


def encode_response(action, serial, shopcode):
    root = ET.Element("data", version="1")
    values = {
        "retcode": "0" if action == "1" else "-1",
        "retdesc": "Offline activation" if action == "1" else "OTA disabled in offline lab",
        "sn": serial,
        "shopcode": shopcode,
    }
    for name, value in values.items():
        ET.SubElement(root, name).text = value
    return base64.b64encode(crypt(ET.tostring(root, encoding="utf-8")))


class ActivationServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 8

    def __init__(self, address, shopcode, client_subnet):
        self.shopcode = shopcode
        self.client_subnet = ipaddress.ip_network(client_subnet)
        self.slots = threading.BoundedSemaphore(12)
        super().__init__(address, Handler)

    def verify_request(self, request, client_address):
        return ipaddress.ip_address(client_address[0]) in self.client_subnet

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "CremaOffline/1"
    sys_version = ""

    def setup(self):
        self.request.settimeout(10)
        super().setup()

    def log_message(self, format_string, *args):
        # Do not log request bodies, personal fields, or URL query strings.
        pass

    def reply(self, status, body, content_type="text/plain; charset=us-ascii"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        self.wfile.write(body)

    def allowed_host(self):
        host = self.headers.get("Host", "").lower().split(":", 1)[0]
        return host in HOSTS or host == self.server.server_address[0]

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/healthz" and self.client_address[0] == self.server.server_address[0]:
            self.reply(200, b"ready\n")
        elif not self.allowed_host():
            self.reply(404, b"Unknown host\n")
        elif path in ("/", SERVICE):
            LOG.info("Connectivity GET from %s -> 200", self.client_address[0])
            self.reply(200, b"Crema offline activation service\n")
        else:
            self.reply(404, b"Unknown endpoint\n")

    def do_POST(self):
        if not self.allowed_host() or urlsplit(self.path).path != SERVICE:
            self.reply(404, b"Unknown endpoint\n")
            return
        try:
            if self.headers.get("Transfer-Encoding"):
                raise BadRequest("chunked requests are not supported")
            if self.headers.get_content_type() != "application/x-www-form-urlencoded":
                raise BadRequest("expected application/x-www-form-urlencoded")
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1:
                raise BadRequest("expected one Content-Length")
            length = int(lengths[0])
            if not 0 < length <= MAX_BODY:
                self.reply(413, b"Invalid request size\n")
                return
            body = self.rfile.read(length)
            if len(body) != length:
                raise BadRequest("incomplete request body")
            action, serial = decode_request(body)
            response = encode_response(action, serial, self.server.shopcode)
            self.reply(200, response)
            if action == "1":
                LOG.info(
                    "ACTIVATION RESPONSE SENT to %s (serial ending %s, shop %s). "
                    "Check the reader screen; sending a reply is not proof of activation.",
                    self.client_address[0], serial[-4:], self.server.shopcode,
                )
            else:
                LOG.info("Declined OTA check from %s; no firmware offered", self.client_address[0])
        except (BadRequest, ValueError) as exc:
            LOG.warning("Rejected request from %s: %s", self.client_address[0], exc)
            self.reply(400, b"Invalid activation request; see local server log\n")
        except (OSError, subprocess.TimeoutExpired):
            LOG.exception("Local encryption/server operation failed")
            self.reply(500, b"Local emulator error\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--client-subnet", default="127.0.0.0/8")
    parser.add_argument("--shopcode", choices=SHOPCODES, default="keph_yes24")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    # Fail before listening if this OpenSSL installation cannot use 3DES.
    if crypt(crypt(b"crema self-test"), decrypt=True) != b"crema self-test":
        raise RuntimeError("3DES self-test failed")
    with ActivationServer((args.bind, args.port), args.shopcode, args.client_subnet) as server:
        LOG.info("Listening on %s:%s (no Internet proxying)", *server.server_address)
        try:
            server.serve_forever(poll_interval=0.25)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
