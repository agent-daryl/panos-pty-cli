#!/usr/bin/env python3
"""tests/test_panos_sh.py -- orchestration tests for the panos.sh wrapper
(API-first, pty-fallback).

The API path is exercised against a local TLS stub of the PAN-OS XML API
(self-signed cert generated with openssl, served by stdlib http.server on
127.0.0.1; panos_api.py verifies TLS off by default). The pty path is
exercised against tests/fake_appliance.py via panos_pty.py's --exec-cmd
seam. No network, no real device.

Requires: openssl on PATH (for the stub's self-signed cert). Skipped if
absent.

Run:  python3 -m unittest -v tests.test_panos_sh
"""

import html
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WRAPPER = os.path.join(ROOT, "panos.sh")
FAKE = os.path.join(HERE, "fake_appliance.py")

PROMPT_RE = r"admin@FAKEHOST"
FAKE_PW = "testpw-not-a-secret"
TEST_KEY = "fake-key-not-a-secret"
ENV_NAME = "PANT_PTY_TEST_PW"


def _make_self_signed(tmpdir):
    key = os.path.join(tmpdir, "stub_key.pem")
    crt = os.path.join(tmpdir, "stub_cert.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
         "-out", crt, "-days", "1", "-nodes", "-subj", "/CN=127.0.0.1"],
        check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    return ctx


class _StubApi(BaseHTTPRequestHandler):
    """Minimal PAN-OS XML API stand-in.

    * missing X-PAN-KEY (or wrong key)  -> 403 Invalid Credential
    * type=version                      -> 200 success
    * type=op with 'stubreject' in cmd  -> 200, status=error code=17
    * type=op otherwise                 -> 200 success echoing the cmd
    """

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        if self.headers.get("X-PAN-KEY") != TEST_KEY:
            self._send(403, b"<response status='error' code='403'>"
                            b"<result><msg>Invalid Credential</msg></result>"
                            b"</response>")
            return
        t = q.get("type", [""])[0]
        if t == "version":
            self._send(200, b'<response status="success"><result>'
                            b'<sw-version>10.9.9</sw-version><model>STUB</model>'
                            b'</result></response>')
        elif t == "op":
            cmd = q.get("cmd", [""])[0]
            if "stubreject" in cmd:
                self._send(200, b'<response status="error" code="17">'
                                b'<msg><line><![CDATA[ stub -> reject  is '
                                b'unexpected]]></line></msg></response>')
            else:
                self._send(200, b'<response status="success"><result>'
                                + html.escape(cmd).encode()
                                + b'</result></response>')
        else:
            self._send(400, b"<response status='error' code='400'>"
                            b"<result><msg>bad type</msg></result></response>")

    def log_message(self, *a):
        pass


class TestPanosSh(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not shutil.which("openssl"):
            raise unittest.SkipTest("openssl not available (needed for the "
                                    "TLS stub)")
        cls.tmp = tempfile.mkdtemp(prefix="panos_sh_test_")
        ctx = _make_self_signed(cls.tmp)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _StubApi)
        cls.httpd.socket = ctx.wrap_socket(cls.httpd.socket, server_side=True)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    # -- helpers ----------------------------------------------------------

    def _env(self, with_password=True):
        env = dict(os.environ)
        env.pop("PANOS_API_KEY", None)
        if with_password:
            env[ENV_NAME] = FAKE_PW
        else:
            env.pop(ENV_NAME, None)
        return env

    def _keyfile(self):
        path = os.path.join(self.tmp, "test_key")
        with open(path, "w") as f:
            f.write(TEST_KEY + "\n")
        return path

    def run_wrapper(self, commands, with_key=True, pty_ready=True,
                    timeout=90):
        """pty_ready: pass --user + a fake-appliance --exec-cmd so the pty
        path (if taken) works against the local fake device."""
        cmd = ["bash", WRAPPER,
               "--host", "127.0.0.1",
               "--port", str(self.port),
               "--api-timeout", "10",
               "--prompt-regex", PROMPT_RE,
               "--password-env", ENV_NAME]
        if with_key:
            cmd += ["--key-file", self._keyfile()]
        if pty_ready:
            cmd += ["--user", "admin",
                    "--pty-exec-cmd",
                    "%s %s --password %s" % (sys.executable, FAKE, FAKE_PW)]
        cmd += list(commands)
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, env=self._env())

    # -- tests ------------------------------------------------------------

    def test_api_path_used(self):
        p = self.run_wrapper(["show system info"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("-> API", p.stderr)
        # API response echoed to stdout, no pty session at all
        self.assertIn('<response status="success">', p.stdout)
        self.assertIn("&lt;show&gt;&lt;system&gt;&lt;info/&gt;", p.stdout)
        self.assertNotIn("raw log:", p.stdout)

    def test_api_reject_falls_back_to_pty(self):
        p = self.run_wrapper(["show system stubreject"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("queuing for pty", p.stderr)
        # the fake appliance answers unknown commands with Invalid syntax
        self.assertIn("Invalid syntax", p.stdout)
        self.assertIn("raw log:", p.stdout)

    def test_no_key_straight_to_pty(self):
        p = self.run_wrapper(["show system info"], with_key=False)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("-> API", p.stderr)
        self.assertIn("hostname: FAKEHOST", p.stdout)
        self.assertIn("raw log:", p.stdout)

    def test_ineligible_commands_batched_into_one_pty_session(self):
        # both commands contain a slash -> not API-eligible -> they must
        # share ONE pty session (exactly one login), even with a key present
        p = self.run_wrapper(["show interface ethernet1/1",
                              "show address 192.0.2.55/32"], with_key=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.count("raw log:"), 1)
        self.assertEqual(p.stdout.count("===== CMD:"), 2)
        self.assertNotIn("-> API", p.stderr)

    def test_mixed_api_and_pty_in_one_run(self):
        p = self.run_wrapper(["show system info",
                              "show interface ethernet1/1"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("-> API", p.stderr)
        self.assertIn("raw log:", p.stdout)
        self.assertIn("<response status=\"success\">", p.stdout)
        self.assertIn("Invalid syntax", p.stdout)

    def test_pty_fallback_without_password_exits_4(self):
        # an ineligible command with no API key available for the pty
        # fallback and no password env var -> clean exit 4
        env = self._env(with_password=False)
        cmd = ["bash", WRAPPER, "--host", "127.0.0.1",
               "--port", str(self.port),
               "--api-timeout", "10", "--prompt-regex", PROMPT_RE,
               "--password-env", ENV_NAME,
               "--user", "admin",
               "show interface ethernet1/1"]
        p2 = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=30, env=env)
        self.assertEqual(p2.returncode, 4, p2.stdout + p2.stderr)
        self.assertIn(ENV_NAME, p2.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
