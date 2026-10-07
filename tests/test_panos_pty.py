#!/usr/bin/env python3
"""tests/test_panos_pty.py -- regression tests for the panos_pty.py
completion rule.

Runs the REAL driver as a subprocess against tests/fake_appliance.py over a
local pty -- no network, no real device, stdlib only. Each test reproduces a
specific pathology that a naive driver gets wrong:

  * two-stage login (banner ack, then password)
  * prompt strings mid-buffer (token echo) must not mean "done"
  * slow trickle output must be captured completely
  * paging must be detected and fed RETURNs
  * ANSI noise must be stripped
  * CR-only line endings must split correctly
  * invisible trailing bytes after a clean prompt must not defeat the
    completion check (2026-10-06 field bug)
  * per-command timeout must fire and the session must recover

Run:  python3 -m unittest -v tests.test_panos_pty
   or: python3 tests/test_panos_pty.py
"""

import os
import shlex
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DRIVER = os.path.join(ROOT, "panos_pty.py")
FAKE = os.path.join(HERE, "fake_appliance.py")

PROMPT_RE = r"admin@FAKEHOST"
FAKE_PW = "testpw-not-a-secret"
ENV_NAME = "PANT_PTY_TEST_PW"


def run(commands, driver_extra=(), appliance_extra=(), timeout=120,
        driver_password=FAKE_PW):
    ap_args = "--password %s" % shlex.quote(FAKE_PW)
    if appliance_extra:
        ap_args += " " + " ".join(shlex.quote(x) for x in appliance_extra)
    cmd = [sys.executable, DRIVER,
           "--exec-cmd", "%s %s %s" % (sys.executable, FAKE, ap_args),
           "--password-env", ENV_NAME,
           "--prompt-regex", PROMPT_RE,
           "--prompt-end-chars", ">#",
           "--idle-done", "0.8",
           "--login-timeout", "3",
           "--log-dir", tempfile.mkdtemp(prefix="panos_pty_test_")]
    cmd += list(driver_extra)
    env = dict(os.environ, **{ENV_NAME: driver_password})
    return subprocess.run(cmd, input="\n".join(commands) + "\n",
                          capture_output=True, text=True, timeout=timeout, env=env)


class TestPanosPty(unittest.TestCase):

    def test_login_and_basic(self):
        p = run(["show system info"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("===== CMD: show system info [done] =====", p.stdout)
        self.assertIn("hostname: FAKEHOST", p.stdout)
        self.assertIn("sw-version: 10.1.3", p.stdout)
        self.assertNotIn("LOGIN FAILED", p.stderr)

    def test_token_echo_not_done_early(self):
        # v1 killer: a prompt-like line appears MID-command. A driver that
        # treats "prompt seen" as done would stop before the final line.
        p = run(["echo-prompt"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("looks like a prompt mid-command", p.stdout)
        self.assertIn("final output line", p.stdout)
        self.assertIn("===== CMD: echo-prompt [done] =====", p.stdout)

    def test_slow_trickle_complete(self):
        p = run(["slow"], timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        for i in range(12):
            line = "trickle line %02d" % i
            self.assertIn(line, p.stdout)
        # order preserved
        idx = [p.stdout.index("trickle line %02d" % i) for i in range(12)]
        self.assertEqual(idx, sorted(idx))
        self.assertIn("===== CMD: slow [done] =====", p.stdout)

    def test_paging_full_capture(self):
        p = run(["page"],
                appliance_extra=["--page-lines", "320", "--page-size", "80"],
                timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.count("page line"), 320)
        self.assertNotIn("--More--", p.stdout)
        self.assertIn("===== CMD: page [done] =====", p.stdout)

    def test_ansi_stripped(self):
        p = run(["ansi"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("\x1b", p.stdout)
        self.assertIn("green bold line one", p.stdout)
        self.assertIn("plain line three", p.stdout)

    def test_cr_only_endings(self):
        p = run(["cr"])
        self.assertEqual(p.returncode, 0, p.stderr)
        for n in ("one", "two", "three"):
            self.assertIn("cr only line %s" % n, p.stdout)

    def test_trailing_invisible_bytes(self):
        # 2026-10-06 field bug: output complete, clean bare prompt at the
        # tail, invisible bytes after it -- must still be detected as done,
        # not a 900s timeout.
        for tb in ("csi2k", "csi-k", "cr", "space", "crlf", "osc-bell"):
            # bounded cmd-timeout so a regression fails fast instead of
            # hanging at the 900s default
            p = run(["cr"], driver_extra=["--cmd-timeout", "20"],
                    appliance_extra=["--trailing-bytes", tb])
            self.assertEqual(p.returncode, 0, (tb, p.stderr))
            self.assertIn("===== CMD: cr [done] =====", p.stdout, tb)
            self.assertNotIn("[TIMEOUT]", p.stdout, tb)

    def test_timeout_and_recovery(self):
        p = run(["hang", "quiet"],
                driver_extra=["--cmd-timeout", "2.5"],
                appliance_extra=["--hang-duration", "6", "--hang-interval", "0.2"],
                timeout=90)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("===== CMD: hang [TIMEOUT] =====", p.stdout)
        self.assertIn("[TIMEOUT]", p.stderr)
        self.assertIn("===== CMD: quiet [done] =====", p.stdout)
        self.assertIn("hang tick", p.stdout)

    def test_bad_password(self):
        p = run(["quiet"], driver_password="wrong-password", timeout=30)
        self.assertEqual(p.returncode, 3, p.stdout + p.stderr)
        self.assertIn("LOGIN FAILED", p.stderr)

    def test_comments_and_blanks(self):
        p = run(["# a comment", "", "quiet", "   # indented comment", "   "])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.count("===== CMD:"), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
