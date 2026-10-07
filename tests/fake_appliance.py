#!/usr/bin/env python3
"""tests/fake_appliance.py -- a fake PAN-OS-style console for testing
panos_pty.py without a network or a real device.

It must be run with a pty as its stdin/stdout (panos_pty.py does this by
passing it via --exec-cmd). It reproduces, byte-for-byte in style, the
pathologies of a real appliance console that broke the naive driver:

  * two-stage login: banner acknowledgement ("Do you acknowledge ... (yes/no)")
    THEN "Password:"
  * token-by-token echo of the typed command, with the prompt re-rendered
    between tokens (the v1 killer: prompt strings appear mid-buffer)
  * slow trickle output (default 3 lines/second)
  * paging with --More-- beyond --page-size lines
  * ANSI escape noise
  * CR-only line endings
  * optional invisible trailing bytes after the final prompt (the
    2026-10-06 field bug: a clean bare prompt that naive checks miss)

Commands it understands:

  show system info    a few lines of plausible system info
  slow                --trickle-lines lines at --trickle-rate lines/second
  page                --page-lines lines, paged every --page-size lines
  ansi                output wrapped in ANSI escapes
  cr                  output with \\r-only line endings
  echo-prompt         output containing a prompt-like line MID-command
  quiet               no output at all (empty command result)
  hang                one line every --hang-interval seconds for
                      --hang-duration seconds (for --cmd-timeout tests)
  logout              end the session
  anything else       "Invalid syntax" (like the real CLI)
"""

import argparse
import os
import sys
import termios
import time
import tty

TRAILING = {
    "csi2k": "\x1b[2K",           # erase whole line
    "csi-k": "\x1b[K",            # erase to end of line
    "cr": "\r",
    "csi2k-cr": "\x1b[2K\r",
    "space": " ",
    "crlf": "\r\n",
    "osc-bell": "\x1b]0;\x07",    # OSC window-title with BEL terminator
}


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--user", default="admin")
    p.add_argument("--hostname", default="FAKEHOST")
    p.add_argument("--password", default=None,
                   help="expected password (or env FAKE_APPLIANCE_PASSWORD)")
    p.add_argument("--prompt-end", default=">", choices=[">", "#"])
    p.add_argument("--delay", type=float, default=0.05,
                   help="base inter-step delay in seconds (default 0.05)")
    p.add_argument("--trickle-rate", type=float, default=3.0,
                   help="lines/second for the 'slow' command (default 3)")
    p.add_argument("--trickle-lines", type=int, default=12)
    p.add_argument("--page-lines", type=int, default=320)
    p.add_argument("--page-size", type=int, default=80)
    p.add_argument("--token-echo", action="store_true", default=True)
    p.add_argument("--no-token-echo", dest="token_echo", action="store_false")
    p.add_argument("--motd-ack", action="store_true", default=True)
    p.add_argument("--no-motd-ack", dest="motd_ack", action="store_false")
    p.add_argument("--trailing-bytes", default="",
                   help="invisible bytes to emit AFTER the final prompt; one of: "
                        + ", ".join(sorted(TRAILING)))
    p.add_argument("--hang-interval", type=float, default=0.2)
    p.add_argument("--hang-duration", type=float, default=30.0)
    a = p.parse_args()

    password = a.password or os.environ.get("FAKE_APPLIANCE_PASSWORD", "")
    if not password:
        sys.stderr.write("fake appliance: need --password or FAKE_APPLIANCE_PASSWORD\n")
        sys.exit(64)
    trailing = TRAILING.get(a.trailing_bytes, "")
    if a.trailing_bytes and not trailing:
        sys.stderr.write("fake appliance: unknown --trailing-bytes %r\n" % a.trailing_bytes)
        sys.exit(64)

    # Raw mode on stdin: like a real device behind ssh, the appliance is the
    # sole owner of the byte stream (no kernel echo, no line discipline).
    try:
        tty.setraw(sys.stdin.fileno())
    except termios.error:
        pass

    prompt = "%s@%s%s" % (a.user, a.hostname, a.prompt_end)
    out = sys.stdout

    def w(s):
        out.write(s)
        out.flush()

    def rd_line():
        buf = ""
        while True:
            c = os.read(sys.stdin.fileno(), 1)
            if not c:
                return None
            c = c.decode("utf-8", "replace")
            if c == "\r":
                return buf
            buf += c

    # ---------------- login ----------------
    if a.motd_ack:
        w("------------------------------------------------------------------\r\n")
        w("You are accessing '%s' (192.0.2.10)\r\n" % a.hostname)
        w("Do you acknowledge that all actions within this session are subject to\r\n")
        w("monitoring? (yes/no)")
        time.sleep(a.delay)
        line = rd_line()
        if line is None or line.strip().lower() != "yes":
            w("\r\nLogin aborted.\r\n")
            sys.exit(0)
        time.sleep(a.delay)
    w("Password: ")
    line = rd_line()
    if line is None or line != password:
        w("\r\nLogin failed\r\n")
        sys.exit(0)
    w("\r\n")
    time.sleep(a.delay)
    w(prompt + " ")

    # ---------------- CLI loop ----------------
    while True:
        line = rd_line()
        if line is None:
            break
        cmd = line.strip()
        if not cmd:
            w(prompt + " ")
            continue
        if cmd == "logout":
            w("\r\nlogout\r\n")
            break

        # The v1 killer: the device re-echoes the typed command token by
        # token with the prompt re-rendered between tokens.
        if a.token_echo:
            for t in cmd.split():
                w("\r\n" + prompt + " " + t)
                time.sleep(a.delay)
            w("\r\n")

        if cmd == "show system info":
            w("hostname: %s\r\n" % a.hostname)
            w("ip-address: 192.0.2.10\r\n")
            w("sw-version: 10.1.3\r\n")
            w("uptime: 12 days, 8:58:24\r\n")
        elif cmd == "slow":
            for i in range(a.trickle_lines):
                w("trickle line %02d\r\n" % i)
                time.sleep(1.0 / a.trickle_rate)
        elif cmd == "page":
            for i in range(a.page_lines):
                w("page line %04d\r\n" % i)
                if (i + 1) % a.page_size == 0:
                    w("--More--")
                    if rd_line() is None:
                        break
        elif cmd == "ansi":
            w("\x1b[1;32mgreen bold line one\x1b[0m\r\n")
            w("\x1b[4munderlined\x1b[0m and \x1b[31mred\x1b[0m line two\r\n")
            w("\x1b[?25lcursor off\x1b[?25h plain line three\r\n")
        elif cmd == "cr":
            w("cr only line one\r")
            w("cr only line two\r")
            w("cr only line three\r")
        elif cmd == "echo-prompt":
            w("first output line\r\n")
            w(prompt + " looks like a prompt mid-command\r\n")
            w("final output line\r\n")
        elif cmd == "hang":
            t0 = time.time()
            i = 0
            while time.time() - t0 < a.hang_duration:
                w("hang tick %d\r\n" % i)
                i += 1
                time.sleep(a.hang_interval)
        elif cmd == "quiet":
            pass
        else:
            w("Invalid syntax\r\n")

        # Final prompt, then (optionally) invisible trailing bytes -- the
        # 2026-10-06 field bug reproduction: a clean bare prompt followed by
        # invisible bytes that defeat naive "last line == prompt" checks.
        w(prompt + " ")
        if trailing:
            w(trailing)


if __name__ == "__main__":
    main()
