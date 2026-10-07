#!/usr/bin/env python3
"""panos_pty.py -- a pty-based CLI driver for PAN-OS firewalls (and similar
appliance consoles that speak an unframed byte stream over ssh).

Why this exists
---------------
The PAN-OS management CLI, reached over ssh, is not a protocol: it is a raw
terminal byte stream. That makes the obvious tools fail:

  * sshpass / one-prompt expect scripts  -- PAN-OS login is two-stage
    (banner "Do you acknowledge ... (yes/no)" THEN "Password:").
  * Fixed sleeps                        -- large displays trickle in at ~2-4
    lines/second; a full `show config running` can take many minutes.
  * Naive "prompt seen = done"          -- the CLI re-echoes your typed
    command token-by-token with the prompt re-rendered between tokens, so the
    prompt string appears in the buffer *immediately* and mid-buffer.

The only reliable completion signal on such a device is: "the device stopped
talking, and it is asking for input again". This driver implements exactly
that, with two conditions that must BOTH hold:

  (a) no new bytes for >= --idle-done seconds (true quiescence), AND
  (b) the last non-empty line, after stripping all non-printable characters,
      matches the prompt pattern and ends with a prompt character (>/#).

An echoed prompt mid-buffer never satisfies (b) because output still follows
it; a prompt with invisible trailing bytes (ANSI erase, stray CR) no longer
defeats (b) because non-printables are stripped before the check.

Usage
-----
  printf 'show system info\nshow config running\n' | \
    python3 panos_pty.py --host 192.0.2.10 --user admin \
      --password-env PANOS_PASSWORD --prompt-regex 'admin@my-fw'

Commands come from stdin (one per line; blank lines and '#' comments ignored)
or from --file. One login session is used for all commands. Each command's
ANSI-stripped output is printed to stdout, and the full session is written to
a log file (path printed at the end) for post-mortems.

The password is read from the environment variable named by --password-env.
It is never printed; every log/failure dump has it masked.

Testing seam
------------
--exec-cmd REPLACES the ssh invocation with an arbitrary command. The
tests/fake_appliance.py in this repo uses it to regression-test the
completion rule against a local pty "device" with no network involved.

Exit codes: 0 = session ran (check [done]/[TIMEOUT] markers per command),
3 = login failed/timed out, 4 = password env var missing/empty.
"""

import argparse
import fcntl
import os
import pty
import re
import select
import shlex
import struct
import sys
import tempfile
import termios
import time

# CSI sequences, OSC sequences (terminated by BEL or ST), and lone 2-byte
# escapes (save/restore cursor, keypad modes).
ANSI = re.compile(
    r"\x1b\[[0-9;?]*[ -/]*[@-~]"      # CSI
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC
    r"|\x1b[P_X^_]"                    # save/restore cursor, etc.
    r"|\x1b[=>]"                       # keypad application modes
)
NONPRINT = re.compile(r"[^\x20-\x7e]")

EXIT_LOGIN_FAILED = 3
EXIT_NO_PASSWORD = 4


def read_avail(fd, timeout):
    r, _, _ = select.select([fd], [], [], timeout)
    if r:
        try:
            return os.read(fd, 8192)
        except OSError:
            return b""
    return b""


def strip_ansi(s):
    return ANSI.sub("", s)


def settle(fd, quiet, cap):
    """Drain until `quiet` seconds of silence (or `cap` seconds).

    Returns the drained text (callers discard it; it is residue from the
    previous step and is logged separately by the caller)."""
    out, t0, silent = "", time.time(), 0.0
    while time.time() - t0 < cap:
        d = read_avail(fd, 0.25)
        if d:
            out += d.decode("utf-8", "replace")
            silent = 0.0
        else:
            silent += 0.25
            if silent >= quiet:
                break
    return out


def prompt_done(out, prompt_re, end_chars):
    """Two-condition rule, condition (b): does the capture END on a bare
    prompt? The last line is first stripped of full ANSI escape SEQUENCES
    (a CSI like \\x1b[2K contains printable characters, so removing
    non-printables alone is not enough), then of any remaining non-printable
    bytes, then rstripped. Invisible trailing bytes (ANSI erase, stray CR,
    empty last line) therefore cannot defeat the check."""
    lines = [l for l in out.splitlines() if l.strip()]
    if not lines:
        return False
    last = NONPRINT.sub("", strip_ansi(lines[-1])).rstrip()
    if not last:
        return False
    return bool(prompt_re.search(last)) and last[-1] in end_chars


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="pty-based CLI driver for PAN-OS appliance consoles",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", help="management IP or hostname of the firewall")
    p.add_argument("--user", help="login username")
    p.add_argument("--password-env",
                   help="name of the environment variable holding the password "
                        "(the password itself never appears on the command line)")
    p.add_argument("--prompt-regex",
                   help="regex matched against the last line to detect the bare "
                        "prompt, e.g. 'admin@my-fw'. Anchor it (^) if command "
                        "output could contain prompt-like text.")
    p.add_argument("--prompt-end-chars", default=">#",
                   help="prompt-terminating characters (default '>%')")
    p.add_argument("--ack-pattern", default=r"acknowledge|\(yes/no\)",
                   help="regex for the banner acknowledgement prompt "
                        "(default: acknowledge|(yes/no))")
    p.add_argument("--ack-answer", default="yes",
                   help="what to type for the ack prompt (default 'yes')")
    p.add_argument("--password-prompt", default=r"Password:",
                   help="regex for the password prompt (default 'Password:')")
    p.add_argument("--idle-done", type=float, default=1.5,
                   help="seconds of silence required before the prompt check "
                        "(default 1.5)")
    p.add_argument("--cmd-timeout", type=float, default=900,
                   help="per-command wall clock in seconds (default 900; "
                        "large displays can be very slow)")
    p.add_argument("--settle", type=float, default=0.5,
                   help="silence window for the pre-command settle drain "
                        "(default 0.5)")
    p.add_argument("--settle-cap", type=float, default=20,
                   help="max seconds for a settle drain (default 20)")
    p.add_argument("--login-timeout", type=float, default=45,
                   help="seconds for the whole login phase (default 45)")
    p.add_argument("--stable", type=float, default=0.0,
                   help="extra seconds the bare prompt must survive after the "
                        "first completion detection before we accept it "
                        "(default 0; raise this for devices that pause > "
                        "--idle-done mid-output)")
    p.add_argument("--page-markers", nargs="+",
                   default=["--More--", "(press RETURN)", "lines 1-"],
                   help="paging footer markers (default: --More-- (press RETURN) "
                        "lines 1-)")
    p.add_argument("--window", default="3000x400",
                   help="pty window ROWSxCOLS (default 3000x400 -- a 'screen' "
                        "so large the pager almost never engages)")
    p.add_argument("--ssh-binary", default="ssh", help="ssh executable (default ssh)")
    p.add_argument("--known-hosts",
                   default=os.path.expanduser("~/.panos_pty_kh"),
                   help="ssh known_hosts file (default ~/.panos_pty_kh)")
    p.add_argument("--connect-timeout", type=int, default=10,
                   help="ssh ConnectTimeout seconds (default 10)")
    p.add_argument("--ssh-extra-args", default="",
                   help="extra ssh arguments, shell-quoted (e.g. '-J bastion')")
    p.add_argument("--no-ssh-config", action="store_true", default=True,
                   help="pass -F /dev/null to ssh (default; deterministic, and "
                        "required on hosts whose ssh_config.d includes have "
                        "bad ownership)")
    p.add_argument("--use-ssh-config", dest="no_ssh_config", action="store_false",
                   help="do NOT pass -F /dev/null (honor the system ssh config)")
    p.add_argument("--exec-cmd", default="",
                   help="TESTING/escape hatch: replace the ssh invocation with "
                        "this command (shell-split). --host/--user are then "
                        "optional. Used by tests/fake_appliance.py.")
    p.add_argument("--file", default="",
                   help="read commands from this file instead of stdin "
                        "(one per line; '#' comments ignored)")
    p.add_argument("--log-dir", default=tempfile.gettempdir(),
                   help="directory for the session log (default: system tempdir)")
    p.add_argument("--no-logout", action="store_true",
                   help="do not send 'logout' at the end")
    return p.parse_args(argv)


def build_transport(args):
    if args.exec_cmd:
        return shlex.split(args.exec_cmd)
    if not (args.host and args.user):
        sys.stderr.write("error: --host and --user are required (or use --exec-cmd)\n")
        sys.exit(2)
    cmd = [args.ssh_binary]
    if args.no_ssh_config:
        cmd += ["-F", "/dev/null"]
    cmd += ["-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=%s" % args.known_hosts,
            "-o", "NumberOfPasswordPrompts=1",
            "-o", "ConnectTimeout=%d" % args.connect_timeout]
    if args.ssh_extra_args:
        cmd += shlex.split(args.ssh_extra_args)
    cmd += ["%s@%s" % (args.user, args.host)]
    return cmd


def main(argv=None):
    args = parse_args(argv)

    password = os.environ.get(args.password_env or "", "")
    if not password:
        sys.stderr.write("error: environment variable %r is empty or unset\n"
                         % (args.password_env or "<--password-env not given>"))
        sys.exit(EXIT_NO_PASSWORD)
    if not args.prompt_regex:
        sys.stderr.write("error: --prompt-regex is required\n")
        sys.exit(2)
    prompt_re = re.compile(args.prompt_regex)
    ack_re = re.compile(args.ack_pattern)
    pass_re = re.compile(args.password_prompt)

    rows, _, cols = args.window.partition("x")
    try:
        rows, cols = int(rows), int(cols)
    except ValueError:
        sys.stderr.write("error: --window must be ROWSxCOLS, got %r\n" % args.window)
        sys.exit(2)

    if args.file:
        with open(args.file) as f:
            src = f
    else:
        src = sys.stdin
    commands = [l.rstrip("\n") for l in src
                if l.strip() and not l.lstrip().startswith("#")]
    if not commands:
        sys.stderr.write("error: no commands given (stdin or --file)\n")
        sys.exit(2)

    os.makedirs(args.log_dir, exist_ok=True)
    logpath = os.path.join(args.log_dir,
                           "panos_pty_session_%d_%d.log" % (int(time.time()), os.getpid()))
    log = open(logpath, "w")

    def logw(s):
        log.write(s.replace(password, "[PASSWORD-MASKED]"))

    transport = build_transport(args)
    pid, fd = pty.fork()
    if pid == 0:  # child
        os.environ["TERM"] = "xterm"
        try:
            os.execvp(transport[0], transport)
        except Exception as e:
            os.write(2, ("exec failed: %s\n" % e).encode())
            os._exit(127)

    try:
        fcntl_ok = True
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except Exception:
        fcntl_ok = False
    logw("=== panos_pty session start: %d commands, transport=%s, window=%dx%d%s ===\n"
         % (len(commands), " ".join(transport), rows, cols,
            "" if fcntl_ok else " [WARNING: could not set pty window]"))

    # ---------------- Phase 1: login ----------------
    buf, sent_ack, sent_pass = "", False, False
    start = time.time()
    while time.time() - start < args.login_timeout:
        d = read_avail(fd, 0.5)
        if d:
            buf += d.decode("utf-8", "replace")
        if not sent_ack and ack_re.search(buf):
            os.write(fd, (args.ack_answer + "\r").encode())
            sent_ack = True
        elif not sent_pass and pass_re.search(buf):
            os.write(fd, (password + "\r").encode())
            sent_pass = True
        if sent_pass and prompt_re.search(buf):
            break
    login_ok = sent_pass and prompt_re.search(buf)
    if not login_ok:
        sys.stderr.write("LOGIN FAILED/TIMEOUT (login_timeout=%.0fs)\n%s\n"
                         % (args.login_timeout,
                            strip_ansi(buf).replace(password, "[PASSWORD-MASKED]")))
        logw("LOGIN FAILED\n%s\n" % strip_ansi(buf))
        log.close()
        try:
            os.kill(pid, 9)
        except Exception:
            pass
        sys.exit(EXIT_LOGIN_FAILED)
    logw("=== login ok ===\n")
    # Discard post-login residue (may include echoed credentials) so command 1
    # starts on a clean slate.
    residue = settle(fd, quiet=0.5, cap=args.settle_cap)
    logw("### settle after login: %r\n" % strip_ansi(residue)[:400])

    # ---------------- Phase 2: commands ----------------
    for c in commands:
        settle(fd, quiet=max(0.25, args.settle * 0.8), cap=args.settle_cap)
        os.write(fd, (c + "\r").encode())
        logw("\n===== CMD: %s =====\n" % c)
        out, start, silence, done = "", time.time(), 0.0, False
        while time.time() - start < args.cmd_timeout:
            d = read_avail(fd, 0.3)
            if d:
                chunk = d.decode("utf-8", "replace")
                out += chunk
                silence = 0.0
                # Paging: check only the recent tail so a marker split across
                # chunk boundaries is still caught, without re-triggering on
                # old text. Truncate the capture at the marker and feed the
                # pager a RETURN.
                tail = out[-32:]
                hit = [m for m in args.page_markers if m in tail]
                if hit:
                    idx = max(out.rfind(m) for m in hit)
                    out = out[:idx]
                    os.write(fd, b"\r")
                    d2 = read_avail(fd, 0.2)
                    if d2:
                        out += d2.decode("utf-8", "replace")
            else:
                silence += 0.3
                if (silence >= args.idle_done and prompt_done(out, prompt_re,
                                                              args.prompt_end_chars)):
                    if args.stable > 0:
                        # survive one more quiescent interval with the same
                        # bare-prompt tail before accepting completion
                        s2, stable_ok = 0.0, True
                        while s2 < args.stable:
                            d2 = read_avail(fd, 0.25)
                            if d2:
                                out += d2.decode("utf-8", "replace")
                                stable_ok = False
                                s2 = 0.0
                            else:
                                s2 += 0.25
                        if stable_ok and prompt_done(out, prompt_re,
                                                     args.prompt_end_chars):
                            done = True
                            break
                    else:
                        done = True
                        break
        clean = strip_ansi(out).replace(password, "[PASSWORD-MASKED]")
        logw(clean)
        if done:
            logw("===== END (done) =====\n")
        else:
            logw("===== END (TIMEOUT %.0fs) =====\n" % args.cmd_timeout)
            sys.stderr.write("[TIMEOUT] %r: no bare prompt after %.0fs; last 64 "
                             "bytes (repr): %r\n" % (c, args.cmd_timeout, out[-64:]))
        sys.stdout.write("===== CMD: %s [%s] =====\n%s" % (c, "done" if done else "TIMEOUT", clean))
        sys.stdout.flush()

    if not args.no_logout:
        os.write(fd, b"logout\r")
        time.sleep(0.5)
    logw("\n=== session end ===\n")
    log.close()
    print("\n[raw log: %s]" % logpath)
    try:
        os.kill(pid, 9)
    except Exception:
        pass
    try:
        os.waitpid(pid, 0)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
