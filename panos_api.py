#!/usr/bin/env python3
"""panos_api.py -- a minimal PAN-OS XML API client (stdlib only).

Companion to panos_pty.py: API-first when the firewall's XML API is
reachable, pty-fallback when it is not. This client encodes the PAN-OS 10.x
quirks that were reverse-engineered against a live PA-440 (PAN-OS 10.1.3),
each of which cost real debugging time:

  * Key generation is  type=keygen&user=...&password=...
    (type=generate-key does not exist and 403s with "Invalid Credential").
  * The API key is returned ONLY ONCE, at generation. Store it immediately.
  * The key is accepted as the X-PAN-KEY header (preferred -- keeps it out
    of URLs, proxies, and access logs) or as a key= query parameter.
  * Authentication runs before XML parsing: a bad key 403s, a good key with
    bad XML 400s.
  * Op commands use <show>, not <get> ("<get> is unexpected" on 10.1.3).
  * Empty elements MUST be self-closing: <info/> works, <info></info> 400s
    with "Request is not a valid XML". This client normalizes automatically.
  * System info on 10.1.3 is <show><system><info/></system></show>
    (<system><status/> is unexpected on that build).
  * Running config is <show><config><running/></config></show>.

Usage:
  # generate a key (print it once; optionally save it, mode 0600)
  python3 panos_api.py keygen --host 192.0.2.10 --user admin \
      --password-env PANOS_PASSWORD --key-out ~/.panos_api_key

  # operational read (key from file, env var, or --key-env)
  python3 panos_api.py show 'show system info' --host 192.0.2.10 \
      --key-file ~/.panos_api_key

  # raw XML op call
  python3 panos_api.py op '<show><system><info/></system></show>' --host 192.0.2.10

  # running config to a file
  python3 panos_api.py config --host 192.0.2.10 --out config.xml

Read-only by default: any command XML containing write verbs (set, delete,
commit, load, save, edit, move, rename, revert, restart, factory-reset,
lock, unlock, clear, upgrade) is refused unless --allow-write is given.
"""

import argparse
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

KEY_ENV_DEFAULT = "PANOS_API_KEY"

WRITE_VERBS = ("set", "delete", "commit", "load", "save", "edit", "move",
               "rename", "revert", "restart", "factory-reset", "lock",
               "unlock", "clear", "upgrade")


def normalize_empty_elements(xml):
    """PAN-OS 10.x rejects empty elements written as <tag></tag> with
    'Request is not a valid XML'; they must be self-closing: <tag/>."""
    prev = None
    while prev != xml:
        prev = xml
        xml = re.sub(
            r"<([A-Za-z_][A-Za-z0-9_.-]*)(\s[^<>]*?)?></\1\s*>",
            r"<\1\2/>",
            xml)
    return xml


def cli_to_xml(cli_cmd):
    """Convert a simple CLI command to API XML. The first token is the
    root verb, the last is a self-closing leaf, everything between is a
    container:  'show system info' ->
    <show><system><info/></system></show>
    Commands needing attributes must be written as raw XML and passed to
    the 'op' subcommand."""
    toks = cli_cmd.split()
    if not toks:
        raise ValueError("empty command")
    for t in toks:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", t):
            raise ValueError("token %r is not a valid element name; use the "
                             "'op' subcommand with raw XML" % t)
    if len(toks) == 1:
        return "<%s/>" % toks[0]
    xml = "<%s>" % toks[0]
    for t in toks[1:-1]:
        xml += "<%s>" % t
    xml += "<%s/>" % toks[-1]
    for t in reversed(toks[:-1]):
        xml += "</%s>" % t
    return xml


def check_read_only(cmd_xml, allow_write):
    if allow_write:
        return
    hits = sorted({v for v in WRITE_VERBS
                   if re.search(r"</?%s[\s/>]" % re.escape(v), cmd_xml)})
    if hits:
        sys.exit("refused: %s is a write verb and this client is read-only "
                 "by default (pass --allow-write to override): %s"
                 % (cmd_xml, ", ".join(hits)))


def make_ssl_context(verify):
    if verify:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def get_key(args):
    if args.key_file:
        with open(os.path.expanduser(args.key_file)) as f:
            return f.read().strip()
    if args.key_env:
        v = os.environ.get(args.key_env)
    else:
        v = os.environ.get(KEY_ENV_DEFAULT)
    if not v:
        sys.exit("no API key: use --key-file, --key-env, or set %s"
                 % KEY_ENV_DEFAULT)
    return v.strip()


def api_call(base, params, key, verify, timeout, key_in_header=True):
    url = base + "/api/?" + urllib.parse.urlencode(params)
    headers = {"User-Agent": "panos-pty-cli/1.0"}
    if key is not None:
        if key_in_header:
            headers["X-PAN-KEY"] = key
        else:
            url += "&key=" + urllib.parse.quote(key)
    req = urllib.request.Request(url, headers=headers)
    try:
        resp = urllib.request.urlopen(
            req, context=make_ssl_context(verify), timeout=timeout)
        return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as e:
        # unreachable host, TLS failure, timeout -- report as a structured
        # error so callers (e.g. the panos.sh wrapper) can fall back cleanly
        return 0, ("<response status='error' code='0'>"
                   "<result><msg>network error: %s</msg></result>"
                   "</response>" % e)


def emit(body, out_path, what):
    if out_path:
        fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(body)
        print("%s written to %s (mode 0600)" % (what, out_path))
    else:
        sys.stdout.write(body if body.endswith("\n") else body + "\n")


def main(argv=None):
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--host", help="firewall management IP or hostname")
    common.add_argument("--port", type=int, default=443)
    common.add_argument("--verify", action="store_true",
                        help="verify the TLS certificate (PAN-OS ships "
                             "self-signed certs; default is no-verify with "
                             "a warning)")
    common.add_argument("--timeout", type=float, default=120)
    common.add_argument("--key-file", help="file containing the API key")
    common.add_argument("--key-env", help="env var containing the API key "
                       "(default: %s when no --key-file)" % KEY_ENV_DEFAULT)
    common.add_argument("--key-in-param", action="store_true",
                        help="send the key as a key= query parameter instead "
                             "of the X-PAN-KEY header (not recommended: it "
                             "lands in URLs and logs)")
    common.add_argument("--allow-write", action="store_true",
                        help="allow write verbs in the command XML "
                             "(set/delete/commit/...) -- off by default")

    p = argparse.ArgumentParser(
        description="minimal PAN-OS XML API client",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)

    pk = sub.add_parser("keygen", parents=[common],
                        help="generate a new API key (printed once)")
    pk.add_argument("--user", required=True)
    pk.add_argument("--password-env", required=True,
                    help="env var holding the user's password")
    pk.add_argument("--key-out", help="also save the key to this file (0600)")

    sub.add_parser("version", parents=[common],
                   help="type=version (no cmd)")

    po = sub.add_parser("op", parents=[common],
                        help="run a raw type=op command (XML)")
    po.add_argument("cmd_xml")
    po.add_argument("--out", help="write the response to a file (0600)")

    ps = sub.add_parser("show", parents=[common],
                        help="run a simple CLI command (converted to XML)")
    ps.add_argument("cli_cmd", help="e.g. 'show system info'")
    ps.add_argument("--out", help="write the response to a file (0600)")

    pc = sub.add_parser("config", parents=[common],
                        help="read the running config "
                             "(<show><config><running/></config></show>)")
    pc.add_argument("--out", help="write the response to a file (0600); "
                    "recommended -- the full config is large and contains "
                    "the admin password hash")

    a = p.parse_args(argv)
    if not a.host:
        p.error("--host is required")
    base = "https://%s:%d" % (a.host, a.port)
    if not a.verify:
        sys.stderr.write("warning: TLS certificate verification is OFF "
                         "(PAN-OS self-signed); use --verify to require a "
                         "valid cert\n")

    if a.command == "keygen":
        pw = os.environ.get(a.password_env, "")
        if not pw:
            sys.exit("environment variable %r is empty or unset" % a.password_env)
        code, body = api_call(base,
                              {"type": "keygen", "user": a.user,
                               "password": pw},
                              None, a.verify, a.timeout)
        m = re.search(r"<key>([^<]+)</key>", body)
        if code != 200 or not m:
            sys.exit("keygen failed: HTTP %d\n%s" % (code, body))
        key = m.group(1).strip()
        # The key is returned only once. Mask it in the warning text.
        print("API key generated. It is shown ONLY ONCE -- store it now.")
        print(key)
        if a.key_out:
            path = os.path.expanduser(a.key_out)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(key + "\n")
            print("saved to %s (mode 0600)" % path)
        return 0

    # All other commands need a key.
    key = get_key(a)
    if a.command == "version":
        code, body = api_call(base, {"type": "version"}, key, a.verify,
                              a.timeout, key_in_header=not a.key_in_param)
    elif a.command == "op":
        cmd_xml = normalize_empty_elements(a.cmd_xml)
        check_read_only(cmd_xml, a.allow_write)
        code, body = api_call(base, {"type": "op", "cmd": cmd_xml}, key,
                              a.verify, a.timeout,
                              key_in_header=not a.key_in_param)
    elif a.command == "show":
        cmd_xml = normalize_empty_elements(cli_to_xml(a.cli_cmd))
        check_read_only(cmd_xml, a.allow_write)
        code, body = api_call(base, {"type": "op", "cmd": cmd_xml}, key,
                              a.verify, a.timeout,
                              key_in_header=not a.key_in_param)
    else:  # config
        cmd_xml = "<show><config><running/></config></show>"
        if not a.out:
            sys.stderr.write("warning: writing the full running config to "
                             "stdout; it contains the admin password hash "
                             "(use --out for a mode-0600 file)\n")
        code, body = api_call(base, {"type": "op", "cmd": cmd_xml}, key,
                              a.verify, a.timeout,
                              key_in_header=not a.key_in_param)

    m = re.search(r"status\s*=\s*['\"]?(\w+)", body)
    status = m.group(1) if m else "unknown"
    if code != 200 or status != "success":
        sys.stderr.write("API call failed: HTTP %d (status=%s)\n" % (code, status))
    emit(body, getattr(a, "out", None), "response")
    return 0 if (code == 200 and status == "success") else 1


if __name__ == "__main__":
    sys.exit(main())
