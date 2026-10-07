# panos-pty-cli

Two small, stdlib-only Python tools for talking to Palo Alto Networks
firewalls (PAN-OS) from a Linux box:

- **`panos_pty.py`** — a pty-based CLI driver. Feeds CLI commands to the
  firewall's ssh console and reliably captures the output, even from a slow,
  paged, ANSI-noisy appliance terminal.
- **`panos_api.py`** — a minimal PAN-OS XML API client (`keygen`, op reads,
  running-config dump) that encodes the 10.x API quirks that cost real
  debugging time.

Python 3.8+, standard library only. No `expect`, no `paramiko`, no
`sshpass`.

Developed and verified against a PA-440 running PAN-OS 10.1.3.

---

## Why a custom driver in the first place

The PAN-OS management CLI, reached over ssh, is **not a protocol** — it is a
raw terminal byte stream. That makes the obvious tools fail:

| Tool tried | Why it fails on PAN-OS |
|---|---|
| `sshpass` / one-prompt expect | Login is **two-stage**: banner `Do you acknowledge ... (yes/no)` **then** `Password:`. One-prompt automation hangs at the ack. |
| Fixed sleeps after each command | Large displays **trickle** in at ~2–4 lines/second; a full `show config running` can take many minutes. Sleeps mis-time everything. |
| "Prompt seen = command done" | The CLI **re-echoes your typed command token-by-token with the prompt re-rendered between tokens** — the prompt string appears in the buffer *immediately* and *mid-buffer*. (v1 of this driver hung 300 s on this exact bug.) |
| XML API (as the only path) | Works, but: key must be generated per device, and on some builds/versions the API surface is a subset of the CLI. A CLI driver is the universal fallback. |
| SFTP to the mgmt IP | Login completes, but the command loop returns only echoes — execution is unverifiable. |

The only reliable completion signal on such a device is: *the device stopped
talking, and it is asking for input again.* Both tools below are built
around that.

### The three reusable insights

1. **The two-condition completion rule.** A command is done only when BOTH
   (a) no new bytes for ≥ N seconds (true quiescence) AND (b) the last
   non-empty line — after stripping ANSI escapes *and* non-printable bytes —
   matches your prompt pattern and ends with a prompt character (`>` / `#`).
   An echoed prompt mid-buffer never qualifies (output still follows it); a
   prompt with invisible trailing bytes no longer defeats it.
2. **A 3000×400 pty window** suppresses paging for almost every display
   ("a screen so large the pager almost never engages"). When paging does
   happen (`--More--`, `(press RETURN)`, `lines 1-` footers), the driver
   detects the marker, truncates the capture at it, and feeds a RETURN.
3. **Quiescence over sleeps** — wait for the device to stop, never for a
   fixed duration.

## `panos_pty.py` — the pty CLI driver

```
export PANOS_PASSWORD='...'          # the password lives only in the env
printf 'show system info\nshow config running\n' |
  python3 panos_pty.py \
    --host 192.0.2.10 --user admin \
    --password-env PANOS_PASSWORD \
    --prompt-regex 'admin@my-fw'
```

- Commands: one per line on stdin (or `--file`); blank lines and `#` comments
  ignored. All commands run in **one** login session.
- Each command's ANSI-stripped output is printed to stdout with a
  `===== CMD: ... [done|TIMEOUT] =====` header; the full session goes to a
  log file (path printed at the end, `--log-dir` to choose).
- The password is read from the env var named by `--password-env`, never
  printed, and masked in every log/failure dump.
- Exit codes: `0` session ran (check the per-command markers), `3` login
  failed/timed out, `4` password env var missing/empty.

Key options (see `--help` for the full list):

| Option | Default | Purpose |
|---|---|---|
| `--prompt-regex` | — (required) | matched against the last line to detect the bare prompt; anchor with `^` if output could contain prompt-like text |
| `--idle-done` | `1.5` | quiescence window (condition a) |
| `--cmd-timeout` | `900` | per-command wall clock (large displays can be very slow) |
| `--stable` | `0` | extra seconds the bare prompt must survive after first detection — raise this for devices that pause > `--idle-done` *mid-output* |
| `--window` | `3000x400` | pty rows×cols (paging suppression) |
| `--page-markers` | `--More-- (press RETURN) lines 1-` | paging footer strings |
| `--ssh-extra-args` | — | e.g. `-J bastion` |
| `--use-ssh-config` | off | by default ssh gets `-F /dev/null` (deterministic; also required on hosts whose `/etc/ssh/ssh_config.d` includes have bad ownership) |
| `--exec-cmd` | — | testing/escape hatch: replace the ssh invocation with an arbitrary command (used by the test suite) |

### The v1 → v2 post-mortem (read this before modifying the completion rule)

v1 declared a command done as soon as the prompt string appeared *anywhere*
in the buffer — which is true **immediately**, because the shell echoes
`admin@my-fw> <your command>` back at you token by token with the prompt
re-rendered between tokens. v1 then drained on 0.25 s of silence and raced
the still-streaming output: one 300 s hang, one truncated capture.

The v2 rule (bare prompt **at the tail**, after **real** quiescence) is
immune: an echoed prompt is mid-buffer while output follows, so it never
qualifies.

A later field bug (fixed, and now regression-tested) showed the tail check
itself needs hygiene: a clean prompt followed by invisible bytes — e.g. an
ANSI erase-line `\x1b[2K` — looks like `admin@my-fw> [2K` to a naive check
(CSI sequences contain *printable* characters, so removing non-printables
alone is not enough). The check therefore strips full ANSI escape sequences
**first**, then remaining non-printables, then rstrips.

## `panos_api.py` — the XML API client

```
# 1. Generate a key (it is printed ONLY ONCE -- store it immediately)
python3 panos_api.py keygen --host 192.0.2.10 --user admin \
    --password-env PANOS_PASSWORD --key-out ~/.panos_api_key

# 2. Operational reads (key from file, --key-env, or PANOS_API_KEY)
python3 panos_api.py show 'show system info' --host 192.0.2.10 \
    --key-file ~/.panos_api_key

# 3. Raw XML op call
python3 panos_api.py op '<show><system><info/></system></show>' --host 192.0.2.10

# 4. Running config to a mode-0600 file (it contains the admin password hash)
python3 panos_api.py config --host 192.0.2.10 --out config.xml
```

**Read-only by default**: any command XML containing a write verb
(`set delete commit load save edit move rename revert restart factory-reset
lock unlock clear upgrade`) is refused unless you pass `--allow-write`.

### PAN-OS 10.x API quirks (each verified on a live 10.1.3 box)

The client encodes all of these; the table is here so nobody re-learns them
the hard way:

| Quirk | Symptom | Resolution (encoded in the client) |
|---|---|---|
| Keygen type is `keygen` | `type=generate-key` → 403 "Invalid Credential" (it is not a real type) | `type=keygen&user=...&password=...` |
| Key returned only once | you cannot retrieve it later | store it at generation (`--key-out`) |
| Auth runs **before** XML parsing | bad key → 403, good key + bad XML → 400 | use the two error codes to localize failures |
| Op verb is `<show>` | `<get>` → code 17 "get is unexpected" | `<show>` for op commands |
| Empty elements must be self-closing | `<info></info>` → 400 "Request is not a valid XML" | `normalize_empty_elements()` rewrites `<tag></tag>` → `<tag/>` |
| 10.1.3 system info path | `<system><status/>` → code 17 "is unexpected" | `<show><system><info/></system></show>` |
| Running config path | — | `<show><config><running/></config></show>` |
| Key transport | in URL = in every log | `X-PAN-KEY` header by default (`--key-in-param` to opt out) |
| TLS | self-signed cert | verification off by default with a loud warning; `--verify` to require a valid cert |

`show 'CLI command'` converts a simple CLI command to API XML
(`show system info` → `<show><system><info/></system></show>`); commands
needing attributes must be written as raw XML for the `op` subcommand.

## Testing

The test suite runs the **real driver as a subprocess** against
`tests/fake_appliance.py`, a local pty "device" that reproduces, in style,
every pathology a naive driver gets wrong: two-stage login, token-echoed
commands with prompt re-render, slow trickle, `--More--` paging, ANSI noise,
CR-only line endings, and invisible trailing bytes after the final prompt.
No network, no real device, stdlib only.

```
python3 -m unittest -v tests.test_panos_pty   # 10 tests, ~50 s
python3 -m unittest -v tests.test_panos_api   # 19 fast unit tests
```

## Security notes

- The password and API key never appear on command lines, in the repo, or in
  logs: password via `--password-env`, key via file (0600) / env var. The
  pty driver masks the password in every log line and failure dump (a pty
  can echo typed credentials back into the capture buffer).
- `panos_api.py` is read-only by default (write-verb guard).
- Session logs and config dumps contain **configuration content** — running
  config includes the admin password *hash* (`mgt-config users admin phash`).
  Keep them local; do not publish them.
- The pty driver talks ssh to the firewall: it inherits your ssh key/host
  configuration unless `--use-ssh-config` is given (default is `-F
  /dev/null`, i.e. no system ssh config at all).

## Known limitations

- Completion is inferred from quiescence + bare prompt: a device that pauses
  for more than `--idle-done` seconds *mid-command* would be misread as done
  (raise `--idle-done`, or use `--stable` for a double check).
- The pty driver assumes the login flow is "optional banner ack, then
  one password prompt" — the PAN-OS pattern. Other multi-stage flows need
  `--ack-pattern`/`--ack-answer` tuning.
- `panos_api.py` targets the PAN-OS (not Panorama) API surface; command
  trees vary between PAN-OS versions, so a path that is "unexpected" on your
  build may be valid on another (the device's code-17 error tells you
  precisely which path it rejects).

## Provenance

Salvaged and generalized from a private driver built and debugged against a
production PA-440 (PAN-OS 10.1.3) in October 2026. All device-specific
values (IPs, hostnames, credentials, serial numbers) were stripped; examples
use TEST-NET-1 (192.0.2.0/24) placeholders.

## License

MIT — see [LICENSE](LICENSE). (Copyright holder to be confirmed by the
author before publishing.)
