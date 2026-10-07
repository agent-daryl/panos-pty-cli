#!/usr/bin/env bash
# panos.sh -- API-first, pty-fallback front end for panos_api.py + panos_pty.py.
#
# Order of operation, per command:
#   1. If an API key is available AND the command is a *simple read* (first
#      token 'show', at least two tokens, every token a bare word), it is
#      tried through the XML API first (panos_api.py show ...).
#   2. If the API is unreachable, refuses the key, or rejects the command
#      (any non-zero exit from panos_api.py), the command is queued for the
#      pty driver.
#   3. After the API pass, ALL queued commands run in ONE pty session
#      (panos_pty.py) -- one login, not one per command.
#
# Anything that is not a simple read (configure/set/commit, interface names
# with slashes, etc.) goes straight to the pty queue. Writes are never sent
# through the API by this wrapper (panos_api.py is read-only by default and
# this wrapper does not pass --allow-write).
#
# stdout carries data (API XML responses and/or pty command blocks);
# stderr carries status lines like:
#   panos.sh: 'show system info' -> API
#   panos.sh: 'show config running' -> API failed, queuing for pty
#
# Credential handling:
#   API key : --key-file FILE, or the PANOS_API_KEY env var, or absent
#   password: the env var named by --password-env (default PANOS_PASSWORD);
#             only needed if the pty path actually runs
#   Store the password in a 0600 file and load it inline so it does not
#   land in shell history:
#       PANOS_PASSWORD="$(cat ~/.panos_pw)" ./panos.sh ...
#
# One-time setup (generate an API key):
#   python3 panos_api.py keygen --host 192.0.2.10 --user admin \
#       --password-env PANOS_PASSWORD --key-out ~/.panos_api_key
#
# Usage:
#   ./panos.sh --host 192.0.2.10 --user admin \
#       --key-file ~/.panos_api_key --prompt-regex 'admin@my-fw' \
#       'show system info' 'show config running'
#
# Exit codes: 0 all commands completed; 2 usage error; 3 pty login failed;
#             4 pty fallback needed but PANOS_PASSWORD not set;
#             plus panos_api.py / panos_pty.py codes when they are final.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HOST=""
PORT=443
USER_NAME=""
KEY_FILE=""
SSH_PORT=""
PROMPT_REGEX=""
PASSWORD_ENV="PANOS_PASSWORD"
API_TIMEOUT=15
PTY_EXEC_CMD=""
declare -a PTY_EXTRA=()
declare -a COMMANDS=()

usage() {
    grep '^#' "$0" | sed -n '2,40p' | sed 's/^# \{0,1\}//'
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)           HOST="$2"; shift 2;;
        --port)           PORT="$2"; shift 2;;
        --user)           USER_NAME="$2"; shift 2;;
        --key-file)       KEY_FILE="$2"; shift 2;;
        --ssh-port)       SSH_PORT="$2"; shift 2;;
        --prompt-regex)   PROMPT_REGEX="$2"; shift 2;;
        --password-env)   PASSWORD_ENV="$2"; shift 2;;
        --api-timeout)    API_TIMEOUT="$2"; shift 2;;
        --pty-extra)      PTY_EXTRA+=("$2"); shift 2;;
        --pty-exec-cmd)   PTY_EXEC_CMD="$2"; shift 2;;
        -h|--help)        usage;;
        -*)               echo "panos.sh: unknown option: $1" >&2; usage;;
        *)                COMMANDS+=("$1"); shift;;
    esac
done

if [[ -z "$HOST" ]]; then
    echo "panos.sh: --host is required" >&2
    exit 2
fi
if [[ ${#COMMANDS[@]} -eq 0 ]]; then
    echo "panos.sh: no commands given (quote multi-word commands)" >&2
    exit 2
fi

# ---- API availability ----
have_key=0
api_args=(--host "$HOST" --port "$PORT" --timeout "$API_TIMEOUT")
if [[ -n "$KEY_FILE" && -r "$KEY_FILE" ]]; then
    have_key=1
    api_args+=(--key-file "$KEY_FILE")
elif [[ -n "${PANOS_API_KEY:-}" ]]; then
    have_key=1
fi

# ---- pty argument accumulation (only used if the fallback runs) ----
pty_args=(--host "$HOST" --password-env "$PASSWORD_ENV")
[[ -n "$USER_NAME" ]]    && pty_args+=(--user "$USER_NAME")
[[ -n "$SSH_PORT" ]]     && pty_args+=(--ssh-port "$SSH_PORT")
[[ -n "$PROMPT_REGEX" ]] && pty_args+=(--prompt-regex "$PROMPT_REGEX")
if [[ -n "$PTY_EXEC_CMD" ]]; then
    pty_args+=(--exec-cmd "$PTY_EXEC_CMD")
fi
if [[ ${#PTY_EXTRA[@]} -gt 0 ]]; then
    pty_args+=("${PTY_EXTRA[@]}")
fi

# A command is API-eligible iff it is a simple read: first token 'show',
# >= 2 tokens, every token a bare element name (no slashes/quotes/attrs).
is_api_eligible() {
    local cmd="$1"
    local -a toks
    read -ra toks <<< "$cmd"
    [[ ${#toks[@]} -ge 2 ]] || return 1
    [[ "${toks[0]}" == "show" ]] || return 1
    local t
    for t in "${toks[@]}"; do
        [[ "$t" =~ ^[A-Za-z][A-Za-z0-9_.-]*$ ]] || return 1
    done
    return 0
}

pty_queue=()
for cmd in "${COMMANDS[@]}"; do
    if [[ "$have_key" -eq 1 ]] && is_api_eligible "$cmd"; then
        if python3 "$SCRIPT_DIR/panos_api.py" show "$cmd" "${api_args[@]}"; then
            echo "panos.sh: '$cmd' -> API" >&2
        else
            echo "panos.sh: '$cmd' -> API failed, queuing for pty" >&2
            pty_queue+=("$cmd")
        fi
    else
        pty_queue+=("$cmd")
    fi
done

if [[ ${#pty_queue[@]} -gt 0 ]]; then
    if [[ -z "${!PASSWORD_ENV:-}" ]]; then
        echo "panos.sh: pty fallback needs the $PASSWORD_ENV env var" >&2
        exit 4
    fi
    if [[ -z "$USER_NAME" || -z "$PROMPT_REGEX" ]]; then
        echo "panos.sh: pty fallback needs --user and --prompt-regex" >&2
        exit 2
    fi
    printf '%s\n' "${pty_queue[@]}" | python3 "$SCRIPT_DIR/panos_pty.py" "${pty_args[@]}"
    exit $?
fi

exit 0
