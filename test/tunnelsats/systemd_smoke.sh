#!/bin/bash
#
# systemd smoke test for the TunnelSats lines of the Lightning units (design 2.1-2.3, 3.3; tests
# 7.3). Needs root and a running systemd: CI runs it with sudo on ubuntu-24.04 (systemd 255); TC-03
# on the VM covers Debian 12 (systemd 252). Do not run it on a RaspiBlitz node.
#
# It installs throwaway runtime units (/run/systemd/system/ts-smoke-*.service) and helpers
# (/usr/local/lib/ts-smoke), starts the units, checks what their main process received and removes
# everything again. The units carry the Lightning unit lines in the same order:
#   EnvironmentFile=-<stray file>        stands in for raspiblitz.conf holding a stray value
#   Environment=<VAR>=                   the value when no file sets the variable
#   EnvironmentFile=-<hybrid env file>   written for this start by the ExecStartPre=+ command
#   ExecStartPre=+<smoke/pre.sh>         production its_guard_init, its_render, its_guard_write_env
#   ExecStart=<argv> $VAR                LND form; CLN form: /bin/sh -c '<argv> $$VAR'
#   User=nobody
# A third unit runs the real script (a byte copy, guard lnd mainnet) on this host, where
# TunnelSats is off.
#
# Usage: sudo test/tunnelsats/systemd_smoke.sh
# Exit 0: all checks passed, 1: a check failed, 2: cannot run here.

# The assertion helpers run through check.
# shellcheck disable=SC2329

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${HERE}/../../home.admin/config.scripts/internet.tunnelsats.sh"
LIB="/usr/local/lib/ts-smoke"
UNIT_DIR="/run/systemd/system"
PROD_RUN="/run/tunnelsats"
PROD_CONF="/mnt/hdd/app-data/raspiblitz.conf"
UNITS=(ts-smoke-lnd ts-smoke-cl ts-smoke-real)
# what pre.sh renders for the endpoint of the verify fixtures
LND_WORDS=(--tor.skip-proxy-for-clearnet-targets --externalhosts=de2.tunnelsats.com:24556)
CLN_WORDS=(--bind-addr=0.0.0.0:9735 --announce-addr=1.2.3.4:24556 --always-use-proxy=false
    --announce-addr-discovered=false)
WORK=""
CREATED_PROD_RUN=0
PASSED=0
FAILED=0

if [[ "$(id -u)" -ne 0 ]]; then
    echo "systemd smoke test: needs root (sudo)" >&2
    exit 2
fi
if [[ ! -d /run/systemd/system ]] || ! command -v systemctl >/dev/null; then
    echo "systemd smoke test: needs a running systemd" >&2
    exit 2
fi
NOBODY_UID="$(id -u nobody)"

cleanup() {
    local u
    for u in "${UNITS[@]}"; do
        systemctl stop "${u}.service" >/dev/null 2>&1 || true
        systemctl reset-failed "${u}.service" >/dev/null 2>&1 || true
        rm -f -- "${UNIT_DIR}/${u}.service"
    done
    systemctl daemon-reload || true
    rm -rf -- "$LIB"
    if [[ -n "$WORK" ]]; then
        rm -rf -- "$WORK"
    fi
    if [[ "$CREATED_PROD_RUN" -eq 1 ]]; then
        rm -rf -- "$PROD_RUN"
    fi
}

check() {   # check <description> <command> [arguments]
    local desc="$1"
    shift
    if "$@"; then
        PASSED=$((PASSED + 1))
        echo "ok - ${desc}"
    else
        FAILED=$((FAILED + 1))
        echo "not ok - ${desc}"
    fi
}

argv_is() {   # argv_is <file> <uid> [word...]: the main process ran as <uid> with exactly these words
    local file="$1" uid="$2" want
    shift 2
    want="$(printf 'uid=%s\nargc=%s\n' "$uid" "$#"; for a in "$@"; do printf 'arg=[%s]\n' "$a"; done)"
    [[ -f "$file" ]] && [[ "$(cat -- "$file")" == "$want" ]]
}

file_is() {   # file_is <file> <line>: the file holds exactly this one line
    [[ -f "$1" ]] && printf '%s\n' "$2" | cmp -s - "$1"
}

owner_mode_is() {   # owner_mode_is <file> "<uid> <mode>"
    [[ "$(stat -c '%u %a' -- "$1" 2>/dev/null)" == "$2" ]]
}

start_unit() {   # start_unit <name>: starts the oneshot unit; shows status and journal on failure
    if systemctl start "$1.service"; then
        return 0
    fi
    systemctl status --no-pager -l "$1.service" || true
    journalctl -b -u "$1.service" --no-pager -n 40 || true
    return 1
}

# set_case <lnd|cl> <hybrid|empty|none> <yes|no>: what pre.sh writes on the next start and whether
# the stray file holds a value
set_case() {
    local impl="$1" mode="$2" stray="$3" base var
    if [[ "$impl" == lnd ]]; then
        base="lnd" var="TUNNELSATS_LND_ARGS"
    else
        base="lightningd" var="TUNNELSATS_CLN_ARGS"
    fi
    printf '%s\n' "$mode" > "${WORK}/ctl/${impl}.mode"
    rm -f -- "${WORK}/run/hybrid-${base}.env" "${WORK}/out/${impl}.argv" "${WORK}/out/pre-${impl}.uid"
    if [[ "$stray" == yes ]]; then
        printf '%s=--stray-flag\n' "$var" > "${WORK}/stray-${base}.env"
    else
        rm -f -- "${WORK}/stray-${base}.env"
    fi
}

form_cases() {   # form_cases <lnd|cl> <unit> <env file base> <variable> <expected words...>
    local impl="$1" unit="$2" var="$4" envf="${WORK}/run/hybrid-${3}.env" out="${WORK}/out/${1}.argv"
    shift 4

    set_case "$impl" hybrid yes
    check "${impl}: start with hybrid flags" start_unit "$unit"
    check "${impl}: exact argv words as nobody, the later file beats the stray value" argv_is "$out" "$NOBODY_UID" "$@"
    check "${impl}: the + command ran as uid 0" file_is "${WORK}/out/pre-${impl}.uid" 0
    check "${impl}: env file holds ${var}=<flags>" file_is "$envf" "${var}=$*"
    check "${impl}: env file is root 0644" owner_mode_is "$envf" "0 644"

    set_case "$impl" empty yes
    check "${impl}: start with the empty value" start_unit "$unit"
    check "${impl}: an empty value adds no argument, the stray value stays out" argv_is "$out" "$NOBODY_UID"
    check "${impl}: env file holds ${var}=" file_is "$envf" "${var}="

    set_case "$impl" none no
    check "${impl}: start without any file" start_unit "$unit"
    check "${impl}: a missing file and Environment=${var}= add no argument" argv_is "$out" "$NOBODY_UID"

    set_case "$impl" none yes
    check "${impl}: start with only the stray file" start_unit "$unit"
    check "${impl}: control: without the later file the stray value arrives (the guard always writes it)" \
        argv_is "$out" "$NOBODY_UID" --stray-flag
}

real_cases() {
    local envf="${PROD_RUN}/hybrid-lnd.env" out="${WORK}/out/real.argv"
    if [[ -e "$PROD_CONF" ]] || [[ -e "$PROD_RUN" ]] || [[ -L "$PROD_RUN" ]]; then
        echo "skip - real script: ${PROD_CONF} or ${PROD_RUN} exists, this is not a throwaway host"
        if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
            FAILED=$((FAILED + 1))
        fi
        return 0
    fi
    check "real: the unit runs a byte copy of internet.tunnelsats.sh" cmp -s "$SRC" "${LIB}/internet.tunnelsats.sh"

    check "real: start (TunnelSats off)" start_unit ts-smoke-real
    check "real: creates nothing (${PROD_RUN} stays absent)" test ! -e "$PROD_RUN"
    check "real: TS_RB_* from the unit environment cannot redirect the script" test ! -e "${WORK}/redirect"
    check "real: no argument" argv_is "$out" "$NOBODY_UID"

    install -d -m 0755 "$PROD_RUN"
    CREATED_PROD_RUN=1
    printf 'TUNNELSATS_LND_ARGS=--planted-flag\n' > "$envf"
    chmod 0644 "$envf"
    rm -f -- "$out"
    check "real: start with a planted flags file" start_unit ts-smoke-real
    check "real: the planted file now holds the empty value" file_is "$envf" "TUNNELSATS_LND_ARGS="
    check "real: no argument (the planted flag stays out)" argv_is "$out" "$NOBODY_UID"
    check "real: the record says noop, tunnelsats_off" \
        grep -q '"decision":"noop","reason":"tunnelsats_off"' "${PROD_RUN}/guard-lnd.json"
}

trap cleanup EXIT
cleanup   # leftovers of an aborted run

WORK="$(mktemp -d /run/ts-smoke.XXXXXX)"
chmod 0755 "$WORK"
install -d -m 0755 "${WORK}/run" "${WORK}/ctl"
install -d -m 0755 -o nobody "${WORK}/out"
printf 'tunnelsats=on\nrunBehindTor=on\n' > "${WORK}/redirect.conf"
install -d -m 0755 "$LIB"
install -m 0755 "${HERE}/smoke/argv.sh" "${LIB}/argv"
install -m 0755 "${HERE}/smoke/pre.sh" "${LIB}/pre"
install -m 0755 "$SRC" "${LIB}/internet.tunnelsats.sh"

cat > "${UNIT_DIR}/ts-smoke-lnd.service" <<EOF
[Unit]
Description=TunnelSats smoke test (LND form)

[Service]
Type=oneshot
TimeoutStartSec=60
User=nobody
Environment=TS_SMOKE_OUT=${WORK}/out/lnd.argv
EnvironmentFile=-${WORK}/stray-lnd.env
Environment=TUNNELSATS_LND_ARGS=
EnvironmentFile=-${WORK}/run/hybrid-lnd.env
ExecStartPre=+${LIB}/pre lnd ${WORK}
ExecStart=${LIB}/argv \$TUNNELSATS_LND_ARGS
EOF

cat > "${UNIT_DIR}/ts-smoke-cl.service" <<EOF
[Unit]
Description=TunnelSats smoke test (CLN form)

[Service]
Type=oneshot
TimeoutStartSec=60
User=nobody
Environment=TS_SMOKE_OUT=${WORK}/out/cl.argv
EnvironmentFile=-${WORK}/stray-lightningd.env
Environment=TUNNELSATS_CLN_ARGS=
EnvironmentFile=-${WORK}/run/hybrid-lightningd.env
ExecStartPre=+${LIB}/pre cl ${WORK}
ExecStart=/bin/sh -c '${LIB}/argv \$\$TUNNELSATS_CLN_ARGS'
EOF

cat > "${UNIT_DIR}/ts-smoke-real.service" <<EOF
[Unit]
Description=TunnelSats smoke test (real guard, TunnelSats off)

[Service]
Type=oneshot
TimeoutStartSec=60
User=nobody
Environment=TS_SMOKE_OUT=${WORK}/out/real.argv
Environment=TS_RB_RUN_DIR=${WORK}/redirect TS_RB_CONF=${WORK}/redirect.conf
Environment=TUNNELSATS_LND_ARGS=
EnvironmentFile=-${PROD_RUN}/hybrid-lnd.env
ExecStartPre=+${LIB}/internet.tunnelsats.sh guard lnd mainnet
ExecStart=${LIB}/argv \$TUNNELSATS_LND_ARGS
EOF

systemctl daemon-reload

form_cases lnd ts-smoke-lnd lnd TUNNELSATS_LND_ARGS "${LND_WORDS[@]}"
form_cases cl ts-smoke-cl lightningd TUNNELSATS_CLN_ARGS "${CLN_WORDS[@]}"
real_cases

version="$(systemctl --version 2>/dev/null | sed -n '1s/^systemd \([0-9]*\).*/\1/p')" || version="?"
echo "systemd smoke (systemd ${version}): ${PASSED} passed, ${FAILED} failed"
if [[ "$FAILED" -ne 0 ]]; then
    exit 1
fi
exit 0
