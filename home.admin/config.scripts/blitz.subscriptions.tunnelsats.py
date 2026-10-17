#!/usr/bin/python3
"""TunnelSats VPN subscription for RaspiBlitz (SSH menu > SUBSCRIBE > TunnelSats).

TunnelSats routes the node's Lightning clearnet traffic through a WireGuard VPN; Tor stays on for
onion peers. The dataplane is TunnelSats' own tunnelsats.sh in managed mode, driven through
internet.tunnelsats.sh (pinned and verified tool, start guard, restore block). This module keeps
the subscription (a WireGuard config rebuilt from validated fields, plus state) and orchestrates
import, adoption, checks, repair and removal.

Verbs (all with --json; every verb except --help needs root, the state is root 0600):
  menu | import --file FILE [--impl lnd|cl] [--dry-run] [--yes] | adopt [--yes] [--upgrade]
  status [--refresh|--cached] | check | detect | repair [--impl lnd|cl] --yes
  uninstall --yes [--purge] | subscriptions-list | tick

Key custody: the private key exists only in tunnelsats.conf (root 0600) and in the config
tunnelsats.sh derives from it. It never appears in argv, environment variables, logs, JSON output,
raspiblitz.conf or notifications; the public key is derived in-process (RFC 7748 X25519).
"""

import argparse
import base64
import datetime
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
import re
import secrets
import signal
import ssl
import subprocess
import sys
import time
import urllib.parse

MODULE_VERSION = "0.2.0"
CONTRACT = 1

# Exit codes (module column of the contract)
EXIT_OK = 0
EXIT_OPERATIONAL = 1
EXIT_USAGE = 2
EXIT_NOT_CONFIGURED = 3
EXIT_UNSAFE = 4
EXIT_DEGRADED = 5
EXIT_INVALID_API = 12
EXIT_API_UNAVAILABLE = 13
EXIT_REFUSED = 14

# Production paths (relative to Deps.root in tests)
APPDATA = "/mnt/hdd/app-data"
STATE_DIR = APPDATA + "/tunnelsats"
CONF_FILE = STATE_DIR + "/tunnelsats.conf"
STATE_FILE = STATE_DIR + "/state.json"
LAST_RESTORE_FILE = STATE_DIR + "/last-restore.json"
RB_CONF = APPDATA + "/raspiblitz.conf"
CUSTOM_INSTALLS = APPDATA + "/custom-installs.sh"
RUN_DIR = "/run/tunnelsats"
# uninstall --managed of the pinned tool (and a failed install's rollback) removes RUN_DIR: the lock
# lives next to it, in a root 0700 directory of its own
LOCK_DIR = "/run/tunnelsats-rb"
LOCK_FILE = LOCK_DIR + "/module.lock"
STOPPED_UNITS = RUN_DIR + "/stopped-units"
ITS = "/home/admin/config.scripts/internet.tunnelsats.sh"
BLITZ_CONF = "/home/admin/config.scripts/blitz.conf.sh"
NOTIFY = "/home/admin/config.scripts/blitz.notify.sh"
LND_ASSET = "/home/admin/assets/lnd.service"
CL_INSTALL_SERVICE = "/home/admin/config.scripts/cl.install-service.sh"
LND_UNLOCK = "/home/admin/config.scripts/lnd.unlock.sh"
CL_HSMTOOL = "/home/admin/config.scripts/cl.hsmtool.sh"
LNCLI = ["sudo", "-u", "bitcoin", "/usr/local/bin/lncli", "-n=mainnet", "--rpcserver", "localhost:10009"]
UNIT_DIR = "/etc/systemd/system"
LEGACY_CONF_RE = re.compile(r"/etc/wireguard/[A-Za-z0-9_.-]{1,64}\.conf")

API_STATUS_URL = "https://tunnelsats.com/api/public/v1/subscription/status"
API_CONNECT_TIMEOUT = 15
API_READ_TIMEOUT = 30
API_MAX_BYTES = 65536
API_CACHE_SECONDS = 6 * 3600

# Timeouts (s) for internet.tunnelsats.sh, each above the script's own worst case, so the script
# ends by itself and cleans up; run_command stops the whole process group only as a last resort.
ITS_TIMEOUT = {
    "fetch": 300,            # its_fetch_online: TS_RB_FETCH_BUDGET (240) for all network steps
    "detect": 420,           # a fetch when no copy is stored, then the tool's detect (120, +10 kill)
    "install": 960,          # the tool's install --managed (900, +10 kill)
    "uninstall": 660,        # the tool's uninstall --managed (600, +10 kill)
    "verify": 150,           # the tool's verify with probes (120, +10 kill)
    "verify_no_probe": 60,   # the tool's verify --no-probe (35, +10 kill)
    "status": 60,            # one verify --no-probe (TS_RB_VERIFY_TIMEOUT 30, +5 kill)
    "guard_dry_run": 120,    # one verify (30, +5 kill), no handshake wait in --dry-run
}

IMPLS = ("lnd", "cl")
UNITS = {"lnd": "lnd.service", "cl": "lightningd.service"}
IMPL_OF_UNIT = {unit: impl for impl, unit in UNITS.items()}
OTHER_IMPL = {"lnd": "cl", "cl": "lnd"}
BASES = {"lnd": "lnd", "cl": "lightningd"}
VARS = {"lnd": "TUNNELSATS_LND_ARGS", "cl": "TUNNELSATS_CLN_ARGS"}
RESTARTABLE = ("emergency_block", "verify_timeout", "verify_unsafe", "verify_failed", "verify_invalid",
               "verify_inconsistent", "not_installed", "tool_missing", "unit_mismatch", "announce_unconfirmed")
RESTART_MESSAGE = ("TunnelSats: the tunnel is ready again. Restart Lightning to resume clearnet connections "
                   "(SSH menu > SUBSCRIBE > TunnelSats).")
# announce_cleanup of the tool's uninstall --managed (contract 1, additive since tunnelsats PR 230): its
# own step that takes the former VPN address out of LND's node announcement
TOOL_ANNOUNCE_RESULTS = ("removed", "none", "lnd_not_ready", "failed", "skipped")
# unit file states in which no boot starts a unit (read back after systemctl disable)
BOOT_OFF = ("disabled", "masked", "masked-runtime")
# an IPv4 address with a port, as the tool's announcement warnings name them
ADDRESS_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}\b")
# REPAIR and IMPORT check the node only once the Lightning unit the tool or the module (re)started
# has left "activating" (LND until it is ready, Type=notify; verify reports such a start as
# degraded): at most LN_START_WAIT seconds, read every LN_START_STEP seconds
LN_START_WAIT = 90
LN_START_STEP = 3
# the drop-in with which install --managed puts the managed unit into the slice, as detect reports it
# (artifact managed_ln_dropin)
DROPIN_RE = re.compile(r"/etc/systemd/system/([A-Za-z0-9_.@-]+\.service)\.d/tunnelsats-managed\.conf")

# Validators, always applied with fullmatch: with match, a "$" would also accept a final newline
KEY_RE = re.compile(r"[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=")
HOST_RE = re.compile(r"([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+tunnelsats\.com")
ISO_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})")
SECTION_RE = re.compile(r"\[([A-Za-z]+)\]")
KV_RE = re.compile(r"([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*)")
PORT_COMMENT_RE = re.compile(r"#\s*(?:Port Forwarding\s*:|VPNPort\s*=)\s*(\S+)\s*", re.IGNORECASE)
VALID_UNTIL_RE = re.compile(r"#\s*Valid Until\s*:\s*(\S+)\s*", re.IGNORECASE)
MYPUBKEY_RE = re.compile(r"#\s*myPubKey\s*:\s*(\S+)\s*", re.IGNORECASE)
DROPPED_KEYS = ("dns", "postup", "postdown", "preup", "predown", "table", "fwmark", "saveconfig", "listenport")
MAX_CONFIG_BYTES = 16384

LND_FLAG_RE = re.compile(r"--(tor\.skip-proxy-for-clearnet-targets(=.*)?|externalhosts=.*)")
CLN_FLAG_RE = re.compile(r"--(bind-addr=0\.0\.0\.0:9735|always-use-proxy=false|announce-addr-discovered=false|announce-addr=(?!.*\.onion).*)")


class ModuleError(Exception):
    """An error with a stable code; the message never holds key material or config values."""

    def __init__(self, code, cls, message, exit_code):
        super().__init__(message)
        self.code = code
        self.cls = cls
        self.message = message
        self.exit_code = exit_code


# ------------------------------------------------------------------------------------------
# Effects (injectable)
# ------------------------------------------------------------------------------------------

def stop_group(proc, grace=10):
    """Stops the process group of proc (started with start_new_session): SIGTERM, so the scripts'
    EXIT and TERM traps can remove their temp files, SIGKILL after grace seconds. Reaps proc."""
    for sig, wait in ((signal.SIGTERM, grace), (signal.SIGKILL, 5)):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            pass
        try:
            proc.communicate(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue
    proc.kill()
    proc.communicate()


def run_command(argv, timeout=60, interactive=False):
    """Runs argv (a list, never through a shell). Returns (rc, stdout, stderr); a timeout is rc 124.
    The command runs in its own process group, so a timeout stops it with all its children."""
    if interactive:
        return subprocess.run(argv, timeout=timeout, check=False).returncode, "", ""
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True)
    except OSError as exc:
        return 127, "", str(exc)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        stop_group(proc)
        return 124, "", "timeout"
    except BaseException:
        stop_group(proc)
        raise
    return proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


def http_post_json(url, payload):
    """POST JSON over TLS (certificate verification on, no proxy). Returns (status, headers, body).
    15 s to connect, 30 s per read, at most API_MAX_BYTES of body. Raises OSError on failure."""
    parts = urllib.parse.urlsplit(url)
    body = json.dumps(payload).encode()
    conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=API_CONNECT_TIMEOUT,
                                       context=ssl.create_default_context())
    try:
        conn.connect()
        conn.sock.settimeout(API_READ_TIMEOUT)
        conn.request("POST", parts.path, body=body, headers={
            "Content-Type": "application/json", "Accept": "application/json",
            "User-Agent": "TunnelSats-RaspiBlitz/" + MODULE_VERSION})
        resp = conn.getresponse()
        raw = resp.read(API_MAX_BYTES + 1)
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, headers, raw
    except (http.client.HTTPException, ssl.SSLError) as exc:
        raise OSError(str(exc)) from None
    finally:
        conn.close()


class Deps:
    """External effects: filesystem root, HTTP, commands, clock, sleep, privilege."""

    def __init__(self, root="/", http=None, run=None, clock=None, sleep=None, is_root=None, log=None):
        self.root = root
        self.http = http or http_post_json
        self.run = run or run_command
        self.clock = clock or (lambda: datetime.datetime.now(datetime.timezone.utc))
        self.sleep = sleep or time.sleep
        self.is_root = is_root or (lambda: os.geteuid() == 0)
        self.log = log or (lambda msg: print(msg, file=sys.stderr))

    def path(self, p):
        return os.path.join(self.root, p.lstrip("/"))


# ------------------------------------------------------------------------------------------
# Small helpers
# ------------------------------------------------------------------------------------------

def now_iso(deps):
    return deps.clock().strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value):
    """Returns an aware datetime for an ISO-8601 string, or None."""
    if not isinstance(value, str) or not ISO_RE.fullmatch(value):
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    frac = re.search(r"\.(\d+)", text)
    if frac and len(frac.group(1)) > 6:
        text = text.replace(frac.group(0), "." + frac.group(1)[:6])
    try:
        return datetime.datetime.fromisoformat(text)
    except ValueError:
        return None


def valid_host(host):
    return isinstance(host, str) and len(host) <= 253 and HOST_RE.fullmatch(host) is not None


def valid_port(port):
    return isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535


def is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0


def is_count(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def parse_one_json(text):
    """The single JSON object in text, or None."""
    try:
        decoder = json.JSONDecoder()
        doc, end = decoder.raw_decode(text.strip())
        if text.strip()[end:].strip() or not isinstance(doc, dict):
            return None
        return doc
    except (ValueError, AttributeError):
        return None


def read_rb_conf(deps):
    """raspiblitz.conf as a dict (KEY=v, KEY='v', KEY="v"; last wins); parsed, never sourced."""
    values = {}
    try:
        with open(deps.path(RB_CONF), encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return values
    for line in lines:
        match = re.fullmatch(r"\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)", line.rstrip("\r"))
        if not match:
            continue
        value = match.group(2)
        if value.startswith("'"):
            value = value[1:].split("'", 1)[0]
        elif value.startswith('"'):
            value = value[1:].split('"', 1)[0]
        else:
            value = value.split()[0] if value.split() else ""
        values[match.group(1)] = value
    return values


def ensure_dir(path, mode):
    if not os.path.isdir(path):
        os.makedirs(path, mode=mode, exist_ok=True)
    os.chmod(path, mode)


def write_private(path, data, mode=0o600):
    """Writes bytes atomically: O_CREAT|O_EXCL temp file (mode 0600), fsync, rename, fsync of the
    directory, read back."""
    directory = os.path.dirname(path)
    fd = None
    tmp = None
    for _ in range(20):
        tmp = os.path.join(directory, ".%s.%s" % (os.path.basename(path), secrets.token_hex(6)))
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
            break
        except FileExistsError:
            continue
    if fd is None:
        raise ModuleError("E_WRITE_FAILED", "operational", "no temp file in %s" % directory, EXIT_OPERATIONAL)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise ModuleError("E_WRITE_FAILED", "operational", "%s could not be written" % path, EXIT_OPERATIONAL) from None
    with open(path, "rb") as handle:
        if handle.read() != data:
            raise ModuleError("E_WRITE_FAILED", "operational", "%s did not read back" % path, EXIT_OPERATIONAL)


def shred(path):
    """Overwrites a file with random bytes before deleting it (best effort on journaling media)."""
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as handle:
            handle.write(secrets.token_bytes(max(size, 1)))
            handle.flush()
            os.fsync(handle.fileno())
        os.unlink(path)
    except FileNotFoundError:
        pass


# ------------------------------------------------------------------------------------------
# X25519 (RFC 7748): the public key, derived in-process
# ------------------------------------------------------------------------------------------

_P = 2 ** 255 - 19
_A24 = 121665


def x25519(scalar, u_coord):
    """X25519(k, u) of RFC 7748 section 5 on 32-byte strings."""
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k_int = int.from_bytes(k, "little")
    u = bytearray(u_coord)
    u[31] &= 127
    x_1 = int.from_bytes(u, "little") % _P
    x_2, z_2, x_3, z_3, swap = 1, 0, x_1, 1, 0
    for t in reversed(range(255)):
        k_t = (k_int >> t) & 1
        swap ^= k_t
        if swap:
            x_2, x_3, z_2, z_3 = x_3, x_2, z_3, z_2
        swap = k_t
        a = (x_2 + z_2) % _P
        aa = a * a % _P
        b = (x_2 - z_2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x_3 + z_3) % _P
        d = (x_3 - z_3) % _P
        da = d * a % _P
        cb = c * b % _P
        x_3 = (da + cb) * (da + cb) % _P
        z_3 = x_1 * (da - cb) * (da - cb) % _P
        x_2 = aa * bb % _P
        z_2 = e * (aa + _A24 * e) % _P
    if swap:
        x_2, x_3, z_2, z_3 = x_3, x_2, z_3, z_2
    return (x_2 * pow(z_2, _P - 2, _P) % _P).to_bytes(32, "little")


def public_key_of(private_b64):
    """The WireGuard public key (base64) of a base64 private key."""
    raw = base64.b64decode(private_b64, validate=True)
    if len(raw) != 32:
        raise ModuleError("E_CONFIG_INVALID", "usage", "PrivateKey is not a 32-byte key", EXIT_USAGE)
    return base64.b64encode(x25519(raw, (9).to_bytes(32, "little"))).decode()


# ------------------------------------------------------------------------------------------
# WireGuard config: parser, validator, canonical rebuild (the claim trust boundary for files)
# ------------------------------------------------------------------------------------------

def _invalid(code, message):
    return ModuleError(code, "usage", message, EXIT_USAGE)


def parse_wg_config(data):
    """Validates a website or exported WireGuard config (bytes) and returns a dict of the validated
    fields plus warnings. Errors name keys and line numbers, never values."""
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_CONFIG_BYTES:
        raise _invalid("E_CONFIG_INVALID", "the config is larger than 16 KiB")
    if b"\x00" in data:
        raise _invalid("E_CONFIG_INVALID", "the config holds NUL bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise _invalid("E_CONFIG_INVALID", "the config is not UTF-8") from None
    warnings = []
    sections = {}
    current = None
    port = None
    valid_until = None
    mypubkey = None
    for number, raw in enumerate(text.split("\n"), start=1):
        line = raw[:-1] if raw.endswith("\r") else raw
        if any(ord(ch) < 32 and ch != "\t" for ch in line) or "\x7f" in line:
            raise _invalid("E_CONFIG_INVALID", "line %d holds a control character" % number)
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            for regex, label in ((PORT_COMMENT_RE, "port"), (VALID_UNTIL_RE, "valid"), (MYPUBKEY_RE, "pub")):
                match = regex.fullmatch(line)
                if not match:
                    continue
                value = match.group(1)
                if label == "port":
                    if port is not None:
                        raise _invalid("E_CONFIG_INVALID", "line %d: a second port comment" % number)
                    if not re.fullmatch(r"[1-9][0-9]{0,4}", value) or int(value) > 65535:
                        raise _invalid("E_CONFIG_NO_PORT", "line %d: the port comment is not a port number" % number)
                    port = int(value)
                elif label == "valid":
                    if valid_until is not None:
                        raise _invalid("E_CONFIG_INVALID", "line %d: a second Valid Until comment" % number)
                    if parse_iso(value) is None:
                        warnings.append("line %d: Valid Until is not an ISO-8601 time and was dropped" % number)
                    else:
                        valid_until = value
                else:
                    if mypubkey is not None:
                        raise _invalid("E_CONFIG_INVALID", "line %d: a second myPubKey comment" % number)
                    mypubkey = value
                break
            continue
        section = SECTION_RE.fullmatch(line)
        if section:
            name = section.group(1).lower()
            if name not in ("interface", "peer"):
                raise _invalid("E_CONFIG_INVALID", "line %d: unknown section" % number)
            if name in sections:
                raise _invalid("E_CONFIG_INVALID", "line %d: a second [%s] section" % (number, section.group(1)))
            sections[name] = {}
            current = name
            continue
        if "#" in line:
            line = line.split("#", 1)[0].rstrip()
        match = KV_RE.fullmatch(line)
        if not match or current is None:
            raise _invalid("E_CONFIG_INVALID", "line %d is not a key = value line inside a section" % number)
        key = match.group(1).lower()
        if key in sections[current]:
            raise _invalid("E_CONFIG_INVALID", "line %d: duplicate key %s" % (number, match.group(1)))
        sections[current][key] = (number, match.group(2).strip(), match.group(1))
    if "interface" not in sections or "peer" not in sections:
        raise _invalid("E_CONFIG_INVALID", "the config needs exactly one [Interface] and one [Peer] section")
    if port is None:
        raise _invalid("E_CONFIG_NO_PORT", "the config has no '# Port Forwarding:' comment (the VPN port)")
    known = {"interface": ("privatekey", "address", "mtu"),
             "peer": ("publickey", "presharedkey", "endpoint", "allowedips", "persistentkeepalive")}
    for name, entries in sections.items():
        for key, (number, _value, label) in sorted(entries.items(), key=lambda item: item[1][0]):
            if key not in known[name]:
                reason = "is not used by managed mode" if key in DROPPED_KEYS else "is unknown"
                warnings.append("line %d: %s %s and was dropped" % (number, label, reason))
    iface, peer = sections["interface"], sections["peer"]

    def required(entries, key, label):
        if key not in entries:
            raise _invalid("E_CONFIG_INVALID", "%s is missing" % label)
        return entries[key]

    number, private_key, _ = required(iface, "privatekey", "PrivateKey")
    if not KEY_RE.fullmatch(private_key):
        raise _invalid("E_CONFIG_INVALID", "line %d: PrivateKey is not a WireGuard key" % number)
    number, address_text, _ = required(iface, "address", "Address")
    addresses = []
    for part in [p.strip() for p in address_text.split(",") if p.strip()]:
        try:
            interface = ipaddress.ip_interface(part)
        except ValueError:
            raise _invalid("E_CONFIG_INVALID", "line %d: Address holds an invalid entry" % number) from None
        if interface.version == 6:
            warnings.append("line %d: an IPv6 Address entry was dropped (the server tunnels IPv4 only)" % number)
            continue
        if interface.ip not in ipaddress.ip_network("10.0.0.0/8"):
            raise _invalid("E_CONFIG_INVALID", "line %d: Address must be inside 10.0.0.0/8" % number)
        if interface.network.prefixlen != 32:
            # TunnelSats issues one /32; a wider prefix would add an on-link route on the tunnel
            raise _invalid("E_CONFIG_INVALID", "line %d: Address must be a single /32 address" % number)
        addresses.append(str(interface))
    if not addresses:
        raise _invalid("E_CONFIG_INVALID", "line %d: Address has no IPv4 entry" % number)
    mtu = None
    if "mtu" in iface:
        number, value, _ = iface["mtu"]
        if not re.fullmatch(r"[0-9]{4}", value) or not 1280 <= int(value) <= 1500:
            raise _invalid("E_CONFIG_INVALID", "line %d: MTU must be 1280-1500" % number)
        mtu = int(value)
    number, peer_key, _ = required(peer, "publickey", "PublicKey")
    if not KEY_RE.fullmatch(peer_key):
        raise _invalid("E_CONFIG_INVALID", "line %d: PublicKey is not a WireGuard key" % number)
    psk = None
    if "presharedkey" in peer:
        number, psk, _ = peer["presharedkey"]
        if not KEY_RE.fullmatch(psk):
            raise _invalid("E_CONFIG_INVALID", "line %d: PresharedKey is not a WireGuard key" % number)
    number, endpoint, _ = required(peer, "endpoint", "Endpoint")
    match = re.fullmatch(r"(.+):([0-9]{1,5})", endpoint)
    if not match:
        raise _invalid("E_CONFIG_INVALID", "line %d: Endpoint is not host:port" % number)
    host = match.group(1).lower()
    endpoint_port = int(match.group(2))
    if host.startswith("[") or re.fullmatch(r"[0-9.]+", host):
        raise ModuleError("E_ENDPOINT_NOT_ALLOWED", "refused",
                          "line %d: Endpoint must be a *.tunnelsats.com host name, not an IP address" % number,
                          EXIT_USAGE)
    if not valid_host(host):
        raise ModuleError("E_ENDPOINT_NOT_ALLOWED", "refused",
                          "line %d: Endpoint host is not a *.tunnelsats.com name" % number, EXIT_USAGE)
    if not 1 <= endpoint_port <= 65535:
        raise _invalid("E_CONFIG_INVALID", "line %d: Endpoint port must be 1-65535" % number)
    number, allowed_text, _ = required(peer, "allowedips", "AllowedIPs")
    networks = []
    for part in [p.strip() for p in allowed_text.split(",") if p.strip()]:
        try:
            networks.append(str(ipaddress.ip_network(part, strict=False)))
        except ValueError:
            raise _invalid("E_CONFIG_INVALID", "line %d: AllowedIPs holds an invalid entry" % number) from None
    if "0.0.0.0/0" not in networks:
        raise _invalid("E_CONFIG_INVALID", "line %d: AllowedIPs must contain 0.0.0.0/0" % number)
    keepalive = None
    if "persistentkeepalive" in peer:
        number, value, _ = peer["persistentkeepalive"]
        if not re.fullmatch(r"[0-9]{1,5}", value) or int(value) > 65535:
            raise _invalid("E_CONFIG_INVALID", "line %d: PersistentKeepalive must be 0-65535" % number)
        keepalive = int(value)
    public_key = public_key_of(private_key)
    matches = None
    if mypubkey is not None:
        matches = mypubkey == public_key
        if not matches:
            warnings.append("the myPubKey comment differs from the key derived from PrivateKey (the derived one is used)")
    return {"private_key": private_key, "addresses": addresses, "mtu": mtu, "peer_public_key": peer_key,
            "preshared_key": psk, "endpoint_host": host, "endpoint_port": endpoint_port,
            "allowed_ips": networks, "keepalive": keepalive, "vpn_port": port, "valid_until": valid_until,
            "public_key": public_key, "public_key_matches": matches, "warnings": warnings}


def render_wg_config(cfg):
    """The canonical config from validated fields only: fixed order, LF. The metadata comments stay
    before [Interface], where tunnelsats.sh reads '# Port Forwarding:'."""
    lines = ["# TunnelSats WireGuard config (rebuilt by RaspiBlitz from validated fields)",
             "# Port Forwarding: %d" % cfg["vpn_port"]]
    if cfg.get("valid_until"):
        lines.append("# Valid Until: %s" % cfg["valid_until"])
    lines += ["# myPubKey: %s" % cfg["public_key"], "[Interface]", "PrivateKey = %s" % cfg["private_key"],
              "Address = %s" % ", ".join(cfg["addresses"])]
    if cfg.get("mtu"):
        lines.append("MTU = %d" % cfg["mtu"])
    lines += ["[Peer]", "PublicKey = %s" % cfg["peer_public_key"]]
    if cfg.get("preshared_key"):
        lines.append("PresharedKey = %s" % cfg["preshared_key"])
    lines += ["Endpoint = %s:%d" % (cfg["endpoint_host"], cfg["endpoint_port"]),
              "AllowedIPs = %s" % ", ".join(cfg["allowed_ips"])]
    if cfg.get("keepalive") is not None:
        lines.append("PersistentKeepalive = %d" % cfg["keepalive"])
    return ("\n".join(lines) + "\n").encode()


# ------------------------------------------------------------------------------------------
# Public API: POST /subscription/status
# ------------------------------------------------------------------------------------------

def _api_error_code(raw):
    doc = parse_one_json(raw.decode("utf-8", "replace")) if raw else None
    code = doc.get("error") if doc else None
    return code if isinstance(code, str) and re.fullmatch(r"ERR_[A-Z0-9_]{1,40}", code) else None


def validate_status(doc):
    """The validated fields of a 200 response, renamed for the module, or None."""
    if not isinstance(doc, dict):
        return None
    expiry = doc.get("expiry")
    synced = doc.get("last_synced_at")
    vpn_port = doc.get("vpn_port")
    if parse_iso(expiry) is None or not (synced is None or parse_iso(synced) is not None):
        return None
    if not is_number(doc.get("bandwidth_used_gb")) or not is_number(doc.get("bandwidth_limit_gb")):
        return None
    if not is_count(doc.get("bandwidth_resets_this_month")) or not is_count(doc.get("max_resets_per_month")):
        return None
    if doc.get("status") not in ("enabled", "disabled") or not valid_host(doc.get("server_domain")):
        return None
    if not (vpn_port is None or valid_port(vpn_port)):
        return None
    return {"expiry": expiry, "bandwidth_used_gb": doc["bandwidth_used_gb"],
            "bandwidth_limit_gb": doc["bandwidth_limit_gb"], "resets_this_month": doc["bandwidth_resets_this_month"],
            "max_resets_per_month": doc["max_resets_per_month"], "peer_status": doc["status"],
            "server_domain": doc["server_domain"], "vpn_port": vpn_port, "last_synced_at": synced}


def api_status(deps, public_key):
    """Asks the API for the subscription of a public key. Returns (outcome, data, detail): outcome is
    confirmed, unknown_key (404, definitive), failed (network, timeout, 5xx, 429), invalid
    (validation failed) or migration (the key must be migrated on the website first). Response
    bodies are never logged."""
    for attempt in (1, 2):
        try:
            status, headers, raw = deps.http(API_STATUS_URL, {"wgPublicKey": public_key})
        except Exception:  # network, TLS, timeout: never the body
            return "failed", None, "the TunnelSats API could not be reached"
        if len(raw) > API_MAX_BYTES:
            return "invalid", None, "the response is larger than 64 KB"
        if status == 503 and attempt == 1:
            retry = headers.get("retry-after", "30")
            deps.sleep(min(int(retry), 60) if str(retry).isdigit() else 30)
            continue
        break
    code = _api_error_code(raw) if status != 200 else None
    if status == 200:
        data = validate_status(parse_one_json(raw.decode("utf-8", "replace")))
        if data is None:
            return "invalid", None, "the status response failed validation"
        return "confirmed", data, ""
    if status == 404 and code == "ERR_RESOURCE_NOT_FOUND":
        return "unknown_key", None, "TunnelSats knows no subscription for this key"
    if status == 403 and code == "ERR_MIGRATION_REQUIRED":
        return "migration", None, "this subscription has to be migrated on tunnelsats.com first"
    if status == 429:
        retry = headers.get("retry-after", "60")
        return "failed", None, "rate limited, retry in %s s" % (retry if str(retry).isdigit() else "60")
    if status >= 500 or status == 404:
        return "failed", None, "the TunnelSats API is unavailable (HTTP %d)" % status
    return "invalid", None, "unexpected API answer (HTTP %d)" % status


# ------------------------------------------------------------------------------------------
# Local state
# ------------------------------------------------------------------------------------------

def load_state(deps):
    try:
        with open(deps.path(STATE_FILE), encoding="utf-8") as handle:
            doc = json.load(handle)
        return doc if isinstance(doc, dict) and doc.get("schema") == "raspiblitz.tunnelsats.state/1" else None
    except (OSError, ValueError):
        return None


def save_state(deps, state):
    ensure_dir(deps.path(STATE_DIR), 0o700)
    write_private(deps.path(STATE_FILE), (json.dumps(state, indent=1, sort_keys=True) + "\n").encode())


def load_stored_config(deps):
    try:
        with open(deps.path(CONF_FILE), "rb") as handle:
            return parse_wg_config(handle.read())
    except OSError:
        return None


class Lock:
    """flock on /run/tunnelsats-rb/module.lock: state-changing verbs run one at a time. Not below
    /run/tunnelsats: uninstall --managed removes that directory while REMOVE or REPAIR holds the lock,
    and a lock file created again there would let a second verb in."""

    def __init__(self, deps, wait):
        self.deps = deps
        self.wait = wait
        self.fd = None

    def __enter__(self):
        lock_dir = self.deps.path(LOCK_DIR)
        os.makedirs(lock_dir, mode=0o700, exist_ok=True)
        os.chmod(lock_dir, 0o700)
        self.fd = os.open(self.deps.path(LOCK_FILE), os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        deadline = time.monotonic() + self.wait
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.monotonic() >= deadline:
                    os.close(self.fd)
                    raise ModuleError("E_BUSY", "operational", "another TunnelSats action is running",
                                      EXIT_OPERATIONAL) from None
                time.sleep(0.5)

    def __exit__(self, *exc):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


# ------------------------------------------------------------------------------------------
# System calls (all as argument lists)
# ------------------------------------------------------------------------------------------

def its(deps, args, timeout=120):
    """internet.tunnelsats.sh <args...>; returns (rc, document or None)."""
    rc, out, _err = deps.run([ITS] + list(args), timeout=timeout)
    return rc, parse_one_json(out)


def blitz_conf_set(deps, key, value):
    rc, _out, _err = deps.run([BLITZ_CONF, "set", key, value], timeout=30)
    if rc != 0:
        raise ModuleError("E_CONF_WRITE", "operational", "raspiblitz.conf: %s could not be set" % key, EXIT_OPERATIONAL)


def unit_props(deps, unit, *props):
    argv = ["systemctl", "show"]
    for prop in props:
        argv += ["-p", prop]
    rc, out, _err = deps.run(argv + [unit], timeout=30)
    values = {prop: "" for prop in props}
    if rc == 0:
        for line in out.splitlines():
            key, _sep, value = line.partition("=")
            if key in values:
                values[key] = value
    return values


def systemctl(deps, *args):
    rc, _out, _err = deps.run(["systemctl"] + list(args), timeout=120)
    return rc == 0


def select_impl(conf, requested=None):
    """The implementation TunnelSats tunnels: LND when it runs (also next to CLN), else CLN.
    Returns (impl or None, reason or None); --impl cl next to LND is refused."""
    lnd_on = conf.get("lightning") == "lnd" or conf.get("lnd") in ("on", "1")
    cl_on = conf.get("lightning") == "cl" or conf.get("cl") in ("on", "1")
    if requested == "cl" and lnd_on:
        raise ModuleError("E_PORT_CONFLICT", "refused",
                          "LND is on and owns port 9735: TunnelSats tunnels LND on this node", EXIT_REFUSED)
    if requested == "lnd":
        return ("lnd", None) if lnd_on else (None, "lnd_not_active")
    if requested == "cl":
        return ("cl", None) if cl_on else (None, "cl_not_active")
    if lnd_on:
        return "lnd", None
    if cl_on:
        return "cl", None
    return None, "no_lightning"


# ------------------------------------------------------------------------------------------
# Output
# ------------------------------------------------------------------------------------------

class Result:
    def __init__(self, command):
        self.command = command
        self.fields = {}
        self.errors = []
        self.exit_code = EXIT_OK

    def error(self, code, cls, message, exit_code=None):
        self.errors.append({"code": code, "class": cls, "message": message})
        if exit_code is not None:
            self.exit_code = exit_code

    def document(self):
        doc = {"contract": CONTRACT, "command": self.command, "module_version": MODULE_VERSION,
               "ok": self.exit_code == EXIT_OK, "exit_code": self.exit_code, "errors": self.errors}
        doc.update(self.fields)
        return doc


def emit(result, as_json, out=None):
    out = out or sys.stdout
    doc = result.document()
    if as_json:
        out.write(json.dumps(doc, sort_keys=True) + "\n")
        return
    for key in sorted(doc):
        if key in ("contract", "module_version"):
            continue
        out.write("%s: %s\n" % (key, json.dumps(doc[key], sort_keys=True)))


# ------------------------------------------------------------------------------------------
# detect
# ------------------------------------------------------------------------------------------

def detect(deps, requested=None):
    """Eligibility (design 6.4). Returns the detect fields; read-only."""
    conf = read_rb_conf(deps)
    reasons = []
    impl, why = select_impl(conf, requested)
    if why:
        reasons.append(why)
    if conf.get("chain", "main") != "main":
        reasons.append("chain_not_main")
    if conf.get("runBehindTor") != "on":
        reasons.append("tor_required")
    if conf.get("lndPort") not in (None, "", "9735"):
        reasons.append("lnd_port")
    if impl:
        rc, audit = its(deps, ["audit", impl, "--json"], timeout=30)
        if audit is None:
            reasons.append("config_check_failed")
        elif audit.get("status") == "unrepairable":
            reasons.append("config_unrepairable:%s" % audit.get("reason"))
        elif audit.get("eligible") is False:
            reasons.append("not_eligible:%s" % audit.get("not_eligible_reason"))
    rc, tool = its(deps, ["detect", "--json"], timeout=ITS_TIMEOUT["detect"])
    kind = None
    artifacts = []
    capabilities = {}
    if tool is None or rc != 0:
        reasons.append("tool_detect_failed")
    else:
        install = tool.get("install") if isinstance(tool.get("install"), dict) else {}
        kind = install.get("kind")
        artifacts = [{"id": a.get("id"), "location": a.get("location")} for a in install.get("artifacts") or []
                     if isinstance(a, dict) and a.get("status") == "present"]
        caps = tool.get("capabilities") if isinstance(tool.get("capabilities"), dict) else {}
        capabilities = {
            "wireguard_tools": (caps.get("wireguard_tools") or {}).get("status"),
            "nft": (caps.get("nft") or {}).get("status"),
            "systemd": (caps.get("systemd") or {}).get("status"),
            "cgroup_v2": (caps.get("cgroup_v2") or {}).get("status"),
        }
        if capabilities["systemd"] != "present":
            reasons.append("systemd_missing")
        if capabilities["cgroup_v2"] != "mounted":
            reasons.append("cgroup_v2_missing")
        if kind in ("legacy_v2", "legacy_v3_pre_204", "legacy_v3_post_204"):
            reasons.append("legacy_install")
        elif kind not in ("none", "managed"):
            reasons.append("unknown_install")
    configured = load_state(deps) is not None
    return {"eligible": not reasons, "impl": impl, "reasons": reasons, "capabilities": capabilities,
            "existing_install": {"kind": kind, "artifacts": artifacts}, "installed": kind == "managed",
            "artifacts": [a["id"] for a in artifacts], "configured": configured,
            "adopt_available": kind in ("legacy_v2", "legacy_v3_pre_204", "legacy_v3_post_204", "unknown")}


def cmd_detect(deps, args, result):
    result.fields.update(detect(deps))
    if not result.fields["eligible"] and not result.fields["configured"]:
        result.exit_code = EXIT_NOT_CONFIGURED


# ------------------------------------------------------------------------------------------
# Activation (shared by IMPORT and REPAIR)
# ------------------------------------------------------------------------------------------

def guard_line(impl):
    """The start guard line of a mainnet Lightning unit (the templates write the same text): it runs
    the guard, or, without an executable internet.tunnelsats.sh, writes the empty value (never a
    deleted file, so a stray raspiblitz.conf value cannot pass) and lets Lightning start Tor-only."""
    return ("ExecStartPre=+/bin/sh -c 'if [ -x {its} ]; then exec {its} guard {impl} mainnet; fi; "
            "echo tunnelsats-guard: internet.tunnelsats.sh is missing, Lightning starts Tor-only >&2; "
            "mkdir -p /run/tunnelsats && echo {var}= > /run/tunnelsats/hybrid-{base}.env'").format(
                its=ITS, impl=impl, var=VARS[impl], base=BASES[impl])


def unit_template_ok(deps, impl):
    """The Lightning unit file carries the guard template lines and needs no daemon-reload."""
    unit = UNITS[impl]
    props = unit_props(deps, unit, "FragmentPath", "NeedDaemonReload")
    path = props["FragmentPath"]
    if not path or props["NeedDaemonReload"] != "no":
        return False
    try:
        with open(deps.path(path), encoding="utf-8", errors="replace") as handle:
            lines = [line.rstrip("\r") for line in handle.read().split("\n")]
    except OSError:
        return False
    var = VARS[impl]
    if "Environment=%s=" % var not in lines:
        return False
    if "EnvironmentFile=-/run/tunnelsats/hybrid-%s.env" % BASES[impl] not in lines:
        return False
    if guard_line(impl) not in lines:
        return False
    starts = [line for line in lines if line.startswith("ExecStart=")]
    if impl == "lnd":
        return bool(starts) and starts[0].endswith(" $" + var)
    return bool(starts) and starts[0].endswith(" $$%s'" % var)


def regenerate_unit(deps, impl):
    """Rewrites a guard-less unit with RaspiBlitz's own writers (no restart for LND)."""
    if impl == "lnd":
        rc, _o, _e = deps.run(["install", "-m", "0644", LND_ASSET, UNIT_DIR + "/lnd.service"], timeout=30)
        ok = rc == 0 and systemctl(deps, "daemon-reload")
    else:
        rc, _o, _e = deps.run([CL_INSTALL_SERVICE, "mainnet"], timeout=300)
        ok = rc == 0
    if not ok or not unit_template_ok(deps, impl):
        raise ModuleError("E_UNIT_TEMPLATE", "operational",
                          "the Lightning unit could not be rewritten with the start guard lines", EXIT_OPERATIONAL)


def map_tool_exit(rc):
    if rc == 6:
        return EXIT_NOT_CONFIGURED
    if rc == 7:
        return EXIT_REFUSED
    return EXIT_OPERATIONAL


def tool_error(doc, fallback):
    errors = (doc or {}).get("errors") or []
    code = errors[0].get("code") if errors and isinstance(errors[0], dict) else None
    return code if isinstance(code, str) and re.fullmatch(r"E_[A-Z0-9_]{1,40}", code) else fallback


def activate(deps, impl, result, stored_writer=None):
    """Design 6.3: preflight without changes, store, unit, flags, install, block, timer, check."""
    activation = {"fetch": None, "unit_regenerated": False, "install": None, "ln_restarted": None,
                  "restore_block": None, "tick_timer": None}
    result.fields["activation"] = activation
    rc, doc = its(deps, ["fetch", "--json"], timeout=ITS_TIMEOUT["fetch"])
    activation["fetch"] = "ok" if rc == 0 else tool_error(doc, "E_DOWNLOAD_FAILED")
    if rc != 0:
        raise ModuleError(activation["fetch"], "operational",
                          "the pinned tunnelsats.sh could not be fetched and verified", EXIT_OPERATIONAL)
    rc, doc = its(deps, ["block-insert", "--check", "--json"], timeout=30)
    if rc != 0:
        raise ModuleError(tool_error(doc, "E_BLOCK_CHECK"), "operational",
                          "custom-installs.sh cannot take the restore block (fix it first)", EXIT_OPERATIONAL)
    template_ok = unit_template_ok(deps, impl)
    if stored_writer:
        stored_writer()
    if not template_ok:
        regenerate_unit(deps, impl)
        activation["unit_regenerated"] = True
    blitz_conf_set(deps, "tunnelsatsImpl", impl)
    blitz_conf_set(deps, "tunnelsats", "on")
    rc, doc = its(deps, ["install", "--impl", impl, "--json"], timeout=ITS_TIMEOUT["install"])
    if rc != 0:
        blitz_conf_set(deps, "tunnelsats", "off")
        activation["install"] = tool_error(doc, "E_INSTALL_FAILED")
        raise ModuleError(activation["install"], "operational",
                          "the managed dataplane could not be installed; Lightning stays Tor-only "
                          "(the stored config stays for REPAIR)", map_tool_exit(rc))
    activation["install"] = "ok"
    activation["ln_restarted"] = bool(doc.get("ln_restarted")) if doc else None
    rc, doc = its(deps, ["block-insert", "--json"], timeout=30)
    activation["restore_block"] = "present" if rc == 0 else "failed"
    rc, out, _err = deps.run([ITS, "tick-timer", "on"], timeout=60)
    activation["tick_timer"] = "active" if rc == 0 else "failed"
    wait_for_handshake(deps)


def wait_for_handshake(deps, seconds=60, step=5):
    """Waits up to 60 s for the first handshake of the tunnel (verify --no-probe)."""
    waited = 0
    while True:
        rc, doc = its(deps, ["verify", "--no-probe", "--json"], timeout=ITS_TIMEOUT["verify_no_probe"])
        checks = (doc or {}).get("checks") or []
        if any(isinstance(c, dict) and c.get("id") == "wg_handshake" and c.get("result") == "pass" for c in checks):
            return True
        if waited >= seconds:
            return False
        deps.sleep(step)
        waited += step


def wait_until_started(deps, unit, limit=LN_START_WAIT, step=LN_START_STEP):
    """REPAIR and IMPORT, before their final check, after the tool or the module (re)started unit:
    waits while it is "activating" (LND until it is ready, Type=notify), at most limit seconds,
    because verify reports a start in progress as degraded. Returns the record for the result:
    unit, state (read last), waited_s and outcome: "active", "not_running" (it was not starting),
    "failed" (it stopped while starting) or "timeout" (still starting at the limit)."""
    started, waited = deps.clock(), 0
    state = unit_props(deps, unit, "ActiveState")["ActiveState"]
    starting = state == "activating"
    while state == "activating" and waited < limit and (deps.clock() - started).total_seconds() < limit:
        deps.sleep(step)
        waited += step
        state = unit_props(deps, unit, "ActiveState")["ActiveState"]
    if state == "active":
        outcome = "active"
    elif state == "activating":
        outcome = "timeout"
    else:
        outcome = "failed" if starting else "not_running"
    return {"unit": unit, "state": state or "unknown", "waited_s": waited, "outcome": outcome}


def start_wait_detail(wait):
    """Why the final check saw a start that did not finish, or None."""
    if not wait:
        return None
    if wait["outcome"] == "timeout":
        hint = " (LND stays starting until its wallet is unlocked)" if wait["unit"] == UNITS["lnd"] else ""
        return ("%s was still starting after %d s, so this check ran while it starts%s: run CHECK again once it "
                "runs" % (wait["unit"], wait["waited_s"], hint))
    if wait["outcome"] == "failed":
        return ("%s stopped while starting (%s): see journalctl -u %s, then REPAIR"
                % (wait["unit"], wait["state"], wait["unit"]))
    return None


def with_start_wait(checked, wait):
    """The check result with a start that did not finish as a failed degraded check (ln_start), so
    the verdict is never protected for it."""
    detail = start_wait_detail(wait)
    if detail:
        checked["checks"].append({"id": "ln_start", "class": "degraded", "result": "fail", "detail": detail})
        checked["reasons"].append("ln_start")
        if checked["verdict"] == "protected":
            checked["verdict"] = "degraded"
    return checked


# ------------------------------------------------------------------------------------------
# import
# ------------------------------------------------------------------------------------------

def sync_fields(outcome, data, cfg):
    return {"sync": {"outcome": outcome}, "server_domain": (data or {}).get("server_domain") or cfg["endpoint_host"],
            "expiry": (data or {}).get("expiry") or cfg.get("valid_until")}


def store_subscription(deps, cfg, mode, impl, outcome, data, extra=None):
    """Writes tunnelsats.conf (0600) and state.json (0600)."""
    ensure_dir(deps.path(STATE_DIR), 0o700)
    write_private(deps.path(CONF_FILE), render_wg_config(cfg))
    state = load_state(deps) or {}
    state.update({
        "schema": "raspiblitz.tunnelsats.state/1", "mode": mode, "impl": impl, "public_key": cfg["public_key"],
        "endpoint_host": cfg["endpoint_host"], "vpn_port": cfg["vpn_port"],
        "server_domain": (data or {}).get("server_domain") or cfg["endpoint_host"],
        "valid_until": cfg.get("valid_until"), "imported_at": state.get("imported_at") or now_iso(deps),
        "api": {"outcome": outcome, "checked_at": now_iso(deps), "data": data,
                "confirmed_at": now_iso(deps) if outcome == "confirmed" else None},
        "notified_invocation_id": state.get("notified_invocation_id"), "notify": state.get("notify") or {},
    })
    if extra:
        state.update(extra)
    save_state(deps, state)
    return state


def confirm_with_api(deps, cfg, yes, result):
    outcome, data, detail = api_status(deps, cfg["public_key"])
    result.fields.update(sync_fields(outcome, data, cfg))
    if outcome == "unknown_key":
        raise ModuleError("E_UNKNOWN_KEY", "refused", detail + "; nothing was stored", EXIT_REFUSED)
    if outcome == "migration":
        raise ModuleError("E_MIGRATION_REQUIRED", "refused", detail, EXIT_REFUSED)
    if outcome == "invalid":
        raise ModuleError("E_API_INVALID", "invalid_response", detail, EXIT_INVALID_API)
    if outcome == "failed" and not yes:
        raise ModuleError("E_API_UNAVAILABLE", "retryable",
                          detail + "; confirm to continue without the API (--yes)", EXIT_API_UNAVAILABLE)
    return outcome, data


def read_import_file(path):
    real = path
    try:
        if not os.path.isfile(real) or os.path.islink(real):
            raise OSError
        if os.path.getsize(real) > MAX_CONFIG_BYTES:
            raise _invalid("E_CONFIG_INVALID", "the config is larger than 16 KiB")
        with open(real, "rb") as handle:
            return handle.read(MAX_CONFIG_BYTES + 1)
    except OSError:
        raise _invalid("E_FILE", "the config file cannot be read (a regular file is needed)") from None


def cmd_import(deps, args, result):
    data = read_import_file(args.file)
    cfg = parse_wg_config(data)
    result.fields.update({"valid": True, "warnings": cfg["warnings"], "public_key": cfg["public_key"],
                          "public_key_matches": cfg["public_key_matches"],
                          "endpoint": {"host": cfg["endpoint_host"]}, "vpn_port": cfg["vpn_port"],
                          "ln_start_wait": None})
    state = load_state(deps)
    if state and state.get("public_key") != cfg["public_key"]:
        raise ModuleError("E_ALREADY_CONFIGURED", "refused",
                          "another subscription is stored on this node: REMOVE it first", EXIT_REFUSED)
    if state and state.get("mode") == "adopted_legacy":
        raise ModuleError("E_UPGRADE_UNAVAILABLE", "refused",
                          "this subscription runs on the adopted standard install; UPGRADE comes with a later "
                          "TunnelSats release", EXIT_REFUSED)
    found = detect(deps, args.impl)
    result.fields["detect"] = {"eligible": found["eligible"], "reasons": found["reasons"]}
    if found["reasons"]:
        raise ModuleError("E_NOT_ELIGIBLE", "not_eligible", "not eligible: %s" % ", ".join(found["reasons"]),
                          EXIT_NOT_CONFIGURED)
    impl = found["impl"]
    outcome, api_data = confirm_with_api(deps, cfg, args.yes, result)
    if args.dry_run:
        result.fields["dry_run"] = True
        return
    if state:
        # The same key again (for example a re-downloaded config): store it and repair
        with Lock(deps, wait=30):
            store_subscription(deps, cfg, "managed", impl, outcome, api_data)
        cmd_repair(deps, argparse.Namespace(yes=True, impl=impl, json=args.json), result)
        return
    with Lock(deps, wait=30):
        activate(deps, impl, result,
                 stored_writer=lambda: store_subscription(deps, cfg, "managed", impl, outcome, api_data))
    # the tool's install restarted a running unit: the check waits until that start is done
    finish_with_check(deps, result, wait_until_started(deps, UNITS[impl]))


def finish_with_check(deps, result, wait=None):
    result.fields["ln_start_wait"] = wait
    checked = with_start_wait(run_check(deps), wait)
    result.fields["verdict"] = checked["verdict"]
    result.fields["guard"] = checked["guard"]
    result.fields["check"] = {"reasons": checked["reasons"], "restart_needed": checked["restart_needed"]}
    if start_wait_detail(wait):
        result.fields["warnings"] = list(result.fields.get("warnings") or []) + [start_wait_detail(wait)]
    result.exit_code = verdict_exit(checked["verdict"])


def verdict_exit(verdict):
    return {"protected": EXIT_OK, "degraded": EXIT_DEGRADED, "unsafe": EXIT_UNSAFE}.get(verdict, EXIT_NOT_CONFIGURED)


# ------------------------------------------------------------------------------------------
# adopt (step 1: take over the subscription of a standard install, no system change)
# ------------------------------------------------------------------------------------------

def custom_installs_lines(deps):
    """Lines outside the TunnelSats block that mention tunnelsats, wireguard or wg-quick (shown,
    never edited)."""
    try:
        with open(deps.path(CUSTOM_INSTALLS), encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return []
    found = []
    inside = False
    for number, line in enumerate(lines, start=1):
        bare = line.rstrip("\r")
        if bare.startswith("# >>> TunnelSats block"):
            inside = True
            continue
        if bare == "# <<< TunnelSats block <<<":
            inside = False
            continue
        if not inside and re.search(r"tunnelsats|wireguard|wg-quick", bare, re.IGNORECASE):
            found.append({"line": number, "text": bare[:200]})
    return found


def cmd_adopt(deps, args, result):
    result.fields.update({"adopted": False, "upgrade_available": False,
                          "upgrade_requires": "tunnelsats.sh adopt --managed (PR-T2)"})
    if args.upgrade:
        raise ModuleError("E_UPGRADE_UNAVAILABLE", "refused",
                          "UPGRADE to managed mode comes with a later TunnelSats release", EXIT_REFUSED)
    rc, tool = its(deps, ["detect", "--json"], timeout=ITS_TIMEOUT["detect"])
    if tool is None or rc != 0:
        raise ModuleError("E_DETECT_FAILED", "operational", "the TunnelSats install could not be detected",
                          EXIT_OPERATIONAL)
    kind = (tool.get("install") or {}).get("kind")
    if kind == "none":
        raise ModuleError("E_NOTHING_TO_ADOPT", "not_configured", "no TunnelSats install found", EXIT_NOT_CONFIGURED)
    if kind == "managed":
        raise ModuleError("E_ALREADY_MANAGED", "refused", "TunnelSats already runs in managed mode", EXIT_REFUSED)
    path = (tool.get("config") or {}).get("path")
    if not isinstance(path, str) or not LEGACY_CONF_RE.fullmatch(path):
        raise ModuleError("E_CONFIG_NOT_FOUND", "operational", "the legacy WireGuard config was not found",
                          EXIT_OPERATIONAL)
    try:
        with open(deps.path(path), "rb") as handle:
            data = handle.read(MAX_CONFIG_BYTES + 1)
    except OSError:
        raise ModuleError("E_CONFIG_NOT_FOUND", "operational", "the legacy WireGuard config cannot be read",
                          EXIT_OPERATIONAL) from None
    cfg = parse_wg_config(data)
    state = load_state(deps)
    if state and state.get("public_key") != cfg["public_key"]:
        raise ModuleError("E_ALREADY_CONFIGURED", "refused",
                          "another subscription is stored on this node: REMOVE it first", EXIT_REFUSED)
    result.fields.update({"public_key": cfg["public_key"], "legacy_kind": kind, "warnings": cfg["warnings"]})
    outcome, data_api = confirm_with_api(deps, cfg, args.yes, result)
    conf = read_rb_conf(deps)
    impl, _why = select_impl(conf)
    with Lock(deps, wait=30):
        store_subscription(deps, cfg, "adopted_legacy", impl, outcome, data_api, {"legacy_kind": kind})
    result.fields["adopted"] = True
    result.fields["custom_installs_lines"] = custom_installs_lines(deps)


# ------------------------------------------------------------------------------------------
# status
# ------------------------------------------------------------------------------------------

def wg_local(deps):
    """Handshake age and transfer of the tunnel (no key material)."""
    info = {"handshake_age_s": None, "rx_bytes": None, "tx_bytes": None}
    rc, out, _err = deps.run(["wg", "show", "tunnelsatsv2", "latest-handshakes"], timeout=10)
    if rc == 0 and out.split():
        fields = out.split()
        if len(fields) >= 2 and fields[1].isdigit() and int(fields[1]) > 0:
            info["handshake_age_s"] = max(0, int(deps.clock().timestamp()) - int(fields[1]))
    rc, out, _err = deps.run(["wg", "show", "tunnelsatsv2", "transfer"], timeout=10)
    if rc == 0 and len(out.split()) >= 3:
        fields = out.split()
        if fields[1].isdigit() and fields[2].isdigit():
            info["rx_bytes"], info["tx_bytes"] = int(fields[1]), int(fields[2])
    return info


def read_guard_record(deps, base):
    try:
        with open(deps.path("%s/guard-%s.json" % (RUN_DIR, base)), encoding="utf-8") as handle:
            doc = json.load(handle)
        return doc if isinstance(doc, dict) and doc.get("schema") == "raspiblitz.tunnelsats.guard/1" else None
    except (OSError, ValueError):
        return None


def cmd_status(deps, args, result):
    state = load_state(deps)
    conf = read_rb_conf(deps)
    if state is None:
        result.fields.update({"configured": False, "tunnelsats": conf.get("tunnelsats", "off")})
        result.exit_code = EXIT_NOT_CONFIGURED
        return
    api = state.get("api") or {}
    outcome = "skipped"
    checked = parse_iso(api.get("checked_at"))
    stale = checked is None or (deps.clock() - checked).total_seconds() > API_CACHE_SECONDS
    if args.refresh or (stale and not args.cached):
        outcome, data, detail = api_status(deps, state["public_key"])
        api["outcome"] = outcome
        api["checked_at"] = now_iso(deps)
        if outcome == "confirmed":
            api["data"] = data
            api["confirmed_at"] = now_iso(deps)
        elif detail:
            result.fields["sync_detail"] = detail
        state["api"] = api
        try:
            with Lock(deps, wait=0):
                save_state(deps, state)
        except ModuleError:
            pass
        if outcome == "invalid":
            result.error("E_API_INVALID", "invalid_response", "the status response failed validation", EXIT_INVALID_API)
    data = api.get("data") or {}
    impl = state.get("impl") or conf.get("tunnelsatsImpl")
    record = read_guard_record(deps, BASES.get(impl, "lnd")) if impl in BASES else None
    live_port = data.get("vpn_port")
    fields = {
        "configured": True, "mode": state.get("mode"), "tunnelsats": conf.get("tunnelsats", "off"), "impl": impl,
        "public_key": state.get("public_key"), "endpoint": {"host": state.get("endpoint_host")},
        "vpn_port": state.get("vpn_port"), "server_domain": data.get("server_domain") or state.get("server_domain"),
        "expiry": data.get("expiry") or state.get("valid_until"), "bandwidth_used_gb": data.get("bandwidth_used_gb"),
        "bandwidth_limit_gb": data.get("bandwidth_limit_gb"), "resets_this_month": data.get("resets_this_month"),
        "max_resets_per_month": data.get("max_resets_per_month"), "peer_status": data.get("peer_status"),
        "sync": {"outcome": outcome, "last_outcome": api.get("outcome"), "confirmed_at": api.get("confirmed_at")},
        "tunnel": wg_local(deps), "last_check": state.get("last_check"),
        "guard": {k: (record or {}).get(k) for k in ("decision", "reason", "decided_at")},
        "notify_state": None,
    }
    if live_port is not None and live_port != state.get("vpn_port"):
        fields["port_changed"] = True
        fields["action"] = "server port changed: REPAIR (restarts Lightning)"
    result.fields.update(fields)


# ------------------------------------------------------------------------------------------
# check
# ------------------------------------------------------------------------------------------

def daemon_cmdline(deps, unit):
    """The command line of the Lightning daemon of unit (lnd, or lightningd below CLN's sh)."""
    props = unit_props(deps, unit, "MainPID", "ActiveState", "InvocationID", "ControlGroup")
    pid = props["MainPID"]
    if not pid.isdigit() or pid == "0":
        return None, props

    def cmdline(p):
        try:
            with open(deps.path("/proc/%s/cmdline" % p), "rb") as handle:
                return [a.decode("utf-8", "replace") for a in handle.read().split(b"\0") if a]
        except OSError:
            return None

    args = cmdline(pid)
    if args and os.path.basename(args[0]) in ("sh", "bash", "dash"):
        try:
            entries = os.listdir(deps.path("/proc"))
        except OSError:
            entries = []
        for entry in entries:
            if not entry.isdigit():
                continue
            try:
                with open(deps.path("/proc/%s/stat" % entry), encoding="utf-8", errors="replace") as handle:
                    stat = handle.read()
            except OSError:
                continue
            fields = stat.rsplit(")", 1)[-1].split()
            if len(fields) > 1 and fields[1] == pid:
                child = cmdline(entry)
                if child and os.path.basename(child[0]) == "lightningd":
                    return child, props
    return args, props


def has_flags(impl, args):
    regex = LND_FLAG_RE if impl == "lnd" else CLN_FLAG_RE
    return any(regex.fullmatch(a) for a in (args or []))


def lightning_info(deps, impl):
    if impl == "lnd":
        argv = LNCLI + ["getinfo"]
    else:
        argv = ["sudo", "-u", "bitcoin", "/usr/local/bin/lightning-cli", "--conf=/home/bitcoin/.lightning/config", "getinfo"]
    rc, out, _err = deps.run(argv, timeout=30)
    return parse_one_json(out) if rc == 0 else None


def public_ipv4(value):
    """value if it is a dotted public IPv4 address, else None."""
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){3}", value):
        return None
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        return None
    return value if address.is_global and not address.is_multicast else None


def announce_check(impl, info, record, state, live_ipv4=None):
    """VPN address announced, onion present, no other clearnet address. LND resolves externalhosts
    itself and announces the resolved IPv4, so its uris carry <ipv4>:<vpn_port>: the endpoint's
    address at the start (guard record) and now (live_ipv4, endpoint.ipv4 of this CHECK's verify)
    both count as the VPN address. CLN announces the address of the guard record."""
    if info is None:
        return "degraded", "fail", "Lightning did not answer getinfo (locked or not running)", None
    if impl == "lnd":
        addrs = [u.split("@", 1)[1] for u in info.get("uris") or [] if isinstance(u, str) and "@" in u]
    else:
        addrs = ["%s:%s" % (a.get("address"), a.get("port")) for a in info.get("address") or [] if isinstance(a, dict)]
    onion = any(".onion" in a for a in addrs)
    clear = [a for a in addrs if ".onion" not in a]
    host, port = state.get("endpoint_host"), state.get("vpn_port")
    announce = (record or {}).get("announce") or {}
    expected = {"%s:%s" % (host, port)}
    for ipv4 in (public_ipv4(announce.get("ipv4")), public_ipv4(live_ipv4) if impl == "lnd" else None):
        if ipv4:
            expected.add("%s:%s" % (ipv4, port))
    foreign = [a for a in clear if a not in expected]
    if foreign:
        return "unsafe", "fail", "another clearnet address is announced", onion
    if not onion:
        return "degraded", "fail", "no onion address announced", onion
    unconfirmed = (record or {}).get("reason") == "announce_unconfirmed"
    if (record or {}).get("decision") == "hybrid" and not clear and not unconfirmed:
        return "degraded", "fail", "the VPN address is not announced yet", onion
    return "degraded", "pass", "onion%s announced" % (" and VPN address" if clear else ""), onion


def run_check(deps):
    """CHECK (design 6.5): the tool's verify with probes plus the RaspiBlitz checks."""
    state = load_state(deps) or {}
    conf = read_rb_conf(deps)
    checks = []

    def add(cid, cls, res, detail):
        checks.append({"id": cid, "class": cls, "result": res, "detail": detail})

    if not state:
        rc, verify = its(deps, ["verify", "--no-probe", "--json"], timeout=ITS_TIMEOUT["verify_no_probe"])
        if rc == 9:
            add("legacy_lifecycle", "unsafe", "fail", "legacy setup: the kill switch depends on the tunnel being up "
                "(ADOPT takes over the subscription)")
            return {"verdict": "unsafe", "reasons": ["legacy_lifecycle"], "checks": checks, "clearnet_blocked": None,
                    "guard": {}, "restart_needed": False}
        return {"verdict": "not_configured", "reasons": ["not_configured"], "checks": [], "clearnet_blocked": None,
                "guard": {}, "restart_needed": False}
    if state.get("mode") != "adopted_legacy" and conf.get("tunnelsats") != "on":
        add("tunnelsats_flag", "degraded", "fail", "TunnelSats is not active on this node: REPAIR activates it again")
        return {"verdict": "not_configured", "reasons": ["tunnelsats_flag"], "checks": checks,
                "clearnet_blocked": None, "guard": {}, "restart_needed": False}
    if state.get("mode") == "adopted_legacy":
        add("legacy_lifecycle", "unsafe", "fail", "legacy setup: the kill switch depends on the tunnel being up "
            "(UPGRADE to managed mode comes with a later TunnelSats release)")
        return {"verdict": "unsafe", "reasons": ["legacy_lifecycle"], "checks": checks, "clearnet_blocked": None,
                "guard": {}, "restart_needed": False}
    impl = state.get("impl") or conf.get("tunnelsatsImpl")
    unit, base = UNITS.get(impl, "lnd.service"), BASES.get(impl, "lnd")
    rc, verify = its(deps, ["verify", "--json"], timeout=ITS_TIMEOUT["verify"])
    clearnet_blocked = None
    if verify is None:
        add("verify", "unsafe", "fail", "tunnelsats verify did not answer")
    else:
        clearnet_blocked = verify.get("clearnet_blocked")
        for c in verify.get("checks") or []:
            if isinstance(c, dict) and isinstance(c.get("id"), str):
                cls = c.get("class") if c.get("class") in ("unsafe", "degraded") else "unsafe"
                add(c["id"], cls, c.get("result") if c.get("result") in ("pass", "fail", "skip") else "fail",
                    str(c.get("detail", ""))[:300])
        if rc == 3:
            add("verify", "degraded", "fail", "the managed dataplane is not installed, Lightning runs Tor-only: REPAIR")
        elif rc not in (0, 4, 5):
            add("verify", "unsafe", "fail", "tunnelsats verify: %s (exit %s)" % (tool_error(verify, "E_VERIFY"), rc))
    rc, audit = its(deps, ["audit", impl, "--json"], timeout=30)
    if audit and audit.get("status") == "clean":
        add("ln_at_rest", "unsafe", "pass", "no clearnet setting at rest")
    else:
        add("ln_at_rest", "unsafe", "fail", "clearnet settings at rest: %s" % ",".join((audit or {}).get("keys") or ["?"]))
    record = read_guard_record(deps, base)
    args, props = daemon_cmdline(deps, unit)
    flags = has_flags(impl, args)
    decision = (record or {}).get("decision")
    if props["ActiveState"] != "active" or args is None:
        add("ln_runtime_flags", "degraded", "fail", "Lightning is not running")
    elif flags and (decision != "hybrid" or record.get("invocation_id") != props["InvocationID"]):
        add("ln_runtime_flags", "unsafe", "fail", "clearnet flags run without a hybrid decision of the start guard")
    elif record is None or record.get("invocation_id") != props["InvocationID"]:
        add("ln_runtime_flags", "degraded", "fail", "no start guard decision for this start (unit without the guard lines: REPAIR)")
    elif decision == "hybrid" and not flags:
        add("ln_runtime_flags", "degraded", "fail", "the start guard decided hybrid but the daemon runs without the flags")
    elif decision != "hybrid":
        add("ln_runtime_flags", "degraded", "fail", "Lightning started Tor-only (%s)" % record.get("reason"))
    else:
        add("ln_runtime_flags", "unsafe", "pass", "hybrid flags for this start, decided by the start guard")
    restart_needed = False
    if record and props["ActiveState"] == "active" and record.get("invocation_id") == props["InvocationID"] and \
            record.get("reason") in RESTARTABLE and decision in ("tor-only", "hybrid"):
        rc, dry = its(deps, ["guard", impl, "mainnet", "--dry-run", "--json"], timeout=ITS_TIMEOUT["guard_dry_run"])
        if dry and dry.get("decision") == "hybrid" and (impl == "lnd" or dry.get("reason") == "ok"):
            restart_needed = True
    if restart_needed:
        add("restart_needed", "degraded", "fail", "Restart Lightning to resume clearnet connections" if impl == "lnd"
            else "Restart Lightning to announce the clearnet address")
    else:
        add("restart_needed", "degraded", "pass", "no restart needed")
    info = lightning_info(deps, impl) if props["ActiveState"] == "active" else None
    endpoint = (verify or {}).get("endpoint")
    live_ipv4 = endpoint.get("ipv4") if isinstance(endpoint, dict) else None
    cls, res, detail, onion = announce_check(impl, info, record, state, live_ipv4)
    add("announce", cls, res, detail)
    if impl == "cl":
        bindings = ["%s:%s" % (b.get("address"), b.get("port")) for b in (info or {}).get("binding") or []
                    if isinstance(b, dict)]
        need = {"127.0.0.1:9736"} | ({"0.0.0.0:9735"} if decision == "hybrid" else set())
        add("cln_bindings", "degraded", "pass" if info and need <= set(bindings) else "fail",
            "bindings %s" % ",".join(bindings) if info else "Lightning did not answer getinfo")
    other = "cl" if impl == "lnd" else "lnd"
    rc, other_audit = its(deps, ["audit", other, "--json"], timeout=30)
    other_record = read_guard_record(deps, BASES[other])
    if other_audit and other_audit.get("reason") == "config_missing":
        add("other_impl", "unsafe", "pass", "%s is not installed" % other)
    elif other_audit and other_audit.get("status") == "clean" and (other_record or {}).get("decision") != "hybrid":
        add("other_impl", "unsafe", "pass", "%s Tor-only at rest and without flags" % other)
    else:
        add("other_impl", "unsafe", "fail", "%s has clearnet settings at rest or flags" % other)
    tor_ok = conf.get("runBehindTor") == "on" and onion is not False
    add("tor", "unsafe", "pass" if tor_ok else "fail", "Tor on" if tor_ok else "Tor is off or no onion address")
    rc, block = its(deps, ["block-status", "--json"], timeout=30)
    if block and block.get("state") == "present":
        add("restore_block", "degraded", "pass", "restore block present in custom-installs.sh")
    else:
        add("restore_block", "degraded", "fail", "TunnelSats is not restored automatically after an SD-card update")
    rc, its_state = its(deps, ["status", "--json"], timeout=ITS_TIMEOUT["status"])
    tool_hash = (its_state or {}).get("tool_hash")
    if tool_hash == "current":
        add("tool_pin", "degraded", "pass", "tunnelsats.sh is the pinned version")
    elif tool_hash == "accepted_older":
        add("tool_pin", "degraded", "fail", "update available: REPAIR")
    else:
        add("tool_pin", "degraded", "fail", "the installed tunnelsats tool is missing or not a pinned version: REPAIR")
    if (its_state or {}).get("dev_override") == "yes":
        add("dev_override", "degraded", "fail", "DEV OVERRIDE active for this boot")
    stopped = False
    try:
        with open(deps.path(STOPPED_UNITS), encoding="utf-8") as handle:
            stopped = any(line.split()[:1] == [unit] for line in handle if line.strip())
    except OSError:
        pass
    add("verifier_stopped", "degraded", "fail" if stopped else "pass",
        "the TunnelSats verifier stopped Lightning because no protection holds; REPAIR" if stopped
        else "Lightning not stopped by the verifier")
    last = None
    try:
        with open(deps.path(LAST_RESTORE_FILE), encoding="utf-8") as handle:
            last = json.load(handle)
    except (OSError, ValueError):
        pass
    if last and last.get("result") not in ("ok", None) and not (verify or {}).get("managed"):
        add("last_restore", "degraded", "fail", "the last restore after an SD-card update failed (%s): REPAIR"
            % last.get("error"))
    else:
        add("last_restore", "degraded", "pass", "last restore %s" % ((last or {}).get("result") or "none"))
    data = (state.get("api") or {}).get("data") or {}
    if data.get("vpn_port") is not None and data.get("vpn_port") != state.get("vpn_port"):
        add("vpn_port", "degraded", "fail", "server port changed: REPAIR (restarts Lightning)")
    failed = [c for c in checks if c["result"] == "fail"]
    if any(c["class"] == "unsafe" for c in failed):
        verdict = "unsafe"
    elif failed:
        verdict = "degraded"
    else:
        verdict = "protected"
    return {"verdict": verdict, "reasons": [c["id"] for c in failed], "checks": checks,
            "clearnet_blocked": clearnet_blocked,
            "guard": {k: (record or {}).get(k) for k in ("decision", "reason", "decided_at")},
            "restart_needed": restart_needed}


def cmd_check(deps, args, result):
    checked = run_check(deps)
    result.fields.update(checked)
    result.exit_code = verdict_exit(checked["verdict"])
    state = load_state(deps)
    if state:
        state["last_check"] = {"verdict": checked["verdict"], "at": now_iso(deps)}
        try:
            with Lock(deps, wait=0):
                save_state(deps, state)
        except ModuleError:
            pass


# ------------------------------------------------------------------------------------------
# uninstall (REMOVE)
# ------------------------------------------------------------------------------------------

def tool_uninstall(deps, unit, own_disable=False):
    """uninstall --managed of the pinned tool, for REMOVE and REPAIR. Returns its document, with
    "remaining" the list of what is left and "tool_errors" the codes of the tool's errors, and a note
    for the result or None. If the document does not arrive (no list "remaining": a timeout, a crash,
    no single JSON document, or a failure such as E_LN_STOP before the removal), the outcome is read
    back instead of assumed: detect for the dataplane, systemd for unit before and after. A lost
    report never turns a done removal into a failed one, and never a failed one into a done one.
    own_disable (REMOVE, which disables the unit itself when its config is not Tor-only at rest):
    a report whose only error is E_LN_DISABLE, the tool removed the dataplane but could not disable
    the unit, counts as a complete removal."""
    before = unit_props(deps, unit, "ActiveState", "UnitFileState") if unit else {}
    rc, doc = its(deps, ["uninstall", "--json"], timeout=ITS_TIMEOUT["uninstall"])
    doc = doc if isinstance(doc, dict) else {}
    codes = [e["code"] for e in doc.get("errors") or [] if isinstance(e, dict) and isinstance(e.get("code"), str)
             and re.fullmatch(r"E_[A-Z0-9_]{1,40}", e["code"])][:10]
    if isinstance(doc.get("remaining"), list):
        done = rc == 0 or (own_disable and codes == ["E_LN_DISABLE"])
        return dict(doc, remaining=doc["remaining"] or ([] if done else ["managed dataplane"]), tool_errors=codes), None
    _rc, found = its(deps, ["detect", "--json"], timeout=ITS_TIMEOUT["detect"])
    kind = ((found or {}).get("install") or {}).get("kind")
    removed = isinstance(kind, str) and kind not in ("managed", "unknown")
    after = unit_props(deps, unit, "ActiveState", "UnitFileState") if unit else {}
    read = {"unit": unit, "remaining": [] if removed else ["managed dataplane"],
            "ln_was_active": before.get("ActiveState") not in (None, "", "inactive", "failed"),
            "ln_disabled": (before.get("UnitFileState") in ("enabled", "enabled-runtime")
                            and after.get("UnitFileState") == "disabled"),
            "ln_started": after.get("ActiveState") == "active", "node_config": "unknown", "tool_errors": codes}
    if removed:
        seen = "the dataplane is removed"
    elif isinstance(kind, str):
        seen = "the dataplane is still there"
    else:
        seen = "detect did not answer, so the removal counts as incomplete"
    code = tool_error(doc, "E_TOOL_OUTPUT")
    if code == "E_TOOL_OUTPUT":
        note = "the report of the TunnelSats uninstall did not arrive (E_TOOL_OUTPUT); read back from the system: %s" % seen
    else:
        note = "the TunnelSats uninstall stopped with %s; read back from the system: %s" % (code, seen)
    return read, note


def announce_candidates(deps, state, record):
    """The VPN addresses (<ipv4>:<port>) LND may announce. LND resolves externalhosts itself and
    announces the IPv4 it got: the endpoint's IPv4 at the last start (guard record, read before
    uninstall removes /run/tunnelsats) and now, with the port of the guard record and of the
    stored subscription."""
    announce = (record or {}).get("announce") or {}
    ipv4s = {public_ipv4(announce.get("ipv4"))}
    host = (state or {}).get("endpoint_host")
    if valid_host(host):
        rc, out, _err = deps.run(["getent", "ahostsv4", host], timeout=10)
        if rc == 0:
            ipv4s.update(public_ipv4(line.split()[0]) for line in out.splitlines() if line.split())
    ports = {port for port in (announce.get("port"), (state or {}).get("vpn_port")) if valid_port(port)}
    return sorted("%s:%d" % (ipv4, port) for ipv4 in ipv4s if ipv4 for port in ports)


def announce_command(addresses):
    return " ".join(LNCLI + ["peers", "updatenodeannouncement"] +
                    [arg for address in addresses for arg in ("--address_remove", address)])


def tool_announce_notes(outcome, warnings, candidates):
    """The tool's announcement warnings REMOVE shows with its own notes: only when the tool's step did
    check LND (removed, none, failed), and only those naming an address outside REMOVE's candidates,
    such as another IPv4 with the forwarded port. REMOVE's own step covers its candidates."""
    if outcome not in ("removed", "none", "failed"):
        return []
    return [w for w in warnings if set(ADDRESS_RE.findall(w)) - set(candidates)]


def announce_cleanup(deps, unit, state, record, wait=120, step=5, candidates=None):
    """REMOVE, LND only. LND saves the addresses it announces and announces them again at every
    start when its config sets no externalip, so after REMOVE it would go on announcing the VPN
    address. This takes exactly the VPN address (announce_candidates, or candidates when given) out
    of LND's node announcement once LND answers, never the onion address or any other one. Returns
    the outcome (removed, none, lnd_not_ready, failed; skipped for CLN) and notes for the result."""
    if unit != UNITS["lnd"]:
        return "skipped", []
    candidates = announce_candidates(deps, state, record) if candidates is None else candidates
    if not candidates:
        return "none", []
    info = None
    if unit_props(deps, unit, "ActiveState")["ActiveState"] in ("active", "activating", "reloading"):
        started, waited = deps.clock(), 0
        info = lightning_info(deps, "lnd")
        while info is None and waited < wait and (deps.clock() - started).total_seconds() < wait:
            deps.sleep(step)
            waited += step
            info = lightning_info(deps, "lnd")
    if info is None:
        return "lnd_not_ready", ["LND did not answer (stopped, locked or still starting). Once it runs, take the "
                                 "VPN address out of its node announcement, which LND keeps from its last start: %s"
                                 % announce_command(candidates)]
    announced = {u.split("@", 1)[1] for u in info.get("uris") or [] if isinstance(u, str) and "@" in u}
    stale = [address for address in candidates if address in announced]
    if not stale:
        return "none", []
    failed = []
    for address in stale:
        rc, _out, _err = deps.run(LNCLI + ["peers", "updatenodeannouncement", "--address_remove", address], timeout=30)
        if rc != 0:
            failed.append(address)
    if failed:
        return "failed", ["LND still announces the VPN address %s; run: %s"
                          % (", ".join(failed), announce_command(failed))]
    return "removed", []


def zero_artifacts(deps, impl, conf_flag_off_expected=True):
    """What is left after REMOVE (design 6.6 step 10)."""
    leftovers = []
    warnings = []
    rc, tool = its(deps, ["detect", "--json"], timeout=ITS_TIMEOUT["detect"])
    kind = ((tool or {}).get("install") or {}).get("kind")
    if kind != "none":
        leftovers.append("tunnelsats install (%s)" % kind)
    try:
        envs = [e for e in os.listdir(deps.path(RUN_DIR)) if e.startswith("hybrid-")]
    except OSError:
        envs = []
    leftovers += ["%s/%s" % (RUN_DIR, e) for e in envs]
    rc, block = its(deps, ["block-status", "--json"], timeout=30)
    if (block or {}).get("state") != "absent":
        warnings.append("restore block %s in custom-installs.sh (inert while TunnelSats is off)"
                        % (block or {}).get("state"))
    if read_rb_conf(deps).get("tunnelsats") == "on":
        leftovers.append("tunnelsats=on in raspiblitz.conf")
    rc, out, _err = deps.run([ITS, "tick-timer", "status"], timeout=30)
    if out.strip() != "absent":
        leftovers.append("tunnelsats-tick.timer")
    if impl:
        args, props = daemon_cmdline(deps, UNITS[impl])
        if props["ControlGroup"] and not props["ControlGroup"].startswith("/system.slice/"):
            leftovers.append("%s runs in %s" % (UNITS[impl], props["ControlGroup"]))
        if has_flags(impl, args):
            leftovers.append("clearnet flags on the command line of %s" % UNITS[impl])
    return leftovers, warnings


def purge(deps):
    shred(deps.path(CONF_FILE))
    for name in (STATE_FILE, LAST_RESTORE_FILE):
        try:
            os.unlink(deps.path(name))
        except FileNotFoundError:
            pass
    for sub in ("dist", "backup"):
        directory = deps.path(STATE_DIR + "/" + sub)
        if os.path.isdir(directory):
            for entry in os.listdir(directory):
                os.unlink(os.path.join(directory, entry))
            os.rmdir(directory)
    try:
        os.rmdir(deps.path(STATE_DIR))
    except OSError:
        pass


def at_rest_audit(deps, impl, repair):
    """The at-rest audit of implementation impl after the dataplane is gone: --repair (toward
    Tor-only, one backup) if asked, read-only while the unit runs or if not asked. The document, or
    None if the audit did not answer (timeout, error)."""
    doc = None
    if repair:
        rc, doc = its(deps, ["audit", impl, "--repair", "--json"], timeout=60)
    if not repair or (doc or {}).get("status") == "not_checked":
        rc, doc = its(deps, ["audit", impl, "--json"], timeout=30)
    return doc if isinstance(doc, dict) and isinstance(doc.get("status"), str) else None


def at_rest_ok(doc, installed_only=False):
    """Tor-only at rest per audit document doc; installed_only: a missing config counts as fine."""
    if doc is None:
        return False
    if installed_only and doc.get("reason") == "config_missing":
        return True
    return doc.get("status") in ("clean", "repaired")


def at_rest_action(impl, doc, unit, then):
    """action_required of REMOVE and REPAIR for one implementation, in the form tunnelsats.sh uninstall uses:
    the exact lines to remove (<file>:<line>:<setting>) and the command to run afterwards."""
    lines = [line for line in (doc or {}).get("lines") or [] if isinstance(line, str)][:50]
    if doc is None:
        detail = "%s: the at-rest check did not answer; check the config of %s for TunnelSats clearnet " \
                 "settings (LND: externalhosts, externalip, tor.skip-proxy-for-clearnet-targets; CLN: " \
                 "bind-addr=0.0.0.0:9735, a clearnet addr or announce-addr, always-use-proxy=false)" % (impl, unit)
    else:
        keys = ",".join(k for k in doc.get("keys") or [] if isinstance(k, str)) or "none"
        detail = "%s: %s (settings: %s)" % (impl, doc.get("reason") or doc.get("status"), keys)
        if "always-use-proxy" in (doc.get("keys") or []):
            detail += "; CLN needs always-use-proxy=true"
    return {"reason": "node_config_clearnet" if lines else "node_config_unknown", "detail": detail,
            "lines": lines, "then": then}


def keep_pending_removal(deps, unit, doc, reason=None, tunnel=None):
    """Records in state.json that a refused or unfinished REMOVE left unit stopped (and disabled,
    per uninstall document doc): the menu then offers REMOVE again instead of START, and the next
    REMOVE enables and starts the unit once the removal is complete and its config is Tor-only at rest.
    reason: what REMOVE could not do to the unit (stop_failed, disable_failed); tunnel: where the
    tunnel stood then (in_place, removed, partly_removed). Both for the menu."""
    if not unit or not (doc.get("ln_disabled") or (doc.get("ln_was_active") and not doc.get("ln_started"))):
        return
    state = load_state(deps)
    if state is None:
        return
    state["remove_pending"] = {"unit": unit, "ln_was_active": bool(doc.get("ln_was_active")),
                               "ln_disabled": bool(doc.get("ln_disabled")), "at": now_iso(deps)}
    if reason:
        state["remove_pending"].update({"reason": reason, "tunnel": tunnel or "in_place"})
    save_state(deps, state)


def pending_removal(deps, state):
    """The unit a refused REMOVE left stopped, as an uninstall-like document, while that unit still
    does not run (someone may have started it by hand since); else None."""
    pending = (state or {}).get("remove_pending")
    if not isinstance(pending, dict) or pending.get("unit") not in UNITS.values():
        return None
    if unit_props(deps, pending["unit"], "ActiveState")["ActiveState"] not in ("inactive", "failed", ""):
        return None
    return {"unit": pending["unit"], "ln_was_active": bool(pending.get("ln_was_active")),
            "ln_disabled": bool(pending.get("ln_disabled")), "ln_started": False}


def clear_pending_removal(deps):
    state = load_state(deps)
    if state is not None and "remove_pending" in state:
        del state["remove_pending"]
        save_state(deps, state)


def managed_unit(deps):
    """The Lightning unit of the managed install, as verify --no-probe names it (dataplane_healthy
    reads it the same way), or None when verify does not name one."""
    _rc, doc = its(deps, ["verify", "--no-probe", "--json"], timeout=ITS_TIMEOUT["verify_no_probe"])
    unit = (doc or {}).get("unit")
    return unit if unit in UNITS.values() else None


def dropin_unit(found):
    """The Lightning unit of the managed install as the detect document found names it: the one unit
    whose drop-in from install --managed is present (artifact managed_ln_dropin). None when there is
    no such drop-in, more than one, or one for a unit RaspiBlitz does not tunnel."""
    units = set()
    for art in ((found or {}).get("install") or {}).get("artifacts") or []:
        if isinstance(art, dict) and art.get("id") == "managed_ln_dropin" and art.get("status") == "present":
            match = DROPIN_RE.fullmatch(str(art.get("location") or ""))
            units.add(match.group(1) if match else None)
    return units.pop() if len(units) == 1 and units <= set(UNITS.values()) else None


def stop_unless_tor_only(deps, unit, managed=None):
    """REMOVE, before uninstall --managed. Since tunnelsats PR 227 the tool starts the unit it stopped
    again itself when its own check of the node config finds no TunnelSats clearnet settings. That
    check is narrower than the at-rest audit (for LND it leaves out externalip, an empty externalhosts
    and tor.active, for CLN a missing always-use-proxy=true), with TunnelSats off the start guard
    repairs nothing at that start, and the audit repairs only a stopped unit. A running unit of the
    managed install whose config the audit does not find Tor-only at rest, or cannot check, is
    therefore stopped here while the dataplane still holds, recorded as remove_pending before the
    stop, and disabled. The tool then neither stops nor starts it, and this REMOVE repairs the config
    and enables and starts the unit after its own audit, or keeps it stopped and disabled, as after a
    refused REMOVE. managed: the managed unit as detect names it (dropin_unit), used as it is, also
    when state.impl names another, stopped unit; without it, verify --no-probe is asked once a stop is
    due, and a unit it names as not the managed one is never touched. Returns (record or None,
    outcome): "skipped", "stopped", or, when the tool must not run, "stop_failed" (the record has the
    state read back in "state") or "disable_failed" (still enabled: without the dataplane the next
    boot would start it with that config)."""
    unit = managed or unit
    impl = IMPL_OF_UNIT.get(unit) if unit else None
    if impl is None:
        return None, "skipped"
    props = unit_props(deps, unit, "ActiveState", "UnitFileState")
    if props["ActiveState"] in ("inactive", "failed") or at_rest_ok(at_rest_audit(deps, impl, repair=False)):
        return None, "skipped"
    found = None if managed else managed_unit(deps)
    if found and found != unit:
        # state.impl does not name the managed install: only its unit is stopped, never another one
        unit, impl = found, IMPL_OF_UNIT[found]
        props = unit_props(deps, unit, "ActiveState", "UnitFileState")
        if props["ActiveState"] in ("inactive", "failed") or at_rest_ok(at_rest_audit(deps, impl, repair=False)):
            return None, "skipped"
    record = {"unit": unit, "ln_was_active": True, "ln_disabled": False, "ln_started": False}
    keep_pending_removal(deps, unit, record)
    systemctl(deps, "stop", unit)
    record["state"] = unit_props(deps, unit, "ActiveState")["ActiveState"] or "unknown"
    if record["state"] not in ("inactive", "failed"):
        keep_pending_removal(deps, unit, record, reason="stop_failed", tunnel="in_place")
        return record, "stop_failed"
    if props["UnitFileState"] not in BOOT_OFF:
        # recorded before the disable: a REMOVE that ends here leaves the next one to enable it again
        record["ln_disabled"] = True
        keep_pending_removal(deps, unit, record)
        systemctl(deps, "disable", unit)
        if unit_props(deps, unit, "UnitFileState")["UnitFileState"] not in BOOT_OFF:
            record["ln_disabled"] = False
            keep_pending_removal(deps, unit, record, reason="disable_failed", tunnel="in_place")
            return record, "disable_failed"
    return record, "stopped"


def keep_off(deps, unit):
    """REMOVE, after the tool, when the config of unit is not Tor-only at rest: with TunnelSats off the
    start guard repairs nothing, and the tunnel is gone or partly gone, so nothing may run or start
    the unit with that config, now or at the next boot. Stops it if it runs and disables it unless no
    boot starts it, each read back from systemd (never taken from the tool's report). Returns
    (stopped_now, disabled_now, problem, state): problem None, "stop_failed" or "disable_failed",
    state the ActiveState read back."""
    props = unit_props(deps, unit, "ActiveState", "UnitFileState")
    state = props["ActiveState"] or "unknown"
    stopped_now = disabled_now = False
    if state not in ("inactive", "failed"):
        systemctl(deps, "stop", unit)
        state = unit_props(deps, unit, "ActiveState")["ActiveState"] or "unknown"
        if state not in ("inactive", "failed"):
            return False, False, "stop_failed", state
        stopped_now = True
    if props["UnitFileState"] not in BOOT_OFF:
        systemctl(deps, "disable", unit)
        if unit_props(deps, unit, "UnitFileState")["UnitFileState"] not in BOOT_OFF:
            return stopped_now, False, "disable_failed", state
        disabled_now = True
    return stopped_now, disabled_now, None, state


def keep_off_error(result, problem, unit, state, prefix=""):
    """E_LN_STOP or E_LN_DISABLE when keep_off could not stop or disable unit, with the command to run."""
    if problem == "stop_failed":
        result.error("E_LN_STOP", "operational",
                     "%s%s did not stop (state: %s): it runs with a config that is not Tor-only at rest, and "
                     "TunnelSats is off. Stop it with: sudo systemctl stop %s, then remove the listed TunnelSats "
                     "settings and choose REMOVE again" % (prefix, unit, state, unit), EXIT_OPERATIONAL)
    else:
        result.error("E_LN_DISABLE", "operational",
                     "%s%s is stopped but could not be disabled: with TunnelSats off, the next boot would start it "
                     "with a config that is not Tor-only at rest. Run: sudo systemctl disable %s, then remove the "
                     "listed TunnelSats settings and choose REMOVE again" % (prefix, unit, unit), EXIT_OPERATIONAL)


def cmd_uninstall(deps, args, result):
    if not args.yes:
        raise ModuleError("E_CONFIRMATION_REQUIRED", "usage", "REMOVE needs --yes", EXIT_USAGE)
    state = load_state(deps)
    conf = read_rb_conf(deps)
    result.fields.update({"removed": False, "remaining": [], "ln_was_active": False, "ln_started": False,
                          "ln_reenabled": False, "ln_stopped_first": False, "node_config": None, "block": None,
                          "purged": False, "artifacts": [], "announce_cleanup": None, "tool_announce_cleanup": None,
                          "tool_warnings": [], "tool_errors": []})
    if state and state.get("mode") == "adopted_legacy":
        with Lock(deps, wait=30):
            purge(deps)
        result.fields.update({"removed": True, "purged": True, "forgotten": True})
        return
    rc, tool = its(deps, ["detect", "--json"], timeout=ITS_TIMEOUT["detect"])
    managed = ((tool or {}).get("install") or {}).get("kind") == "managed"
    if not state and conf.get("tunnelsats") != "on" and not managed:
        raise ModuleError("E_NOT_CONFIGURED", "not_configured", "TunnelSats is not set up on this node",
                          EXIT_NOT_CONFIGURED)
    impl = (state or {}).get("impl") or conf.get("tunnelsatsImpl")
    impl = impl if impl in IMPLS else select_impl(conf)[0]
    with Lock(deps, wait=30):
        # the address LND announced at its last start, read before uninstall removes /run/tunnelsats
        record = read_guard_record(deps, BASES["lnd"])
        blitz_conf_set(deps, "tunnelsats", "off")
        try:
            for entry in os.listdir(deps.path(RUN_DIR)):
                if entry.startswith("hybrid-") and entry.endswith(".env"):
                    os.unlink(deps.path("%s/%s" % (RUN_DIR, entry)))
        except FileNotFoundError:
            pass
        rc, block = its(deps, ["block-remove", "--json"], timeout=30)
        result.fields["block"] = (block or {}).get("state") if rc == 0 else "error:%s" % tool_error(block, "E_BLOCK")
        deps.run([ITS, "tick-timer", "off"], timeout=60)
        unit = UNITS.get(impl)
        doc = {}
        notes = []
        result.fields["warnings"] = notes
        if managed:
            # the unit of the managed install: detect names its drop-in (no extra call), which also
            # holds when state.impl names the other implementation; else the stored implementation's
            dropin = dropin_unit(tool)
            unit = dropin or unit
            # an earlier REMOVE that did not finish may have stopped the unit (read while it is stopped)
            pending = pending_removal(deps, state)
            if pending is None:
                pending, outcome = stop_unless_tor_only(deps, unit, managed=dropin)
                result.fields["ln_stopped_first"] = outcome in ("stopped", "disable_failed")
                unit = pending["unit"] if pending else unit
                if outcome in ("stop_failed", "disable_failed"):
                    # the tool would start the unit again with that config, or the next boot would start
                    # it without the tunnel: the tool does not run, the dataplane and kill switch stay
                    result.fields.update({"remaining": ["managed dataplane"], "ln_was_active": True})
                    if outcome == "stop_failed":
                        result.error("E_LN_STOP", "operational",
                                     "%s did not stop (state: %s), so the TunnelSats uninstall did not run: it would "
                                     "start %s again with a config that is not Tor-only at rest. The tunnel and its "
                                     "kill switch stay in place; run REMOVE again" % (unit, pending["state"], unit),
                                     EXIT_OPERATIONAL)
                    else:
                        result.error("E_LN_DISABLE", "operational",
                                     "%s could not be disabled, so the TunnelSats uninstall did not run: without the "
                                     "tunnel, the next boot would start it with a config that is not Tor-only at "
                                     "rest. %s stays stopped, and the tunnel and its kill switch stay in place; run "
                                     "REMOVE again" % (unit, unit), EXIT_OPERATIONAL)
                    return
            doc, note = tool_uninstall(deps, unit, own_disable=True)
            if note:
                notes.append(note)
            unit = doc.get("unit") if doc.get("unit") in UNITS.values() else unit
            if pending and pending["unit"] == unit:
                doc = dict(doc, ln_was_active=bool(doc.get("ln_was_active")) or pending["ln_was_active"],
                           ln_disabled=bool(doc.get("ln_disabled")) or pending["ln_disabled"])
            result.fields.update({"remaining": doc["remaining"], "ln_was_active": bool(doc.get("ln_was_active")),
                                  "ln_started": bool(doc.get("ln_started")), "node_config": doc.get("node_config"),
                                  "tool_errors": doc.get("tool_errors") or []})
            # the tool's own step for LND's node announcement, for the record: REMOVE checks the
            # announcement again itself below, and only that step decides what REMOVE reports and warns
            if doc.get("announce_cleanup") in TOOL_ANNOUNCE_RESULTS:
                result.fields["tool_announce_cleanup"] = doc["announce_cleanup"]
            result.fields["tool_warnings"] = [w for w in doc.get("warnings") or [] if isinstance(w, str)][:10]
        else:
            # a REMOVE refused earlier (config not Tor-only at rest) kept this unit stopped: this run
            # audits it again and enables and starts it only if the config is Tor-only now
            pending = pending_removal(deps, state)
            if pending:
                doc = pending
                unit = pending["unit"]
                result.fields["ln_was_active"] = pending["ln_was_active"]
        # uninstall --managed starts the unit again itself when it finds the node config clean (since
        # tunnelsats PR 227 also with the start guard's variable in ExecStart: the env file this REMOVE
        # deleted counts like an empty one). It leaves the unit stopped, and disabled, when the config
        # holds TunnelSats settings or cannot be checked, and it never starts a unit that was not running
        # when it began, such as one an earlier REMOVE left stopped (remove_pending) or one this REMOVE
        # stopped first (stop_unless_tor_only). Then, and when the report was lost, only this REMOVE's
        # own audit of exactly that unit's implementation may enable and start it; the other one is
        # checked too. When that audit does not find the config Tor-only at rest, REMOVE itself makes
        # sure the unit neither runs nor starts at the next boot (keep_off), whatever the tool reported.
        unit_impl = IMPL_OF_UNIT.get(unit) if unit else None
        main_ok = other_ok = True
        main_doc = other_doc = None
        if unit_impl:
            main_doc = at_rest_audit(deps, unit_impl, repair=True)
            other_doc = at_rest_audit(deps, OTHER_IMPL[unit_impl], repair=False)
            result.fields["at_rest"] = (main_doc or {}).get("status")
            result.fields["other_impl_at_rest"] = (other_doc or {}).get("status")
            main_ok = at_rest_ok(main_doc)
            other_ok = at_rest_ok(other_doc, installed_only=True)
        complete = not result.fields["remaining"]
        tool_errors = result.fields["tool_errors"]
        problem = state_now = None
        if unit and not main_ok and (managed or pending) and "E_LN_STOP" not in tool_errors:
            # TunnelSats is off and the tunnel is gone or partly gone, so no start guard repairs this
            # config: nothing may run or start the unit with it, now or at the next boot. Read back from
            # systemd, so a failed disable by the tool (E_LN_DISABLE) or a lost report is covered too
            stopped_now, disabled_now, problem, state_now = keep_off(deps, unit)
            if stopped_now:
                doc = dict(doc, ln_was_active=True, ln_started=False)
                result.fields.update({"ln_was_active": True, "ln_started": False})
            if disabled_now:
                doc = dict(doc, ln_disabled=True)
        if complete and main_ok and doc.get("ln_disabled") and unit:
            result.fields["ln_reenabled"] = systemctl(deps, "enable", unit)
        if complete and main_ok and doc.get("ln_was_active") and not doc.get("ln_started") and unit:
            result.fields["ln_started"] = systemctl(deps, "start", unit)
        if not complete:
            if "E_LN_STOP" in tool_errors:
                # the tool removed nothing: the unit did not stop, the tunnel and its kill switch stay
                state_now = (unit_props(deps, unit, "ActiveState")["ActiveState"] if unit else "") or "unknown"
                keep_pending_removal(deps, unit, dict(doc, ln_was_active=True, ln_started=False), reason="stop_failed",
                                     tunnel="in_place")
                result.error("E_LN_STOP", "operational",
                             "%s did not stop (state: %s), so the TunnelSats uninstall removed nothing. The tunnel "
                             "and its kill switch stay in place; run REMOVE again" % (unit, state_now), EXIT_OPERATIONAL)
                return
            # the next REMOVE finds the unit stopped by this one in remove_pending and starts it again
            keep_pending_removal(deps, unit, dict(doc, ln_started=False) if problem else doc, reason=problem,
                                 tunnel="partly_removed")
            left = "removal incomplete: %s; " % ", ".join(result.fields["remaining"])
            if problem:
                keep_off_error(result, problem, unit, state_now, left)
            else:
                state_now = (unit_props(deps, unit, "ActiveState")["ActiveState"] if unit else "") or "unknown"
                running = bool(unit) and state_now not in ("inactive", "failed")
                result.error("E_REMOVE_INCOMPLETE", "operational", "%s%s, run REMOVE again" % (
                    left, "%s is %s" % (unit, state_now) if running else "Lightning stays stopped"), EXIT_OPERATIONAL)
            return
        other_action = None
        if not other_ok:
            # the other implementation's config is read-only for TunnelSats and never started by it
            other_unit = UNITS[OTHER_IMPL[unit_impl]]
            other_action = at_rest_action(OTHER_IMPL[unit_impl], other_doc, other_unit, None)
        if not main_ok:
            then = None
            if problem:
                messages = []
            elif doc.get("ln_disabled"):
                then = "systemctl enable --now %s" % unit
                messages = ["%s stays stopped and disabled: its config is not Tor-only at rest" % unit]
            elif doc.get("ln_was_active") and not doc.get("ln_started"):
                then = "systemctl start %s" % unit
                messages = ["%s stays stopped: its config is not Tor-only at rest" % unit]
            else:
                messages = ["the config of %s is not Tor-only at rest" % unit]
            actions = [at_rest_action(unit_impl, main_doc, unit, then)]
            if other_action:
                actions.append(other_action)
                messages.append("the config of %s is not Tor-only at rest" % other_unit)
            result.fields["action_required"] = {
                "reason": "node_config_clearnet" if any(a["lines"] for a in actions) else "node_config_unknown",
                "detail": "; ".join(a["detail"] for a in actions),
                "lines": [line for a in actions for line in a["lines"]],
                "then": then}
            keep_pending_removal(deps, unit, dict(doc, ln_started=False) if problem else doc, reason=problem,
                                 tunnel="removed")
            if problem:
                keep_off_error(result, problem, unit, state_now, "; ".join(messages + [""]))
            else:
                result.error("E_AT_REST_UNREPAIRABLE", "operational",
                             "%s. Remove the listed TunnelSats settings%s" % (
                                 "; ".join(messages), ", then run: sudo %s" % then if then else ""), EXIT_OPERATIONAL)
            return
        candidates = announce_candidates(deps, state, record) if unit == UNITS["lnd"] else []
        cleanup, cleanup_notes = announce_cleanup(deps, unit, state, record, candidates=candidates)
        result.fields["announce_cleanup"] = cleanup
        leftovers, warnings = zero_artifacts(deps, impl)
        if other_action:
            result.fields["other_impl_lines"] = other_action["lines"]
            warnings.insert(0, "%s was left as it is: its config is not Tor-only at rest (%s). TunnelSats never "
                               "starts it; %s before you start it" % (
                                   other_unit, other_action["detail"],
                                   "remove these settings: %s" % "; ".join(other_action["lines"])
                                   if other_action["lines"] else "check its config"))
        result.fields["artifacts"] = leftovers
        result.fields["warnings"] = notes + warnings + cleanup_notes + tool_announce_notes(
            result.fields["tool_announce_cleanup"], result.fields["tool_warnings"], candidates)
        if leftovers:
            result.error("E_ARTIFACTS_LEFT", "operational", "left behind: %s" % "; ".join(leftovers), EXIT_OPERATIONAL)
            return
        result.fields["removed"] = True
        if args.purge:
            purge(deps)
            result.fields["purged"] = True
        else:
            clear_pending_removal(deps)


# ------------------------------------------------------------------------------------------
# repair
# ------------------------------------------------------------------------------------------

def dataplane_healthy(deps, impl):
    rc, doc = its(deps, ["verify", "--no-probe", "--json"], timeout=ITS_TIMEOUT["verify_no_probe"])
    if rc not in (0, 5) or not doc:
        return False
    if doc.get("install_state") != "installed" or doc.get("unit") != UNITS[impl] or doc.get("emergency_block"):
        return False
    return not any(isinstance(c, dict) and c.get("class") == "unsafe" and c.get("result") == "fail"
                   for c in doc.get("checks") or [])


def cmd_repair(deps, args, result):
    if not args.yes:
        raise ModuleError("E_CONFIRMATION_REQUIRED", "usage", "REPAIR needs --yes (it may restart Lightning)",
                          EXIT_USAGE)
    state = load_state(deps)
    if state is None:
        raise ModuleError("E_NOT_CONFIGURED", "not_configured", "no stored subscription: IMPORT first",
                          EXIT_NOT_CONFIGURED)
    if state.get("mode") == "adopted_legacy":
        raise ModuleError("E_UPGRADE_UNAVAILABLE", "refused",
                          "the adopted standard install can be upgraded with a later TunnelSats release", EXIT_REFUSED)
    cfg = load_stored_config(deps)
    if cfg is None or cfg["public_key"] != state.get("public_key"):
        raise ModuleError("E_STORED_CONFIG", "operational", "the stored config is missing or invalid: IMPORT again",
                          EXIT_OPERATIONAL)
    conf = read_rb_conf(deps)
    if conf.get("runBehindTor") != "on":
        # the start guard would block every mainnet start (tor_off); a refusal keeps Lightning running
        raise ModuleError("E_TOR_REQUIRED", "refused",
                          "TunnelSats needs Tor: switch Tor on first (SSH menu > SETTINGS), then REPAIR",
                          EXIT_REFUSED)
    impl, why = select_impl(conf, args.impl)
    if impl is None:
        raise ModuleError("E_NOT_ELIGIBLE", "not_eligible", "no Lightning implementation to tunnel (%s)" % why,
                          EXIT_NOT_CONFIGURED)
    actions = []
    result.fields.update({"actions": actions, "ln_start_wait": None})
    with Lock(deps, wait=30):
        rc, tool = its(deps, ["detect", "--json"], timeout=ITS_TIMEOUT["detect"])
        managed = ((tool or {}).get("install") or {}).get("kind") == "managed"
        rc, its_state = its(deps, ["status", "--json"], timeout=ITS_TIMEOUT["status"])
        current_tool = (its_state or {}).get("tool_hash") == "current"
        unit = UNITS[impl]
        was_active = unit_props(deps, unit, "ActiveState")["ActiveState"] == "active"
        if managed and (not current_tool or state.get("impl") != impl or not dataplane_healthy(deps, impl)):
            # the unit of the old install: the one of the stored implementation
            doc, note = tool_uninstall(deps, UNITS[state["impl"]] if state.get("impl") in IMPLS else unit)
            actions.append("uninstall")
            if note:
                result.fields["warnings"] = [note]
            if doc["remaining"]:
                raise ModuleError("E_REMOVE_INCOMPLETE", "operational",
                                  "the old dataplane could not be removed; Lightning stays stopped", EXIT_OPERATIONAL)
            if doc.get("ln_disabled") and doc.get("unit") in UNITS.values():
                # as in REMOVE: undo uninstall's disable only after a Tor-only at-rest audit of that
                # unit (if the activation below fails, TunnelSats is off and the guard repairs nothing)
                audit = at_rest_audit(deps, IMPL_OF_UNIT[doc["unit"]], repair=True)
                if not at_rest_ok(audit):
                    then = "systemctl enable --now %s" % doc["unit"]
                    result.fields["action_required"] = at_rest_action(IMPL_OF_UNIT[doc["unit"]], audit, doc["unit"], then)
                    raise ModuleError("E_AT_REST_UNREPAIRABLE", "operational",
                                      "%s stays stopped and disabled: its config is not Tor-only at rest. Remove the "
                                      "listed TunnelSats settings, then run: sudo %s, and REPAIR again"
                                      % (doc["unit"], then), EXIT_OPERATIONAL)
                systemctl(deps, "enable", doc["unit"])
                actions.append("reenable")
            was_active = was_active or bool(doc.get("ln_was_active"))
            managed = False
        if not managed:
            state["impl"] = impl
            activate(deps, impl, result, stored_writer=lambda: save_state(deps, state))
            actions.append("install")
            if was_active and unit_props(deps, unit, "ActiveState")["ActiveState"] != "active":
                systemctl(deps, "start", unit)
                actions.append("start")
        else:
            rc, out, _err = deps.run([ITS, "fetch", "--json"], timeout=ITS_TIMEOUT["fetch"])
            if not unit_template_ok(deps, impl):
                regenerate_unit(deps, impl)
                actions.append("unit_regenerated")
            blitz_conf_set(deps, "tunnelsatsImpl", impl)
            blitz_conf_set(deps, "tunnelsats", "on")
            rc, block = its(deps, ["block-insert", "--json"], timeout=30)
            actions.append("block" if rc == 0 else "block_failed")
            deps.run([ITS, "tick-timer", "on"], timeout=60)
            actions.append("tick_timer")
    # the reinstall restarted a running unit (the tool's install, or the start above): the check
    # waits until that start is done; the path without a restart makes no wait
    wait = wait_until_started(deps, unit) if "install" in actions else None
    result.fields["ln_start_wait"] = wait
    checked = with_start_wait(run_check(deps), wait)
    result.fields.update(checked)
    if start_wait_detail(wait):
        result.fields["warnings"] = list(result.fields.get("warnings") or []) + [start_wait_detail(wait)]
    result.exit_code = verdict_exit(checked["verdict"])


# ------------------------------------------------------------------------------------------
# subscriptions-list, tick
# ------------------------------------------------------------------------------------------

def cmd_subscriptions_list(deps, args, result):
    state = load_state(deps)
    items = []
    if state and state.get("public_key"):
        conf = read_rb_conf(deps)
        data = (state.get("api") or {}).get("data") or {}
        expiry = parse_iso(data.get("expiry") or state.get("valid_until") or "")
        warning = ""
        if expiry and expiry < deps.clock():
            warning = "expired"
        elif data.get("peer_status") == "disabled":
            warning = "peer disabled (bandwidth or subscription)"
        elif (state.get("last_check") or {}).get("verdict") not in (None, "protected"):
            warning = "check: %s" % state["last_check"]["verdict"]
        server = data.get("server_domain") or state.get("server_domain") or state.get("endpoint_host")
        items.append({
            "type": "tunnelsats-v1",
            "id": hashlib.sha256(state["public_key"].encode()).hexdigest()[:8],
            "name": server, "active": conf.get("tunnelsats") == "on" or state.get("mode") == "adopted_legacy",
            "warning": warning,
            "description": "WireGuard VPN for Lightning clearnet via %s%s" % (
                server, ", expires %s" % expiry.strftime("%Y-%m-%d") if expiry else ""),
            "time_created": state.get("imported_at"),
        })
    result.fields["subscriptions"] = items


def notify(deps, conf, state, invocation):
    """The restart notice, once per Lightning start (invocation). Returns the notification entry."""
    record = state.get("notify") or {}
    if record.get("invocation_id") != invocation:
        record = {"invocation_id": invocation, "attempts": 0, "outcome": None}
    if record.get("outcome") in ("handed_off", "skipped_disabled", "dropped"):
        return None
    if conf.get("notify") != "on":
        record["outcome"] = "skipped_disabled"
    else:
        record["attempts"] += 1
        rc, _out, _err = deps.run([NOTIFY, "send", RESTART_MESSAGE], timeout=60)
        if rc == 0:
            record["outcome"] = "handed_off"
        else:
            record["outcome"] = "failed" if record["attempts"] < 3 else "dropped"
    state["notify"] = record
    if record["outcome"] != "failed":
        state["notified_invocation_id"] = invocation
    deps.log("notify event=restart_needed outcome=%s attempt=%d" % (record["outcome"], record["attempts"]))
    return {"event": "restart_needed", "outcome": record["outcome"], "attempt": record["attempts"]}


def cmd_tick(deps, args, result):
    result.fields.update({"restart_needed": False, "notifications": [], "test_hook": None})
    try:
        lock = Lock(deps, wait=0).__enter__()
    except ModuleError:
        result.fields["skipped"] = "another TunnelSats action is running"
        return
    try:
        conf = read_rb_conf(deps)
        state = load_state(deps)
        if conf.get("tunnelsats") != "on" or not state:
            return
        impl = state.get("impl") or conf.get("tunnelsatsImpl")
        if impl not in IMPLS:
            return
        props = unit_props(deps, UNITS[impl], "ActiveState", "InvocationID")
        record = read_guard_record(deps, BASES[impl])
        if props["ActiveState"] != "active" or not record or not props["InvocationID"] or \
                record.get("invocation_id") != props["InvocationID"]:
            return
        if record.get("decision") not in ("tor-only", "hybrid") or record.get("reason") not in RESTARTABLE:
            return
        rc, dry = its(deps, ["guard", impl, "mainnet", "--dry-run", "--json"], timeout=ITS_TIMEOUT["guard_dry_run"])
        if not dry or dry.get("decision") != "hybrid" or (impl == "cl" and dry.get("reason") != "ok"):
            return
        result.fields["restart_needed"] = True
        entry = notify(deps, conf, state, props["InvocationID"])
        if entry:
            result.fields["notifications"].append(entry)
            save_state(deps, state)
    finally:
        lock.__exit__(None, None, None)


# ------------------------------------------------------------------------------------------
# menu (TUI)
# ------------------------------------------------------------------------------------------

ABOUT_TEXT = """TunnelSats routes this node's Lightning clearnet traffic through a WireGuard
VPN. Peers see the VPN server's address, never your home IP.

- Your node becomes reachable on clearnet via the VPN server and connects to
  clearnet peers through the tunnel. Tor stays on for onion peers.
- If the tunnel is down or the subscription ended, clearnet Lightning traffic
  is blocked. Onion peers keep working.
- TunnelSats sees your home IP (as the VPN client) and your WireGuard public
  key. Your private key never leaves this node.

Buy a subscription on tunnelsats.com, then use IMPORT with the downloaded
WireGuard config."""

VERDICT_TEXT = {"protected": "Protected", "degraded": "Clearnet paused, Tor peers keep working",
                "unsafe": "Action needed", "not_configured": "Not set up"}


def check_text(checked):
    lines = [VERDICT_TEXT.get(checked["verdict"], checked["verdict"]), ""]
    for c in checked["checks"]:
        if c["result"] == "fail":
            lines.append("- %s: %s" % (c["id"], c["detail"]))
    if checked["verdict"] == "protected":
        lines.append("Every check passed.")
    return "\n".join(lines)


def menu_run(deps, verb_args):
    """Runs a verb in-process and returns its document."""
    result = Result(verb_args[0])
    try:
        args = build_parser().parse_args(verb_args)
        HANDLERS[verb_args[0]](deps, args, result)
    except (ModuleError, _UsageError) as exc:
        code = getattr(exc, "code", "E_USAGE")
        result.error(code, getattr(exc, "cls", "usage"), str(exc), getattr(exc, "exit_code", EXIT_USAGE))
    return result.document()


def menu_choices(deps, state, conf, found=None):
    """The menu entries (tag, text) and a notice shown above them, or None. START and RESTART only
    while TunnelSats is on: the start guard then audits the config at rest before Lightning runs.
    With TunnelSats off (after REMOVE) nothing would, so this menu never starts Lightning then;
    after a refused REMOVE it shows what keeps Lightning stopped and offers REMOVE again."""
    if state is None:
        choices = [("IMPORT", "Import a WireGuard config (bought on tunnelsats.com)")]
        if (found or {}).get("adopt_available"):
            choices.append(("ADOPT", "Take over the existing TunnelSats setup"))
        choices.append(("ABOUT", "How it works, privacy trade-offs"))
        return choices, None
    active_ts = conf.get("tunnelsats") == "on"
    impl = state.get("impl") or conf.get("tunnelsatsImpl") or "lnd"
    pending = state.get("remove_pending")
    notice = None
    remove = ("REMOVE", "Remove TunnelSats from this node")
    if not active_ts and isinstance(pending, dict) and pending.get("unit") in UNITS.values():
        notice = pending_removal_text(deps, pending)
        remove = ("REMOVE", "Remove again: check the config, then start Lightning")
    choices = [("STATUS", "Subscription and tunnel status"), ("CHECK", "Connection check"),
               ("REPAIR", "Re-apply TunnelSats (also: update the pinned tool)"), remove]
    if active_ts and state.get("mode") != "adopted_legacy" and impl in UNITS:
        if unit_props(deps, UNITS[impl], "ActiveState")["ActiveState"] != "active":
            choices.append(("START", "Start Lightning"))
        else:
            record = read_guard_record(deps, BASES[impl])
            if record and record.get("reason") in RESTARTABLE:
                choices.append(("RESTART", "Restart Lightning to resume clearnet"))
    return choices, notice


def pending_removal_text(deps, pending):
    """The notice after a REMOVE that did not finish: the live state of the unit it recorded (never the
    record alone, which is written before the stop), where the tunnel stands (in place when REMOVE
    stopped before the tool; removed, or partly removed, when REMOVE could not stop or disable the
    unit afterwards, with the command to run), and a fresh read-only audit of the unit's config."""
    unit = pending["unit"]
    props = unit_props(deps, unit, "ActiveState", "UnitFileState")
    running = props["ActiveState"] not in ("inactive", "failed")
    boot = props["UnitFileState"] not in BOOT_OFF
    stopped = "stopped and disabled" if not boot else "stopped"
    reason, tunnel = pending.get("reason"), pending.get("tunnel") or "in_place"
    what = "did not stop" if reason == "stop_failed" else "could not be disabled"
    joiner = ": its"
    if reason in ("stop_failed", "disable_failed") and tunnel != "in_place":
        now = ("%s still runs (%s)" % (unit, props["ActiveState"] or "state unknown") if running
               else "%s is stopped but still enabled" % unit if boot else "%s is %s" % (unit, stopped))
        text = "REMOVE did not finish: the tunnel is %s, and %s %s; %s" % (
            "already removed" if tunnel == "removed" else "partly removed", unit, what, now)
        command = ("systemctl disable --now %s" if running and boot else "systemctl stop %s" if running
                   else "systemctl disable %s" if boot else None)
        if command:
            text += ". Run now: sudo %s, so that it neither runs nor starts without the tunnel" % (command % unit)
            joiner = ". Its"
    elif reason in ("stop_failed", "disable_failed"):
        now = "%s still runs (%s)" % (unit, props["ActiveState"] or "state unknown") if running \
            else "%s is %s" % (unit, stopped)
        text = "REMOVE did not finish: %s %s, so the tunnel and its kill switch stay in place; %s" % (unit, what, now)
    elif running:
        text = "REMOVE did not finish: %s still runs (%s)" % (unit, props["ActiveState"] or "state unknown")
    else:
        text = "REMOVE left %s %s" % (unit, stopped)
    then = "it checks the config first" if running else "it checks the config, then starts %s" % unit
    rc, audit = its(deps, ["audit", IMPL_OF_UNIT[unit], "--json"], timeout=30)
    if audit and audit.get("status") == "clean":
        return text + ". Its config is Tor-only now: choose REMOVE again to finish; %s." % (
            "it enables and starts %s" % unit if not running else "it checks the config first")
    text += joiner + " config is not Tor-only at rest"
    lines = [line for line in (audit or {}).get("lines") or [] if isinstance(line, str)][:8]
    if lines:
        text += ". Remove these lines:\n" + "\n".join("  %s" % line for line in lines)
    elif audit is None:
        text += " (the check did not answer)"
    else:
        text += " (%s)" % (audit.get("reason") or audit.get("status"))
    return text + "\nThen choose REMOVE again: %s." % then


def menu_start(deps, restart=False):
    """START and RESTART of the menu, only while TunnelSats is on (see menu_choices). Returns the
    implementation it started, or None if TunnelSats is off."""
    conf = read_rb_conf(deps)
    if conf.get("tunnelsats") != "on":
        return None
    impl = (load_state(deps) or {}).get("impl") or conf.get("tunnelsatsImpl") or "lnd"
    if impl not in UNITS:
        return None
    systemctl(deps, "restart" if restart else "start", UNITS[impl])
    return impl


def cmd_menu(deps, args, result):  # pragma: no cover - interactive
    from dialog import Dialog  # imported only here
    d = Dialog(dialog="dialog", autowidgetsize=True)
    d.set_background_title("TunnelSats VPN")
    found = None
    while True:
        state = load_state(deps)
        conf = read_rb_conf(deps)
        if state is None and found is None:
            os.system("clear")
            print("# TunnelSats: checking this node ...")
            found = detect(deps)
        choices, notice = menu_choices(deps, state, conf, found)
        text = "\nTunnelSats VPN for Lightning clearnet:"
        if notice:
            text = "\n%s\n%s" % (notice, text)
        code, tag = d.menu(text, choices=choices, width=78 if notice else 70, height=28 if notice else 16,
                           title="TunnelSats", cancel_label="Back")
        if code != d.OK:
            return
        if tag == "ABOUT":
            d.msgbox(ABOUT_TEXT, title="About TunnelSats", width=80, height=22)
        elif tag == "IMPORT":
            code, path = d.inputbox("Path of the WireGuard config file to import:", init="/home/admin/tunnelsats.conf",
                                    width=70, height=10, title="IMPORT")
            if code != d.OK or not path.strip():
                continue
            if d.yesno(ABOUT_TEXT + "\n\nImport and activate now?", width=80, height=24, title="IMPORT") != d.OK:
                continue
            os.system("clear")
            print("# TunnelSats: importing, this can take a few minutes ...")
            doc = menu_run(deps, ["import", "--file", path.strip()])
            if doc["errors"] and doc["errors"][0]["code"] == "E_API_UNAVAILABLE" and d.yesno(
                    "The TunnelSats API could not be reached to confirm the subscription.\n\n"
                    "Continue without the confirmation?", width=70, height=10) == d.OK:
                doc = menu_run(deps, ["import", "--file", path.strip(), "--yes"])
            d.msgbox(result_text(doc), title="IMPORT", width=78, height=20)
        elif tag == "ADOPT":
            if d.yesno("Take over the subscription of the existing TunnelSats setup?\n\nNothing on the system "
                       "changes; STATUS works afterwards.", width=70, height=10) != d.OK:
                continue
            doc = menu_run(deps, ["adopt"])
            d.msgbox(result_text(doc), title="ADOPT", width=78, height=20)
        elif tag == "STATUS":
            doc = menu_run(deps, ["status", "--refresh"])
            d.msgbox(status_text(doc), title="STATUS", width=78, height=22)
        elif tag == "CHECK":
            os.system("clear")
            print("# TunnelSats: running the connection check ...")
            d.msgbox(check_text(run_check(deps)), title="CHECK", width=78, height=22)
        elif tag == "REPAIR":
            if d.yesno("REPAIR re-applies TunnelSats and may restart Lightning. Continue?", width=60, height=8) != d.OK:
                continue
            os.system("clear")
            doc = menu_run(deps, ["repair", "--yes"])
            d.msgbox(result_text(doc), title="REPAIR", width=78, height=20)
        elif tag == "REMOVE":
            code = d.yesno("Lightning restarts in Tor-only mode and the tunnel and kill switch are removed.\n"
                           "Your subscription keeps running at TunnelSats until it expires.\n\n"
                           "Keep the stored config to re-install later?", yes_label="Keep", no_label="Delete",
                           extra_button=True, extra_label="Cancel", width=76, height=12, title="REMOVE")
            if code == d.EXTRA or code == d.ESC:
                continue
            os.system("clear")
            print("# TunnelSats: removing (Lightning stops while the kill switch goes away) ...")
            doc = menu_run(deps, ["uninstall", "--yes"] + ([] if code == d.OK else ["--purge"]))
            d.msgbox(result_text(doc), title="REMOVE", width=78, height=20)
        elif tag in ("START", "RESTART"):
            os.system("clear")
            impl = menu_start(deps, restart=tag == "RESTART")
            if impl is None:
                d.msgbox("TunnelSats is off: this menu starts Lightning only while TunnelSats is on.",
                         title=tag, width=70, height=8)
            elif impl == "lnd" and conf.get("autoUnlock") != "on":
                deps.run([LND_UNLOCK, "chain-unlock", "mainnet"], timeout=600, interactive=True)
            elif impl == "cl" and conf.get("clEncryptedHSM") == "on" and conf.get("clAutoUnlock") != "on":
                deps.run([CL_HSMTOOL, "unlock", "mainnet"], timeout=600, interactive=True)


def result_text(doc):
    action = doc.get("action_required") or {}
    if doc["errors"]:
        lines = ["%s\n\n%s" % (doc["errors"][0]["code"], doc["errors"][0]["message"])]
        if action.get("lines"):
            lines += ["", "Lines to remove:"] + ["  %s" % line for line in action["lines"][:8]]
        if action.get("then"):
            lines += ["", "Then run: sudo %s" % action["then"]]
            if doc.get("command") == "uninstall":
                lines.append("Or choose REMOVE again: it checks the config first, then starts Lightning.")
        return "\n".join(lines)
    lines = ["Done."]
    if "verdict" in doc:
        lines.append("Connection check: %s" % VERDICT_TEXT.get(doc["verdict"], doc["verdict"]))
    if doc.get("warnings"):
        lines += ["", "Notes:"] + ["- %s" % w for w in doc["warnings"][:6]]
    if doc.get("custom_installs_lines"):
        lines += ["", "Lines in custom-installs.sh to review by hand:"]
        lines += ["  %d: %s" % (entry["line"], entry["text"]) for entry in doc["custom_installs_lines"][:8]]
    return "\n".join(lines)


def status_text(doc):
    if not doc.get("configured"):
        return "No TunnelSats subscription is set up on this node."
    tunnel = doc.get("tunnel") or {}
    lines = ["Server:      %s (VPN port %s)" % (doc.get("server_domain"), doc.get("vpn_port")),
             "Expires:     %s" % (doc.get("expiry") or "unknown"),
             "Bandwidth:   %s of %s GB, resets used %s of %s" % (
                 doc.get("bandwidth_used_gb"), doc.get("bandwidth_limit_gb"), doc.get("resets_this_month"),
                 doc.get("max_resets_per_month")),
             "Peer:        %s" % (doc.get("peer_status") or "unknown"),
             "API sync:    %s" % (doc.get("sync") or {}).get("outcome"),
             "Handshake:   %s" % ("%s s ago" % tunnel["handshake_age_s"] if tunnel.get("handshake_age_s") is not None
                                  else "none"),
             "Guard:       %s (%s)" % ((doc.get("guard") or {}).get("decision"), (doc.get("guard") or {}).get("reason")),
             "Public key:  %s" % doc.get("public_key")]
    if doc.get("action"):
        lines += ["", doc["action"]]
    return "\n".join(lines)


# ------------------------------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------------------------------

HANDLERS = {"menu": cmd_menu, "import": cmd_import, "adopt": cmd_adopt, "status": cmd_status, "check": cmd_check,
            "detect": cmd_detect, "repair": cmd_repair, "uninstall": cmd_uninstall,
            "subscriptions-list": cmd_subscriptions_list, "tick": cmd_tick}


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    """Raises on a usage error instead of exiting, so every run prints one document."""

    def error(self, message):
        raise _UsageError(message)


def build_parser():
    parser = _Parser(prog="blitz.subscriptions.tunnelsats.py", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="verb", required=True)

    def verb(name):
        p = sub.add_parser(name)
        p.add_argument("--json", action="store_true")
        return p

    verb("menu")
    p = verb("import")
    p.add_argument("--file", required=True)
    p.add_argument("--impl", choices=IMPLS)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--yes", action="store_true")
    p = verb("adopt")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--upgrade", action="store_true")
    p = verb("status")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--refresh", action="store_true")
    group.add_argument("--cached", action="store_true")
    verb("check")
    verb("detect")
    p = verb("repair")
    p.add_argument("--impl", choices=IMPLS)
    p.add_argument("--yes", action="store_true")
    p = verb("uninstall")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--purge", action="store_true")
    verb("subscriptions-list")
    verb("tick")
    return parser


def main(argv=None, deps=None, out=None):
    argv = sys.argv[1:] if argv is None else argv
    deps = deps or Deps()
    as_json = "--json" in argv
    verb = next((a for a in argv if not a.startswith("-")), "")
    result = Result(verb or "usage")
    if argv in (["-h"], ["--help"]):
        build_parser().print_help()
        return EXIT_OK
    try:
        args = build_parser().parse_args(argv)
        if not deps.is_root():
            raise ModuleError("E_NOT_ROOT", "usage", "run as root (sudo)", EXIT_USAGE)
        os.umask(0o077)
        HANDLERS[args.verb](deps, args, result)
    except _UsageError as exc:
        result.error("E_USAGE", "usage", str(exc), EXIT_USAGE)
    except ModuleError as exc:
        result.error(exc.code, exc.cls, exc.message, exc.exit_code)
    except Exception as exc:  # an unexpected failure still gives one document, without details
        deps.log("unexpected %s" % type(exc).__name__)
        result.error("E_INTERNAL", "operational", "unexpected %s" % type(exc).__name__, EXIT_OPERATIONAL)
    if verb == "menu" and not as_json:
        return EXIT_OK
    emit(result, as_json, out)
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
