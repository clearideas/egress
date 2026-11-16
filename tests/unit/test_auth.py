import base64
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from clearideas_egress.audit import AuditLog
from clearideas_egress.auth import (BasicAuthHelper, KeyRing, TokenError, _b64url_encode, decode_key, mint_token,
                                    verify_token)

SRC = str(Path(__file__).resolve().parents[2] / "src")


class TokenTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.key = os.urandom(32)
        (self.dir / "k1.key").write_text(base64.b64encode(self.key).decode())
        self.keys = KeyRing(self.dir, refresh_seconds=0)

    def mint(self, sub="sbx-1", src=("10.0.0.7/32",), ttl=600, key=None, kid="k1", now=None):
        return mint_token(key or self.key, kid, sub, list(src), ttl, now=now)

    def reason(self, token, username="sbx-1", ip="10.0.0.7", **kwargs):
        try:
            verify_token(token, username, ip, self.keys, **kwargs)
            return "ok"
        except TokenError as error:
            return error.reason

    def test_valid(self):
        claims = verify_token(self.mint(), "sbx-1", "10.0.0.7", self.keys)
        self.assertEqual(claims["sub"], "sbx-1")

    def test_rejections(self):
        token = self.mint()
        prefix, kid, payload, sig = token.split(".")
        forged_claims = _b64url_encode(json.dumps({"sub": "sbx-1", "src": ["0.0.0.0/0"], "iat": 1, "exp": 2**40}).encode())
        cases = {
            "expired": self.reason(self.mint(ttl=60, now=int(time.time()) - 3600)),
            "not_yet_valid": self.reason(self.mint(now=int(time.time()) + 3600)),
            "bad_signature": self.reason(f"{prefix}.{kid}.{payload}.{sig[:-4]}AAAA"),
            "bad_signature ": self.reason(f"{prefix}.{kid}.{forged_claims}.{sig}"),
            "unknown_key": self.reason(self.mint(kid="k2")),
            "unknown_key ": self.reason(self.mint(key=os.urandom(32), kid="k9")),
            "subject_mismatch": self.reason(token, username="sbx-2"),
            "source_not_allowed": self.reason(token, ip="10.0.0.8"),
            "source_not_allowed ": self.reason(token, ip=None),
            "malformed": self.reason("v1.k1.abc"),
            "malformed ": self.reason("v2." + token[3:]),
            "malformed  ": self.reason(token + "=="),
            "malformed   ": self.reason("x" * 5000),
        }
        for expected, got in cases.items():
            with self.subTest(expected=expected.strip()):
                self.assertEqual(got, expected.strip())

    def test_ipv4_mapped_source(self):
        self.assertEqual(self.reason(self.mint(), ip="::ffff:10.0.0.7"), "ok")

    def test_clock_skew_tolerance(self):
        self.assertEqual(self.reason(self.mint(ttl=60, now=int(time.time()) - 80)), "ok")
        self.assertEqual(self.reason(self.mint(now=int(time.time()) + 20)), "ok")

    def test_mint_validation(self):
        for kwargs in [{"ttl": 0}, {"ttl": 10**6}, {"src": ()}, {"src": ("10.0.0.1/24",)}, {"sub": "a b"},
                       {"kid": "bad kid"}, {"key": b"short"}]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.mint(**kwargs)

    def test_key_rotation_and_revocation(self):
        new_key = os.urandom(32)
        (self.dir / "k2.key").write_text(base64.b64encode(new_key).decode())
        self.assertEqual(self.reason(self.mint(key=new_key, kid="k2")), "ok")
        (self.dir / "k1.key").unlink()
        self.assertEqual(self.reason(self.mint()), "unknown_key")

    def test_helper_without_keys_refuses_and_keeps_running(self):
        empty = Path(tempfile.mkdtemp())
        token = mint_token(os.urandom(32), "k1", "sbx-1", ["10.0.0.7/32"], 60)
        result = subprocess.run([sys.executable, "-m", "clearideas_egress", "auth", "--concurrent"],
                                input=f"0 sbx-1 {token} 10.0.0.7\n1 sbx-1 {token} 10.0.0.7\n", capture_output=True,
                                text=True, env={**os.environ, "PYTHONPATH": SRC, "EGRESS_AUTH_KEYS_DIR": str(empty),
                                                "EGRESS_AUDIT_LOG": "off"})
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.splitlines(), ["0 ERR", "1 ERR"])
        keys = KeyRing(empty, require_keys=False)
        self.assertEqual(len(keys), 0)
        (empty / "k1.key").write_text(base64.b64encode(os.urandom(32)).decode())
        keys.refresh_seconds = 0
        self.assertIsNotNone(keys.get("k1"))  # keys appearing later are picked up

    def test_keyring_requires_strong_keys(self):
        empty = Path(tempfile.mkdtemp())
        (empty / "weak.key").write_text(base64.b64encode(b"short").decode())
        with self.assertRaises(ValueError):
            KeyRing(empty)
        with self.assertRaises(ValueError):
            decode_key("")


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.key = os.urandom(32)
        (self.dir / "k1.key").write_text(base64.b64encode(self.key).decode())
        self.helper = BasicAuthHelper(KeyRing(self.dir), AuditLog(None))

    def test_line_formats(self):
        token = mint_token(self.key, "k1", "sbx-1", ["10.0.0.7/32"], 60)
        self.assertEqual(self.helper.check(["sbx-1", token, "10.0.0.7"]), "OK")
        self.assertEqual(self.helper.check(["sbx-1", token, "10.0.0.8"]), "ERR")
        self.assertEqual(self.helper.check(["sbx-1", token]), "ERR")  # no key_extras: source unknown
        self.assertEqual(self.helper.check(["sbx%2D1", token, "10.0.0.7"]), "OK")  # Squid URL-escapes fields
        self.assertEqual(self.helper.check(["-", token, "10.0.0.7"]), "ERR")
        self.assertTrue(self.helper.check(["only-one-field"]).startswith("BH"))

    def test_helper_process_concurrent(self):
        token = mint_token(self.key, "k1", "sbx-1", ["10.0.0.7/32"], 60)
        result = subprocess.run([sys.executable, "-m", "clearideas_egress", "auth", "--concurrent"],
                                input=f"0 sbx-1 {token} 10.0.0.7\n1 sbx-1 {token} 10.0.0.9\n2 garbage\n",
                                capture_output=True, text=True,
                                env={**os.environ, "PYTHONPATH": SRC, "EGRESS_AUTH_KEYS_DIR": str(self.dir),
                                     "EGRESS_AUDIT_LOG": "off"})
        self.assertEqual(result.stdout.splitlines(), ["0 OK", "1 ERR", "2 BH message=invalid_request"])

    def test_mint_cli(self):
        key_file = self.dir / "k1.key"
        result = subprocess.run([sys.executable, "-c", "from clearideas_egress.auth import mint_main; raise SystemExit(mint_main())",
                                 "--key-file", str(key_file), "--kid", "k1", "--sub", "sbx-1", "--src", "10.0.0.7/32",
                                 "--ttl", "60"], capture_output=True, text=True, env={**os.environ, "PYTHONPATH": SRC})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.helper.check(["sbx-1", result.stdout.strip(), "10.0.0.7"]), "OK")


if __name__ == "__main__":
    unittest.main()
