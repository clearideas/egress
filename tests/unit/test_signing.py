import base64
import time
import unittest

from clearideas_egress.signing import (Destination, SignatureError, SigningProfile, canonical_string, decode_identity,
                                       derive_run_key, encode_identity, sign_request, verify_request)

MASTER = bytes(range(32))
DEFAULT = SigningProfile.parse()
TWO = SigningProfile.parse("tenantId=X-Egress-Tenant-Id,runId=X-Egress-Run-Id", "runId")
TWO_ID = {"tenantId": "tenant-1", "runId": "run-7f3a"}


class Keys:
    def __init__(self, mapping):
        self.mapping = mapping

    def get(self, kid):
        return self.mapping.get(kid)


KEYS = Keys({"m1": MASTER})


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class SpecVectorTests(unittest.TestCase):
    """Published in docs/INTEGRATION.md; independently reproduced with `openssl dgst -hmac`."""

    DEST = Destination.build("POST", "https", "api.anthropic.com", 443, "/v1/messages?beta=true")
    CONNECT = Destination.build("CONNECT", "", "api.openai.com", 443, "")

    def check(self, profile, identity, run_key, sig, connect_sig):
        key = derive_run_key(MASTER, identity)
        self.assertEqual(b64(key), run_key)
        headers = sign_request(key, "m1", profile, identity, self.DEST, timestamp=1767225600, nonce="n0nce-0123456789abcdef")
        self.assertEqual(headers[profile.signature_header], sig)
        connect = sign_request(key, "m1", profile, identity, self.CONNECT, timestamp=1767225600,
                               nonce="n0nce-0123456789abcdef")
        self.assertEqual(connect[profile.signature_header], connect_sig)

    def test_default_profile_vector(self):
        self.check(DEFAULT, {"runId": "run-7f3a"}, "VctavRCQzvBuA82WYFCITmZjDIk3NEBhmM_QFHVuil8", "v1.m1.wGm2lf9OXuKRKHoI4JWDNqlPVbsJNwXNRDp0dLHZUsM", "v1.m1.1CSd-kY_kUpAVP6i2sUM12LA4ATTzRaNUfwTbdFVoFI")

    def test_two_attribute_vector(self):
        self.check(TWO, TWO_ID, "OKDytoJZEYeGfQoLrz6RGJsV4Uu6xTVnHIKiGVHW-fs", "v1.m1.vTX77V54GpPnV6msWMAgkOP_YCV5gXwbaraTUFk71dc", "v1.m1.vtEk5xOOTojpnyktehU4LteOBdFt-H9swGZjmgd49tk")
        self.assertEqual(canonical_string(self.DEST, TWO_ID, "1767225600", "n0nce-0123456789abcdef"),
                         "EGRESS-SIG-V1\nPOST\nhttps\napi.anthropic.com\n443\n/v1/messages?beta=true\n"
                         "tenantId=tenant-1\nrunId=run-7f3a\n1767225600\nn0nce-0123456789abcdef")

    def test_run_keys_are_distinct_per_run_and_attribute_name(self):
        keys = {derive_run_key(MASTER, i) for i in [{"runId": "a"}, {"runId": "b"}, {"jobId": "a"},
                                                    {"tenantId": "t", "runId": "a"}, {"runId": "a", "tenantId": "t"}]}
        self.assertEqual(len(keys), 5)


class ProfileTests(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual(DEFAULT.all_headers, ("X-Egress-Run-Id", "X-Egress-Timestamp", "X-Egress-Nonce",
                                               "X-Egress-Signature"))
        self.assertEqual(DEFAULT.principal, "runId")
        self.assertEqual(SigningProfile.from_env({}), DEFAULT)

    def test_custom(self):
        profile = SigningProfile.from_env({"EGRESS_SIGNED_IDENTITY": "jobId=X-Acme-Job,runnerId=X-Acme-Runner",
                                           "EGRESS_SIGNED_PRINCIPAL": "runnerId", "EGRESS_SIGNED_HEADER_PREFIX": "X-Acme-"})
        self.assertEqual(profile.principal, "runnerId")
        self.assertEqual(profile.signature_header, "X-Acme-Signature")

    def test_invalid(self):
        for args in [("runId",), ("run id=X-A",), ("runId=X A",), ("a=X-A,a=X-B",), ("a=X-A,b=x-a",),
                     ("a=Authorization",), ("a=Host",), ("a=X-A", "b"), ("a=X-A", None, "X A"),
                     (",".join(f"a{i}=X-H{i}" for i in range(9)),), ("a=X-Egress-Nonce",)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                SigningProfile.parse(*args)

    def test_identity_encoding(self):
        self.assertEqual(encode_identity(TWO_ID), "tenantId=tenant-1,runId=run-7f3a")
        self.assertEqual(decode_identity("tenantId=tenant-1,runId=run-7f3a"), TWO_ID)
        for bad in ["", "-", "a", "a=", "a=b,a=c", "a=b c", "1a=b", "a=b,,c=d"]:
            with self.subTest(bad=bad):
                self.assertIsNone(decode_identity(bad))


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.run_key = derive_run_key(MASTER, TWO_ID)
        self.dest = Destination.build("POST", "https", "API.Anthropic.com.", "443", "/v1/messages")

    def headers(self, **kwargs):
        return sign_request(self.run_key, "m1", TWO, TWO_ID, self.dest, **kwargs)

    def reason(self, headers, dest=None, now=None):
        try:
            verify_request(headers, dest or self.dest, KEYS, TWO, now=now)
            return "ok"
        except SignatureError as error:
            return error.reason

    def test_valid(self):
        verified = verify_request(self.headers(), self.dest, KEYS, TWO)
        self.assertEqual(dict(verified.identity), TWO_ID)
        self.assertEqual(verified.principal, "run-7f3a")

    def test_destination_binding(self):
        headers = self.headers()
        for other in [("GET", "https", "api.anthropic.com", 443, "/v1/messages"),
                      ("POST", "http", "api.anthropic.com", 443, "/v1/messages"),
                      ("POST", "https", "api.openai.com", 443, "/v1/messages"),
                      ("POST", "https", "api.anthropic.com", 8443, "/v1/messages"),
                      ("POST", "https", "api.anthropic.com", 443, "/v1/messages/"),
                      ("POST", "https", "api.anthropic.com", 443, "/v1/messages?x=1"),
                      ("POST", "https", "api.anthropic.com", 443, "/v1/%6Dessages")]:
            with self.subTest(other=other):
                self.assertEqual(self.reason(headers, Destination.build(*other)), "bad_signature")

    def test_profile_mismatch(self):
        # Headers from a default-profile signer are missing under the two-attribute profile.
        default_headers = sign_request(derive_run_key(MASTER, {"runId": "run-7f3a"}), "m1", DEFAULT,
                                       {"runId": "run-7f3a"}, self.dest)
        self.assertEqual(self.reason(default_headers), "missing_header")

    def test_rejections(self):
        good = self.headers()
        cases = {
            "missing_header": {k: v for k, v in good.items() if k != "X-Egress-Timestamp"},
            "missing_header ": {**good, "X-Egress-Nonce": "-"},
            "invalid_identity": {**good, "X-Egress-Run-Id": "run-7f3a,%20run-evil"},
            "invalid_identity ": {**good, "X-Egress-Tenant-Id": "tenant 1"},
            "malformed_header": {**good, "X-Egress-Nonce": "short"},
            "malformed_header ": {**good, "X-Egress-Timestamp": "17e9"},
            "malformed_signature": {**good, "X-Egress-Signature": good["X-Egress-Signature"] + "x"},
            "malformed_signature ": {**good, "X-Egress-Signature": "v1.m1"},
            "unknown_key": sign_request(self.run_key, "m2", TWO, TWO_ID, self.dest),
            "stale_timestamp": self.headers(timestamp=int(time.time()) - 31),
            "stale_timestamp ": self.headers(timestamp=int(time.time()) + 31),
            "bad_signature": {**good, "X-Egress-Tenant-Id": "tenant-2"},
            "bad_signature ": sign_request(derive_run_key(MASTER, {"tenantId": "x", "runId": "run-7f3a"}), "m1", TWO,
                                           TWO_ID, self.dest),
            "bad_signature  ": sign_request(derive_run_key(b"\xff" * 32, TWO_ID), "m1", TWO, TWO_ID, self.dest),
        }
        for expected, headers in cases.items():
            with self.subTest(expected=expected.strip()):
                self.assertEqual(self.reason(headers), expected.strip())

    def test_destination_validation(self):
        for args in [("get", "https", "a.example", 443, "/"), ("GET", "ftp", "a.example", 21, "/"),
                     ("GET", "https", "0x7f000001", 443, "/"), ("GET", "https", "a.example", 0, "/"),
                     ("GET", "https", "a.example", 443, "no-slash"), ("GET", "https", "a.example", 443, "/a b"),
                     ("CONNECT", "https", "a.example", 443, ""), ("CONNECT", "", "a.example", 443, "/x")]:
            with self.subTest(args=args), self.assertRaises(SignatureError):
                Destination.build(*args)
        self.assertEqual(Destination.build("CONNECT", "-", "[2001:DB8::1]", "443", "-").host, "2001:db8::1")


if __name__ == "__main__":
    unittest.main()
