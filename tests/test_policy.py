import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from clearideas_egress import (
    ACLRequest,
    HTTPPolicy,
    PolicyError,
    authorize,
    compile_file_policy,
    normalize_host,
    parse_acl_line,
)


class PolicyTests(unittest.TestCase):
    def test_file_policy_matches_principal_scheme_host_and_port(self):
        backend = compile_file_policy({
            "version": 1,
            "principals": {"alice": ["https://Example.COM", "http://example.net:8080"]},
        })
        self.assertTrue(authorize(parse_acl_line("alice 192.0.2.10 CONNECT example.com 443"), backend))
        self.assertTrue(authorize(parse_acl_line("alice 192.0.2.10 GET example.net 8080"), backend))
        for line in [
            "bob 192.0.2.10 CONNECT example.com 443",
            "alice 192.0.2.10 GET example.com 443",
            "alice 192.0.2.10 CONNECT example.net 8080",
            "alice 192.0.2.10 CONNECT example.com 8443",
            "alice 192.0.2.10 CONNECT sub.example.com 443",
        ]:
            with self.subTest(line=line):
                self.assertFalse(authorize(parse_acl_line(line), backend))

    def test_invalid_policy_rejected_instead_of_partially_loaded(self):
        invalid = [
            {"version": True, "principals": {}},
            {"version": 1, "principals": {"alice": ["https://example.com/path"]}},
            {"version": 1, "principals": {"alice": ["https://user@example.com"]}},
            {"version": 1, "principals": {"alice": ["https://*.example.com"]}},
            {"version": 1, "principals": {"alice": ["https://example.com?x=1"]}},
            {"version": 1, "principals": {"alice": ["ftp://example.com"]}},
            {"version": 1, "principals": {"alice": ["https://example.com:0"]}},
            {"version": 1, "principals": {"alice": ["https://example.com:"]}},
            {"version": 1, "principals": {"alice": "https://example.com"}},
        ]
        for document in invalid:
            with self.subTest(document=document), self.assertRaises(PolicyError):
                compile_file_policy(document)

    def test_host_normalization_and_invalid_acl_lines(self):
        self.assertEqual(normalize_host("EXAMPLE.COM."), "example.com")
        self.assertEqual(normalize_host("[2001:db8::1]"), "2001:db8::1")
        self.assertEqual(normalize_host("bücher.example"), "xn--bcher-kva.example")
        for value in ["example.com/path", "user@example.com", "fe80::1%eth0", "-", "[example.com]"]:
            with self.subTest(value=value):
                self.assertIsNone(normalize_host(value))
        for line in [
            "- 192.0.2.10 CONNECT example.com 443",
            "alice invalid-ip CONNECT example.com 443",
            "alice 192.0.2.10 connect example.com 443",
            "alice 192.0.2.10 CONNECT example.com 0",
            "alice 192.0.2.10 CONNECT example.com 65536",
            "alice 192.0.2.10 CONNECT example.com 443 extra",
        ]:
            with self.subTest(line=line):
                self.assertIsNone(parse_acl_line(line))
        self.assertIsNotNone(parse_acl_line("alice 192.0.2.10 CONNECT example.com 443 -"))

    def test_ipv6_and_idn_exact_match(self):
        backend = compile_file_policy({
            "version": 1,
            "principals": {"alice": ["https://[2001:db8::1]", "https://bücher.example"]},
        })
        self.assertTrue(authorize(parse_acl_line("alice 2001:db8::2 CONNECT [2001:db8::1] 443"), backend))
        self.assertTrue(authorize(parse_acl_line("alice 192.0.2.10 CONNECT xn--bcher-kva.example 443"), backend))

    def test_backend_errors_and_non_boolean_values_fail_closed(self):
        request = ACLRequest("alice", "192.0.2.10", "CONNECT", "example.com", 443)
        self.assertFalse(authorize(request, lambda _: "true"))
        self.assertFalse(authorize(request, lambda _: 1))
        self.assertFalse(authorize(request, lambda _: (_ for _ in ()).throw(TimeoutError())))
        self.assertFalse(authorize(None, lambda _: True))

    def test_http_policy_rejects_unprotected_remote_endpoint(self):
        for url, token in [
            ("http://policy.example/authorize", "secret"),
            ("http://localhost/authorize", None),
            ("https://policy.example/authorize", None),
        ]:
            with self.subTest(url=url), self.assertRaises(PolicyError):
                HTTPPolicy(url, token=token)

    def test_http_policy_sends_identity_and_accepts_only_explicit_allow(self):
        class Response:
            status = 200

            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def read(self, _):
                return self.body

        class Opener:
            def __init__(self, body):
                self.body = body
                self.requests = []

            def open(self, outgoing, timeout):
                self.requests.append((outgoing, timeout))
                return Response(self.body)

        request = ACLRequest("alice", "192.0.2.10", "CONNECT", "example.com", 443)
        opener = Opener(b'{"decision":"allow"}')
        backend = HTTPPolicy("https://policy.example/authorize", token="secret", opener=opener)
        self.assertTrue(authorize(request, backend))
        outgoing, timeout = opener.requests[0]
        self.assertEqual(outgoing.get_method(), "POST")
        self.assertEqual(outgoing.get_header("Authorization"), "Bearer secret")
        self.assertEqual(json.loads(outgoing.data)["principal"], "alice")
        self.assertEqual(timeout, 2.0)
        for body in [b'{"decision":true}', b'{"decision":"deny"}', b'{}', b'invalid-json']:
            with self.subTest(body=body):
                self.assertFalse(authorize(request, HTTPPolicy("https://policy.example", token="secret", opener=Opener(body))))

    def test_cli_emits_one_decision_per_line(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_file = Path(directory) / "policy.json"
            policy_file.write_text(json.dumps({"version": 1, "principals": {"alice": ["https://example.com"]}}))
            result = subprocess.run(
                [sys.executable, "-m", "clearideas_egress"],
                input="alice 192.0.2.10 CONNECT example.com 443\nbob 192.0.2.10 CONNECT example.com 443\nbad line\n",
                text=True,
                capture_output=True,
                env={**os.environ, "EGRESS_POLICY_FILE": str(policy_file), "EGRESS_POLICY_URL": ""},
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "OK\nERR\nERR\n")

    def test_cli_rejects_bad_configuration_at_startup(self):
        result = subprocess.run(
            [sys.executable, "-m", "clearideas_egress"],
            input="alice 192.0.2.10 CONNECT example.com 443\n",
            text=True,
            capture_output=True,
            env={**os.environ, "EGRESS_POLICY_FILE": "", "EGRESS_POLICY_URL": ""},
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
