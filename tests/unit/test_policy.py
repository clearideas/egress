import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from clearideas_egress import ACLRequest, Decision, PolicyError, authorize, compile_file_policy, decide, normalize_host, parse_acl_line
from clearideas_egress.policy import decode_field, load_policy_document

SRC = str(Path(__file__).resolve().parents[2] / "src")


class FilePolicyV1Tests(unittest.TestCase):
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
            {"version": 3, "principals": {}},
            {"version": 1, "principals": {"alice": ["https://example.com/path"]}},
            {"version": 1, "principals": {"alice": ["https://user@example.com"]}},
            {"version": 1, "principals": {"alice": ["https://*.example.com"]}},
            {"version": 1, "principals": {"alice": ["https://example.com?x=1"]}},
            {"version": 1, "principals": {"alice": ["ftp://example.com"]}},
            {"version": 1, "principals": {"alice": ["https://example.com:0"]}},
            {"version": 1, "principals": {"alice": ["https://example.com:"]}},
            {"version": 1, "principals": {"alice": "https://example.com"}},
            {"version": 1, "principals": {"al ice": []}},
            {"version": 1, "principals": {"al%ice": []}},
            {"version": 1, "principals": {}, "extra": 1},
        ]
        for document in invalid:
            with self.subTest(document=document), self.assertRaises(PolicyError):
                compile_file_policy(document)

    def test_identical_duplicates_merge_conflicts_fail(self):
        policy = compile_file_policy({"version": 1, "principals": {"a": ["https://Example.com", "https://example.com"]}})
        self.assertEqual(len(policy.principals["a"].origins), 1)
        with self.assertRaises(PolicyError):
            compile_file_policy({"version": 2, "principals": {"a": {"origins": [
                {"origin": "http://example.com", "methods": ["GET"]}, "http://example.com"]}}})


class FilePolicyV2Tests(unittest.TestCase):
    POLICY = {"version": 2, "principals": {
        "sbx": {"sources": ["10.0.0.0/24", "2001:db8::/64"], "origins": [
            "https://pypi.org",
            {"origin": "http://archive.ubuntu.com", "methods": ["GET", "HEAD"]},
            {"origin": "https://ssh.github.com", "allowNonTls": True},
        ]},
        "any-source": {"origins": ["https://example.com"]},
    }}

    def setUp(self):
        self.policy = compile_file_policy(self.POLICY)

    def test_sources(self):
        self.assertEqual(decide(ACLRequest("sbx", "10.0.0.7", "CONNECT", "pypi.org", 443), self.policy).reason, "allowed")
        self.assertEqual(decide(ACLRequest("sbx", "10.0.1.7", "CONNECT", "pypi.org", 443), self.policy).reason,
                         "source_not_allowed")
        self.assertTrue(decide(ACLRequest("sbx", "::ffff:10.0.0.7", "CONNECT", "pypi.org", 443), self.policy).allowed)
        self.assertTrue(decide(ACLRequest("sbx", "2001:db8::5", "CONNECT", "pypi.org", 443), self.policy).allowed)
        self.assertTrue(decide(ACLRequest("any-source", "203.0.113.9", "CONNECT", "example.com", 443), self.policy).allowed)

    def test_methods(self):
        self.assertTrue(decide(ACLRequest("sbx", "10.0.0.7", "GET", "archive.ubuntu.com", 80), self.policy).allowed)
        self.assertEqual(decide(ACLRequest("sbx", "10.0.0.7", "POST", "archive.ubuntu.com", 80), self.policy).reason,
                         "method_not_allowed")

    def test_methods_on_https_origins(self):
        # Proxy-originated TLS exposes the method; a CONNECT tunnel cannot be method-checked.
        policy = compile_file_policy({"version": 2, "principals": {"sbx": {"origins": [
            {"origin": "https://api.example.com", "methods": ["POST"]}]}}})
        post = ACLRequest("sbx", "10.0.0.7", "POST", "api.example.com", 443, scheme="https", path="/v1/x")
        self.assertTrue(decide(post, policy).allowed)
        get = ACLRequest("sbx", "10.0.0.7", "GET", "api.example.com", 443, scheme="https", path="/v1/x")
        self.assertEqual(decide(get, policy).reason, "method_not_allowed")
        tunnel = ACLRequest("sbx", "10.0.0.7", "CONNECT", "api.example.com", 443)
        self.assertEqual(decide(tunnel, policy).reason, "method_not_allowed")
        # Without an explicit scheme a non-CONNECT request is plain HTTP and does not match https://.
        legacy = ACLRequest("sbx", "10.0.0.7", "POST", "api.example.com", 443)
        self.assertEqual(decide(legacy, policy).reason, "origin_not_allowed")

    def test_allow_non_tls_annotation(self):
        decision = decide(ACLRequest("sbx", "10.0.0.7", "CONNECT", "ssh.github.com", 443), self.policy)
        self.assertEqual(decision.annotations, {"egress_tls_": "optional"})
        self.assertEqual(decide(ACLRequest("sbx", "10.0.0.7", "CONNECT", "pypi.org", 443), self.policy).annotations, {})

    def test_reasons(self):
        self.assertEqual(decide(ACLRequest("nobody", "10.0.0.7", "CONNECT", "pypi.org", 443), self.policy).reason,
                         "unknown_principal")
        self.assertEqual(decide(ACLRequest("sbx", "10.0.0.7", "CONNECT", "evil.example", 443), self.policy).reason,
                         "origin_not_allowed")

    def test_v2_validation(self):
        for bad in [
            {"version": 2, "principals": {"a": ["https://example.com"]}},
            {"version": 2, "principals": {"a": {"origins": [{"origin": "http://x.example", "allowNonTls": True}]}}},
            {"version": 2, "principals": {"a": {"origins": [{"origin": "http://x.example", "methods": ["get"]}]}}},
            {"version": 2, "principals": {"a": {"origins": [{"origin": "http://x.example", "methods": ["CONNECT"]}]}}},
            {"version": 2, "principals": {"a": {"origins": [{"origin": "http://x.example", "methods": []}]}}},
            {"version": 2, "principals": {"a": {"origins": [{"origin": "http://x.example", "extra": 1}]}}},
            {"version": 2, "principals": {"a": {"sources": ["10.0.0.1/24"], "origins": []}}},
            {"version": 2, "principals": {"a": {"sources": [], "origins": []}}},
            {"version": 2, "principals": {"a": {"origins": [{"origin": "https://x.example", "allowNonTls": "yes"}]}}},
        ]:
            with self.subTest(bad=bad), self.assertRaises(PolicyError):
                compile_file_policy(bad)


class HostNormalizationTests(unittest.TestCase):
    def test_canonical_forms(self):
        self.assertEqual(normalize_host("EXAMPLE.COM."), "example.com")
        self.assertEqual(normalize_host("[2001:db8::1]"), "2001:db8::1")
        self.assertEqual(normalize_host("2001:DB8::1"), "2001:db8::1")
        self.assertEqual(normalize_host("bücher.example"), "xn--bcher-kva.example")
        self.assertEqual(normalize_host("xn--bcher-kva.example"), "xn--bcher-kva.example")
        for value in ["1password.com", "123.example.com", "a.b.c.example", "x1.example"]:
            self.assertEqual(normalize_host(value), value)

    def test_rejects_ambiguous(self):
        for value in ["example.com/path", "user@example.com", "fe80::1%eth0", "-", "[example.com]", "[192.0.2.1]",
                      "exa mple.com", "example..com", "-example.com", "example.com\x00", "%65xample.com",
                      "xn--zz.example", "a" * 64 + ".example"]:
            with self.subTest(value=value):
                self.assertIsNone(normalize_host(value))

    def test_numeric_hosts_rejected(self):  # review M-2
        for value in ["2130706433", "0x7f000001", "0x7f.1", "127.1", "0177.0.0.1", "1.2.3", "169.254.43518",
                      "0xa9fea9fe", "example.0x1", "example.123", "0x"]:
            with self.subTest(value=value):
                self.assertIsNone(normalize_host(value))

    def test_policy_hosts_must_be_ascii(self):  # review L-1
        for origin in ["https://faß.de", "https://bücher.example", "https://a\u200db.example", "https://ＥＸＡＭＰＬＥ.com"]:
            with self.subTest(origin=origin), self.assertRaises(PolicyError):
                compile_file_policy({"version": 1, "principals": {"a": [origin]}})
        compile_file_policy({"version": 1, "principals": {"a": ["https://xn--bcher-kva.example"]}})


class ACLLineTests(unittest.TestCase):
    def test_invalid_lines(self):
        for line in [
            "- 192.0.2.10 CONNECT example.com 443",
            "alice invalid-ip CONNECT example.com 443",
            "alice 192.0.2.10 connect example.com 443",
            "alice 192.0.2.10 CONNECT example.com 0",
            "alice 192.0.2.10 CONNECT example.com 65536",
            "alice 192.0.2.10 CONNECT example.com 443 extra",
            "alice 192.0.2.10 CONNECT example.com \u0664\u0664\u0663",  # Arabic-Indic digits (review L-5)
            "alice 192.0.2.10 CONNECT example.com +443",
            "alice  192.0.2.10 CONNECT example.com 443",
            "alice 192.0.2.10 CONNECT %252Fexample.com 443",  # double encoding
            "ali%0Ace 192.0.2.10 CONNECT example.com 443",
        ]:
            with self.subTest(line=line):
                self.assertIsNone(parse_acl_line(line))
        self.assertIsNotNone(parse_acl_line("alice 192.0.2.10 CONNECT example.com 443 -"))

    def test_squid_url_quoting_decoded_once(self):  # review L-9
        request = parse_acl_line("alice 2001:db8::2 CONNECT %5B2001:db8::1%5D 443 -")
        self.assertEqual(request.host, "2001:db8::1")
        self.assertEqual(parse_acl_line("alice 2001:db8::2 CONNECT [2001:db8::1] 443").host, "2001:db8::1")
        self.assertEqual(parse_acl_line("a%40corp 192.0.2.1 GET example.com 80").principal, "a@corp")

    def test_decode_field(self):
        self.assertEqual(decode_field("abc"), "abc")
        self.assertEqual(decode_field("%5Bx%5D"), "[x]")
        for bad in ["%", "%zz", "%2", "%25", "%00", "%0A", "a b", "%C3%28"]:
            with self.subTest(bad=bad):
                self.assertIsNone(decode_field(bad))


class DecideTests(unittest.TestCase):
    def test_backend_errors_and_non_boolean_values_fail_closed(self):
        request = ACLRequest("alice", "192.0.2.10", "CONNECT", "example.com", 443)
        self.assertFalse(authorize(request, lambda _: "true"))
        self.assertFalse(authorize(request, lambda _: 1))
        self.assertFalse(authorize(request, lambda _: (_ for _ in ()).throw(TimeoutError())))
        self.assertFalse(authorize(None, lambda _: True))
        self.assertTrue(authorize(request, lambda _: True))
        self.assertEqual(decide(request, lambda _: (_ for _ in ()).throw(OSError())).reason, "backend_error")
        self.assertFalse(decide(request, lambda _: Decision("yes", "x")).allowed)

    def test_request_revalidated(self):
        for request in [ACLRequest("alice", "bad", "CONNECT", "example.com", 443),
                        ACLRequest("alice", "192.0.2.1", "CONNECT", "EXAMPLE.com", 443),
                        ACLRequest("alice", "192.0.2.1", "CONNECT", "example.com", 0),
                        ACLRequest("", "192.0.2.1", "CONNECT", "example.com", 443)]:
            with self.subTest(request=request):
                self.assertEqual(decide(request, lambda _: True).reason, "invalid_request")

    def test_duplicate_json_keys_rejected(self):  # review L-2
        with self.assertRaises(PolicyError):
            load_policy_document('{"version":1,"principals":{"a":["https://safe.example"],"a":["https://evil.example"]}}')


class CLITests(unittest.TestCase):
    def _run(self, stdin: str, env: dict, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-m", "clearideas_egress", *args], input=stdin, text=True,
                              capture_output=True, env={**os.environ, "PYTHONPATH": SRC, "EGRESS_AUDIT_LOG": "off",
                                                        **env}, check=False)

    def test_cli_emits_one_decision_per_line(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_file = Path(directory) / "policy.json"
            policy_file.write_text(json.dumps({"version": 1, "principals": {"alice": ["https://example.com"]}}))
            result = self._run("alice 192.0.2.10 CONNECT example.com 443\nbob 192.0.2.10 CONNECT example.com 443\n"
                               "bad line\n", {"EGRESS_POLICY_FILE": str(policy_file), "EGRESS_POLICY_URL": ""})
            self.assertEqual(result.returncode, 0, result.stderr)
            stdout = re.sub(r" egress_decision_=[0-9a-f]+", "", result.stdout)
            self.assertEqual(stdout, "OK log=allowed\nERR log=unknown_principal\nERR log=invalid_request\n")
            self.assertEqual(len(re.findall(r"egress_decision_=[0-9a-f]{32}", result.stdout)), 3)

    def test_cli_bad_configuration_denies_without_exiting(self):
        # Squid aborts when helpers keep failing to start, so a broken configuration must deny
        # every request and keep running rather than exit (the renderer validates before start).
        for env in ({"EGRESS_POLICY_FILE": "", "EGRESS_POLICY_URL": ""},
                    {"EGRESS_POLICY_FILE": "/nonexistent/policy.json", "EGRESS_POLICY_URL": ""}):
            result = self._run("alice 192.0.2.10 CONNECT example.com 443\n3 x\n", env)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "ERR log=helper_misconfigured egress_retry_=503\n" * 2)
            self.assertIn("denying all requests", result.stderr)

    def test_check_policy_command(self):
        with tempfile.TemporaryDirectory() as directory:
            good, bad = Path(directory) / "good.json", Path(directory) / "bad.json"
            good.write_text(json.dumps({"version": 1, "principals": {"a": ["https://example.com"]}}))
            bad.write_text('{"version":1,"principals":{"a":[],"a":[]}}')
            self.assertEqual(self._run("", {}, "check-policy", str(good)).returncode, 0)
            result = self._run("", {}, "check-policy", str(bad))
            self.assertEqual(result.returncode, 1)
            self.assertIn("duplicate", result.stderr)


if __name__ == "__main__":
    unittest.main()
