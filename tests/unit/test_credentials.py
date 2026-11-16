import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from clearideas_egress import ACLRequest, PolicyError
from clearideas_egress.audit import AuditLog
from clearideas_egress.credentials import CredentialInjector, load_rules


def write(directory: Path, rules) -> Path:
    path = directory / "credentials.json"
    path.write_text(json.dumps({"version": 1, "rules": rules}) if not isinstance(rules, str) else rules)
    return path


class RuleValidationTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.secret = self.dir / "s"
        self.secret.write_text("sk-test-1234567890")

    def rule(self, **overrides):
        base = {"id": "anthropic", "origin": "https://api.anthropic.com", "header": "x-api-key",
                "value": "{secret}", "secretFile": str(self.secret)}
        base.update(overrides)
        return {k: v for k, v in base.items() if v is not None}

    def test_valid(self):
        rules = load_rules(write(self.dir, [self.rule(stripHeaders=["Authorization", "x-api-key"],
                                                      rejectQueryParams=["Key"])]))
        self.assertEqual(rules[0].strip_headers, ("authorization",))  # injected header not duplicated
        self.assertEqual(rules[0].reject_query_params, ("key",))
        self.assertEqual(rules[0].origin, ("https", "api.anthropic.com", 443))

    def test_invalid(self):
        for overrides in [
            {"origin": "http://api.anthropic.com"},          # never inject over clear text
            {"header": "Host"}, {"header": "Proxy-Authorization"}, {"header": "bad header"},
            {"value": "Bearer"}, {"value": "{secret}{secret}"}, {"value": 'Bearer "{secret}"'},
            {"value": "%{secret}"}, {"value": "{secret}\\"},
            {"secretFile": "relative"}, {"id": "Bad Id"}, {"stripHeaders": ["content-length"]},
            {"rejectQueryParams": ["a b"]}, {"extra": 1},
        ]:
            with self.subTest(overrides=overrides), self.assertRaises(PolicyError):
                load_rules(write(self.dir, [self.rule(**overrides)]))
        with self.assertRaises(PolicyError):
            load_rules(write(self.dir, [self.rule(), self.rule(id="other")]))  # duplicate origin
        with self.assertRaises(PolicyError):
            load_rules(write(self.dir, '{"version":1,"rules":[],"rules":[]}'))


class InjectorTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.secret = self.dir / "s"
        self.secret.write_text("sk-test+/abc==\n")
        rules = load_rules(write(self.dir, [{"id": "g", "origin": "https://generativelanguage.googleapis.com",
                                             "header": "x-goog-api-key", "secretFile": str(self.secret),
                                             "rejectQueryParams": ["key"]}]))
        self.injector = CredentialInjector(rules, refresh_seconds=0)

    def req(self, method="POST", scheme="https", path="/v1/models", port=443, host="generativelanguage.googleapis.com"):
        return ACLRequest("p", "10.0.0.1", method, host, port, scheme=None if method == "CONNECT" else scheme,
                          path=None if method == "CONNECT" else path)

    def test_apply(self):
        self.assertEqual(self.injector.apply(self.req()),
                         (None, {"egress_cred_": "g", "egress_secret_": "sk-test+/abc=="}, "g"))
        self.assertEqual(self.injector.apply(self.req(host="api.example.com")), (None, {}, None))
        self.assertEqual(self.injector.apply(self.req(method="CONNECT"))[0], "credential_requires_origination")
        self.assertEqual(self.injector.apply(self.req(scheme="http"))[0], "credential_requires_origination")
        self.assertEqual(self.injector.apply(self.req(path="/v1/models?alt=json&Key=x"))[0], "credential_query_param")
        self.assertEqual(self.injector.apply(self.req(path="/v1/models?k%65y=x"))[0], "credential_query_param")
        self.assertIsNone(self.injector.apply(self.req(path="/v1/models?keys=x"))[0])

    def test_rotation_and_fail_closed(self):
        self.secret.write_text("sk-rotated-000001")
        time.sleep(0.01)
        os.utime(self.secret)
        self.assertEqual(self.injector.apply(self.req())[1]["egress_secret_"], "sk-rotated-000001")
        self.secret.write_text("bad secret with spaces")
        os.utime(self.secret, (time.time() + 5, time.time() + 5))
        self.assertEqual(self.injector.apply(self.req())[0], "credential_unavailable")
        self.secret.unlink()
        self.assertEqual(self.injector.apply(self.req())[0], "credential_unavailable")

    def test_request_handler_never_logs_secret(self):
        from clearideas_egress.cli import RequestHandler
        audit_path = self.dir / "audit.jsonl"
        audit = AuditLog.from_setting(str(audit_path))
        self.addCleanup(audit.close)
        handler = RequestHandler(audit, credentials=self.injector)
        fields = ["p", "POST", "https", "generativelanguage.googleapis.com", "443", "/v1/models", "-", "-"]
        self.assertEqual(handler(fields), "OK log=credential_injected egress_cred_=g egress_secret_=sk-test+/abc==")
        self.assertEqual(handler(["p", "POST", "https", "generativelanguage.googleapis.com", "443", "/v1/m?key=x", "-", "-"]),
                         "ERR log=credential_query_param")
        self.assertEqual(handler(["p", "CONNECT", "-", "generativelanguage.googleapis.com", "443", "-", "-", "-"]),
                         "ERR log=credential_requires_origination")
        self.assertEqual(handler(["p", "GET", "https", "other.example", "443", "/", "-", "-"]), "OK log=request_ok")
        self.assertNotIn("sk-test", audit_path.read_text())
        self.assertIn('"credential":"g"', audit_path.read_text())

if __name__ == "__main__":
    unittest.main()
