import io
import json
import re
import os
import random
import tempfile
import threading
import time
import unittest
from pathlib import Path

from clearideas_egress.audit import AuditLog
from clearideas_egress.cli import AclHandler, SniHandler, serve
from clearideas_egress.limits import PrincipalConcurrency, TokenBucketLimiter
from clearideas_egress.policy import Decision, compile_file_policy

POLICY = compile_file_policy({"version": 2, "principals": {"alice": {"origins": [
    "https://example.com", {"origin": "https://ssh.github.com", "allowNonTls": True}]}}})


def run(handler, lines: bytes, concurrent: bool = False, workers: int = 4) -> list[str]:
    out = io.StringIO()
    serve(handler, concurrent_mode=concurrent, workers=workers, stdin=io.BytesIO(lines), stdout=out)
    return [clean(line) for line in out.getvalue().splitlines()]


def clean(answer: str) -> str:
    return re.sub(r" egress_decision_=[0-9a-f]+", "", answer)


class AclProtocolTests(unittest.TestCase):
    def setUp(self):
        self.audit_path = Path(tempfile.mkdtemp()) / "audit.jsonl"
        audit = AuditLog.from_setting(str(self.audit_path))
        self.addCleanup(audit.close)
        self.handler = AclHandler(POLICY, "file", audit, PrincipalConcurrency(4), None)

    def test_sequential(self):
        out = run(self.handler, b"alice 10.0.0.1 CONNECT example.com 443 -\n"
                                b"alice 10.0.0.1 CONNECT evil.example 443 -\n"
                                b"alice 10.0.0.1 CONNECT ssh.github.com 443 -\n")
        self.assertEqual(out, ["OK log=allowed", "ERR log=origin_not_allowed",
                               "OK log=allowed egress_tls_=optional"])
        audit = [json.loads(line) for line in self.audit_path.read_text().splitlines()]
        self.assertEqual([a["reason"] for a in audit], ["allowed", "origin_not_allowed", "allowed"])
        self.assertEqual(audit[0]["principal"], "alice")

    def test_concurrent_channel_ids(self):
        out = run(self.handler, b"7 alice 10.0.0.1 CONNECT example.com 443 -\n"
                                b"3 alice 10.0.0.1 CONNECT evil.example 443 -\n", concurrent=True)
        self.assertEqual(sorted(out), ["3 ERR log=origin_not_allowed", "7 OK log=allowed"])

    def test_out_of_order_responses(self):
        gate = threading.Event()

        def slow_first(fields):
            if fields[0] == "slow":
                gate.wait(2)
                return "OK log=allowed"
            gate.set()
            return "ERR log=fast"

        out = run(slow_first, b"1 slow\n2 fast\n", concurrent=True)
        self.assertEqual(out, ["2 ERR log=fast", "1 OK log=allowed"])

    def test_fuzz_never_crashes_one_reply_per_line(self):  # review L-5
        rng = random.Random(1234)
        lines = []
        for _ in range(10000):
            length = rng.randint(0, 80)
            raw = bytes(rng.choice(range(256)) for _ in range(length)).replace(b"\n", b"")
            lines.append(raw)
        out = run(self.handler, b"\n".join(lines) + b"\n")
        self.assertEqual(len(out), 10000)
        self.assertTrue(all(line.startswith(("ERR", "BH")) for line in out))

    def test_handler_exception_is_bh(self):
        def boom(fields):
            raise RuntimeError("bug")

        self.assertEqual(run(boom, b"x\n"), ["BH log=helper_error"])  # never cached by Squid
        self.assertEqual(run(boom, b"5 x\n", concurrent=True), ["5 BH log=helper_error"])

    def test_non_ascii_and_oversized_lines(self):
        out = run(self.handler, "alice 10.0.0.1 CONNECT exämple.com 443\n".encode() + b"a" * 20000 + b"\n")
        self.assertEqual(out, ["BH log=invalid_line", "BH log=invalid_line"])

    def test_principal_concurrency_cap(self):
        release = threading.Event()

        class Slow:
            def decide(self, request):
                release.wait(3)
                return Decision.allow()

        handler = AclHandler(Slow(), "test", AuditLog(None), PrincipalConcurrency(2), None, budget_seconds=0.3)
        results = []
        threads = [threading.Thread(target=lambda: results.append(clean(handler(
            ["alice", "10.0.0.1", "CONNECT", "example.com", "443"])))) for _ in range(2)]
        for thread in threads:
            thread.start()
        time.sleep(0.1)
        # A third request from the same principal waits for a slot, up to the decision budget.
        started = time.monotonic()
        self.assertEqual(clean(handler(["alice", "10.0.0.1", "CONNECT", "example.com", "443"])),
                         "ERR log=backend_saturated egress_retry_=503")
        self.assertGreaterEqual(time.monotonic() - started, 0.25)
        # Another principal is not blocked by alice's burst.
        other = []
        t = threading.Thread(target=lambda: other.append(clean(handler(["bob", "10.0.0.2", "CONNECT", "example.com", "443"]))))
        t.start()
        time.sleep(0.1)
        release.set()
        for thread in threads + [t]:
            thread.join()
        self.assertEqual(other, ["OK log=allowed"])

    def test_burst_waits_instead_of_failing(self):
        gate = threading.Semaphore(0)

        class Quick:
            def decide(self, request):
                time.sleep(0.05)
                return Decision.allow()

        handler = AclHandler(Quick(), "test", AuditLog(None), PrincipalConcurrency(2), None, budget_seconds=5)
        results = []
        threads = [threading.Thread(target=lambda: results.append(clean(handler(
            ["alice", "10.0.0.1", "GET", "example.com", "80"])))) for _ in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(results, ["OK log=allowed"] * 20)

    def test_rate_limit(self):
        handler = AclHandler(POLICY, "file", AuditLog(None), PrincipalConcurrency(4), TokenBucketLimiter(1, 3))
        answers = [clean(handler(["alice", "10.0.0.1", "CONNECT", "example.com", "443"])) for _ in range(5)]
        self.assertEqual(answers.count("OK log=allowed"), 3)
        self.assertEqual(answers.count("ERR log=rate_limited egress_retry_=429"), 2)


class SniTests(unittest.TestCase):
    def check(self, *fields):
        return SniHandler(AuditLog(None)).check(list(fields))[0]

    def test_truth_table(self):
        cases = [
            (("alice", "10.0.0.1", "example.com", "443", "example.com"), True, "sni_match"),
            (("alice", "10.0.0.1", "example.com", "443", "EXAMPLE.com."), True, "sni_match"),
            (("alice", "10.0.0.1", "example.com", "443", "fronted.test"), False, "sni_mismatch"),
            (("alice", "10.0.0.1", "example.com", "443", "sub.example.com"), False, "sni_mismatch"),
            (("alice", "10.0.0.1", "example.com", "443", "-"), False, "sni_missing"),
            (("alice", "10.0.0.1", "192.0.2.5", "443", "-"), True, "sni_absent_ip_literal"),
            (("alice", "10.0.0.1", "%5B2001:db8::1%5D", "443", "-"), True, "sni_absent_ip_literal"),
            (("alice", "10.0.0.1", "192.0.2.5", "443", "example.com"), False, "sni_mismatch"),
            (("alice", "10.0.0.1", "192.0.2.5", "443", "192.0.2.5"), False, "sni_invalid"),
            (("alice", "10.0.0.1", "example.com", "443", "exa%00mple.com"), False, "sni_invalid"),
            (("alice", "10.0.0.1", "example.com", "443", "example.com", "-"), True, "sni_match"),
            (("-", "10.0.0.1", "example.com", "443", "example.com"), False, "invalid_request"),
            (("alice", "10.0.0.1", "example.com", "443"), False, "invalid_request"),
        ]
        for fields, allowed, reason in cases:
            with self.subTest(fields=fields):
                decision = self.check(*fields)
                self.assertEqual((decision.allowed, decision.reason), (allowed, reason))


class LimitTests(unittest.TestCase):
    def test_token_bucket_parse(self):
        self.assertIsNone(TokenBucketLimiter.parse(""))
        self.assertIsNone(TokenBucketLimiter.parse("off"))
        self.assertEqual(TokenBucketLimiter.parse("50/200").burst, 200)
        for bad in ("50", "x/1", "0/1", "1/0"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                TokenBucketLimiter.parse(bad)

    def test_concurrency_slot_release(self):
        limiter = PrincipalConcurrency(1)
        with limiter.slot("a") as first:
            self.assertTrue(first)
            with limiter.slot("a") as second:
                self.assertFalse(second)
        with limiter.slot("a") as third:
            self.assertTrue(third)
        self.assertEqual(limiter._active, {})


if __name__ == "__main__":
    unittest.main()


class SignedHandlerTests(unittest.TestCase):
    PROFILE_ENV = {"EGRESS_SIGNED_IDENTITY": "jobId=X-Acme-Job,runnerId=X-Acme-Runner", "EGRESS_SIGNED_PRINCIPAL": "runnerId",
                   "EGRESS_SIGNED_HEADER_PREFIX": "X-Acme-"}

    def setUp(self):
        import base64, os
        from clearideas_egress.auth import KeyRing
        from clearideas_egress.cli import SignedHandler
        from clearideas_egress.signing import SigningProfile, derive_run_key
        self.master = os.urandom(32)
        directory = Path(tempfile.mkdtemp())
        (directory / "m1.key").write_text(base64.b64encode(self.master).decode())
        self.profile = SigningProfile.from_env(self.PROFILE_ENV)
        self.handler = SignedHandler(KeyRing(directory), AuditLog(None), self.profile)
        self.identity = {"jobId": "job-1", "runnerId": "runner-1"}
        self.run_key = derive_run_key(self.master, self.identity)

    def fields(self, method, scheme, host, port, path, headers=None, tag="-"):
        from clearideas_egress.signing import Destination, sign_request
        if headers is None:
            headers = sign_request(self.run_key, "m1", self.profile, self.identity,
                                   Destination.build(method, scheme, host, port, path))
        return ([method, scheme or "-", host, str(port), path or "-"] +
                [headers.get(h, "-") for h in self.profile.all_headers] + [tag])

    def test_signed_get_returns_identity_annotations(self):
        answer = self.handler(self.fields("GET", "https", "api.example.com", 443, "/v1/x"))
        self.assertEqual(answer, "OK user=runner-1 egress_principal_=runner-1 "
                                 "egress_identity_=jobId=job-1,runnerId=runner-1 log=signature_valid")

    def test_signed_connect_tags_connection(self):
        answer = self.handler(self.fields("CONNECT", "", "api.example.com", 443, ""))
        self.assertTrue(answer.endswith("clt_conn_tag=egress-connect/jobId=job-1,runnerId=runner-1/api.example.com/443"),
                        answer)

    def test_recheck_requires_matching_tag(self):
        tag = "egress-connect/jobId=job-1,runnerId=runner-1/api.example.com/443"
        recheck = ["CONNECT", "authority_form", "api.example.com", "443", "-"] + ["-"] * len(self.profile.all_headers)
        self.assertTrue(self.handler(recheck + [tag]).startswith("OK user=runner-1 egress_principal_=runner-1"))
        for bad_tag in ["-", "egress-connect/jobId=job-1,runnerId=runner-1/other.example/443",
                        "egress-connect/jobId=job-1,runnerId=runner-1/api.example.com/8443",
                        "egress-connect/jobId=job 1,runnerId=runner-1/api.example.com/443",
                        "egress-connect/runId=x/api.example.com/443",            # wrong attribute set
                        "something-else/jobId=job-1,runnerId=runner-1/api.example.com/443", "egress-connect/x"]:
            with self.subTest(tag=bad_tag):
                self.assertEqual(self.handler(recheck + [bad_tag]), "ERR log=connect_recheck_denied")

    def test_recheck_only_for_internal_connect(self):
        tag = "egress-connect/jobId=job-1,runnerId=runner-1/api.example.com/443"
        n = len(self.profile.all_headers)
        client_connect = ["CONNECT", "-", "api.example.com", "443", "-"] + ["-"] * n + [tag]
        self.assertEqual(self.handler(client_connect), "ERR log=missing_header")
        get = ["GET", "https", "api.example.com", "443", "/"] + ["-"] * n + [tag]
        self.assertEqual(self.handler(get), "ERR log=missing_header")

    def test_get_does_not_tag(self):
        self.assertNotIn("clt_conn_tag", self.handler(self.fields("GET", "https", "api.example.com", 443, "/")))


class V2FieldTests(unittest.TestCase):
    def test_origin_scope(self):
        from clearideas_egress.cli import parse_v2_fields
        request = parse_v2_fields(["runner-1", "10.0.0.1", "POST", "https", "api.example.com", "443",
                                   "runner-1", "runId=runner-1"], "signed", "origin")
        self.assertEqual((request.method, request.host, request.path, request.effective_scheme),
                         ("POST", "api.example.com", None, "https"))
        connect = parse_v2_fields(["sbx", "10.0.0.1", "CONNECT", "-", "api.example.com", "443", "-", "-"], "auth", "origin")
        self.assertEqual(connect.method, "CONNECT")
        # A request-scope line (path present, plus Squid's trailing "-") is rejected in origin scope.
        self.assertIsNone(parse_v2_fields(["sbx", "10.0.0.1", "GET", "https", "a.example", "443", "/x", "-", "-", "-"],
                                          "auth", "origin"))

    def test_parse(self):
        from clearideas_egress.cli import parse_v2_fields
        signed = parse_v2_fields(["runner-1", "10.0.0.1", "POST", "https", "api.example.com", "443", "/v1/x?y=1",
                                  "runner-1", "jobId=job-1,runnerId=runner-1"], "signed")
        self.assertEqual((signed.principal, signed.scheme, signed.path, signed.effective_scheme),
                         ("runner-1", "https", "/v1/x?y=1", "https"))
        self.assertEqual(signed.attributes, {"jobId": "job-1", "runnerId": "runner-1"})
        auth = parse_v2_fields(["sbx-1", "10.0.0.1", "CONNECT", "-", "api.example.com", "443", "-",
                                "forged", "runId=forged"], "auth")
        self.assertEqual((auth.principal, auth.attributes, auth.path), ("sbx-1", {}, None))
        self.assertIsNotNone(parse_v2_fields(["sbx-1", "10.0.0.1", "CONNECT", "authority_form", "api.example.com",
                                              "443", "-", "-", "-"], "auth"))
        for bad in [
            ["-", "10.0.0.1", "GET", "https", "a.example", "443", "/", "-", "-"],                   # signed, no notes
            ["x", "10.0.0.1", "GET", "ftp", "a.example", "21", "/", "r", "runId=r"],               # scheme
            ["x", "10.0.0.1", "GET", "https", "a.example", "443", "-", "r", "runId=r"],            # path
            ["x", "10.0.0.1", "CONNECT", "https", "a.example", "443", "-", "r", "runId=r"],        # connect scheme
            ["x", "10.0.0.1", "GET", "https", "a.example", "443", "/", "r", "runId=r,runId=s"],    # duplicate attr
            ["x", "10.0.0.1", "GET", "https", "a.example", "443", "/", "other", "runId=r"],        # principal not in identity
        ]:
            with self.subTest(bad=bad):
                self.assertIsNone(parse_v2_fields(bad, "signed"))
