import os
import tempfile
import time
import unittest
from pathlib import Path

from clearideas_egress.audit import AuditLog
from clearideas_egress.cli import RequestHandler
from clearideas_egress.revocation import RevocationError, RevocationList, parse


class RevocationTests(unittest.TestCase):
    def setUp(self):
        self.path = Path(tempfile.mkdtemp()) / "revoked"
        self.path.write_text("# kill switch\nprincipal=sbx-42\nrunnerAuthId=auth-9c1e  # compromised\n")
        self.errors = []
        self.list = RevocationList(self.path, refresh_seconds=0, on_error=self.errors.append)

    def bump(self, text):
        self.path.write_text(text)
        stamp = time.time() + 5
        os.utime(self.path, (stamp, stamp))

    def test_matches(self):
        self.assertTrue(self.list.revoked("sbx-42"))
        self.assertTrue(self.list.revoked("runner-1", {"jobId": "j", "runnerAuthId": "auth-9c1e"}))
        self.assertFalse(self.list.revoked("sbx-43", {"runnerAuthId": "auth-other"}))
        self.assertFalse(self.list.revoked("auth-9c1e"))  # attribute entries only match that attribute

    def test_reload_and_keep_last_good(self):
        self.bump("principal=sbx-43\n")
        self.assertTrue(self.list.revoked("sbx-43"))
        self.assertFalse(self.list.revoked("sbx-42"))
        self.bump("this is not valid\n")
        self.assertTrue(self.list.revoked("sbx-43"))  # invalid edit: keep last good
        self.path.unlink()
        self.assertTrue(self.list.revoked("sbx-43"))  # missing file: keep last good
        self.assertEqual(len(self.errors), 2)
        self.bump("")
        self.assertFalse(self.list.revoked("sbx-43"))  # empty file clears

    def test_never_loaded_fails_closed(self):
        missing = RevocationList(self.path.parent / "missing", refresh_seconds=0)
        self.assertIsNone(missing.revoked("anyone"))
        handler = RequestHandler(AuditLog(None), revocations=missing)
        self.assertEqual(handler(["u", "GET", "https", "a.example", "443", "/", "-", "-"]),
                         "ERR log=helper_misconfigured egress_retry_=503")

    def test_parse_errors(self):
        for text in ["principal", "=x", "principal=a b", "1x=y", "principal=x=y"]:
            with self.subTest(text=text), self.assertRaises(RevocationError):
                parse(text)

    def test_request_handler(self):
        handler = RequestHandler(AuditLog(None), revocations=self.list)
        self.assertEqual(handler(["sbx-42", "GET", "https", "a.example", "443", "/", "-", "-"]), "ERR log=revoked")
        self.assertEqual(handler(["-", "POST", "https", "a.example", "443", "/x", "runner-1",
                                  "jobId=j,runnerAuthId=auth-9c1e"]), "ERR log=revoked")
        self.assertEqual(handler(["sbx-1", "GET", "https", "a.example", "443", "/", "-", "-"]), "OK log=request_ok")
        self.assertEqual(handler(["sbx-1", "CONNECT", "authority_form", "a.example", "443", "-", "-", "-"]),
                         "OK log=request_ok")


if __name__ == "__main__":
    unittest.main()
