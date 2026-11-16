"""M-7: the real entrypoint runs non-root on a read-only root; secrets stay out of process state."""

import os
from pathlib import Path

import unittest

from tests.e2e.harness import Arbiter, Proxy, ProxyTestCase, can_run_unprivileged, http_request, requires_current


def _process_tree_files(root_pid: int) -> list[tuple[int, bytes, bytes]]:
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            environ = (entry / "environ").read_bytes()
            cmdline = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        found.append((int(entry.name), environ, cmdline))
    return found


@requires_current("entrypoint")
class EntrypointTests(ProxyTestCase):
    @unittest.skipUnless(can_run_unprivileged(), "needs an unprivileged user to run the entrypoint as")
    def test_entrypoint_demo_mode_non_root_read_only(self):  # E-M7-01, E-M7-02
        arbiter = Arbiter(port=18100)
        try:
            proxy = Proxy(policy_url=arbiter.url, entrypoint=True, users={},
                          env={"EGRESS_DEMO_USER": "demo", "EGRESS_DEMO_PASSWORD": "demo-ENV-secret",
                               "EGRESS_POLICY_TOKEN": "inline-TOKEN-secret"})
            with proxy:
                r = http_request(proxy, "http://example.com/", ("demo", "demo-ENV-secret"))
                self.assertEqual(r.status, 200, proxy.diagnostics()[-3000:])
                self.assertEqual(arbiter.headers[-1].get("Authorization"), "Bearer inline-TOKEN-secret")
                leaks = []
                checked = 0
                for pid, environ, cmdline in _process_tree_files(proxy.process.pid):
                    if b"squid" in cmdline or b"clearideas_egress" in cmdline:
                        checked += 1
                    for secret in (b"demo-ENV-secret", b"inline-TOKEN-secret"):
                        if secret in environ or secret in cmdline:
                            if pid in (os.getpid(), proxy.process.pid):
                                continue  # the test process and the launcher (stand-in for `docker run -e`)
                            name = cmdline.split(b"\0")[0].decode(errors="replace")
                            leaks.append((pid, name, secret.decode()))
                self.assertEqual(leaks, [], "secret visible in another process's environ/cmdline")
                self.assertGreaterEqual(checked, 3, "expected to inspect squid and its helper processes")
                token_file = proxy.run_dir / "run" / "policy-token"
                self.assertEqual(oct(token_file.stat().st_mode & 0o777), "0o600")
        finally:
            arbiter.close()

    def test_entrypoint_refuses_root(self):
        import subprocess
        result = subprocess.run(["/bin/sh", str(Path(__file__).resolve().parents[2] / "docker" / "entrypoint.sh")],
                                env={"PATH": "/usr/bin:/bin", "EGRESS_RUN_DIR": "/tmp/nonexistent"},
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to run as root", result.stderr)
