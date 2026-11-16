"""Deployment artifacts stay in sync with the single source of truth (templates/deny-cidrs.conf)."""

import ipaddress
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def source_cidrs():
    text = (ROOT / "src/clearideas_egress/templates/deny-cidrs.conf").read_text()
    return {ipaddress.ip_network(line.split("#", 1)[0].strip()) for line in text.splitlines()
            if line.split("#", 1)[0].strip()}


class DeploySyncTests(unittest.TestCase):
    def test_nftables_matches_deny_list(self):
        text = (ROOT / "deploy/nftables/egress-proxy.nft").read_text()
        found = set()
        for block in re.findall(r"elements = \{(.*?)\}", text, re.S):
            found |= {ipaddress.ip_network(item.strip()) for item in block.split(",") if item.strip()}
        self.assertEqual(found, source_cidrs())

    def test_networkpolicy_matches_deny_list(self):
        text = (ROOT / "deploy/kubernetes/networkpolicy.yaml").read_text()
        excepts = {ipaddress.ip_network(m) for m in re.findall(r"^\s+- ([0-9a-f:.]+/\d+)\s*$", text, re.M)}
        self.assertEqual(excepts, source_cidrs())


class SupplyChainTests(unittest.TestCase):
    def test_dockerfile(self):
        text = (ROOT / "Dockerfile").read_text()
        # Numeric and non-zero, so Kubernetes can verify runAsNonRoot.
        self.assertRegex(text, r"(?m)^USER [1-9][0-9]*(:[0-9]+)?\s*$")
        self.assertNotRegex(text, r"(?m)^FROM .*:latest")
        self.assertIn("ARG PYTHON_IMAGE", text)

    def test_workflow_least_privilege(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertRegex(text, r"(?m)^permissions:\s*\n\s+contents: read")
        self.assertIn("make e2e", text)

    def test_compose_hardening(self):
        text = (ROOT / "compose.yaml").read_text()
        for needle in ("read_only: true", "cap_drop: [ALL]", "no-new-privileges:true", "127.0.0.1:3128:3128"):
            self.assertIn(needle, text)


if __name__ == "__main__":
    unittest.main()
