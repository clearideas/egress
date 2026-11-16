"""Documentation stays truthful: examples work, every setting is documented (review L-8)."""

import json
import re
import unittest
from pathlib import Path

from clearideas_egress import compile_file_policy

ROOT = Path(__file__).resolve().parents[2]
SAFE_PORTS = {"http": {80, 443}, "https": {443}}


def policy_examples():
    readme = (ROOT / "README.md").read_text()
    for block in re.findall(r"```json\n(.*?)```", readme, re.S):
        document = json.loads(block)
        if isinstance(document, dict) and "principals" in document:
            yield "README.md", document
    for path in sorted((ROOT / "examples").glob("*.json")):
        yield path.name, json.loads(path.read_text())


class DocsTests(unittest.TestCase):
    def test_policy_examples_compile_and_are_reachable(self):
        examples = list(policy_examples())
        self.assertGreaterEqual(len(examples), 3)
        for name, document in examples:
            with self.subTest(example=name):
                policy = compile_file_policy(document)
                for rule in policy.principals.values():
                    for scheme, host, port in rule.origins:
                        self.assertIn(port, SAFE_PORTS[scheme], f"{scheme}://{host}:{port} can never be reached")

    def test_every_setting_is_documented(self):
        used = set()
        for path in list((ROOT / "src").rglob("*.py")) + [ROOT / "docker" / "entrypoint.sh"]:
            used |= set(re.findall(r"EGRESS_[A-Z0-9_]+", path.read_text()))
        docs = (ROOT / "docs" / "OPERATIONS.md").read_text()
        missing = sorted(name for name in used if name not in docs)
        self.assertEqual(missing, [], "settings used in code but not documented in docs/OPERATIONS.md")


if __name__ == "__main__":
    unittest.main()
