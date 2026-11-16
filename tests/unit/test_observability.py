"""Alert rules and the dashboard only reference metrics the code actually emits."""

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HISTOGRAMS = {"egress_policy_decision_seconds"}


def emitted() -> set[str]:
    names = set()
    for path in (ROOT / "src" / "clearideas_egress").glob("*.py"):
        names |= set(re.findall(r'"(egress_[a-z0-9_]+)"', path.read_text()))
    for histogram in HISTOGRAMS:
        names |= {f"{histogram}_bucket", f"{histogram}_sum", f"{histogram}_count"}
    return names


def referenced(text: str) -> set[str]:
    return set(re.findall(r"\b(egress_[a-z0-9_]+)\b", text)) - {"egress_proxy", "egress_proxy_"}


class ObservabilityTests(unittest.TestCase):
    def test_alert_rules_reference_real_metrics(self):
        rules = (ROOT / "deploy/observability/prometheus-rules.yaml").read_text()
        expressions = "\n".join(re.findall(r"expr:\s*(\|[\s\S]*?(?=\n\s+for:|\n\s+labels:)|.*)", rules))
        self.assertGreaterEqual(len(referenced(expressions)), 12, "rule expressions were not extracted")
        missing = referenced(expressions) - emitted()
        self.assertEqual(missing, set())
        self.assertGreaterEqual(len(re.findall(r"- alert:", rules)), 12)

    def test_dashboard_references_real_metrics(self):
        dashboard = json.loads((ROOT / "deploy/observability/grafana-dashboard.json").read_text())
        expressions = " ".join(t["expr"] for p in dashboard["panels"] for t in p["targets"])
        self.assertEqual(referenced(expressions) - emitted(), set())

    def test_access_log_fields_used_in_log_queries_exist(self):
        template = (ROOT / "src/clearideas_egress/templates/squid.conf.template").read_text()
        fields = set(re.findall(r'"([a-z_]+)":"', template.split("logformat egress_json", 1)[1].splitlines()[0]))
        for needed in ("result", "decision", "decision_id", "xaction", "instance", "principal", "bytes_from_client"):
            self.assertIn(needed, fields)


if __name__ == "__main__":
    unittest.main()
