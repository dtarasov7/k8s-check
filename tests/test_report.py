import tempfile
import unittest
from pathlib import Path

from kdiag.report import build_report
from kdiag.util import atomic_write_gzip_json, atomic_write_json


class ReportTest(unittest.TestCase):
    def test_partial_collection_produces_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            atomic_write_gzip_json(
                root / "node-n1.json.gz",
                {
                    "schema_version": 1,
                    "kind": "node_snapshot",
                    "host": {"hostname": "n1", "kernel_release": "6.1", "os_release": {"PRETTY_NAME": "RED OS"}},
                    "facts": {
                        "boot_id_end": "boot",
                        "boot_changed_during_collection": False,
                        "root_disk": {"total_bytes": 100, "free_bytes": 50},
                        "ipv6_disable": {},
                        "cgroup": {"status": "disabled"},
                        "service_states": {"kubelet.service": {"status": "collected", "properties": {"ActiveState": "active"}}},
                    },
                    "commands": [],
                    "pod_logs": {"status": "truncated", "entries": []},
                },
            )
            atomic_write_gzip_json(root / "prometheus.json.gz", {"status": "not_configured"})
            atomic_write_gzip_json(
                root / "kubernetes.json.gz",
                {
                    "sources": {
                        "nodes": {"status": "collected", "data": {"items": []}},
                        "events": {"status": "failed", "error": "forbidden"},
                    },
                    "logs": {"status": "source_unavailable", "entries": []},
                },
            )
            atomic_write_json(
                root / "collection.json",
                {
                    "collection_id": "test",
                    "status": "partial",
                    "started_at": "start",
                    "ended_at": "end",
                    "options": {"collect_cgroup": False},
                    "nodes": [
                        {"host": "n1", "status": "collected", "file": "node-n1.json.gz"},
                        {"host": "n2", "status": "unreachable", "error": "ssh failed"},
                    ],
                    "kubernetes": {"status": "partial", "file": "kubernetes.json.gz", "error": None},
                    "prometheus": {"status": "not_configured", "file": "prometheus.json.gz"},
                },
            )
            report = build_report(root)
            self.assertEqual("partial", report["status"])
            self.assertTrue((root / "facts.json").is_file())
            self.assertTrue((root / "findings.json").is_file())
            self.assertTrue((root / "normalized-events.json.gz").is_file())
            self.assertTrue((root / "report.json").is_file())
            self.assertTrue((root / "report.md").is_file())
            coverage = {item["source"]: item["status"] for item in report["coverage"]}
            self.assertEqual("collected", coverage["kubernetes/nodes"])
            self.assertEqual("failed", coverage["kubernetes/events"])
            self.assertEqual("truncated", coverage["node/n1/pod_logs"])
            self.assertIn("collector.node_gap", {item["rule_id"] for item in report["findings"]})
            ledger = {item["rule_id"]: item for item in report["rule_evaluation_ledger"]}
            self.assertEqual("matched", ledger["collector.node_gap"]["status"])
            self.assertEqual("unknown", ledger["kubernetes.node_not_ready"]["status"])
            self.assertTrue(ledger["kubernetes.node_not_ready"]["missing_evidence"])
            self.assertFalse(report["options"]["collect_cgroup"])
            self.assertEqual("disabled", report["node_inventory"][0]["cgroup_mode"])
            self.assertIn("Cgroup checks: **disabled**", (root / "report.md").read_text(encoding="utf-8"))
            self.assertIn("Rule ID:", (root / "report.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
