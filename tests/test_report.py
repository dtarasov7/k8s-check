import json
import tempfile
import unittest
from pathlib import Path

from kdiag.report import (
    RULE_COVERAGE_REQUIREMENTS,
    _compact_missing_evidence,
    _coverage,
    _coverage_display_rows,
    _rule_ledger,
    _render_message_insights,
    build_report,
    load_collection,
)
from kdiag.rule_catalog import RULE_CATALOG
from kdiag.util import atomic_write_gzip_json, atomic_write_json, markdown_code, markdown_escape


class ReportTest(unittest.TestCase):
    def test_coverage_display_groups_same_node_problem(self):
        rows = _coverage_display_rows(
            [
                {"source": "node/node-a/command/journal_services_current", "status": "truncated", "required": True},
                {"source": "node/node-b/command/journal_services_current", "status": "truncated", "required": True},
                {"source": "node/node-a/command/uname", "status": "collected", "required": False},
            ]
        )
        self.assertEqual(1, len(rows))
        self.assertIn("служебный журнал текущей загрузки: 2 узл.", rows[0]["display_source"])

    def test_message_insight_render_explains_estimates_and_decision_context(self):
        lines = []
        _render_message_insights(
            lines,
            [
                {
                    "insight_id": "routine-demo",
                    "category": "routine",
                    "title": "Конфигурация Nginx не изменилась",
                },
                {
                    "insight_id": "routine-correlated",
                    "category": "routine",
                    "title": "Успех рядом с деградацией",
                    "component": "demo",
                    "template": "successful",
                    "decision_state": "investigate",
                    "occurrence_range": {"minimum": 10, "maximum": 10},
                    "checks": [{"name": "component_pod_state", "status": "problem", "summary": "Pod не готов"}],
                    "explanation": "Сообщение штатное, но связанный Pod не готов.",
                    "decision_condition": "Проверять только при деградации Pod.",
                    "recommendation": "Проверить Pod.",
                },
                {
                    "insight_id": "demo",
                    "category": "actionable",
                    "title": "Проверка <n>",
                    "component": "demo",
                    "template": "failure code <n>",
                    "decision_state": "investigate",
                    "occurrence_range": {"minimum": 3, "maximum": 4},
                    "estimate_error": 1,
                    "affected_nodes": ["node-a"],
                    "affected_nodes_count": 1,
                    "affected_pods": ["demo/pod-a"],
                    "affected_pods_count": 1,
                    "explanation": "Описание",
                    "checks": [{"name": "pod_state", "status": "problem", "summary": "not ready"}],
                    "counter_evidence": ["readyz healthy"],
                    "missing_checks": ["secret content is not collected"],
                    "decision_condition": "Решить при повторении",
                    "recommendation": "Проверить Pod",
                }
            ],
        )
        rendered = "\n".join(lines)
        self.assertIn("Сообщения, требующие внимания", rendered)
        self.assertNotIn("Конфигурация Nginx не изменилась", rendered)
        self.assertIn("Успех рядом с деградацией", rendered)
        self.assertIn("гарантированно не менее 3, оценочная верхняя граница 4", rendered)
        self.assertIn("Что говорит против текущей проблемы: readyz healthy", rendered)
        self.assertIn("Когда требуется действие: Решить при повторении", rendered)
        self.assertIn("`failure code <n>`", rendered)
        self.assertNotIn("&lt;", rendered)
        for unwanted in ("triage", "findings", "Counter-evidence", "Missing checks", "first seen", "rate"):
            self.assertNotIn(unwanted, rendered)

    def test_markdown_uses_readable_angle_brackets(self):
        self.assertEqual(r"\<n\>", markdown_escape("<n>"))
        self.assertEqual("`<n>`", markdown_code("<n>"))

    def test_non_collector_rules_declare_coverage_requirements(self):
        expected = {rule_id for rule_id in RULE_CATALOG if not rule_id.startswith("collector.")}
        self.assertEqual(expected, set(RULE_COVERAGE_REQUIREMENTS))

    def test_rule_ledger_limits_gaps_to_dependent_rules(self):
        coverage = [
            {"source": "node/n1", "status": "collected", "required": True},
            {"source": "node/n1/command/runtime_crictl_info", "status": "unsupported", "required": False},
            {"source": "node/n1/pod_logs", "status": "truncated", "required": True},
            {"source": "kubernetes", "status": "partial", "required": True},
            {"source": "kubernetes/nodes", "status": "collected", "required": True},
            {"source": "kubernetes/events", "status": "failed", "required": True},
            {"source": "kubernetes/logs", "status": "partial", "required": True},
            {"source": "prometheus", "status": "not_configured", "required": False},
        ]
        ledger = {
            item["rule_id"]: item
            for item in _rule_ledger([], coverage, {"collect_cgroup": True, "collect_etcd": False})
        }
        self.assertEqual("not_matched", ledger["node.low_root_disk"]["status"])
        self.assertEqual("not_matched", ledger["kubernetes.node_not_ready"]["status"])
        self.assertEqual("unknown", ledger["runtime.cri_not_ready"]["status"])
        self.assertEqual(
            ["node/n1/command/runtime_crictl_info:unsupported"],
            ledger["runtime.cri_not_ready"]["missing_evidence"],
        )
        self.assertEqual("unknown", ledger["kubernetes.failed_scheduling"]["status"])
        self.assertEqual(
            ["kubernetes/events:failed"],
            ledger["kubernetes.failed_scheduling"]["missing_evidence"],
        )
        self.assertEqual("unknown", ledger["dns.coredns_errors"]["status"])
        self.assertEqual("not_applicable", ledger["etcd.unhealthy"]["status"])

    def test_unreachable_kubernetes_bundle_keeps_source_failure_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            atomic_write_gzip_json(
                root / "kubernetes.json.gz",
                {
                    "sources": {
                        "nodes": {"status": "failed", "required": True, "error": "forbidden"},
                    },
                    "logs": {"status": "source_unavailable", "entries": []},
                },
            )
            atomic_write_json(
                root / "collection.json",
                {
                    "nodes": [],
                    "kubernetes": {"status": "unreachable", "file": "kubernetes.json.gz"},
                    "prometheus": {"status": "not_configured"},
                },
            )
            collection, nodes, kubernetes, _prometheus = load_collection(root)
            self.assertEqual("failed", kubernetes["sources"]["nodes"]["status"])
            ledger = {
                item["rule_id"]: item
                for item in _rule_ledger([], _coverage(collection, nodes, kubernetes), {})
            }
            self.assertEqual(
                ["kubernetes/nodes:failed"],
                ledger["kubernetes.node_not_ready"]["missing_evidence"],
            )

    def test_disabled_kubernetes_rules_are_not_applicable_and_node_gaps_compact(self):
        ledger = {
            item["rule_id"]: item
            for item in _rule_ledger(
                [],
                [{"source": "kubernetes", "status": "disabled", "required": False}],
                {},
            )
        }
        self.assertEqual("not_applicable", ledger["kubernetes.node_not_ready"]["status"])
        self.assertEqual(
            ["node/*/command/journal_services_current:unsupported (2 nodes)"],
            _compact_missing_evidence(
                [
                    "node/n1/command/journal_services_current:unsupported",
                    "node/n2/command/journal_services_current:unsupported",
                ]
            ),
        )

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
                    "commands": [
                        {
                            "id": "journal_services_current",
                            "status": "collected",
                            "stdout": json.dumps(
                                {
                                    "MESSAGE": "opaque-unclassified-marker-7391",
                                    "_SYSTEMD_UNIT": "demo.service",
                                    "__REALTIME_TIMESTAMP": "1767225600000000",
                                }
                            ),
                        }
                    ],
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
            self.assertTrue((root / "causal-graph.json").is_file())
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
            self.assertEqual("not_matched", ledger["kubernetes.node_not_ready"]["status"])
            self.assertEqual("unknown", ledger["kubernetes.failed_scheduling"]["status"])
            self.assertTrue(ledger["kubernetes.failed_scheduling"]["missing_evidence"])
            self.assertFalse(report["options"]["collect_cgroup"])
            self.assertEqual("check", report["analysis"]["purpose"])
            self.assertIn("hypotheses", report)
            self.assertIn("finding_role", report["findings"][0])
            self.assertIn("finding_status", report["findings"][0])
            self.assertEqual("disabled", report["node_inventory"][0]["cgroup_mode"])
            markdown = (root / "report.md").read_text(encoding="utf-8")
            self.assertIn("Проверки cgroup: **отключены**", markdown)
            self.assertIn("Идентификатор проверки:", markdown)
            self.assertIn("Что обнаружено:", markdown)
            self.assertIn("Что это означает:", markdown)
            self.assertIn("Что делать:", markdown)
            self.assertIn("Наиболее вероятные объяснения", markdown)
            self.assertIn("Причинный граф", markdown)
            self.assertIn("Состояние:", markdown)
            self.assertIn("Сохранено неизвестных шаблонов: 1", markdown)
            self.assertNotIn("opaque-unclassified-marker", markdown)
            for unwanted in ("Rule ID:", "Evidence:", "Counter-evidence:", "Missing checks:", "## Findings", "ledger", "coverage"):
                self.assertNotIn(unwanted, markdown)


if __name__ == "__main__":
    unittest.main()
