import unittest

from kdiag.analysis import resolve_analysis_window
from kdiag.causal import annotate_findings, build_causal_analysis


class AnalysisWindowTest(unittest.TestCase):
    def test_check_has_no_incident_window(self):
        value = resolve_analysis_window("check")
        self.assertEqual({"purpose": "check", "incident_start": None, "incident_end": None}, value)

    def test_incident_since_resolves_to_utc_window(self):
        value = resolve_analysis_window(
            "incident",
            incident_since="2h",
            now="2026-08-27T12:00:00Z",
        )
        self.assertEqual("2026-08-27T10:00:00Z", value["incident_start"])
        self.assertEqual("2026-08-27T12:00:00Z", value["incident_end"])

    def test_incident_accepts_explicit_utc_bounds(self):
        value = resolve_analysis_window(
            "incident",
            incident_start="2026-08-27T10:00:00+00:00",
            incident_end="2026-08-27T11:30:00Z",
        )
        self.assertEqual("2026-08-27T10:00:00Z", value["incident_start"])
        self.assertEqual("2026-08-27T11:30:00Z", value["incident_end"])

    def test_invalid_window_combinations_are_rejected(self):
        values = (
            ("incident", {}),
            ("check", {"incident_since": "2h"}),
            ("incident", {"incident_since": "2h", "incident_start": "2026-08-27T10:00:00Z"}),
            ("incident", {"incident_start": "2026-08-27T12:00:00Z", "incident_end": "2026-08-27T11:00:00Z"}),
            ("incident", {"incident_since": "0h"}),
        )
        for purpose, arguments in values:
            with self.subTest(purpose=purpose, arguments=arguments), self.assertRaises(ValueError):
                resolve_analysis_window(purpose, now="2026-08-27T12:00:00Z", **arguments)


class CausalAnalysisTest(unittest.TestCase):
    def test_findings_get_activity_status_and_role(self):
        findings = [
            {
                "id": "node.low_root_disk:node-a",
                "rule_id": "node.low_root_disk",
                "severity": "warning",
                "classification": "fact",
                "causal_confidence": "high",
                "detection_confidence": "high",
                "affected": ["node-a"],
                "evidence": ["node-node-a.json.gz#facts.root_disk"],
            },
            {
                "id": "kubernetes.pod_crash_loop:demo/app",
                "rule_id": "kubernetes.pod_crash_loop",
                "severity": "warning",
                "classification": "fact",
                "causal_confidence": "high",
                "detection_confidence": "high",
                "affected": ["demo/app"],
                "evidence": ["kubernetes.json.gz#sources.pods.items[0]"],
            },
            {
                "id": "node.oom_detected:node-a",
                "rule_id": "node.oom_detected",
                "severity": "warning",
                "classification": "fact",
                "causal_confidence": "medium",
                "detection_confidence": "high",
                "affected": ["node-a"],
                "evidence": ["node-node-a.json.gz#commands.journal_kernel_current:line-1"],
                "event_count": 1,
                "started_at": "2026-08-27T09:00:00Z",
                "ended_at": "2026-08-27T09:00:00Z",
            },
        ]
        collection = {
            "ended_at": "2026-08-27T12:00:00Z",
            "options": {"purpose": "check", "incident_start": None, "incident_end": None},
        }
        values = annotate_findings(findings, collection)
        by_rule = {item["rule_id"]: item for item in values}
        self.assertEqual("active", by_rule["node.low_root_disk"]["finding_status"])
        self.assertEqual("configuration_risk", by_rule["node.low_root_disk"]["finding_role"])
        self.assertEqual("consequence", by_rule["kubernetes.pod_crash_loop"]["finding_role"])
        self.assertEqual("resolved", by_rule["node.oom_detected"]["finding_status"])
        analysis = build_causal_analysis({}, values, {}, {}, collection)
        self.assertNotIn("node.oom_detected", {item["rule_id"] for item in analysis["hypotheses"]})

    def test_topology_links_node_pod_workload_endpoint_and_service_and_ranks_cause(self):
        kubernetes = {
            "sources": {
                "nodes": {"data": {"items": [{"metadata": {"name": "node-a"}}]}},
                "pods": {"data": {"items": [{
                    "metadata": {
                        "namespace": "demo",
                        "name": "app-0",
                        "ownerReferences": [{"kind": "ReplicaSet", "name": "app-abc"}],
                    },
                    "spec": {"nodeName": "node-a", "persistentVolumeClaims": []},
                }]}},
                "workloads": {"data": {"items": [
                    {
                        "kind": "ReplicaSet",
                        "metadata": {
                            "namespace": "demo",
                            "name": "app-abc",
                            "ownerReferences": [{"kind": "Deployment", "name": "app"}],
                        },
                    },
                    {"kind": "Deployment", "metadata": {"namespace": "demo", "name": "app"}},
                ]}},
                "services": {"data": {"items": [{"metadata": {"namespace": "demo", "name": "app"}}]}},
                "endpoint_slices": {"data": {"items": [{
                    "metadata": {"namespace": "demo", "name": "app-abc", "labels": {"kubernetes.io/service-name": "app"}},
                    "endpoints": [{"targetRef": {"kind": "Pod", "namespace": "demo", "name": "app-0"}}],
                }]}},
                "pvc": {"data": {"items": []}},
                "pv": {"data": {"items": []}},
            }
        }
        findings = annotate_findings(
            [
                {
                    "id": "kubernetes.node_not_ready:node-a",
                    "rule_id": "kubernetes.node_not_ready",
                    "severity": "critical",
                    "classification": "fact",
                    "causal_confidence": "high",
                    "detection_confidence": "high",
                    "affected": ["node-a"],
                    "evidence": ["kubernetes.json.gz#sources.nodes.items[0]"],
                    "counter_evidence": [],
                    "missing_checks": [],
                },
                {
                    "id": "kubernetes.pod_crash_loop:demo/app-0",
                    "rule_id": "kubernetes.pod_crash_loop",
                    "severity": "warning",
                    "classification": "fact",
                    "causal_confidence": "high",
                    "detection_confidence": "high",
                    "affected": ["demo/app-0"],
                    "evidence": ["kubernetes.json.gz#sources.pods.items[0]"],
                    "counter_evidence": [],
                    "missing_checks": [],
                },
            ],
            {"ended_at": "2026-08-27T12:00:00Z", "options": {"purpose": "incident", "incident_start": "2026-08-27T10:00:00Z", "incident_end": "2026-08-27T12:00:00Z"}},
        )
        analysis = build_causal_analysis(
            kubernetes,
            findings,
            {},
            {},
            {"options": {"purpose": "incident", "incident_start": "2026-08-27T10:00:00Z", "incident_end": "2026-08-27T12:00:00Z"}},
        )
        edges = {(item["source"], item["target"], item["relation"]) for item in analysis["graph"]["edges"]}
        self.assertIn(("node:node-a", "pod:demo/app-0", "hosts"), edges)
        self.assertIn(("pod:demo/app-0", "workload:ReplicaSet:demo/app-abc", "member_of"), edges)
        self.assertIn(("workload:ReplicaSet:demo/app-abc", "workload:Deployment:demo/app", "member_of"), edges)
        self.assertIn(("pod:demo/app-0", "endpoint_slice:demo/app-abc", "backend_of"), edges)
        self.assertIn(("endpoint_slice:demo/app-abc", "service:demo/app", "serves"), edges)
        self.assertIn(
            ("finding:kubernetes.node_not_ready:node-a", "finding:kubernetes.pod_crash_loop:demo/app-0", "may_explain"),
            edges,
        )
        self.assertEqual("kubernetes.node_not_ready", analysis["hypotheses"][0]["rule_id"])
        self.assertGreater(analysis["hypotheses"][0]["score"], 0)

    def test_prometheus_range_is_summarized_without_inventing_thresholds(self):
        analysis = build_causal_analysis(
            {},
            [],
            {},
            {
                "sources": {
                    "range_api_server_5xx": {
                        "status": "collected",
                        "data": {
                            "query_id": "api_server_5xx",
                            "title": "Ошибки API 5xx",
                            "unit": "requests_per_second",
                            "series": [
                                {"metric": {}, "values": [[1, "0"], [2, "1.5"], [3, "4"]]},
                            ],
                            "series_count": 1,
                            "truncated": False,
                        },
                    }
                }
            },
            {"options": {"purpose": "incident", "incident_start": "2026-08-27T10:00:00Z", "incident_end": "2026-08-27T12:00:00Z"}},
        )
        self.assertEqual(1, len(analysis["metric_signals"]))
        signal = analysis["metric_signals"][0]
        self.assertEqual("rising", signal["trend"])
        self.assertEqual(4.0, signal["maximum"])
        self.assertNotIn("healthy", signal)


if __name__ == "__main__":
    unittest.main()
