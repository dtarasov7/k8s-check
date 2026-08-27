import json
import unittest

from kdiag.message_insights import enrich_message_insights, match_message_insight
from kdiag.normalize import normalize_evidence


class MessageInsightsTest(unittest.TestCase):
    def test_catalog_classifies_known_templates_without_creating_findings(self):
        pull_secret = match_message_insight(
            "kubelet.service",
            'unable to retrieve pull secret, the image pull may not succeed pod="ns/pod" secret="registry"',
        )
        self.assertEqual("image_pull_secret_unavailable", pull_secret["insight_id"])
        self.assertEqual("actionable", pull_secret["category"])

        reload_noop = match_message_insight(
            "kubernetes-api-proxy-reloader",
            "/etc/nginx/config/nginx.conf and /etc/nginx/config/nginx_new.conf are equal, skipping reload",
        )
        self.assertEqual("routine", reload_noop["category"])

        compatibility = match_message_insight(
            "systemd-sysv-generator",
            "SysV service lacks a native systemd unit file, automatically generating a unit file",
        )
        self.assertEqual("observe", compatibility["category"])

        routine_messages = (
            (
                "kubelet",
                'Container image "registry/image@sha256:abc" already present and unpacked successfully on machine',
            ),
            (
                "statefulset-controller",
                "create Pod smoke-mini-a-0 in StatefulSet smoke-mini-a successful",
            ),
            (
                "cert-manager-certificaterequests-issuer-ca",
                "certificate fetched from issuer successfully",
            ),
            (
                "kube-rbac-proxy",
                "added upstream: path=/metrics, upstream=http://127.0.0.1:8080/metrics",
            ),
        )
        for component, message in routine_messages:
            with self.subTest(component=component, message=message):
                insight = match_message_insight(component, message)
                self.assertIsNotNone(insight)
                self.assertEqual("routine", insight["category"])

        expected_messages = (
            (
                "cert-manager-certificaterequests-issuer-acme",
                "not signing CertificateRequest until it is approved",
                "observe",
            ),
            (
                "cert-manager-certificates-trigger",
                "issuing certificate as Secret does not exist",
                "observe",
            ),
            (
                "control-plane-manager",
                '"msg":"kubernetes pod checksum does not match expected checksum"',
                "actionable",
            ),
            (
                "kubelet",
                "failed to garbage collect required amount of images, attempted to free 100 bytes",
                "actionable",
            ),
        )
        for component, message, category in expected_messages:
            with self.subTest(component=component, message=message):
                insight = match_message_insight(component, message)
                self.assertIsNotNone(insight)
                self.assertEqual(category, insight["category"])

    def test_security_catalog_also_enriches_a_categorized_event(self):
        message = 'ptrace attack of "/opt/target" was attempted by "/opt/kaspersky/kesl"'
        normalized = normalize_evidence(
            {"collection_id": "security"},
            {
                "node-a": {
                    "commands": [
                        {
                            "id": "journal_kernel_current",
                            "stdout": json.dumps(
                                {
                                    "MESSAGE": message,
                                    "SYSLOG_IDENTIFIER": "kernel",
                                    "__REALTIME_TIMESTAMP": "1767225600000000",
                                }
                            ),
                        }
                    ],
                    "pod_logs": {"entries": []},
                    "facts": {"service_states": {}},
                }
            },
            {},
        )
        self.assertTrue(any("ptrace_security_alert" in event["categories"] for event in normalized["events"]))
        insight = next(item for item in normalized["message_insights"] if item["insight_id"] == "ptrace_attack_attempt")
        self.assertEqual("security", insight["category"])
        self.assertEqual(["node-a"], insight["affected_nodes"])

    def test_normalizer_builds_bounded_occurrence_time_and_scope_context(self):
        message = (
            'Unable to retrieve pull secret, the image pull may not succeed. '
            'pod="d8-runtime-audit-engine/runtime-audit-engine-a" '
            'secret="deckhouse-registry" err="secret not found"'
        )
        nodes = {}
        for index, node_name in enumerate(("node-a", "node-b")):
            nodes[node_name] = {
                "ended_at": "2026-01-01T00:10:00Z",
                "commands": [
                    {
                        "id": "journal_services_current",
                        "stdout": json.dumps(
                            {
                                "MESSAGE": message,
                                "_SYSTEMD_UNIT": "kubelet.service",
                                "__REALTIME_TIMESTAMP": str(1767225600000000 + index * 3600000000),
                            }
                        ),
                    }
                ],
                "pod_logs": {"entries": []},
                "facts": {"service_states": {}},
            }

        normalized = normalize_evidence({"collection_id": "insights"}, nodes, {})
        insight = normalized["message_insights"][0]
        self.assertEqual("image_pull_secret_unavailable", insight["insight_id"])
        self.assertEqual({"minimum": 2, "maximum": 2}, insight["occurrence_range"])
        self.assertEqual(3600.0, insight["observed_span_seconds"])
        self.assertEqual(2, insight["affected_nodes_count"])
        self.assertEqual(["node-a", "node-b"], insight["affected_nodes"])
        self.assertEqual(["d8-runtime-audit-engine/runtime-audit-engine-a"], insight["affected_pods"])
        self.assertEqual(2.0, insight["rate_per_hour_range"]["maximum"])
        self.assertEqual([], normalized["unknown_fingerprints"])

    def test_enrichment_correlates_pod_events_readyz_endpoints_and_journal_errors(self):
        insights = [
            {
                "insight_id": "image_pull_secret_unavailable",
                "category": "actionable",
                "title": "pull secret",
                "template": "pull secret",
                "occurrence_range": {"minimum": 2, "maximum": 2},
                "affected_nodes": ["node-a"],
                "examples": [
                    {
                        "message": 'Unable to retrieve pull secret pod="demo/app-a" secret="registry"',
                        "evidence": "node-a#journal:1",
                    }
                ],
            },
            {
                "insight_id": "nginx_upstream_temporarily_disabled",
                "category": "actionable",
                "title": "upstream disabled",
                "template": "upstream disabled",
                "occurrence_range": {"minimum": 3, "maximum": 4},
                "affected_nodes": ["node-a"],
                "examples": [
                    {
                        "message": 'upstream server temporarily disabled while connecting to upstream, upstream: "http://10.0.0.8:6443"',
                        "evidence": "node-a#journal:2",
                    }
                ],
            },
        ]
        kubernetes = {
            "sources": {
                "pods": {
                    "status": "collected",
                    "data": {
                        "items": [
                            {
                                "metadata": {"namespace": "demo", "name": "app-a"},
                                "spec": {"imagePullSecrets": ["registry"]},
                                "status": {
                                    "phase": "Pending",
                                    "containerStatuses": [
                                        {
                                            "name": "app",
                                            "ready": False,
                                            "restartCount": 3,
                                            "state": {"waiting": {"reason": "ImagePullBackOff"}},
                                        }
                                    ],
                                },
                            }
                        ]
                    },
                },
                "events": {
                    "status": "collected",
                    "data": {
                        "items": [
                            {
                                "reason": "FailedToRetrieveImagePullSecret",
                                "note": "Unable to retrieve registry",
                                "regarding": {"kind": "Pod", "namespace": "demo", "name": "app-a"},
                            }
                        ]
                    },
                },
                "api_readyz": {
                    "status": "collected",
                    "data": {"checks": [{"name": "etcd", "status": "failed", "message": "timeout"}]},
                },
                "endpoint_slices": {
                    "status": "collected",
                    "data": {
                        "items": [
                            {
                                "metadata": {"namespace": "default", "labels": {"kubernetes.io/service-name": "kubernetes"}},
                                "endpoints": [
                                    {"addresses": ["10.0.0.8"], "conditions": {"ready": False}}
                                ],
                            }
                        ]
                    },
                },
            }
        }
        normalized = {
            "events": [
                {
                    "categories": ["connection_refused"],
                    "node": "node-a",
                    "timestamp_epoch": 10,
                    "evidence": "node-a#journal:3",
                }
            ]
        }
        enriched = enrich_message_insights(insights, {}, kubernetes, normalized)
        pull = next(item for item in enriched if item["insight_id"] == "image_pull_secret_unavailable")
        self.assertEqual("investigate", pull["decision_state"])
        self.assertTrue(any(check["name"] == "pod_state" and check["status"] == "problem" for check in pull["checks"]))
        self.assertTrue(any(check["name"] == "kubernetes_events" for check in pull["checks"]))

        upstream = next(item for item in enriched if item["insight_id"] == "nginx_upstream_temporarily_disabled")
        self.assertEqual("investigate", upstream["decision_state"])
        self.assertTrue(any(check["name"] == "api_readyz" and check["status"] == "problem" for check in upstream["checks"]))
        self.assertTrue(any(check["name"] == "endpoint_state" and check["status"] == "problem" for check in upstream["checks"]))
        self.assertTrue(any(check["name"] == "related_journal_events" for check in upstream["checks"]))


if __name__ == "__main__":
    unittest.main()
